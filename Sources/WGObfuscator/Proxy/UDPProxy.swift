import Foundation
import Network
import Logging
import os.log

/// UDP Proxy that sits between WireGuard (localhost) and the Remote Server.
/// It obfuscates outgoing traffic and de-obfuscates incoming traffic.
/// 
/// PERFORMANCE CRITICAL: This implementation processes packets directly in NWConnection
/// callbacks WITHOUT creating Tasks or crossing actor boundaries. The codec and masker
/// are Sendable structs that can be safely used from any thread.
/// 
/// Thread safety: Mutable state is synchronized via stateQueue, hence @unchecked Sendable.
public final class UDPProxy: @unchecked Sendable {
    
    // MARK: - Configuration
    
    public struct Configuration: Sendable {
        /// The local port to listen on (0 for ephemeral)
        public let localPort: UInt16
        /// The remote server endpoint to forward obfuscated traffic to
        public let remoteEndpoint: NWEndpoint
        /// Obfuscation key
        public let key: Data
        /// Masking type
        public let masking: MaskingType
        
        public init(localPort: UInt16 = 0, remoteEndpoint: NWEndpoint, key: Data, masking: MaskingType = .stun) {
            self.localPort = localPort
            self.remoteEndpoint = remoteEndpoint
            self.key = key
            self.masking = masking
        }
    }
    
    // MARK: - Properties
    
    private let config: Configuration
    private let logger = Logger(label: "com.wg-obfuscator.UDPProxy")
    
    // Thread-safe packet processors (Sendable structs)
    private let codec: PacketCodec
    private let masker: (any MaskingProvider)?
    
    // Connection state managed via dispatch queue for thread safety
    private let stateQueue = DispatchQueue(label: "com.wg-obfuscator.UDPProxy.state")
    private var _listener: NWListener?
    private var _remoteConnection: NWConnection?
    private var _localConnection: NWConnection?
    private var _listeningPort: UInt16?
    
    /// The port the proxy is actually listening on (valid after start)
    public var listeningPort: UInt16? {
        stateQueue.sync { _listeningPort }
    }
    
    // MARK: - Initialization
    
    public init(configuration: Configuration) throws {
        self.config = configuration
        self.codec = try PacketCodec(key: configuration.key)
        self.masker = MaskingFactory.create(configuration.masking)
    }
    
    // MARK: - Lifecycle
    
    /// Start the proxy
    /// - Returns: The local port being listened on
    public func start() async throws -> UInt16 {
        logger.info("Starting UDP Proxy...")
        
        // 1. Setup Listener (Local side - receives from WireGuard)
        let listenerParams = NWParameters.udp
        listenerParams.allowLocalEndpointReuse = true
        listenerParams.requiredInterfaceType = .loopback
        
        let listener = try NWListener(using: listenerParams, on: NWEndpoint.Port(integerLiteral: config.localPort))
        
        stateQueue.sync { self._listener = listener }
        
        listener.stateUpdateHandler = { [weak self] state in
            self?.handleListenerState(state)
        }
        
        listener.newConnectionHandler = { [weak self] connection in
            self?.handleNewLocalConnection(connection)
        }
        
        // Use a dedicated queue for network operations
        let networkQueue = DispatchQueue(label: "com.wg-obfuscator.network", qos: .userInteractive)
        listener.start(queue: networkQueue)
        
        // Wait for listener to be ready
        while listener.state != .ready {
            if case .failed(let error) = listener.state {
                throw error
            }
            try await Task.sleep(nanoseconds: 50_000_000) // 50ms
        }
        
        guard let port = listener.port?.rawValue else {
            throw ProxyError.failedToBindPort
        }
        
        stateQueue.sync { self._listeningPort = port }
        
        logger.info("UDP Proxy listening on 127.0.0.1:\(port)")
        
        // 2. Setup Remote Connection
        startRemoteConnection()
        
        return port
    }
    
    public func stop() {
        logger.info("Stopping UDP Proxy...")
        stateQueue.sync {
            _listener?.cancel()
            _remoteConnection?.cancel()
            _localConnection?.cancel()
            _listener = nil
            _remoteConnection = nil
            _localConnection = nil
        }
    }
    
    // MARK: - Connection Handling
    
    private func handleListenerState(_ state: NWListener.State) {
        switch state {
        case .ready:
            logger.info("Listener ready")
        case .failed(let error):
            logger.error("Listener failed: \(error.localizedDescription)")
        case .cancelled:
            logger.info("Listener cancelled")
        default:
            break
        }
    }
    
    private func handleNewLocalConnection(_ connection: NWConnection) {
        // Replace existing connection if any
        stateQueue.sync {
            _localConnection?.cancel()
            _localConnection = connection
        }
        
        logger.info("New local connection from \(String(describing: connection.endpoint))")
        
        connection.stateUpdateHandler = { [weak self] state in
            if case .failed(_) = state {
                self?.stateQueue.sync { self?._localConnection = nil }
            } else if case .cancelled = state {
                self?.stateQueue.sync { self?._localConnection = nil }
            }
        }
        
        let networkQueue = DispatchQueue(label: "com.wg-obfuscator.local", qos: .userInteractive)
        connection.start(queue: networkQueue)
        
        // Start receiving - packets processed directly in callback!
        receiveFromLocal(connection)
    }
    
    private func startRemoteConnection() {
        let params = NWParameters.udp
        params.allowFastOpen = true
        
        let connection = NWConnection(to: config.remoteEndpoint, using: params)
        stateQueue.sync { self._remoteConnection = connection }
        
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                self.logger.info("Connected to remote server")
                self.receiveFromRemote(connection)
            case .failed(let error):
                self.logger.error("Remote connection failed: \(error.localizedDescription)")
                self.stateQueue.sync { self._remoteConnection = nil }
            case .cancelled:
                self.stateQueue.sync { self._remoteConnection = nil }
            default:
                break
            }
        }
        
        let networkQueue = DispatchQueue(label: "com.wg-obfuscator.remote", qos: .userInteractive)
        connection.start(queue: networkQueue)
    }
    
    // MARK: - Data Flow (HOT PATH - NO TASKS, NO ACTOR HOPS)
    
    /// Receive cleartext WireGuard packets from Local, Obfuscate, Send to Remote
    /// CRITICAL: Processing happens directly in this callback - no Task creation!
    private func receiveFromLocal(_ connection: NWConnection) {
        connection.receiveMessage { [self] content, context, isComplete, error in
            if let error = error {
                self.logger.error("Receive local error: \(error.localizedDescription)")
                return
            }
            
            if let data = content, !data.isEmpty {
                // DIRECT PROCESSING - no Task, no actor hop!
                self.processLocalPacketDirect(data)
            }
            
            // Continue receiving
            if error == nil {
                self.receiveFromLocal(connection)
            }
        }
    }
    
    /// Process packet directly without any async overhead
    @inline(__always)
    private func processLocalPacketDirect(_ data: Data) {
        do {
            // 1. Get packet type
            guard let typeByte = data.first,
                  let type = WireGuardMessageType(rawValue: UInt32(typeByte)) else {
                return
            }
            
            // 2. Encode (Obfuscate) - synchronous, no allocation
            let obfuscated = try codec.encode(data, type: type)
            
            // 3. Wrap in Masking (if enabled)
            let wrapped: Data
            if let masker = masker {
                wrapped = try masker.wrap(obfuscated)
            } else {
                wrapped = obfuscated
            }
            
            // 4. Send to Remote - get connection synchronously
            let remote = stateQueue.sync { _remoteConnection }
            remote?.send(content: wrapped, completion: .contentProcessed({ _ in }))
            
        } catch {
            // Silently drop malformed packets in hot path
        }
    }
    
    /// Receive obfuscated packets from Remote, De-obfuscate, Send to Local
    private func receiveFromRemote(_ connection: NWConnection) {
        connection.receiveMessage { [self] content, context, isComplete, error in
            if let error = error {
                self.logger.error("Receive remote error: \(error.localizedDescription)")
                return
            }
            
            if let data = content, !data.isEmpty {
                // DIRECT PROCESSING - no Task, no actor hop!
                self.processRemotePacketDirect(data)
            }
            
            // Continue receiving
            if error == nil {
                self.receiveFromRemote(connection)
            }
        }
    }
    
    /// Process packet directly without any async overhead
    @inline(__always)
    private func processRemotePacketDirect(_ data: Data) {
        do {
            // 1. Unwrap Masking (if enabled)
            let obfuscated: Data
            if let masker = masker {
                guard let content = try masker.unwrap(data) else {
                    // Not a Data Indication - ignore
                    return
                }
                obfuscated = content
            } else {
                obfuscated = data
            }
            
            // 2. Decode (De-obfuscate)
            let cleartext = try codec.decode(obfuscated)
            
            // 3. Send to Local (WireGuard) - get connection synchronously
            let local = stateQueue.sync { _localConnection }
            local?.send(content: cleartext, completion: .contentProcessed({ _ in }))
            
        } catch {
            // Silently drop malformed packets in hot path
        }
    }
}

public enum ProxyError: Error, Sendable {
    case failedToBindPort
}
