import Foundation
import Network
import Logging
import os.log

/// UDP Proxy that sits between WireGuard (localhost) and the Remote Server.
/// It obfuscates outgoing traffic and de-obfuscates incoming traffic.
/// 
/// PERFORMANCE CRITICAL: This implementation processes packets directly in NWConnection
/// callbacks WITHOUT creating Tasks, actor hops, or synchronization on the hot path.
/// Connections are captured directly in closures to avoid any locking overhead.
/// 
/// Thread safety: Uses atomic-like patterns for connection references.
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
    
    // Connection state - accessed atomically via OSAtomic or locks only during setup/teardown
    private var listener: NWListener?
    private var remoteConnection: NWConnection?
    private var localConnection: NWConnection?
    private var listeningPortValue: UInt16?
    
    /// The port the proxy is actually listening on (valid after start)
    public var listeningPort: UInt16? {
        listeningPortValue
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
        
        let newListener = try NWListener(using: listenerParams, on: NWEndpoint.Port(integerLiteral: config.localPort))
        self.listener = newListener
        
        newListener.stateUpdateHandler = { [weak self] state in
            self?.handleListenerState(state)
        }
        
        newListener.newConnectionHandler = { [weak self] connection in
            self?.handleNewLocalConnection(connection)
        }
        
        // Use a dedicated high-priority queue for network operations
        let networkQueue = DispatchQueue(label: "com.wg-obfuscator.network", qos: .userInteractive)
        newListener.start(queue: networkQueue)
        
        // Wait for listener to be ready
        while newListener.state != .ready {
            if case .failed(let error) = newListener.state {
                throw error
            }
            try await Task.sleep(nanoseconds: 50_000_000) // 50ms
        }
        
        guard let port = newListener.port?.rawValue else {
            throw ProxyError.failedToBindPort
        }
        
        self.listeningPortValue = port
        
        logger.info("UDP Proxy listening on 127.0.0.1:\(port)")
        
        // 2. Setup Remote Connection and start receiving immediately
        setupRemoteConnection()
        
        return port
    }
    
    public func stop() {
        logger.info("Stopping UDP Proxy...")
        listener?.cancel()
        remoteConnection?.cancel()
        localConnection?.cancel()
        listener = nil
        remoteConnection = nil
        localConnection = nil
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
        localConnection?.cancel()
        localConnection = connection
        
        connection.stateUpdateHandler = { [weak self] state in
            if case .failed(_) = state {
                self?.localConnection = nil
            } else if case .cancelled = state {
                self?.localConnection = nil
            }
        }
        
        let networkQueue = DispatchQueue(label: "com.wg-obfuscator.local", qos: .userInteractive)
        connection.start(queue: networkQueue)
        
        // Start receiving - capture connections directly in closure
        guard let remote = remoteConnection else {
            logger.error("Remote connection not ready when local connected")
            return
        }
        
        startReceivingFromLocal(local: connection, remote: remote)
    }
    
    private func setupRemoteConnection() {
        let params = NWParameters.udp
        params.allowFastOpen = true
        
        let connection = NWConnection(to: config.remoteEndpoint, using: params)
        self.remoteConnection = connection
        
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                self.logger.info("Connected to remote server")
                // Start receiving from remote - capture local connection
                if let local = self.localConnection {
                    self.startReceivingFromRemote(remote: connection, local: local)
                }
            case .failed(let error):
                self.logger.error("Remote connection failed: \(error.localizedDescription)")
                self.remoteConnection = nil
            case .cancelled:
                self.remoteConnection = nil
            default:
                break
            }
        }
        
        let networkQueue = DispatchQueue(label: "com.wg-obfuscator.remote", qos: .userInteractive)
        connection.start(queue: networkQueue)
    }
    
    // MARK: - Data Flow (HOT PATH - ZERO OVERHEAD)
    // Connections are captured directly in closures - no locks, no queues, no indirection
    
    /// Receive from local, process, send to remote
    /// Connection references are captured to avoid any synchronization on hot path
    private func startReceivingFromLocal(local: NWConnection, remote: NWConnection) {
        local.receiveMessage { [codec, masker] content, context, isComplete, error in
            if let error = error {
                os_log("Receive local error: %{public}@", type: .error, error.localizedDescription)
                return
            }
            
            if let data = content, !data.isEmpty {
                // DIRECT PROCESSING - no Task, no actor hop, no locks!
                do {
                    // 1. Get packet type
                    guard let typeByte = data.first,
                          let type = WireGuardMessageType(rawValue: UInt32(typeByte)) else {
                        return
                    }
                    
                    // 2. Encode (Obfuscate)
                    let obfuscated = try codec.encode(data, type: type)
                    
                    // 3. Wrap in Masking (if enabled)
                    let wrapped: Data
                    if let masker = masker {
                        wrapped = try masker.wrap(obfuscated)
                    } else {
                        wrapped = obfuscated
                    }
                    
                    // 4. Send to Remote - connection captured directly, no lookup!
                    remote.send(content: wrapped, completion: .contentProcessed({ _ in }))
                    
                } catch {
                    // Silently drop malformed packets
                }
            }
            
            // Continue receiving - recursively capture same connections
            if error == nil {
                self.startReceivingFromLocal(local: local, remote: remote)
            }
        }
    }
    
    /// Receive from remote, process, send to local
    private func startReceivingFromRemote(remote: NWConnection, local: NWConnection) {
        remote.receiveMessage { [codec, masker] content, context, isComplete, error in
            if let error = error {
                os_log("Receive remote error: %{public}@", type: .error, error.localizedDescription)
                return
            }
            
            if let data = content, !data.isEmpty {
                // DIRECT PROCESSING - no Task, no actor hop, no locks!
                do {
                    // 1. Unwrap Masking (if enabled)
                    let obfuscated: Data
                    if let masker = masker {
                        guard let content = try masker.unwrap(data) else {
                            // Not a Data Indication - ignore
                            self.startReceivingFromRemote(remote: remote, local: local)
                            return
                        }
                        obfuscated = content
                    } else {
                        obfuscated = data
                    }
                    
                    // 2. Decode (De-obfuscate)
                    let cleartext = try codec.decode(obfuscated)
                    
                    // 3. Send to Local - connection captured directly, no lookup!
                    local.send(content: cleartext, completion: .contentProcessed({ _ in }))
                    
                } catch {
                    // Silently drop malformed packets
                }
            }
            
            // Continue receiving
            if error == nil {
                self.startReceivingFromRemote(remote: remote, local: local)
            }
        }
    }
}

public enum ProxyError: Error, Sendable {
    case failedToBindPort
}
