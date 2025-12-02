import Foundation
import Network
import Logging
import os.log

/// UDP Proxy that sits between WireGuard (localhost) and the Remote Server.
/// It obfuscates outgoing traffic and de-obfuscates incoming traffic.
public actor UDPProxy {
    
    // MARK: - Configuration
    
    public struct Configuration: Sendable {
        /// The local port to listen on (0 for ephemeral)
        public let localPort: UInt16
        /// The remote server endpoint to forward obfuscated traffic to
        public let remoteEndpoint: NWEndpoint
        /// Obfuscation key
        public let key: Data
        
        public init(localPort: UInt16 = 0, remoteEndpoint: NWEndpoint, key: Data) {
            self.localPort = localPort
            self.remoteEndpoint = remoteEndpoint
            self.key = key
        }
    }
    
    // MARK: - Properties
    
    private let config: Configuration
    private let logger = Logger(label: "com.wg-obfuscator.UDPProxy")
    
    private var listener: NWListener?
    private var remoteConnection: NWConnection?
    private var localConnection: NWConnection?
    
    private let codec: PacketCodec
    private let stunMasker = STUNMasker()
    
    /// The port the proxy is actually listening on (valid after start)
    public var listeningPort: UInt16? {
        guard let endpoint = listener?.port else { return nil }
        return endpoint.rawValue
    }
    
    // MARK: - Initialization
    
    public init(configuration: Configuration) throws {
        self.config = configuration
        self.codec = try PacketCodec(key: configuration.key)
    }
    
    // MARK: - Lifecycle
    
    /// Start the proxy
    /// - Returns: The local port being listened on
    public func start() async throws -> UInt16 {
        logger.info("Starting UDP Proxy...")
        
        // 1. Setup Listener (Local side - receives from WireGuard)
        let listenerParams = NWParameters.udp
        listenerParams.allowLocalEndpointReuse = true
        
        // Only bind to localhost to avoid exposing the proxy externally
        if let localIP = IPv4Address("127.0.0.1") {
            let interface = NWInterface.InterfaceType.loopback
            listenerParams.requiredInterfaceType = interface
        }
        
        let listener = try NWListener(using: listenerParams, on: NWEndpoint.Port(integerLiteral: config.localPort))
        
        listener.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            Task { await self.handleListenerState(state) }
        }
        
        listener.newConnectionHandler = { [weak self] connection in
            guard let self = self else { return }
            Task { await self.handleNewLocalConnection(connection) }
        }
        
        listener.start(queue: .global())
        self.listener = listener
        
        // Wait for listener to be ready (simple polling for now, could be improved)
        // In a real actor, we might want to use a continuation, but for simplicity:
        while listener.state != .ready {
            if case .failed(let error) = listener.state {
                throw error
            }
            try await Task.sleep(nanoseconds: 100_000_000) // 100ms
        }
        
        guard let port = listener.port?.rawValue else {
            throw ProxyError.failedToBindPort
        }
        
        logger.info("UDP Proxy listening on 127.0.0.1:\(port)")
        
        // 2. Setup Remote Connection (Remote side - sends to Server)
        startRemoteConnection()
        
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
        // We only support one active WireGuard tunnel connection at a time for this simple proxy
        if let current = localConnection {
            logger.warning("Replacing existing local connection")
            current.cancel()
        }
        
        logger.info("New local connection from \(String(describing: connection.endpoint))")
        localConnection = connection
        
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            Task { await self.handleLocalConnectionState(state) }
        }
        
        connection.start(queue: .global())
        
        // Start receiving loop
        receiveFromLocal(connection)
    }
    
    private func handleLocalConnectionState(_ state: NWConnection.State) {
        switch state {
        case .failed(let error):
            logger.error("Local connection failed: \(error.localizedDescription)")
            localConnection = nil
        case .cancelled:
            localConnection = nil
        default:
            break
        }
    }
    
    private func startRemoteConnection() {
        let params = NWParameters.udp
        // Optimization: Fast open if possible
        params.allowFastOpen = true
        
        let connection = NWConnection(to: config.remoteEndpoint, using: params)
        self.remoteConnection = connection
        
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            Task { await self.handleRemoteConnectionState(state) }
        }
        
        connection.start(queue: .global())
        
        // Start receiving loop
        receiveFromRemote(connection)
    }
    
    private func handleRemoteConnectionState(_ state: NWConnection.State) {
        switch state {
        case .ready:
            logger.info("Connected to remote server")
        case .failed(let error):
            logger.error("Remote connection failed: \(error.localizedDescription)")
            // Simple reconnect logic could go here
            remoteConnection = nil
            // Try to reconnect after delay?
        case .cancelled:
            remoteConnection = nil
        default:
            break
        }
    }
    
    // MARK: - Data Flow
    
    /// Receive cleartext WireGuard packets from Local, Obfuscate, Send to Remote
    private func receiveFromLocal(_ connection: NWConnection) {
        connection.receiveMessage { [weak self] content, context, isComplete, error in
            guard let self = self else { return }
            
            if let error = error {
                Task { await self.logError("Receive local error: \(error.localizedDescription)") }
                return
            }
            
            if let data = content, !data.isEmpty {
                Task { await self.processLocalPacket(data) }
            }
            
            // Continue receiving
            if error == nil {
                self.receiveFromLocal(connection)
            }
        }
    }
    
    private func processLocalPacket(_ data: Data) async {
        do {
            // 1. Encode (Obfuscate)
            guard let typeByte = data.first,
                  let type = WireGuardMessageType(rawValue: UInt32(typeByte)) else {
                logger.error("Unknown WireGuard packet type: \(data.first ?? 0)")
                return
            }
            
            let obfuscated = try await self.codec.encode(data, type: type)
            
            // 2. Wrap in STUN (DISABLED - Server expects NONE)
            // let wrapped = try await self.stunMasker.wrap(obfuscated)
            let wrapped = obfuscated
            
            // 3. Send to Remote
            if let remote = self.remoteConnection {
                // logger.debug("Sending \(wrapped.count) bytes to remote (Type: \(type))")
                os_log("UDPProxy: -> Remote (%d bytes, Type: %d)", type: .debug, wrapped.count, typeByte)
                
                remote.send(content: wrapped, completion: .contentProcessed({ [weak self] error in
                    if let error = error {
                        Task { await self?.logError("Send remote error: \(error.localizedDescription)") }
                    }
                }))
            }
            
        } catch {
            logger.error("Obfuscation error: \(error.localizedDescription)")
        }
    }
    
    /// Receive obfuscated packets from Remote, De-obfuscate, Send to Local
    private func receiveFromRemote(_ connection: NWConnection) {
        connection.receiveMessage { [weak self] content, context, isComplete, error in
            guard let self = self else { return }
            
            if let error = error {
                Task { await self.logError("Receive remote error: \(error.localizedDescription)") }
                return
            }
            
            if let data = content, !data.isEmpty {
                Task { await self.processRemotePacket(data) }
            }
            
            // Continue receiving
            if error == nil {
                self.receiveFromRemote(connection)
            }
        }
    }
    
    private func processRemotePacket(_ data: Data) async {
        do {
            // 1. Unwrap STUN (DISABLED - Server expects NONE)
            // guard let obfuscated = try await self.stunMasker.unwrap(data) else {
            //    os_log("UDPProxy: Failed to unwrap STUN packet (%d bytes)", type: .debug, data.count)
            //    return
            // }
            let obfuscated = data
            
            // 2. Decode (De-obfuscate)
            let cleartext = try await self.codec.decode(obfuscated)
            
            // 3. Send to Local (WireGuard)
            if let local = self.localConnection {
                // logger.debug("Sending \(cleartext.count) bytes to local")
                os_log("UDPProxy: <- Remote (%d bytes)", type: .debug, cleartext.count)
                
                local.send(content: cleartext, completion: .contentProcessed({ [weak self] error in
                    if let error = error {
                        Task { await self?.logError("Send local error: \(error.localizedDescription)") }
                    }
                }))
            }
            
        } catch {
            logger.error("De-obfuscation error: \(error.localizedDescription)")
        }
    }
    
    private func logError(_ message: String) {
        logger.error("\(message)")
        os_log("UDPProxy Error: %{public}@", type: .error, message)
    }
}

public enum ProxyError: Error {
    case failedToBindPort
}
