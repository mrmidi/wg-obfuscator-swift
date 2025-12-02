import Foundation
import Network
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
    private let logger = Logger(subsystem: "com.wg-obfuscator", category: "UDPProxy")
    
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
                self.logger.error("Receive local error: \(error.localizedDescription)")
                return
            }
            
            if let data = content, !data.isEmpty {
                Task {
                    do {
                        // 1. Encode (Obfuscate)
                        // Note: We assume 'data' is a standard WireGuard packet.
                        // We need to determine the type. For simplicity, we might try to guess or track state.
                        // However, PacketCodec.encode requires a type.
                        // WireGuard first byte:
                        // 1 = Handshake Initiation
                        // 2 = Handshake Response
                        // 3 = Cookie Reply
                        // 4 = Transport Data
                        
                        guard let typeByte = data.first,
                              let type = WireGuardMessageType(rawValue: typeByte) else {
                            self.logger.error("Unknown WireGuard packet type: \(data.first ?? 0)")
                            return
                        }
                        
                        let obfuscated = try await self.codec.encode(data, type: type)
                        
                        // 2. Wrap in STUN (if needed - assuming yes for now based on requirements)
                        let wrapped = try await self.stunMasker.wrap(obfuscated)
                        
                        // 3. Send to Remote
                        if let remote = self.remoteConnection {
                            remote.send(content: wrapped, completion: .contentProcessed({ error in
                                if let error = error {
                                    self.logger.error("Send remote error: \(error.localizedDescription)")
                                }
                            }))
                        }
                        
                    } catch {
                        self.logger.error("Obfuscation error: \(error.localizedDescription)")
                    }
                }
            }
            
            // Continue receiving
            if error == nil {
                self.receiveFromLocal(connection)
            }
        }
    }
    
    /// Receive obfuscated packets from Remote, De-obfuscate, Send to Local
    private func receiveFromRemote(_ connection: NWConnection) {
        connection.receiveMessage { [weak self] content, context, isComplete, error in
            guard let self = self else { return }
            
            if let error = error {
                self.logger.error("Receive remote error: \(error.localizedDescription)")
                return
            }
            
            if let data = content, !data.isEmpty {
                Task {
                    do {
                        // 1. Unwrap STUN
                        guard let obfuscated = try await self.stunMasker.unwrap(data) else {
                            // Not a data packet (maybe STUN keepalive response?), ignore
                            return
                        }
                        
                        // 2. Decode (De-obfuscate)
                        let cleartext = try await self.codec.decode(obfuscated)
                        
                        // 3. Send to Local (WireGuard)
                        if let local = self.localConnection {
                            local.send(content: cleartext, completion: .contentProcessed({ error in
                                if let error = error {
                                    self.logger.error("Send local error: \(error.localizedDescription)")
                                }
                            }))
                        }
                        
                    } catch {
                        self.logger.error("De-obfuscation error: \(error.localizedDescription)")
                    }
                }
            }
            
            // Continue receiving
            if error == nil {
                self.receiveFromRemote(connection)
            }
        }
    }
}

public enum ProxyError: Error {
    case failedToBindPort
}
