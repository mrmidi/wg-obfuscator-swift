import Foundation
import Network

/// Simple NAT table to map local endpoints to remote sessions
public actor NATTable {
    
    private var mappings: [NWEndpoint: ClientSession] = [:]
    
    public init() {}
    
    public func getSession(for endpoint: NWEndpoint) -> ClientSession? {
        return mappings[endpoint]
    }
    
    public func createSession(for endpoint: NWEndpoint) -> ClientSession {
        if let existing = mappings[endpoint] {
            return existing
        }
        let newSession = ClientSession()
        mappings[endpoint] = newSession
        return newSession
    }
    
    public func removeSession(for endpoint: NWEndpoint) {
        mappings.removeValue(forKey: endpoint)
    }
}
