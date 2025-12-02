import Foundation

/// Manages session state for a proxy client
public actor ClientSession {
    public let id: UUID
    public let createdAt: Date
    public var lastActivity: Date
    
    public init() {
        self.id = UUID()
        self.createdAt = Date()
        self.lastActivity = Date()
    }
    
    public func touch() {
        self.lastActivity = Date()
    }
}
