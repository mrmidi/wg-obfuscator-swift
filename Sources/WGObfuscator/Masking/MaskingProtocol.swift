import Foundation

/// Protocol for packet masking implementations (e.g., STUN)
public protocol MaskingProvider: Sendable {
    /// Wrap obfuscated data in masking protocol
    func wrap(_ data: Data) async throws -> Data
    
    /// Unwrap masking protocol to reveal obfuscated data
    /// Returns nil if packet should be handled separately (e.g., STUN binding requests)
    func unwrap(_ data: Data) async throws -> Data?
    
    /// Generate keepalive packet for this masking protocol
    func generateKeepalive() async -> Data?
    
    /// Timer interval for keepalive packets
    var timerInterval: Duration { get }
}
