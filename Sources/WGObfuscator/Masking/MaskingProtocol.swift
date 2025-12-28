import Foundation

/// Protocol for packet masking implementations (e.g., STUN)
/// Note: Methods are synchronous for performance - masking operations are stateless transformations
public protocol MaskingProvider: Sendable {
    /// Wrap obfuscated data in masking protocol
    func wrap(_ data: Data) throws -> Data
    
    /// Unwrap masking protocol to reveal obfuscated data
    /// Returns nil if packet should be handled separately (e.g., STUN binding requests)
    func unwrap(_ data: Data) throws -> Data?
    
    /// Generate keepalive packet for this masking protocol
    func generateKeepalive() -> Data?
    
    /// Timer interval for keepalive packets
    var timerInterval: Duration { get }
}
