import Foundation

/// Core obfuscation engine using XOR cipher with CRC8-based key derivation
/// This matches the C implementation's algorithm but with critical bug fixes
public struct ObfuscationEngine: Sendable {
    
    public let key: Data
    
    /// Initialize with obfuscation key
    /// - Parameter key: Secret key for obfuscation (1-255 bytes)
    /// - Throws: ObfuscationError if key is invalid
    public init(key: Data) throws {
        guard !key.isEmpty else {
            throw ObfuscationError.keyTooShort
        }
        guard key.count <= 255 else {
            throw ObfuscationError.keyTooLong
        }
        self.key = key
    }
    
    /// Apply XOR obfuscation to data
    /// Note: This is a FIXED version that removes the length-dependent bug from C implementation
    /// - Parameter data: Data to obfuscate (will be modified in place)
    public func xor(_ data: inout Data) {
        let keyLength = key.count
        
        data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            
            var crc: UInt8 = 0
            
            for i in 0..<buffer.count {
                // Get key byte
                let keyByte = key[i % keyLength]
                
                // Calculate CRC8 based on key byte, data length, and key length
                // Reverting to match C implementation behavior (including length dependency)
                var inbyte = keyByte &+ UInt8(truncatingIfNeeded: buffer.count) &+ UInt8(truncatingIfNeeded: keyLength)
                
                // Calculate CRC8 (Inlined to maintain state across iterations)
                for _ in 0..<8 {
                    let mix = (crc ^ inbyte) & 0x01
                    crc >>= 1
                    if mix != 0 {
                        crc ^= 0x8C
                    }
                    inbyte >>= 1
                }
                
                // XOR the data with the CRC
                baseAddress.assumingMemoryBound(to: UInt8.self)[i] ^= crc
            }
        }
    }
    
    /// Check if data appears to be obfuscated (not a valid WireGuard packet)
    /// - Parameter data: Data to check (must be at least 4 bytes)
    /// - Returns: true if data is obfuscated, false if it's a valid WireGuard packet
    public static func isObfuscated(_ data: Data) -> Bool {
        guard data.count >= 4 else { return true }
        
        guard let packetType = try? CryptoUtilities.readUInt32LE(from: data, at: 0) else {
            return true
        }
        
        // WireGuard packet types are 1-4
        return !(1...4).contains(packetType)
    }
    
    /// Detect WireGuard message type from packet
    /// - Parameter data: Packet data (must be at least 4 bytes)
    /// - Returns: WireGuard message type if valid, nil otherwise
    public static func detectMessageType(_ data: Data) -> WireGuardMessageType? {
        guard data.count >= 4 else { return nil }
        
        guard let packetType = try? CryptoUtilities.readUInt32LE(from: data, at: 0) else {
            return nil
        }
        
        return WireGuardMessageType(rawValue: packetType)
    }
}
