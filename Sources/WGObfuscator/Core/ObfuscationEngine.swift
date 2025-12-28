import Foundation

/// Precomputed CRC8 lookup table using polynomial 0x8C
/// This eliminates the need for 8 iterations per byte
private let crc8LookupTable: [UInt8] = {
    var table = [UInt8](repeating: 0, count: 256)
    for i in 0..<256 {
        var crc: UInt8 = 0
        var byte = UInt8(i)
        for _ in 0..<8 {
            let mix = (crc ^ byte) & 0x01
            crc >>= 1
            if mix != 0 {
                crc ^= 0x8C
            }
            byte >>= 1
        }
        table[i] = crc
    }
    return table
}()

/// Core obfuscation engine using XOR cipher with CRC8-based key derivation
/// This matches the C implementation's algorithm but with critical bug fixes
/// Performance optimized with CRC8 lookup table and unsafe pointer access
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
    
    /// Apply XOR obfuscation to data using optimized CRC8 lookup table
    /// - Parameter data: Data to obfuscate (will be modified in place)
    @inline(__always)
    public func xor(_ data: inout Data) {
        let keyLength = key.count
        let dataLength = data.count
        
        // Use unsafe pointers for both key and data to eliminate subscript overhead
        key.withUnsafeBytes { keyBuffer in
            data.withUnsafeMutableBytes { dataBuffer in
                guard let keyPtr = keyBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                      let dataPtr = dataBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return
                }
                
                var crc: UInt8 = 0
                let lengthComponent = UInt8(truncatingIfNeeded: dataLength) &+ UInt8(truncatingIfNeeded: keyLength)
                
                for i in 0..<dataLength {
                    // Get key byte using direct pointer access (no bounds checking overhead)
                    let keyByte = keyPtr[i % keyLength]
                    
                    // Calculate input byte for CRC
                    let inbyte = keyByte &+ lengthComponent
                    
                    // CRC8 using lookup table - single array access instead of 8 iterations
                    // The CRC state is accumulated, so we XOR with previous CRC
                    crc = crc8LookupTable[Int(crc ^ inbyte)]
                    
                    // XOR the data with the CRC (direct pointer access)
                    dataPtr[i] ^= crc
                }
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
