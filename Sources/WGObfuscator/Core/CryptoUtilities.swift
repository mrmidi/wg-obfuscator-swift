import Foundation
#if canImport(Security)
import Security
#endif

/// CRC8 and CRC32 implementations for obfuscation
public struct CryptoUtilities: Sendable {
    
    // MARK: - CRC8
    
    /// Calculate CRC8 with custom initialization for obfuscation
    /// This matches the C implementation's algorithm
    public static func calculateCRC8(
        data: UInt8,
        iterations: Int = 8,
        polynomial: UInt8 = 0x8C
    ) -> UInt8 {
        var crc: UInt8 = 0
        var inbyte = data
        
        for _ in 0..<iterations {
            let mix = (crc ^ inbyte) & 0x01
            crc >>= 1
            if mix != 0 {
                crc ^= polynomial
            }
            inbyte >>= 1
        }
        
        return crc
    }
    
    // MARK: - CRC32
    
    /// Calculate CRC32 for STUN fingerprint
    /// Uses standard CRC32 algorithm with polynomial 0xEDB88320
    public static func calculateCRC32(_ data: Data) -> UInt32 {
        var crc: UInt32 = ~0
        
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                let mask = UInt32(bitPattern: -Int32(crc & 1))
                crc = (crc >> 1) ^ (0xEDB88320 & mask)
            }
        }
        
        return ~crc
    }
    
    // MARK: - Data Extensions
    
    /// Read little-endian UInt32 from data at offset
    public static func readUInt32LE(from data: Data, at offset: Int) throws -> UInt32 {
        guard offset + 4 <= data.count else {
            throw ObfuscationError.packetTooShort(expected: offset + 4, got: data.count)
        }
        
        return data.withUnsafeBytes { buffer in
            buffer.loadUnaligned(fromByteOffset: offset, as: UInt32.self).littleEndian
        }
    }
    
    /// Read little-endian UInt16 from data at offset
    public static func readUInt16LE(from data: Data, at offset: Int) throws -> UInt16 {
        guard offset + 2 <= data.count else {
            throw ObfuscationError.packetTooShort(expected: offset + 2, got: data.count)
        }
        
        return data.withUnsafeBytes { buffer in
            buffer.loadUnaligned(fromByteOffset: offset, as: UInt16.self).littleEndian
        }
    }
    
    /// Read big-endian UInt32 from data at offset
    public static func readUInt32BE(from data: Data, at offset: Int) throws -> UInt32 {
        guard offset + 4 <= data.count else {
            throw ObfuscationError.packetTooShort(expected: offset + 4, got: data.count)
        }
        
        return data.withUnsafeBytes { buffer in
            buffer.loadUnaligned(fromByteOffset: offset, as: UInt32.self).bigEndian
        }
    }
    
    /// Read big-endian UInt16 from data at offset
    public static func readUInt16BE(from data: Data, at offset: Int) throws -> UInt16 {
        guard offset + 2 <= data.count else {
            throw ObfuscationError.packetTooShort(expected: offset + 2, got: data.count)
        }
        
        return data.withUnsafeBytes { buffer in
            buffer.loadUnaligned(fromByteOffset: offset, as: UInt16.self).bigEndian
        }
    }
    
    /// Write little-endian UInt16 to data
    public static func writeUInt16LE(_ value: UInt16, to data: inout Data, at offset: Int) {
        let leValue = value.littleEndian
        withUnsafeBytes(of: leValue) { bytes in
            data.replaceSubrange(offset..<offset+2, with: bytes)
        }
    }
    
    /// Write big-endian UInt16 to data
    public static func writeUInt16BE(_ value: UInt16, to data: inout Data, at offset: Int) {
        let beValue = value.bigEndian
        withUnsafeBytes(of: beValue) { bytes in
            data.replaceSubrange(offset..<offset+2, with: bytes)
        }
    }
    
    /// Write big-endian UInt32 to data
    public static func writeUInt32BE(_ value: UInt32, to data: inout Data, at offset: Int) {
        let beValue = value.bigEndian
        withUnsafeBytes(of: beValue) { bytes in
            data.replaceSubrange(offset..<offset+4, with: bytes)
        }
    }
    
    // MARK: - Convenience Aliases
    
    /// Alias for readUInt16BE for STUN compatibility
    public static func readUInt16BigEndian(from data: Data, at offset: Int) throws -> UInt16 {
        try readUInt16BE(from: data, at: offset)
    }
    
    /// Alias for readUInt32BE for STUN compatibility
    public static func readUInt32BigEndian(from data: Data, at offset: Int) throws -> UInt32 {
        try readUInt32BE(from: data, at: offset)
    }
    
    /// Generate secure random data
    public static func generateSecureRandom(count: Int) throws -> Data {
        Data.secureRandom(count: count)
    }
}

// MARK: - Data Extension for Convenience

extension Data {
    /// Secure random data generation
    public static func secureRandom(count: Int) -> Data {
#if canImport(Security)
        var data = Data(count: count)
        let result = data.withUnsafeMutableBytes { buffer -> OSStatus in
            guard let baseAddress = buffer.baseAddress else {
                return errSecParam
            }
            return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }
        precondition(result == errSecSuccess, "Failed to generate random data")
        return data
#else
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<count).map { _ in
            UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
        }
        return Data(bytes)
#endif
    }
}
