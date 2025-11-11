import Foundation

/// Actor-based packet codec for encoding and decoding WireGuard packets
/// Provides thread-safe encode/decode operations
public actor PacketCodec {
    
    private let engine: ObfuscationEngine
    private let maxDummyLengthData: Int
    
    /// Initialize packet codec
    /// - Parameters:
    ///   - key: Obfuscation key (1-255 bytes)
    ///   - maxDummyLengthData: Maximum dummy padding for data packets (default: 4)
    /// - Throws: ObfuscationError if key is invalid
    public init(key: Data, maxDummyLengthData: Int = maxDummyLengthDataDefault) throws {
        self.engine = try ObfuscationEngine(key: key)
        self.maxDummyLengthData = maxDummyLengthData
    }
    
    /// Encode a WireGuard packet with obfuscation
    /// - Parameters:
    ///   - packet: Original WireGuard packet data
    ///   - type: WireGuard message type
    /// - Returns: Obfuscated packet data
    /// - Throws: ObfuscationError if encoding fails
    public func encode(_ packet: Data, type: WireGuardMessageType) async throws -> Data {
        guard packet.count >= 4 else {
            throw ObfuscationError.packetTooShort(expected: 4, got: packet.count)
        }
        
        var buffer = packet
        
        // 1. Generate random byte for header obfuscation
        let randomByte = UInt8.random(in: 1...255)
        
        // 2. XOR first byte with random value
        buffer[0] ^= randomByte
        
        // 3. Store random byte in second position
        buffer[1] = randomByte
        
        // 4. Calculate and add dummy padding
        let dummyLength = calculateDummyLength(for: type, currentLength: buffer.count)
        
        // Store dummy length in bytes 2-3 (little-endian)
        CryptoUtilities.writeUInt16LE(UInt16(dummyLength), to: &buffer, at: 2)
        
        // Append dummy data (filled with 0xFF)
        if dummyLength > 0 {
            buffer.append(Data(repeating: 0xFF, count: dummyLength))
        }
        
        // 5. Apply XOR obfuscation to entire packet
        var mutableBuffer = buffer
        engine.xor(&mutableBuffer)
        
        return mutableBuffer
    }
    
    /// Decode an obfuscated packet
    /// - Parameter packet: Obfuscated packet data
    /// - Returns: Original WireGuard packet data
    /// - Throws: ObfuscationError if decoding fails
    public func decode(_ packet: Data) async throws -> Data {
        guard packet.count >= 4 else {
            throw ObfuscationError.packetTooShort(expected: 4, got: packet.count)
        }
        
        var buffer = packet
        
        // 1. Apply XOR deobfuscation
        engine.xor(&buffer)
        
        // 2. Check if it was actually obfuscated
        if !ObfuscationEngine.isObfuscated(buffer) {
            // This is an old version or unobfuscated packet
            // Return as-is after XOR reversal
            return packet
        }
        
        // 3. Restore first byte by XORing with second byte
        buffer[0] ^= buffer[1]
        
        // 4. Read dummy length from bytes 2-3
        let dummyLength = try CryptoUtilities.readUInt16LE(from: buffer, at: 2)
        
        // 5. Validate dummy length
        guard dummyLength <= buffer.count - 4 else {
            throw ObfuscationError.decodingFailed(
                reason: "Invalid dummy length: \(dummyLength) for packet size \(buffer.count)"
            )
        }
        
        // 6. Remove dummy padding
        let originalLength = buffer.count - Int(dummyLength)
        buffer = buffer.prefix(originalLength)
        
        // 7. Zero out reserved bytes (1-3) per WireGuard protocol
        buffer[1] = 0
        buffer[2] = 0
        buffer[3] = 0
        
        // 8. Verify it's a valid WireGuard packet now
        guard ObfuscationEngine.detectMessageType(buffer) != nil else {
            throw ObfuscationError.invalidWireGuardPacket
        }
        
        return buffer
    }
    
    // MARK: - Private Helpers
    
    private func calculateDummyLength(for type: WireGuardMessageType, currentLength: Int) -> Int {
        guard currentLength < maxDummyLengthTotal else {
            return 0
        }
        
        let maxDummy = maxDummyLengthTotal - currentLength
        
        switch type {
        case .handshakeInitiation, .handshakeResponse:
            let limit = min(maxDummy, maxDummyLengthHandshake)
            return Int.random(in: 0...limit)
            
        case .cookie, .data:
            guard maxDummyLengthData > 0 else { return 0 }
            let limit = min(maxDummy, maxDummyLengthData)
            return Int.random(in: 0...limit)
        }
    }
}
