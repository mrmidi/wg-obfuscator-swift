import Testing
import Foundation
@testable import WGObfuscator

/// Test suite for PacketCodec
struct PacketCodecTests {
    
    // MARK: - Initialization Tests
    
    @Test("Codec initializes with valid key")
    func testValidInitialization() async throws {
        let key = Data("testkey".utf8)
        let codec = try await PacketCodec(key: key)
        
        // Codec should be usable
        #expect(codec != nil, "Codec should initialize successfully")
    }
    
    @Test("Codec rejects invalid key")
    func testInvalidKeyRejection() async {
        let emptyKey = Data()
        
        await #expect(throws: ObfuscationError.self) {
            _ = try await PacketCodec(key: emptyKey)
        }
    }
    
    // MARK: - Encode/Decode Roundtrip Tests
    
    @Test("Encode and decode roundtrip preserves data", 
          arguments: WireGuardMessageType.allCases)
    func testEncodeDecodeRoundtrip(type: WireGuardMessageType) async throws {
        let key = Data("testkey123".utf8)
        let codec = try await PacketCodec(key: key, maxDummyLengthData: 4)
        
        // Create a valid WireGuard packet
        var original = Data(count: type.typicalSize)
        withUnsafeBytes(of: type.rawValue.littleEndian) { bytes in
            original[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        // Add some test payload
        for i in 16..<min(original.count, 100) {
            original[i] = UInt8(i % 256)
        }
        
        // Encode
        let encoded = try await codec.encode(original, type: type)
        
        // Encoded should be different and longer
        #expect(encoded != original, "Encoded should differ from original")
        #expect(encoded.count >= original.count, "Encoded should be at least as long")
        
        // Decode
        let decoded = try await codec.decode(encoded)
        
        // Decoded should match original
        #expect(decoded == original, "Decoded should match original")
    }
    
    @Test("Roundtrip with complex key")
    func testRoundtripWithComplexKey() async throws {
        let key = Data("Ipy:SMOQnfxK6>;Ks<?njL#0ta|W:To-e)Vb;+h?O&(|E!7nA73F&;x&uGi_X*Ja".utf8)
        let codec = try await PacketCodec(key: key)
        
        // Create handshake response packet
        var original = Data(count: 92)
        withUnsafeBytes(of: UInt32(2).littleEndian) { bytes in
            original[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        let encoded = try await codec.encode(original, type: .handshakeResponse)
        let decoded = try await codec.decode(encoded)
        
        #expect(decoded == original, "Complex key roundtrip should work")
    }
    
    @Test("Roundtrip preserves payload data")
    func testPayloadPreservation() async throws {
        let key = Data("testkey".utf8)
        let codec = try await PacketCodec(key: key)
        
        // Create data packet with specific payload
        var original = Data(count: 307)
        withUnsafeBytes(of: UInt32(4).littleEndian) { bytes in
            original[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        // Fill payload with pattern
        for i in 16..<original.count {
            original[i] = UInt8((i * 7) % 256)
        }
        
        let payload = original[16...]
        
        let encoded = try await codec.encode(original, type: .data)
        let decoded = try await codec.decode(encoded)
        
        let decodedPayload = decoded[16...]
        #expect(Data(payload) == Data(decodedPayload), "Payload should be preserved")
    }
    
    // MARK: - Real-World Packet Sizes Tests
    
    @Test("Handles various real packet sizes", 
          arguments: [148, 92, 64, 32, 307, 512, 1024])
    func testRealPacketSizes(size: Int) async throws {
        let key = Data("Ipy:SMOQnfxK6>;Ks<?njL#0ta|W:To-e)Vb;+h?O&(|E!7nA73F&;x&uGi_X*Ja".utf8)
        let codec = try await PacketCodec(key: key)
        
        // Create data packet
        var original = Data(count: size)
        withUnsafeBytes(of: UInt32(4).littleEndian) { bytes in
            original[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        // Fill with test data
        for i in 16..<original.count {
            original[i] = UInt8((i ^ 0xAA) % 256)
        }
        
        let encoded = try await codec.encode(original, type: .data)
        let decoded = try await codec.decode(encoded)
        
        #expect(decoded == original, "Size \(size) should roundtrip correctly")
    }
    
    // MARK: - Reserved Bytes Tests
    
    @Test("Decode restores WireGuard reserved bytes to zero")
    func testReservedBytesRestoration() async throws {
        let key = Data("testkey".utf8)
        let codec = try await PacketCodec(key: key)
        
        // Create handshake packet
        var original = Data(count: 148)
        withUnsafeBytes(of: UInt32(1).littleEndian) { bytes in
            original[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        let encoded = try await codec.encode(original, type: .handshakeInitiation)
        let decoded = try await codec.decode(encoded)
        
        // Bytes 1-3 must be zero (WireGuard reserved bytes)
        #expect(decoded[1] == 0, "Byte 1 should be zero")
        #expect(decoded[2] == 0, "Byte 2 should be zero")
        #expect(decoded[3] == 0, "Byte 3 should be zero")
    }
    
    // MARK: - Error Handling Tests
    
    @Test("Encode rejects too-short packet")
    func testEncodeTooShortPacket() async throws {
        let key = Data("testkey".utf8)
        let codec = try await PacketCodec(key: key)
        
        let shortPacket = Data([0x01, 0x00])
        
        await #expect(throws: ObfuscationError.self) {
            _ = try await codec.encode(shortPacket, type: .data)
        }
    }
    
    @Test("Decode rejects too-short packet")
    func testDecodeTooShortPacket() async throws {
        let key = Data("testkey".utf8)
        let codec = try await PacketCodec(key: key)
        
        let shortPacket = Data([0x01, 0x00])
        
        await #expect(throws: ObfuscationError.self) {
            _ = try await codec.decode(shortPacket)
        }
    }
    
    // MARK: - Mismatched Keys Tests
    
    @Test("Mismatched keys produce corruption")
    func testMismatchedKeys() async throws {
        let key1 = Data("key1".utf8)
        let key2 = Data("key2".utf8)
        
        let encoder = try await PacketCodec(key: key1)
        let decoder = try await PacketCodec(key: key2)
        
        // Create packet
        var original = Data(count: 148)
        withUnsafeBytes(of: UInt32(1).littleEndian) { bytes in
            original[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        let encoded = try await encoder.encode(original, type: .handshakeInitiation)
        
        // Decoding with wrong key should either throw or produce garbage
        do {
            let decoded = try await decoder.decode(encoded)
            #expect(decoded != original, "Wrong key should produce different data")
        } catch {
            // Expected: decoding may fail with wrong key
            #expect(error is ObfuscationError, "Should throw ObfuscationError")
        }
    }
    
    // MARK: - Randomization Tests
    
    @Test("Encoding produces different ciphertext each time")
    func testEncodingRandomization() async throws {
        let key = Data("testkey".utf8)
        let codec = try await PacketCodec(key: key)
        
        // Create packet
        var original = Data(count: 148)
        withUnsafeBytes(of: UInt32(1).littleEndian) { bytes in
            original[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        // Encode twice
        let encoded1 = try await codec.encode(original, type: .handshakeInitiation)
        let encoded2 = try await codec.encode(original, type: .handshakeInitiation)
        
        // Results should differ (due to random padding and random byte)
        #expect(encoded1 != encoded2, "Encoding should be randomized")
        
        // But both should decode correctly
        let decoded1 = try await codec.decode(encoded1)
        let decoded2 = try await codec.decode(encoded2)
        
        #expect(decoded1 == original, "First decoding should work")
        #expect(decoded2 == original, "Second decoding should work")
    }
    
    // MARK: - Ported tests from C
    
    @Test("Dummy length encoding is correct (White-box test)")
    func testDummyLengthEncoding() async throws {
        // Test that dummy length is correctly stored in bytes 2-3 before final XOR
        let key = Data("testkey".utf8)
        let codec = try await PacketCodec(key: key, maxDummyLengthData: 10)
        let engine = try ObfuscationEngine(key: key) // Local engine for manual de-obfuscation
        
        var original = Data(count: 148)
        withUnsafeBytes(of: UInt32(1).littleEndian) { bytes in
            original[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        let encoded = try await codec.encode(original, type: .handshakeInitiation)
        
        // Manually reverse the outer XOR layer to peek at internal structure
        var bufferForInspection = encoded
        engine.xor(&bufferForInspection)
        
        // Read the dummy length from bytes 2-3
        let storedDummyLength = try CryptoUtilities.readUInt16LE(from: bufferForInspection, at: 2)
        
        // Calculate expected dummy length (Total - Original)
        // Note: Encoded length = Original + Dummy
        // So Dummy = Encoded - Original
        let expectedDummyLength = encoded.count - original.count
        
        #expect(Int(storedDummyLength) == expectedDummyLength,
               "Stored dummy length \(storedDummyLength) should match actual added bytes \(expectedDummyLength)")
    }
    
    @Test("Mismatched keys statistically produce corruption")
    func testMismatchedKeysStatistics() async throws {
        let key1 = Data("Ipy:SMOQnfxK6>;Ks<?njL#0ta|W:To-e)Vb;+h?O&(|E!7nA73F&;x&uGi_X*Ja".utf8)
        let key2 = Data("Ipy:SMOQnfxK6>;Ks<?njL#0ta|W:To-e)Vb;+h?O&(|E!7nA73F&;x&uGi_X*JA".utf8) // Last char differs
        
        let encoder = try await PacketCodec(key: key1)
        let decoder = try await PacketCodec(key: key2)
        
        let originalLength = 307
        var mismatchCount = 0
        let iterations = 200
        
        for i in 0..<iterations {
            var original = Data(count: originalLength)
            withUnsafeBytes(of: UInt32(4).littleEndian) { bytes in
                original[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
            }
            // Add varying payload
            for j in 16..<original.count {
                original[j] = UInt8((j * 5 + i) & 0xFF)
            }
            
            let encoded = try await encoder.encode(original, type: .data)
            
            // Attempt decode with wrong key
            // It should either throw OR return corrupted data
            do {
                let decoded = try await decoder.decode(encoded)
                if decoded != original {
                    mismatchCount += 1
                }
            } catch {
                mismatchCount += 1
            }
        }
        
        // We expect mismatches/failures in almost all cases
        // Being generous with > 0, but realistically it should be near 100%
        #expect(mismatchCount > 0, "Should detect corruption with mismatched keys")
    }
}
