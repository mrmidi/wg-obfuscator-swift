import Testing
import Foundation
@testable import WGObfuscator

/// Test suite for ObfuscationEngine
struct ObfuscationEngineTests {
    
    // MARK: - Initialization Tests
    
    @Test("Engine initializes with valid key")
    func testValidKeyInitialization() throws {
        let key = Data("testkey".utf8)
        let engine = try ObfuscationEngine(key: key)
        
        #expect(engine.key == key, "Key should be stored correctly")
    }
    
    @Test("Engine rejects empty key")
    func testEmptyKeyRejection() {
        let emptyKey = Data()
        
        #expect(throws: ObfuscationError.self) {
            _ = try ObfuscationEngine(key: emptyKey)
        }
    }
    
    @Test("Engine rejects too long key")
    func testTooLongKeyRejection() {
        let longKey = Data(repeating: 0x42, count: 256)
        
        #expect(throws: ObfuscationError.self) {
            _ = try ObfuscationEngine(key: longKey)
        }
    }
    
    @Test("Engine accepts maximum key length")
    func testMaximumKeyLength() throws {
        let maxKey = Data(repeating: 0x42, count: 255)
        let engine = try ObfuscationEngine(key: maxKey)
        
        #expect(engine.key.count == 255, "Should accept 255-byte key")
    }
    
    @Test("Engine preserves complex keys")
    func testComplexKeyStorage() throws {
        // Test that complex key with special characters is stored properly
        let keyString = "Ipy:SMOQnfxK6>;Ks<?njL#0ta|W:To-e)Vb;+h?O&(|E!7nA73F&;x&uGi_X*Ja"
        let key = Data(keyString.utf8)
        let engine = try ObfuscationEngine(key: key)
        
        #expect(engine.key == key, "Key should be stored exactly as provided")
        #expect(engine.key.count == 64, "Key length should be 64")
        
        // Verify specific bytes to ensure no encoding issues
        #expect(engine.key[0] == UInt8(ascii: "I"), "First char should match")
        #expect(engine.key[63] == UInt8(ascii: "a"), "Last char should match")
    }
    
    // MARK: - XOR Tests
    
    @Test("XOR is reversible")
    func testXORReversibility() throws {
        let key = Data("testkey123".utf8)
        let engine = try ObfuscationEngine(key: key)
        
        let original = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        var encrypted = original
        
        // Encrypt
        engine.xor(&encrypted)
        #expect(encrypted != original, "XOR should modify data")
        
        // Decrypt
        engine.xor(&encrypted)
        #expect(encrypted == original, "XOR should be reversible")
    }
    
    @Test("XOR with different keys produces different results")
    func testDifferentKeysProduceDifferentResults() throws {
        let key1 = Data("key1".utf8)
        let key2 = Data("key2".utf8)
        
        let engine1 = try ObfuscationEngine(key: key1)
        let engine2 = try ObfuscationEngine(key: key2)
        
        let original = Data(repeating: 0xAA, count: 16)
        var encrypted1 = original
        var encrypted2 = original
        
        engine1.xor(&encrypted1)
        engine2.xor(&encrypted2)
        
        #expect(encrypted1 != encrypted2, "Different keys should produce different ciphertext")
    }
    
    @Test("XOR is deterministic for same length")
    func testXORDeterminism() throws {
        // This test verifies that XOR produces consistent results for the same input
        // Note: The implementation intentionally includes buffer length in CRC calculation
        let key = Data("Ipy:SMOQnfxK6>;Ks<?njL#0ta|W:To-e)Vb;+h?O&(|E!7nA73F&;x&uGi_X*Ja".utf8)
        let engine = try ObfuscationEngine(key: key)
        
        // Create two identical data buffers of the SAME length
        var data1 = Data(repeating: 0xAA, count: 307)
        var data2 = Data(repeating: 0xAA, count: 307)
        
        // XOR both
        engine.xor(&data1)
        engine.xor(&data2)
        
        // They should be IDENTICAL since same input produces same output
        #expect(data1 == data2, "XOR should be deterministic for same input")
        
        // Verify that different lengths produce different results (expected behavior)
        var data3 = Data(repeating: 0xAA, count: 400)
        engine.xor(&data3)
        
        let prefix1 = data1.prefix(307)
        let prefix3 = data3.prefix(307)
        
        #expect(prefix1 != prefix3, "XOR should be length-dependent (matches C implementation)")
    }
    
    // MARK: - Obfuscation Detection Tests
    
    @Test("Detects valid WireGuard packets as non-obfuscated")
    func testValidWireGuardDetection() {
        // Test all valid WireGuard message types
        for typeValue: UInt32 in 1...4 {
            var data = Data(count: 148)
            withUnsafeBytes(of: typeValue.littleEndian) { bytes in
                data[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
            }
            
            #expect(!ObfuscationEngine.isObfuscated(data), 
                   "Type \(typeValue) should be detected as valid WireGuard")
        }
    }
    
    @Test("Detects invalid packet types as obfuscated")
    func testInvalidPacketDetection() {
        let invalidTypes: [UInt32] = [0, 5, 0xFF, 0xDEADBEEF]
        
        for typeValue in invalidTypes {
            var data = Data(count: 148)
            withUnsafeBytes(of: typeValue.littleEndian) { bytes in
                data[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
            }
            
            #expect(ObfuscationEngine.isObfuscated(data), 
                   "Type \(typeValue) should be detected as obfuscated")
        }
    }
    
    @Test("Detects too-short packets as obfuscated")
    func testShortPacketDetection() {
        let shortData = Data([0x01, 0x00])
        #expect(ObfuscationEngine.isObfuscated(shortData), 
               "Short packet should be detected as obfuscated")
    }
    
    // MARK: - Message Type Detection Tests
    
    @Test("Detects handshake initiation")
    func testHandshakeInitiationDetection() {
        var data = Data(count: 148)
        let typeValue: UInt32 = 1
        withUnsafeBytes(of: typeValue.littleEndian) { bytes in
            data[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        let detected = ObfuscationEngine.detectMessageType(data)
        #expect(detected == .handshakeInitiation, "Should detect handshake initiation")
    }
    
    @Test("Detects handshake response")
    func testHandshakeResponseDetection() {
        var data = Data(count: 92)
        let typeValue: UInt32 = 2
        withUnsafeBytes(of: typeValue.littleEndian) { bytes in
            data[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        let detected = ObfuscationEngine.detectMessageType(data)
        #expect(detected == .handshakeResponse, "Should detect handshake response")
    }
    
    @Test("Detects data packets")
    func testDataPacketDetection() {
        var data = Data(count: 148)
        let typeValue: UInt32 = 4
        withUnsafeBytes(of: typeValue.littleEndian) { bytes in
            data[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        let detected = ObfuscationEngine.detectMessageType(data)
        #expect(detected == .data, "Should detect data packet")
    }
    
    @Test("Returns nil for invalid message type")
    func testInvalidMessageType() {
        var data = Data(count: 148)
        let typeValue: UInt32 = 99
        withUnsafeBytes(of: typeValue.littleEndian) { bytes in
            data[0..<4] = Data(bytes.bindMemory(to: UInt8.self))
        }
        
        let detected = ObfuscationEngine.detectMessageType(data)
        #expect(detected == nil, "Should return nil for invalid type")
    }
}
