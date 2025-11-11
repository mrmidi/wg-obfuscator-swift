import Testing
import Foundation
@testable import WGObfuscator

/// Test suite for CryptoUtilities
struct CryptoUtilitiesTests {
    
    // MARK: - CRC8 Tests
    
    @Test("CRC8 calculation produces consistent results")
    func testCRC8Consistency() {
        let testData: UInt8 = 0x42
        let crc1 = CryptoUtilities.calculateCRC8(data: testData)
        let crc2 = CryptoUtilities.calculateCRC8(data: testData)
        
        #expect(crc1 == crc2, "CRC8 should be deterministic")
    }
    
    @Test("CRC8 produces different values for different inputs")
    func testCRC8Variation() {
        let crc1 = CryptoUtilities.calculateCRC8(data: 0x00)
        let crc2 = CryptoUtilities.calculateCRC8(data: 0xFF)
        
        #expect(crc1 != crc2, "Different inputs should produce different CRCs")
    }
    
    // MARK: - CRC32 Tests
    
    @Test("CRC32 calculation matches standard implementation")
    func testCRC32Known() {
        let testData = Data("123456789".utf8)
        let crc = CryptoUtilities.calculateCRC32(testData)
        
        // Known CRC32 value for "123456789"
        #expect(crc == 0xCBF43926, "CRC32 should match known value")
    }
    
    @Test("CRC32 empty data")
    func testCRC32Empty() {
        let emptyData = Data()
        let crc = CryptoUtilities.calculateCRC32(emptyData)
        
        #expect(crc == 0x00000000, "Empty data CRC32 should be 0")
    }
    
    // MARK: - Data Reading Tests
    
    @Test("Read UInt32 little-endian")
    func testReadUInt32LE() throws {
        var data = Data([0x01, 0x00, 0x00, 0x00])
        let value = try CryptoUtilities.readUInt32LE(from: data, at: 0)
        
        #expect(value == 1, "Should read little-endian UInt32")
        
        data = Data([0x00, 0x00, 0x00, 0x04])
        let value2 = try CryptoUtilities.readUInt32LE(from: data, at: 0)
        
        #expect(value2 == 0x04000000, "Should preserve byte order")
    }
    
    @Test("Read UInt16 little-endian")
    func testReadUInt16LE() throws {
        let data = Data([0x05, 0x00])
        let value = try CryptoUtilities.readUInt16LE(from: data, at: 0)
        
        #expect(value == 5, "Should read little-endian UInt16")
    }
    
    @Test("Read UInt32 big-endian")
    func testReadUInt32BE() throws {
        let data = Data([0x21, 0x12, 0xA4, 0x42]) // STUN magic cookie
        let value = try CryptoUtilities.readUInt32BE(from: data, at: 0)
        
        #expect(value == 0x2112A442, "Should read big-endian UInt32")
    }
    
    @Test("Read UInt16 big-endian")
    func testReadUInt16BE() throws {
        let data = Data([0x01, 0x15]) // STUN Data Indication type
        let value = try CryptoUtilities.readUInt16BE(from: data, at: 0)
        
        #expect(value == 0x0115, "Should read big-endian UInt16")
    }
    
    @Test("Read from insufficient data throws error")
    func testReadInsufficientData() {
        let data = Data([0x01, 0x02])
        
        #expect(throws: ObfuscationError.self) {
            _ = try CryptoUtilities.readUInt32LE(from: data, at: 0)
        }
    }
    
    // MARK: - Data Writing Tests
    
    @Test("Write UInt16 little-endian")
    func testWriteUInt16LE() {
        var data = Data([0x00, 0x00, 0xFF])
        CryptoUtilities.writeUInt16LE(0x1234, to: &data, at: 0)
        
        #expect(data[0] == 0x34, "LSB should be first")
        #expect(data[1] == 0x12, "MSB should be second")
        #expect(data[2] == 0xFF, "Rest should be unchanged")
    }
    
    @Test("Write UInt16 big-endian")
    func testWriteUInt16BE() {
        var data = Data([0x00, 0x00, 0xFF])
        CryptoUtilities.writeUInt16BE(0x1234, to: &data, at: 0)
        
        #expect(data[0] == 0x12, "MSB should be first")
        #expect(data[1] == 0x34, "LSB should be second")
        #expect(data[2] == 0xFF, "Rest should be unchanged")
    }
    
    @Test("Write UInt32 big-endian")
    func testWriteUInt32BE() {
        var data = Data([0x00, 0x00, 0x00, 0x00, 0xFF])
        CryptoUtilities.writeUInt32BE(0x2112A442, to: &data, at: 0)
        
        #expect(data[0] == 0x21, "First byte correct")
        #expect(data[1] == 0x12, "Second byte correct")
        #expect(data[2] == 0xA4, "Third byte correct")
        #expect(data[3] == 0x42, "Fourth byte correct")
        #expect(data[4] == 0xFF, "Rest unchanged")
    }
    
    // MARK: - Secure Random Tests
    
    @Test("Secure random generates correct length")
    func testSecureRandomLength() {
        let data = Data.secureRandom(count: 32)
        #expect(data.count == 32, "Should generate requested length")
    }
    
    @Test("Secure random generates different data")
    func testSecureRandomUnique() {
        let data1 = Data.secureRandom(count: 16)
        let data2 = Data.secureRandom(count: 16)
        
        #expect(data1 != data2, "Should generate unique random data")
    }
}
