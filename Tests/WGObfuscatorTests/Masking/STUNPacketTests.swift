import Testing
import Foundation
@testable import WGObfuscator

@Suite("STUN Packet Tests")
struct STUNPacketTests {
    
    @Test("Creates binding request with auto-generated transaction ID")
    func testBindingRequestCreation() throws {
        let packet = try STUNPacket(messageType: .bindingRequest)
        
        #expect(packet.messageType == .bindingRequest)
        #expect(packet.transactionID.count == 12)
        #expect(packet.attributes.isEmpty)
    }
    
    @Test("Creates packet with custom transaction ID")
    func testCustomTransactionID() throws {
        let txID = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 
                        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C])
        let packet = try STUNPacket(messageType: .dataIndication, transactionID: txID)
        
        #expect(packet.transactionID == txID)
    }
    
    @Test("Rejects invalid transaction ID length")
    func testInvalidTransactionID() async {
        let shortID = Data([0x01, 0x02, 0x03])
        
        await #expect(throws: STUNError.self) {
            _ = try STUNPacket(messageType: .bindingRequest, transactionID: shortID)
        }
    }
    
    @Test("Serializes binding request correctly")
    func testSerializeBindingRequest() throws {
        let txID = Data(repeating: 0xAB, count: 12)
        let packet = try STUNPacket(messageType: .bindingRequest, transactionID: txID)
        let data = packet.serialize()
        
        // Check header size (20 bytes for empty packet)
        #expect(data.count == 20)
        
        // Check message type (0x0001)
        #expect(data[0] == 0x00)
        #expect(data[1] == 0x01)
        
        // Check message length (0 for no attributes)
        #expect(data[2] == 0x00)
        #expect(data[3] == 0x00)
        
        // Check magic cookie (0x2112A442)
        #expect(data[4] == 0x21)
        #expect(data[5] == 0x12)
        #expect(data[6] == 0xA4)
        #expect(data[7] == 0x42)
        
        // Check transaction ID
        #expect(data.subdata(in: 8..<20) == txID)
    }
    
    @Test("Serializes data indication with attribute")
    func testSerializeDataIndication() throws {
        let payload = Data("Hello WireGuard".utf8)
        let attribute = STUNAttribute(type: .data, value: payload)
        let packet = try STUNPacket(messageType: .dataIndication, attributes: [attribute])
        
        let data = packet.serialize()
        
        // Header (20) + attr header (4) + payload (15) + padding (1) = 40 bytes
        #expect(data.count == 40)
        
        // Message type should be 0x0115
        #expect(data[0] == 0x01)
        #expect(data[1] == 0x15)
        
        // Message length should be 20 (attr header + payload + padding)
        let msgLen = Int(data[2]) << 8 | Int(data[3])
        #expect(msgLen == 20)
        
        // First attribute should be DATA (0x0013)
        #expect(data[20] == 0x00)
        #expect(data[21] == 0x13)
        
        // Attribute length should be 15
        let attrLen = Int(data[22]) << 8 | Int(data[23])
        #expect(attrLen == 15)
        
        // Payload should match
        let extractedPayload = data.subdata(in: 24..<39)
        #expect(extractedPayload == payload)
    }
    
    @Test("Parses valid STUN packet")
    func testParseValidPacket() throws {
        let txID = Data(repeating: 0xCD, count: 12)
        let original = try STUNPacket(messageType: .bindingResponse, transactionID: txID)
        let serialized = original.serialize()
        
        let parsed = try STUNPacket.parse(from: serialized)
        
        #expect(parsed.messageType == original.messageType)
        #expect(parsed.transactionID == original.transactionID)
        #expect(parsed.attributes.count == original.attributes.count)
    }
    
    @Test("Parses packet with attributes")
    func testParsePacketWithAttributes() throws {
        let payload = Data("Test data".utf8)
        let attr = STUNAttribute(type: .data, value: payload)
        let original = try STUNPacket(messageType: .dataIndication, attributes: [attr])
        
        let serialized = original.serialize()
        let parsed = try STUNPacket.parse(from: serialized)
        
        #expect(parsed.attributes.count == 1)
        #expect(parsed.attributes[0].type == STUNAttributeType.data.rawValue)
        #expect(parsed.attributes[0].value == payload)
    }
    
    @Test("Rejects packet that is too short")
    func testParsePacketTooShort() async {
        let shortData = Data([0x00, 0x01, 0x00])
        
        await #expect(throws: STUNError.packetTooShort) {
            _ = try STUNPacket.parse(from: shortData)
        }
    }
    
    @Test("Rejects packet with invalid magic cookie")
    func testParseInvalidMagicCookie() async {
        var data = Data(count: 20)
        data[0] = 0x00  // Binding request type
        data[1] = 0x01
        data[2] = 0x00  // Length 0
        data[3] = 0x00
        // Wrong magic cookie
        data[4] = 0xFF
        data[5] = 0xFF
        data[6] = 0xFF
        data[7] = 0xFF
        
        await #expect(throws: STUNError.invalidMagicCookie) {
            _ = try STUNPacket.parse(from: data)
        }
    }
    
    @Test("Rejects unknown message type")
    func testParseUnknownMessageType() async {
        var data = Data(count: 20)
        // Unknown type 0xFFFF
        data[0] = 0xFF
        data[1] = 0xFF
        data[2] = 0x00
        data[3] = 0x00
        // Valid magic cookie
        data[4] = 0x21
        data[5] = 0x12
        data[6] = 0xA4
        data[7] = 0x42
        
        await #expect(throws: STUNError.unknownMessageType(0xFFFF)) {
            _ = try STUNPacket.parse(from: data)
        }
    }
    
    @Test("Checks magic cookie correctly")
    func testHasMagicCookie() {
        var validData = Data(count: 20)
        validData[4] = 0x21
        validData[5] = 0x12
        validData[6] = 0xA4
        validData[7] = 0x42
        
        #expect(STUNPacket.hasMagicCookie(validData))
        
        var invalidData = Data(count: 20)
        invalidData[4] = 0xFF
        invalidData[5] = 0xFF
        invalidData[6] = 0xFF
        invalidData[7] = 0xFF
        
        #expect(!STUNPacket.hasMagicCookie(invalidData))
    }
    
    @Test("Peeks message type without full parse")
    func testPeekMessageType() throws {
        var data = Data(count: 20)
        data[0] = 0x01  // Data Indication
        data[1] = 0x15
        
        let type = try STUNPacket.peekMessageType(data)
        #expect(type == .dataIndication)
    }
    
    @Test("Roundtrip serialization preserves data")
    func testRoundtripSerialization() throws {
        let payload1 = Data("First attribute".utf8)
        let payload2 = Data("Second attribute".utf8)
        
        let original = try STUNPacket(
            messageType: .dataIndication,
            attributes: [
                STUNAttribute(type: .data, value: payload1),
                STUNAttribute(type: .software, value: payload2)
            ]
        )
        
        let serialized = original.serialize()
        let parsed = try STUNPacket.parse(from: serialized)
        
        #expect(parsed.messageType == original.messageType)
        #expect(parsed.transactionID == original.transactionID)
        #expect(parsed.attributes.count == 2)
        #expect(parsed.attributes[0].value == payload1)
        #expect(parsed.attributes[1].value == payload2)
    }
    
    @Test("Handles attribute padding correctly")
    func testAttributePadding() throws {
        // Test various payload sizes to verify 4-byte padding
        let sizes = [1, 2, 3, 4, 5, 6, 7, 8, 13, 15, 16, 17]
        
        for size in sizes {
            let payload = Data(repeating: 0xAB, count: size)
            let packet = try STUNPacket(
                messageType: .dataIndication,
                attributes: [STUNAttribute(type: .data, value: payload)]
            )
            
            let serialized = packet.serialize()
            let parsed = try STUNPacket.parse(from: serialized)
            
            #expect(parsed.attributes.count == 1)
            #expect(parsed.attributes[0].value == payload)
        }
    }
    
    @Test("Magic cookie constant is correct")
    func testMagicCookieValue() {
        #expect(STUNPacket.magicCookie == 0x2112A442)
    }
    
    @Test("Message type enums have correct values")
    func testMessageTypeValues() {
        #expect(STUNMessageType.bindingRequest.rawValue == 0x0001)
        #expect(STUNMessageType.bindingResponse.rawValue == 0x0101)
        #expect(STUNMessageType.dataIndication.rawValue == 0x0115)
    }
    
    @Test("Attribute type enums have correct values")
    func testAttributeTypeValues() {
        #expect(STUNAttributeType.xorMappedAddress.rawValue == 0x0020)
        #expect(STUNAttributeType.software.rawValue == 0x8022)
        #expect(STUNAttributeType.fingerprint.rawValue == 0x8028)
        #expect(STUNAttributeType.data.rawValue == 0x0013)
    }
}
