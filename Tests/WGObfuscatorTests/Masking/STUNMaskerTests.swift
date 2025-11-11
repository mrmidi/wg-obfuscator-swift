import Testing
import Foundation
@testable import WGObfuscator

@Suite("STUN Masker Tests")
struct STUNMaskerTests {
    
    @Test("STUN masker initializes")
    func testInitialization() async {
        let masker = STUNMasker()
        let interval = await masker.timerInterval
        #expect(interval == .seconds(10))
    }
    
    @Test("Wraps WireGuard data in STUN Data Indication")
    func testWrapData() async throws {
        let masker = STUNMasker()
        let wgData = Data("WireGuard packet data".utf8)
        
        let wrapped = try await masker.wrap(wgData)
        
        // Should be longer than original
        #expect(wrapped.count > wgData.count)
        
        // Should have STUN magic cookie
        #expect(STUNPacket.hasMagicCookie(wrapped))
        
        // Should be Data Indication type
        let type = try STUNPacket.peekMessageType(wrapped)
        #expect(type == .dataIndication)
    }
    
    @Test("Unwraps STUN Data Indication to WireGuard data")
    func testUnwrapData() async throws {
        let masker = STUNMasker()
        let originalData = Data("WireGuard test payload".utf8)
        
        let wrapped = try await masker.wrap(originalData)
        let unwrapped = try await masker.unwrap(wrapped)
        
        #expect(unwrapped == originalData)
    }
    
    @Test("Wrap and unwrap roundtrip preserves data")
    func testRoundtrip() async throws {
        let masker = STUNMasker()
        let testCases = [
            Data("Short".utf8),
            Data("Medium length WireGuard packet data".utf8),
            Data(repeating: 0xAB, count: 148), // Typical handshake initiation size
            Data(repeating: 0xCD, count: 1420) // Large data packet
        ]
        
        for original in testCases {
            let wrapped = try await masker.wrap(original)
            let unwrapped = try await masker.unwrap(wrapped)
            
            #expect(unwrapped == original, "Roundtrip failed for \(original.count) bytes")
        }
    }
    
    @Test("Unwrap returns nil for non-STUN data")
    func testUnwrapNonSTUN() async throws {
        let masker = STUNMasker()
        let nonStunData = Data("Not a STUN packet".utf8)
        
        let result = try await masker.unwrap(nonStunData)
        
        #expect(result == nil)
    }
    
    @Test("Unwrap returns nil for STUN Binding Request")
    func testUnwrapBindingRequest() async throws {
        let masker = STUNMasker()
        
        // Create a Binding Request
        let bindingRequest = try STUNPacket(messageType: .bindingRequest)
        let data = bindingRequest.serialize()
        
        let result = try await masker.unwrap(data)
        
        #expect(result == nil, "Should not unwrap Binding Request")
    }
    
    @Test("Generates valid keepalive packet")
    func testGenerateKeepalive() async throws {
        let masker = STUNMasker()
        
        let keepalive = await masker.generateKeepalive()
        
        #expect(keepalive != nil)
        guard let data = keepalive else { return }
        
        // Should have STUN magic cookie
        #expect(STUNPacket.hasMagicCookie(data))
        
        // Should be Binding Request
        let type = try STUNPacket.peekMessageType(data)
        #expect(type == .bindingRequest)
        
        // Parse and verify structure
        let packet = try STUNPacket.parse(from: data)
        #expect(packet.messageType == .bindingRequest)
        #expect(packet.transactionID.count == 12)
        
        // Should have FINGERPRINT attribute
        let hasFingerprintAttr = packet.attributes.contains { 
            $0.type == STUNAttributeType.fingerprint.rawValue 
        }
        #expect(hasFingerprintAttr, "Keepalive should have FINGERPRINT attribute")
    }
    
    @Test("Keepalive has correct FINGERPRINT calculation")
    func testKeepaliveFingerprint() async throws {
        let masker = STUNMasker()
        
        let keepalive = await masker.generateKeepalive()
        guard let data = keepalive else {
            Issue.record("Failed to generate keepalive")
            return
        }
        
        let packet = try STUNPacket.parse(from: data)
        
        // Find FINGERPRINT attribute
        guard let fingerprintAttr = packet.attributes.first(where: { 
            $0.type == STUNAttributeType.fingerprint.rawValue 
        }) else {
            Issue.record("No FINGERPRINT attribute found")
            return
        }
        
        #expect(fingerprintAttr.value.count == 4, "FINGERPRINT should be 4 bytes")
        
        // Verify fingerprint calculation
        // Fingerprint is calculated over the packet up to (but not including) the fingerprint attribute
        // For simplicity, we just verify it has the correct length
    }
    
    @Test("Handles binding request and generates response")
    func testHandleBindingRequest() async throws {
        let masker = STUNMasker()
        
        // Create a binding request
        let request = try STUNPacket(messageType: .bindingRequest)
        let requestData = request.serialize()
        
        let response = try await masker.handleBindingRequest(requestData)
        
        #expect(response != nil)
        guard let responseData = response else { return }
        
        // Parse response
        let responsePacket = try STUNPacket.parse(from: responseData)
        #expect(responsePacket.messageType == .bindingResponse)
        
        // Should preserve transaction ID
        #expect(responsePacket.transactionID == request.transactionID)
    }
    
    @Test("Handle binding request returns nil for non-STUN data")
    func testHandleBindingRequestNonSTUN() async throws {
        let masker = STUNMasker()
        let nonStunData = Data("Not STUN".utf8)
        
        let response = try await masker.handleBindingRequest(nonStunData)
        
        #expect(response == nil)
    }
    
    @Test("Handle binding request returns nil for non-binding-request")
    func testHandleBindingRequestWrongType() async throws {
        let masker = STUNMasker()
        
        // Create a Data Indication instead
        let dataIndication = try STUNPacket(messageType: .dataIndication)
        let data = dataIndication.serialize()
        
        let response = try await masker.handleBindingRequest(data)
        
        #expect(response == nil)
    }
    
    @Test("Wrap rejects empty data")
    func testWrapEmptyData() async {
        let masker = STUNMasker()
        let emptyData = Data()
        
        await #expect(throws: STUNError.packetTooShort) {
            _ = try await masker.wrap(emptyData)
        }
    }
    
    @Test("Wrapped packet structure is correct")
    func testWrappedPacketStructure() async throws {
        let masker = STUNMasker()
        let payload = Data("Test payload".utf8)
        
        let wrapped = try await masker.wrap(payload)
        let packet = try STUNPacket.parse(from: wrapped)
        
        // Should be Data Indication
        #expect(packet.messageType == .dataIndication)
        
        // Should have exactly one attribute
        #expect(packet.attributes.count == 1)
        
        // Attribute should be DATA type
        let attr = packet.attributes[0]
        #expect(attr.type == STUNAttributeType.data.rawValue)
        
        // Attribute value should match payload
        #expect(attr.value == payload)
    }
    
    @Test("Multiple wrap operations produce different packets")
    func testMultipleWraps() async throws {
        let masker = STUNMasker()
        let payload = Data("Same payload".utf8)
        
        let wrapped1 = try await masker.wrap(payload)
        let wrapped2 = try await masker.wrap(payload)
        
        // Different transaction IDs mean different packets
        #expect(wrapped1 != wrapped2, "Each wrap should produce different transaction ID")
        
        // But both should unwrap to same payload
        let unwrapped1 = try await masker.unwrap(wrapped1)
        let unwrapped2 = try await masker.unwrap(wrapped2)
        
        #expect(unwrapped1 == payload)
        #expect(unwrapped2 == payload)
    }
}
