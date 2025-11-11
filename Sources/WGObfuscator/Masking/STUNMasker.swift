//
//  STUNMasker.swift
//  WGObfuscator
//
//  STUN masking implementation for WireGuard traffic obfuscation
//

import Foundation

/// Actor-based STUN masker for thread-safe packet wrapping/unwrapping
public actor STUNMasker: MaskingProvider {
    
    public init() {}
    
    /// Wrap WireGuard data in a STUN Data Indication packet (0x0115)
    /// - Parameter data: WireGuard packet to wrap
    /// - Returns: STUN Data Indication packet containing the data
    public func wrap(_ data: Data) async throws -> Data {
        guard !data.isEmpty else {
            throw STUNError.packetTooShort
        }
        
        // Create DATA attribute with the WireGuard payload
        let attribute = STUNAttribute(type: .data, value: data)
        
        // Create STUN Data Indication packet
        let packet = try STUNPacket(
            messageType: .dataIndication,
            attributes: [attribute]
        )
        
        return packet.serialize()
    }
    
    /// Unwrap WireGuard data from a STUN packet
    /// - Parameter data: STUN packet data
    /// - Returns: Extracted WireGuard data, or nil if not a Data Indication
    public func unwrap(_ data: Data) async throws -> Data? {
        // Check if this is a STUN packet
        guard STUNPacket.hasMagicCookie(data) else {
            return nil
        }
        
        // Parse the STUN packet
        let packet = try STUNPacket.parse(from: data)
        
        // Only unwrap Data Indication packets
        guard packet.messageType == .dataIndication else {
            // Other STUN types (binding requests/responses) should be handled separately
            return nil
        }
        
        // Find the DATA attribute (0x0013)
        guard let dataAttr = packet.attributes.first(where: { 
            $0.type == STUNAttributeType.data.rawValue 
        }) else {
            throw STUNError.malformedAttribute
        }
        
        return dataAttr.value
    }
    
    /// Generate a STUN Binding Request with FINGERPRINT for keepalive
    /// - Returns: STUN Binding Request packet
    public func generateKeepalive() async -> Data? {
        do {
            // Create empty binding request
            var packet = try STUNPacket(messageType: .bindingRequest)
            
            // Add FINGERPRINT attribute
            let packetData = packet.serialize()
            let fingerprint = calculateFingerprint(for: packetData)
            
            // Create new packet with fingerprint attribute
            let fingerprintAttr = STUNAttribute(type: .fingerprint, value: fingerprint)
            packet = try STUNPacket(
                messageType: .bindingRequest,
                transactionID: packet.transactionID,
                attributes: [fingerprintAttr]
            )
            
            return packet.serialize()
        } catch {
            return nil
        }
    }
    
    public nonisolated var timerInterval: Duration {
        .seconds(10)
    }
    
    // MARK: - Private Helpers
    
    /// Calculate STUN FINGERPRINT attribute per RFC 5389
    /// FINGERPRINT = CRC32(STUN message) XOR 0x5354554e
    private func calculateFingerprint(for data: Data) -> Data {
        let crc = CryptoUtilities.calculateCRC32(data)
        let fingerprint = crc ^ 0x5354554e
        
        // Return as big-endian 4 bytes
        var value = fingerprint.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
    
    /// Handle incoming STUN Binding Request and generate response
    /// - Parameters:
    ///   - request: Incoming STUN Binding Request
    ///   - sourceAddress: Source address to include in XOR-MAPPED-ADDRESS
    /// - Returns: STUN Binding Response packet
    public func handleBindingRequest(_ request: Data, sourceAddress: (host: String, port: UInt16)? = nil) async throws -> Data? {
        guard STUNPacket.hasMagicCookie(request) else {
            return nil
        }
        
        let packet = try STUNPacket.parse(from: request)
        
        guard packet.messageType == .bindingRequest else {
            return nil
        }
        
        // For now, just generate a simple Binding Response with the same transaction ID
        // In a full implementation, we would include XOR-MAPPED-ADDRESS attribute
        let response = try STUNPacket(
            messageType: .bindingResponse,
            transactionID: packet.transactionID,
            attributes: []
        )
        
        return response.serialize()
    }
}
