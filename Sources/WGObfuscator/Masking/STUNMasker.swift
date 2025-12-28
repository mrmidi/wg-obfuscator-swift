//
//  STUNMasker.swift
//  WGObfuscator
//
//  STUN masking implementation for WireGuard traffic obfuscation
//  Performance optimized: converted from actor to struct for hot-path operations
//

import Foundation

/// Thread-safe STUN masker for high-performance packet wrapping/unwrapping
/// Note: Converted from actor to struct - all operations are stateless transformations
public struct STUNMasker: MaskingProvider, Sendable {
    
    public init() {}
    
    /// Wrap WireGuard data in a STUN Data Indication packet (0x0115)
    /// - Parameter data: WireGuard packet to wrap
    /// - Returns: STUN Data Indication packet containing the data
    @inline(__always)
    public func wrap(_ data: Data) throws -> Data {
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
    /// Fast-path extraction for DATA attribute without full parsing when possible
    /// - Parameter data: STUN packet data
    /// - Returns: Extracted WireGuard data, or nil if not a Data Indication
    @inline(__always)
    public func unwrap(_ data: Data) throws -> Data? {
        // Fast check: is this even a STUN packet?
        guard data.count >= 24 else { return nil }  // 20 header + 4 attr header minimum
        
        // Check magic cookie without full parsing (bytes 4-7)
        guard STUNPacket.hasMagicCookie(data) else {
            return nil
        }
        
        // Fast-path: Check if it's a Data Indication (0x0115)
        let typeHigh = data[0]
        let typeLow = data[1]
        guard typeHigh == 0x01 && typeLow == 0x15 else {
            // Not a Data Indication - ignore (likely Binding Request/Response)
            return nil
        }
        
        // Fast-path DATA attribute extraction:
        // For Data Indication, DATA attribute (0x0013) should be first/only attribute
        // Attribute starts at offset 20 (after STUN header)
        let attrTypeHigh = data[20]
        let attrTypeLow = data[21]
        
        // Check if it's a DATA attribute (0x0013)
        if attrTypeHigh == 0x00 && attrTypeLow == 0x13 {
            // Read attribute length (bytes 22-23, big-endian)
            let attrLength = (UInt16(data[22]) << 8) | UInt16(data[23])
            
            let valueStart = 24
            let valueEnd = valueStart + Int(attrLength)
            
            guard valueEnd <= data.count else {
                throw STUNError.malformedAttribute
            }
            
            // Return the DATA value directly without allocating intermediate objects
            return data.subdata(in: valueStart..<valueEnd)
        }
        
        // Fallback to full parsing if fast-path doesn't match
        let packet = try STUNPacket.parse(from: data)
        
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
    public func generateKeepalive() -> Data? {
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
    
    public var timerInterval: Duration {
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
    public func handleBindingRequest(_ request: Data, sourceAddress: (host: String, port: UInt16)? = nil) throws -> Data? {
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
