//
//  STUNPacket.swift
//  WGObfuscator
//
//  STUN packet structure conforming to RFC 5389
//  https://tools.ietf.org/html/rfc5389
//

import Foundation

/// STUN message types used in the obfuscator
public enum STUNMessageType: UInt16, Sendable {
    case bindingRequest = 0x0001
    case bindingResponse = 0x0101
    case dataIndication = 0x0115
    
    var rawValueBigEndian: Data {
        var value = self.rawValue.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}

/// STUN attribute types
public enum STUNAttributeType: UInt16, Sendable {
    case xorMappedAddress = 0x0020
    case software = 0x8022
    case fingerprint = 0x8028
    case data = 0x0013
    
    var rawValueBigEndian: Data {
        var value = self.rawValue.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}

/// STUN packet structure with RFC 5389 compliance
public struct STUNPacket: Sendable {
    // STUN magic cookie as defined in RFC 5389
    public static let magicCookie: UInt32 = 0x2112A442
    
    /// Message type
    public let messageType: STUNMessageType
    
    /// Transaction ID (12 bytes)
    public let transactionID: Data
    
    /// Attributes contained in the packet
    public let attributes: [STUNAttribute]
    
    /// Initialize a STUN packet
    /// - Parameters:
    ///   - messageType: Type of STUN message
    ///   - transactionID: 12-byte transaction ID (generated if nil)
    ///   - attributes: Optional attributes to include
    public init(messageType: STUNMessageType, transactionID: Data? = nil, attributes: [STUNAttribute] = []) throws {
        self.messageType = messageType
        
        if let txID = transactionID {
            guard txID.count == 12 else {
                throw STUNError.invalidTransactionID
            }
            self.transactionID = txID
        } else {
            self.transactionID = try CryptoUtilities.generateSecureRandom(count: 12)
        }
        
        self.attributes = attributes
    }
    
    /// Parse a STUN packet from data
    /// - Parameter data: Raw packet data
    /// - Returns: Parsed STUN packet
    public static func parse(from data: Data) throws -> STUNPacket {
        guard data.count >= 20 else {
            throw STUNError.packetTooShort
        }
        
        // Parse message type
        let typeValue = try CryptoUtilities.readUInt16BigEndian(from: data, at: 0)
        guard let messageType = STUNMessageType(rawValue: typeValue) else {
            throw STUNError.unknownMessageType(typeValue)
        }
        
        // Parse message length
        let messageLength = try CryptoUtilities.readUInt16BigEndian(from: data, at: 2)
        guard data.count >= 20 + Int(messageLength) else {
            throw STUNError.packetTooShort
        }
        
        // Verify magic cookie
        let cookie = try CryptoUtilities.readUInt32BigEndian(from: data, at: 4)
        guard cookie == magicCookie else {
            throw STUNError.invalidMagicCookie
        }
        
        // Extract transaction ID
        let transactionID = data.subdata(in: 8..<20)
        
        // Parse attributes
        var attributes: [STUNAttribute] = []
        var offset = 20
        
        while offset < data.count && offset < 20 + Int(messageLength) {
            let attrType = try CryptoUtilities.readUInt16BigEndian(from: data, at: offset)
            let attrLength = try CryptoUtilities.readUInt16BigEndian(from: data, at: offset + 2)
            
            let attrValueStart = offset + 4
            let attrValueEnd = attrValueStart + Int(attrLength)
            
            guard attrValueEnd <= data.count else {
                throw STUNError.malformedAttribute
            }
            
            let attrValue = data.subdata(in: attrValueStart..<attrValueEnd)
            attributes.append(STUNAttribute(type: attrType, value: attrValue))
            
            // Attributes are padded to 4-byte boundaries
            let padding = (4 - (Int(attrLength) % 4)) % 4
            offset = attrValueEnd + padding
        }
        
        return try STUNPacket(messageType: messageType, transactionID: transactionID, attributes: attributes)
    }
    
    /// Serialize the STUN packet to data
    public func serialize() -> Data {
        var result = Data()
        
        // Calculate message length (sum of all attribute lengths including headers and padding)
        var messageLength = 0
        for attr in attributes {
            messageLength += 4 + attr.value.count // 4 bytes header + value length
            let padding = (4 - (attr.value.count % 4)) % 4
            messageLength += padding
        }
        
        // Write message type (2 bytes)
        result.append(messageType.rawValueBigEndian)
        
        // Write message length (2 bytes)
        var msgLen = UInt16(messageLength).bigEndian
        result.append(contentsOf: withUnsafeBytes(of: &msgLen) { Data($0) })
        
        // Write magic cookie (4 bytes)
        var cookie = Self.magicCookie.bigEndian
        result.append(contentsOf: withUnsafeBytes(of: &cookie) { Data($0) })
        
        // Write transaction ID (12 bytes)
        result.append(transactionID)
        
        // Write attributes
        for attr in attributes {
            // Attribute type (2 bytes)
            var attrType = attr.type.bigEndian
            result.append(contentsOf: withUnsafeBytes(of: &attrType) { Data($0) })
            
            // Attribute length (2 bytes)
            var attrLength = UInt16(attr.value.count).bigEndian
            result.append(contentsOf: withUnsafeBytes(of: &attrLength) { Data($0) })
            
            // Attribute value
            result.append(attr.value)
            
            // Padding to 4-byte boundary
            let padding = (4 - (attr.value.count % 4)) % 4
            if padding > 0 {
                result.append(Data(count: padding))
            }
        }
        
        return result
    }
    
    /// Check if data contains a valid STUN magic cookie
    public static func hasMagicCookie(_ data: Data) -> Bool {
        guard data.count >= 8 else { return false }
        guard let cookie = try? CryptoUtilities.readUInt32BigEndian(from: data, at: 4) else {
            return false
        }
        return cookie == magicCookie
    }
    
    /// Get the message type from raw packet data without full parsing
    public static func peekMessageType(_ data: Data) throws -> STUNMessageType {
        guard data.count >= 2 else {
            throw STUNError.packetTooShort
        }
        let typeValue = try CryptoUtilities.readUInt16BigEndian(from: data, at: 0)
        guard let messageType = STUNMessageType(rawValue: typeValue) else {
            throw STUNError.unknownMessageType(typeValue)
        }
        return messageType
    }
}

/// STUN attribute structure
public struct STUNAttribute: Sendable {
    public let type: UInt16
    public let value: Data
    
    public init(type: UInt16, value: Data) {
        self.type = type
        self.value = value
    }
    
    public init(type: STUNAttributeType, value: Data) {
        self.type = type.rawValue
        self.value = value
    }
}

/// Errors specific to STUN packet handling
public enum STUNError: Error, Sendable, Equatable {
    case packetTooShort
    case invalidMagicCookie
    case invalidTransactionID
    case unknownMessageType(UInt16)
    case malformedAttribute
    case fingerprintMismatch
}
