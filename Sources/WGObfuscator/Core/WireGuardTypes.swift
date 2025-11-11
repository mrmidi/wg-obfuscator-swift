import Foundation

/// WireGuard message types as defined in the protocol
/// These are the first 4 bytes of every WireGuard packet (little-endian u32)
public enum WireGuardMessageType: UInt32, Sendable, CaseIterable {
    case handshakeInitiation = 1
    case handshakeResponse = 2
    case cookie = 3
    case data = 4
    
    /// Maximum dummy length for handshake packets
    public var maxDummyLength: Int {
        switch self {
        case .handshakeInitiation, .handshakeResponse:
            return 512
        case .cookie, .data:
            return 4 // Configurable, but default is 4
        }
    }
    
    /// Typical packet sizes for this message type
    public var typicalSize: Int {
        switch self {
        case .handshakeInitiation:
            return 148
        case .handshakeResponse:
            return 92
        case .cookie:
            return 64
        case .data:
            return 32 // Minimum, varies with payload
        }
    }
}

/// Errors that can occur during obfuscation/deobfuscation
public enum ObfuscationError: Error, Sendable, CustomStringConvertible {
    case invalidPacketType
    case packetTooShort(expected: Int, got: Int)
    case keyTooLong
    case keyTooShort
    case decodingFailed(reason: String)
    case maskingFailed(reason: String)
    case invalidWireGuardPacket
    
    public var description: String {
        switch self {
        case .invalidPacketType:
            return "Invalid WireGuard packet type (must be 1-4)"
        case .packetTooShort(let expected, let got):
            return "Packet too short: expected at least \(expected) bytes, got \(got)"
        case .keyTooLong:
            return "Obfuscation key too long (max 255 bytes)"
        case .keyTooShort:
            return "Obfuscation key too short (min 1 byte)"
        case .decodingFailed(let reason):
            return "Decoding failed: \(reason)"
        case .maskingFailed(let reason):
            return "Masking failed: \(reason)"
        case .invalidWireGuardPacket:
            return "Invalid WireGuard packet structure"
        }
    }
}

/// Maximum packet size including dummy data
public let maxDummyLengthTotal = 1024

/// Maximum dummy length for handshake packets
public let maxDummyLengthHandshake = 512

/// Default maximum dummy length for data packets
public let maxDummyLengthDataDefault = 4

/// Buffer size for packet processing
public let bufferSize = 65535

/// Current obfuscation protocol version
public let obfuscationVersion: UInt8 = 1
