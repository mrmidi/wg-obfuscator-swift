import Foundation

// Masking factory - to be implemented
// Placeholder for now

public enum MaskingType: Sendable {
    case none
    case stun
    case auto
}

public struct MaskingFactory: Sendable {
    public static func create(_ type: MaskingType) -> (any MaskingProvider)? {
        switch type {
        case .none:
            return nil
        case .stun, .auto:
            return STUNMasker()
        }
    }
}
