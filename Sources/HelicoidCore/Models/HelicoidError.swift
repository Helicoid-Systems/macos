import Foundation

/// Errors surfaced by Helicoid Core. Every case has a user-visible honest state.
public enum HelicoidError: Error, Hashable, Sendable {
    case notConfigured
    case invalidInput(field: String, detail: String)
    case identityMismatch
    case permissionDenied(detail: String)
    case authenticationFailed(detail: String)
    case computerOutOfScope
    case engineUnavailable
    case serverContractUnavailable
    case setupBlocked(reason: String)
    case hostIdentityUnverified
    case installNotAvailable
    case unreachable
    case cancelled
    case offline

    public var title: String {
        switch self {
        case .notConfigured: "Not configured"
        case .invalidInput: "Invalid input"
        case .identityMismatch: "Identity mismatch"
        case .permissionDenied: "Permission denied"
        case .authenticationFailed: "Sign-in failed"
        case .computerOutOfScope: "Computer out of scope"
        case .engineUnavailable: "Engine Unavailable"
        case .serverContractUnavailable: "Server contract unavailable"
        case .setupBlocked: "Setup blocked"
        case .hostIdentityUnverified: "Host identity not verified"
        case .installNotAvailable: "Install not available"
        case .unreachable: "Server unreachable"
        case .cancelled: "Cancelled"
        case .offline: "Offline"
        }
    }

    public var explanation: String {
        switch self {
        case .notConfigured:
            "Connect to a Helicoid server first. No deployment is configured yet."
        case .invalidInput(let field, let detail):
            "\(field): \(detail)"
        case .identityMismatch:
            "The verified identity does not match the stored trust. Access is stopped."
        case .permissionDenied(let detail):
            detail
        case .authenticationFailed(let detail):
            detail
        case .computerOutOfScope:
            "This computer is outside the account access scope."
        case .engineUnavailable:
            "The remote-view engine is not available. No screen pixels are produced by this build."
        case .serverContractUnavailable:
            "The server connection is not available. Production mode stays closed until a trusted server identity is implemented."
        case .setupBlocked(let reason):
            reason
        case .hostIdentityUnverified:
            "Verify the SSH host identity before any write. A changed key or refusal performs no writes."
        case .installNotAvailable:
            "Installation is not performed by this build. Server packages are not integrated, so setup will not claim a successful install."
        case .unreachable:
            "The address did not answer. Check the server address and that the Helicoid server is running."
        case .cancelled:
            "The operation was cancelled before its stated boundary."
        case .offline:
            "The computer or server is offline."
        }
    }
}
