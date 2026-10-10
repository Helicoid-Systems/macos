import Foundation

/// Distinct lifecycle phases for the manager connection flow (C01–C03).
public enum ConnectionPhase: Hashable, Sendable {
    case notConfigured
    case connecting
    case needsVerification
    case verified
    case needsSignIn
    case pendingManagerApproval
    case signedIn
    case failed(ConnectionFailure)
}

public enum ConnectionFailure: Hashable, Sendable, Equatable {
    case invalidAddress(detail: String)
    case unreachable
    case identityChanged
    case identityUnverified
    case authenticationFailed(detail: String)
    case managerPendingApproval
    case managerDenied
    case engineUnavailable
    case serverContractUnavailable
    case cancelled
}

public extension ConnectionFailure {
    var title: String {
        switch self {
        case .invalidAddress: "Invalid address"
        case .unreachable: "Server unreachable"
        case .identityChanged: "Server identity changed"
        case .identityUnverified: "Server identity not verified"
        case .authenticationFailed: "Sign-in failed"
        case .managerPendingApproval: "Manager pending approval"
        case .managerDenied: "Manager denied"
        case .engineUnavailable: "Engine Unavailable"
        case .serverContractUnavailable: "Server contract unavailable"
        case .cancelled: "Cancelled"
        }
    }

    /// Honest explanation. Never claims success the product did not observe.
    var explanation: String {
        switch self {
        case .invalidAddress(let detail):
            detail
        case .unreachable:
            "The address did not answer. Check the server address and that the Helicoid server is running on your LAN."
        case .identityChanged:
            "The server presented a different identity than the one you trusted. Access is stopped. Contact IT to re-verify."
        case .identityUnverified:
            "This server is not verified yet. Compare the identity fingerprint through a trusted Helicoid Systems channel before trusting it."
        case .authenticationFailed(let detail):
            detail
        case .managerPendingApproval:
            "This management computer is waiting for administrator approval. No computer screens are available until an administrator approves it."
        case .managerDenied:
            "This management computer is not authorized. Contact IT."
        case .engineUnavailable:
            "The remote-view engine is not available in this build. No screen pixels are produced."
        case .serverContractUnavailable:
            "The server HTTP contract is not integrated in this build. Connection is intentionally unavailable rather than simulated."
        case .cancelled:
            "The connection attempt was cancelled."
        }
    }
}

/// Observation admission is separate from login and from OS desktop sessions.
public enum ObservationAdmission: Hashable, Sendable {
    case idle
    case requesting
    case admitted
    case denied(reason: String)
    case expired
}

/// Enrollment / identity competition outcome for a computer.
public enum ComputerIdentityState: Hashable, Sendable {
    case enrolled
    case pendingEnrollment
    case identityNeedsReview
    case quarantined
}
