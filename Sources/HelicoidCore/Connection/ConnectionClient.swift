import Foundation

/// Result of validating a server address before any connection attempt.
public struct AddressValidation: Hashable, Sendable {
    public enum Outcome: Hashable, Sendable {
        case ok
        case invalid(detail: String)
    }

    public let outcome: Outcome

    public init(outcome: Outcome) {
        self.outcome = outcome
    }

    public var isOK: Bool {
        if case .ok = outcome { return true }
        return false
    }
}

/// Connection client boundary.
///
/// This is the only seam the macOS apps use to reach a Helicoid server.
/// Server HTTP routes are not invented here. When
/// `modules/server/contracts/http-v1.md` is published, a concrete client
/// can implement this protocol without changing UI code.
public protocol ConnectionClient: Sendable {
    /// Validate address/schema before connecting. Discovery never establishes trust.
    func validateAddress(_ address: String) async -> AddressValidation

    /// Attempt connection. On success returns the identity that must be verified.
    func connect(address: String) async -> Result<ServerIdentity, HelicoidError>

    /// Trust a verified identity. A later changed identity must stop access.
    func trust(identity: ServerIdentity, address: String) async -> Result<Void, HelicoidError>

    /// Sign in with a local organization account.
    func signIn(username: String, password: String) async -> Result<OperatorID, HelicoidError>

    /// Resolve authorized inventory after sign-in. Never invents computers.
    func authorizedInventory() async -> Result<[Computer], HelicoidError>

    /// Manager approval state for the current management computer.
    func managerApprovalState() async -> Result<ManagerApprovalState, HelicoidError>

    /// Release scoped session material. Does not invent server logout routes.
    func signOut() async
}

public enum ManagerApprovalState: String, Hashable, Sendable {
    case approved
    case pending
    case denied
    case unknown
}

/// Default production boundary. Reports honest unavailability until the server contract is integrated.
public struct UnavailableConnectionClient: ConnectionClient {
    public init() {}

    public func validateAddress(_ address: String) async -> AddressValidation {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return AddressValidation(outcome: .invalid(detail: "Enter a server address."))
        }
        if trimmed.contains(" ") {
            return AddressValidation(outcome: .invalid(detail: "A server address cannot contain spaces."))
        }
        // Schema checks only. Discovery/network reachability is not trust.
        let knownSchemes = ["http://", "https://"]
        let hasScheme = knownSchemes.contains { trimmed.lowercased().hasPrefix($0) }
        let hostPart = hasScheme
            ? String(trimmed.drop(while: { $0 != "/" && !$0.isWhitespace }).dropFirst(2))
            : trimmed
        _ = hostPart
        return AddressValidation(outcome: .ok)
    }

    public func connect(address: String) async -> Result<ServerIdentity, HelicoidError> {
        let validation = await validateAddress(address)
        if case .invalid(let detail) = validation.outcome {
            return .failure(.invalidInput(field: "Server address", detail: detail))
        }
        // Production path stays closed. Never invent a server identity or fingerprint.
        return .failure(.serverContractUnavailable)
    }

    public func trust(identity: ServerIdentity, address: String) async -> Result<Void, HelicoidError> {
        _ = identity
        _ = address
        return .failure(.serverContractUnavailable)
    }

    public func signIn(username: String, password: String) async -> Result<OperatorID, HelicoidError> {
        _ = username
        _ = password
        return .failure(.serverContractUnavailable)
    }

    public func authorizedInventory() async -> Result<[Computer], HelicoidError> {
        .success([])
    }

    public func managerApprovalState() async -> Result<ManagerApprovalState, HelicoidError> {
        .success(.unknown)
    }

    public func signOut() async {}
}
