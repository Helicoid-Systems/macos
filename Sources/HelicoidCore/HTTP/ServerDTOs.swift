import Foundation

/// Bounded DTOs for the HS Server HTTP contract version 1.
/// Do not invent fields beyond `Resources/Contracts/http-v1.md`.

public struct ServerErrorEnvelope: Codable, Sendable, Equatable {
    public struct Body: Codable, Sendable, Equatable {
        public let code: String
        public let message: String
        public let detail: String?

        public init(code: String, message: String, detail: String? = nil) {
            self.code = code
            self.message = message
            self.detail = detail
        }
    }

    public let error: Body

    public init(error: Body) {
        self.error = error
    }
}

public struct HealthDTO: Codable, Sendable, Equatable {
    public let status: String
    public let acceptingAuthorizedOperations: Bool
    public let schemaVersion: Int
    public let bootstrapCompleted: Bool
    public let features: [String: Bool]

    enum CodingKeys: String, CodingKey {
        case status
        case acceptingAuthorizedOperations = "accepting_authorized_operations"
        case schemaVersion = "schema_version"
        case bootstrapCompleted = "bootstrap_completed"
        case features
    }

    public init(
        status: String,
        acceptingAuthorizedOperations: Bool,
        schemaVersion: Int,
        bootstrapCompleted: Bool,
        features: [String: Bool]
    ) {
        self.status = status
        self.acceptingAuthorizedOperations = acceptingAuthorizedOperations
        self.schemaVersion = schemaVersion
        self.bootstrapCompleted = bootstrapCompleted
        self.features = features
    }
}

public struct AccountCapabilitiesDTO: Codable, Sendable, Equatable {
    public let operate: Bool?
    public let manageEnrollment: Bool?
    public let manageAccess: Bool?
    public let manageAccounts: Bool?
    public let manageSecurity: Bool?

    enum CodingKeys: String, CodingKey {
        case operate
        case manageEnrollment = "manage_enrollment"
        case manageAccess = "manage_access"
        case manageAccounts = "manage_accounts"
        case manageSecurity = "manage_security"
    }

    public init(
        operate: Bool? = nil,
        manageEnrollment: Bool? = nil,
        manageAccess: Bool? = nil,
        manageAccounts: Bool? = nil,
        manageSecurity: Bool? = nil
    ) {
        self.operate = operate
        self.manageEnrollment = manageEnrollment
        self.manageAccess = manageAccess
        self.manageAccounts = manageAccounts
        self.manageSecurity = manageSecurity
    }
}

public struct AccountDTO: Codable, Sendable, Equatable {
    public let id: String
    public let username: String
    public let state: String
    public let capabilities: AccountCapabilitiesDTO?
    public let revision: Int?

    public init(
        id: String,
        username: String,
        state: String,
        capabilities: AccountCapabilitiesDTO? = nil,
        revision: Int? = nil
    ) {
        self.id = id
        self.username = username
        self.state = state
        self.capabilities = capabilities
        self.revision = revision
    }
}

public struct ManagerDTO: Codable, Sendable, Equatable {
    public let id: String
    public let publicIdentity: String
    public let friendlyName: String?
    public let lifecycleState: String
    public let approvedAtUnix: Int?

    enum CodingKeys: String, CodingKey {
        case id
        case publicIdentity = "public_identity"
        case friendlyName = "friendly_name"
        case lifecycleState = "lifecycle_state"
        case approvedAtUnix = "approved_at_unix"
    }

    public init(
        id: String,
        publicIdentity: String,
        friendlyName: String? = nil,
        lifecycleState: String,
        approvedAtUnix: Int? = nil
    ) {
        self.id = id
        self.publicIdentity = publicIdentity
        self.friendlyName = friendlyName
        self.lifecycleState = lifecycleState
        self.approvedAtUnix = approvedAtUnix
    }

    public var isApproved: Bool { lifecycleState == "approved" }
    public var isPending: Bool { lifecycleState == "pending" }
    public var isRevoked: Bool { lifecycleState == "revoked" }
}

public struct MFADTO: Codable, Sendable, Equatable {
    public let required: Bool
    public let available: Bool
    public let reason: String?

    public init(required: Bool, available: Bool, reason: String? = nil) {
        self.required = required
        self.available = available
        self.reason = reason
    }
}

public struct LoginResponseDTO: Codable, Sendable, Equatable {
    public let token: String
    public let expiresAtUnix: Int?
    public let account: AccountDTO
    public let manager: ManagerDTO?
    public let mfa: MFADTO?

    enum CodingKeys: String, CodingKey {
        case token
        case expiresAtUnix = "expires_at_unix"
        case account
        case manager
        case mfa
    }

    public init(
        token: String,
        expiresAtUnix: Int? = nil,
        account: AccountDTO,
        manager: ManagerDTO? = nil,
        mfa: MFADTO? = nil
    ) {
        self.token = token
        self.expiresAtUnix = expiresAtUnix
        self.account = account
        self.manager = manager
        self.mfa = mfa
    }
}

public struct SessionResponseDTO: Codable, Sendable, Equatable {
    public let account: AccountDTO
    public let manager: ManagerDTO?
    public let expiresAtUnix: Int?

    enum CodingKeys: String, CodingKey {
        case account
        case manager
        case expiresAtUnix = "expires_at_unix"
    }

    public init(account: AccountDTO, manager: ManagerDTO? = nil, expiresAtUnix: Int? = nil) {
        self.account = account
        self.manager = manager
        self.expiresAtUnix = expiresAtUnix
    }
}

public struct ComputerDTO: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let publicIdentity: String
    public let friendlyName: String?
    public let platform: String?
    public let enrollmentState: String
    public let enrollmentEpoch: Int?

    enum CodingKeys: String, CodingKey {
        case id
        case publicIdentity = "public_identity"
        case friendlyName = "friendly_name"
        case platform
        case enrollmentState = "enrollment_state"
        case enrollmentEpoch = "enrollment_epoch"
    }

    public init(
        id: String,
        publicIdentity: String,
        friendlyName: String? = nil,
        platform: String? = nil,
        enrollmentState: String,
        enrollmentEpoch: Int? = nil
    ) {
        self.id = id
        self.publicIdentity = publicIdentity
        self.friendlyName = friendlyName
        self.platform = platform
        self.enrollmentState = enrollmentState
        self.enrollmentEpoch = enrollmentEpoch
    }
}

public struct InventoryResponseDTO: Codable, Sendable, Equatable {
    public let computers: [ComputerDTO]
    public let scopeIsExplicit: Bool?
    public let maxPageSize: Int?

    enum CodingKeys: String, CodingKey {
        case computers
        case scopeIsExplicit = "scope_is_explicit"
        case maxPageSize = "max_page_size"
    }

    public init(computers: [ComputerDTO], scopeIsExplicit: Bool? = nil, maxPageSize: Int? = nil) {
        self.computers = computers
        self.scopeIsExplicit = scopeIsExplicit
        self.maxPageSize = maxPageSize
    }
}

/// Placeholder for 204/empty JSON responses.
public struct EmptySuccessDTO: Codable, Sendable, Equatable {
    public init() {}
}

/// Result of a single HTTP call after status and decode checks.
public enum HTTPCallOutcome<Value: Sendable>: Sendable {
    case success(Value)
    case failure(HelicoidError)
}
