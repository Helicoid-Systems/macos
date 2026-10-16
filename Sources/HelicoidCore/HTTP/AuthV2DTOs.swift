import Foundation

/// Wire types for the frozen v2 device-key challenge login extension.
/// Do not invent fields beyond `http-v2.md` and `native-auth-contract.md`.

public struct AuthChallengeBeginRequestDTO: Codable, Sendable, Equatable {
    public let username: String
    public let password: String
    public let operation: String
    public let managerPublicKey: String

    enum CodingKeys: String, CodingKey {
        case username
        case password
        case operation
        case managerPublicKey = "manager_public_key"
    }

    public init(username: String, password: String, operation: String, managerPublicKey: String) {
        self.username = username
        self.password = password
        self.operation = operation
        self.managerPublicKey = managerPublicKey
    }
}

public struct AuthChallengeBeginResponseDTO: Codable, Sendable, Equatable {
    public let challengeID: String
    public let challengeToken: String
    public let operation: String
    public let managerPublicKey: String
    public let deploymentID: String
    public let expiresAtUnix: Int
    /// Server-derived. Missing means required (never optional).
    public let mfaRequired: Bool?

    enum CodingKeys: String, CodingKey {
        case challengeID = "challenge_id"
        case challengeToken = "challenge_token"
        case operation
        case managerPublicKey = "manager_public_key"
        case deploymentID = "deployment_id"
        case expiresAtUnix = "expires_at_unix"
        case mfaRequired = "mfa_required"
    }

    public init(
        challengeID: String,
        challengeToken: String,
        operation: String,
        managerPublicKey: String,
        deploymentID: String,
        expiresAtUnix: Int,
        mfaRequired: Bool? = nil
    ) {
        self.challengeID = challengeID
        self.challengeToken = challengeToken
        self.operation = operation
        self.managerPublicKey = managerPublicKey
        self.deploymentID = deploymentID
        self.expiresAtUnix = expiresAtUnix
        self.mfaRequired = mfaRequired
    }
}

public struct AuthChallengeCompleteRequestDTO: Codable, Sendable, Equatable {
    public let challengeID: String
    public let challengeToken: String
    public let managerSignature: String
    public let totpCode: String?

    enum CodingKeys: String, CodingKey {
        case challengeID = "challenge_id"
        case challengeToken = "challenge_token"
        case managerSignature = "manager_signature"
        case totpCode = "totp_code"
    }

    public init(challengeID: String, challengeToken: String, managerSignature: String, totpCode: String? = nil) {
        self.challengeID = challengeID
        self.challengeToken = challengeToken
        self.managerSignature = managerSignature
        self.totpCode = totpCode
    }
}


/// Successful v2 challenge completion (contract revision 2).
/// Reuses LoginResponse fields and adds completion-only top-level
/// `manager_public_key` sourced from the final approved-key transaction.
/// `manager.public_identity` remains a display identity (bootstrap uses
/// `key:<hex>`) and is never cryptographic key authority.
public struct AuthChallengeCompleteResponseDTO: Codable, Sendable, Equatable {
    public let token: String
    public let expiresAtUnix: Int?
    public let account: AccountDTO
    public let manager: ManagerDTO?
    public let mfa: MFADTO?
    public let managerPublicKey: String

    enum CodingKeys: String, CodingKey {
        case token
        case expiresAtUnix = "expires_at_unix"
        case account
        case manager
        case mfa
        case managerPublicKey = "manager_public_key"
    }

    public init(
        token: String,
        expiresAtUnix: Int? = nil,
        account: AccountDTO,
        manager: ManagerDTO? = nil,
        mfa: MFADTO? = nil,
        managerPublicKey: String
    ) {
        self.token = token
        self.expiresAtUnix = expiresAtUnix
        self.account = account
        self.manager = manager
        self.mfa = mfa
        self.managerPublicKey = managerPublicKey
    }
}
