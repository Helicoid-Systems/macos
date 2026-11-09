import CryptoKit
import Foundation

/// Explicit operator acknowledgement required before the client will return
/// first-administrator bootstrap secrets.
///
/// There is deliberately no default value: a caller must state that it will
/// keep the one-time TOTP secret and recovery codes in memory, show them once,
/// and store recovery codes independently before MFA confirmation.
public enum LocalBootstrapSecretAcknowledgement: Sendable {
    case operatorWillStoreMFASecretAndRecoveryCodesIndependently
}

/// Explicit acknowledgement that server-side MFA cancellation is destructive.
///
/// There is deliberately no default value. Cancelling the pending enrollment
/// invalidates the only first-administrator TOTP material; it is not a
/// harmless back-out.
public enum LocalBootstrapDestructiveCancellationAcknowledgement: Sendable {
    case cancelPendingServerEnrollmentAndDiscardSecrets
}

/// Explicit acknowledgement that local secrets will be discarded without
/// cancelling the server-side pending enrollment.
///
/// There is deliberately no default value. The server enrollment remains
/// pending and its one-time material becomes unusable to this client.
public enum LocalBootstrapDiscardAcknowledgement: Sendable {
    case discardLocalSecretsWithoutCancellingServerEnrollment
}

/// In-memory local lifecycle for the first-administrator bootstrap.
///
/// This state is not persisted. The client is intentionally poisoned after any
/// irreversible operation whose outcome is unknown. Create a new client only
/// after inspecting the server locally; do not retry the same bootstrap token.
public enum LocalBootstrapState: Sendable, Equatable {
    case idle
    case bootstrapInFlight
    case awaitingMFAConfirmation
    case confirmed
    case cancelled
    case discarded
    case bootstrapOutcomeUnknown
    case confirmationOutcomeUnknown
    case cancellationOutcomeUnknown
    case disposed
}

/// Bounded, non-secret diagnostic for an unknown mutation outcome.
///
/// This never carries response bodies, tokens, TOTP secrets, recovery codes,
/// passwords, or certificate material.
public enum LocalBootstrapUnknownDiagnostic: String, Sendable, Equatable {
    case transportFailure
    case nonSuccessStatus
    case malformedResponse
    case responseIdentityMismatch
}

/// Bootstrap-specific operational failures that are not ordinary validation
/// errors. Messages are fixed and never include tokens, TOTP secrets, recovery
/// codes, or passwords.
public enum LocalBootstrapOperationError: Error, Sendable, Equatable,
    CustomStringConvertible {
    case operationInProgress
    case stateUnavailable(LocalBootstrapState)
    case activeEnrollmentWouldBeDiscarded
    case bootstrapOutcomeUnknown
    case confirmationOutcomeUnknown
    case cancellationOutcomeUnknown

    public var description: String {
        switch self {
        case .operationInProgress:
            "Another bootstrap or MFA operation is still in flight."
        case .stateUnavailable(let state):
            "The bootstrap client is not available in state \(state)."
        case .activeEnrollmentWouldBeDiscarded:
            "A pending MFA enrollment and its one-time secrets are still held. Confirm it, cancel it on the server, or explicitly discard local state."
        case .bootstrapOutcomeUnknown:
            "The bootstrap request may have reached the local server. Do not retry with the same token. Inspect the server state locally before any further attempt."
        case .confirmationOutcomeUnknown:
            "The MFA confirmation may have reached the local server. Do not retry blindly. Inspect the server state locally before any further attempt."
        case .cancellationOutcomeUnknown:
            "The MFA cancellation may have reached the local server. Do not retry blindly. Inspect the server state locally before any further attempt."
        }
    }
}

/// Separately established trust for a first-administrator bootstrap on this
/// Mac.
///
/// The caller supplies a `DeploymentTLSIdentity` from installation or another
/// out-of-band trust channel. `/v2/deployment` is used only as a consistency
/// check; it is never the source of trust. The local server must expose the v2
/// loopback HTTPS listener (`serve-tls`) with a certificate chain rooted at
/// this CA. Only a literal loopback HTTPS origin is accepted. Plain HTTP,
/// hostnames, and non-loopback addresses are refused here; the client's pinned
/// transport refuses redirects.
public struct LocalBootstrapTrust: Sendable, Hashable {
    public let identity: DeploymentTLSIdentity

    public init(identity: DeploymentTLSIdentity) throws {
        guard identity.originURL.scheme?.lowercased() == "https" else {
            throw HelicoidError.invalidInput(
                field: "origin",
                detail: "Bootstrap requires an HTTPS loopback origin."
            )
        }
        guard Self.isLiteralLoopbackHost(identity.host) else {
            throw HelicoidError.invalidInput(
                field: "host",
                detail: "Bootstrap requires a literal 127.0.0.0/8 or ::1 HTTPS origin. Hostnames and remote addresses are refused."
            )
        }
        self.identity = identity
    }

    public var deploymentID: String { identity.deploymentID }
    public var originURL: URL { identity.originURL }
    public var caFingerprintSHA256: String { identity.caFingerprintSHA256 }

    /// True only for a literal IPv4 loopback address or the exact IPv6
    /// loopback. `localhost` and names such as `127.attacker.example` are
    /// refused so DNS cannot escape loopback.
    public static func isLiteralLoopbackHost(_ raw: String) -> Bool {
        var host = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if host.hasPrefix("["), host.hasSuffix("]") {
            host = String(host.dropFirst().dropLast())
        }
        if host == "::1" || host == "0:0:0:0:0:0:0:1" {
            return true
        }
        guard let address = LoopbackAddressPolicy.parseIPv4Literal(host) else {
            return false
        }
        return (address & 0xFF00_0000) == 0x7F00_0000
    }
}

/// One-time bootstrap secrets plus non-secret enrollment metadata.
///
/// Secrets stay in process memory only. This type is intentionally not
/// `Codable` and its description is redacted. `takeSecrets()` is a one-shot
/// handoff that clears the client-held copy. Callers must not log or persist
/// the returned values.
///
/// The v2 bootstrap response does not include a trustworthy enrollment
/// deadline. This type therefore exposes no expiry and callers must not infer
/// one from client time.
public final class LocalBootstrapEnrollment: @unchecked Sendable,
    CustomStringConvertible, CustomDebugStringConvertible {
    public let accountID: String
    public let username: String
    public let mfaEnrollmentID: String
    public let managerPublicKey: String?
    public let accountState: String
    public let serverState: String

    private let lock = NSLock()
    private var totpSecretBase32: String?
    private var recoveryCodes: [String]?

    init(
        accountID: String,
        username: String,
        mfaEnrollmentID: String,
        managerPublicKey: String?,
        accountState: String,
        serverState: String,
        totpSecretBase32: String,
        recoveryCodes: [String]
    ) {
        self.accountID = accountID
        self.username = username
        self.mfaEnrollmentID = mfaEnrollmentID
        self.managerPublicKey = managerPublicKey
        self.accountState = accountState
        self.serverState = serverState
        self.totpSecretBase32 = totpSecretBase32
        self.recoveryCodes = recoveryCodes
    }

    /// True while the one-time material is still held by this object.
    public var hasSecrets: Bool {
        lock.lock()
        defer { lock.unlock() }
        return totpSecretBase32 != nil && recoveryCodes != nil
    }

    /// One-shot handoff. Clears this object's copy before returning. Returns
    /// nil when the secrets were already taken or cleared.
    public func takeSecrets() -> (totpSecretBase32: String, recoveryCodes: [String])? {
        lock.lock()
        defer { lock.unlock() }
        guard let totpSecretBase32, let recoveryCodes else { return nil }
        self.totpSecretBase32 = nil
        self.recoveryCodes = nil
        return (totpSecretBase32, recoveryCodes)
    }

    /// Clear any remaining one-time material. Safe to call repeatedly.
    public func clear() {
        lock.lock()
        totpSecretBase32 = nil
        recoveryCodes = nil
        lock.unlock()
    }

    /// Redacted. Never includes the TOTP secret, recovery codes, or
    /// enrollment identifiers.
    public var description: String {
        "LocalBootstrapEnrollment(secrets: \(hasSecrets ? "present" : "cleared"))"
    }

    public var debugDescription: String { description }

    deinit {
        clear()
    }
}

/// Non-secret result of MFA activation. The server never issues a session on
/// this path.
public struct LocalBootstrapConfirmation: Sendable, Equatable {
    public let accountID: String
    public let mfaStatus: String
    public let accountState: String

    init(accountID: String, mfaStatus: String, accountState: String) {
        self.accountID = accountID
        self.mfaStatus = mfaStatus
        self.accountState = accountState
    }
}

/// Local first-administrator bootstrap client for the v2 server contract.
///
/// Contract: server `contracts/http-v2.md` (`POST /v2/bootstrap`,
/// `POST /v2/mfa/enroll/confirm`, `POST /v2/mfa/enroll/cancel`).
///
/// The only public initializer builds a `PinnedHTTPSTransport` from a
/// separately established loopback deployment identity. The transport pins the
/// deployment CA, refuses OS/browser roots, network AIA fetches, redirects,
/// cookies, and proxy adoption, and bounds response bodies and operation time.
///
/// Flow:
/// 1. Verify `/v2/deployment` equals the trusted deployment id.
/// 2. Verify `/health` is in first-administrator bootstrap state with MFA
///    available and bootstrap not already completed.
/// 3. Sign the contract proof over the deployment id, SHA-256 bootstrap token
///    hash, and Manager public key, then `POST /v2/bootstrap`.
/// 4. Return one-time secrets in memory for display and independent recovery
///    storage.
/// 5. Require an explicit recovery-stored acknowledgement and a six-digit TOTP
///    code before `POST /v2/mfa/enroll/confirm`.
///
/// The bootstrap POST is irreversible. Once it is dispatched, the client does
/// not use task cancellation or a local generation fence to discard a received
/// success. If the transport fails or returns an unusable response after
/// dispatch, the client reports an unknown outcome and refuses further
/// bootstrap/MFA mutations. The same serialized rule applies to MFA
/// confirmation and destructive cancellation.
///
/// GETs use the pinned transport's non-2xx refusal before a body is exposed.
/// Mutation POSTs use the narrow typed-status seam so the contractually
/// determinate wrong-TOTP `401` remains retryable; every other post-dispatch
/// failure is conservatively unknown. This client does not parse server error
/// envelopes.
///
/// This is a core seam only. It is not wired into the Manager UI or installer.
/// Do not wire it into operator UI yet: the server still has no recovery
/// protocol for a bootstrap response that is lost after commit.
public actor LocalServerBootstrapClient {
    public static let proofMessagePrefix = "hs-bootstrap-v2"
    public static let maxTokenLength = 512
    public static let minUsernameLength = 3
    public static let maxUsernameLength = 64
    public static let minPasswordLength = 12
    public static let maxPasswordLength = 256
    public static let maxFriendlyNameLength = 128
    public static let maxIDLength = 128
    public static let maxTOTPSecretLength = 128
    public static let maxRecoveryCodes = 32
    public static let maxRecoveryCodeLength = 64
    public static let maxResponseBytes = PinnedHTTPSConfiguration.defaultMaxResponseBytes
    public static let requestTimeout: TimeInterval = 15
    public static let operationTimeout: TimeInterval = 30

    private let transport: any HTTPTransport
    private let ownedTransport: PinnedHTTPSTransport?
    private let trust: LocalBootstrapTrust
    private let signingIdentity: ManagerSigningIdentity
    private let originURL: URL
    private let expectedManagerPublicKeyHex: String
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    /// Serializes every bootstrap and MFA mutation. This is not a generation
    /// fence: a dispatched operation is never discarded because another local
    /// operation was requested.
    private var operationInFlight = false
    private var irreversibleRequestInFlight = false
    public private(set) var state: LocalBootstrapState = .idle
    /// Bounded, non-secret diagnostic for the last unknown outcome. Nil until
    /// an operation becomes unknown.
    public private(set) var lastUnknownDiagnostic: LocalBootstrapUnknownDiagnostic?
    private var activeEnrollment: LocalBootstrapEnrollment?

    /// Production initializer. Always uses a pinned HTTPS loopback transport.
    public init(
        trust: LocalBootstrapTrust,
        signingIdentity: ManagerSigningIdentity
    ) throws {
        let configuration = try PinnedHTTPSConfiguration(
            identity: trust.identity,
            requestTimeout: Self.requestTimeout,
            operationTimeout: Self.operationTimeout,
            maxResponseBytes: Self.maxResponseBytes
        )
        let transport = try PinnedHTTPSTransport(configuration: configuration)
        self.transport = transport
        self.ownedTransport = transport
        self.trust = trust
        self.signingIdentity = signingIdentity
        self.originURL = trust.originURL
        self.expectedManagerPublicKeyHex = AuthV2Canonical.lowercaseHex(signingIdentity.publicKey)
    }

    /// Internal test seam. Production callers use the pinned initializer above.
    init(
        trust: LocalBootstrapTrust,
        signingIdentity: ManagerSigningIdentity,
        transport: any HTTPTransport
    ) {
        self.transport = transport
        self.ownedTransport = nil
        self.trust = trust
        self.signingIdentity = signingIdentity
        self.originURL = trust.originURL
        self.expectedManagerPublicKeyHex = AuthV2Canonical.lowercaseHex(signingIdentity.publicKey)
    }

    // MARK: - Public state

    public var deploymentID: String { trust.deploymentID }
    public var managerPublicKeyHex: String { expectedManagerPublicKeyHex }
    public var hasActiveEnrollment: Bool { activeEnrollment != nil }
    public var isOperationInFlight: Bool { operationInFlight }

    /// True from immediately before a bootstrap/confirmation/cancellation POST
    /// is handed to the transport until its outcome is processed. Cancelling
    /// the calling task in this window can produce an unknown outcome.
    public var isIrreversibleRequestInFlight: Bool { irreversibleRequestInFlight }

    // MARK: - Contract proof

    /// Exact UTF-8 proof message frozen by the v2 bootstrap contract.
    public static func bootstrapProofMessage(
        deploymentID: String,
        bootstrapTokenHash: String,
        managerPublicKeyHex: String
    ) -> Data {
        Data(
            "\(proofMessagePrefix)|deployment:\(deploymentID)|token:\(bootstrapTokenHash)|manager:\(managerPublicKeyHex)".utf8
        )
    }

    /// SHA-256 of the exact bootstrap token bytes, lowercase hex. The server
    /// hashes the token it receives, so callers must not alter the token after
    /// this value is computed.
    public static func bootstrapTokenHashHex(_ token: String) -> String {
        AuthV2Canonical.lowercaseHex(Data(SHA256.hash(data: Data(token.utf8))))
    }

    // MARK: - Bootstrap

    /// Create the first administrator in `pending_mfa` and return one-time
    /// enrollment secrets. The bootstrap token is sent only after the trusted
    /// deployment identity and bootstrap-pending state are verified.
    ///
    /// Once the POST is dispatched, a received 201 response is retained even
    /// if the calling task was cancelled. A transport failure or unusable
    /// response after dispatch throws
    /// `LocalBootstrapOperationError.bootstrapOutcomeUnknown` and poisons the
    /// client against blind retry.
    public func bootstrapFirstAdministrator(
        token: String,
        username: String,
        password: String,
        managerFriendlyName: String? = nil,
        acknowledgement: LocalBootstrapSecretAcknowledgement
    ) async throws -> LocalBootstrapEnrollment {
        _ = acknowledgement
        try Self.throwIfCancelled()

        guard !operationInFlight else {
            throw LocalBootstrapOperationError.operationInProgress
        }
        guard state == .idle else {
            throw LocalBootstrapOperationError.stateUnavailable(state)
        }

        let token = try Self.validateToken(token)
        let username = try Self.validateUsername(username)
        try Self.validatePassword(password)
        let friendlyName = try Self.validateFriendlyName(managerFriendlyName)

        let tokenHash = Self.bootstrapTokenHashHex(token)
        let message = Self.bootstrapProofMessage(
            deploymentID: trust.deploymentID,
            bootstrapTokenHash: tokenHash,
            managerPublicKeyHex: expectedManagerPublicKeyHex
        )
        let signature = try signingIdentity.sign(canonicalMessage: message)
        guard signature.count == 64 else {
            throw HelicoidError.authenticationFailed(
                detail: "The Manager identity produced an invalid bootstrap proof."
            )
        }
        let proofHex = AuthV2Canonical.lowercaseHex(signature)
        guard proofHex.utf8.count == 128, proofHex.allSatisfy(\.isHexDigit) else {
            throw HelicoidError.authenticationFailed(
                detail: "The Manager identity produced an invalid bootstrap proof."
            )
        }

        let body: Data
        do {
            body = try encoder.encode(
                BootstrapRequestDTO(
                    bootstrapToken: token,
                    username: username,
                    password: password,
                    managerPublicKey: expectedManagerPublicKeyHex,
                    managerProof: proofHex,
                    managerFriendlyName: friendlyName
                )
            )
        } catch {
            throw HelicoidError.invalidInput(
                field: "request",
                detail: "The bootstrap request could not be encoded."
            )
        }

        try Self.throwIfCancelled()
        operationInFlight = true
        state = .bootstrapInFlight
        defer {
            irreversibleRequestInFlight = false
            operationInFlight = false
            if state == .bootstrapInFlight {
                state = .idle
            }
        }

        try await verifyDeploymentIdentity()
        try Self.throwIfCancelled()
        try await requireBootstrapPending()
        try Self.throwIfCancelled()

        let result: HTTPResult
        do {
            result = try await post(path: "/v2/bootstrap", body: body)
        } catch {
            state = .bootstrapOutcomeUnknown
            lastUnknownDiagnostic = .transportFailure
            throw LocalBootstrapOperationError.bootstrapOutcomeUnknown
        }

        // No cancellation or local-generation checks after dispatch. The
        // server may already have committed the only first-admin MFA
        // material; a received success must be retained.
        guard result.statusCode == 201 else {
            // Any non-201 response that reaches this seam is treated as
            // unknown because the server may already have committed.
            state = .bootstrapOutcomeUnknown
            lastUnknownDiagnostic = .nonSuccessStatus
            throw LocalBootstrapOperationError.bootstrapOutcomeUnknown
        }
        do {
            let dto: BootstrapResponseDTO = try decode(
                BootstrapResponseDTO.self,
                body: result.body
            )
            let enrollment = try Self.validateBootstrapResponse(
                dto,
                expectedUsername: username,
                expectedManagerPublicKeyHex: expectedManagerPublicKeyHex
            )
            clearActiveEnrollment()
            activeEnrollment = enrollment
            state = .awaitingMFAConfirmation
            return enrollment
        } catch {
            state = .bootstrapOutcomeUnknown
            lastUnknownDiagnostic = Self.unknownDiagnostic(for: error)
            throw LocalBootstrapOperationError.bootstrapOutcomeUnknown
        }
    }

    /// Confirm the pending TOTP enrollment and activate the administrator.
    ///
    /// `recoveryCodesStoredIndependently` must be true. A false value is
    /// refused locally and sends nothing. The TOTP code must come from the
    /// operator's authenticator; this client never derives or stores it.
    ///
    /// Once the confirmation POST is dispatched, a received success is
    /// retained even if the calling task was cancelled. Any post-dispatch
    /// transport failure or unusable response poisons the client with
    /// `confirmationOutcomeUnknown`.
    public func confirmMFAEnrollment(
        _ enrollment: LocalBootstrapEnrollment,
        totpCode: String,
        recoveryCodesStoredIndependently: Bool
    ) async throws -> LocalBootstrapConfirmation {
        try Self.throwIfCancelled()

        guard !operationInFlight else {
            throw LocalBootstrapOperationError.operationInProgress
        }
        guard state == .awaitingMFAConfirmation,
              let active = activeEnrollment,
              active === enrollment else {
            throw LocalBootstrapOperationError.stateUnavailable(state)
        }
        guard recoveryCodesStoredIndependently else {
            throw HelicoidError.invalidInput(
                field: "recovery_material_stored",
                detail: "Store the recovery codes independently before activating MFA. No confirmation was sent."
            )
        }
        guard NativeV2AuthClient.isValidTOTPCode(totpCode) else {
            throw HelicoidError.invalidInput(
                field: "totp_code",
                detail: "Enter the six-digit code from the authenticator. No confirmation was sent."
            )
        }

        let code = totpCode.trimmingCharacters(in: .whitespacesAndNewlines)
        let body: Data
        do {
            body = try encoder.encode(
                MFAConfirmRequestDTO(
                    mfaEnrollmentID: active.mfaEnrollmentID,
                    totpCode: code,
                    recoveryMaterialStored: true
                )
            )
        } catch {
            throw HelicoidError.invalidInput(
                field: "request",
                detail: "The MFA confirmation request could not be encoded."
            )
        }

        operationInFlight = true
        defer {
            irreversibleRequestInFlight = false
            operationInFlight = false
        }

        try await verifyDeploymentIdentity()
        try Self.throwIfCancelled()

        let result: HTTPResult
        do {
            result = try await post(path: "/v2/mfa/enroll/confirm", body: body)
        } catch {
            state = .confirmationOutcomeUnknown
            lastUnknownDiagnostic = .transportFailure
            throw LocalBootstrapOperationError.confirmationOutcomeUnknown
        }

        // No cancellation checks after dispatch. A received success wins.
        //
        // contracts/http-v2.md (`POST /v2/mfa/enroll/confirm`,
        // "Failure mapping (endpoint-specific)") pins: wrong TOTP is 401 with the
        // transaction rolled back, so neither the enrollment nor the TOTP
        // time step is consumed; expired and already-consumed enrollments are
        // 409. Only the 401 is determinate and retryable with the same
        // enrollment.
        if result.statusCode == 401 {
            throw HelicoidError.authenticationFailed(
                detail: "The verification code was refused. The enrollment remains pending; try again."
            )
        }

        guard result.statusCode == 200 else {
            // Any other non-200 response is conservatively unknown. This
            // includes the contract's determinate 409 expired/consumed
            // outcomes: the client refuses retry and requires local
            // inspection until that mapping is explicitly handled.
            state = .confirmationOutcomeUnknown
            lastUnknownDiagnostic = .nonSuccessStatus
            throw LocalBootstrapOperationError.confirmationOutcomeUnknown
        }
        guard active === activeEnrollment else {
            state = .confirmationOutcomeUnknown
            lastUnknownDiagnostic = .responseIdentityMismatch
            throw LocalBootstrapOperationError.confirmationOutcomeUnknown
        }
        do {
            let dto: MFAConfirmResponseDTO = try decode(
                MFAConfirmResponseDTO.self,
                body: result.body
            )
            let confirmation = try Self.validateConfirmResponse(
                dto,
                expectedAccountID: active.accountID
            )
            clearActiveEnrollment()
            state = .confirmed
            return confirmation
        } catch {
            state = .confirmationOutcomeUnknown
            lastUnknownDiagnostic = Self.unknownDiagnostic(for: error)
            throw LocalBootstrapOperationError.confirmationOutcomeUnknown
        }
    }

    /// Cancel the current pending MFA enrollment on the server and clear
    /// one-time secrets.
    ///
    /// This is destructive and requires an explicit acknowledgement. It is
    /// refused while another mutation is in flight. A transport failure or
    /// unusable response after dispatch poisons the client with
    /// `cancellationOutcomeUnknown`; secrets are retained because the server
    /// may not have cancelled the enrollment.
    public func cancelPendingEnrollment(
        acknowledgement: LocalBootstrapDestructiveCancellationAcknowledgement
    ) async throws {
        _ = acknowledgement
        try Self.throwIfCancelled()

        guard !operationInFlight else {
            throw LocalBootstrapOperationError.operationInProgress
        }
        guard state == .awaitingMFAConfirmation, let active = activeEnrollment else {
            throw LocalBootstrapOperationError.stateUnavailable(state)
        }

        let body: Data
        do {
            body = try encoder.encode(
                MFAEnrollCancelRequestDTO(mfaEnrollmentID: active.mfaEnrollmentID)
            )
        } catch {
            throw HelicoidError.invalidInput(
                field: "request",
                detail: "The MFA cancellation request could not be encoded."
            )
        }

        operationInFlight = true
        defer {
            irreversibleRequestInFlight = false
            operationInFlight = false
        }

        try await verifyDeploymentIdentity()
        try Self.throwIfCancelled()

        let result: HTTPResult
        do {
            result = try await post(path: "/v2/mfa/enroll/cancel", body: body)
        } catch {
            state = .cancellationOutcomeUnknown
            lastUnknownDiagnostic = .transportFailure
            throw LocalBootstrapOperationError.cancellationOutcomeUnknown
        }

        guard result.statusCode == 204 else {
            // Any non-204 response is conservatively unknown.
            state = .cancellationOutcomeUnknown
            lastUnknownDiagnostic = .nonSuccessStatus
            throw LocalBootstrapOperationError.cancellationOutcomeUnknown
        }
        guard active === activeEnrollment else {
            state = .cancellationOutcomeUnknown
            lastUnknownDiagnostic = .responseIdentityMismatch
            throw LocalBootstrapOperationError.cancellationOutcomeUnknown
        }
        clearActiveEnrollment()
        state = .cancelled
    }

    /// Explicitly discard local one-time secrets without cancelling the
    /// server-side pending enrollment.
    ///
    /// The server enrollment remains pending and its one-time material becomes
    /// unusable to this client. The client moves to `.discarded` and refuses
    /// further bootstrap/MFA mutations.
    public func discardLocalState(
        acknowledgement: LocalBootstrapDiscardAcknowledgement
    ) throws {
        _ = acknowledgement
        guard !operationInFlight else {
            throw LocalBootstrapOperationError.operationInProgress
        }
        guard state != .disposed else {
            throw LocalBootstrapOperationError.stateUnavailable(state)
        }
        clearActiveEnrollment()
        state = .discarded
    }

    /// Release the owned pinned transport.
    ///
    /// Refused while a mutation is in flight and while a pending enrollment's
    /// secrets are still held. Use `cancelPendingEnrollment` or
    /// `discardLocalState` explicitly first.
    public func dispose() throws {
        guard !operationInFlight else {
            throw LocalBootstrapOperationError.operationInProgress
        }
        guard state != .disposed else { return }
        guard activeEnrollment == nil else {
            throw LocalBootstrapOperationError.activeEnrollmentWouldBeDiscarded
        }
        ownedTransport?.dispose()
        state = .disposed
    }

    // MARK: - State checks

    private func verifyDeploymentIdentity() async throws {
        let response = try await get(path: "/v2/deployment")
        let dto: DeploymentResponseDTO = try decode(
            DeploymentResponseDTO.self,
            body: response.body
        )
        let returned = try Self.boundedID(dto.deploymentID, field: "deployment_id")
        guard returned == trust.deploymentID else {
            throw HelicoidError.identityMismatch
        }
    }

    private func requireBootstrapPending() async throws {
        let response = try await get(path: "/health")
        let health: HealthDTO = try decode(HealthDTO.self, body: response.body)
        guard health.schemaVersion == 1 else {
            throw HelicoidError.serverContractUnavailable
        }
        guard health.features["mfa"] == true else {
            throw HelicoidError.serverContractUnavailable
        }
        guard !health.bootstrapCompleted else {
            throw HelicoidError.setupBlocked(
                reason: "Bootstrap has already been completed on this deployment. No bootstrap token was sent."
            )
        }
        guard health.status == "degraded", !health.acceptingAuthorizedOperations else {
            throw HelicoidError.setupBlocked(
                reason: "The local server is not in first-administrator bootstrap state. No bootstrap token was sent."
            )
        }
    }

    private func clearActiveEnrollment() {
        activeEnrollment?.clear()
        activeEnrollment = nil
    }

    // MARK: - HTTP

    private struct HTTPResult: Sendable {
        let statusCode: Int
        let body: Data
    }

    private func get(path: String) async throws -> HTTPResult {
        let result = try await perform(method: "GET", path: path, body: nil)
        // The production pinned transport throws non-2xx before returning a
        // body. This guard is a defensive contract check for the test/future
        // transport seam and does not parse server error envelopes.
        guard result.statusCode == 200 else {
            throw HelicoidError.serverContractUnavailable
        }
        return result
    }

    private func post(path: String, body: Data) async throws -> HTTPResult {
        try await performMutation(method: "POST", path: path, body: body)
    }

    /// Mutation POSTs use the typed-status transport seam so a contractually
    /// determinate 401 can be distinguished from transport loss. Transports
    /// without that seam keep the existing bounded `bytes` path.
    private func performMutation(method: String, path: String, body: Data) async throws -> HTTPResult {
        let request = try makeRequest(method: method, path: path, body: body)
        irreversibleRequestInFlight = true

        if let statusTransport = transport as? any HTTPStatusTransport {
            let response = try await statusTransport.requestStatus(
                for: request,
                maxBytes: Self.maxResponseBytes
            )
            return try validatedResult(
                statusCode: response.statusCode,
                body: response.body,
                responseURL: response.url,
                requestedURL: request.url
            )
        }

        let (data, response) = try await bytes(for: request)
        return try validatedResult(
            data: data,
            response: response,
            requestedURL: request.url
        )
    }

    private func perform(method: String, path: String, body: Data?) async throws -> HTTPResult {
        let request = try makeRequest(method: method, path: path, body: body)
        let (data, response) = try await bytes(for: request)
        return try validatedResult(
            data: data,
            response: response,
            requestedURL: request.url
        )
    }

    private func makeRequest(method: String, path: String, body: Data?) throws -> URLRequest {
        let resolved: URL
        switch DeploymentOriginPolicy.resolve(path: path, origin: originURL) {
        case .allowed(let url):
            resolved = url
        case .refused(let reason):
            throw HelicoidError.invalidInput(field: "path", detail: reason.message)
        }

        var request = URLRequest(url: resolved)
        request.httpMethod = method
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if body != nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return request
    }

    private func bytes(for request: URLRequest) async throws -> (Data, URLResponse) {
        do {
            return try await transport.bytes(
                for: request,
                maxBytes: Self.maxResponseBytes
            )
        } catch let error as HelicoidError {
            throw error
        } catch {
            if Task.isCancelled { throw HelicoidError.cancelled }
            throw HelicoidError.unreachable
        }
    }

    private func validatedResult(
        data: Data,
        response: URLResponse,
        requestedURL: URL?
    ) throws -> HTTPResult {
        guard let http = response as? HTTPURLResponse, let responseURL = http.url else {
            throw HelicoidError.unreachable
        }
        return try validatedResult(
            statusCode: http.statusCode,
            body: data,
            responseURL: responseURL,
            requestedURL: requestedURL
        )
    }

    private func validatedResult(
        statusCode: Int,
        body: Data,
        responseURL: URL,
        requestedURL: URL?
    ) throws -> HTTPResult {
        guard body.count <= Self.maxResponseBytes else {
            throw HelicoidError.invalidInput(
                field: "response",
                detail: "Response body exceeded the bounded size limit."
            )
        }
        // Defense in depth for the test transport seam and any transport that
        // follows a redirect: the final response must still be the pinned
        // loopback origin and the exact requested path. Production
        // PinnedHTTPSTransport already refuses all redirects.
        try PinnedHTTPSTransport.validateRequestURL(responseURL, origin: originURL)
        guard responseURL.path == requestedURL?.path,
              responseURL.query == requestedURL?.query else {
            throw HelicoidError.invalidInput(
                field: "response",
                detail: "The local server response did not come from the requested loopback path."
            )
        }
        return HTTPResult(statusCode: statusCode, body: body)
    }

    private func decode<T: Decodable>(_ type: T.Type, body: Data) throws -> T {
        guard body.count <= Self.maxResponseBytes else {
            throw HelicoidError.invalidInput(
                field: "response",
                detail: "Response body exceeded the bounded size limit."
            )
        }
        do {
            return try decoder.decode(T.self, from: body)
        } catch {
            throw HelicoidError.invalidInput(
                field: "response",
                detail: "The local server returned a malformed success payload."
            )
        }
    }

    // MARK: - Validation

    static func validateToken(_ raw: String) throws -> String {
        let token = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty, token.utf8.count <= maxTokenLength else {
            throw HelicoidError.invalidInput(
                field: "bootstrap_token",
                detail: "The bootstrap token is empty or exceeds its size limit."
            )
        }
        guard !token.unicodeScalars.contains(where: { scalar in
            scalar.value < 0x20 || scalar.value == 0x7F
                || CharacterSet.whitespacesAndNewlines.contains(scalar)
        }) else {
            throw HelicoidError.invalidInput(
                field: "bootstrap_token",
                detail: "The bootstrap token contains whitespace or control characters."
            )
        }
        return token
    }

    static func validateUsername(_ raw: String) throws -> String {
        let username = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard username.utf8.count >= minUsernameLength,
              username.utf8.count <= maxUsernameLength else {
            throw HelicoidError.invalidInput(
                field: "username",
                detail: "Use 3–64 letters, digits, dot, underscore, or hyphen."
            )
        }
        let allowed = Set<Character>(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        )
        guard username.allSatisfy({ allowed.contains($0) }) else {
            throw HelicoidError.invalidInput(
                field: "username",
                detail: "Use only letters, digits, dot, underscore, or hyphen."
            )
        }
        return username
    }

    static func validatePassword(_ password: String) throws {
        guard password.utf8.count >= minPasswordLength,
              password.utf8.count <= maxPasswordLength else {
            throw HelicoidError.invalidInput(
                field: "password",
                detail: "Use a password of 12–256 bytes."
            )
        }
    }

    static func validateFriendlyName(_ raw: String?) throws -> String? {
        guard let raw else { return nil }
        let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.isEmpty { return nil }
        guard name.utf8.count <= maxFriendlyNameLength else {
            throw HelicoidError.invalidInput(
                field: "manager_friendly_name",
                detail: "The Manager name exceeds its size limit."
            )
        }
        guard !name.unicodeScalars.contains(where: { scalar in
            scalar.value < 0x20 || scalar.value == 0x7F
        }) else {
            throw HelicoidError.invalidInput(
                field: "manager_friendly_name",
                detail: "The Manager name contains control characters."
            )
        }
        return name
    }

    static func validateBootstrapResponse(
        _ dto: BootstrapResponseDTO,
        expectedUsername: String,
        expectedManagerPublicKeyHex: String
    ) throws -> LocalBootstrapEnrollment {
        let accountID = try boundedID(dto.accountID, field: "account_id")
        let username = dto.username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard username == expectedUsername else {
            throw HelicoidError.identityMismatch
        }
        let mfaEnrollmentID = try boundedID(dto.mfaEnrollmentID, field: "mfa_enrollment_id")

        let totpSecret = dto.totpSecretBase32
        guard !totpSecret.isEmpty,
              totpSecret.utf8.count <= maxTOTPSecretLength,
              totpSecret == totpSecret.trimmingCharacters(in: .whitespacesAndNewlines),
              totpSecret.unicodeScalars.allSatisfy({ scalar in
                  let value = scalar.value
                  return (value >= 0x41 && value <= 0x5A)
                      || (value >= 0x61 && value <= 0x7A)
                      || (value >= 0x32 && value <= 0x37)
              }) else {
            throw HelicoidError.invalidInput(
                field: "totp_secret_base32",
                detail: "The local server returned an invalid TOTP secret."
            )
        }

        guard (1...maxRecoveryCodes).contains(dto.recoveryCodes.count) else {
            throw HelicoidError.invalidInput(
                field: "recovery_codes",
                detail: "The local server returned an invalid recovery-code count."
            )
        }
        var seenCodes = Set<String>()
        var recoveryCodes: [String] = []
        recoveryCodes.reserveCapacity(dto.recoveryCodes.count)
        for code in dto.recoveryCodes {
            guard !code.isEmpty,
                  code.utf8.count <= maxRecoveryCodeLength,
                  code == code.trimmingCharacters(in: .whitespacesAndNewlines),
                  !code.unicodeScalars.contains(where: { scalar in
                      scalar.value < 0x20 || scalar.value == 0x7F
                          || CharacterSet.whitespacesAndNewlines.contains(scalar)
                  }),
                  seenCodes.insert(code).inserted else {
                throw HelicoidError.invalidInput(
                    field: "recovery_codes",
                    detail: "The local server returned an invalid recovery code."
                )
            }
            recoveryCodes.append(code)
        }

        guard dto.accountState == "pending_mfa" else {
            throw HelicoidError.invalidInput(
                field: "account_state",
                detail: "The local server did not create an inactive pending-MFA administrator."
            )
        }
        guard dto.serverState == "awaiting_mfa_confirmation" else {
            throw HelicoidError.invalidInput(
                field: "server_state",
                detail: "The local server did not report awaiting MFA confirmation."
            )
        }

        guard let rawKey = dto.managerPublicKey else {
            throw HelicoidError.identityMismatch
        }
        let returnedKey = rawKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard returnedKey == expectedManagerPublicKeyHex,
              returnedKey.utf8.count == 64,
              returnedKey.allSatisfy(\.isHexDigit) else {
            throw HelicoidError.identityMismatch
        }

        return LocalBootstrapEnrollment(
            accountID: accountID,
            username: username,
            mfaEnrollmentID: mfaEnrollmentID,
            managerPublicKey: returnedKey,
            accountState: dto.accountState,
            serverState: dto.serverState,
            totpSecretBase32: totpSecret,
            recoveryCodes: recoveryCodes
        )
    }

    static func validateConfirmResponse(
        _ dto: MFAConfirmResponseDTO,
        expectedAccountID: String
    ) throws -> LocalBootstrapConfirmation {
        let accountID = try boundedID(dto.accountID, field: "account_id")
        guard accountID == expectedAccountID else {
            throw HelicoidError.identityMismatch
        }
        guard dto.mfaStatus == "active" else {
            throw HelicoidError.invalidInput(
                field: "mfa_status",
                detail: "The local server did not activate MFA."
            )
        }
        guard dto.accountState == "active" else {
            throw HelicoidError.invalidInput(
                field: "account_state",
                detail: "The local server did not activate the administrator."
            )
        }
        return LocalBootstrapConfirmation(
            accountID: accountID,
            mfaStatus: dto.mfaStatus,
            accountState: dto.accountState
        )
    }

    static func boundedID(_ raw: String, field: String) throws -> String {
        guard !raw.isEmpty,
              raw.utf8.count <= maxIDLength,
              raw == raw.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.unicodeScalars.contains(where: { scalar in
                  scalar.value < 0x20 || scalar.value == 0x7F
                      || CharacterSet.whitespacesAndNewlines.contains(scalar)
              }) else {
            throw HelicoidError.invalidInput(
                field: field,
                detail: "The local server returned an invalid \(field)."
            )
        }
        return raw
    }

    private static func unknownDiagnostic(for error: Error) -> LocalBootstrapUnknownDiagnostic {
        if let helicoid = error as? HelicoidError, case .identityMismatch = helicoid {
            return .responseIdentityMismatch
        }
        return .malformedResponse
    }

    private static func throwIfCancelled() throws {
        if Task.isCancelled { throw HelicoidError.cancelled }
    }
}

// MARK: - Wire DTOs (internal; never public secret containers)

// Contains a bootstrap token and password. Never log or persist this type.
struct BootstrapRequestDTO: Encodable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible {
    let bootstrapToken: String
    let username: String
    let password: String
    let managerPublicKey: String
    let managerProof: String
    let managerFriendlyName: String?

    enum CodingKeys: String, CodingKey {
        case bootstrapToken = "bootstrap_token"
        case username
        case password
        case managerPublicKey = "manager_public_key"
        case managerProof = "manager_proof"
        case managerFriendlyName = "manager_friendly_name"
    }

    var description: String { "BootstrapRequestDTO(redacted)" }

    var debugDescription: String { description }
}

// Contains one-time TOTP and recovery secrets. Never log or persist this type.
struct BootstrapResponseDTO: Decodable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible {
    let accountID: String
    let username: String
    let mfaEnrollmentID: String
    let totpSecretBase32: String
    let recoveryCodes: [String]
    let managerPublicKey: String?
    let accountState: String
    let serverState: String

    enum CodingKeys: String, CodingKey {
        case accountID = "account_id"
        case username
        case mfaEnrollmentID = "mfa_enrollment_id"
        case totpSecretBase32 = "totp_secret_base32"
        case recoveryCodes = "recovery_codes"
        case managerPublicKey = "manager_public_key"
        case accountState = "account_state"
        case serverState = "server_state"
    }

    var description: String {
        "BootstrapResponseDTO(redacted, recoveryCodeCount: \(recoveryCodes.count))"
    }

    var debugDescription: String { description }
}

struct DeploymentResponseDTO: Decodable, Sendable {
    let deploymentID: String

    enum CodingKeys: String, CodingKey {
        case deploymentID = "deployment_id"
    }
}

// Contains a TOTP code. Never log or persist this type.
struct MFAConfirmRequestDTO: Encodable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible {
    let mfaEnrollmentID: String
    let totpCode: String
    let recoveryMaterialStored: Bool

    enum CodingKeys: String, CodingKey {
        case mfaEnrollmentID = "mfa_enrollment_id"
        case totpCode = "totp_code"
        case recoveryMaterialStored = "recovery_material_stored"
    }

    var description: String { "MFAConfirmRequestDTO(redacted)" }

    var debugDescription: String { description }
}

struct MFAConfirmResponseDTO: Decodable, Sendable {
    let accountID: String
    let mfaStatus: String
    let accountState: String

    enum CodingKeys: String, CodingKey {
        case accountID = "account_id"
        case mfaStatus = "mfa_status"
        case accountState = "account_state"
    }
}

struct MFAEnrollCancelRequestDTO: Encodable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible {
    let mfaEnrollmentID: String

    enum CodingKeys: String, CodingKey {
        case mfaEnrollmentID = "mfa_enrollment_id"
    }

    var description: String { "MFAEnrollCancelRequestDTO(redacted)" }

    var debugDescription: String { description }
}
