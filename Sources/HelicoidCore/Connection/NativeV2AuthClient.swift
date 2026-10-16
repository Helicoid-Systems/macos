import CryptoKit
import Foundation

// MARK: - Public auth model

/// Server-derived MFA policy for one challenge.
/// `.optional` is accepted only when the server reports `mfa_required == false`.
public enum AuthChallengeMFARequirement: Hashable, Sendable {
    case required
    case optional
}

/// In-memory pending challenge. Secrets never leave process memory and are
/// never logged. Cleared on success, cancel, sign-out, expiry, identity
/// change, or client disposal.
public struct PendingAuthChallenge: Sendable {
    public let mfaRequirement: AuthChallengeMFARequirement
    public let expiresAtUnix: Int

    let challengeID: String
    let challengeToken: String
    let operation: String
    let managerPublicKeyHex: String
    let deploymentID: String

    /// True when a six-digit factor code must be collected before completion.
    public var requiresCode: Bool { mfaRequirement == .required }

    /// Public projection used by UI. Never includes challenge token.
    public var codeState: AuthCodeState {
        requiresCode ? .required : .notRequired
    }
}

/// UI-facing required-code state. Cancellable at every point.
public enum AuthCodeState: Hashable, Sendable {
    case idle
    case notRequired
    case required
}

/// Operation-generation fence for UI session installation.
///
/// Cancellation or a newer sign-in invalidates the previous token even after
/// the network call already completed, so late replies cannot re-enter
/// `signedIn` after cancel.
public struct AuthInstallGate: Sendable {
    public private(set) var generation: UInt64 = 0

    public init() {}

    /// Start a new operation and return its install token.
    public mutating func begin() -> UInt64 {
        generation &+= 1
        return generation
    }

    /// Invalidate in-flight operations. Returns the new generation.
    @discardableResult
    public mutating func cancel() -> UInt64 {
        generation &+= 1
        return generation
    }

    /// True only for the still-current operation.
    public func permits(_ token: UInt64) -> Bool {
        token == generation
    }
}

/// Memory-only bearer session established by a completed challenge.
public struct AuthenticatedSession: Sendable, Equatable {
    public let token: String
    public let expiresAtUnix: Int
    public let account: AccountDTO
    public let manager: ManagerDTO?
    public let mfa: MFADTO?

    public var operatorID: OperatorID { OperatorID(account.id) }
}

// MARK: - Canonical signing

public enum AuthV2Canonical {
    public static let sessionOperation = "session"
    /// Domain-separated message frozen by the native auth contract.
    public static let messagePrefix = "hs-auth-v2"

    /// Exact UTF-8 message the manager signs for a session challenge.
    public static func sessionMessage(
        deploymentID: String,
        challengeID: String,
        managerPublicKeyHex: String
    ) -> Data {
        Data("\(messagePrefix)|deployment:\(deploymentID)|challenge:\(challengeID)|operation:\(sessionOperation)|manager:\(managerPublicKeyHex)".utf8)
    }

    /// Lowercase hex encoding used on the wire for keys and signatures.
    public static func lowercaseHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// Parse lowercase/uppercase hex into bytes. Returns nil on any non-hex or odd length.
    public static func bytes(fromHex hex: String) -> Data? {
        let trimmed = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count % 2 == 0, !trimmed.isEmpty else { return nil }
        var out = Data(capacity: trimmed.count / 2)
        var index = trimmed.startIndex
        while index < trimmed.endIndex {
            let next = trimmed.index(index, offsetBy: 2)
            guard let byte = UInt8(trimmed[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        return out
    }
}

// MARK: - Client

/// Real pinned-HTTPS two-step device-key challenge client (contract v2).
///
/// Trust comes from an independently supplied `DeploymentTLSIdentity` and a
/// `PinnedHTTPSTransport` (or another `HTTPTransport` seam in tests). It never
/// learns deployment identity from an unauthenticated health reply, never
/// falls back to v1/password-only/dev labels, and never invents grants.
public actor NativeV2AuthClient {
    public static let maxIDLength = 128
    public static let maxTokenLength = 512
    public static let maxSignatureHexLength = 128
    public static let publicKeyHexLength = 64
    /// Challenge lifetime bound from the wire contract (seconds).
    public static let maxChallengeLifetimeSeconds = 120
    /// Session lifetime bound from the wire contract (seconds).
    public static let maxSessionLifetimeSeconds = 7_200

    private let transport: any HTTPTransport
    private let signingIdentity: ManagerSigningIdentity
    private let trustedDeploymentID: String
    private let originURL: URL
    private let caFingerprintSHA256: String
    private let expectedManagerPublicKeyHex: String
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()
    private let tokenBox: TokenBox
    private let timeSource: any SessionTimeSource

    private var pending: PendingAuthChallenge?
    private var sessionAccountID: String?
    /// Incremented on every cancel/start/sign-out. Late replies from an older
    /// generation must never install a session.
    private var generation: UInt64 = 0

    /// Live bearer + monotonic deadline. Clearing never requires a network call.
    private struct LiveBearerSession: Sendable {
        let token: String
        let expiresAtUnix: Int
        let monotonicDeadlineNanos: UInt64
        let installGeneration: UInt64
    }

    /// Why a `waitForSessionExpiry` call returned.
    public enum SessionWaitOutcome: Sendable, Equatable {
        /// Deadline passed for this generation; live material was cleared.
        case expired(generation: UInt64)
        /// Session was cleared or replaced. Not an expiry.
        case cleared
        /// The waiting task was cancelled. Live session is left untouched.
        case cancelled
    }

    private var liveSession: LiveBearerSession?
    /// Owned deadline sleeper. `[weak self]` so sleep does not retain the client.
    private var expiryTask: Task<Void, Never>?
    /// Continuations waiting on a specific session stamp.
    private struct SessionWaiter {
        let token: String
        let generation: UInt64
        let continuation: CheckedContinuation<SessionWaitOutcome, Never>
    }

    private var sessionWaiters: [UInt64: SessionWaiter] = [:]
    private var nextWaiterID: UInt64 = 0

    /// Production initializer. Always uses the live ContinuousClock-backed source.
    public init(
        transport: any HTTPTransport,
        trustedAuthority: DeploymentTLSIdentity,
        signingIdentity: ManagerSigningIdentity,
        tokenBox: TokenBox = TokenBox()
    ) {
        self.transport = transport
        self.trustedDeploymentID = trustedAuthority.deploymentID
        self.originURL = trustedAuthority.originURL
        self.caFingerprintSHA256 = trustedAuthority.caFingerprintSHA256
        self.signingIdentity = signingIdentity
        self.expectedManagerPublicKeyHex = AuthV2Canonical.lowercaseHex(signingIdentity.publicKey)
        self.tokenBox = tokenBox
        self.timeSource = LiveSessionTimeSource()
    }

    /// Internal test seam. Production callers use the public initializer.
    init(
        transport: any HTTPTransport,
        trustedAuthority: DeploymentTLSIdentity,
        signingIdentity: ManagerSigningIdentity,
        tokenBox: TokenBox = TokenBox(),
        timeSource: any SessionTimeSource
    ) {
        self.transport = transport
        self.trustedDeploymentID = trustedAuthority.deploymentID
        self.originURL = trustedAuthority.originURL
        self.caFingerprintSHA256 = trustedAuthority.caFingerprintSHA256
        self.signingIdentity = signingIdentity
        self.expectedManagerPublicKeyHex = AuthV2Canonical.lowercaseHex(signingIdentity.publicKey)
        self.tokenBox = tokenBox
        self.timeSource = timeSource
    }

    // MARK: Seams

    public var managerPublicKeyHex: String { expectedManagerPublicKeyHex }
    public var deploymentID: String { trustedDeploymentID }
    public var hasPendingChallenge: Bool { pending != nil }
    public var currentCodeState: AuthCodeState { pending?.codeState ?? .idle }

    /// Live bearer only. Never returns an expired token.
    public var bearerToken: String? {
        guard let live = liveSession, isLive(live) else {
            if liveSession != nil {
                clearLiveSession()
            }
            return nil
        }
        return live.token
    }

    /// True when a non-expired bearer is available for authorized calls.
    public var hasLiveSession: Bool { bearerToken != nil }

    /// Wall expiry of the live session for display. Nil when none.
    public var sessionExpiresAtUnix: Int? {
        guard let live = liveSession, isLive(live) else { return nil }
        return live.expiresAtUnix
    }

    /// Live bearer for an authorized request, stamped with install generation.
    /// Throws `sessionExpired` when the deadline has passed — the request is
    /// never sent with expired credentials.
    public func currentBearerForRequest() throws -> (token: String, generation: UInt64) {
        guard let live = liveSession else {
            throw HelicoidError.notConfigured
        }
        guard isLive(live) else {
            clearLiveSession()
            throw HelicoidError.sessionExpired(detail: "Your session expired. Sign in again.")
        }
        return (live.token, live.installGeneration)
    }

    /// Suspend until the current session expires, is cleared/replaced, or the
    /// waiting task is cancelled.
    ///
    /// - Cancellation returns promptly with `.cancelled` and does **not** clear
    ///   any live session.
    /// - `.expired` is only for a deadline that actually elapsed for this
    ///   generation; `.cleared` is never reported as expiry.
    /// - No polling. One cancellable deadline sleep plus explicit wake on clear.
    public func waitForSessionExpiry() async -> SessionWaitOutcome {
        guard let live = liveSession else { return .cleared }
        let token = live.token
        let generation = live.installGeneration

        if !isLive(live) {
            clearLiveSession(ifToken: token)
            return .expired(generation: generation)
        }

        nextWaiterID &+= 1
        let waiterID = nextWaiterID

        let outcome = await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<SessionWaitOutcome, Never>) in
                // Actor-isolated registration. If state already moved on, do not park.
                guard let parked = self.liveSession,
                      parked.token == token,
                      parked.installGeneration == generation else {
                    continuation.resume(returning: .cleared)
                    return
                }
                if !self.isLive(parked) {
                    self.clearLiveSession(ifToken: token, waitOutcome: .expired(generation: generation))
                    continuation.resume(returning: .expired(generation: generation))
                    return
                }
                self.sessionWaiters[waiterID] = SessionWaiter(
                    token: token,
                    generation: generation,
                    continuation: continuation
                )
                self.ensureDeadlineTimerLocked(for: token, generation: generation, deadline: live.monotonicDeadlineNanos)
            }
        } onCancel: {
            // Prompt return; never clears session state.
            Task { await self.resumeWaiter(id: waiterID, with: .cancelled) }
        }

        return outcome
    }

    /// Resume and drop a waiter. No-op when already resumed.
    private func resumeWaiter(id: UInt64, with outcome: SessionWaitOutcome) {
        guard let waiter = sessionWaiters.removeValue(forKey: id) else { return }
        waiter.continuation.resume(returning: outcome)
    }

    /// Resume only waiters parked on this exact session stamp.
    /// A stale deadline callback must never drain replacement waiters.
    private func resumeWaiters(token: String, generation: UInt64, with outcome: SessionWaitOutcome) {
        var remaining: [UInt64: SessionWaiter] = [:]
        for (id, waiter) in sessionWaiters {
            if waiter.token == token, waiter.generation == generation {
                waiter.continuation.resume(returning: outcome)
            } else {
                remaining[id] = waiter
            }
        }
        sessionWaiters = remaining
    }

    /// Ensure one deadline sleeper for this session generation.
    ///
    /// Captures only the Sendable clock/deadline across `sleepUntil`. Weak
    /// `self` is upgraded **after** the sleep so the sleeper cannot retain
    /// the client for the session lifetime.
    private func ensureDeadlineTimerLocked(for token: String, generation: UInt64, deadline: UInt64) {
        expiryTask?.cancel()
        let clock = timeSource
        expiryTask = Task { [weak self] in
            do {
                try await clock.sleepUntil(monotonicNanos: deadline)
            } catch {
                // Cancelled sleeper (replacement/disposal). Do not clear state.
                return
            }
            guard let self else { return }
            await self.fireDeadlineIfOwned(token: token, generation: generation)
        }
    }

    private func fireDeadlineIfOwned(token: String, generation: UInt64) {
        guard let current = liveSession,
              current.token == token,
              current.installGeneration == generation else {
            // Replaced/cleared already — only this stamp's waiters see cleared.
            resumeWaiters(token: token, generation: generation, with: .cleared)
            return
        }
        guard !isLive(current) else {
            return
        }
        // Atomic expiry delivery for this stamp only; orphans are cleared.
        resumeWaiters(token: token, generation: generation, with: .expired(generation: generation))
        clearLiveSession(waitOutcome: .cleared)
    }

    private func isLive(_ session: LiveBearerSession) -> Bool {
        timeSource.monotonicNanos < session.monotonicDeadlineNanos
    }

    /// Conservative monotonic deadline from reception-relative remaining seconds.
    /// No padding. Overflow or non-positive remaining fails closed.
    static func monotonicDeadlineNanos(
        remainingSeconds: Int,
        nowNanos: UInt64
    ) -> UInt64? {
        guard remainingSeconds > 0, remainingSeconds <= maxSessionLifetimeSeconds else {
            return nil
        }
        let (delta, mulOverflow) = UInt64(remainingSeconds).multipliedReportingOverflow(by: 1_000_000_000)
        if mulOverflow { return nil }
        let (deadline, addOverflow) = nowNanos.addingReportingOverflow(delta)
        if addOverflow { return nil }
        return deadline
    }

    /// Clear the live session only when it is still the named token.
    private func clearLiveSession(ifToken token: String, waitOutcome: SessionWaitOutcome = .cleared) {
        guard liveSession?.token == token else { return }
        clearLiveSession(waitOutcome: waitOutcome)
    }

    private func clearLiveSession(waitOutcome: SessionWaitOutcome = .cleared) {
        expiryTask?.cancel()
        expiryTask = nil
        liveSession = nil
        tokenBox.token = nil
        sessionAccountID = nil
        // Default clear/replacement is not expiry. Orphaned waiters are
        // cleared; callers that mean expiry pass `.expired` after scoping.
        let parked = sessionWaiters
        sessionWaiters = [:]
        for (_, waiter) in parked {
            waiter.continuation.resume(returning: waitOutcome)
        }
    }

    /// Clear only when this request's token/generation still matches live state.
    /// A 401 for a replaced session must not destroy the replacement.
    func clearLiveSession(ifRequestToken token: String, requestGeneration: UInt64) {
        guard let live = liveSession,
              live.token == token,
              live.installGeneration == requestGeneration else {
            return
        }
        clearLiveSession()
    }

    /// Install the live bearer using the **already validated** reception-relative
    /// remaining seconds. Fails with a real error when a bounded deadline cannot
    /// be formed — never silently signs in without a bearer.
    private func installLiveSession(
        _ session: AuthenticatedSession,
        remainingSeconds: Int,
        installGeneration: UInt64
    ) throws {
        clearLiveSession()
        guard let deadline = Self.monotonicDeadlineNanos(
            remainingSeconds: remainingSeconds,
            nowNanos: timeSource.monotonicNanos
        ) else {
            throw HelicoidError.authenticationFailed(
                detail: "The session deadline could not be established. Sign in again."
            )
        }
        let live = LiveBearerSession(
            token: session.token,
            expiresAtUnix: session.expiresAtUnix,
            monotonicDeadlineNanos: deadline,
            installGeneration: installGeneration
        )
        liveSession = live
        tokenBox.token = session.token
        sessionAccountID = session.account.id
        // Deadline sleeper only — must not retain the client across sleep.
        ensureDeadlineTimerLocked(
            for: session.token,
            generation: installGeneration,
            deadline: deadline
        )
    }

    // MARK: Two-step sign-in

    /// POST /v2/auth/challenge. Returns a validated pending challenge.
    /// Clears any previous pending challenge and bearer first.
    public func beginChallenge(username: String, password: String) async throws -> PendingAuthChallenge {
        // A cancelled task must not enter begin and wipe a replacement.
        guard !Task.isCancelled else {
            throw HelicoidError.cancelled
        }
        clearPendingChallenge()
        clearLiveSession()
        generation &+= 1
        let startedGeneration = generation

        let request = AuthChallengeBeginRequestDTO(
            username: username,
            password: password,
            operation: AuthV2Canonical.sessionOperation,
            managerPublicKey: expectedManagerPublicKeyHex
        )
        let body = try encoder.encode(request)
        let response = try await post(path: "/v2/auth/challenge", body: body, authorized: false)
        guard !Task.isCancelled, startedGeneration == generation else {
            // Stale/cancelled begin must not clear or install over a replacement.
            throw HelicoidError.cancelled
        }
        let dto: AuthChallengeBeginResponseDTO = try decodeSuccess(response)
        let challenge = try Self.validateChallengeResponse(
            dto,
            requestedManagerPublicKeyHex: expectedManagerPublicKeyHex,
            trustedDeploymentID: trustedDeploymentID,
            nowUnix: timeSource.wallUnix
        )
        guard !Task.isCancelled, startedGeneration == generation else {
            throw HelicoidError.cancelled
        }
        pending = challenge
        return challenge
    }

    /// POST /v2/auth/challenge/complete.
    ///
    /// Required MFA needs a six-digit `totpCode`. Optional non-enrolled login
    /// omits the code. An active factor remains server policy; the client
    /// cannot waive it. Cancellation/timeout never installs a session.
    public func completeChallenge(_ challenge: PendingAuthChallenge, totpCode: String?) async throws -> AuthenticatedSession {
        guard !Task.isCancelled else {
            throw HelicoidError.cancelled
        }
        guard let current = pending,
              current.challengeID == challenge.challengeID,
              current.challengeToken == challenge.challengeToken else {
            // Obsolete completion must not erase a replacement challenge.
            throw HelicoidError.authenticationFailed(detail: "The sign-in challenge is no longer valid. Start sign-in again.")
        }

        let now = timeSource.wallUnix
        guard current.expiresAtUnix > now else {
            clearPending(ifChallengeID: current.challengeID)
            throw HelicoidError.authenticationFailed(detail: "The sign-in challenge expired. Start sign-in again.")
        }

        let code: String?
        if current.requiresCode {
            guard let totpCode, Self.isValidTOTPCode(totpCode) else {
                // Keep the pending challenge so the operator can retry the code.
                throw HelicoidError.authenticationFailed(detail: "Enter the six-digit verification code from your authenticator.")
            }
            code = totpCode.trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            // Optional login is accepted only when the server reported it.
            // Optional and not enrolled omits the factor code entirely.
            code = nil
        }

        let managerPublicKeyHex = current.managerPublicKeyHex
        let message = AuthV2Canonical.sessionMessage(
            deploymentID: current.deploymentID,
            challengeID: current.challengeID,
            managerPublicKeyHex: managerPublicKeyHex
        )
        let signature = try signingIdentity.sign(canonicalMessage: message)
        let signatureHex = AuthV2Canonical.lowercaseHex(signature)

        let requestBody = AuthChallengeCompleteRequestDTO(
            challengeID: current.challengeID,
            challengeToken: current.challengeToken,
            managerSignature: signatureHex,
            totpCode: code
        )
        let body = try encoder.encode(requestBody)
        let startedGeneration = generation
        let response = try await post(path: "/v2/auth/challenge/complete", body: body, authorized: false)

        // Late completion after cancel/sign-out/replacement must not install
        // and must not clear the replacement's pending/session material.
        guard !Task.isCancelled, startedGeneration == generation else {
            clearPending(ifChallengeID: current.challengeID)
            throw HelicoidError.cancelled
        }

        let login: AuthChallengeCompleteResponseDTO = try decodeSuccess(response)
        // Reception-relative clock: the pre-await timestamp is stale once the
        // request is in flight. A legitimate 7200s session issued after a slow
        // round-trip must not look oversized; strict upper bounds still apply.
        let receptionUnix = timeSource.wallUnix
        let session = try Self.validateCompletedLogin(
            login,
            challenge: current,
            expectedManagerPublicKeyHex: expectedManagerPublicKeyHex,
            nowUnix: receptionUnix
        )
        guard !Task.isCancelled, startedGeneration == generation else {
            clearPending(ifChallengeID: current.challengeID)
            throw HelicoidError.cancelled
        }

        // Success: install live bearer using reception-relative remaining
        // seconds computed once at reception (checked, unpadded).
        clearPending(ifChallengeID: current.challengeID)
        guard let remaining = Self.remainingSeconds(
            expiresAtUnix: session.expiresAtUnix,
            nowUnix: receptionUnix
        ), remaining > 0, remaining <= Self.maxSessionLifetimeSeconds else {
            throw HelicoidError.authenticationFailed(
                detail: "The session deadline could not be established. Sign in again."
            )
        }
        try installLiveSession(session, remainingSeconds: remaining, installGeneration: startedGeneration)
        return session
    }

    /// Cancel any pending challenge and clear secrets. Invalidates late replies.
    public func cancelSignIn() {
        generation &+= 1
        clearPendingChallenge()
    }

    /// Clear session material. Does not invent a remote logout claim on failure.
    public func signOutLocal() {
        generation &+= 1
        clearLiveSession()
        clearPendingChallenge()
    }

    public func dispose() {
        signOutLocal()
    }

    // MARK: Validation (public test seams)

    /// Validate a begin response. Returns a pending challenge or throws.
    public static func validateChallengeResponse(
        _ response: AuthChallengeBeginResponseDTO,
        requestedManagerPublicKeyHex: String,
        trustedDeploymentID: String,
        nowUnix: Int
    ) throws -> PendingAuthChallenge {
        let challengeID = response.challengeID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !challengeID.isEmpty, challengeID.count <= maxIDLength, !challengeID.contains(where: \.isWhitespace) else {
            throw HelicoidError.invalidInput(field: "challenge_id", detail: "The server returned an invalid challenge id.")
        }
        let challengeToken = response.challengeToken
        guard !challengeToken.isEmpty, challengeToken.count <= maxTokenLength else {
            throw HelicoidError.invalidInput(field: "challenge_token", detail: "The server returned an invalid challenge token.")
        }
        guard response.operation == AuthV2Canonical.sessionOperation else {
            throw HelicoidError.invalidInput(field: "operation", detail: "The server returned a different challenge operation than requested.")
        }
        let returnedKey = response.managerPublicKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard returnedKey == requestedManagerPublicKeyHex.lowercased(),
              returnedKey.count == publicKeyHexLength,
              returnedKey.allSatisfy(\.isHexDigit) else {
            throw HelicoidError.identityMismatch
        }
        let deploymentID = response.deploymentID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !deploymentID.isEmpty, deploymentID.count <= DeploymentTLSIdentity.maxDeploymentIDLength else {
            throw HelicoidError.invalidInput(field: "deployment_id", detail: "The server returned an invalid deployment id.")
        }
        guard deploymentID == trustedDeploymentID else {
            throw HelicoidError.identityMismatch
        }
        guard let lifetime = Self.remainingSeconds(expiresAtUnix: response.expiresAtUnix, nowUnix: nowUnix) else {
            throw HelicoidError.invalidInput(field: "expires_at_unix", detail: "The server returned an invalid challenge expiry.")
        }
        guard lifetime > 0 else {
            throw HelicoidError.authenticationFailed(detail: "The sign-in challenge already expired. Start sign-in again.")
        }
        guard lifetime <= maxChallengeLifetimeSeconds else {
            throw HelicoidError.invalidInput(field: "expires_at_unix", detail: "The server returned an oversized challenge lifetime.")
        }

        // Missing mfa_required is required, never optional.
        let mfa: AuthChallengeMFARequirement = (response.mfaRequired == false) ? .optional : .required

        return PendingAuthChallenge(
            mfaRequirement: mfa,
            expiresAtUnix: response.expiresAtUnix,
            challengeID: challengeID,
            challengeToken: challengeToken,
            operation: response.operation,
            managerPublicKeyHex: returnedKey,
            deploymentID: deploymentID
        )
    }

    /// Checked `expires - now`. Returns nil on integer overflow or non-finite
    /// domain values; never traps on extreme `Int` payloads.
    public static func remainingSeconds(expiresAtUnix: Int, nowUnix: Int) -> Int? {
        let (remaining, overflow) = expiresAtUnix.subtractingReportingOverflow(nowUnix)
        if overflow { return nil }
        return remaining
    }

    /// Validate a completed login against the finished challenge.
    ///
    /// `nowUnix` must be a **reception** timestamp taken after the HTTP await.
    /// Session lifetime is bounded by `maxSessionLifetimeSeconds` relative to
    /// reception (not request start). A response whose reception-relative
    /// remaining lifetime exceeds 7200s is still denied.
    ///
    /// Cryptographic manager binding uses completion-only top-level
    /// `manager_public_key` (must equal the actual signer/challenge key).
    /// `manager.public_identity` is a display identity only (bootstrap uses
    /// `key:<hex>`) and never grants key authority. MFA metadata must match
    /// the factor actually completed. Unlike legacy v1, a truthful
    /// `mfa.required` response is not blanket-refused after the challenge
    /// satisfied required policy.
    public static func validateCompletedLogin(
        _ response: AuthChallengeCompleteResponseDTO,
        challenge: PendingAuthChallenge,
        expectedManagerPublicKeyHex: String,
        nowUnix: Int
    ) throws -> AuthenticatedSession {
        let token = response.token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty, token.count <= maxTokenLength else {
            throw HelicoidError.authenticationFailed(detail: "Server returned an empty session token.")
        }
        let accountID = response.account.id.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !accountID.isEmpty, accountID.count <= maxIDLength else {
            throw HelicoidError.authenticationFailed(detail: "Server returned an invalid account id.")
        }
        let username = response.account.username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty else {
            throw HelicoidError.authenticationFailed(detail: "Server returned an empty account username.")
        }
        guard response.account.state == "active" else {
            throw HelicoidError.permissionDenied(detail: "This account is not active. Contact your administrator.")
        }

        // Completion identity binding: top-level manager_public_key only.
        // Do not parse public_identity labels into authority.
        let returnedKey = response.managerPublicKey.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard returnedKey.count == publicKeyHexLength,
              returnedKey.allSatisfy(\.isHexDigit) else {
            throw HelicoidError.invalidInput(field: "manager_public_key", detail: "Server returned an invalid manager public key.")
        }
        guard returnedKey == expectedManagerPublicKeyHex.lowercased(),
              returnedKey == challenge.managerPublicKeyHex.lowercased() else {
            throw HelicoidError.identityMismatch
        }

        guard let manager = response.manager else {
            throw HelicoidError.permissionDenied(detail: "This management computer is not bound to an approved manager identity.")
        }
        guard manager.isApproved else {
            if manager.isPending {
                throw HelicoidError.permissionDenied(detail: "This management computer is waiting for administrator approval.")
            }
            if manager.isRevoked {
                throw HelicoidError.permissionDenied(detail: "This management computer is no longer authorized.")
            }
            throw HelicoidError.permissionDenied(detail: "Manager state is \(manager.lifecycleState). Contact your administrator.")
        }

        try validateMFAConsistency(response.mfa, challenge: challenge)

        guard let expires = response.expiresAtUnix else {
            throw HelicoidError.authenticationFailed(detail: "Server returned a session without an expiry.")
        }
        guard let remaining = remainingSeconds(expiresAtUnix: expires, nowUnix: nowUnix) else {
            throw HelicoidError.invalidInput(field: "expires_at_unix", detail: "Server returned an invalid session expiry.")
        }
        guard remaining > 0 else {
            throw HelicoidError.authenticationFailed(detail: "The session already expired. Sign in again.")
        }
        guard remaining <= maxSessionLifetimeSeconds else {
            throw HelicoidError.invalidInput(field: "expires_at_unix", detail: "Server returned an oversized session lifetime.")
        }

        // Metadata must stay consistent with the completed challenge.
        guard challenge.operation == AuthV2Canonical.sessionOperation else {
            throw HelicoidError.invalidInput(field: "operation", detail: "Challenge operation changed before completion.")
        }

        return AuthenticatedSession(
            token: token,
            expiresAtUnix: expires,
            account: response.account,
            manager: manager,
            mfa: response.mfa
        )
    }

    /// Require MFA metadata consistent with the factor actually completed.
    /// Rejects missing, weaker, or contradictory blocks.
    public static func validateMFAConsistency(
        _ mfa: MFADTO?,
        challenge: PendingAuthChallenge
    ) throws {
        guard let mfa else {
            throw HelicoidError.authenticationFailed(detail: "Server returned no MFA state.")
        }
        switch challenge.mfaRequirement {
        case .required:
            // Factor code was completed. Server must report an active required factor.
            guard mfa.available else {
                throw HelicoidError.authenticationFailed(detail: "Server reported no active factor after verification.")
            }
            guard mfa.required else {
                throw HelicoidError.authenticationFailed(detail: "Server MFA metadata is inconsistent with the completed factor.")
            }
        case .optional:
            // Optional non-enrolled login omitted the code. Under this contract
            // an active available factor always requires TOTP, so optional
            // completion must report neither required nor available.
            guard !mfa.required, !mfa.available else {
                throw HelicoidError.authenticationFailed(detail: "Server MFA metadata is inconsistent with optional login.")
            }
        }
    }

    /// Six-digit ASCII 0-9 only. Unicode digits are refused.
    public static func isValidTOTPCode(_ code: String) -> Bool {
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.utf8.count == 6 else { return false }
        return trimmed.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }

    // MARK: HTTP plumbing

    private func clearPendingChallenge() {
        pending = nil
    }

    /// Clear pending only when it is still the named challenge.
    /// Never erases a newer replacement.
    private func clearPending(ifChallengeID challengeID: String) {
        if pending?.challengeID == challengeID {
            pending = nil
        }
    }

    private func post(path: String, body: Data, authorized: Bool) async throws -> PinnedHTTPSResponse {
        var headers = [
            "Accept": "application/json",
            "Content-Type": "application/json",
        ]
        if authorized {
            let stamp = try currentBearerForRequest()
            headers["Authorization"] = "Bearer \(stamp.token)"
            return try await performAuthorized(method: "POST", path: path, headers: headers, body: body, stamp: stamp)
        }
        return try await transportRequest(method: "POST", path: path, headers: headers, body: body)
    }

    private func get(path: String, authorized: Bool) async throws -> PinnedHTTPSResponse {
        var headers = ["Accept": "application/json"]
        if authorized {
            let stamp = try currentBearerForRequest()
            headers["Authorization"] = "Bearer \(stamp.token)"
            return try await performAuthorized(method: "GET", path: path, headers: headers, body: nil, stamp: stamp)
        }
        return try await transportRequest(method: "GET", path: path, headers: headers, body: nil)
    }

    /// Authorized request: never sent with an expired bearer. A response 401
    /// for the exact token/generation used is confirmed credential loss.
    /// A 403 is an operation denial and must not clear the session.
    private func performAuthorized(
        method: String,
        path: String,
        headers: [String: String],
        body: Data?,
        stamp: (token: String, generation: UInt64)
    ) async throws -> PinnedHTTPSResponse {
        let response: PinnedHTTPSResponse
        do {
            response = try await transportRequest(method: method, path: path, headers: headers, body: body)
        } catch {
            throw error
        }
        if response.statusCode == 401 {
            clearLiveSession(ifRequestToken: stamp.token, requestGeneration: stamp.generation)
            throw HelicoidError.sessionExpired(
                detail: "Your session expired or was revoked. Sign in again."
            )
        }
        if response.statusCode == 403 {
            // Operation denial only — keep the permitted session.
            throw HelicoidError.permissionDenied(
                detail: "This account is not permitted to use that operation. Your session remains active."
            )
        }
        return response
    }

    private func transportRequest(
        method: String,
        path: String,
        headers: [String: String],
        body: Data?
    ) async throws -> PinnedHTTPSResponse {
        // Prefer the pinned transport's typed request seam when available.
        if let pinned = transport as? PinnedHTTPSTransport {
            return try await pinned.request(method: method, path: path, headers: headers, body: body)
        }
        guard let url = URL(string: path, relativeTo: originURL) else {
            throw HelicoidError.invalidInput(field: "path", detail: "Invalid request path")
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }
        let (data, response) = try await transport.bytes(for: request, maxBytes: PinnedHTTPSConfiguration.defaultMaxResponseBytes)
        guard let http = response as? HTTPURLResponse else {
            throw HelicoidError.unreachable
        }
        return PinnedHTTPSResponse(statusCode: http.statusCode, body: data)
    }

    private func decodeSuccess<T: Decodable>(_ response: PinnedHTTPSResponse) throws -> T {
        try Self.decodeBody(T.self, statusCode: response.statusCode, body: response.body)
    }

    /// 2xx + bounded decode, or map the contracted error envelope.
    static func decodeBody<T: Decodable>(_ type: T.Type, statusCode: Int, body: Data) throws -> T {
        if body.count > PinnedHTTPSConfiguration.absoluteMaxResponseBytes {
            throw HelicoidError.invalidInput(field: "response", detail: "Response body exceeded the bounded size limit.")
        }
        let decoder = JSONDecoder()
        if (200...299).contains(statusCode) {
            do {
                return try decoder.decode(T.self, from: body)
            } catch {
                throw HelicoidError.invalidInput(field: "response", detail: "Malformed success payload.")
            }
        }
        if let envelope = try? decoder.decode(ServerErrorEnvelope.self, from: body) {
            throw mapServerError(envelope)
        }
        if statusCode == 401 {
            throw HelicoidError.authenticationFailed(detail: "Sign-in was refused. Check your credentials and try again.")
        }
        if statusCode == 403 {
            throw HelicoidError.permissionDenied(detail: "This management computer or account is not allowed to sign in.")
        }
        throw HelicoidError.unreachable
    }

    /// Plain-language mapping for contracted auth failures.
    static func mapServerError(_ envelope: ServerErrorEnvelope) -> HelicoidError {
        let code = envelope.error.code
        let message = envelope.error.message
        let detail = envelope.error.detail
        switch code {
        case "unauthorized":
            return .authenticationFailed(detail: message.isEmpty ? "Sign-in was refused." : message)
        case "forbidden":
            let combined = [message, detail].compactMap { $0 }.joined(separator: " ").lowercased()
            if combined.contains("manager") || combined.contains("revoked") {
                return .permissionDenied(detail: message.isEmpty ? "This management computer is not authorized." : message)
            }
            return .permissionDenied(detail: message.isEmpty ? "Access was refused." : message)
        case "bad_request", "unprocessable":
            return .invalidInput(field: "request", detail: message)
        case "rate_limited":
            return .authenticationFailed(detail: "Too many sign-in attempts. Wait a moment and try again.")
        case "not_implemented":
            return .serverContractUnavailable
        case "security_state_unavailable":
            return .setupBlocked(reason: message)
        case "not_found":
            return .authenticationFailed(detail: message.isEmpty ? "The sign-in challenge was not found." : message)
        case "conflict":
            return .authenticationFailed(detail: message.isEmpty ? "The sign-in challenge was already used. Start sign-in again." : message)
        case "internal":
            return .unreachable
        default:
            return .authenticationFailed(detail: message)
        }
    }
}

// MARK: - ConnectionClient

extension NativeV2AuthClient: ConnectionClient {
    public func validateAddress(_ address: String) async -> AddressValidation {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return AddressValidation(outcome: .invalid(detail: "Enter a server address."))
        }
        // Trust configuration is independent of discovery. The configured
        // pinned origin is authoritative; a different address is refused.
        if !Self.addressMatchesConfiguredOrigin(trimmed, origin: originURL) {
            return AddressValidation(outcome: .invalid(detail: "Server address must match the independently configured deployment origin."))
        }
        return AddressValidation(outcome: .ok)
    }

    /// True when `address` names the same scheme/host/port as the configured origin.
    public static func addressMatchesConfiguredOrigin(_ address: String, origin: URL) -> Bool {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        // `host:port` must not be parsed as a URL scheme. Only explicit
        // schemes are taken as absolute; bare host:port gets https.
        let candidate: URL
        if trimmed.contains("://") {
            guard let url = URL(string: trimmed) else { return false }
            candidate = url
        } else {
            guard let url = URL(string: "https://\(trimmed)") else { return false }
            candidate = url
        }
        guard let candidateHost = candidate.host.map(DeploymentTLSIdentity.normalizeHostForCompare),
              let originHost = origin.host.map(DeploymentTLSIdentity.normalizeHostForCompare) else {
            return false
        }
        guard candidateHost == originHost else { return false }
        let candidatePort = candidate.port ?? (candidate.scheme?.lowercased() == "https" ? 443 : candidate.port)
        let originPort = origin.port ?? 443
        guard candidatePort == originPort else { return false }
        return true
    }

    public func connect(address: String) async -> Result<ServerIdentity, HelicoidError> {
        // Refuse an address that disagrees with independently configured trust.
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.addressMatchesConfiguredOrigin(trimmed, origin: originURL) else {
            return .failure(.invalidInput(field: "Server address", detail: "Server address must match the independently configured deployment origin."))
        }
        // Validate pinned reachability. Health is never used to mint trust.
        do {
            let healthResponse = try await transportRequest(method: "GET", path: "/health", headers: ["Accept": "application/json"], body: nil)
            guard (200...299).contains(healthResponse.statusCode) else {
                return .failure(.unreachable)
            }
        } catch let error as HelicoidError {
            return .failure(error)
        } catch {
            return .failure(.unreachable)
        }
        // Identity is reported from configured trust only (never discovered).
        let identity = ServerIdentity(
            deploymentName: trustedDeploymentID,
            verificationFingerprint: caFingerprintSHA256,
            trustedSourceNote: "Independently supplied deployment TLS trust. Discovery does not establish trust."
        )
        return .success(identity)
    }

    public func trust(identity: ServerIdentity, address: String) async -> Result<Void, HelicoidError> {
        // No TOFU. Trust is configuration, not a runtime adoption step.
        _ = identity
        _ = address
        return .failure(.serverContractUnavailable)
    }

    public func signIn(username: String, password: String) async -> Result<OperatorID, HelicoidError> {
        // One-shot entry: optional MFA can complete immediately; required MFA
        // returns a refusal that the UI maps into the cancellable code state.
        do {
            let challenge = try await beginChallenge(username: username, password: password)
            if challenge.requiresCode {
                return .failure(.authenticationFailed(detail: "Enter the six-digit verification code to finish sign-in."))
            }
            let session = try await completeChallenge(challenge, totpCode: nil)
            return .success(session.operatorID)
        } catch let error as HelicoidError {
            return .failure(error)
        } catch {
            return .failure(.authenticationFailed(detail: "Sign-in failed."))
        }
    }

    public func authorizedInventory() async -> Result<[Computer], HelicoidError> {
        guard tokenBox.token != nil else {
            return .failure(.notConfigured)
        }
        do {
            let response = try await get(path: "/v1/computers", authorized: true)
            let inventory: InventoryResponseDTO = try decodeSuccess(response)
            if let problem = Self.validateInventory(inventory) {
                return .failure(problem)
            }
            return .success(inventory.computers.map { dto in
                let status = LoopbackDevelopmentClient.mapEnrollmentState(dto.enrollmentState)
                return Computer(
                    id: ComputerID(dto.id),
                    name: dto.friendlyName ?? dto.id,
                    trustedUserName: nil,
                    isOnline: status.isOnline,
                    needsAttention: status.needsAttention,
                    groupIDs: [],
                    enrollmentState: dto.enrollmentState,
                    statusLabel: status.statusLabel,
                    publicIdentity: dto.publicIdentity
                )
            })
        } catch let error as HelicoidError {
            return .failure(error)
        } catch {
            return .failure(.offline)
        }
    }

    public func managerApprovalState() async -> Result<ManagerApprovalState, HelicoidError> {
        guard tokenBox.token != nil else {
            return .failure(.notConfigured)
        }
        do {
            let response = try await get(path: "/v1/auth/session", authorized: true)
            let session: SessionResponseDTO = try decodeSuccess(response)
            guard let manager = session.manager else {
                return .success(.unknown)
            }
            if manager.isApproved { return .success(.approved) }
            if manager.isPending { return .success(.pending) }
            if manager.isRevoked { return .success(.denied) }
            return .success(.unknown)
        } catch let error as HelicoidError {
            return .failure(error)
        } catch {
            return .failure(.offline)
        }
    }

    public func signOut() async {
        let token = tokenBox.token
        let body: Data
        do {
            body = try encoder.encode(EmptySuccessDTO())
        } catch {
            signOutLocal()
            return
        }
        // Clear local material first; remote logout uses the pre-cleared token.
        generation &+= 1
        pending = nil
        clearLiveSession()
        guard token != nil else { return }
        do {
            let headers = [
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": "Bearer \(token ?? "")",
            ]
            _ = try await transportRequest(method: "POST", path: "/v1/auth/logout", headers: headers, body: body)
        } catch {
            // Local material is already cleared. Remote logout failure is not a grant.
        }
    }

    static func validateInventory(_ inventory: InventoryResponseDTO) -> HelicoidError? {
        if inventory.computers.count > 100 {
            return .invalidInput(field: "inventory", detail: "Inventory exceeded max_page_size 100.")
        }
        var seen = Set<String>()
        for computer in inventory.computers {
            let id = computer.id.trimmingCharacters(in: .whitespacesAndNewlines)
            if id.isEmpty {
                return .invalidInput(field: "inventory", detail: "Computer id must not be empty.")
            }
            if id.count > 128 {
                return .invalidInput(field: "inventory", detail: "Computer id exceeded 128 characters.")
            }
            if seen.contains(id) {
                return .invalidInput(field: "inventory", detail: "Duplicate computer id in inventory.")
            }
            seen.insert(id)
        }
        return nil
    }
}
