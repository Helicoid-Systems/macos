import CryptoKit
import Foundation

/// Exact Manager session generation and liveness check for one observation
/// operation. The generation is the app-level `ManagerSession` generation, not
/// the auth client's internal install counter (that is checked separately).
public struct ManagerObservationSessionFence: Sendable {
    public let generation: UInt64
    private let check: @Sendable (UInt64) async -> Bool

    public init(
        generation: UInt64,
        isCurrent: @escaping @Sendable (UInt64) async -> Bool
    ) {
        self.generation = generation
        self.check = isCurrent
    }

    public func isCurrent() async -> Bool {
        await check(generation)
    }
}

/// One verified, short-lived observation lease plus the exact session and
/// bearer incarnation that requested it. The grant token is intentionally not
/// retained: the Manager never redeems it and signaling routes by `grant_id`.
public struct ManagerObservationLease: Sendable, Equatable {
    public let grant: VerifiedObservationAdmissionGrant
    public let sessionGeneration: UInt64
    public let authGeneration: UInt64

    fileprivate let bearerFingerprint: Data

    public var grantID: String { grant.grantID }
    public var expiresAtUnix: Int64 { grant.expiresAtUnix }

    public func isCurrent(
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) -> Bool {
        grant.expiresAtUnix > nowUnixSeconds
    }
}

/// HTTP lease for Manager observation grant issuance and bounded signaling.
///
/// This type is deliberately narrower than a general HTTP client:
///
/// - It only exists on top of a production trust record previously persisted in
///   `ManagerAuthorityTrustStore`. There is no initializer that adopts an
///   observed authority or accepts a caller-supplied checkpoint.
/// - The public factory creates a `PinnedHTTPSTransport`; arbitrary transports
///   are not part of the public API. An internal executor seam exists only for
///   tests in this module.
/// - Every bearer-bearing request is fenced by the app session generation and
///   by the exact `NativeV2AuthClient` token/install generation.
/// - The server grant lifetime is at most 10 seconds. Publishing revalidates
///   live authority before and after the outbound state-changing request, and
///   polling revalidates live authority before accepting a returned batch.
///   Those pinned HTTPS authority round trips consume lease time; callers must
///   keep poll interval plus latency inside the remaining lease and renew
///   before it expires.
/// - A successful signal relay is negotiation only. No peer, capture, frame, or
///   preview success is inferred here.
public actor ManagerObservationLeaseClient {
    public static let maximumGrantResponseBytes = 16 * 1024
    public static let maximumSignalPublishResponseBytes = 16 * 1024
    private static let maximumGrantLifetimeSeconds: Int64 = 10

    private let authClient: NativeV2AuthClient
    private let executor: any ManagerObservationHTTPExecutor
    private let tlsIdentity: DeploymentTLSIdentity
    private let signingIdentity: ManagerSigningIdentity
    private let authorityTrust: ManagerAuthorityTrustStore
    private let savedRecord: ManagerAuthorityTrustRecord
    private let authorityRevalidator: @Sendable () async throws -> Void
    private let nowUnix: @Sendable () -> Int64

    private var savedAuthority: DeploymentAuthorityCheckpoint {
        savedRecord.checkpoint
    }

    public var deploymentID: String { tlsIdentity.deploymentID }
    public var authorityCheckpoint: DeploymentAuthorityCheckpoint {
        savedRecord.checkpoint
    }

    /// Production factory. The persisted production trust record must already
    /// exist and bind a TLS configuration; a legacy checkpoint-only record is
    /// refused. The live authority must exactly match that saved checkpoint
    /// before this client exists and before every later grant issuance.
    ///
    /// Production callers should obtain `tlsIdentity` and the signed-in auth
    /// client from the same `ManagerProductionConnection.makeVerifiedClient`
    /// composition, so the pinned origin is the one bound in that record.
    public static func make(
        authClient: NativeV2AuthClient,
        tlsIdentity: DeploymentTLSIdentity,
        authorityTrust: ManagerAuthorityTrustStore,
        signingIdentity: ManagerSigningIdentity
    ) async throws -> ManagerObservationLeaseClient {
        guard authClient.isProductionPinned else {
            throw HelicoidError.authenticationFailed(
                detail: "Observation requires a production-pinned authentication client."
            )
        }
        let configuration = try PinnedHTTPSConfiguration(
            identity: tlsIdentity,
            requestTimeout: 10,
            operationTimeout: 15,
            maxResponseBytes: PinnedHTTPSConfiguration.absoluteMaxResponseBytes
        )
        let transport = try PinnedHTTPSTransport(configuration: configuration)
        return try await make(
            authClient: authClient,
            executor: ManagerObservationPinnedExecutor(transport: transport),
            tlsIdentity: tlsIdentity,
            authorityTrust: authorityTrust,
            signingIdentity: signingIdentity
        )
    }

    /// Test seam. Production callers use the pinned factory above.
    static func make(
        authClient: NativeV2AuthClient,
        executor: any ManagerObservationHTTPExecutor,
        tlsIdentity: DeploymentTLSIdentity,
        authorityTrust: ManagerAuthorityTrustStore,
        signingIdentity: ManagerSigningIdentity,
        nowUnix: @escaping @Sendable () -> Int64 = {
            Int64(Date().timeIntervalSince1970)
        }
    ) async throws -> ManagerObservationLeaseClient {
        guard executor.originURL == tlsIdentity.originURL,
              authClient.trustedIdentity == tlsIdentity else {
            throw HelicoidError.identityMismatch
        }
        guard let record = try await authorityTrust.productionTrustRecord(
            deploymentID: tlsIdentity.deploymentID
        ) else {
            throw HelicoidError.authenticationFailed(
                detail: "No atomically bound production trust record is saved. Complete out-of-band production trust setup before requesting observation."
            )
        }
        try record.requireBoundTLSIdentity(tlsIdentity)
        let observed = try await authClient.fetchDeploymentAuthority()
        _ = try await authorityTrust.requireCurrent(observed)
        guard observed == record.checkpoint else {
            throw HelicoidError.identityMismatch
        }
        guard try await authorityTrust.verifyProductionTrustRecord(
            record,
            deploymentID: tlsIdentity.deploymentID
        ) else {
            throw HelicoidError.identityMismatch
        }
        let deploymentID = await authClient.deploymentID
        guard deploymentID == tlsIdentity.deploymentID else {
            throw HelicoidError.identityMismatch
        }
        let managerPublicKeyHex = await authClient.managerPublicKeyHex
        guard managerPublicKeyHex == AuthV2Canonical.lowercaseHex(
            signingIdentity.publicKey
        ) else {
            throw HelicoidError.identityMismatch
        }

        let savedAuthority = record.checkpoint
        let revalidator: @Sendable () async throws -> Void = {
            guard try await authorityTrust.verifyProductionTrustRecord(
                record,
                deploymentID: tlsIdentity.deploymentID
            ) else {
                throw HelicoidError.identityMismatch
            }
            let observed = try await authClient.fetchDeploymentAuthority()
            _ = try await authorityTrust.requireCurrent(observed)
            guard observed == savedAuthority else {
                throw HelicoidError.identityMismatch
            }
            guard try await authorityTrust.verifyProductionTrustRecord(
                record,
                deploymentID: tlsIdentity.deploymentID
            ) else {
                throw HelicoidError.identityMismatch
            }
        }
        return try ManagerObservationLeaseClient(
            authClient: authClient,
            executor: executor,
            tlsIdentity: tlsIdentity,
            signingIdentity: signingIdentity,
            authorityTrust: authorityTrust,
            savedRecord: record,
            authorityRevalidator: revalidator,
            nowUnix: nowUnix
        )
    }

    init(
        authClient: NativeV2AuthClient,
        executor: any ManagerObservationHTTPExecutor,
        tlsIdentity: DeploymentTLSIdentity,
        signingIdentity: ManagerSigningIdentity,
        authorityTrust: ManagerAuthorityTrustStore,
        savedRecord: ManagerAuthorityTrustRecord,
        authorityRevalidator: @escaping @Sendable () async throws -> Void,
        nowUnix: @escaping @Sendable () -> Int64
    ) throws {
        guard executor.originURL == tlsIdentity.originURL,
              savedRecord.checkpoint.deploymentID == tlsIdentity.deploymentID else {
            throw HelicoidError.identityMismatch
        }
        try savedRecord.requireBoundTLSIdentity(tlsIdentity)
        self.authClient = authClient
        self.executor = executor
        self.tlsIdentity = tlsIdentity
        self.signingIdentity = signingIdentity
        self.authorityTrust = authorityTrust
        self.savedRecord = savedRecord
        self.authorityRevalidator = authorityRevalidator
        self.nowUnix = nowUnix
    }

    /// Recheck the exact persisted production trust record and the live pinned
    /// authority. The caller may invoke this before starting peer setup;
    /// `issueGrant` always invokes it before and after sending the bearer.
    public func requireAuthorityCurrent() async throws {
        try await requireExactRecord()
        try await authorityRevalidator()
        try await requireExactRecord()
    }

    /// Require the full persisted record (checkpoint *and* bound TLS
    /// configuration) to still equal the record captured at client creation.
    /// This detects reset, deletion, checkpoint changes, and config-only edits.
    private func requireExactRecord() async throws {
        guard try await authorityTrust.verifyProductionTrustRecord(
            savedRecord,
            deploymentID: tlsIdentity.deploymentID
        ) else {
            throw HelicoidError.identityMismatch
        }
        try savedRecord.requireBoundTLSIdentity(tlsIdentity)
    }

    // MARK: Grant issuance

    /// Request one short-lived grant for the exact Manager session and computer.
    /// The response token is verified with `verifyForManager` before a lease is
    /// returned. No lease is returned for an invalid or mismatched token.
    public func issueGrant(
        expectation: ObservationAdmissionManagerExpectation,
        fence: ManagerObservationSessionFence
    ) async throws -> ManagerObservationLease {
        guard !Task.isCancelled else { throw HelicoidError.cancelled }
        guard expectation.deploymentID == tlsIdentity.deploymentID,
              expectation.managerPublicKeyHex == signingKeyHex else {
            throw HelicoidError.identityMismatch
        }
        guard Self.isCanonicalUUID(expectation.computerID) else {
            throw HelicoidError.invalidInput(
                field: "computer_id",
                detail: "The selected computer identifier is invalid."
            )
        }
        try await requireSessionCurrent(fence)
        try await requireExactRecord()
        try await authorityRevalidator()
        try await requireExactRecord()
        try await validateAuthBinding()
        let bearer = try await liveBearer()
        try await requireSessionCurrent(fence)
        try await requireExactRecord()

        let requestBody = try JSONEncoder().encode(
            ManagerObservationGrantRequest(computerID: expectation.computerID)
        )
        let url = try requestURL(path: "/v2/admissions/observation")
        let response = try await perform(
            method: "POST",
            url: url,
            bearerToken: bearer.token,
            body: requestBody,
            maxBytes: Self.maximumGrantResponseBytes
        )

        try await requireSessionCurrent(fence)
        try await validateAuthBinding()
        try await ensureSameBearer(bearer)
        guard response.statusCode == 201 else {
            throw serverError(status: response.statusCode, operation: "observation grant")
        }
        // A grant response is only usable while the exact saved trust record
        // still exists and the live authority still matches it.
        try await authorityRevalidator()
        try await requireExactRecord()
        guard let decoded = Self.decodeGrantResponse(response.body) else {
            throw HelicoidError.serverContractUnavailable
        }
        let receivedAt = nowUnix()
        let (latestExpiry, overflow) = receivedAt.addingReportingOverflow(
            Self.maximumGrantLifetimeSeconds
        )
        guard !overflow,
              decoded.expiresAtUnix > receivedAt,
              decoded.expiresAtUnix <= latestExpiry else {
            throw HelicoidError.serverContractUnavailable
        }

        let grant = try ObservationAdmissionGrantVerifier.verifyForManager(
            token: decoded.grantToken,
            serverPublicKeyHex: savedAuthority.grantSigningPublicKeyHex,
            expected: expectation,
            nowUnixSeconds: receivedAt
        )
        guard grant.grantID == decoded.grantID,
              grant.computerID == decoded.computerID,
              grant.expiresAtUnix == decoded.expiresAtUnix else {
            throw HelicoidError.serverContractUnavailable
        }

        try await requireSessionCurrent(fence)
        try await validateAuthBinding()
        try await ensureSameBearer(bearer)
        try await requireExactRecord()
        return ManagerObservationLease(
            grant: grant,
            sessionGeneration: fence.generation,
            authGeneration: bearer.generation,
            bearerFingerprint: bearer.fingerprint
        )
    }

    // MARK: Signaling

    /// Fetch one bounded endpoint signaling batch. The envelope is validated by
    /// `ManagerObservationSignalingSession.decodeBatch`; the caller must still
    /// feed the batch into its state machine to check sender, kind, order, and
    /// challenge attestation.
    ///
    /// A returned batch is accepted only after a live pinned-authority
    /// revalidation. That HTTPS round trip consumes part of the grant's
    /// at-most-10-second lease; poll intervals and latency must fit inside the
    /// remaining lease.
    public func pollSignals(
        for lease: ManagerObservationLease,
        after cursor: UInt64,
        fence: ManagerObservationSessionFence
    ) async throws -> ObservationSignalBatch {
        guard !Task.isCancelled else { throw HelicoidError.cancelled }
        guard cursor <= ManagerObservationSignalingSession.maximumSignalSequence else {
            throw Self.invalidSignalCursor()
        }
        let before = try await requireLeaseCurrent(lease, fence: fence)
        let url = try requestURL(
            path: "/v2/admissions/observation/\(lease.grantID)/signals",
            queryItems: [URLQueryItem(name: "after", value: String(cursor))]
        )
        try await requireExactRecord()
        let response = try await perform(
            method: "GET",
            url: url,
            bearerToken: before.token,
            body: nil,
            maxBytes: min(
                ManagerObservationSignalingSession.maximumBatchBytes,
                PinnedHTTPSConfiguration.absoluteMaxResponseBytes
            )
        )

        try await requireSessionCurrent(fence)
        try await validateAuthBinding()
        try await ensureSameBearer(before)
        guard response.statusCode == 200 else {
            throw serverError(status: response.statusCode, operation: "observation signal poll")
        }
        // Accept a polled batch only while the persisted record and live pinned
        // authority are still current. This HTTPS round trip consumes lease time.
        try await requireAuthorityCurrent()
        try await requireLeaseGrantCurrent(lease)
        try await requireSessionCurrent(fence)
        try await ensureSameBearer(before)
        let batch = try ManagerObservationSignalingSession.decodeBatch(response.body)
        guard batch.cursor >= cursor else {
            throw Self.invalidSignalCursor()
        }
        try await requireExactRecord()
        return batch
    }

    /// Relay one bounded Manager signaling value. Offers are rejected here:
    /// they must go through `publishAttestedOffer` so arbitrary SDP can never
    /// be relayed without the signed Manager certificate attribute.
    ///
    /// Outbound relay revalidates live pinned authority both before sending and
    /// after the server accepts it. Both authority round trips consume the
    /// grant's at-most-10-second lease.
    public func publishSignal(
        for lease: ManagerObservationLease,
        kind: ObservationSignalKind,
        payload: String,
        fence: ManagerObservationSessionFence
    ) async throws {
        guard !Task.isCancelled else { throw HelicoidError.cancelled }
        try Self.validateOutboundSignal(kind: kind, payload: payload)
        try await relaySignal(
            for: lease,
            kind: kind,
            payload: payload,
            fence: fence
        )
    }

    /// Relay the attested Manager offer. The value can only be produced by
    /// `VerifiedObservationAdmissionGrant.attestedOffer`, and it is rechecked
    /// here against this lease's signed grant before any request is sent.
    ///
    /// This is a state-changing outbound relay: live pinned authority is
    /// revalidated before and after it, consuming part of the short lease.
    public func publishAttestedOffer(
        for lease: ManagerObservationLease,
        offer: ManagerObservationAttestedOffer,
        fence: ManagerObservationSessionFence
    ) async throws {
        guard !Task.isCancelled else { throw HelicoidError.cancelled }
        guard offer.grantID == lease.grantID,
              offer.signature.count == 64,
              lease.grant.verifiesPeerCertificateAttestation(
                certificatePEM: offer.certificatePEM,
                endpointNonceHex: offer.endpointNonceHex,
                role: .manager,
                signature: offer.signature,
                nowUnixSeconds: nowUnix()
              ),
              Self.isValidAttestedOfferPayload(offer.sdp) else {
            throw HelicoidError.observationProtocolViolation(
                detail: "The Manager offer is not signed by this verified grant's certificate attestation. The Manager session remains active."
            )
        }
        try await relaySignal(
            for: lease,
            kind: .offer,
            payload: offer.sdp,
            fence: fence
        )
    }

    private func relaySignal(
        for lease: ManagerObservationLease,
        kind: ObservationSignalKind,
        payload: String,
        fence: ManagerObservationSessionFence
    ) async throws {
        let before = try await requireLeaseCurrent(lease, fence: fence)
        let requestBody = try JSONEncoder().encode(
            ManagerObservationSignalRequest(kind: kind.rawValue, payload: payload)
        )
        let url = try requestURL(
            path: "/v2/admissions/observation/\(lease.grantID)/signals"
        )
        // State-changing relays revalidate live authority before sending. The
        // pinned HTTPS round trip consumes part of the 10-second grant lease.
        try await requireAuthorityCurrent()
        try await requireLeaseGrantCurrent(lease)
        let response = try await perform(
            method: "POST",
            url: url,
            bearerToken: before.token,
            body: requestBody,
            maxBytes: Self.maximumSignalPublishResponseBytes
        )

        try await requireSessionCurrent(fence)
        try await validateAuthBinding()
        try await ensureSameBearer(before)
        guard response.statusCode == 204, response.body.isEmpty else {
            throw serverError(status: response.statusCode, operation: "observation signal publish")
        }
        // Do not report publish success unless authority is still current after
        // the server accepted the state-changing outbound value.
        try await requireAuthorityCurrent()
        try await requireLeaseGrantCurrent(lease)
        try await requireSessionCurrent(fence)
        try await ensureSameBearer(before)
        try await requireExactRecord()
    }

    // MARK: Session and authority fencing

    private struct BearerSnapshot: Sendable, Equatable {
        let token: String
        let generation: UInt64
        let fingerprint: Data
    }

    private var signingKeyHex: String {
        AuthV2Canonical.lowercaseHex(signingIdentity.publicKey)
    }

    private func requireSessionCurrent(
        _ fence: ManagerObservationSessionFence
    ) async throws {
        guard !Task.isCancelled else {
            throw HelicoidError.cancelled
        }
        guard await fence.isCurrent() else {
            throw Self.invalidatedObservationSession()
        }
    }

    private func validateAuthBinding() async throws {
        let deploymentID = await authClient.deploymentID
        let managerPublicKeyHex = await authClient.managerPublicKeyHex
        guard deploymentID == tlsIdentity.deploymentID,
              managerPublicKeyHex == signingKeyHex else {
            throw HelicoidError.identityMismatch
        }
    }

    private func liveBearer() async throws -> BearerSnapshot {
        do {
            let pair = try await authClient.currentBearerForRequest()
            guard !pair.token.isEmpty else {
                throw HelicoidError.sessionExpired(
                    detail: "Your session expired. Sign in again."
                )
            }
            return BearerSnapshot(
                token: pair.token,
                generation: pair.generation,
                fingerprint: Data(SHA256.hash(data: Data(pair.token.utf8)))
            )
        } catch let error as HelicoidError where error == .notConfigured {
            throw HelicoidError.sessionExpired(
                detail: "The Manager session ended. Request a new observation grant."
            )
        }
    }

    private func ensureSameBearer(_ snapshot: BearerSnapshot) async throws {
        let current = try await liveBearer()
        guard current.generation == snapshot.generation,
              current.fingerprint == snapshot.fingerprint else {
            throw HelicoidError.sessionExpired(
                detail: "The Manager session changed. Request a new observation grant."
            )
        }
    }

    private func requireLeaseCurrent(
        _ lease: ManagerObservationLease,
        fence: ManagerObservationSessionFence
    ) async throws -> BearerSnapshot {
        guard fence.generation == lease.sessionGeneration else {
            throw Self.invalidatedObservationSession()
        }
        try await requireSessionCurrent(fence)
        try await requireExactRecord()
        try await requireLeaseGrantCurrent(lease)
        try await validateAuthBinding()
        let current = try await liveBearer()
        guard current.generation == lease.authGeneration,
              current.fingerprint == lease.bearerFingerprint else {
            throw HelicoidError.sessionExpired(
                detail: "The observation grant belongs to a previous Manager session."
            )
        }
        return current
    }

    private func requireLeaseGrantCurrent(
        _ lease: ManagerObservationLease
    ) async throws {
        guard lease.isCurrent(nowUnixSeconds: nowUnix()) else {
            throw HelicoidError.authenticationFailed(
                detail: "The observation grant has expired. Request a new preview."
            )
        }
    }

    // MARK: HTTP plumbing

    private struct ManagerObservationGrantRequest: Encodable {
        let computerID: String

        enum CodingKeys: String, CodingKey {
            case computerID = "computer_id"
        }
    }

    private struct ManagerObservationSignalRequest: Encodable {
        let kind: String
        let payload: String
    }

    private struct ManagerObservationGrantResponse: Sendable {
        let grantID: String
        let computerID: String
        let expiresAtUnix: Int64
        let grantToken: String
    }

    private func perform(
        method: String,
        url: URL,
        bearerToken: String,
        body: Data?,
        maxBytes: Int
    ) async throws -> ManagerObservationHTTPResult {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let response = try await executor.perform(request, maxBytes: maxBytes)
        guard response.url == url else {
            throw HelicoidError.serverContractUnavailable
        }
        if response.statusCode == 401 {
            // Clear only this exact token. A replacement session installed
            // while the request was in flight must survive.
            await authClient.signOutLocal(ifToken: bearerToken)
            throw HelicoidError.sessionExpired(
                detail: "Your Manager session expired or was revoked. Sign in again."
            )
        }
        return response
    }

    private func requestURL(
        path: String,
        queryItems: [URLQueryItem]? = nil
    ) throws -> URL {
        guard var components = URLComponents(
            url: tlsIdentity.originURL,
            resolvingAgainstBaseURL: false
        ) else {
            throw HelicoidError.notConfigured
        }
        components.path = path
        components.queryItems = queryItems
        components.fragment = nil
        guard let url = components.url else {
            throw HelicoidError.invalidInput(
                field: "path",
                detail: "Invalid observation request path."
            )
        }
        return url
    }

    private func serverError(status: Int, operation: String) -> HelicoidError {
        switch status {
        case 401:
            return .sessionExpired(detail: "Your Manager session expired. Sign in again.")
        case 403:
            return .permissionDenied(
                detail: "The server refused the \(operation) for this account or computer."
            )
        case 409:
            return .observationProtocolViolation(
                detail: "The observation exchange is out of order or already closed."
            )
        case 429:
            return .observationProtocolViolation(
                detail: "The short-lived observation limit was reached. Try again shortly."
            )
        default:
            return .serverContractUnavailable
        }
    }

    private static func decodeGrantResponse(
        _ data: Data
    ) -> ManagerObservationGrantResponse? {
        guard !data.isEmpty, data.count <= maximumGrantResponseBytes,
              let root = try? JSONSerialization.jsonObject(with: data),
              let object = root as? [String: Any],
              Set(object.keys) == Set([
                  "grant_id", "computer_id", "expires_at_unix", "grant_token",
              ]),
              let grantID = object["grant_id"] as? String,
              isCanonicalUUID(grantID),
              let computerID = object["computer_id"] as? String,
              let expiresNumber = object["expires_at_unix"] as? NSNumber,
              !(object["expires_at_unix"] is Bool),
              let expiresAtUnix = Int64(exactly: expiresNumber.doubleValue),
              let grantToken = object["grant_token"] as? String,
              !grantToken.isEmpty,
              grantToken.utf8.count <= 8 * 1024,
              grantToken.utf8.allSatisfy({ $0 < 0x80 && $0 != 0 }) else {
            return nil
        }
        return ManagerObservationGrantResponse(
            grantID: grantID,
            computerID: computerID,
            expiresAtUnix: expiresAtUnix,
            grantToken: grantToken
        )
    }

    private static func validateOutboundSignal(
        kind: ObservationSignalKind,
        payload: String
    ) throws {
        let byteCount = payload.utf8.count
        switch kind {
        case .offer:
            throw HelicoidError.observationProtocolViolation(
                detail: "An attested Manager offer is required. Use publishAttestedOffer with a signed certificate attribute."
            )
        case .ice:
            guard byteCount > 0,
                  byteCount <= ManagerObservationSignalingSession.maximumICEBytes,
                  hasValidSignalPayloadCharacters(payload) else {
                throw HelicoidError.observationProtocolViolation(
                    detail: "The Manager ICE candidate is invalid or exceeds the signaling size limit."
                )
            }
        case .close:
            guard payload.isEmpty else {
                throw HelicoidError.observationProtocolViolation(
                    detail: "A close signal must have an empty payload."
                )
            }
        case .answer:
            throw HelicoidError.observationProtocolViolation(
                detail: "The endpoint sends observation answers; the Manager cannot relay one."
            )
        }
    }

    private static func isValidAttestedOfferPayload(_ payload: String) -> Bool {
        let byteCount = payload.utf8.count
        return byteCount > 0
            && byteCount <= ManagerObservationSignalingSession.maximumAnswerBytes
            && payload.hasPrefix("v=0")
            && hasValidSignalPayloadCharacters(payload)
            && payload.range(
                of: ManagerObservationSDP.certificateAttributePrefix
            ) != nil
    }

    private static func hasValidSignalPayloadCharacters(_ value: String) -> Bool {
        value.utf8.allSatisfy { byte in
            if byte == 0x09 || byte == 0x0A || byte == 0x0D { return true }
            return !(byte < 0x20 || byte == 0x7F)
        }
    }

    private static func isCanonicalUUID(_ value: String) -> Bool {
        UUID(uuidString: value)?.uuidString.lowercased() == value
    }

    private static func invalidSignalCursor() -> HelicoidError {
        .observationProtocolViolation(
            detail: "The observation signaling cursor is outside the current grant. The Manager session remains active."
        )
    }

    /// A stale app-level observation fence is not task cancellation. It is an
    /// explicit observation-session invalidation; no network request may follow.
    private static func invalidatedObservationSession() -> HelicoidError {
        .sessionExpired(
            detail: "The Manager observation session generation changed. Request a new preview."
        )
    }
}

// MARK: - Internal transport seam

protocol ManagerObservationHTTPExecutor: Sendable {
    var originURL: URL { get }
    func perform(
        _ request: URLRequest,
        maxBytes: Int
    ) async throws -> ManagerObservationHTTPResult
}

struct ManagerObservationHTTPResult: Sendable {
    let statusCode: Int
    let body: Data
    let url: URL
}

struct ManagerObservationPinnedExecutor: ManagerObservationHTTPExecutor {
    let transport: PinnedHTTPSTransport

    var originURL: URL { transport.originURL }

    func perform(
        _ request: URLRequest,
        maxBytes: Int
    ) async throws -> ManagerObservationHTTPResult {
        do {
            let response = try await transport.requestStatus(
                for: request,
                maxBytes: maxBytes
            )
            return ManagerObservationHTTPResult(
                statusCode: response.statusCode,
                body: response.body,
                url: response.url
            )
        } catch is CancellationError {
            throw HelicoidError.cancelled
        } catch let error as HelicoidError {
            throw error
        } catch {
            throw HelicoidError.unreachable
        }
    }
}
