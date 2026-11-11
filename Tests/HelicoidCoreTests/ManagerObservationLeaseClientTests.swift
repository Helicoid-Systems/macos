import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

private struct LeaseNoopAuthorityLock: ManagerAuthorityLocking {
    func acquire() async throws -> any ManagerAuthorityLockReleasing {
        LeaseNoopAuthorityHandle()
    }
}

private struct LeaseNoopAuthorityHandle: ManagerAuthorityLockReleasing {
    func release() {}
}

private actor LeaseAuthorityKeyStore: ManagerAuthorityKeyStoring {
    private var values: [String: Data] = [:]

    func read(account: String) throws -> Data? { values[account] }

    func insertIfAbsent(_ bytes: Data, account: String) throws -> Bool {
        guard values[account] == nil else { return false }
        values[account] = bytes
        return true
    }

    func update(_ bytes: Data, account: String) throws {
        guard values[account] != nil else { throw HelicoidError.offline }
        values[account] = bytes
    }

    func delete(account: String) throws {
        values.removeValue(forKey: account)
    }

    func allAccounts() -> [String] { Array(values.keys) }
}

private final class LeaseObservationExecutor: ManagerObservationHTTPExecutor, @unchecked Sendable {
    struct Stub {
        let status: Int
        let body: Data
        var responseURL: URL? = nil
    }

    let originURL: URL
    private let lock = NSLock()
    private var stubs: [Stub] = []
    private var recordedRequests: [URLRequest] = []
    private var onRequest: (@Sendable (URLRequest) async throws -> Void)?

    init(originURL: URL) {
        self.originURL = originURL
    }

    func enqueue(_ stub: Stub) {
        lock.lock()
        stubs.append(stub)
        lock.unlock()
    }

    func setOnRequest(
        _ body: @escaping @Sendable (URLRequest) async throws -> Void
    ) {
        lock.lock()
        onRequest = body
        lock.unlock()
    }

    var requests: [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return recordedRequests
    }

    var requestCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return recordedRequests.count
    }

    func perform(
        _ request: URLRequest,
        maxBytes: Int
    ) async throws -> ManagerObservationHTTPResult {
        lock.lock()
        recordedRequests.append(request)
        guard !stubs.isEmpty else {
            lock.unlock()
            throw HelicoidError.offline
        }
        let stub = stubs.removeFirst()
        let hook = onRequest
        lock.unlock()
        if let hook {
            try await hook(request)
        }
        guard stub.body.count <= maxBytes else {
            throw HelicoidError.invalidInput(
                field: "response",
                detail: "Response body exceeded the bounded size limit."
            )
        }
        return ManagerObservationHTTPResult(
            statusCode: stub.status,
            body: stub.body,
            url: stub.responseURL ?? request.url!
        )
    }
}

private final class LeaseManualClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int64

    init(_ value: Int64) {
        self.value = value
    }

    var now: Int64 {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func set(_ value: Int64) {
        lock.lock()
        self.value = value
        lock.unlock()
    }
}

private actor LeaseStartGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var opened = false

    func wait() async {
        if opened { return }
        await withCheckedContinuation { continuation = $0 }
    }

    func open() {
        opened = true
        continuation?.resume()
        continuation = nil
    }
}

@Suite("Manager observation HTTP lease")
struct ManagerObservationLeaseClientTests {
    private static let now: Int64 = 1_800_000_000
    private static let deploymentID = "dep_" + String(repeating: "a", count: 32)
    private static let grantID = "b8eeedb7-1d8d-4c29-9e13-05ec6045a173"
    private static let accountID = "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d"
    private static let managerID = "7a01cf88-6fdb-4cc1-a72f-d155f5309355"
    private static let computerID = "6b7b0f41-8af7-4a09-90d0-91c9cd1c0dc9"
    private static let endpointSessionID = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1"
    private static let endpointNonce = String(repeating: "ab", count: 32)
    private static let certificatePEM = Data(
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".utf8
    )

    private struct Environment {
        let trust: DeploymentTLSIdentity
        let authClient: NativeV2AuthClient
        let authTransport: FixtureTransport
        let authorityTrust: ManagerAuthorityTrustStore
        let checkpoint: DeploymentAuthorityCheckpoint
        let managerIdentity: ManagerSigningIdentity
        let serverKey: Curve25519.Signing.PrivateKey
        let endpointKey: Curve25519.Signing.PrivateKey
        let expectation: ObservationAdmissionManagerExpectation
        let token: String
    }

    private func lowerHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private func makeTrust() async throws -> DeploymentTLSIdentity {
        let material = try await TLSTestHarness.sharedMaterial()
        return try DeploymentTLSIdentity(
            deploymentID: Self.deploymentID,
            host: "server.test",
            port: 8443,
            caDER: material.caDER,
            caFingerprintSHA256: material.caFingerprint
        )
    }

    private func authorityJSON(_ checkpoint: DeploymentAuthorityCheckpoint) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "deployment_id": checkpoint.deploymentID,
            "grant_signing_public_key": checkpoint.grantSigningPublicKeyHex,
            "authority_generation": Int(checkpoint.authorityGeneration),
        ])
    }

    private func makeEnvironment(
        seedTrust: Bool,
        generation: UInt64 = 1
    ) async throws -> Environment {
        let trust = try await makeTrust()
        let realNow = Int(Date().timeIntervalSince1970)
        let managerKey = Curve25519.Signing.PrivateKey()
        let managerIdentity = try ManagerSigningIdentity(
            storedBytes: Data([1]) + managerKey.rawRepresentation
        )
        let managerKeyHex = lowerHex(managerIdentity.publicKey)

        let authTransport = FixtureTransport()
        let authClient = NativeV2AuthClient(
            transport: authTransport,
            trustedAuthority: trust,
            signingIdentity: managerIdentity
        )
        authTransport.stub = .init(
            status: 201,
            body: try JSONSerialization.data(withJSONObject: [
                "challenge_id": "challenge-1",
                "challenge_token": "challenge-token-secret",
                "operation": "session",
                "manager_public_key": managerKeyHex,
                "deployment_id": Self.deploymentID,
                "expires_at_unix": realNow + 60,
                "mfa_required": true,
            ])
        )
        let challenge = try await authClient.beginChallenge(
            username: "operator",
            password: "fixture"
        )
        authTransport.stub = .init(
            status: 200,
            body: try JSONSerialization.data(withJSONObject: [
                "token": "bearer-token-secret",
                "expires_at_unix": realNow + 3_600,
                "account": [
                    "id": Self.accountID,
                    "username": "operator",
                    "state": "active",
                    "capabilities": ["operate": true],
                    "revision": 1,
                ] as [String: Any],
                "manager": [
                    "id": Self.managerID,
                    "public_identity": "key:\(managerKeyHex)",
                    "lifecycle_state": "approved",
                ] as [String: Any],
                "manager_public_key": managerKeyHex,
                "mfa": [
                    "required": true,
                    "available": true,
                    "reason": "totp_active",
                ] as [String: Any],
            ])
        )
        _ = try await authClient.completeChallenge(challenge, totpCode: "123456")

        let serverKey = Curve25519.Signing.PrivateKey()
        let endpointKey = Curve25519.Signing.PrivateKey()
        let checkpoint = try DeploymentAuthorityCheckpoint(
            deploymentID: Self.deploymentID,
            grantSigningPublicKeyHex: lowerHex(serverKey.publicKey.rawRepresentation),
            authorityGeneration: generation
        )
        let keyStore = LeaseAuthorityKeyStore()
        let authorityTrust = ManagerAuthorityTrustStore(
            keyStore: keyStore,
            authorityLock: LeaseNoopAuthorityLock()
        )
        if seedTrust {
            let configuration = ManagerProductionTrustConfiguration(
                tlsIdentity: trust
            )
            let record = try ManagerAuthorityTrustRecord(
                checkpoint: checkpoint,
                configurationData: try configuration.encodedForTrustRecord()
            )
            let confirmation = try ManagerAuthorityConfirmation(
                operatorEnteredDeploymentID: checkpoint.deploymentID,
                operatorEnteredKeyFingerprintSHA256: checkpoint
                    .grantSigningKeyFingerprintSHA256,
                operatorEnteredAuthorityGeneration: checkpoint.authorityGeneration
            )
            #expect(try await authorityTrust.commitProductionTrustRecord(
                record,
                expected: nil,
                confirmation: confirmation
            ) == .committed)
        }
        authTransport.stub = .init(
            status: 200,
            body: try authorityJSON(checkpoint)
        )

        let claims = Data(
            "{\"version\":1,\"grant_id\":\"\(Self.grantID)\",\"deployment_id\":\"\(Self.deploymentID)\",\"account_id\":\"\(Self.accountID)\",\"manager_id\":\"\(Self.managerID)\",\"manager_public_key\":\"\(managerKeyHex)\",\"computer_id\":\"\(Self.computerID)\",\"endpoint_public_key\":\"\(lowerHex(endpointKey.publicKey.rawRepresentation))\",\"endpoint_session_id\":\"\(Self.endpointSessionID)\",\"enrollment_epoch\":1,\"issued_at_unix\":\(Self.now),\"expires_at_unix\":\(Self.now + 10),\"capability\":\"observe\"}".utf8
        )
        let signature = try serverKey.signature(
            for: Data("hs-observation-grant-v1\0".utf8) + claims
        )
        let token = claims.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            + "." + lowerHex(signature)

        return Environment(
            trust: trust,
            authClient: authClient,
            authTransport: authTransport,
            authorityTrust: authorityTrust,
            checkpoint: checkpoint,
            managerIdentity: managerIdentity,
            serverKey: serverKey,
            endpointKey: endpointKey,
            expectation: ObservationAdmissionManagerExpectation(
                deploymentID: Self.deploymentID,
                accountID: Self.accountID,
                computerID: Self.computerID,
                managerID: Self.managerID,
                managerPublicKeyHex: managerKeyHex
            ),
            token: token
        )
    }

    private func grantResponse(
        token: String,
        computerID: String = ManagerObservationLeaseClientTests.computerID,
        expiresAtUnix: Int64 = ManagerObservationLeaseClientTests.now + 10,
        grantID: String = ManagerObservationLeaseClientTests.grantID
    ) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "grant_id": grantID,
            "computer_id": computerID,
            "expires_at_unix": Int(expiresAtUnix),
            "grant_token": token,
        ])
    }

    private func makeClient(
        environment: Environment,
        executor: LeaseObservationExecutor,
        nowUnix: @escaping @Sendable () -> Int64 = {
            ManagerObservationLeaseClientTests.now
        }
    ) async throws -> ManagerObservationLeaseClient {
        try await ManagerObservationLeaseClient.make(
            authClient: environment.authClient,
            executor: executor,
            tlsIdentity: environment.trust,
            authorityTrust: environment.authorityTrust,
            signingIdentity: environment.managerIdentity,
            nowUnix: nowUnix
        )
    }

    private func fence(_ generation: UInt64 = 7) -> ManagerObservationSessionFence {
        ManagerObservationSessionFence(generation: generation) { $0 == generation }
    }

    @Test("Issues a verified grant with the current bearer and pinned origin")
    func issuesVerifiedGrant() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence()
        )
        #expect(lease.grant.grantID == Self.grantID)
        #expect(lease.grant.computerID == Self.computerID)
        #expect(lease.sessionGeneration == 7)

        let request = try #require(executor.requests.first)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.scheme == "https")
        #expect(request.url?.host == "server.test")
        #expect(request.url?.port == 8443)
        #expect(request.url?.path == "/v2/admissions/observation")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer bearer-token-secret")
        let body = try #require(request.httpBody)
        let bodyJSON = try JSONSerialization.jsonObject(with: body)
        let object = try #require(bodyJSON as? [String: Any])
        #expect(object["computer_id"] as? String == Self.computerID)
    }

    @Test("Polls and publishes only bounded Manager signals")
    func relaysBoundedSignals() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence()
        )

        executor.enqueue(.init(
            status: 200,
            body: Data(#"{"cursor":0,"messages":[]}"#.utf8)
        ))
        let batch = try await client.pollSignals(
            for: lease,
            after: 0,
            fence: fence()
        )
        #expect(batch.cursor == 0)
        #expect(batch.messages.isEmpty)
        let pollRequest = try #require(executor.requests.last)
        #expect(pollRequest.httpMethod == "GET")
        #expect(pollRequest.url?.path == "/v2/admissions/observation/\(Self.grantID)/signals")
        #expect(pollRequest.url?.query == "after=0")
        #expect(pollRequest.value(forHTTPHeaderField: "Authorization") == "Bearer bearer-token-secret")

        executor.enqueue(.init(status: 204, body: Data()))
        let plainOffer = "v=0\r\ns=-\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        let attestedOffer = try lease.grant.attestedOffer(
            sdp: plainOffer,
            certificatePEM: Self.certificatePEM,
            endpointNonceHex: Self.endpointNonce,
            identity: environment.managerIdentity,
            nowUnixSeconds: Self.now
        )
        try await client.publishAttestedOffer(
            for: lease,
            offer: attestedOffer,
            fence: fence()
        )
        let offerRequest = try #require(executor.requests.last)
        #expect(offerRequest.httpMethod == "POST")
        let offerBody = try #require(offerRequest.httpBody)
        let offerJSON = try JSONSerialization.jsonObject(with: offerBody)
        let offerObject = try #require(offerJSON as? [String: Any])
        #expect(offerObject["kind"] as? String == "offer")
        #expect(offerObject["payload"] as? String == attestedOffer.sdp)
        #expect(attestedOffer.sdp.contains(ManagerObservationSDP.certificateAttributePrefix))

        let count = executor.requestCount
        await #expect(throws: HelicoidError.self) {
            try await client.publishSignal(
                for: lease,
                kind: .offer,
                payload: plainOffer,
                fence: fence()
            )
        }
        await #expect(throws: HelicoidError.self) {
            try await client.publishSignal(
                for: lease,
                kind: .offer,
                payload: attestedOffer.sdp,
                fence: fence()
            )
        }
        await #expect(throws: HelicoidError.self) {
            try await client.publishSignal(
                for: lease,
                kind: .answer,
                payload: "v=0\r\n",
                fence: fence()
            )
        }
        await #expect(throws: HelicoidError.self) {
            try await client.publishSignal(
                for: lease,
                kind: .ice,
                payload: String(repeating: "a", count: 4_097),
                fence: fence()
            )
        }
        #expect(executor.requestCount == count)
    }

    @Test("Rejects an attested offer built for another grant")
    func rejectsOfferFromAnotherGrant() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence()
        )

        let otherGrantID = "11111111-1111-4111-8111-111111111111"
        let claims = Data(
            "{\"version\":1,\"grant_id\":\"\(otherGrantID)\",\"deployment_id\":\"\(Self.deploymentID)\",\"account_id\":\"\(Self.accountID)\",\"manager_id\":\"\(Self.managerID)\",\"manager_public_key\":\"\(lowerHex(environment.managerIdentity.publicKey))\",\"computer_id\":\"\(Self.computerID)\",\"endpoint_public_key\":\"\(lowerHex(environment.endpointKey.publicKey.rawRepresentation))\",\"endpoint_session_id\":\"\(Self.endpointSessionID)\",\"enrollment_epoch\":1,\"issued_at_unix\":\(Self.now),\"expires_at_unix\":\(Self.now + 10),\"capability\":\"observe\"}".utf8
        )
        let signature = try environment.serverKey.signature(
            for: Data("hs-observation-grant-v1\0".utf8) + claims
        )
        let otherToken = claims.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            + "." + lowerHex(signature)
        let otherGrant = try ObservationAdmissionGrantVerifier.verifyForManager(
            token: otherToken,
            serverPublicKeyHex: environment.checkpoint.grantSigningPublicKeyHex,
            expected: ObservationAdmissionManagerExpectation(
                deploymentID: Self.deploymentID,
                accountID: Self.accountID,
                computerID: Self.computerID,
                managerID: Self.managerID,
                managerPublicKeyHex: lowerHex(environment.managerIdentity.publicKey)
            ),
            nowUnixSeconds: Self.now
        )
        let otherOffer = try otherGrant.attestedOffer(
            sdp: "v=0\r\ns=-\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n",
            certificatePEM: Self.certificatePEM,
            endpointNonceHex: Self.endpointNonce,
            identity: environment.managerIdentity,
            nowUnixSeconds: Self.now
        )
        let count = executor.requestCount
        await #expect(throws: HelicoidError.observationProtocolViolation(
            detail: "The Manager offer is not signed by this verified grant's certificate attestation. The Manager session remains active."
        )) {
            try await client.publishAttestedOffer(
                for: lease,
                offer: otherOffer,
                fence: fence()
            )
        }
        #expect(executor.requestCount == count)
    }

    @Test("Refuses a missing persisted trust record without a network request")
    func refusesMissingPersistedTrust() async throws {
        let environment = try await makeEnvironment(seedTrust: false)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "No atomically bound production trust record is saved. Complete out-of-band production trust setup before requesting observation."
        )) {
            _ = try await makeClient(environment: environment, executor: executor)
        }
        #expect(executor.requestCount == 0)
    }

    @Test("Refuses a legacy checkpoint-only record")
    func refusesLegacyCheckpointOnlyRecord() async throws {
        let environment = try await makeEnvironment(seedTrust: false)
        let confirmation = try ManagerAuthorityConfirmation(
            operatorEnteredDeploymentID: environment.checkpoint.deploymentID,
            operatorEnteredKeyFingerprintSHA256: environment.checkpoint
                .grantSigningKeyFingerprintSHA256,
            operatorEnteredAuthorityGeneration: environment.checkpoint.authorityGeneration
        )
        _ = try await environment.authorityTrust.adopt(
            environment.checkpoint,
            confirmation: confirmation
        )
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        await #expect(throws: HelicoidError.self) {
            _ = try await makeClient(environment: environment, executor: executor)
        }
        #expect(executor.requestCount == 0)
    }

    @Test("Public observation factory refuses an arbitrary auth transport")
    func refusesArbitraryAuthTransport() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let requestsBefore = environment.authTransport.requestCount

        await #expect(throws: HelicoidError.self) {
            _ = try await ManagerObservationLeaseClient.make(
                authClient: environment.authClient,
                tlsIdentity: environment.trust,
                authorityTrust: environment.authorityTrust,
                signingIdentity: environment.managerIdentity
            )
        }
        #expect(environment.authTransport.requestCount == requestsBefore)
    }

    @Test("Pinned production factory succeeds with an exactly bound trust record")
    func pinnedFactoryHappyPath() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let pinnedAuthClient = NativeV2AuthClient(
            transport: environment.authTransport,
            trustedAuthority: environment.trust,
            signingIdentity: environment.managerIdentity,
            timeSource: LiveSessionTimeSource(),
            productionPinnedForTesting: true
        )
        let client = try await ManagerObservationLeaseClient.make(
            authClient: pinnedAuthClient,
            tlsIdentity: environment.trust,
            authorityTrust: environment.authorityTrust,
            signingIdentity: environment.managerIdentity
        )
        let checkpoint = await client.authorityCheckpoint
        let deploymentID = await client.deploymentID
        #expect(checkpoint == environment.checkpoint)
        #expect(deploymentID == Self.deploymentID)
    }

    @Test("Refuses a substituted TLS origin before any request")
    func refusesSubstitutedTLSOrigin() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let substituted = try DeploymentTLSIdentity(
            deploymentID: environment.trust.deploymentID,
            host: "other.example",
            port: environment.trust.port,
            caDER: environment.trust.caDER,
            caFingerprintSHA256: environment.trust.caFingerprintSHA256
        )
        let authTransport = FixtureTransport()
        let authClient = NativeV2AuthClient(
            transport: authTransport,
            trustedAuthority: substituted,
            signingIdentity: environment.managerIdentity
        )
        let executor = LeaseObservationExecutor(originURL: substituted.originURL)

        await #expect(throws: HelicoidError.self) {
            _ = try await ManagerObservationLeaseClient.make(
                authClient: authClient,
                executor: executor,
                tlsIdentity: substituted,
                authorityTrust: environment.authorityTrust,
                signingIdentity: environment.managerIdentity,
                nowUnix: { Self.now }
            )
        }
        #expect(executor.requestCount == 0)
        #expect(authTransport.requestCount == 0)
    }

    @Test("Rechecks the persisted authority before sending the bearer")
    func revalidatesAuthorityBeforeBearer() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        let client = try await makeClient(environment: environment, executor: executor)

        let changed = try DeploymentAuthorityCheckpoint(
            deploymentID: Self.deploymentID,
            grantSigningPublicKeyHex: environment.checkpoint.grantSigningPublicKeyHex,
            authorityGeneration: environment.checkpoint.authorityGeneration + 1
        )
        environment.authTransport.stub = .init(
            status: 200,
            body: try authorityJSON(changed)
        )
        await #expect(throws: HelicoidError.identityMismatch) {
            _ = try await client.issueGrant(
                expectation: environment.expectation,
                fence: fence()
            )
        }
        #expect(executor.requestCount == 0)
    }

    @Test("Rechecks live authority after the grant response before returning a lease")
    func revalidatesLiveAuthorityAfterGrantResponse() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let changed = try DeploymentAuthorityCheckpoint(
            deploymentID: Self.deploymentID,
            grantSigningPublicKeyHex: environment.checkpoint.grantSigningPublicKeyHex,
            authorityGeneration: environment.checkpoint.authorityGeneration + 1
        )
        let changedJSON = try authorityJSON(changed)
        let authTransport = environment.authTransport
        executor.setOnRequest { _ in
            authTransport.stub = .init(status: 200, body: changedJSON)
        }
        let client = try await makeClient(environment: environment, executor: executor)
        await #expect(throws: HelicoidError.identityMismatch) {
            _ = try await client.issueGrant(
                expectation: environment.expectation,
                fence: fence()
            )
        }
    }

    @Test("Refuses a live authority change before accepting a poll response")
    func liveAuthorityChangeBeforePollAccepted() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence()
        )

        let changed = try DeploymentAuthorityCheckpoint(
            deploymentID: Self.deploymentID,
            grantSigningPublicKeyHex: environment.checkpoint.grantSigningPublicKeyHex,
            authorityGeneration: environment.checkpoint.authorityGeneration + 1
        )
        let changedJSON = try authorityJSON(changed)
        let authTransport = environment.authTransport
        executor.setOnRequest { _ in
            authTransport.stub = .init(status: 200, body: changedJSON)
        }
        executor.enqueue(.init(
            status: 200,
            body: Data(#"{"cursor":0,"messages":[]}"#.utf8)
        ))
        await #expect(throws: HelicoidError.identityMismatch) {
            _ = try await client.pollSignals(
                for: lease,
                after: 0,
                fence: fence()
            )
        }
    }

    @Test("Refuses a live authority change around a state-changing publish")
    func liveAuthorityChangeAroundPublish() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence()
        )

        let changed = try DeploymentAuthorityCheckpoint(
            deploymentID: Self.deploymentID,
            grantSigningPublicKeyHex: environment.checkpoint.grantSigningPublicKeyHex,
            authorityGeneration: environment.checkpoint.authorityGeneration + 1
        )
        let changedJSON = try authorityJSON(changed)
        let authTransport = environment.authTransport
        executor.setOnRequest { _ in
            authTransport.stub = .init(status: 200, body: changedJSON)
        }
        executor.enqueue(.init(status: 204, body: Data()))
        await #expect(throws: HelicoidError.identityMismatch) {
            try await client.publishSignal(
                for: lease,
                kind: .close,
                payload: "",
                fence: fence()
            )
        }
    }

    @Test("Non-2xx poll response is rejected before post-response authority fetch")
    func non2xxPollSkipsPostAuthorityFetch() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence()
        )
        let authRequestsBefore = environment.authTransport.requestCount
        executor.enqueue(.init(status: 500, body: Data()))
        await #expect(throws: HelicoidError.serverContractUnavailable) {
            _ = try await client.pollSignals(
                for: lease,
                after: 0,
                fence: fence()
            )
        }
        #expect(environment.authTransport.requestCount == authRequestsBefore)
    }

    @Test("Fences stale app generations and signed-out sessions before requests")
    func fencesStaleSessions() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence(9)
        )
        let count = executor.requestCount

        await #expect(throws: HelicoidError.sessionExpired(
            detail: "The Manager observation session generation changed. Request a new preview."
        )) {
            _ = try await client.pollSignals(
                for: lease,
                after: 0,
                fence: fence(10)
            )
        }
        #expect(executor.requestCount == count)

        await environment.authClient.signOutLocal()
        await #expect(throws: HelicoidError.self) {
            _ = try await client.pollSignals(
                for: lease,
                after: 0,
                fence: fence(9)
            )
        }
        #expect(executor.requestCount == count)
    }

    @Test("Lease and grant expire exactly at the signed boundary")
    func leaseExpiryBoundary() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let clock = LeaseManualClock(Self.now)
        let client = try await makeClient(
            environment: environment,
            executor: executor,
            nowUnix: { clock.now }
        )
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence()
        )
        let expiry = lease.expiresAtUnix
        #expect(lease.isCurrent(nowUnixSeconds: expiry - 1))
        #expect(!lease.isCurrent(nowUnixSeconds: expiry))

        clock.set(expiry - 1)
        executor.enqueue(.init(
            status: 200,
            body: Data(#"{"cursor":0,"messages":[]}"#.utf8)
        ))
        _ = try await client.pollSignals(
            for: lease,
            after: 0,
            fence: fence()
        )

        let count = executor.requestCount
        clock.set(expiry)
        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The observation grant has expired. Request a new preview."
        )) {
            _ = try await client.pollSignals(
                for: lease,
                after: 0,
                fence: fence()
            )
        }
        #expect(executor.requestCount == count)
    }

    @Test("Task cancellation is distinct from an invalidated observation fence")
    func cancellationIsDistinctFromFence() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence(9)
        )

        let gate = LeaseStartGate()
        let task = Task { () -> HelicoidError? in
            await gate.wait()
            do {
                _ = try await client.pollSignals(
                    for: lease,
                    after: 0,
                    fence: fence(9)
                )
                return nil
            } catch let error as HelicoidError {
                return error
            } catch {
                return nil
            }
        }
        task.cancel()
        await gate.open()
        let result = await task.value
        let error = try #require(result)
        #expect(error == .cancelled)
    }

    @Test("A 401 clears only the exact live bearer")
    func unauthorizedClearsBearer() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence()
        )
        executor.enqueue(.init(status: 401, body: Data()))
        await #expect(throws: HelicoidError.self) {
            _ = try await client.pollSignals(
                for: lease,
                after: 0,
                fence: fence()
            )
        }
        #expect(await environment.authClient.bearerToken == nil)
    }

    @Test("Refuses a grant token signed by a foreign authority key")
    func refusesForeignGrantToken() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let foreignKey = Curve25519.Signing.PrivateKey()
        let claims = Data(
            "{\"version\":1,\"grant_id\":\"\(Self.grantID)\",\"deployment_id\":\"\(Self.deploymentID)\",\"account_id\":\"\(Self.accountID)\",\"manager_id\":\"\(Self.managerID)\",\"manager_public_key\":\"\(lowerHex(environment.managerIdentity.publicKey))\",\"computer_id\":\"\(Self.computerID)\",\"endpoint_public_key\":\"\(lowerHex(environment.endpointKey.publicKey.rawRepresentation))\",\"endpoint_session_id\":\"\(Self.endpointSessionID)\",\"enrollment_epoch\":1,\"issued_at_unix\":\(Self.now),\"expires_at_unix\":\(Self.now + 10),\"capability\":\"observe\"}".utf8
        )
        let signature = try foreignKey.signature(
            for: Data("hs-observation-grant-v1\0".utf8) + claims
        )
        let token = claims.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            + "." + lowerHex(signature)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        await #expect(throws: HelicoidError.self) {
            _ = try await client.issueGrant(
                expectation: environment.expectation,
                fence: fence()
            )
        }
    }

    @Test("Refuses a response whose unsigned fields do not match the signed grant")
    func refusesUnsignedResponseFieldMismatch() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(
                token: environment.token,
                computerID: "11111111-1111-4111-8111-111111111111"
            )
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        await #expect(throws: HelicoidError.serverContractUnavailable) {
            _ = try await client.issueGrant(
                expectation: environment.expectation,
                fence: fence()
            )
        }
    }

    @Test("Refuses an in-flight trust reset during grant issuance")
    func refusesInFlightResetDuringGrant() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let store = environment.authorityTrust
        let deploymentID = environment.trust.deploymentID
        executor.setOnRequest { _ in
            guard let current = try await store.productionTrustRecord(
                deploymentID: deploymentID
            ) else { return }
            _ = try await store.deleteProductionTrustRecord(
                deploymentID: deploymentID,
                expected: current
            )
        }
        let client = try await makeClient(environment: environment, executor: executor)
        await #expect(throws: HelicoidError.identityMismatch) {
            _ = try await client.issueGrant(
                expectation: environment.expectation,
                fence: fence()
            )
        }
        let remainingRecord = try await store.productionTrustRecord(
            deploymentID: deploymentID
        )
        #expect(remainingRecord == nil)
    }

    @Test("Refuses a config-only trust change during grant issuance")
    func refusesConfigOnlyChangeDuringGrant() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let store = environment.authorityTrust
        let deploymentID = environment.trust.deploymentID
        let currentRecord = try await store.productionTrustRecord(
            deploymentID: deploymentID
        )
        let current = try #require(currentRecord)
        let changedRecord = try ManagerAuthorityTrustRecord(
            checkpoint: current.checkpoint,
            configurationData: (current.configurationData ?? Data()) + Data(" \n".utf8)
        )
        let confirmation = try ManagerAuthorityConfirmation(
            operatorEnteredDeploymentID: current.checkpoint.deploymentID,
            operatorEnteredKeyFingerprintSHA256: current.checkpoint
                .grantSigningKeyFingerprintSHA256,
            operatorEnteredAuthorityGeneration: current.checkpoint.authorityGeneration
        )
        executor.setOnRequest { _ in
            _ = try await store.commitProductionTrustRecord(
                changedRecord,
                expected: current,
                confirmation: confirmation
            )
        }
        let client = try await makeClient(environment: environment, executor: executor)
        await #expect(throws: HelicoidError.identityMismatch) {
            _ = try await client.issueGrant(
                expectation: environment.expectation,
                fence: fence()
            )
        }
        let after = try await store.productionTrustRecord(deploymentID: deploymentID)
        let afterRecord = try #require(after)
        #expect(afterRecord == changedRecord)
    }

    @Test("Refuses a config-only trust change during signal polling")
    func refusesConfigOnlyChangeDuringPoll() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence()
        )

        let store = environment.authorityTrust
        let deploymentID = environment.trust.deploymentID
        let currentRecord = try await store.productionTrustRecord(
            deploymentID: deploymentID
        )
        let current = try #require(currentRecord)
        let changedRecord = try ManagerAuthorityTrustRecord(
            checkpoint: current.checkpoint,
            configurationData: (current.configurationData ?? Data()) + Data(" \n".utf8)
        )
        let confirmation = try ManagerAuthorityConfirmation(
            operatorEnteredDeploymentID: current.checkpoint.deploymentID,
            operatorEnteredKeyFingerprintSHA256: current.checkpoint
                .grantSigningKeyFingerprintSHA256,
            operatorEnteredAuthorityGeneration: current.checkpoint.authorityGeneration
        )
        executor.setOnRequest { _ in
            _ = try await store.commitProductionTrustRecord(
                changedRecord,
                expected: current,
                confirmation: confirmation
            )
        }
        executor.enqueue(.init(
            status: 200,
            body: Data(#"{"cursor":0,"messages":[]}"#.utf8)
        ))
        await #expect(throws: HelicoidError.identityMismatch) {
            _ = try await client.pollSignals(
                for: lease,
                after: 0,
                fence: fence()
            )
        }
        let after = try await store.productionTrustRecord(deploymentID: deploymentID)
        let afterRecord = try #require(after)
        #expect(afterRecord == changedRecord)
        #expect(afterRecord != current)
    }

    @Test("Refuses an in-flight trust reset during signal publishing")
    func refusesInFlightResetDuringPublish() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token)
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        let lease = try await client.issueGrant(
            expectation: environment.expectation,
            fence: fence()
        )

        let store = environment.authorityTrust
        let deploymentID = environment.trust.deploymentID
        executor.setOnRequest { _ in
            guard let current = try await store.productionTrustRecord(
                deploymentID: deploymentID
            ) else { return }
            _ = try await store.deleteProductionTrustRecord(
                deploymentID: deploymentID,
                expected: current
            )
        }
        executor.enqueue(.init(status: 204, body: Data()))
        await #expect(throws: HelicoidError.identityMismatch) {
            try await client.publishSignal(
                for: lease,
                kind: .close,
                payload: "",
                fence: fence()
            )
        }
        let remainingRecord = try await store.productionTrustRecord(
            deploymentID: deploymentID
        )
        #expect(remainingRecord == nil)
    }

    @Test("Refuses a response whose final URL is not the requested pinned URL")
    func refusesUnexpectedResponseURL() async throws {
        let environment = try await makeEnvironment(seedTrust: true)
        let executor = LeaseObservationExecutor(originURL: environment.trust.originURL)
        executor.enqueue(.init(
            status: 201,
            body: try grantResponse(token: environment.token),
            responseURL: URL(string: "https://evil.test:8443/v2/admissions/observation")!
        ))
        let client = try await makeClient(environment: environment, executor: executor)
        await #expect(throws: HelicoidError.serverContractUnavailable) {
            _ = try await client.issueGrant(
                expectation: environment.expectation,
                fence: fence()
            )
        }
    }
}
