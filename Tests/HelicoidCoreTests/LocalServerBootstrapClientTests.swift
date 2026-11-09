import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

private struct TestTimeout: Error {}

/// Deterministic safety net for a test that would otherwise wait forever.
/// Synchronization itself is by `TestGate`, not by this timeout.
private func withTestTimeout<T: Sendable>(
    _ operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: 5_000_000_000)
            throw TestTimeout()
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else { throw TestTimeout() }
        return result
    }
}

/// One-shot gate used to hold a request at a known point. By default it
/// releases on cancellation so a cancelled test cannot strand its operation.
/// `ignoresCancellation` is used only to prove that a received success is
/// retained after the caller cancels.
private final class TestGate: @unchecked Sendable {
    private let lock = NSLock()
    private let ignoresCancellation: Bool
    private var arrived = false
    private var released = false
    private var arrivalWaiters: [CheckedContinuation<Void, Error>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Error>] = []

    init(ignoresCancellation: Bool = false) {
        self.ignoresCancellation = ignoresCancellation
    }

    func arriveAndWait() async throws {
        if ignoresCancellation {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                arrived = true
                let arrivals = arrivalWaiters
                arrivalWaiters = []
                if released {
                    lock.unlock()
                    arrivals.forEach { $0.resume() }
                    continuation.resume()
                    return
                }
                releaseWaiters.append(continuation)
                lock.unlock()
                arrivals.forEach { $0.resume() }
            }
            return
        }

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                arrived = true
                let arrivals = arrivalWaiters
                arrivalWaiters = []
                if released {
                    lock.unlock()
                    arrivals.forEach { $0.resume() }
                    continuation.resume()
                    return
                }
                releaseWaiters.append(continuation)
                lock.unlock()
                arrivals.forEach { $0.resume() }
            }
            try Task.checkCancellation()
        } onCancel: {
            release()
        }
    }

    func waitUntilArrived() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                if arrived {
                    lock.unlock()
                    continuation.resume()
                    return
                }
                arrivalWaiters.append(continuation)
                lock.unlock()
            }
            try Task.checkCancellation()
        } onCancel: {
            cancelArrivalWaiters()
        }
    }

    func release() {
        lock.lock()
        released = true
        let waiters = releaseWaiters
        releaseWaiters = []
        lock.unlock()
        waiters.forEach { $0.resume() }
    }

    private func cancelArrivalWaiters() {
        lock.lock()
        let waiters = arrivalWaiters
        arrivalWaiters = []
        lock.unlock()
        waiters.forEach { $0.resume(throwing: CancellationError()) }
    }
}

/// Disposable in-memory transport. Never opens a socket and never uses real
/// credentials. Each stub is returned in order; requests are recorded for
/// assertions.
private final class ControlledBootstrapTransport: HTTPStatusTransport, @unchecked Sendable {
    struct Stub {
        var status: Int
        var body: Data
        var responseURL: URL?
        var error: Error?
        var gate: TestGate?

        init(
            status: Int,
            body: Data = Data(),
            responseURL: URL? = nil,
            error: Error? = nil,
            gate: TestGate? = nil
        ) {
            self.status = status
            self.body = body
            self.responseURL = responseURL
            self.error = error
            self.gate = gate
        }
    }

    private let lock = NSLock()
    private var stubs: [Stub]
    private var requests: [URLRequest] = []

    init(stubs: [Stub] = []) {
        self.stubs = stubs
    }

    func enqueue(_ stub: Stub) {
        lock.lock()
        stubs.append(stub)
        lock.unlock()
    }

    var recordedRequests: [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return requests
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        let stub = try await nextStub(for: request)
        if let error = stub.error { throw error }
        try checkBound(stub, maxBytes: maxBytes)
        let url = stub.responseURL
            ?? request.url
            ?? URL(string: "https://127.0.0.1:8443/")!
        guard let response = HTTPURLResponse(
            url: url,
            statusCode: stub.status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        ) else {
            throw HelicoidError.unreachable
        }
        return (stub.body, response)
    }

    func requestStatus(
        for request: URLRequest,
        maxBytes: Int
    ) async throws -> PinnedHTTPStatusResponse {
        let stub = try await nextStub(for: request)
        if let error = stub.error { throw error }
        try checkBound(stub, maxBytes: maxBytes)
        let url = stub.responseURL
            ?? request.url
            ?? URL(string: "https://127.0.0.1:8443/")!
        return PinnedHTTPStatusResponse(
            statusCode: stub.status,
            body: stub.body,
            url: url
        )
    }

    private func nextStub(for request: URLRequest) async throws -> Stub {
        let stub: Stub? = lock.withLock {
            requests.append(request)
            guard !stubs.isEmpty else { return nil }
            return stubs.removeFirst()
        }
        guard let stub else { throw HelicoidError.unreachable }
        if let gate = stub.gate {
            try await gate.arriveAndWait()
        }
        return stub
    }

    private func checkBound(_ stub: Stub, maxBytes: Int) throws {
        guard stub.body.count <= maxBytes else {
            throw HelicoidError.invalidInput(
                field: "response",
                detail: "Response body exceeded the bounded size limit."
            )
        }
    }
}

@Suite("Local server bootstrap client")
struct LocalServerBootstrapClientTests {
    private let deploymentID = "dep_test_123"
    private let fixtureToken = "fixture-bootstrap-token"
    private let fixtureUsername = "admin"
    private let fixturePassword = "fixture password 123"
    private let fixtureTOTPSecret = "JBSWY3DPEHPK3PXP"
    private let fixtureRecoveryCodes = [
        "AAAA-BBBB-CCCC-DDDD",
        "EEEE-FFFF-GGGG-HHHH",
    ]

    // MARK: - Fixtures

    private func makeIdentity() throws -> ManagerSigningIdentity {
        try ManagerSigningIdentity(
            storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation
        )
    }

    private func makeTrust(
        host: String = "127.0.0.1",
        port: Int = 8443,
        deploymentID: String? = nil
    ) async throws -> LocalBootstrapTrust {
        let material = try await TLSTestHarness.sharedMaterial()
        let identity = try DeploymentTLSIdentity(
            deploymentID: deploymentID ?? self.deploymentID,
            host: host,
            port: port,
            caDER: material.caDER,
            caFingerprintSHA256: material.caFingerprint
        )
        return try LocalBootstrapTrust(identity: identity)
    }

    private func makeClient(
        transport: ControlledBootstrapTransport,
        trust: LocalBootstrapTrust,
        identity: ManagerSigningIdentity
    ) -> LocalServerBootstrapClient {
        LocalServerBootstrapClient(
            trust: trust,
            signingIdentity: identity,
            transport: transport
        )
    }

    private func json(_ object: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    }

    private func deploymentBody(_ id: String) -> Data {
        json(["deployment_id": id])
    }

    private func healthBody(
        status: String = "degraded",
        accepting: Bool = false,
        bootstrapCompleted: Bool = false,
        mfa: Bool = true,
        schemaVersion: Int = 1
    ) -> Data {
        json([
            "status": status,
            "accepting_authorized_operations": accepting,
            "schema_version": schemaVersion,
            "bootstrap_completed": bootstrapCompleted,
            "features": ["mfa": mfa],
        ])
    }

    private func bootstrapBody(
        accountID: String = "account-1",
        username: String = "admin",
        mfaID: String = "enrollment-1",
        totpSecret: String? = nil,
        recoveryCodes: [String]? = nil,
        managerKey: String,
        accountState: String = "pending_mfa",
        serverState: String = "awaiting_mfa_confirmation"
    ) -> Data {
        json([
            "account_id": accountID,
            "username": username,
            "mfa_enrollment_id": mfaID,
            "totp_secret_base32": totpSecret ?? fixtureTOTPSecret,
            "recovery_codes": recoveryCodes ?? fixtureRecoveryCodes,
            "manager_public_key": managerKey,
            "account_state": accountState,
            "server_state": serverState,
        ])
    }

    private func confirmBody(
        accountID: String = "account-1",
        mfaStatus: String = "active",
        accountState: String = "active"
    ) -> Data {
        json([
            "account_id": accountID,
            "mfa_status": mfaStatus,
            "account_state": accountState,
        ])
    }

    private func bootstrapSuccessStubs(
        transport: ControlledBootstrapTransport,
        managerKey: String,
        bootstrapGate: TestGate? = nil
    ) {
        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(status: 200, body: healthBody()))
        transport.enqueue(.init(
            status: 201,
            body: bootstrapBody(managerKey: managerKey),
            gate: bootstrapGate
        ))
    }

    private func bootstrap(
        _ client: LocalServerBootstrapClient
    ) async throws -> LocalBootstrapEnrollment {
        try await client.bootstrapFirstAdministrator(
            token: fixtureToken,
            username: fixtureUsername,
            password: fixturePassword,
            managerFriendlyName: "Installer",
            acknowledgement: .operatorWillStoreMFASecretAndRecoveryCodesIndependently
        )
    }

    private func expectOperationError(
        _ expected: LocalBootstrapOperationError,
        _ operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            Issue.record("Expected \(expected)")
        } catch let error as LocalBootstrapOperationError {
            #expect(error == expected, "Unexpected operation error: \(error)")
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    private func expectHelicoidError(
        _ predicate: (HelicoidError) -> Bool,
        _ operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            Issue.record("Expected a HelicoidError")
        } catch let error as HelicoidError {
            #expect(predicate(error), "Unexpected HelicoidError: \(error)")
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    private func isCancelled(_ error: HelicoidError) -> Bool {
        if case .cancelled = error { return true }
        return false
    }

    private func isIdentityMismatch(_ error: HelicoidError) -> Bool {
        if case .identityMismatch = error { return true }
        return false
    }

    private func isAuthenticationFailed(_ error: HelicoidError) -> Bool {
        if case .authenticationFailed = error { return true }
        return false
    }

    private func isSetupBlocked(_ error: HelicoidError) -> Bool {
        if case .setupBlocked = error { return true }
        return false
    }

    private func isContractUnavailable(_ error: HelicoidError) -> Bool {
        if case .serverContractUnavailable = error { return true }
        return false
    }

    // MARK: - Trust binding

    @Test("Only literal loopback HTTPS trust is accepted")
    func literalLoopbackOnly() async throws {
        let material = try await TLSTestHarness.sharedMaterial()

        func identity(host: String) throws -> DeploymentTLSIdentity {
            try DeploymentTLSIdentity(
                deploymentID: deploymentID,
                host: host,
                port: 8443,
                caDER: material.caDER,
                caFingerprintSHA256: material.caFingerprint
            )
        }

        for host in ["127.0.0.1", "127.255.255.255", "::1"] {
            let trust = try LocalBootstrapTrust(identity: identity(host: host))
            #expect(trust.deploymentID == deploymentID)
            #expect(trust.originURL.scheme == "https")
        }

        for host in [
            "server.test",
            "localhost",
            "127.attacker.example",
            "10.0.0.1",
            "0.0.0.0",
            "::2",
        ] {
            #expect(throws: HelicoidError.self) {
                _ = try LocalBootstrapTrust(identity: identity(host: host))
            }
        }
    }

    // MARK: - Bootstrap

    @Test("Bootstrap verifies deployment, signs proof, and returns one-shot secrets")
    func bootstrapProofAndSecrets() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        let enrollment = try await bootstrap(client)
        #expect(enrollment.accountID == "account-1")
        #expect(enrollment.username == fixtureUsername)
        #expect(enrollment.mfaEnrollmentID == "enrollment-1")
        #expect(enrollment.managerPublicKey == key)
        #expect(enrollment.accountState == "pending_mfa")
        #expect(enrollment.serverState == "awaiting_mfa_confirmation")
        #expect(await client.hasActiveEnrollment)
        #expect(await client.state == .awaitingMFAConfirmation)

        let requests = transport.recordedRequests
        #expect(requests.count == 3)
        #expect(requests[0].httpMethod == "GET")
        #expect(requests[1].httpMethod == "GET")
        #expect(requests[2].httpMethod == "POST")
        #expect(requests[0].url?.path == "/v2/deployment")
        #expect(requests[1].url?.path == "/health")
        #expect(requests[2].url?.path == "/v2/bootstrap")
        #expect(requests[2].url?.scheme == "https")
        #expect(requests[2].url?.host == "127.0.0.1")
        #expect(requests[2].url?.port == 8443)
        #expect(requests[0].httpBody == nil)
        #expect(requests[1].httpBody == nil)
        for request in requests {
            #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
        }

        let requestData = try #require(requests[2].httpBody)
        let object = try #require(
            JSONSerialization.jsonObject(with: requestData) as? [String: Any]
        )
        #expect(object["bootstrap_token"] as? String == fixtureToken)
        #expect(object["username"] as? String == fixtureUsername)
        #expect(object["password"] as? String == fixturePassword)
        #expect(object["manager_public_key"] as? String == key)
        #expect(object["manager_friendly_name"] as? String == "Installer")

        let proofHex = try #require(object["manager_proof"] as? String)
        let proof = try #require(AuthV2Canonical.bytes(fromHex: proofHex))
        let expectedTokenHash = SHA256.hash(data: Data(fixtureToken.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        let expectedMessage = Data(
            "hs-bootstrap-v2|deployment:\(deploymentID)|token:\(expectedTokenHash)|manager:\(key)".utf8
        )
        let message = LocalServerBootstrapClient.bootstrapProofMessage(
            deploymentID: deploymentID,
            bootstrapTokenHash: LocalServerBootstrapClient.bootstrapTokenHashHex(fixtureToken),
            managerPublicKeyHex: key
        )
        #expect(message == expectedMessage)
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: identity.publicKey)
        #expect(publicKey.isValidSignature(proof, for: expectedMessage))

        #expect(!String(describing: enrollment).contains(fixtureTOTPSecret))
        #expect(!String(reflecting: enrollment).contains(fixtureTOTPSecret))
        #expect(!String(describing: enrollment).contains(fixtureRecoveryCodes[0]))
        #expect(!String(reflecting: enrollment).contains(fixtureRecoveryCodes[0]))

        let secrets = try #require(enrollment.takeSecrets())
        #expect(secrets.totpSecretBase32 == fixtureTOTPSecret)
        #expect(secrets.recoveryCodes == fixtureRecoveryCodes)
        #expect(enrollment.takeSecrets() == nil)
        #expect(!enrollment.hasSecrets)

        try await client.discardLocalState(
            acknowledgement: .discardLocalSecretsWithoutCancellingServerEnrollment
        )
        #expect(await client.state == .discarded)
        try await client.dispose()
    }

    @Test("Secret-bearing wire descriptions are redacted")
    func secretBearingWireDescriptionsAreRedacted() throws {
        let response = BootstrapResponseDTO(
            accountID: "account-1",
            username: fixtureUsername,
            mfaEnrollmentID: "enrollment-1",
            totpSecretBase32: fixtureTOTPSecret,
            recoveryCodes: fixtureRecoveryCodes,
            managerPublicKey: String(repeating: "a", count: 64),
            accountState: "pending_mfa",
            serverState: "awaiting_mfa_confirmation"
        )
        let bootstrapRequest = BootstrapRequestDTO(
            bootstrapToken: fixtureToken,
            username: fixtureUsername,
            password: fixturePassword,
            managerPublicKey: String(repeating: "a", count: 64),
            managerProof: String(repeating: "b", count: 128),
            managerFriendlyName: "Installer"
        )
        let confirmRequest = MFAConfirmRequestDTO(
            mfaEnrollmentID: "enrollment-1",
            totpCode: "123456",
            recoveryMaterialStored: true
        )
        let cancelRequest = MFAEnrollCancelRequestDTO(
            mfaEnrollmentID: "enrollment-1"
        )

        let rendered = [
            String(describing: response),
            String(reflecting: response),
            String(describing: bootstrapRequest),
            String(reflecting: bootstrapRequest),
            String(describing: confirmRequest),
            String(reflecting: confirmRequest),
            String(describing: cancelRequest),
            String(reflecting: cancelRequest),
        ]

        for text in rendered {
            #expect(!text.contains(fixtureTOTPSecret))
            #expect(!text.contains(fixtureRecoveryCodes[0]))
            #expect(!text.contains(fixtureToken))
            #expect(!text.contains(fixturePassword))
            #expect(!text.contains("123456"))
            #expect(!text.contains("enrollment-1"))
        }
        #expect(String(describing: response).contains("recoveryCodeCount: 2"))
    }

    @Test("Stale deployment identity refuses before sending the token")
    func staleDeploymentIdentity() async throws {
        let identity = try makeIdentity()
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        transport.enqueue(.init(status: 200, body: deploymentBody("dep_other")))
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        await expectHelicoidError(isIdentityMismatch) {
            _ = try await bootstrap(client)
        }
        #expect(await client.state == .idle)
        #expect(await !client.hasActiveEnrollment)
        #expect(transport.recordedRequests.count == 1)
        #expect(transport.recordedRequests[0].url?.path == "/v2/deployment")
        #expect(transport.recordedRequests[0].httpBody == nil)
    }

    @Test("Completed bootstrap refuses before sending the token")
    func completedBootstrapRefuses() async throws {
        let identity = try makeIdentity()
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(
            status: 200,
            body: healthBody(status: "ok", accepting: true, bootstrapCompleted: true)
        ))
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        await expectHelicoidError(isSetupBlocked) {
            _ = try await bootstrap(client)
        }
        #expect(await client.state == .idle)
        #expect(transport.recordedRequests.count == 2)
        #expect(transport.recordedRequests.allSatisfy { $0.httpMethod == "GET" })
        #expect(transport.recordedRequests.allSatisfy { $0.httpBody == nil })
    }

    @Test("Missing MFA capability refuses before sending the token")
    func missingMFAFeatureRefuses() async throws {
        let identity = try makeIdentity()
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(status: 200, body: healthBody(mfa: false)))
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        await expectHelicoidError(isContractUnavailable) {
            _ = try await bootstrap(client)
        }
        #expect(await client.state == .idle)
        #expect(transport.recordedRequests.count == 2)
        #expect(transport.recordedRequests.allSatisfy { $0.httpBody == nil })
    }

    @Test("Foreign or redirected response URL is refused")
    func foreignOrRedirectedResponseURLRefused() async throws {
        let identity = try makeIdentity()
        let trust = try await makeTrust()

        for responseURL in [
            URL(string: "https://evil.test:8443/v2/deployment")!,
            URL(string: "https://127.0.0.1:8443/redirected")!,
        ] {
            let transport = ControlledBootstrapTransport()
            transport.enqueue(.init(
                status: 200,
                body: deploymentBody(deploymentID),
                responseURL: responseURL
            ))
            let client = makeClient(transport: transport, trust: trust, identity: identity)

            await #expect(throws: HelicoidError.self) {
                _ = try await bootstrap(client)
            }
            #expect(await client.state == .idle)
            #expect(transport.recordedRequests.count == 1)
            #expect(transport.recordedRequests[0].httpBody == nil)
        }
    }

    @Test("Local bounds are enforced before any request")
    func localBounds() async throws {
        let identity = try makeIdentity()
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        let tooLongToken = String(repeating: "a", count: LocalServerBootstrapClient.maxTokenLength + 1)
        let tooLongPassword = String(repeating: "a", count: LocalServerBootstrapClient.maxPasswordLength + 1)
        let tooLongName = String(repeating: "a", count: LocalServerBootstrapClient.maxFriendlyNameLength + 1)

        let cases: [(String, String, String, String?)] = [
            (tooLongToken, fixtureUsername, fixturePassword, nil),
            ("token with\ncontrol", fixtureUsername, fixturePassword, nil),
            (fixtureToken, "ab", fixturePassword, nil),
            (fixtureToken, "bad name", fixturePassword, nil),
            (fixtureToken, fixtureUsername, "short", nil),
            (fixtureToken, fixtureUsername, tooLongPassword, nil),
            (fixtureToken, fixtureUsername, fixturePassword, tooLongName),
        ]

        for (token, username, password, name) in cases {
            await #expect(throws: HelicoidError.self) {
                _ = try await client.bootstrapFirstAdministrator(
                    token: token,
                    username: username,
                    password: password,
                    managerFriendlyName: name,
                    acknowledgement: .operatorWillStoreMFASecretAndRecoveryCodesIndependently
                )
            }
        }
        #expect(await client.state == .idle)
        #expect(transport.recordedRequests.isEmpty)
    }

    @Test("Unusable bootstrap success is unknown and not retryable")
    func unusableBootstrapSuccessIsUnknown() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()

        let wrongKeyTransport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(
            transport: wrongKeyTransport,
            managerKey: String(repeating: "0", count: 64)
        )
        let wrongKeyClient = makeClient(
            transport: wrongKeyTransport,
            trust: trust,
            identity: identity
        )
        await expectOperationError(.bootstrapOutcomeUnknown) {
            _ = try await bootstrap(wrongKeyClient)
        }
        #expect(await wrongKeyClient.state == .bootstrapOutcomeUnknown)
        #expect(await !wrongKeyClient.hasActiveEnrollment)
        let wrongKeyCount = wrongKeyTransport.recordedRequests.count
        await expectOperationError(.stateUnavailable(.bootstrapOutcomeUnknown)) {
            _ = try await bootstrap(wrongKeyClient)
        }
        #expect(wrongKeyTransport.recordedRequests.count == wrongKeyCount)

        let wrongStateTransport = ControlledBootstrapTransport()
        wrongStateTransport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        wrongStateTransport.enqueue(.init(status: 200, body: healthBody()))
        wrongStateTransport.enqueue(.init(
            status: 201,
            body: bootstrapBody(managerKey: key, accountState: "active")
        ))
        let wrongStateClient = makeClient(
            transport: wrongStateTransport,
            trust: trust,
            identity: identity
        )
        await expectOperationError(.bootstrapOutcomeUnknown) {
            _ = try await bootstrap(wrongStateClient)
        }
        #expect(await wrongStateClient.state == .bootstrapOutcomeUnknown)
        #expect(await !wrongStateClient.hasActiveEnrollment)
    }

    @Test("Invalid one-time bootstrap material is unknown")
    func invalidBootstrapSecretsAreUnknown() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()

        let cases: [(totpSecret: String?, recoveryCodes: [String]?)] = [
            ("not-base32!", nil),
            (nil, []),
            (nil, ["AAAA-BBBB-CCCC-DDDD", "AAAA-BBBB-CCCC-DDDD"]),
            (nil, ["code with space"]),
        ]

        for (totpSecret, recoveryCodes) in cases {
            let transport = ControlledBootstrapTransport()
            transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
            transport.enqueue(.init(status: 200, body: healthBody()))
            transport.enqueue(.init(
                status: 201,
                body: bootstrapBody(
                    totpSecret: totpSecret,
                    recoveryCodes: recoveryCodes,
                    managerKey: key
                )
            ))
            let client = makeClient(
                transport: transport,
                trust: trust,
                identity: identity
            )

            await expectOperationError(.bootstrapOutcomeUnknown) {
                _ = try await bootstrap(client)
            }
            #expect(await client.state == .bootstrapOutcomeUnknown)
            #expect(await !client.hasActiveEnrollment)
            try await client.dispose()
        }
    }

    @Test("Unrecognized bootstrap response is unknown")
    func unrecognizedBootstrapResponseIsUnknown() async throws {
        let identity = try makeIdentity()
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(status: 200, body: healthBody()))
        transport.enqueue(.init(status: 500, body: Data(#"{"error":"ambiguous"}"#.utf8)))
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        await expectOperationError(.bootstrapOutcomeUnknown) {
            _ = try await bootstrap(client)
        }
        #expect(await client.state == .bootstrapOutcomeUnknown)
        #expect(await !client.hasActiveEnrollment)
    }

    @Test("Bootstrap while an enrollment is pending is refused without clearing secrets")
    func bootstrapWhileEnrollmentPendingIsRefused() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)
        let enrollment = try await bootstrap(client)
        #expect(enrollment.hasSecrets)

        let countBefore = transport.recordedRequests.count
        await expectOperationError(.stateUnavailable(.awaitingMFAConfirmation)) {
            _ = try await bootstrap(client)
        }
        #expect(transport.recordedRequests.count == countBefore)
        #expect(await client.hasActiveEnrollment)
        #expect(enrollment.hasSecrets)
    }

    // MARK: - MFA confirmation

    @Test("Confirmation requires recovery acknowledgement and a current enrollment")
    func confirmationRequiresAcknowledgement() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)
        let enrollment = try await bootstrap(client)

        await #expect(throws: HelicoidError.self) {
            _ = try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: "123456",
                recoveryCodesStoredIndependently: false
            )
        }
        await #expect(throws: HelicoidError.self) {
            _ = try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: "12345",
                recoveryCodesStoredIndependently: true
            )
        }
        #expect(transport.recordedRequests.count == 3)

        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(status: 200, body: confirmBody()))
        let confirmation = try await client.confirmMFAEnrollment(
            enrollment,
            totpCode: "123456",
            recoveryCodesStoredIndependently: true
        )
        #expect(confirmation.accountID == "account-1")
        #expect(confirmation.mfaStatus == "active")
        #expect(confirmation.accountState == "active")
        #expect(await client.state == .confirmed)
        #expect(await !client.hasActiveEnrollment)
        #expect(!enrollment.hasSecrets)

        let requests = transport.recordedRequests
        #expect(requests.count == 5)
        #expect(requests[3].httpMethod == "GET")
        #expect(requests[4].httpMethod == "POST")
        #expect(requests[3].url?.path == "/v2/deployment")
        #expect(requests[4].url?.path == "/v2/mfa/enroll/confirm")
        #expect(requests[4].value(forHTTPHeaderField: "Authorization") == nil)
        let bodyData = try #require(requests[4].httpBody)
        let body = try #require(
            JSONSerialization.jsonObject(with: bodyData) as? [String: Any]
        )
        #expect(body["mfa_enrollment_id"] as? String == "enrollment-1")
        #expect(body["totp_code"] as? String == "123456")
        #expect(body["recovery_material_stored"] as? Bool == true)
        try await client.dispose()
    }

    @Test("Stale deployment identity refuses before MFA confirmation")
    func staleDeploymentIdentityBeforeConfirmation() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)
        let enrollment = try await bootstrap(client)

        transport.enqueue(.init(status: 200, body: deploymentBody("dep_other")))
        let countBefore = transport.recordedRequests.count
        await expectHelicoidError(isIdentityMismatch) {
            _ = try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: "123456",
                recoveryCodesStoredIndependently: true
            )
        }
        #expect(transport.recordedRequests.count == countBefore + 1)
        #expect(transport.recordedRequests.last?.url?.path == "/v2/deployment")
        #expect(transport.recordedRequests.last?.httpBody == nil)
        #expect(await client.state == .awaitingMFAConfirmation)
        #expect(await client.hasActiveEnrollment)
        #expect(enrollment.hasSecrets)
    }

    @Test("Unusable confirmation success is unknown and not retryable")
    func unusableConfirmationSuccessIsUnknown() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)
        let enrollment = try await bootstrap(client)

        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(status: 200, body: confirmBody(mfaStatus: "pending")))
        await expectOperationError(.confirmationOutcomeUnknown) {
            _ = try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: "123456",
                recoveryCodesStoredIndependently: true
            )
        }
        #expect(await client.state == .confirmationOutcomeUnknown)
        #expect(await client.hasActiveEnrollment)
        #expect(enrollment.hasSecrets)

        let countBefore = transport.recordedRequests.count
        await expectOperationError(.stateUnavailable(.confirmationOutcomeUnknown)) {
            _ = try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: "123456",
                recoveryCodesStoredIndependently: true
            )
        }
        #expect(transport.recordedRequests.count == countBefore)
    }

    @Test("Wrong TOTP 401 is a determinate refusal and stays retryable")
    func wrongTOTPIsRetryable() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)
        let enrollment = try await bootstrap(client)

        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(
            status: 401,
            body: Data(#"{"error":{"code":"unauthorized","message":"invalid totp code"}}"#.utf8)
        ))
        await expectHelicoidError(isAuthenticationFailed) {
            _ = try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: "123456",
                recoveryCodesStoredIndependently: true
            )
        }

        // The server contract defines this 401 as transactional: the
        // enrollment is still pending and the same client may retry it.
        #expect(await client.state == .awaitingMFAConfirmation)
        #expect(await client.hasActiveEnrollment)
        #expect(enrollment.hasSecrets)
        #expect(await client.lastUnknownDiagnostic == nil)
        #expect(await !client.isOperationInFlight)
        #expect(await !client.isIrreversibleRequestInFlight)

        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(status: 200, body: confirmBody()))
        let confirmation = try await client.confirmMFAEnrollment(
            enrollment,
            totpCode: "123456",
            recoveryCodesStoredIndependently: true
        )
        #expect(confirmation.accountID == "account-1")
        #expect(confirmation.mfaStatus == "active")
        #expect(confirmation.accountState == "active")
        #expect(await client.state == .confirmed)
        #expect(await !client.hasActiveEnrollment)
        #expect(!enrollment.hasSecrets)
        try await client.dispose()
    }

    @Test("Non-401 confirmation statuses are unknown and not retryable")
    func ambiguousConfirmationStatusIsUnknown() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()

        for status in [400, 403, 409, 500, 503] {
            let transport = ControlledBootstrapTransport()
            bootstrapSuccessStubs(transport: transport, managerKey: key)
            let client = makeClient(
                transport: transport,
                trust: trust,
                identity: identity
            )
            let enrollment = try await bootstrap(client)

            transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
            transport.enqueue(.init(
                status: status,
                body: Data(#"{"error":"ambiguous"}"#.utf8)
            ))
            await expectOperationError(.confirmationOutcomeUnknown) {
                _ = try await client.confirmMFAEnrollment(
                    enrollment,
                    totpCode: "123456",
                    recoveryCodesStoredIndependently: true
                )
            }
            #expect(await client.state == .confirmationOutcomeUnknown)
            #expect(await client.lastUnknownDiagnostic == .nonSuccessStatus)
            #expect(await client.hasActiveEnrollment)
            #expect(enrollment.hasSecrets)

            let countBefore = transport.recordedRequests.count
            await expectOperationError(.stateUnavailable(.confirmationOutcomeUnknown)) {
                _ = try await client.confirmMFAEnrollment(
                    enrollment,
                    totpCode: "123456",
                    recoveryCodesStoredIndependently: true
                )
            }
            #expect(transport.recordedRequests.count == countBefore)

            try await client.discardLocalState(
                acknowledgement: .discardLocalSecretsWithoutCancellingServerEnrollment
            )
            try await client.dispose()
        }
    }

    @Test("Mutation response from a foreign path is unknown")
    func mutationResponsePathMismatchIsUnknown() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)
        let enrollment = try await bootstrap(client)

        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(
            status: 401,
            body: Data(#"{"error":"unexpected location"}"#.utf8),
            responseURL: URL(string: "https://127.0.0.1:8443/not-the-confirm-path")!
        ))
        await expectOperationError(.confirmationOutcomeUnknown) {
            _ = try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: "123456",
                recoveryCodesStoredIndependently: true
            )
        }
        #expect(await client.state == .confirmationOutcomeUnknown)
        #expect(await client.lastUnknownDiagnostic == .transportFailure)
        #expect(await client.hasActiveEnrollment)
        #expect(enrollment.hasSecrets)

        try await client.discardLocalState(
            acknowledgement: .discardLocalSecretsWithoutCancellingServerEnrollment
        )
        try await client.dispose()
    }

    // MARK: - Destructive cancellation

    @Test("Cancel requires the destructive acknowledgement and clears one-time secrets")
    func cancelEnrollment() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)
        let enrollment = try await bootstrap(client)

        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(status: 204))
        try await client.cancelPendingEnrollment(
            acknowledgement: .cancelPendingServerEnrollmentAndDiscardSecrets
        )

        #expect(await client.state == .cancelled)
        #expect(await !client.hasActiveEnrollment)
        #expect(!enrollment.hasSecrets)
        let requests = transport.recordedRequests
        #expect(requests.count == 5)
        #expect(requests[3].httpMethod == "GET")
        #expect(requests[4].httpMethod == "POST")
        #expect(requests[3].url?.path == "/v2/deployment")
        #expect(requests[4].url?.path == "/v2/mfa/enroll/cancel")
        let bodyData = try #require(requests[4].httpBody)
        let body = try #require(
            JSONSerialization.jsonObject(with: bodyData) as? [String: Any]
        )
        #expect(body["mfa_enrollment_id"] as? String == "enrollment-1")
        try await client.dispose()
    }

    @Test("Dispose refuses to discard an active enrollment")
    func disposeRefusesToDiscardActiveEnrollment() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)
        let enrollment = try await bootstrap(client)

        await expectOperationError(.activeEnrollmentWouldBeDiscarded) {
            try await client.dispose()
        }
        #expect(enrollment.hasSecrets)

        try await client.discardLocalState(
            acknowledgement: .discardLocalSecretsWithoutCancellingServerEnrollment
        )
        #expect(await client.state == .discarded)
        #expect(await !client.hasActiveEnrollment)
        #expect(!enrollment.hasSecrets)
        try await client.dispose()
        #expect(await client.state == .disposed)

        let countBefore = transport.recordedRequests.count
        await expectOperationError(.stateUnavailable(.disposed)) {
            _ = try await bootstrap(client)
        }
        #expect(transport.recordedRequests.count == countBefore)
    }

    // MARK: - Serialization and in-flight behavior

    @Test("Concurrent bootstrap attempts are serialized")
    func concurrentBootstrapAttemptsAreSerialized() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        let gate = TestGate()
        defer { gate.release() }
        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID), gate: gate))
        transport.enqueue(.init(status: 200, body: healthBody()))
        transport.enqueue(.init(status: 201, body: bootstrapBody(managerKey: key)))
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        let token = fixtureToken
        let username = fixtureUsername
        let password = fixturePassword
        let first = Task {
            try await client.bootstrapFirstAdministrator(
                token: token,
                username: username,
                password: password,
                managerFriendlyName: "Installer",
                acknowledgement: .operatorWillStoreMFASecretAndRecoveryCodesIndependently
            )
        }

        try await withTestTimeout { try await gate.waitUntilArrived() }
        #expect(await !client.isIrreversibleRequestInFlight)
        await expectOperationError(.operationInProgress) {
            _ = try await bootstrap(client)
        }
        #expect(transport.recordedRequests.count == 1)

        gate.release()
        let enrollment = try await withTestTimeout { try await first.value }
        #expect(enrollment.accountID == "account-1")
        #expect(await client.state == .awaitingMFAConfirmation)
        #expect(await !client.isIrreversibleRequestInFlight)
        #expect(transport.recordedRequests.count == 3)
    }

    @Test("Concurrent MFA mutations are serialized")
    func concurrentMFAMutationsAreSerialized() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)
        let enrollment = try await bootstrap(client)

        let gate = TestGate()
        defer { gate.release() }
        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(status: 200, body: confirmBody(), gate: gate))
        let code = "123456"
        let confirmationTask = Task {
            try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: code,
                recoveryCodesStoredIndependently: true
            )
        }

        try await withTestTimeout { try await gate.waitUntilArrived() }
        #expect(await client.isIrreversibleRequestInFlight)
        await expectOperationError(.operationInProgress) {
            _ = try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: code,
                recoveryCodesStoredIndependently: true
            )
        }
        await expectOperationError(.operationInProgress) {
            try await client.cancelPendingEnrollment(
                acknowledgement: .cancelPendingServerEnrollmentAndDiscardSecrets
            )
        }
        await expectOperationError(.operationInProgress) {
            _ = try await bootstrap(client)
        }
        #expect(transport.recordedRequests.count == 5)

        gate.release()
        let confirmation = try await withTestTimeout { try await confirmationTask.value }
        #expect(confirmation.mfaStatus == "active")
        #expect(await client.state == .confirmed)
        #expect(await !client.isIrreversibleRequestInFlight)
        #expect(transport.recordedRequests.count == 5)
    }

    @Test("Cancellation before dispatch is safe and leaves the client idle")
    func cancellationBeforeDispatchIsSafe() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        let gate = TestGate()
        defer { gate.release() }
        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID), gate: gate))
        transport.enqueue(.init(status: 200, body: healthBody()))
        transport.enqueue(.init(status: 201, body: bootstrapBody(managerKey: key)))
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        let token = fixtureToken
        let username = fixtureUsername
        let password = fixturePassword
        let task = Task {
            try await client.bootstrapFirstAdministrator(
                token: token,
                username: username,
                password: password,
                managerFriendlyName: "Installer",
                acknowledgement: .operatorWillStoreMFASecretAndRecoveryCodesIndependently
            )
        }

        try await withTestTimeout { try await gate.waitUntilArrived() }
        #expect(await !client.isIrreversibleRequestInFlight)
        task.cancel()
        gate.release()
        await expectHelicoidError(isCancelled) {
            _ = try await withTestTimeout { try await task.value }
        }
        #expect(await client.state == .idle)
        #expect(await !client.hasActiveEnrollment)
        #expect(await !client.isIrreversibleRequestInFlight)
        #expect(transport.recordedRequests.count == 1)
    }

    @Test("Cancellation after dispatch retains a received success")
    func cancellationAfterDispatchRetainsSuccess() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        let gate = TestGate(ignoresCancellation: true)
        defer { gate.release() }
        bootstrapSuccessStubs(
            transport: transport,
            managerKey: key,
            bootstrapGate: gate
        )
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        let token = fixtureToken
        let username = fixtureUsername
        let password = fixturePassword
        let task = Task {
            try await client.bootstrapFirstAdministrator(
                token: token,
                username: username,
                password: password,
                managerFriendlyName: "Installer",
                acknowledgement: .operatorWillStoreMFASecretAndRecoveryCodesIndependently
            )
        }

        try await withTestTimeout { try await gate.waitUntilArrived() }
        #expect(await client.isIrreversibleRequestInFlight)
        task.cancel()
        gate.release()
        let enrollment = try await withTestTimeout { try await task.value }
        #expect(enrollment.hasSecrets)
        #expect(await client.state == .awaitingMFAConfirmation)
        #expect(await client.hasActiveEnrollment)
        #expect(await !client.isIrreversibleRequestInFlight)
        #expect(transport.recordedRequests.count == 3)
    }

    @Test("Cancellation after dispatch without a response is unknown")
    func cancellationAfterDispatchWithoutResponseIsUnknown() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        let gate = TestGate()
        defer { gate.release() }
        bootstrapSuccessStubs(
            transport: transport,
            managerKey: key,
            bootstrapGate: gate
        )
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        let token = fixtureToken
        let username = fixtureUsername
        let password = fixturePassword
        let task = Task {
            try await client.bootstrapFirstAdministrator(
                token: token,
                username: username,
                password: password,
                managerFriendlyName: "Installer",
                acknowledgement: .operatorWillStoreMFASecretAndRecoveryCodesIndependently
            )
        }

        try await withTestTimeout { try await gate.waitUntilArrived() }
        task.cancel()
        await expectOperationError(.bootstrapOutcomeUnknown) {
            _ = try await withTestTimeout { try await task.value }
        }
        #expect(await client.state == .bootstrapOutcomeUnknown)
        #expect(await !client.hasActiveEnrollment)

        let countBefore = transport.recordedRequests.count
        await expectOperationError(.stateUnavailable(.bootstrapOutcomeUnknown)) {
            _ = try await bootstrap(client)
        }
        #expect(transport.recordedRequests.count == countBefore)
    }

    @Test("Transport failure after dispatch is unknown and not retryable")
    func transportFailureAfterDispatchIsUnknown() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        let gate = TestGate()
        defer { gate.release() }
        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(status: 200, body: healthBody()))
        transport.enqueue(.init(
            status: 201,
            body: bootstrapBody(managerKey: key),
            error: HelicoidError.unreachable,
            gate: gate
        ))
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        let token = fixtureToken
        let username = fixtureUsername
        let password = fixturePassword
        let task = Task {
            try await client.bootstrapFirstAdministrator(
                token: token,
                username: username,
                password: password,
                managerFriendlyName: "Installer",
                acknowledgement: .operatorWillStoreMFASecretAndRecoveryCodesIndependently
            )
        }

        try await withTestTimeout { try await gate.waitUntilArrived() }
        gate.release()
        await expectOperationError(.bootstrapOutcomeUnknown) {
            _ = try await withTestTimeout { try await task.value }
        }
        #expect(await client.state == .bootstrapOutcomeUnknown)
        #expect(await !client.hasActiveEnrollment)

        let countBefore = transport.recordedRequests.count
        await expectOperationError(.stateUnavailable(.bootstrapOutcomeUnknown)) {
            _ = try await bootstrap(client)
        }
        #expect(transport.recordedRequests.count == countBefore)
    }

    @Test("Confirmation failure after dispatch is unknown and not retryable")
    func confirmationFailureAfterDispatchIsUnknown() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)
        let enrollment = try await bootstrap(client)

        let gate = TestGate()
        defer { gate.release() }
        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(
            status: 200,
            body: confirmBody(),
            error: HelicoidError.unreachable,
            gate: gate
        ))
        let code = "123456"
        let task = Task {
            try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: code,
                recoveryCodesStoredIndependently: true
            )
        }

        try await withTestTimeout { try await gate.waitUntilArrived() }
        gate.release()
        await expectOperationError(.confirmationOutcomeUnknown) {
            _ = try await withTestTimeout { try await task.value }
        }
        #expect(await client.state == .confirmationOutcomeUnknown)
        #expect(await client.hasActiveEnrollment)
        #expect(enrollment.hasSecrets)

        let countBefore = transport.recordedRequests.count
        await expectOperationError(.stateUnavailable(.confirmationOutcomeUnknown)) {
            _ = try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: code,
                recoveryCodesStoredIndependently: true
            )
        }
        await expectOperationError(.stateUnavailable(.confirmationOutcomeUnknown)) {
            try await client.cancelPendingEnrollment(
                acknowledgement: .cancelPendingServerEnrollmentAndDiscardSecrets
            )
        }
        #expect(transport.recordedRequests.count == countBefore)
    }

    @Test("Cancellation failure after dispatch is unknown and not retryable")
    func cancellationFailureAfterDispatchIsUnknown() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        bootstrapSuccessStubs(transport: transport, managerKey: key)
        let client = makeClient(transport: transport, trust: trust, identity: identity)
        let enrollment = try await bootstrap(client)

        let gate = TestGate()
        defer { gate.release() }
        transport.enqueue(.init(status: 200, body: deploymentBody(deploymentID)))
        transport.enqueue(.init(
            status: 204,
            error: HelicoidError.unreachable,
            gate: gate
        ))
        let task = Task {
            try await client.cancelPendingEnrollment(
                acknowledgement: .cancelPendingServerEnrollmentAndDiscardSecrets
            )
        }

        try await withTestTimeout { try await gate.waitUntilArrived() }
        gate.release()
        await expectOperationError(.cancellationOutcomeUnknown) {
            try await withTestTimeout { try await task.value }
        }
        #expect(await client.state == .cancellationOutcomeUnknown)
        #expect(await client.hasActiveEnrollment)
        #expect(enrollment.hasSecrets)

        let countBefore = transport.recordedRequests.count
        await expectOperationError(.stateUnavailable(.cancellationOutcomeUnknown)) {
            try await client.cancelPendingEnrollment(
                acknowledgement: .cancelPendingServerEnrollmentAndDiscardSecrets
            )
        }
        #expect(transport.recordedRequests.count == countBefore)
    }

    @Test("Destructive operations are refused while a bootstrap is in flight")
    func destructiveOperationsRefusedWhileBootstrapInFlight() async throws {
        let identity = try makeIdentity()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let trust = try await makeTrust()
        let transport = ControlledBootstrapTransport()
        let gate = TestGate()
        defer { gate.release() }
        bootstrapSuccessStubs(
            transport: transport,
            managerKey: key,
            bootstrapGate: gate
        )
        let client = makeClient(transport: transport, trust: trust, identity: identity)

        let token = fixtureToken
        let username = fixtureUsername
        let password = fixturePassword
        let task = Task {
            try await client.bootstrapFirstAdministrator(
                token: token,
                username: username,
                password: password,
                managerFriendlyName: "Installer",
                acknowledgement: .operatorWillStoreMFASecretAndRecoveryCodesIndependently
            )
        }

        try await withTestTimeout { try await gate.waitUntilArrived() }
        #expect(await client.isIrreversibleRequestInFlight)
        await expectOperationError(.operationInProgress) {
            try await client.dispose()
        }
        await expectOperationError(.operationInProgress) {
            try await client.discardLocalState(
                acknowledgement: .discardLocalSecretsWithoutCancellingServerEnrollment
            )
        }
        await expectOperationError(.operationInProgress) {
            try await client.cancelPendingEnrollment(
                acknowledgement: .cancelPendingServerEnrollmentAndDiscardSecrets
            )
        }
        await expectOperationError(.operationInProgress) {
            _ = try await bootstrap(client)
        }
        #expect(await client.isOperationInFlight)
        #expect(await client.state == .bootstrapInFlight)

        gate.release()
        let enrollment = try await withTestTimeout { try await task.value }
        #expect(enrollment.hasSecrets)
        #expect(await client.state == .awaitingMFAConfirmation)
        #expect(await !client.isIrreversibleRequestInFlight)
    }
}
