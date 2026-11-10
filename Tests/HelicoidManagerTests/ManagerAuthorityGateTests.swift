import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore
@testable import HelicoidManager

private let gateDeploymentID = "dep_00000000000000000000000000000004"
private let gateAuthorityKeyHex = String(repeating: "a", count: 64)
private let gateAuthorityFingerprint =
    "e0e77a507412b120f6ede61f62295b1a7b2ff19d3dcc8f7253e51663470c888e"

private actor GateAuthorityKeyStore: ManagerAuthorityKeyStoring {
    private var values: [String: Data] = [:]

    func read(account: String) -> Data? { values[account] }

    func insertIfAbsent(_ bytes: Data, account: String) -> Bool {
        guard values[account] == nil else { return false }
        values[account] = bytes
        return true
    }

    func update(_ bytes: Data, account: String) throws {
        guard values[account] != nil else { throw HelicoidError.offline }
        values[account] = bytes
    }

    func delete(account: String) { values.removeValue(forKey: account) }
}

private struct GateNoopAuthorityLock: ManagerAuthorityLocking {
    func acquire() async throws -> any ManagerAuthorityLockReleasing {
        GateNoopAuthorityLockHandle()
    }
}

private struct GateNoopAuthorityLockHandle: ManagerAuthorityLockReleasing {
    func release() {}
}

private actor GateTransport: HTTPTransport {
    private var authorityBody: Data
    private var challengeBody: Data?
    private var completeBody: Data?
    private var pauseNextAuthority = false
    private var authorityPause: CheckedContinuation<Void, Never>?
    private(set) var authorityRequestCount = 0
    private(set) var healthRequestCount = 0
    private(set) var challengeRequestCount = 0
    private(set) var completeRequestCount = 0

    init(authorityBody: Data) {
        self.authorityBody = authorityBody
    }

    func setAuthorityBody(_ body: Data) {
        authorityBody = body
    }

    func setChallengeBody(_ body: Data?) {
        challengeBody = body
    }

    func setCompleteBody(_ body: Data?) {
        completeBody = body
    }

    func enablePauseNextAuthority() {
        pauseNextAuthority = true
    }

    func releaseAuthority() {
        authorityPause?.resume()
        authorityPause = nil
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        guard let url = request.url else {
            throw HelicoidError.invalidInput(field: "request", detail: "Missing URL.")
        }
        switch url.path {
        case "/v2/deployment/authority":
            authorityRequestCount += 1
            if pauseNextAuthority {
                pauseNextAuthority = false
                await withCheckedContinuation { authorityPause = $0 }
            }
            return try response(url: url, status: 200, body: authorityBody)
        case "/health":
            healthRequestCount += 1
            let body = Data(#"{"status":"ok","accepting_authorized_operations":true,"schema_version":2,"bootstrap_completed":true,"features":{}}"#.utf8)
            return try response(url: url, status: 200, body: body)
        case "/v2/auth/challenge":
            challengeRequestCount += 1
            guard let challengeBody else {
                throw HelicoidError.authenticationFailed(detail: "Unexpected challenge request.")
            }
            return try response(url: url, status: 201, body: challengeBody)
        case "/v2/auth/challenge/complete":
            completeRequestCount += 1
            guard let completeBody else {
                throw HelicoidError.authenticationFailed(detail: "Unexpected challenge completion.")
            }
            return try response(url: url, status: 200, body: completeBody)
        default:
            throw HelicoidError.unreachable
        }
    }

    private func response(url: URL, status: Int, body: Data) throws -> (Data, URLResponse) {
        let response = HTTPURLResponse(
            url: url,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        return (body, response)
    }
}

private func waitForGateCondition(
    _ condition: @Sendable () async -> Bool
) async throws {
    for _ in 0..<200 {
        if await condition() { return }
        try await Task.sleep(for: .milliseconds(10))
    }
    Issue.record("Timed out waiting for authority gate condition.")
}

private func gateAuthorityJSON(
    deploymentID: String = gateDeploymentID,
    keyHex: String = gateAuthorityKeyHex,
    generation: Int = 1
) -> Data {
    let object: [String: Any] = [
        "deployment_id": deploymentID,
        "grant_signing_public_key": keyHex,
        "authority_generation": generation,
    ]
    // swiftlint:disable:next force_try
    return try! JSONSerialization.data(withJSONObject: object)
}

private func gateBeginJSON(managerKey: String) -> Data {
    let object: [String: Any] = [
        "challenge_id": "gate-challenge",
        "challenge_token": "gate-challenge-token",
        "operation": "session",
        "manager_public_key": managerKey,
        "deployment_id": gateDeploymentID,
        "expires_at_unix": Int(Date().timeIntervalSince1970) + 60,
        "mfa_required": true,
    ]
    // swiftlint:disable:next force_try
    return try! JSONSerialization.data(withJSONObject: object)
}

private func gateLoginJSON(managerKey: String) -> Data {
    let object: [String: Any] = [
        "token": "gate-bearer",
        "expires_at_unix": Int(Date().timeIntervalSince1970) + 3_600,
        "account": [
            "id": "gate-account",
            "username": "operator",
            "state": "active",
            "capabilities": ["operate": true],
            "revision": 1,
        ] as [String: Any],
        "manager": [
            "id": "gate-manager",
            "public_identity": "key:\(managerKey)",
            "lifecycle_state": "approved",
        ] as [String: Any],
        "mfa": [
            "required": true,
            "available": true,
            "reason": "totp_active",
        ] as [String: Any],
        "manager_public_key": managerKey,
    ]
    // swiftlint:disable:next force_try
    return try! JSONSerialization.data(withJSONObject: object)
}

/// Test-only CA fixture (allowed in tests, never normal operation).
private let gateCADERHex = "3082019030820135a00302010202142f2d30f1e37fdf3db4f30d8fdf8728741175b71b300a06082a8648ce3d04030230153113301106035504030c0a48532d546573742d4341301e170d3236313031363135333434365a170d3336313031333135333434365a30153113301106035504030c0a48532d546573742d43413059301306072a8648ce3d020106082a8648ce3d030107034200045dda8b60404df01b54df24ff5be48548d57ee450d0d34016a3f917e964d4258ea20c94821c4d8fde270f7370d403b1b6d4a00d8be30ddd2c9c4ff7f96e108830a3633061301d0603551d0e04160414110d92f6818de0787dcf793d09154c449fcd5a33301f0603551d23041830168014110d92f6818de0787dcf793d09154c449fcd5a33300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020204300a06082a8648ce3d040302034900304602210090e960a7cbc20680e19c9af2859397890b074166c6da5d571f5f71577f80e60f022100f60d9460317df7434ac3f97ff9d9ebff66e8024063b6d6ead5ed477383301443"

private func makeGateTLSIdentity() throws -> DeploymentTLSIdentity {
    var bytes = Data()
    var index = gateCADERHex.startIndex
    while index < gateCADERHex.endIndex {
        let next = gateCADERHex.index(index, offsetBy: 2)
        bytes.append(UInt8(gateCADERHex[index..<next], radix: 16)!)
        index = next
    }
    let fingerprint = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    return try DeploymentTLSIdentity(
        deploymentID: gateDeploymentID,
        host: "server.test",
        port: 8443,
        caDER: bytes,
        caFingerprintSHA256: fingerprint
    )
}

private func makeGateSigningIdentity() throws -> ManagerSigningIdentity {
    try ManagerSigningIdentity(
        storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation
    )
}

private func makeGateStore(seeded: Bool) async throws -> ManagerAuthorityTrustStore {
    let store = ManagerAuthorityTrustStore(
        keyStore: GateAuthorityKeyStore(),
        authorityLock: GateNoopAuthorityLock()
    )
    guard seeded else { return store }
    let checkpoint = try DeploymentAuthorityCheckpoint(
        deploymentID: gateDeploymentID,
        grantSigningPublicKeyHex: gateAuthorityKeyHex,
        authorityGeneration: 1
    )
    let confirmation = try ManagerAuthorityConfirmation(
        operatorEnteredDeploymentID: gateDeploymentID,
        operatorEnteredKeyFingerprintSHA256: gateAuthorityFingerprint,
        operatorEnteredAuthorityGeneration: 1
    )
    _ = try await store.adopt(checkpoint, confirmation: confirmation)
    return store
}

private func makeGateClient(
    transport: GateTransport,
    identity: DeploymentTLSIdentity,
    signingIdentity: ManagerSigningIdentity? = nil
) throws -> NativeV2AuthClient {
    let signer: ManagerSigningIdentity
    if let signingIdentity {
        signer = signingIdentity
    } else {
        signer = try makeGateSigningIdentity()
    }
    return NativeV2AuthClient(
        transport: transport,
        trustedAuthority: identity,
        signingIdentity: signer
    )
}

private actor GateConnectionClient: ConnectionClient {
    private(set) var connectCount = 0
    private(set) var signInCount = 0

    func validateAddress(_ address: String) async -> AddressValidation {
        AddressValidation(outcome: .ok)
    }

    func connect(address: String) async -> Result<ServerIdentity, HelicoidError> {
        connectCount += 1
        return .failure(.serverContractUnavailable)
    }

    func trust(identity: ServerIdentity, address: String) async -> Result<Void, HelicoidError> {
        .failure(.serverContractUnavailable)
    }

    func signIn(username: String, password: String) async -> Result<OperatorID, HelicoidError> {
        signInCount += 1
        return .failure(.serverContractUnavailable)
    }

    func authorizedInventory() async -> Result<[Computer], HelicoidError> {
        .success([])
    }

    func managerApprovalState() async -> Result<ManagerApprovalState, HelicoidError> {
        .success(.unknown)
    }

    func signOut() async {}
}

@Suite("Manager production authority gate")
@MainActor
struct ManagerAuthorityGateTests {
    @Test("Nonproduction fixtures remain independent of production trust")
    func nonproductionModesRemainAvailable() {
        let fixtures = ManagerSession(
            configuration: ManagerLaunchConfiguration(useSourceFixtures: true)
        )
        let development = ManagerSession(
            configuration: ManagerLaunchConfiguration(useDevelopmentServer: true)
        )
        #expect(fixtures.allowsConnect)
        #expect(development.allowsConnect)
        #expect(fixtures.isFixturesMode)
        #expect(!fixtures.isDevelopmentServerMode)
        #expect(development.isDevelopmentServerMode)
        #expect(!development.isFixturesMode)
    }

    @Test("Generic client injection cannot bypass the production trust gate")
    func genericClientCannotBypassProductionGate() async throws {
        let client = GateConnectionClient()
        let session = ManagerSession(
            configuration: ManagerLaunchConfiguration(),
            client: client
        )
        session.username = "operator"
        session.password = "pw"

        #expect(session.allowsConnect == false)
        await session.connect()
        #expect(session.phase == .failed(.identityUnverified))
        await session.signIn()
        #expect(session.phase == .failed(.identityUnverified))
        #expect(await client.connectCount == 0)
        #expect(await client.signInCount == 0)
    }

    @Test("Production client without a checkpoint store refuses connect")
    func missingStoreRefusesConnect() async throws {
        let identity = try makeGateTLSIdentity()
        let transport = GateTransport(authorityBody: gateAuthorityJSON())
        let client = try makeGateClient(transport: transport, identity: identity)
        let session = ManagerSession(
            configuration: ManagerLaunchConfiguration(),
            productionAuthClient: client
        )

        #expect(session.allowsConnect == false)
        await session.connect()
        #expect(session.phase == .failed(.identityUnverified))
        session.username = "operator"
        session.password = "pw"
        await session.signIn()
        #expect(session.phase == .failed(.identityUnverified))
        #expect(await transport.authorityRequestCount == 0)
        #expect(await transport.healthRequestCount == 0)
        #expect(await transport.challengeRequestCount == 0)
    }

    @Test("Empty checkpoint store fails closed before health")
    func emptyStoreFailsClosed() async throws {
        let identity = try makeGateTLSIdentity()
        let transport = GateTransport(authorityBody: gateAuthorityJSON())
        let client = try makeGateClient(transport: transport, identity: identity)
        let session = ManagerSession(
            configuration: ManagerLaunchConfiguration(),
            productionAuthClient: client,
            authorityTrust: try await makeGateStore(seeded: false)
        )

        #expect(session.allowsConnect)
        session.serverAddress = "https://server.test:8443"
        await session.connect()
        if case .failed(.authenticationFailed) = session.phase {
            // Expected: no checkpoint is a trust-setup failure, not a key change.
        } else {
            Issue.record("expected authenticationFailed for an empty checkpoint store, got \(session.phase)")
        }
        #expect(await transport.authorityRequestCount == 0)
        #expect(await transport.healthRequestCount == 0)
    }

    @Test("Matching checkpoint permits production connect")
    func matchingCheckpointPermitsConnect() async throws {
        let identity = try makeGateTLSIdentity()
        let transport = GateTransport(authorityBody: gateAuthorityJSON())
        let client = try makeGateClient(transport: transport, identity: identity)
        let session = ManagerSession(
            configuration: ManagerLaunchConfiguration(),
            productionAuthClient: client,
            authorityTrust: try await makeGateStore(seeded: true)
        )

        session.serverAddress = "https://server.test:8443"
        await session.connect()
        #expect(session.phase == .needsSignIn)
        #expect(session.screen == .signIn)
        #expect(await transport.authorityRequestCount == 1)
        #expect(await transport.healthRequestCount == 1)
    }

    @Test("Rollback after connect fails sign-in before a challenge")
    func rollbackFailsSignInBeforeChallenge() async throws {
        let identity = try makeGateTLSIdentity()
        let transport = GateTransport(authorityBody: gateAuthorityJSON())
        let client = try makeGateClient(transport: transport, identity: identity)
        let store = try await makeGateStore(seeded: true)
        let session = ManagerSession(
            configuration: ManagerLaunchConfiguration(),
            productionAuthClient: client,
            authorityTrust: store
        )

        session.serverAddress = "https://server.test:8443"
        await session.connect()
        #expect(session.phase == .needsSignIn)

        await transport.setAuthorityBody(gateAuthorityJSON(generation: 2))
        session.username = "operator"
        session.password = "pw"
        await session.signIn()

        #expect(session.phase == .failed(.identityChanged))
        #expect(session.screen == .signIn)
        #expect(await transport.challengeRequestCount == 0)
    }

    @Test("Required MFA submission rechecks the authority checkpoint")
    func mfaSubmissionRechecksCheckpoint() async throws {
        let identity = try makeGateTLSIdentity()
        let signingIdentity = try makeGateSigningIdentity()
        let managerKey = AuthV2Canonical.lowercaseHex(signingIdentity.publicKey)
        let transport = GateTransport(authorityBody: gateAuthorityJSON())
        await transport.setChallengeBody(gateBeginJSON(managerKey: managerKey))
        await transport.setCompleteBody(gateLoginJSON(managerKey: managerKey))
        let client = try makeGateClient(
            transport: transport,
            identity: identity,
            signingIdentity: signingIdentity
        )
        let session = ManagerSession(
            configuration: ManagerLaunchConfiguration(),
            productionAuthClient: client,
            authorityTrust: try await makeGateStore(seeded: true)
        )

        session.serverAddress = "https://server.test:8443"
        await session.connect()
        session.username = "operator"
        session.password = "pw"
        await session.signIn()
        #expect(session.authCodeState == .required)
        #expect(await transport.challengeRequestCount == 1)

        await transport.setAuthorityBody(gateAuthorityJSON(generation: 2))
        session.authCode = "123456"
        await session.submitAuthCode()

        #expect(session.phase == .failed(.identityChanged))
        #expect(session.authCodeState == .idle)
        #expect(session.authCode.isEmpty)
        if case .identityMismatch = session.signInError {
            // Expected fail-closed authority mismatch.
        } else {
            Issue.record("expected identityMismatch for signInError, got \(String(describing: session.signInError))")
        }
        if case .identityMismatch = session.authCodeError {
            // Expected fail-closed authority mismatch.
        } else {
            Issue.record("expected identityMismatch for authCodeError, got \(String(describing: session.authCodeError))")
        }
        #expect(await transport.completeRequestCount == 0)
    }

    @Test("Required MFA submission fails closed after checkpoint clear")
    func mfaSubmissionFailsAfterCheckpointClear() async throws {
        let identity = try makeGateTLSIdentity()
        let signingIdentity = try makeGateSigningIdentity()
        let managerKey = AuthV2Canonical.lowercaseHex(signingIdentity.publicKey)
        let transport = GateTransport(authorityBody: gateAuthorityJSON())
        await transport.setChallengeBody(gateBeginJSON(managerKey: managerKey))
        await transport.setCompleteBody(gateLoginJSON(managerKey: managerKey))
        let client = try makeGateClient(
            transport: transport,
            identity: identity,
            signingIdentity: signingIdentity
        )
        let store = try await makeGateStore(seeded: true)
        let session = ManagerSession(
            configuration: ManagerLaunchConfiguration(),
            productionAuthClient: client,
            authorityTrust: store
        )

        session.serverAddress = "https://server.test:8443"
        await session.connect()
        session.username = "operator"
        session.password = "pw"
        await session.signIn()
        #expect(session.authCodeState == .required)

        try await store.clear(deploymentID: gateDeploymentID)
        session.authCode = "123456"
        await session.submitAuthCode()

        if case .failed(.authenticationFailed) = session.phase {
            // Expected: no saved checkpoint, so MFA completion is refused.
        } else {
            Issue.record("expected authenticationFailed after checkpoint clear, got \(session.phase)")
        }
        #expect(session.authCodeState == .idle)
        #expect(await transport.completeRequestCount == 0)
    }

    @Test("Stale authority failure cannot override sign-out")
    func staleAuthorityFailureCannotOverrideSignOut() async throws {
        let identity = try makeGateTLSIdentity()
        let transport = GateTransport(authorityBody: gateAuthorityJSON())
        let client = try makeGateClient(transport: transport, identity: identity)
        let session = ManagerSession(
            configuration: ManagerLaunchConfiguration(),
            productionAuthClient: client,
            authorityTrust: try await makeGateStore(seeded: true)
        )

        session.serverAddress = "https://server.test:8443"
        await session.connect()
        #expect(session.phase == .needsSignIn)

        await transport.enablePauseNextAuthority()
        session.username = "operator"
        session.password = "pw"
        let signInTask = Task { await session.signIn() }
        try await waitForGateCondition { await transport.authorityRequestCount >= 2 }

        await session.signOut()
        #expect(session.phase == .notConfigured)
        #expect(session.screen == .connect)

        await transport.setAuthorityBody(gateAuthorityJSON(generation: 2))
        await transport.releaseAuthority()
        await signInTask.value

        #expect(session.phase == .notConfigured)
        #expect(session.screen == .connect)
        #expect(session.signInError == nil)
        #expect(await transport.challengeRequestCount == 0)
    }
}
