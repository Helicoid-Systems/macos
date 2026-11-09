import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

/// Causal regressions at the actual sign-in state coordinator seam.
/// These drive AuthSignInCoordinator — the code ManagerSession uses — not
/// isolated counter helpers.
@Suite("Auth sign-in coordinator causality")
@MainActor
struct AuthSignInCoordinatorTests {
    private func makeIdentity() throws -> ManagerSigningIdentity {
        try ManagerSigningIdentity(storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation)
    }

    private func makeAuthority(deploymentID: String = "deploy-1") async throws -> DeploymentTLSIdentity {
        let material = try await TLSTestHarness.sharedMaterial()
        return try DeploymentTLSIdentity(
            deploymentID: deploymentID,
            host: "server.test",
            port: 8443,
            caDER: material.caDER,
            caFingerprintSHA256: material.caFingerprint
        )
    }

    private func hexKey(_ identity: ManagerSigningIdentity) -> String {
        AuthV2Canonical.lowercaseHex(identity.publicKey)
    }

    private func beginJSON(
        managerKey: String,
        mfaRequired: Bool? = true,
        expiresAtUnix: Int? = nil,
        token: String = "challenge-token-secret",
        challengeID: String = "challenge-1"
    ) -> Data {
        var object: [String: Any] = [
            "challenge_id": challengeID,
            "challenge_token": token,
            "operation": "session",
            "manager_public_key": managerKey,
            "deployment_id": "deploy-1",
            "expires_at_unix": expiresAtUnix ?? (Int(Date().timeIntervalSince1970) + 60),
        ]
        if let mfaRequired {
            object["mfa_required"] = mfaRequired
        }
        // swiftlint:disable:next force_try
        return try! JSONSerialization.data(withJSONObject: object)
    }

    private func loginJSON(managerKey: String, mfaRequired: Bool = true, mfaAvailable: Bool = true) -> Data {
        let object: [String: Any] = [
            "token": "bearer-token-secret",
            "expires_at_unix": Int(Date().timeIntervalSince1970) + 3600,
            "account": [
                "id": "account-1",
                "username": "operator",
                "state": "active",
                "capabilities": ["operate": true],
                "revision": 1,
            ] as [String: Any],
            "manager": [
                "id": "manager-1",
                "public_identity": "key:\(managerKey)",
                "lifecycle_state": "approved",
            ] as [String: Any],
            "mfa": [
                "required": mfaRequired,
                "available": mfaAvailable,
                "reason": "totp_active",
            ] as [String: Any],
            "manager_public_key": managerKey,
        ]
        // swiftlint:disable:next force_try
        return try! JSONSerialization.data(withJSONObject: object)
    }

    private func inventoryJSON(computerID: String = "computer-1") -> Data {
        let object: [String: Any] = [
            "computers": [[
                "id": computerID,
                "public_identity": "computer-key",
                "enrollment_state": "enrolled",
            ] as [String: Any]],
        ]
        // swiftlint:disable:next force_try
        return try! JSONSerialization.data(withJSONObject: object)
    }

    @Test("Cancel after client success but before UI install cannot install")
    func cancelBlocksInstallAfterClientSuccess() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let transport = FixtureTransport()
        transport.stub = .init(status: 201, body: beginJSON(managerKey: key, mfaRequired: true))
        let client = NativeV2AuthClient(transport: transport, trustedAuthority: authority, signingIdentity: identity)
        let coordinator = AuthSignInCoordinator(client: client)

        // Drive begin through the actual coordinator path with required code.
        await coordinator.signIn(username: "operator", password: "pw")
        #expect(coordinator.phase == .awaitingRequiredCode)
        #expect(coordinator.pendingChallenge != nil)

        // Complete on the client (network success), then cancel BEFORE UI install.
        guard let challenge = coordinator.pendingChallenge else {
            Issue.record("pending challenge required")
            return
        }
        transport.stub = .init(status: 200, body: loginJSON(managerKey: key))
        let session = try await client.completeChallenge(challenge, totpCode: "123456")
        // Causal gate: cancel after client success, before applyCompletedSession.
        await coordinator.cancelAuthCode()
        try await coordinator.applyCompletedSession(session, installToken: coordinator.currentGeneration &- 1)
        // Old token cannot install.
        #expect(coordinator.phase != .signedIn)
        #expect(coordinator.session == nil)

        // Explicit current-generation install would work; stale token must not.
        let stale = coordinator.beginOperation()
        await coordinator.cancelAuthCode()
        try await coordinator.applyCompletedSession(session, installToken: stale)
        #expect(coordinator.phase != .signedIn)
        #expect(coordinator.session == nil)
    }

    @Test("Old sign-in completion/error cannot clear a newer challenge")
    func staleCompletionCannotClearReplacement() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let transport = FixtureTransport()
        let client = NativeV2AuthClient(transport: transport, trustedAuthority: authority, signingIdentity: identity)
        let coordinator = AuthSignInCoordinator(client: client)

        // Operation 1 begins (required code).
        transport.stub = .init(status: 201, body: beginJSON(managerKey: key, mfaRequired: true, expiresAtUnix: Int(Date().timeIntervalSince1970) + 30, token: "old-challenge-token", challengeID: "challenge-old"))
        await coordinator.signIn(username: "operator", password: "pw")
        let oldToken = coordinator.currentGeneration
        #expect(coordinator.pendingChallenge != nil)
        let oldChallenge = coordinator.pendingChallenge

        // Operation 2 begins (new challenge).
        transport.stub = .init(status: 201, body: beginJSON(managerKey: key, mfaRequired: true, expiresAtUnix: Int(Date().timeIntervalSince1970) + 90, token: "new-challenge-token", challengeID: "challenge-new"))
        await coordinator.signIn(username: "operator", password: "pw2")
        let newToken = coordinator.currentGeneration
        let newChallenge = coordinator.pendingChallenge
        #expect(newToken != oldToken)
        #expect(newChallenge?.challengeToken != oldChallenge?.challengeToken)

        // Stale branch tries to clear/cancel after client work of op1 finished.
        await coordinator.applyFailure(.authenticationFailed(detail: "stale"), installToken: oldToken)
        #expect(coordinator.pendingChallenge?.challengeToken == newChallenge?.challengeToken)
        #expect(coordinator.phase == .awaitingRequiredCode)

        // Stale branch tries to install a completed session.
        let staleSession = AuthenticatedSession(
            token: "stale-token",
            expiresAtUnix: Int(Date().timeIntervalSince1970) + 3600,
            account: AccountDTO(id: "a", username: "u", state: "active"),
            manager: nil,
            mfa: nil
        )
        try await coordinator.applyCompletedSession(staleSession, installToken: oldToken)
        #expect(coordinator.session == nil)
        #expect(coordinator.pendingChallenge?.challengeToken == newChallenge?.challengeToken)

        // Explicit cancel of the CURRENT operation clears the replacement.
        await coordinator.cancelAuthCode()
        #expect(coordinator.pendingChallenge == nil)
        #expect(coordinator.phase == .awaitingCredentials)
    }

    @Test("Sign-out while inventory is in flight cannot re-install prior inventory")
    func signOutFencesInventory() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let sequencer = SequencedTransport()
        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, mfaRequired: false))
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, mfaRequired: false, mfaAvailable: false))
        let client2 = NativeV2AuthClient(transport: sequencer, trustedAuthority: authority, signingIdentity: identity)
        let coordinator2 = AuthSignInCoordinator(client: client2)
        await coordinator2.signIn(username: "operator", password: "pw")
        #expect(coordinator2.phase == .signedIn)

        // Start inventory (will complete slowly), then sign out before it lands.
        sequencer.enqueueDelay(status: 200, body: inventoryJSON(), delayNs: 200_000_000)
        async let reload: Void = coordinator2.reloadInventory()
        await coordinator2.signOut()
        await reload
        #expect(coordinator2.inventory.isEmpty)
        #expect(coordinator2.session == nil)
        #expect(coordinator2.phase == .idle)
    }

    @Test("Successful inventory retry clears a stale refresh error")
    func successfulReloadClearsStaleError() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let sequencer = SequencedTransport()
        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, mfaRequired: false))
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, mfaRequired: false, mfaAvailable: false))
        sequencer.enqueue(status: 500, body: Data())
        let client = NativeV2AuthClient(transport: sequencer, trustedAuthority: authority, signingIdentity: identity)
        let coordinator = AuthSignInCoordinator(client: client)

        await coordinator.signIn(username: "operator", password: "pw")
        #expect(coordinator.phase == .signedIn)
        #expect(coordinator.signInError == .unreachable)
        #expect(coordinator.inventory.isEmpty)

        sequencer.enqueue(status: 200, body: inventoryJSON())
        await coordinator.reloadInventory()

        #expect(coordinator.signInError == nil)
        #expect(coordinator.inventory.count == 1)
    }

    @Test("Newer inventory request wins when an older response arrives last")
    func newerInventoryRequestSupersedesOlderResponse() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let sequencer = SequencedTransport()
        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, mfaRequired: false))
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, mfaRequired: false, mfaAvailable: false))
        sequencer.enqueue(status: 200, body: inventoryJSON(computerID: "initial"))
        let client = NativeV2AuthClient(transport: sequencer, trustedAuthority: authority, signingIdentity: identity)
        let coordinator = AuthSignInCoordinator(client: client)
        await coordinator.signIn(username: "operator", password: "pw")
        #expect(coordinator.inventory.map(\.id.rawValue) == ["initial"])

        // Older request starts first but returns last. The newer response is
        // already installed and must not be replaced by the stale one.
        let previousRequests = sequencer.startedRequestCount
        sequencer.enqueueDelay(status: 200, body: inventoryJSON(computerID: "older"), delayNs: 250_000_000)
        async let older: Void = coordinator.reloadInventory()
        await sequencer.waitUntilRequestsStarted(previousRequests + 1)

        sequencer.enqueue(status: 200, body: inventoryJSON(computerID: "newer"))
        await coordinator.reloadInventory()
        #expect(coordinator.inventory.map(\.id.rawValue) == ["newer"])

        await older
        #expect(coordinator.inventory.map(\.id.rawValue) == ["newer"], "older response must be discarded")
        #expect(coordinator.signInError == nil)
        #expect(coordinator.session != nil)
    }

    @Test("Inventory 401 credential loss ends the session and clears inventory")
    func inventoryExpiryEndsSession() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let sequencer = SequencedTransport()
        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, mfaRequired: false))
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, mfaRequired: false, mfaAvailable: false))
        sequencer.enqueue(status: 200, body: inventoryJSON())
        let client = NativeV2AuthClient(transport: sequencer, trustedAuthority: authority, signingIdentity: identity)
        let coordinator = AuthSignInCoordinator(client: client)
        await coordinator.signIn(username: "operator", password: "pw")
        #expect(coordinator.phase == .signedIn)
        #expect(await client.hasLiveSession)

        sequencer.enqueue(status: 401, body: Data())
        await coordinator.reloadInventory()

        #expect(coordinator.phase == .awaitingCredentials)
        #expect(coordinator.session == nil)
        #expect(coordinator.inventory.isEmpty)
        if case .sessionExpired = coordinator.signInError {} else {
            Issue.record("expected sessionExpired, got \(String(describing: coordinator.signInError))")
        }
        #expect(await client.hasLiveSession == false)
    }

    @Test("Owned sign-in task slot is not stolen by a stale finisher")
    func staleTaskClearIsOwned() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let sequencer = SequencedTransport()
        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, mfaRequired: true))
        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, mfaRequired: true))
        let client = NativeV2AuthClient(transport: sequencer, trustedAuthority: authority, signingIdentity: identity)
        let coordinator = AuthSignInCoordinator(client: client)

        await coordinator.signIn(username: "operator", password: "pw")
        #expect(coordinator.phase == .awaitingRequiredCode)
        let firstToken = coordinator.currentGeneration
        await coordinator.signIn(username: "operator", password: "pw")
        #expect(coordinator.currentGeneration != firstToken)
        #expect(coordinator.ownsOperation(coordinator.currentGeneration))
        #expect(!coordinator.ownsOperation(firstToken))
    }
}

/// Minimal in-order HTTP transport for causal sequencing in tests only.
/// `bodyBuilder` runs after `delayNs`, so a responder can issue `expires`
/// at actual response time (interop clock semantics).
final class SequencedTransport: HTTPTransport, @unchecked Sendable {
    struct Item {
        var status: Int
        var body: Data
        var delayNs: UInt64
        var bodyBuilder: (@Sendable () -> Data)?
    }

    private let lock = NSLock()
    private var items: [Item] = []
    private var startedRequestCountValue = 0
    private var startWaiters: [CheckedContinuation<Void, Never>] = []

    var startedRequestCount: Int {
        lock.withLock { startedRequestCountValue }
    }

    /// Wait until at least `count` requests have begun (before any delay).
    func waitUntilRequestsStarted(_ count: Int) async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if startedRequestCountValue >= count {
                lock.unlock()
                continuation.resume()
            } else {
                startWaiters.append(continuation)
                lock.unlock()
            }
        }
    }

    func enqueue(status: Int, body: Data) {
        lock.lock()
        items.append(Item(status: status, body: body, delayNs: 0, bodyBuilder: nil))
        lock.unlock()
    }

    func enqueueDelay(status: Int, body: Data, delayNs: UInt64) {
        lock.lock()
        items.append(Item(status: status, body: body, delayNs: delayNs, bodyBuilder: nil))
        lock.unlock()
    }

    func enqueueDelayBuilder(status: Int, delayNs: UInt64, bodyBuilder: @escaping @Sendable () -> Data) {
        lock.lock()
        items.append(Item(status: status, body: Data(), delayNs: delayNs, bodyBuilder: bodyBuilder))
        lock.unlock()
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        let (item, waiters): (Item?, [CheckedContinuation<Void, Never>]) = lock.withLock {
            guard !items.isEmpty else { return (nil, []) }
            startedRequestCountValue += 1
            let waiters = startWaiters
            startWaiters.removeAll()
            return (items.removeFirst(), waiters)
        }
        for waiter in waiters {
            waiter.resume()
        }
        guard let item else {
            throw HelicoidError.unreachable
        }
        if item.delayNs > 0 {
            try await Task.sleep(nanoseconds: item.delayNs)
        }
        let body = item.bodyBuilder?() ?? item.body
        if body.count > maxBytes {
            throw HelicoidError.invalidInput(field: "response", detail: "Response body exceeded the bounded size limit.")
        }
        let url = request.url ?? URL(string: "https://server.test:8443/")!
        let response = HTTPURLResponse(
            url: url,
            statusCode: item.status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        return (body, response)
    }
}
