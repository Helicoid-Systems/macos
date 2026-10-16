import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

/// Session expiry / invalidation at the actual client + coordinator seam.
@Suite("Native v2 session expiry")
@MainActor
struct SessionExpiryTests {
    private func makeIdentity() throws -> ManagerSigningIdentity {
        try ManagerSigningIdentity(storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation)
    }

    private func makeAuthority() async throws -> DeploymentTLSIdentity {
        let material = try await TLSTestHarness.sharedMaterial()
        return try DeploymentTLSIdentity(
            deploymentID: "deploy-1",
            host: "server.test",
            port: 8443,
            caDER: material.caDER,
            caFingerprintSHA256: material.caFingerprint
        )
    }

    private func keyHex(_ identity: ManagerSigningIdentity) -> String {
        AuthV2Canonical.lowercaseHex(identity.publicKey)
    }

    private func beginJSON(managerKey: String, expiresAtUnix: Int) -> Data {
        let object: [String: Any] = [
            "challenge_id": "ch-1",
            "challenge_token": "tok-1",
            "operation": "session",
            "manager_public_key": managerKey,
            "deployment_id": "deploy-1",
            "expires_at_unix": expiresAtUnix,
            "mfa_required": false,
        ]
        // swiftlint:disable:next force_try
        return try! JSONSerialization.data(withJSONObject: object)
    }

    private func loginJSON(managerKey: String, expiresAtUnix: Int) -> Data {
        let object: [String: Any] = [
            "token": "bearer-live",
            "expires_at_unix": expiresAtUnix,
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
                "required": false,
                "available": false,
                "reason": "none",
            ] as [String: Any],
            "manager_public_key": managerKey,
        ]
        // swiftlint:disable:next force_try
        return try! JSONSerialization.data(withJSONObject: object)
    }

    private func inventoryJSON() -> Data {
        let object: [String: Any] = [
            "computers": [[
                "id": "c1",
                "public_identity": "p1",
                "enrollment_state": "enrolled",
            ] as [String: Any]],
        ]
        // swiftlint:disable:next force_try
        return try! JSONSerialization.data(withJSONObject: object)
    }

    private func makeClient(
        transport: some HTTPTransport,
        clock: ManualSessionTimeSource
    ) async throws -> (NativeV2AuthClient, String) {
        let identity = try makeIdentity()
        let authority = try await makeAuthority()
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: authority,
            signingIdentity: identity,
            timeSource: clock
        )
        return (client, keyHex(identity))
    }

    // MARK: - Client deadline

    @Test("Coordinator: session deadline task does not retain abandoned client")
    func coordinatorDeadlineTaskDoesNotRetainClient() async throws {
        let clock = ManualSessionTimeSource()
        let sequencer = SequencedTransport()
        weak var abandoned: NativeV2AuthClient?
        do {
            let (client, key) = try await makeClient(transport: sequencer, clock: clock)
            sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
            let challenge = try await client.beginChallenge(username: "u", password: "p")
            sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3600))
            _ = try await client.completeChallenge(challenge, totpCode: nil)
            for _ in 0..<200 where clock.coordinatorSleeperCount == 0 { await Task.yield() }
            try #require(clock.coordinatorSleeperCount > 0, "actual owned deadline sleeper must be parked")
            abandoned = client
        }
        for _ in 0..<200 { await Task.yield() }
        #expect(abandoned == nil, "the owned deadline task must not retain its client through the session lifetime")
        clock.advanceMonotonic(seconds: 3601)
    }

    @Test("Coordinator: continuous time preserves positive subsecond duration")
    func coordinatorContinuousClockSubsecondPrecision() {
        let start = ContinuousClock.now
        let end = start.advanced(by: .milliseconds(500))
        #expect(LiveSessionTimeSource.nanos(from: start, to: end) == 500_000_000)
    }

    @Test("Coordinator: canceled expiry waiter returns without spinning or clearing live session")
    func coordinatorCancelledExpiryWaiterReturns() async throws {
        let clock = ManualSessionTimeSource()
        let sequencer = SequencedTransport()
        let (client, key) = try await makeClient(transport: sequencer, clock: clock)
        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        let challenge = try await client.beginChallenge(username: "u", password: "p")
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3600))
        _ = try await client.completeChallenge(challenge, totpCode: nil)
        let waiter = Task { await client.waitForSessionExpiry() }
        waiter.cancel()
        _ = await waiter.value
        #expect(await client.hasLiveSession)
        await client.signOutLocal()
    }

    @Test("Successful session becomes expired and bearer is cleared without network")
    func sessionBecomesExpired() async throws {
        let clock = ManualSessionTimeSource(wallUnix: 1_760_000_000, monotonicNanos: 1_000)
        let sequencer = SequencedTransport()
        let (client, key) = try await makeClient(transport: sequencer, clock: clock)
        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        let challenge = try await client.beginChallenge(username: "u", password: "p")
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: 1_760_000_000 + 3_600))
        _ = try await client.completeChallenge(challenge, totpCode: nil)
        #expect(await client.hasLiveSession)
        #expect(await client.bearerToken == "bearer-live")

        clock.advanceMonotonic(seconds: 3_601)
        #expect(!(await client.hasLiveSession))
        #expect(await client.bearerToken == nil)
    }

    @Test("No authorized request is sent with an expired bearer")
    func expiredBearerNeverSent() async throws {
        let clock = ManualSessionTimeSource(wallUnix: 1_760_000_000, monotonicNanos: 1_000)
        let transport = CountingTransport()
        let (client, key) = try await makeClient(transport: transport, clock: clock)
        transport.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        let challenge = try await client.beginChallenge(username: "u", password: "p")
        transport.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: 1_760_000_000 + 60))
        _ = try await client.completeChallenge(challenge, totpCode: nil)
        let sentAfterInstall = await transport.requestCount

        clock.advanceMonotonic(seconds: 61)
        let result = await client.authorizedInventory()
        guard case .failure(let error) = result else {
            Issue.record("expired authorized call must fail")
            return
        }
        if case .sessionExpired = error {} else if case .notConfigured = error {} else {
            Issue.record("expected sessionExpired, got \(error)")
        }
        #expect(await transport.requestCount == sentAfterInstall, "must not send with expired bearer")
    }

    @Test("Wall clock rollback cannot prolong the session")
    func wallRollbackCannotProlong() async throws {
        let clock = ManualSessionTimeSource(wallUnix: 1_760_000_000, monotonicNanos: 1_000)
        let sequencer = SequencedTransport()
        let (client, key) = try await makeClient(transport: sequencer, clock: clock)
        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        let challenge = try await client.beginChallenge(username: "u", password: "p")
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: 1_760_000_000 + 3_600))
        _ = try await client.completeChallenge(challenge, totpCode: nil)
        #expect(await client.hasLiveSession)

        clock.rollbackWall(seconds: 86_400)
        clock.advanceMonotonic(seconds: 3_601)
        #expect(!(await client.hasLiveSession))
    }

    @Test("Monotonic deadline helper is overflow-safe and unpadded")
    func deadlineHelper() {
        #expect(NativeV2AuthClient.monotonicDeadlineNanos(remainingSeconds: 7200, nowNanos: 100) == 100 + 7_200_000_000_000)
        #expect(NativeV2AuthClient.monotonicDeadlineNanos(remainingSeconds: 0, nowNanos: 100) == nil)
        #expect(NativeV2AuthClient.monotonicDeadlineNanos(remainingSeconds: -1, nowNanos: 100) == nil)
        #expect(NativeV2AuthClient.monotonicDeadlineNanos(remainingSeconds: 7201, nowNanos: 100) == nil)
        #expect(NativeV2AuthClient.monotonicDeadlineNanos(remainingSeconds: 7200, nowNanos: UInt64.max) == nil)
    }

    // MARK: - 401 / 403

    @Test("Current 401 clears the matching bearer")
    func current401Clears() async throws {
        let clock = ManualSessionTimeSource()
        let transport = CountingTransport()
        let (client, key) = try await makeClient(transport: transport, clock: clock)
        transport.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        let challenge = try await client.beginChallenge(username: "u", password: "p")
        transport.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3_600))
        _ = try await client.completeChallenge(challenge, totpCode: nil)
        #expect(await client.hasLiveSession)

        transport.enqueue(status: 401, body: Data())
        let result = await client.authorizedInventory()
        guard case .failure(let error) = result else {
            Issue.record("401 must fail")
            return
        }
        if case .sessionExpired = error {} else {
            Issue.record("expected sessionExpired, got \(error)")
        }
        #expect(!(await client.hasLiveSession))
        #expect(await client.bearerToken == nil)
    }

    @Test("Old request 401 after replacement preserves the new bearer")
    func stale401PreservesReplacement() async throws {
        let clock = ManualSessionTimeSource()
        let transport = CountingTransport()
        let (client, key) = try await makeClient(transport: transport, clock: clock)

        transport.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        let first = try await client.beginChallenge(username: "u", password: "p")
        transport.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3_600))
        _ = try await client.completeChallenge(first, totpCode: nil)
        #expect(await client.bearerToken == "bearer-live")

        // Replacement sign-in installs a new bearer (new install generation).
        transport.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        let second = try await client.beginChallenge(username: "u", password: "p")
        transport.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3_600))
        _ = try await client.completeChallenge(second, totpCode: nil)
        #expect(await client.hasLiveSession)

        // Simulate old-generation 401 cleanup against a replaced session.
        await client.clearLiveSession(ifRequestToken: "bearer-live", requestGeneration: 1)
        #expect(await client.hasLiveSession, "stale 401 must not clear replacement")
    }

    @Test("Operation 403 keeps the permitted session")
    func forbiddenKeepsSession() async throws {
        let clock = ManualSessionTimeSource()
        let transport = CountingTransport()
        let (client, key) = try await makeClient(transport: transport, clock: clock)
        transport.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        let challenge = try await client.beginChallenge(username: "u", password: "p")
        transport.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3_600))
        _ = try await client.completeChallenge(challenge, totpCode: nil)

        transport.enqueue(status: 403, body: Data())
        let result = await client.authorizedInventory()
        guard case .failure(let error) = result else {
            Issue.record("403 must fail the operation")
            return
        }
        if case .permissionDenied = error {} else {
            Issue.record("expected permissionDenied, got \(error)")
        }
        #expect(await client.hasLiveSession, "403 must not destroy the session")
    }

    // MARK: - Coordinator UI

    @Test("Coordinator expiry clears inventory and returns to sign-in")
    func coordinatorExpiryClearsUI() async throws {
        let clock = ManualSessionTimeSource()
        let sequencer = SequencedTransport()
        let (client, key) = try await makeClient(transport: sequencer, clock: clock)
        let coordinator = AuthSignInCoordinator(client: client)

        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3_600))
        sequencer.enqueue(status: 200, body: inventoryJSON())
        await coordinator.signIn(username: "u", password: "p")
        #expect(coordinator.phase == .signedIn)
        #expect(!coordinator.inventory.isEmpty)

        // Automatic expiry: advance the wakeable clock; no helper call.
        clock.advanceMonotonic(seconds: 3_601)
        // Allow the parked deadline sleeper / waiter to resume.
        try await Task.sleep(nanoseconds: 20_000_000)
        #expect(coordinator.phase == .awaitingCredentials)
        #expect(coordinator.inventory.isEmpty)
        #expect(coordinator.session == nil)
        if case .sessionExpired = coordinator.signInError {} else {
            Issue.record("expected sessionExpired copy, got \(String(describing: coordinator.signInError))")
        }
        #expect(!(await client.hasLiveSession))
    }

    @Test("Canceled watcher does not expire a valid replacement session")
    func canceledWatcherDoesNotExpireReplacement() async throws {
        let clock = ManualSessionTimeSource()
        let sequencer = SequencedTransport()
        let (client, key) = try await makeClient(transport: sequencer, clock: clock)
        let coordinator = AuthSignInCoordinator(client: client)

        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3600))
        sequencer.enqueue(status: 200, body: inventoryJSON())
        await coordinator.signIn(username: "u", password: "p")
        #expect(coordinator.phase == .signedIn)
        let firstToken = coordinator.currentGeneration

        // Replace session (cancels the first watcher).
        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3600))
        sequencer.enqueue(status: 200, body: inventoryJSON())
        await coordinator.signIn(username: "u", password: "p")
        #expect(coordinator.phase == .signedIn)
        #expect(coordinator.currentGeneration != firstToken)

        // Canceled first watcher must not expire the live replacement.
        #expect(coordinator.phase == .signedIn)
        #expect(await client.hasLiveSession)
    }

    @Test("Stale expiry callback after replacement cannot clear the new session")
    func staleExpiryCallbackIgnored() async throws {
        let clock = ManualSessionTimeSource()
        let sequencer = SequencedTransport()
        let (client, key) = try await makeClient(transport: sequencer, clock: clock)
        let coordinator = AuthSignInCoordinator(client: client)

        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3_600))
        sequencer.enqueue(status: 200, body: inventoryJSON())
        await coordinator.signIn(username: "u", password: "p")
        let oldToken = coordinator.currentGeneration

        // Replacement
        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3_600))
        sequencer.enqueue(status: 200, body: inventoryJSON())
        await coordinator.signIn(username: "u", password: "p")
        #expect(coordinator.phase == .signedIn)

        // Stale watcher callback path: generation fence (does not wait on live clock).
        coordinator.applySessionExpired(installToken: oldToken)
        #expect(coordinator.phase == .signedIn, "stale expiry must not clear replacement")
        #expect(!coordinator.inventory.isEmpty)
        #expect(coordinator.session != nil)
    }

    @Test("Client releases after dispose when no waiters remain")
    func deallocationAfterDisposal() async throws {
        let clock = ManualSessionTimeSource()
        let sequencer = SequencedTransport()
        weak var weakClient: NativeV2AuthClient?
        weak var weakCoordinator: AuthSignInCoordinator?

        do {
            let identity = try makeIdentity()
            let authority = try await makeAuthority()
            let client = NativeV2AuthClient(
                transport: sequencer,
                trustedAuthority: authority,
                signingIdentity: identity,
                timeSource: clock
            )
            let coordinator = AuthSignInCoordinator(client: client)
            let key = keyHex(identity)
            sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
            let challenge = try await client.beginChallenge(username: "u", password: "p")
            sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3600))
            _ = try await client.completeChallenge(challenge, totpCode: nil)
            await coordinator.signOut()
            await client.dispose()
            weakClient = client
            weakCoordinator = coordinator
        }

        for _ in 0..<10 {
            await Task.yield()
        }
        // Ownership: dispose/cancel releases waiters and deadline tasks.
        #expect(weakCoordinator == nil, "coordinator must deallocate after its owner drops")
        #expect(weakClient == nil, "client must deallocate after dispose when no waiters remain")
    }

    @Test("Coordinator 403 denies data but keeps signed-in session")
    func coordinator403KeepsSession() async throws {
        let clock = ManualSessionTimeSource()
        let sequencer = SequencedTransport()
        let (client, key) = try await makeClient(transport: sequencer, clock: clock)
        let coordinator = AuthSignInCoordinator(client: client)

        sequencer.enqueue(status: 201, body: beginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 60))
        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key, expiresAtUnix: clock.wallUnix + 3_600))
        sequencer.enqueue(status: 200, body: inventoryJSON())
        await coordinator.signIn(username: "u", password: "p")
        #expect(coordinator.phase == .signedIn)

        sequencer.enqueue(status: 403, body: Data())
        await coordinator.reloadInventory()
        #expect(coordinator.phase == .signedIn, "403 must not log the operator out")
        #expect(coordinator.inventory.isEmpty, "denied data is not shown")
        #expect(coordinator.session != nil)
    }

}

/// Counting transport for "request must not be sent" assertions.
final class CountingTransport: HTTPTransport, @unchecked Sendable {
    struct Item {
        var status: Int
        var body: Data
    }

    private let lock = NSLock()
    private var items: [Item] = []
    private var count = 0

    var requestCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    func enqueue(status: Int, body: Data) {
        lock.lock()
        items.append(Item(status: status, body: body))
        lock.unlock()
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        let item: Item? = lock.withLock {
            count += 1
            guard !items.isEmpty else { return nil }
            return items.removeFirst()
        }
        guard let item else {
            throw HelicoidError.unreachable
        }
        if item.body.count > maxBytes {
            throw HelicoidError.invalidInput(field: "response", detail: "Response body exceeded the bounded size limit.")
        }
        let url = request.url ?? URL(string: "https://server.test:8443/")!
        let response = HTTPURLResponse(
            url: url,
            statusCode: item.status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        return (item.body, response)
    }
}
