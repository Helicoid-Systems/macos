import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore
@testable import HelicoidManager

/// Actual ManagerSession facade: automatic expiry must update screen/phase/
/// overview without a user action or coordinator helper call.
@Suite("ManagerSession automatic expiry")
@MainActor
struct ManagerSessionExpiryTests {
    // MARK: - Test clock (test target only)

    final class Clock: SessionTimeSource, @unchecked Sendable {
        private let lock = NSLock()
        private var _wall: Int
        private var _mono: UInt64
        private var nextWaiter: UInt64 = 0
        private var waiters: [UInt64: (deadline: UInt64, continuation: CheckedContinuation<Void, Error>)] = [:]
        private var cancelledBeforeRegister: Set<UInt64> = []

        init(wallUnix: Int = 1_760_000_000, monotonicNanos: UInt64 = 1_000_000_000) {
            _wall = wallUnix
            _mono = monotonicNanos
        }

        var wallUnix: Int {
            lock.lock()
            defer { lock.unlock() }
            return _wall
        }

        var monotonicNanos: UInt64 {
            lock.lock()
            defer { lock.unlock() }
            return _mono
        }

        func advanceMonotonic(seconds: Int) {
            lock.lock()
            _mono &+= UInt64(seconds) &* 1_000_000_000
            _wall &+= seconds
            let due = waiters.filter { $0.value.deadline <= _mono }
            for (id, waiter) in due {
                waiters.removeValue(forKey: id)
                waiter.continuation.resume()
            }
            lock.unlock()
        }

        func sleepUntil(monotonicNanos deadline: UInt64) async throws {
            try Task.checkCancellation()
            let id: UInt64 = lock.withLock {
                nextWaiter &+= 1
                return nextWaiter
            }
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    lock.lock()
                    if cancelledBeforeRegister.contains(id) {
                        cancelledBeforeRegister.remove(id)
                        lock.unlock()
                        continuation.resume(throwing: CancellationError())
                        return
                    }
                    if _mono >= deadline {
                        lock.unlock()
                        continuation.resume()
                        return
                    }
                    waiters[id] = (deadline, continuation)
                    lock.unlock()
                }
            } onCancel: {
                lock.lock()
                if let waiter = waiters.removeValue(forKey: id) {
                    lock.unlock()
                    waiter.continuation.resume(throwing: CancellationError())
                } else {
                    cancelledBeforeRegister.insert(id)
                    lock.unlock()
                }
            }
        }
    }

    final class Transport: HTTPTransport, @unchecked Sendable {
        struct Item {
            var status: Int
            var body: Data
        }

        private let lock = NSLock()
        private var items: [Item] = []

        func enqueue(status: Int, body: Data) {
            lock.lock()
            items.append(Item(status: status, body: body))
            lock.unlock()
        }

        func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
            let item: Item? = lock.withLock {
                guard !items.isEmpty else { return nil }
                return items.removeFirst()
            }
            guard let item else { throw HelicoidError.unreachable }
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

    // MARK: - Fixtures

    private func makeIdentity() throws -> ManagerSigningIdentity {
        try ManagerSigningIdentity(storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation)
    }

    /// Test-only CA fixture (allowed in tests, never normal operation).
    private static let testCADERHex = "3082019030820135a00302010202142f2d30f1e37fdf3db4f30d8fdf8728741175b71b300a06082a8648ce3d04030230153113301106035504030c0a48532d546573742d4341301e170d3236313031363135333434365a170d3336313031333135333434365a30153113301106035504030c0a48532d546573742d43413059301306072a8648ce3d020106082a8648ce3d030107034200045dda8b60404df01b54df24ff5be48548d57ee450d0d34016a3f917e964d4258ea20c94821c4d8fde270f7370d403b1b6d4a00d8be30ddd2c9c4ff7f96e108830a3633061301d0603551d0e04160414110d92f6818de0787dcf793d09154c449fcd5a33301f0603551d23041830168014110d92f6818de0787dcf793d09154c449fcd5a33300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020204300a06082a8648ce3d040302034900304602210090e960a7cbc20680e19c9af2859397890b074166c6da5d571f5f71577f80e60f022100f60d9460317df7434ac3f97ff9d9ebff66e8024063b6d6ead5ed477383301443"

    private func makeAuthority() async throws -> DeploymentTLSIdentity {
        var bytes = Data()
        var idx = Self.testCADERHex.startIndex
        while idx < Self.testCADERHex.endIndex {
            let next = Self.testCADERHex.index(idx, offsetBy: 2)
            bytes.append(UInt8(Self.testCADERHex[idx..<next], radix: 16)!)
            idx = next
        }
        let fingerprint = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        return try DeploymentTLSIdentity(
            deploymentID: "deploy-1",
            host: "server.test",
            port: 8443,
            caDER: bytes,
            caFingerprintSHA256: fingerprint
        )
    }
    private func json(_ object: [String: Any]) -> Data {
        // swiftlint:disable:next force_try
        try! JSONSerialization.data(withJSONObject: object)
    }

    private func healthJSON() -> Data {
        json([
            "status": "ok",
            "accepting_authorized_operations": true,
            "schema_version": 2,
            "bootstrap_completed": true,
            "features": [String: Bool](),
        ])
    }

    private func beginJSON(key: String, wall: Int) -> Data {
        json([
            "challenge_id": "ch-1",
            "challenge_token": "tok-1",
            "operation": "session",
            "manager_public_key": key,
            "deployment_id": "deploy-1",
            "expires_at_unix": wall + 60,
            "mfa_required": false,
        ])
    }

    private func loginJSON(key: String, wall: Int, expiresAtUnix: Int) -> Data {
        json([
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
                "public_identity": "key:\(key)",
                "lifecycle_state": "approved",
            ] as [String: Any],
            "mfa": [
                "required": false,
                "available": false,
                "reason": "none",
            ] as [String: Any],
            "manager_public_key": key,
        ])
    }

    private func inventoryJSON() -> Data {
        json([
            "computers": [[
                "id": "c1",
                "public_identity": "p1",
                "enrollment_state": "enrolled",
            ] as [String: Any]],
        ])
    }

    // MARK: - Tests

    @Test("Idle clock expiry clears actual ManagerSession facade without user action")
    func managerSessionExpiryClearsFacade() async throws {
        let clock = Clock()
        let transport = Transport()
        let identity = try makeIdentity()
        let authority = try await makeAuthority()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: authority,
            signingIdentity: identity,
            timeSource: clock
        )
        let session = ManagerSession(
            configuration: ManagerLaunchConfiguration(),
            productionAuthClient: client
        )

        // connect: pinned health + configured trust identity
        transport.enqueue(status: 200, body: healthJSON())
        session.serverAddress = "https://server.test:8443"
        await session.connect()
        #expect(session.screen == .signIn)

        // optional MFA sign-in → inventory
        transport.enqueue(status: 201, body: beginJSON(key: key, wall: clock.wallUnix))
        transport.enqueue(status: 200, body: loginJSON(key: key, wall: clock.wallUnix, expiresAtUnix: clock.wallUnix + 3600))
        transport.enqueue(status: 200, body: inventoryJSON())
        session.username = "operator"
        session.password = "pw"
        await session.signIn()
        #expect(session.screen == .computers)
        #expect(session.phase == .signedIn)
        #expect(!session.overview.authorizedInventory.isEmpty)

        // Automatic expiry — no reloadSignIn/cancel/helper call.
        clock.advanceMonotonic(seconds: 3601)
        try await Task.sleep(nanoseconds: 30_000_000)

        #expect(session.screen == .signIn, "facade must show sign-in after idle expiry")
        #expect(session.phase == .needsSignIn)
        #expect(session.overview.authorizedInventory.isEmpty, "overview inventory must clear")
        #expect(session.openRemoteWindows.isEmpty)
        if case .sessionExpired = session.signInError {} else {
            Issue.record("expected sessionExpired copy, got \(String(describing: session.signInError))")
        }
    }

    @Test("Replacement after expiry can sign in again (fenced)")
    func managerSessionCanSignInAfterExpiry() async throws {
        let clock = Clock()
        let transport = Transport()
        let identity = try makeIdentity()
        let authority = try await makeAuthority()
        let key = AuthV2Canonical.lowercaseHex(identity.publicKey)
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: authority,
            signingIdentity: identity,
            timeSource: clock
        )
        let session = ManagerSession(
            configuration: ManagerLaunchConfiguration(),
            productionAuthClient: client
        )
        transport.enqueue(status: 200, body: healthJSON())
        session.serverAddress = "https://server.test:8443"
        await session.connect()

        transport.enqueue(status: 201, body: beginJSON(key: key, wall: clock.wallUnix))
        transport.enqueue(status: 200, body: loginJSON(key: key, wall: clock.wallUnix, expiresAtUnix: clock.wallUnix + 3600))
        transport.enqueue(status: 200, body: inventoryJSON())
        session.username = "operator"
        session.password = "pw"
        await session.signIn()
        #expect(session.phase == .signedIn)

        clock.advanceMonotonic(seconds: 3601)
        try await Task.sleep(nanoseconds: 30_000_000)
        #expect(session.phase == .needsSignIn)

        // Fresh sign-in after expiry
        transport.enqueue(status: 201, body: beginJSON(key: key, wall: clock.wallUnix))
        transport.enqueue(status: 200, body: loginJSON(key: key, wall: clock.wallUnix, expiresAtUnix: clock.wallUnix + 3600))
        transport.enqueue(status: 200, body: inventoryJSON())
        session.password = "pw"
        await session.signIn()
        #expect(session.phase == .signedIn)
        #expect(session.screen == .computers)
        #expect(!session.overview.authorizedInventory.isEmpty)
    }
}
