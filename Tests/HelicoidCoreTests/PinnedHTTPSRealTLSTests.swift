import Foundation
import Testing
@testable import HelicoidCore

/// Actual native URLSession HTTPS against disposable generated CA/server certs.
///
/// Each test opens a real TLS socket to a python HTTPS helper. No fabricated
/// SecTrust or response statuses. TEST-ONLY fixtures never enter app operation.
///
/// Serialized: parallel TLS fixture/server startup overloads the full suite
/// (RSA keygen + python servers starve unrelated timing assertions). The
/// concurrent-dispose test still races actual requests internally.
@Suite("Pinned HTTPS real TLS sockets", .serialized)
struct PinnedHTTPSRealTLSTests {

    private func makeIdentity(
        pki: TLSTestHarness.PKI,
        host: String = "127.0.0.1",
        port: Int,
        caDER: Data? = nil,
        fingerprint: String? = nil
    ) throws -> DeploymentTLSIdentity {
        try DeploymentTLSIdentity(
            deploymentID: "tls-deploy-test",
            host: host,
            port: port,
            caDER: caDER ?? pki.caDER,
            caFingerprintSHA256: fingerprint ?? pki.caFingerprint
        )
    }

    private func makeTransport(
        identity: DeploymentTLSIdentity,
        requestTimeout: TimeInterval = 5,
        operationTimeout: TimeInterval = 8,
        maxResponseBytes: Int = PinnedHTTPSConfiguration.defaultMaxResponseBytes
    ) throws -> PinnedHTTPSTransport {
        try PinnedHTTPSTransport(
            configuration: PinnedHTTPSConfiguration(
                identity: identity,
                requestTimeout: requestTimeout,
                operationTimeout: operationTimeout,
                maxResponseBytes: maxResponseBytes
            )
        )
    }

    // MARK: - Positive

    @Test("Positive pinned CA completes a real TLS GET")
    func positivePinnedCA() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)
        defer { transport.dispose() }

        let response = try await transport.request(method: "GET", path: "/ok")
        #expect(response.statusCode == 200)
        #expect(!response.body.isEmpty)
        let json = try JSONSerialization.jsonObject(with: response.body) as? [String: Any]
        #expect(json?["status"] as? String == "ok")
        // Successful pinned evaluation must be visible to tests as accepted.
        let diagnostic = transport.lastTrustDiagnostic
        #expect(diagnostic?.decision == .accepted)
        #expect(diagnostic?.step == "evaluate")
    }

    @Test("Positive pinned CA completes a real TLS POST")
    func positivePost() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)
        defer { transport.dispose() }

        let response = try await transport.request(
            method: "POST",
            path: "/echo",
            headers: ["Content-Type": "application/json"],
            body: Data(#"{"a":1}"#.utf8)
        )
        #expect(response.statusCode == 201)
    }

    // MARK: - Pin / chain rejections

    @Test("Foreign CA is refused even though the socket is valid TLS")
    func foreignCARefused() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.foreignCertPEM, key: pki.foreignKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        // Pin the good CA, but the server presents the foreign CA chain.
        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)
        defer { transport.dispose() }

        do {
            _ = try await transport.request(method: "GET", path: "/ok")
            Issue.record("Foreign CA must be refused")
        } catch let error as HelicoidError {
            // Trust failure must never succeed, and must not collapse into a
            // bare task-cancellation mask (that made negative checks vacuous
            // while every positive request was cancelled).
            if error == .cancelled {
                Issue.record("Foreign CA refusal must not surface as task cancellation: \(error)")
            }
            if case .invalidInput(let field, _) = error, field != "server_trust" {
                Issue.record("Foreign CA refusal should carry server_trust diagnostics, got field=\(field)")
            }
        } catch {
            // Non-Helicoid errors are still refusals; never success.
        }
    }

    /// Trust refusals must carry a bounded native diagnostic, not a bare
    /// `.cancelled` mask. This is the seam that makes a native first-positive
    /// failure actionable (decision step + CFError codes, no PKI contents).
    @Test("Foreign CA refusal exposes trust diagnostic instead of bare cancellation")
    func foreignCATrustDiagnostic() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.foreignCertPEM, key: pki.foreignKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)
        defer { transport.dispose() }

        do {
            _ = try await transport.request(method: "GET", path: "/ok")
            Issue.record("Foreign CA must be refused")
        } catch let error as HelicoidError {
            #expect(error != .cancelled)
            if case .invalidInput(let field, let detail) = error {
                #expect(field == "server_trust")
                #expect(detail.contains("decision="))
                #expect(detail.contains("step="))
                #expect(detail.contains("certs="))
                #expect(!detail.contains("BEGIN CERTIFICATE"))
            }
            let diagnostic = transport.lastTrustDiagnostic
            #expect(diagnostic != nil)
            #expect(diagnostic?.decision != .accepted)
            #expect(diagnostic?.certificateCount ?? 0 > 0)
        } catch {
            Issue.record("Foreign CA refusal must throw HelicoidError, got \(error)")
        }
    }

    /// Smoke only: two `PinnedHTTPSTransport`s also mean two delegates, so this
    /// cannot prove shared-delegate sink ownership. Retained as a real-socket
    /// concurrency smoke. See `sharedDelegateKeepsSinksIsolated` for the
    /// single-delegate regression.
    @Test("Concurrent trust refusal and user cancellation stay task-owned")
    func concurrentTrustRefusalAndUserCancellationAreIsolated() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }

        let refusedServer = try TLSTestHarness.startServer(cert: pki.foreignCertPEM, key: pki.foreignKeyPEM)
        defer {
            do { try refusedServer.stop() }
            catch { Issue.record("Unexpected refused-server teardown failure: \(error)") }
        }
        let goodServer = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try goodServer.stop() }
            catch { Issue.record("Unexpected good-server teardown failure: \(error)") }
        }

        // Owner A: foreign chain pinned to the good CA — trust refusal.
        let refusedIdentity = try makeIdentity(pki: pki, port: refusedServer.port)
        let refusedTransport = try makeTransport(identity: refusedIdentity, requestTimeout: 20, operationTimeout: 20)
        defer { refusedTransport.dispose() }

        // Owner B: valid chain, cancelled by the caller mid-flight.
        let goodIdentity = try makeIdentity(pki: pki, port: goodServer.port)
        let goodTransport = try makeTransport(identity: goodIdentity, requestTimeout: 20, operationTimeout: 20)
        defer { goodTransport.dispose() }

        async let refusedResult: Result<Void, any Error> = {
            do {
                _ = try await refusedTransport.request(method: "GET", path: "/ok")
                return .success(())
            } catch {
                return .failure(error)
            }
        }()

        async let cancelledResult: Result<Void, any Error> = {
            let task = Task {
                try await goodTransport.request(method: "GET", path: "/slow")
            }
            try await Task.sleep(nanoseconds: 200_000_000)
            task.cancel()
            do {
                _ = try await task.value
                return .success(())
            } catch {
                return .failure(error)
            }
        }()

        let (refused, cancelled) = try await (refusedResult, cancelledResult)

        switch refused {
        case .success:
            Issue.record("Foreign CA owner must not succeed")
        case .failure(let error):
            guard let helicoid = error as? HelicoidError else {
                Issue.record("Foreign CA owner must throw HelicoidError, got \(error)")
                break
            }
            #expect(helicoid != .cancelled)
            if case .invalidInput(let field, let detail) = helicoid {
                #expect(field == "server_trust")
                #expect(detail.contains("decision="))
                #expect(!detail.contains("BEGIN CERTIFICATE"))
            } else {
                Issue.record("Foreign CA owner should get server_trust diagnostics, got \(error)")
            }
            #expect(refusedTransport.lastTrustDiagnostic?.decision != .accepted)
        }

        switch cancelled {
        case .success:
            Issue.record("Cancelled owner must not succeed")
        case .failure(let error):
            // User cancel may surface as Swift `CancellationError` (structured
            // concurrency) or `HelicoidError.cancelled` (URLSession mapping).
            // Anything else — including a leaked server_trust — is a failure.
            if error is CancellationError {
                break
            }
            guard let helicoid = error as? HelicoidError else {
                Issue.record("Cancelled owner must throw HelicoidError/CancellationError, got \(error)")
                break
            }
            #expect(helicoid == .cancelled)
            if case .invalidInput(let field, _) = helicoid, field == "server_trust" {
                Issue.record("Cancelled owner inherited another task's trust refusal: \(error)")
            }
        }
    }

    /// Shared-delegate regression: TWO BodySinks on ONE `PinnedTrustDelegate`.
    /// Two transports would hide a per-delegate broadcast bug. Real generated
    /// certs, real TLS, genuine native ServerTrust challenges (captured and
    /// replayed for the late-challenge case). Owner A = foreign chain refusal;
    /// owner B = user cancellation; late challenge for retired A must not
    /// touch B. Each challenge's completion runs exactly once; both sinks drain.
    @Test("Shared PinnedTrustDelegate keeps task sinks isolated")
    func sharedDelegateKeepsSinksIsolated() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }

        let foreignServer = try TLSTestHarness.startServer(cert: pki.foreignCertPEM, key: pki.foreignKeyPEM)
        defer {
            do { try foreignServer.stop() }
            catch { Issue.record("Unexpected foreign-server teardown failure: \(error)") }
        }
        let goodServer = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try goodServer.stop() }
            catch { Issue.record("Unexpected good-server teardown failure: \(error)") }
        }

        // One shared production trust delegate for both owners.
        let pinned = PinnedTrustDelegate(
            caDER: pki.caDER,
            caFingerprintSHA256: pki.caFingerprint,
            expectedHost: "127.0.0.1"
        )
        let forwarder = ChallengeCapturingForwarder(pinned: pinned)
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 15
        config.httpShouldSetCookies = false
        config.urlCache = nil
        let session = URLSession(configuration: config, delegate: forwarder, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        // Owner A — foreign chain on the shared delegate.
        let sinkA = BodySink(maxBytes: 65_536)
        let taskA = session.dataTask(with: URL(string: "https://127.0.0.1:\(foreignServer.port)/ok")!)
        sinkA.bindDataTask(taskA)
        pinned.registerSink(sinkA, taskID: taskA.taskIdentifier)

        // Owner B — good chain, stalled response, still live during late challenge.
        let sinkB = BodySink(maxBytes: 65_536)
        let taskB = session.dataTask(with: URL(string: "https://127.0.0.1:\(goodServer.port)/slow")!)
        sinkB.bindDataTask(taskB)
        pinned.registerSink(sinkB, taskID: taskB.taskIdentifier)

        taskA.resume()
        taskB.resume()

        // A: genuine ServerTrust refusal on the shared delegate.
        do {
            _ = try await sinkA.result()
            Issue.record("Foreign owner A must not succeed")
        } catch let error as HelicoidError {
            guard case .invalidInput(let field, let detail) = error else {
                Issue.record("Owner A should get server_trust diagnostics, got \(error)")
                throw error
            }
            #expect(field == "server_trust")
            #expect(detail.contains("decision="))
            #expect(detail.contains("step="))
            #expect(!detail.contains("BEGIN CERTIFICATE"))
        } catch {
            Issue.record("Owner A must throw HelicoidError, got \(error)")
            throw error
        }

        // Production unregisters A on completion; make retirement explicit and
        // deterministic before the late challenge.
        pinned.unregisterSink(taskID: taskA.taskIdentifier)

        // Late challenge for retired owner A using the genuine captured
        // ServerTrust challenge and the actual task A object.
        guard let lateChallenge = forwarder.takeServerTrustChallenge(taskID: taskA.taskIdentifier) else {
            Issue.record("Expected a captured genuine ServerTrust challenge for owner A")
            return
        }
        #expect(lateChallenge.protectionSpace.port == foreignServer.port)
        let completions = ChallengeCompletionCounter()
        pinned.urlSession(
            session,
            task: taskA,
            didReceive: lateChallenge,
            completionHandler: completions.wrap()
        )
        // Exactly once per challenge — never zero, never double-complete.
        #expect(completions.count == 1)
        #expect(pinned.lastTrustDiagnostic?.decision == .refusedEvaluate)

        // Owner B is still registered and must be unaffected by the late write.
        // User cancellation stays `.cancelled`, never A's server_trust refusal.
        taskB.cancel()
        do {
            _ = try await sinkB.result()
            Issue.record("Cancelled owner B must not succeed")
        } catch let error as HelicoidError {
            #expect(error == .cancelled)
            if case .invalidInput(let field, _) = error, field == "server_trust" {
                Issue.record("Late challenge for retired A contaminated B: \(error)")
            }
        } catch {
            Issue.record("Owner B must throw HelicoidError, got \(error)")
        }

    }

    @Test("Bad pin is refused before any successful request")
    func badPinRefused() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let wrongPin = String(repeating: "a", count: 64)
        // Identity constructor validates pin against DER — a mismatched pin is rejected at init.
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(
                deploymentID: "tls-deploy-test",
                host: "127.0.0.1",
                port: server.port,
                caDER: pki.caDER,
                caFingerprintSHA256: wrongPin
            )
        }
    }

    @Test("Wrong DNS name cert is refused")
    func wrongDNSNameRefused() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.wrongHostCertPEM, key: pki.wrongHostKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        // Server cert is only valid for wrong.example; we connect as 127.0.0.1.
        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)
        defer { transport.dispose() }

        do {
            _ = try await transport.request(method: "GET", path: "/ok")
            Issue.record("Wrong DNS name must be refused")
        } catch let error as HelicoidError {
            if error == .cancelled {
                Issue.record("Wrong DNS name refusal must not surface as task cancellation: \(error)")
            }
        } catch {
            // expected
        }
    }

    @Test("Expired server cert is refused")
    func expiredCertRefused() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.expiredCertPEM, key: pki.expiredKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)
        defer { transport.dispose() }

        do {
            _ = try await transport.request(method: "GET", path: "/ok")
            Issue.record("Expired cert must be refused")
        } catch let error as HelicoidError {
            if error == .cancelled {
                Issue.record("Expired cert refusal must not surface as task cancellation: \(error)")
            }
        } catch {
            // expected
        }
    }

    @Test("Non-serverAuth EKU cert is refused")
    func nonServerAuthRefused() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.nonServerAuthCertPEM, key: pki.nonServerAuthKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)
        defer { transport.dispose() }

        do {
            _ = try await transport.request(method: "GET", path: "/ok")
            Issue.record("clientAuth-only cert must be refused")
        } catch let error as HelicoidError {
            if error == .cancelled {
                Issue.record("clientAuth-only refusal must not surface as task cancellation: \(error)")
            }
        } catch {
            // expected
        }
    }

    // MARK: - Origin / redirects

    @Test("HTTPS origin mismatch is refused before I/O")
    func originMismatchRefused() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)
        defer { transport.dispose() }

        for path in ["https://evil.example/steal", "//evil.example/steal", "/../etc/passwd"] {
            do {
                _ = try await transport.request(method: "GET", path: path)
                Issue.record("Origin mismatch must be refused: \(path)")
            } catch let error as HelicoidError {
                if case .invalidInput = error {
                    // expected refusal
                } else {
                    Issue.record("Expected invalidInput for \(path), got \(error)")
                }
            }
        }
    }

    @Test("Redirects are never followed (absolute and same-origin)")
    func redirectsNotFollowed() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)
        defer { transport.dispose() }

        // 302 is non-2xx and must be refused (and the Location not followed).
        for path in ["/redirect", "/redirect-same"] {
            do {
                _ = try await transport.request(method: "GET", path: path)
                Issue.record("Redirect must not succeed: \(path)")
            } catch is HelicoidError {
                // expected
            }
        }
    }

    // MARK: - Bounds

    @Test("Oversized declared Content-Length is refused")
    func oversizedDeclaredRefused() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity, maxResponseBytes: 65_536)
        defer { transport.dispose() }

        do {
            _ = try await transport.request(method: "GET", path: "/declared-large")
            Issue.record("Declared oversized body must be refused")
        } catch let error as HelicoidError {
            #expect(error == .invalidInput(field: "response", detail: "Response body exceeded the bounded size limit."))
        }
    }

    @Test("Oversized chunked/streamed body is refused")
    func oversizedChunkedRefused() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity, maxResponseBytes: 65_536)
        defer { transport.dispose() }

        do {
            _ = try await transport.request(method: "GET", path: "/large")
            Issue.record("Streamed oversized body must be refused")
        } catch let error as HelicoidError {
            #expect(error == .invalidInput(field: "response", detail: "Response body exceeded the bounded size limit."))
        }

        do {
            _ = try await transport.request(method: "GET", path: "/chunked-large")
            Issue.record("Chunked oversized body must be refused")
        } catch let error as HelicoidError {
            #expect(error == .invalidInput(field: "response", detail: "Response body exceeded the bounded size limit."))
        }
    }

    @Test("Non-2xx responses are refused")
    func non2xxRefused() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)
        defer { transport.dispose() }

        do {
            _ = try await transport.request(method: "GET", path: "/status/500")
            Issue.record("500 must be refused")
        } catch is HelicoidError {
            // expected
        }
        do {
            _ = try await transport.request(method: "GET", path: "/status/404")
            Issue.record("404 must be refused")
        } catch is HelicoidError {
            // expected
        }
    }

    // MARK: - Cancellation / timeout / disposal

    @Test("Per-operation deadline covers a hung response")
    func timeoutRefused() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity, requestTimeout: 2, operationTimeout: 2)
        defer { transport.dispose() }

        do {
            _ = try await transport.request(method: "GET", path: "/slow")
            Issue.record("Hung request must hit the deadline")
        } catch {
            // expected
        }
    }

    @Test("Task cancellation aborts an in-flight request")
    func cancellationAborts() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity, requestTimeout: 20, operationTimeout: 20)
        defer { transport.dispose() }

        let task = Task {
            try await transport.request(method: "GET", path: "/slow")
        }
        try await Task.sleep(nanoseconds: 200_000_000)
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Cancelled task must not succeed")
        } catch {
            // CancellationError or HelicoidError.unreachable/cancelled — any failure is correct.
        }
    }

    @Test("Disposal makes subsequent requests fail closed")
    func disposalFailsClosed() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)

        // Confirm it works first.
        let before = try await transport.request(method: "GET", path: "/ok")
        #expect(before.statusCode == 200)

        transport.dispose()
        do {
            _ = try await transport.request(method: "GET", path: "/ok")
            Issue.record("Disposed transport must fail closed")
        } catch {
            // expected
        }
    }

    // MARK: - bytes() entry point (status/redirect before body)

    @Test("bytes() entry point refuses non-2xx and redirects before returning a body")
    func bytesEntryPointRefusesNon2xxAndRedirect() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity)
        defer { transport.dispose() }

        for path in ["/status/403", "/status/500", "/redirect", "/redirect-same"] {
            var request = URLRequest(url: URL(string: path, relativeTo: transport.originURL)!.absoluteURL)
            request.httpMethod = "GET"
            do {
                let (data, _) = try await transport.bytes(for: request, maxBytes: transport.maxResponseBytes)
                Issue.record("bytes() must refuse \(path); got \(data.count) bytes")
            } catch let error as HelicoidError {
                if case .invalidInput(let field, _) = error {
                    #expect(field == "response")
                } else {
                    Issue.record("Expected invalidInput(response) for \(path), got \(error)")
                }
            }
        }
    }

    @Test("bytes() enforces the configured body cap, not only request()")
    func bytesEnforcesConfiguredCap() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity, maxResponseBytes: 65_536)
        defer { transport.dispose() }

        var request = URLRequest(url: URL(string: "/large", relativeTo: transport.originURL)!.absoluteURL)
        request.httpMethod = "GET"
        // Caller asks for a larger cap; configured cap must still win.
        do {
            _ = try await transport.bytes(for: request, maxBytes: 2_000_000)
            Issue.record("bytes() must enforce configured cap")
        } catch let error as HelicoidError {
            #expect(error == .invalidInput(field: "response", detail: "Response body exceeded the bounded size limit."))
        }
    }

    // MARK: - Concurrent startup vs dispose (no fatal exception)

    @Test("Concurrent request startup and dispose never crashes the process")
    func concurrentDisposeStress() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)

        // Repeat to widen the registration-vs-invalidate window.
        for round in 0..<8 {
            let transport = try makeTransport(
                identity: identity,
                requestTimeout: 2,
                operationTimeout: 2
            )
            let request = Task { () -> Bool in
                do {
                    _ = try await transport.request(method: "GET", path: "/ok")
                    return true
                } catch {
                    return false
                }
            }
            let request2 = Task { () -> Bool in
                do {
                    _ = try await transport.request(method: "GET", path: "/ok")
                    return true
                } catch {
                    return false
                }
            }
            // Dispose while requests are starting / in flight.
            if round % 2 == 0 {
                try await Task.sleep(nanoseconds: 1_000_000)
            }
            transport.dispose()
            _ = await request.value
            _ = await request2.value
            // A disposed transport must refuse later work without crashing.
            do {
                _ = try await transport.request(method: "GET", path: "/ok")
                Issue.record("Post-dispose request must fail closed (round \(round))")
            } catch {
                // expected
            }
        }
    }

    // MARK: - Measured cancellation / deadline / drain seams

    @Test("Task cancellation completes in under 3s despite 8s+ timeouts")
    func cancellationUnderThreeSeconds() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity, requestTimeout: 15, operationTimeout: 15)
        defer { transport.dispose() }

        let clock = ContinuousClock()
        let start = clock.now
        let task = Task {
            try await transport.request(method: "GET", path: "/slow")
        }
        try await Task.sleep(nanoseconds: 150_000_000)
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Cancelled request must not succeed")
        } catch {
            // Must fail by cancellation/deadline — and promptly.
        }
        let elapsed = start.duration(to: clock.now)
        #expect(elapsed < .seconds(3), "cancellation took \(elapsed), expected <3s")
    }

    @Test("Operation deadline 1s fires while request timeout is 15s on a slow body")
    func operationDeadlineBeatsRequestTimeout() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity, requestTimeout: 15, operationTimeout: 1)
        defer { transport.dispose() }

        let clock = ContinuousClock()
        let start = clock.now
        do {
            _ = try await transport.request(method: "GET", path: "/slow")
            Issue.record("Slow body must hit the 1s operation deadline")
        } catch {
            // expected
        }
        let elapsed = start.duration(to: clock.now)
        #expect(elapsed < .seconds(3), "operation deadline took \(elapsed), expected <3s")
    }

    @Test("Disposal of an in-flight request drains promptly and releases active count")
    func disposalDrainsPromptly() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try makeTransport(identity: identity, requestTimeout: 15, operationTimeout: 15)

        let clock = ContinuousClock()
        let start = clock.now
        let task = Task {
            try await transport.request(method: "GET", path: "/slow")
        }
        try await Task.sleep(nanoseconds: 100_000_000)
        transport.dispose()
        do {
            _ = try await task.value
            Issue.record("Disposed in-flight request must not succeed")
        } catch {
            // expected
        }
        let elapsed = start.duration(to: clock.now)
        #expect(elapsed < .seconds(3), "disposal drain took \(elapsed), expected <3s")
        #expect(transport.activeOperationCount == 0)
        #expect(transport.isDisposed)
    }

    // MARK: - Overflow then stall (prompt task cancel, bounded buffer)

    @Test("Overflow then stall cancels the owned URLSessionTask promptly")
    func overflowThenStallStopsPromptly() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { pki.disposeFiles() }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        // Cap well below the 128 KiB burst the /overflow-stall route writes
        // before sleeping 30s. Must fail fast and drain — not wait out the stall.
        let transport = try makeTransport(identity: identity, maxResponseBytes: 4096)
        defer { transport.dispose() }

        let clock = ContinuousClock()
        let start = clock.now
        do {
            _ = try await transport.request(method: "GET", path: "/overflow-stall")
            Issue.record("Overflowing stalled body must be refused")
        } catch let error as HelicoidError {
            #expect(error == .invalidInput(field: "response", detail: "Response body exceeded the bounded size limit."))
        }
        let elapsed = start.duration(to: clock.now)
        #expect(elapsed < .seconds(3), "overflow-stall took \(elapsed), expected prompt cancel <3s")
        #expect(transport.activeOperationCount == 0)
    }

    @Test("BodySink buffer never exceeds the configured limit")
    func bodySinkNeverExceedsCap() async throws {
        let sink = BodySink(maxBytes: 16)
        // Each append is rejected before write when it would overflow.
        sink.append(Data(repeating: 0x61, count: 16))
        #expect(sink.bufferedCount == 16)
        sink.append(Data(repeating: 0x62, count: 1))
        #expect(sink.bufferedCount == 16, "buffer must not grow past maxBytes")
        sink.append(Data(repeating: 0x63, count: 64))
        #expect(sink.bufferedCount == 16)

        let small = BodySink(maxBytes: 8)
        small.append(Data(repeating: 0x64, count: 4))
        #expect(small.bufferedCount == 4)
        small.append(Data(repeating: 0x65, count: 5))
        #expect(small.bufferedCount == 4, "partial overflow chunk must be refused whole")
        do {
            _ = try await small.result()
            Issue.record("Overflow must fail the sink")
        } catch let error as HelicoidError {
            #expect(error == .invalidInput(field: "response", detail: "Response body exceeded the bounded size limit."))
        }
    }
}

// MARK: - Shared-delegate test helpers (TEST-ONLY)

/// Records genuine native ServerTrust challenges then forwards every
/// URLSession callback to the production `PinnedTrustDelegate`. Used so a
/// late challenge can be replayed against a retired owner without inventing
/// a `SecTrust`-bearing `URLProtectionSpace` (no public initializer).
private final class ChallengeCapturingForwarder: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    let pinned: PinnedTrustDelegate
    private let lock = NSLock()
    private var serverTrustChallenges: [Int: URLAuthenticationChallenge] = [:]

    init(pinned: PinnedTrustDelegate) {
        self.pinned = pinned
        super.init()
    }

    func takeServerTrustChallenge(taskID: Int) -> URLAuthenticationChallenge? {
        lock.lock()
        defer { lock.unlock() }
        return serverTrustChallenges.removeValue(forKey: taskID)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            lock.lock()
            serverTrustChallenges[task.taskIdentifier] = challenge
            lock.unlock()
        }
        pinned.urlSession(session, task: task, didReceive: challenge, completionHandler: completionHandler)
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        pinned.urlSession(session, dataTask: dataTask, didReceive: response, completionHandler: completionHandler)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        pinned.urlSession(session, dataTask: dataTask, didReceive: data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        pinned.urlSession(session, task: task, didCompleteWithError: error)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @Sendable (URLRequest?) -> Void
    ) {
        pinned.urlSession(session, task: task, willPerformHTTPRedirection: response, newRequest: request, completionHandler: completionHandler)
    }
}

/// Counts auth-challenge completion invocations (must be exactly once).
private final class ChallengeCompletionCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var invocations = 0

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return invocations
    }

    func wrap() -> (URLSession.AuthChallengeDisposition, URLCredential?) -> Void {
        { [weak self] _, _ in
            guard let self else { return }
            self.lock.lock()
            self.invocations += 1
            self.lock.unlock()
        }
    }
}
