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
        let pki = try TLSTestHarness.makePKI()
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
    }

    @Test("Positive pinned CA completes a real TLS POST")
    func positivePost() async throws {
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        } catch {
            // Trust failure must never succeed.
        }
    }

    @Test("Bad pin is refused before any successful request")
    func badPinRefused() async throws {
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        } catch {
            // expected
        }
    }

    @Test("Expired server cert is refused")
    func expiredCertRefused() async throws {
        let pki = try TLSTestHarness.makePKI()
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
        } catch {
            // expected
        }
    }

    @Test("Non-serverAuth EKU cert is refused")
    func nonServerAuthRefused() async throws {
        let pki = try TLSTestHarness.makePKI()
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
        } catch {
            // expected
        }
    }

    // MARK: - Origin / redirects

    @Test("HTTPS origin mismatch is refused before I/O")
    func originMismatchRefused() async throws {
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
        let pki = try TLSTestHarness.makePKI()
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
