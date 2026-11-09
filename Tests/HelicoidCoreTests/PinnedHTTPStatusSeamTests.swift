import Foundation
import Testing
@testable import HelicoidCore

/// Real disposable loopback TLS coverage for the typed-status transport seam
/// used by local bootstrap mutation POSTs. No real server, credentials, or
/// account changes.
@Suite("Pinned HTTPS typed-status seam", .serialized)
struct PinnedHTTPStatusSeamTests {
    private func makeIdentity(
        pki: TLSTestHarness.PKI,
        port: Int
    ) throws -> DeploymentTLSIdentity {
        try DeploymentTLSIdentity(
            deploymentID: "tls-deploy-test",
            host: "127.0.0.1",
            port: port,
            caDER: pki.caDER,
            caFingerprintSHA256: pki.caFingerprint
        )
    }

    private func makeTransport(
        identity: DeploymentTLSIdentity
    ) throws -> PinnedHTTPSTransport {
        try PinnedHTTPSTransport(
            configuration: PinnedHTTPSConfiguration(
                identity: identity,
                requestTimeout: 5,
                operationTimeout: 8,
                maxResponseBytes: PinnedHTTPSConfiguration.defaultMaxResponseBytes
            )
        )
    }

    private func request(
        _ path: String,
        origin: URL
    ) -> URLRequest {
        var request = URLRequest(url: URL(string: path, relativeTo: origin)!.absoluteURL)
        request.httpMethod = "GET"
        return request
    }

    @Test("Typed status returns a bounded non-2xx body")
    func typedStatusReturnsNon2xx() async throws {
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

        let response = try await transport.requestStatus(
            for: request("/status/403", origin: transport.originURL),
            maxBytes: transport.maxResponseBytes
        )
        #expect(response.statusCode == 403)
        #expect(response.url.path == "/status/403")
        #expect(!response.body.isEmpty)
    }

    @Test("Existing bytes and request paths still refuse non-2xx")
    func existingPathsStillRefuseNon2xx() async throws {
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

        for (path, status) in [("/status/403", 403), ("/status/500", 500)] {
            do {
                _ = try await transport.bytes(
                    for: request(path, origin: transport.originURL),
                    maxBytes: transport.maxResponseBytes
                )
                Issue.record("bytes() must still refuse \(path)")
            } catch let error as HelicoidError {
                #expect(error == .invalidInput(
                    field: "response",
                    detail: "Pinned HTTPS transport refused non-2xx status \(status)."
                ))
            }

            do {
                _ = try await transport.request(method: "GET", path: path)
                Issue.record("request() must still refuse \(path)")
            } catch let error as HelicoidError {
                #expect(error == .invalidInput(
                    field: "response",
                    detail: "Pinned HTTPS transport refused non-2xx status \(status)."
                ))
            }
        }
    }

    @Test("Typed status still enforces the configured body cap")
    func typedStatusEnforcesBodyCap() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try makeIdentity(pki: pki, port: server.port)
        let transport = try PinnedHTTPSTransport(
            configuration: PinnedHTTPSConfiguration(
                identity: identity,
                requestTimeout: 5,
                operationTimeout: 8,
                maxResponseBytes: 1_024
            )
        )
        defer { transport.dispose() }

        for path in ["/large", "/status/403-large"] {
            do {
                _ = try await transport.requestStatus(
                    for: request(path, origin: transport.originURL),
                    maxBytes: 2_000_000
                )
                Issue.record("requestStatus() must enforce the configured body cap for \(path)")
            } catch let error as HelicoidError {
                #expect(error == .invalidInput(
                    field: "response",
                    detail: "Response body exceeded the bounded size limit."
                ))
            }
        }
    }

    @Test("Typed status description redacts the body")
    func typedStatusDescriptionRedactsBody() throws {
        let response = PinnedHTTPStatusResponse(
            statusCode: 401,
            body: Data("secret-body-value".utf8),
            url: URL(string: "https://127.0.0.1:8443/v2/mfa/enroll/confirm")!
        )
        for rendered in [
            String(describing: response),
            String(reflecting: response),
        ] {
            #expect(!rendered.contains("secret-body-value"))
            #expect(!rendered.contains("127.0.0.1"))
            #expect(rendered.contains("bodyBytes:"))
        }
    }

    @Test("Typed status refuses redirects before returning a body")
    func typedStatusRefusesRedirects() async throws {
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

        for path in ["/redirect", "/redirect-same"] {
            do {
                _ = try await transport.requestStatus(
                    for: request(path, origin: transport.originURL),
                    maxBytes: transport.maxResponseBytes
                )
                Issue.record("requestStatus() must refuse redirect \(path)")
            } catch let error as HelicoidError {
                #expect(error == .invalidInput(
                    field: "response",
                    detail: "Pinned HTTPS transport refused redirect status 302."
                ))
            }
        }
    }
}
