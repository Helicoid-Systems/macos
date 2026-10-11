import Foundation
import Testing
@testable import HelicoidCore

@Suite("Pinned HTTPS completion deadline boundary", .serialized)
struct PinnedHTTPSDeadlineBoundaryTests {
    @Test("A completed real HTTPS request does not wait for its deadline")
    func completedRequestDrainsTimer() async throws {
        // Owned async fixture: server/pipes/temp PKI disposed on success,
        // error, and cancellation. Never fire-and-forget.
        try await TLSTestHarness.withServer { pki, server in
            let identity = try DeploymentTLSIdentity(
                deploymentID: "deadline-test", host: "127.0.0.1", port: server.port,
                caDER: pki.caDER, caFingerprintSHA256: pki.caFingerprint
            )
            let transport = try PinnedHTTPSTransport(configuration: PinnedHTTPSConfiguration(
                identity: identity, requestTimeout: 8, operationTimeout: 8
            ))
            defer { transport.dispose() }
            let clock = ContinuousClock()
            let start = clock.now
            let response = try await transport.request(method: "GET", path: "/ok")
            #expect(response.statusCode == 200)
            #expect(start.duration(to: clock.now) < .seconds(3))
            #expect(transport.activeOperationCount == 0)
        }
    }
}
