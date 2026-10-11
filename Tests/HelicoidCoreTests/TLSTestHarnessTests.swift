import Foundation
import Testing
@testable import HelicoidCore

/// Regression coverage for the owned-fd process-output seam.
///
/// These tests drive a real `python3` child with controlled output. They never
/// mock `Process` or file handles, and never reimplement the harness pump —
/// they exercise `TLSTestHarness.OwnedChild` and `startServer` directly.
@Suite("TLS harness owned child output seam")
struct TLSTestHarnessTests {

    /// Newline READY must arrive while the owned child is still running and
    /// has not hit EOF, then teardown must complete within a bounded window.
    @Test("READY arrives while owned child is still running and has not hit EOF")
    func readyWhileChildRunningWithoutEOF() throws {
        let child = TLSTestHarness.OwnedChild()
        child.configure(
            executable: URL(fileURLWithPath: "/usr/bin/env"),
            arguments: [
                "python3",
                "-c",
                "import time; print('READY 4242', flush=True); time.sleep(30)",
            ]
        )
        try child.launch()
        defer {
            do { try child.stop() }
            catch { Issue.record("Unexpected owned-child teardown failure: \(error)") }
        }

        var seenPort: Int?
        let sawReady = child.waitUntil(timeout: 5) { data in
            guard let text = String(data: data, encoding: .utf8),
                  let range = text.range(of: "READY ") else {
                return false
            }
            let digits = text[range.upperBound...].prefix(while: { $0.isNumber })
            if let port = Int(digits), port > 0 {
                seenPort = port
                return true
            }
            return false
        }

        #expect(sawReady)
        #expect(seenPort == 4242)
        // READY was observed without consuming the child's lifetime: the
        // process is still up and stdout has not reached EOF.
        #expect(child.isRunning)
        #expect(!child.hasSeenStdoutEOF)

        // Bounded cleanup of the still-running owned child.
        let started = Date()
        try child.stop()
        #expect(!child.isRunning)
        #expect(Date().timeIntervalSince(started) < 5)
    }

    /// Startup failure through the real harness entry point must carry bounded
    /// child stderr so a native CI timeout is diagnosable from the error text.
    @Test("Startup failure surfaces bounded child stderr")
    func startupFailureSurfacesStderr() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("helicoid-tls-startup-fail-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let cert = directory.appendingPathComponent("server.crt")
        let key = directory.appendingPathComponent("server.key")
        try Data("not-a-cert".utf8).write(to: cert)
        try Data("not-a-key".utf8).write(to: key)

        do {
            let server = try TLSTestHarness.startServer(cert: cert, key: key)
            defer { try? server.stop() }
            Issue.record("startServer unexpectedly succeeded with invalid fixtures")
        } catch {
            let text = String(describing: error)
            #expect(text.contains("stderr="))
            // python's ssl.load_cert_chain reports an SSL/PEM failure on stderr.
            #expect(text.contains("SSL") || text.contains("PEM") || text.contains("ssl"))
        }
    }
}
