import CryptoKit
import Foundation
@testable import HelicoidCore

/// TEST-ONLY disposable PKI + HTTPS server harness.
///
/// Generates genuine CA/server certificates with the installed `openssl`,
/// then serves HTTPS from a disposable `python3` process. Nothing here is
/// used by normal app operation. Certificates are created under a unique
/// temporary directory and deleted when the harness is torn down.
///
/// Process ownership is bounded: termination observation is installed
/// before launch, teardown never blocks on an unbounded `waitUntilExit`,
/// and only the harness-owned child PID is force-killed after a graceful
/// SIGTERM window. Pipes and temp fixtures are disposed on every path.
enum TLSTestHarness {
    enum HarnessError: Error, CustomStringConvertible {
        case toolMissing(String)
        case commandFailed(String, Int32, String)
        case timeout(String)
        case malformed(String)
        case teardownFailed(String)

        var description: String {
            switch self {
            case .toolMissing(let name): "Required tool not found: \(name)"
            case .commandFailed(let cmd, let code, let stderr): "Command failed (\(code)): \(cmd)\n\(stderr)"
            case .timeout(let what): "Timed out waiting for \(what)"
            case .malformed(let detail): "Malformed harness output: \(detail)"
            case .teardownFailed(let detail): "Teardown failed: \(detail)"
            }
        }
    }

    // MARK: - Fixture concurrency bound

    /// Serializes `openssl` fixture generation across tests. Parallel RSA
    /// keygen starves unrelated timing assertions in the full suite.
    private static let generationLock = NSLock()

    /// Material-only CA/leaf bytes generated once per process. Constructor
    /// tests never need live files or a server, so the on-disk PKI is deleted
    /// immediately after extraction.
    struct MaterialPKI: Sendable {
        let caDER: Data
        let caFingerprint: String
        let leafDER: Data
        let noKeySignCADER: Data
    }

    // Guarded by materialLock.
    nonisolated(unsafe) private static var cachedMaterial: MaterialPKI?
    private static let materialLock = NSLock()

    /// Shared CA material for constructor/policy tests. Generates once.
    static func sharedMaterial() throws -> MaterialPKI {
        materialLock.lock()
        defer { materialLock.unlock() }
        if let cachedMaterial {
            return cachedMaterial
        }
        let pki = try makePKI()
        let material = MaterialPKI(
            caDER: pki.caDER,
            caFingerprint: pki.caFingerprint,
            leafDER: pki.goodLeafDER,
            noKeySignCADER: pki.noKeySignCADER
        )
        try? FileManager.default.removeItem(at: pki.directory)
        cachedMaterial = material
        return material
    }

    // MARK: - PKI

    struct PKI {
        let directory: URL
        let caDER: Data
        let caFingerprint: String
        /// Server cert/key valid for 127.0.0.1 + localhost, signed by `ca`.
        let goodCertPEM: URL
        let goodKeyPEM: URL
        /// DER of the good server (leaf) certificate — not a CA.
        let goodLeafDER: Data
        /// Unrelated CA + server cert (platform-trusted if installed, but not pinned).
        let foreignCertPEM: URL
        let foreignKeyPEM: URL
        /// Same CA, expired server cert.
        let expiredCertPEM: URL
        let expiredKeyPEM: URL
        /// Same CA, clientAuth EKU only (not serverAuth).
        let nonServerAuthCertPEM: URL
        let nonServerAuthKeyPEM: URL
        /// Same CA, wrong DNS name.
        let wrongHostCertPEM: URL
        let wrongHostKeyPEM: URL
        /// CA:TRUE but keyUsage without keyCertSign — invalid signing CA.
        let noKeySignCADER: Data

        var caFingerprintSHA256: String { caFingerprint }

        /// Delete owned temp fixture. Safe to call once; repeated calls are no-ops.
        func disposeFiles() {
            try? FileManager.default.removeItem(at: directory)
        }
    }

    /// Generate a disposable PKI under a unique temp directory.
    /// Serialized: concurrent RSA keygen overloads the full suite.
    static func makePKI() throws -> PKI {
        generationLock.lock()
        defer { generationLock.unlock() }
        return try makePKIUnlocked()
    }

    private static func makePKIUnlocked() throws -> PKI {
        try ensureTool("openssl")
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("helicoid-tls-fixture-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        do {
            return try generatePKI(directory: directory)
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    private static func generatePKI(directory: URL) throws -> PKI {
        let caKey = directory.appendingPathComponent("ca.key")
        let caCrt = directory.appendingPathComponent("ca.crt")
        let caDer = directory.appendingPathComponent("ca.der")

        try openssl([
            "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", caKey.path, "-out", caCrt.path,
            "-days", "365", "-nodes",
            "-subj", "/CN=Helicoid Disposable Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ])

        try openssl([
            "x509", "-in", caCrt.path, "-outform", "DER", "-out", caDer.path,
        ])

        // Foreign CA (independent root).
        let foreignCAKey = directory.appendingPathComponent("foreign-ca.key")
        let foreignCACrt = directory.appendingPathComponent("foreign-ca.crt")
        try openssl([
            "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", foreignCAKey.path, "-out", foreignCACrt.path,
            "-days", "365", "-nodes",
            "-subj", "/CN=Helicoid Foreign Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ])

        func signedServer(
            name: String,
            caCrt: String,
            caKey: String,
            subject: String,
            ext: String,
            notBefore: String? = nil,
            notAfter: String? = nil
        ) throws -> (cert: URL, key: URL) {
            let key = directory.appendingPathComponent("\(name).key")
            let csr = directory.appendingPathComponent("\(name).csr")
            let crt = directory.appendingPathComponent("\(name).crt")
            let extFile = directory.appendingPathComponent("\(name).ext")
            try ext.write(to: extFile, atomically: true, encoding: .utf8)
            try openssl([
                "req", "-newkey", "rsa:2048",
                "-keyout", key.path, "-out", csr.path,
                "-nodes", "-subj", subject,
            ])
            var args = [
                "x509", "-req", "-in", csr.path,
                "-CA", caCrt, "-CAkey", caKey, "-CAcreateserial",
                "-out", crt.path, "-extfile", extFile.path,
            ]
            if let notBefore, let notAfter {
                args += ["-not_before", notBefore, "-not_after", notAfter]
            } else {
                args += ["-days", "365"]
            }
            try openssl(args)
            return (crt, key)
        }

        let good = try signedServer(
            name: "server",
            caCrt: caCrt.path,
            caKey: caKey.path,
            subject: "/CN=127.0.0.1",
            ext: """
            basicConstraints=CA:FALSE
            keyUsage=digitalSignature,keyEncipherment
            extendedKeyUsage=serverAuth
            subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:server.test
            """
        )

        let foreign = try signedServer(
            name: "foreign-server",
            caCrt: foreignCACrt.path,
            caKey: foreignCAKey.path,
            subject: "/CN=127.0.0.1",
            ext: """
            basicConstraints=CA:FALSE
            keyUsage=digitalSignature,keyEncipherment
            extendedKeyUsage=serverAuth
            subjectAltName=IP:127.0.0.1,DNS:localhost
            """
        )

        let expired = try signedServer(
            name: "expired-server",
            caCrt: caCrt.path,
            caKey: caKey.path,
            subject: "/CN=127.0.0.1",
            ext: """
            basicConstraints=CA:FALSE
            keyUsage=digitalSignature,keyEncipherment
            extendedKeyUsage=serverAuth
            subjectAltName=IP:127.0.0.1,DNS:localhost
            """,
            notBefore: "20200101000000Z",
            notAfter: "20200102000000Z"
        )

        let nonServerAuth = try signedServer(
            name: "clientauth-server",
            caCrt: caCrt.path,
            caKey: caKey.path,
            subject: "/CN=127.0.0.1",
            ext: """
            basicConstraints=CA:FALSE
            keyUsage=digitalSignature,keyEncipherment
            extendedKeyUsage=clientAuth
            subjectAltName=IP:127.0.0.1,DNS:localhost
            """
        )

        let wrongHost = try signedServer(
            name: "wronghost-server",
            caCrt: caCrt.path,
            caKey: caKey.path,
            subject: "/CN=wrong.example",
            ext: """
            basicConstraints=CA:FALSE
            keyUsage=digitalSignature,keyEncipherment
            extendedKeyUsage=serverAuth
            subjectAltName=DNS:wrong.example
            """
        )

        // CA:TRUE with digitalSignature only (no keyCertSign) — invalid as an anchor.
        let noKeySignCAKey = directory.appendingPathComponent("nokeysign-ca.key")
        let noKeySignCACrt = directory.appendingPathComponent("nokeysign-ca.crt")
        let noKeySignCADERURL = directory.appendingPathComponent("nokeysign-ca.der")
        try openssl([
            "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", noKeySignCAKey.path, "-out", noKeySignCACrt.path,
            "-days", "365", "-nodes",
            "-subj", "/CN=Helicoid NoKeySign CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,digitalSignature",
        ])
        try openssl([
            "x509", "-in", noKeySignCACrt.path, "-outform", "DER", "-out", noKeySignCADERURL.path,
        ])
        let noKeySignDER = try Data(contentsOf: noKeySignCADERURL)

        let der = try Data(contentsOf: caDer)
        let leafDER = try pemToDER(good.cert)
        return PKI(
            directory: directory,
            caDER: der,
            caFingerprint: DeploymentTLSIdentity.sha256Hex(der),
            goodCertPEM: good.cert,
            goodKeyPEM: good.key,
            goodLeafDER: leafDER,
            foreignCertPEM: foreign.cert,
            foreignKeyPEM: foreign.key,
            expiredCertPEM: expired.cert,
            expiredKeyPEM: expired.key,
            nonServerAuthCertPEM: nonServerAuth.cert,
            nonServerAuthKeyPEM: nonServerAuth.key,
            wrongHostCertPEM: wrongHost.cert,
            wrongHostKeyPEM: wrongHost.key,
            noKeySignCADER: noKeySignDER
        )
    }

    /// Convert a PEM certificate file to DER bytes.
    static func pemToDER(_ pemURL: URL) throws -> Data {
        let pem = try String(contentsOf: pemURL, encoding: .utf8)
        let b64 = pem
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .components(separatedBy: .whitespacesAndNewlines)
            .joined()
        guard let der = Data(base64Encoded: b64), !der.isEmpty else {
            throw HarnessError.malformed("PEM at \(pemURL.path) did not decode to DER")
        }
        return der
    }

    // MARK: - Bounded owned child process

    /// Non-consumable exit latch owned by `OwnedChild`'s termination handler.
    private final class ExitLatch: @unchecked Sendable {
        private let lock = NSLock()
        private var exited = false

        func markExited() {
            lock.lock()
            exited = true
            lock.unlock()
        }

        var hasExited: Bool {
            lock.lock()
            defer { lock.unlock() }
            return exited
        }
    }

    /// TEST-ONLY owned child with bounded startup and teardown.
    ///
    /// Termination observation is installed before launch. `stop()` never
    /// blocks on an unbounded `waitUntilExit`. After a graceful SIGTERM
    /// window only this process's own PID is force-killed. Pipes are closed
    /// and readability handlers detached on dispose.
    ///
    /// Exit observation is non-consumable: `waitUntil` cannot eat a
    /// termination signal out from under a later `stop()`. `isRunning == false`
    /// is terminal success at entry and after any bounded observation window.
    final class OwnedChild: @unchecked Sendable {
        private let process = Process()
        private let stdout: Pipe
        private let stderr: Pipe
        private let exitLatch = ExitLatch()
        private let bufferLock = NSLock()
        private var stdoutBuffer = Data()
        private var stderrBuffer = Data()
        private var stopped = false

        init(stdout: Pipe, stderr: Pipe) {
            self.stdout = stdout
            self.stderr = stderr
            // Observe termination BEFORE launch so exit can never be missed.
            let latch = exitLatch
            process.terminationHandler = { _ in
                latch.markExited()
            }
        }

        var isRunning: Bool { process.isRunning }
        var pid: pid_t { process.processIdentifier }

        /// True when the child is known dead (`isRunning == false`) or the
        /// termination latch fired. Terminal — not consumable.
        private var isTerminated: Bool {
            !process.isRunning || exitLatch.hasExited
        }

        /// Termination status once the child has exited; nil while still running.
        var terminationStatus: Int32? {
            process.isRunning ? nil : process.terminationStatus
        }

        func configure(
            executable: URL,
            arguments: [String],
            currentDirectory: URL? = nil
        ) {
            process.executableURL = executable
            process.arguments = arguments
            if let currentDirectory {
                process.currentDirectoryURL = currentDirectory
            }
            process.standardOutput = stdout
            process.standardError = stderr
        }

        /// Launch. Throws on startup failure within a bounded window.
        func launch() throws {
            do {
                try process.run()
            } catch {
                detachPipes()
                throw HarnessError.commandFailed(
                    "launch \(process.executableURL?.path ?? "?")",
                    -1,
                    String(describing: error)
                )
            }
            // Drain pipes on background reads so children never block on a full pipe.
            stdout.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let chunk = handle.availableData
                guard let self else { return }
                if chunk.isEmpty {
                    handle.readabilityHandler = nil
                    return
                }
                self.bufferLock.lock()
                self.stdoutBuffer.append(chunk)
                self.bufferLock.unlock()
            }
            stderr.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let chunk = handle.availableData
                guard let self else { return }
                if chunk.isEmpty {
                    handle.readabilityHandler = nil
                    return
                }
                self.bufferLock.lock()
                self.stderrBuffer.append(chunk)
                self.bufferLock.unlock()
            }
        }

        func takeStdout() -> Data {
            bufferLock.lock()
            defer { bufferLock.unlock() }
            return stdoutBuffer
        }

        func takeStderr() -> Data {
            bufferLock.lock()
            defer { bufferLock.unlock() }
            return stderrBuffer
        }

        /// Wait until `deadline` for `predicate` over the stdout buffer.
        /// Never blocks past the deadline. Returns false on timeout.
        /// Does not consume termination state.
        func waitUntil(
            timeout: TimeInterval,
            predicate: (Data) -> Bool
        ) -> Bool {
            let deadline = Date().addingTimeInterval(timeout)
            while Date() < deadline {
                if predicate(takeStdout()) {
                    return true
                }
                if isTerminated {
                    // Child is gone; one final predicate check on remaining buffer.
                    return predicate(takeStdout())
                }
                Thread.sleep(forTimeInterval: 0.05)
            }
            return predicate(takeStdout())
        }

        /// Bounded teardown. Graceful SIGTERM, then SIGKILL of owned PID only.
        /// Unexpected survivors are reported as `teardownFailed` — not
        /// disguised as best-effort reaping.
        func stop(
            gracefulTimeout: TimeInterval = 2.0,
            forceTimeout: TimeInterval = 1.0
        ) throws {
            bufferLock.lock()
            let alreadyStopped = stopped
            stopped = true
            bufferLock.unlock()
            if alreadyStopped {
                return
            }

            defer { detachPipes() }

            // Terminal success at entry: already dead children are never signaled.
            if isTerminated {
                return
            }

            process.terminate()
            if waitForExit(gracefulTimeout) {
                return
            }

            // Recheck immediately before SIGKILL. Never signal an exited child.
            guard !isTerminated else {
                return
            }
            // Owned child PID only — captured for the diagnostic message.
            let ownedPID = process.processIdentifier
            if ownedPID > 0 {
                kill(ownedPID, SIGKILL)
            }
            if waitForExit(forceTimeout) {
                return
            }

            throw HarnessError.teardownFailed(
                "owned child pid=\(ownedPID) still running after SIGTERM+\(gracefulTimeout)s and SIGKILL+\(forceTimeout)s"
            )
        }

        /// Bounded wait for termination. `isRunning == false` (or the exit
        /// latch) is terminal success at entry and after the observation
        /// window — never depends on a consumable signal.
        private func waitForExit(_ timeout: TimeInterval) -> Bool {
            if isTerminated {
                return true
            }
            let deadline = Date().addingTimeInterval(timeout)
            while Date() < deadline {
                if isTerminated {
                    return true
                }
                Thread.sleep(forTimeInterval: 0.01)
            }
            return isTerminated
        }

        private func detachPipes() {
            stdout.fileHandleForReading.readabilityHandler = nil
            stderr.fileHandleForReading.readabilityHandler = nil
            // Close owned descriptors; ignore already-closed.
            try? stdout.fileHandleForReading.close()
            try? stderr.fileHandleForReading.close()
            try? stdout.fileHandleForWriting.close()
            try? stderr.fileHandleForWriting.close()
        }
    }

    // MARK: - HTTPS server

    final class Server {
        private let child: OwnedChild
        let port: Int
        let baseURL: URL

        init(child: OwnedChild, port: Int) {
            self.child = child
            self.port = port
            self.baseURL = URL(string: "https://127.0.0.1:\(port)/")!
        }

        /// Bounded teardown of the owned server process. Throws on unexpected
        /// teardown failure so tests can record it — not silently ignored.
        func stop() throws {
            try child.stop()
        }

        deinit {
            // Last-resort bounded stop if a call site forgot. Never unbounded.
            try? child.stop()
        }
    }

    /// Start a disposable HTTPS server on 127.0.0.1 with an ephemeral port.
    /// Startup readiness is bounded; launch failure tears the child down.
    static func startServer(cert: URL, key: URL) throws -> Server {
        try ensureTool("python3")
        let script = try writeServerScript()
        let child = OwnedChild(stdout: Pipe(), stderr: Pipe())
        child.configure(
            executable: URL(fileURLWithPath: "/usr/bin/env"),
            arguments: ["python3", script.path, cert.path, key.path, "127.0.0.1", "0"],
            currentDirectory: cert.deletingLastPathComponent()
        )
        try child.launch()

        let ready = try waitForReady(child: child, timeout: 15)
        return Server(child: child, port: ready)
    }

    /// Run `body` with a live server and exclusive fixture ownership.
    ///
    /// Server, pipes, and temp PKI files are disposed on success, error, and
    /// cancellation. No fire-and-forget teardown.
    static func withServer<T: Sendable>(
        cert: (PKI) -> URL = { $0.goodCertPEM },
        key: (PKI) -> URL = { $0.goodKeyPEM },
        body: @Sendable (PKI, Server) async throws -> T
    ) async throws -> T {
        let pki = try makePKI()
        let server: Server
        do {
            server = try startServer(cert: cert(pki), key: key(pki))
        } catch {
            pki.disposeFiles()
            throw error
        }
        do {
            let value = try await body(pki, server)
            try server.stop()
            pki.disposeFiles()
            return value
        } catch {
            // Always tear down owned process + fixture on error/cancel.
            try? server.stop()
            pki.disposeFiles()
            throw error
        }
    }

    // MARK: - Internals

    /// Wait for a short-lived helper to exit within `timeout`. Reaps via
    /// bounded stop (never unbounded `waitUntilExit`). Returns exit status
    /// or throws `timeout` / `teardownFailed`.
    private static func awaitExit(_ child: OwnedChild, timeout: TimeInterval) throws -> Int32 {
        let deadline = Date().addingTimeInterval(timeout)
        while child.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        if child.isRunning {
            // Bound the kill path too — never wait forever.
            try child.stop(gracefulTimeout: 0.5, forceTimeout: 0.5)
            throw HarnessError.timeout("child exit within \(timeout)s")
        }
        try child.stop(gracefulTimeout: 0.5, forceTimeout: 0.5)
        return child.terminationStatus ?? -1
    }

    private static func ensureTool(_ name: String) throws {
        let child = OwnedChild(stdout: Pipe(), stderr: Pipe())
        child.configure(
            executable: URL(fileURLWithPath: "/usr/bin/env"),
            arguments: ["which", name]
        )
        try child.launch()
        let status = try awaitExit(child, timeout: 5.0)
        let output = String(data: child.takeStdout(), encoding: .utf8) ?? ""
        if status != 0 || output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw HarnessError.toolMissing(name)
        }
    }

    private static func openssl(_ arguments: [String]) throws {
        let child = OwnedChild(stdout: Pipe(), stderr: Pipe())
        child.configure(
            executable: URL(fileURLWithPath: "/usr/bin/env"),
            arguments: ["openssl"] + arguments
        )
        try child.launch()
        let status = try awaitExit(child, timeout: 60.0)
        let errText = String(data: child.takeStderr(), encoding: .utf8) ?? ""
        if status != 0 {
            throw HarnessError.commandFailed(
                "openssl \(arguments.joined(separator: " "))",
                status,
                errText
            )
        }
    }

    private static func waitForReady(child: OwnedChild, timeout: TimeInterval) throws -> Int {
        var readyPort: Int?
        let sawReady = child.waitUntil(timeout: timeout) { data in
            guard let text = String(data: data, encoding: .utf8),
                  let range = text.range(of: "READY ") else {
                return false
            }
            let rest = text[range.upperBound...]
            let portString = rest.prefix(while: { $0.isNumber })
            if let port = Int(portString), port > 0 {
                readyPort = port
                return true
            }
            return false
        }
        if let readyPort, sawReady {
            return readyPort
        }
        if !child.isRunning {
            let err = String(data: child.takeStderr(), encoding: .utf8) ?? ""
            try? child.stop(gracefulTimeout: 0.5, forceTimeout: 0.5)
            throw HarnessError.commandFailed("python3 tls server", -1, err)
        }
        try? child.stop(gracefulTimeout: 0.5, forceTimeout: 0.5)
        throw HarnessError.timeout("TLS server READY")
    }

    /// Disposable Python HTTPS helper. TEST-ONLY.
    private static func writeServerScript() throws -> URL {
        let script = """
        import http.server, json, ssl, sys, time

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                return

            def _send(self, status, body, extra_headers=None, chunked=False):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                if chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                else:
                    self.send_header("Content-Length", str(len(body)))
                if extra_headers:
                    for k, v in extra_headers:
                        self.send_header(k, v)
                self.end_headers()
                if chunked:
                    for i in range(0, len(body), 1024):
                        chunk = body[i:i+1024]
                        self.wfile.write(f"{len(chunk):x}\\r\\n".encode() + chunk + b"\\r\\n")
                    self.wfile.write(b"0\\r\\n\\r\\n")
                else:
                    self.wfile.write(body)

            def do_GET(self):
                path = self.path.split("?", 1)[0]
                if path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "https://127.0.0.1:1/steal")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if path == "/redirect-same":
                    self.send_response(302)
                    self.send_header("Location", "/ok")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if path == "/large":
                    body = b"x" * (2 * 1024 * 1024)
                    self._send(200, body)
                    return
                if path == "/chunked-large":
                    body = b"y" * (256 * 1024)
                    self._send(200, body, chunked=True)
                    return
                if path == "/declared-large":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(2 * 1024 * 1024))
                    self.end_headers()
                    self.wfile.write(b"z" * (2 * 1024 * 1024))
                    return
                if path == "/overflow-stall":
                    # Exceed a small cap, then stall. Proves prompt cancel of the
                    # actual URLSessionDataTask and owned-operation drain.
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(2 * 1024 * 1024))
                    self.end_headers()
                    self.wfile.write(b"x" * (128 * 1024))
                    self.wfile.flush()
                    time.sleep(30)
                    self.wfile.write(b"x" * (1024 * 1024))
                    return
                if path == "/slow":
                    time.sleep(30)
                    self._send(200, b'{"late": true}')
                    return
                if path == "/status/500":
                    self._send(500, b'{"error": {"code": "internal", "message": "boom"}}')
                    return
                if path == "/status/403":
                    self._send(403, b'{"error": {"code": "forbidden", "message": "no"}}')
                    return
                if path == "/status/404":
                    self._send(404, b'{"error": {"code": "not_found", "message": "missing"}}')
                    return
                self._send(200, json.dumps({"status": "ok", "path": self.path}).encode())

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or 0)
                self.rfile.read(length)
                self._send(201, b'{"ok": true}')

        if __name__ == "__main__":
            certfile, keyfile, host, port = sys.argv[1:5]
            server = http.server.HTTPServer((host, int(port)), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certfile, keyfile)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            print(f"READY {server.server_address[1]}", flush=True)
            server.serve_forever()
        """
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("helicoid-tls-server-\(UUID().uuidString).py")
        try script.write(to: url, atomically: true, encoding: .utf8)
        return url
    }
}
