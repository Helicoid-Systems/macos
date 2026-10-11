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

// MARK: - Duplicate-extension regression

/// DER certificate extension inspection for fixture regression.
///
/// Parses the Certificate extensions sequence directly so a duplicate
/// extension OID (the `errSecCertificateDuplicateExtension` / -67903 cause)
/// is visible as raw OIDs, not as openssl `-text` prose. Non-secret: only
/// OID strings and boolean constraint bits are exposed.
enum FixtureDER {
    static let basicConstraintsOID = "2.5.29.19"
    static let keyUsageOID = "2.5.29.15"
    static let extendedKeyUsageOID = "2.5.29.37"
    static let subjectAltNameOID = "2.5.29.17"

    struct Extension {
        let oid: String
        let critical: Bool
        /// Raw extnValue OCTET STRING contents (DER of the extension payload).
        let value: [UInt8]
    }

    /// Parse Certificate extensions from DER bytes.
    static func extensions(fromDER der: Data) throws -> [Extension] {
        let bytes = [UInt8](der)
        var i = 0
        let cert = try readTLV(bytes, &i)
        guard cert.tag == 0x30 else { throw ParseError.badTag("certificate", cert.tag) }
        var j = 0
        let tbs = try readTLV(cert.body, &j)
        guard tbs.tag == 0x30 else { throw ParseError.badTag("tbs", tbs.tag) }

        var k = 0
        // optional [0] version
        if tbs.body[k] == 0xa0 {
            _ = try readTLV(tbs.body, &k)
        }
        // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
        for _ in 0..<6 {
            _ = try readTLV(tbs.body, &k)
        }
        // optional issuerUniqueID [1], subjectUniqueID [2], extensions [3]
        while k < tbs.body.count {
            let item = try readTLV(tbs.body, &k)
            guard item.tag == 0xa3 else { continue }
            var m = 0
            let seq = try readTLV(item.body, &m)
            guard seq.tag == 0x30 else { throw ParseError.badTag("extensions", seq.tag) }
            var result: [Extension] = []
            var n = 0
            while n < seq.body.count {
                let ext = try readTLV(seq.body, &n)
                guard ext.tag == 0x30 else { throw ParseError.badTag("extension", ext.tag) }
                var p = 0
                let oidTLV = try readTLV(ext.body, &p)
                let oid = parseOID(oidTLV.body)
                var critical = false
                if p < ext.body.count, ext.body[p] == 0x01 {
                    let boolTLV = try readTLV(ext.body, &p)
                    critical = !boolTLV.body.isEmpty && boolTLV.body[0] != 0
                }
                let valueTLV = try readTLV(ext.body, &p)
                result.append(Extension(oid: oid, critical: critical, value: valueTLV.body))
            }
            return result
        }
        return []
    }

    /// Count of each extension OID in DER.
    static func oidCounts(fromDER der: Data) throws -> [String: Int] {
        var counts: [String: Int] = [:]
        for ext in try extensions(fromDER: der) {
            counts[ext.oid, default: 0] += 1
        }
        return counts
    }

    /// True when `basicConstraints` decodes with CA:TRUE.
    static func isCA(der: Data) throws -> Bool {
        for ext in try extensions(fromDER: der) where ext.oid == basicConstraintsOID {
            // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
            var i = 0
            let seq = try readTLV(ext.value, &i)
            guard seq.tag == 0x30 else { return false }
            var j = 0
            if j < seq.body.count, seq.body[j] == 0x01 {
                let b = try readTLV(seq.body, &j)
                return !b.body.isEmpty && b.body[0] != 0
            }
            return false
        }
        return false
    }

    /// True when `keyUsage` bit 5 (keyCertSign) is set.
    static func hasKeyCertSign(der: Data) throws -> Bool {
        for ext in try extensions(fromDER: der) where ext.oid == keyUsageOID {
            // ext.value is the OCTET STRING payload = DER of KeyUsage BIT STRING.
            var i = 0
            let bitString = try readTLV(ext.value, &i)
            guard bitString.tag == 0x03, bitString.body.count > 1 else { return false }
            // body = unused-bits, then bit bytes. Bit 5 is 0b0000_0100 of the first bit byte.
            let bits = bitString.body[1]
            return (bits & 0b0000_0100) != 0
        }
        return false
    }

    enum ParseError: Error, CustomStringConvertible {
        case truncated
        case badTag(String, UInt8)

        var description: String {
            switch self {
            case .truncated: "DER truncated"
            case .badTag(let what, let tag): "Unexpected tag in \(what): 0x\(String(tag, radix: 16))"
            }
        }
    }

    private struct TLV {
        let tag: UInt8
        let body: [UInt8]
    }

    private static func readTLV(_ data: [UInt8], _ i: inout Int) throws -> TLV {
        guard i < data.count else { throw ParseError.truncated }
        let tag = data[i]
        i += 1
        guard i < data.count else { throw ParseError.truncated }
        var length = Int(data[i])
        i += 1
        if length & 0x80 != 0 {
            let n = length & 0x7f
            guard n > 0, i + n <= data.count else { throw ParseError.truncated }
            length = 0
            for _ in 0..<n {
                length = (length << 8) | Int(data[i])
                i += 1
            }
        }
        guard i + length <= data.count else { throw ParseError.truncated }
        let body = Array(data[i..<(i + length)])
        i += length
        return TLV(tag: tag, body: body)
    }

    private static func parseOID(_ bytes: [UInt8]) -> String {
        guard !bytes.isEmpty else { return "" }
        let first = Int(bytes[0])
        var parts = [String(first / 40), String(first % 40)]
        var value = 0
        for b in bytes.dropFirst() {
            value = (value << 7) | Int(b & 0x7f)
            if b & 0x80 == 0 {
                parts.append(String(value))
                value = 0
            }
        }
        return parts.joined(separator: ".")
    }
}

/// Regression: every fixture certificate must contain each intended
/// extension OID exactly once. Duplicate OIDs make native SecTrust return
/// `errSecCertificateDuplicateExtension` (-67903) and refuse evaluation.
@Suite("TLS fixture extension uniqueness")
struct TLSTestHarnessExtensionTests {

    private func expectUniqueExtensions(der: Data, label: String) throws {
        let counts = try FixtureDER.oidCounts(fromDER: der)
        for (oid, count) in counts.sorted(by: { $0.key < $1.key }) {
            #expect(count == 1, "\(label): extension \(oid) occurs \(count) times (must be 1)")
        }
    }

    @Test("PKI roots and leaves carry each extension OID at most once")
    func pkiExtensionsAreUnique() throws {
        let pki = try TLSTestHarness.makePKI()
        defer { pki.disposeFiles() }

        try expectUniqueExtensions(der: pki.caDER, label: "ca")
        try expectUniqueExtensions(der: pki.noKeySignCADER, label: "nokeysign-ca")
        try expectUniqueExtensions(der: pki.goodLeafDER, label: "good-leaf")

        let foreignDER = try TLSTestHarness.pemToDER(pki.foreignCertPEM)
        try expectUniqueExtensions(der: foreignDER, label: "foreign-leaf")
        let expiredDER = try TLSTestHarness.pemToDER(pki.expiredCertPEM)
        try expectUniqueExtensions(der: expiredDER, label: "expired-leaf")
        let nonServerDER = try TLSTestHarness.pemToDER(pki.nonServerAuthCertPEM)
        try expectUniqueExtensions(der: nonServerDER, label: "clientauth-leaf")
        let wrongHostDER = try TLSTestHarness.pemToDER(pki.wrongHostCertPEM)
        try expectUniqueExtensions(der: wrongHostDER, label: "wronghost-leaf")
    }

    @Test("Positive CA has exactly one basicConstraints and one keyUsage with CA:TRUE and keyCertSign")
    func positiveCARootConstraints() throws {
        let pki = try TLSTestHarness.makePKI()
        defer { pki.disposeFiles() }

        let counts = try FixtureDER.oidCounts(fromDER: pki.caDER)
        #expect(counts[FixtureDER.basicConstraintsOID] == 1, "CA must have exactly one basicConstraints")
        #expect(counts[FixtureDER.keyUsageOID] == 1, "CA must have exactly one keyUsage")
        #expect(try FixtureDER.isCA(der: pki.caDER), "CA basicConstraints must be CA:TRUE")
        #expect(try FixtureDER.hasKeyCertSign(der: pki.caDER), "CA keyUsage must include keyCertSign")
    }

    @Test("NoKeySign root keeps CA:TRUE without keyCertSign")
    func noKeySignRootKeepsNegativeShape() throws {
        let pki = try TLSTestHarness.makePKI()
        defer { pki.disposeFiles() }

        let counts = try FixtureDER.oidCounts(fromDER: pki.noKeySignCADER)
        #expect(counts[FixtureDER.basicConstraintsOID] == 1)
        #expect(counts[FixtureDER.keyUsageOID] == 1)
        #expect(try FixtureDER.isCA(der: pki.noKeySignCADER))
        #expect(try FixtureDER.hasKeyCertSign(der: pki.noKeySignCADER) == false,
                "nokeysign root must not claim keyCertSign")
    }

    @Test("LibreSSL self-sign path emits unique extension OIDs")
    func libresslSelfSignUniqueExtensions() throws {
        let libreSSLPath = "/usr/bin/openssl"
        guard FileManager.default.isExecutableFile(atPath: libreSSLPath) else {
            return
        }
        // Confirm the binary is present; generation uses the same owned
        // self-sign config as makePKI so ambient defaults cannot inject OIDs.
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("helicoid-tls-libressl-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let config = directory.appendingPathComponent("selfsign.cnf")
        try TLSTestHarness.ownedSelfSignConfig(
            commonName: "Helicoid Disposable Test CA",
            extensions: """
            basicConstraints=critical,CA:TRUE
            keyUsage=critical,keyCertSign,cRLSign
            """
        ).write(to: config, atomically: true, encoding: .utf8)

        let key = directory.appendingPathComponent("ca.key")
        let crt = directory.appendingPathComponent("ca.crt")

        let child = TLSTestHarness.OwnedChild()
        child.configure(
            executable: URL(fileURLWithPath: libreSSLPath),
            arguments: [
                "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key.path, "-out", crt.path,
                "-days", "365", "-nodes",
                "-config", config.path,
            ]
        )
        try child.launch()
        let deadline = Date().addingTimeInterval(60)
        while child.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if child.isRunning {
            try child.stop(gracefulTimeout: 0.5, forceTimeout: 0.5)
            Issue.record("LibreSSL self-sign did not exit within 60s")
            return
        }
        try child.stop(gracefulTimeout: 0.5, forceTimeout: 0.5)
        #expect(child.terminationStatus == 0, "LibreSSL self-sign failed: \(child.failureDiagnostics())")

        let der = try TLSTestHarness.pemToDER(crt)
        try expectUniqueExtensions(der: der, label: "libressl-ca")

        let counts = try FixtureDER.oidCounts(fromDER: der)
        #expect(counts[FixtureDER.basicConstraintsOID] == 1, "LibreSSL CA must have exactly one basicConstraints")
        #expect(counts[FixtureDER.keyUsageOID] == 1, "LibreSSL CA must have exactly one keyUsage")
        #expect(try FixtureDER.isCA(der: der))
        #expect(try FixtureDER.hasKeyCertSign(der: der))
    }
}
