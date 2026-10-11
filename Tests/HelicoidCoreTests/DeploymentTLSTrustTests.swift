import Foundation
import Testing
@testable import HelicoidCore

@Suite("Deployment TLS trust validation")
struct DeploymentTLSTrustValidationTests {

    private func sampleCA() throws -> (der: Data, fingerprint: String) {
        // Material-only CA bytes, generated once per process. Constructor
        // tests never need live fixture files or a server.
        let material = try TLSTestHarness.sharedMaterial()
        return (material.caDER, material.caFingerprint)
    }

    @Test("Accepts valid identity and matching pin")
    func acceptsValidIdentity() throws {
        let (der, fingerprint) = try sampleCA()
        let identity = try DeploymentTLSIdentity(
            deploymentID: "deploy-1",
            host: "server.test",
            port: 8443,
            caDER: der,
            caFingerprintSHA256: fingerprint
        )
        #expect(identity.deploymentID == "deploy-1")
        #expect(identity.host == "server.test")
        #expect(identity.port == 8443)
        #expect(identity.originURL.absoluteString == "https://server.test:8443/")
        #expect(identity.caFingerprintSHA256 == fingerprint)
    }

    @Test("Rejects empty or oversized deployment id")
    func rejectsDeploymentID() throws {
        let (der, fingerprint) = try sampleCA()
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(deploymentID: "", host: "h", port: 443, caDER: der, caFingerprintSHA256: fingerprint)
        }
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(deploymentID: "   ", host: "h", port: 443, caDER: der, caFingerprintSHA256: fingerprint)
        }
        let long = String(repeating: "a", count: 129)
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(deploymentID: long, host: "h", port: 443, caDER: der, caFingerprintSHA256: fingerprint)
        }
    }

    @Test("Rejects host with scheme, path, credentials, or empty")
    func rejectsHost() throws {
        let (der, fingerprint) = try sampleCA()
        for bad in ["", "https://evil", "evil/path", "evil?x", "evil#f", "user@evil", "  ", " evil", "evil "] {
            #expect(throws: HelicoidError.self) {
                try DeploymentTLSIdentity(deploymentID: "d", host: bad, port: 443, caDER: der, caFingerprintSHA256: fingerprint)
            }
        }
    }

    @Test("Rejects malformed host: percent, brackets, controls, whitespace, oversized")
    func rejectsMalformedHosts() throws {
        let (der, fingerprint) = try sampleCA()
        let oversized = String(repeating: "a", count: 254)
        let longLabel = String(repeating: "a", count: 64) + ".test"
        let control = "ev\u{0000}il"
        let tab = "ev\u{0009}il"
        let badHosts: [String] = [
            "%41.test",           // percent-encoding
            "ho%st",              // percent in host
            "[::1",               // unbalanced bracket
            "::1]",               // unbalanced bracket
            "[abc]",              // brackets without IPv6 colons
            "[[]]",               // nested brackets
            control,              // NUL control
            tab,                  // tab whitespace
            "ev il",              // interior whitespace
            oversized,            // > 253
            longLabel,            // label > 63
            ".leading",           // empty label
            "trailing.",          // empty label
            "a..b",               // empty label
            "-leading.test",      // leading hyphen
            "trailing-.test",     // trailing hyphen
            "a_b.test",           // illegal char
            "a!.test",            // illegal char
        ]
        for bad in badHosts {
            #expect(throws: HelicoidError.self) {
                try DeploymentTLSIdentity(deploymentID: "d", host: bad, port: 443, caDER: der, caFingerprintSHA256: fingerprint)
            }
        }
    }

    @Test("Accepts valid IPv4, IPv6, and DNS hosts with canonical roundtrip")
    func acceptsValidHosts() throws {
        let (der, fingerprint) = try sampleCA()
        let cases: [(String, String)] = [
            ("server.test", "server.test"),
            ("SERVER.Test", "server.test"),
            ("127.0.0.1", "127.0.0.1"),
            ("::1", "::1"),
            ("[::1]", "::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),
        ]
        for (input, expected) in cases {
            let identity = try DeploymentTLSIdentity(
                deploymentID: "d",
                host: input,
                port: 8443,
                caDER: der,
                caFingerprintSHA256: fingerprint
            )
            #expect(identity.host == expected)
            let originHost = identity.originURL.host.map { host -> String in
                var h = host.lowercased()
                if h.hasPrefix("["), h.hasSuffix("]") { h = String(h.dropFirst().dropLast()) }
                return h
            }
            #expect(originHost == expected.lowercased())
            #expect(identity.originURL.port == 8443)
            #expect(identity.originURL.user == nil)
            #expect(identity.originURL.path == "/" || identity.originURL.path.isEmpty)
            // Roundtrip without force-unwrap crash.
            #expect(identity.originURL.absoluteString.hasPrefix("https://"))
        }
    }

    @Test("Rejects port outside 1...65535")
    func rejectsPort() throws {
        let (der, fingerprint) = try sampleCA()
        for bad in [0, -1, 65_536] {
            #expect(throws: HelicoidError.self) {
                try DeploymentTLSIdentity(deploymentID: "d", host: "h", port: bad, caDER: der, caFingerprintSHA256: fingerprint)
            }
        }
    }

    @Test("Rejects empty, oversized, or non-certificate CA DER")
    func rejectsCA() throws {
        let (_, fingerprint) = try sampleCA()
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(deploymentID: "d", host: "h", port: 443, caDER: Data(), caFingerprintSHA256: fingerprint)
        }
        let oversized = Data(repeating: 0x30, count: DeploymentTLSIdentity.maxCADerBytes + 1)
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(deploymentID: "d", host: "h", port: 443, caDER: oversized, caFingerprintSHA256: fingerprint)
        }
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(
                deploymentID: "d", host: "h", port: 443,
                caDER: Data("not-a-certificate".utf8),
                caFingerprintSHA256: fingerprint
            )
        }
    }

    @Test("Rejects pin that does not match CA DER")
    func rejectsBadPin() throws {
        let (der, _) = try sampleCA()
        let wrongPin = String(repeating: "0", count: 64)
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(deploymentID: "d", host: "h", port: 443, caDER: der, caFingerprintSHA256: wrongPin)
        }
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(deploymentID: "d", host: "h", port: 443, caDER: der, caFingerprintSHA256: "abc")
        }
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(
                deploymentID: "d", host: "h", port: 443, caDER: der,
                caFingerprintSHA256: String(repeating: "g", count: 64)
            )
        }
    }

    @Test("Fingerprint is lowercase SHA-256 hex of exact DER")
    func fingerprintMatchesDer() throws {
        let (der, fingerprint) = try sampleCA()
        #expect(fingerprint == DeploymentTLSIdentity.sha256Hex(der))
        #expect(fingerprint.count == 64)
        #expect(fingerprint == fingerprint.lowercased())
    }
}

@Suite("Deployment origin policy")
struct DeploymentOriginPolicyTests {
    private let origin = URL(string: "https://server.test:8443/")!

    private func resolve(_ path: String) -> DeploymentOriginPolicy.Decision {
        DeploymentOriginPolicy.resolve(path: path, origin: origin)
    }

    @Test("Allows root-relative paths on the configured origin")
    func allowsRootRelative() {
        guard case .allowed(let url) = resolve("/health") else {
            Issue.record("expected allow")
            return
        }
        #expect(url.absoluteString.hasPrefix("https://server.test:8443/"))
        #expect(url.path == "/health")

        guard case .allowed(let q) = resolve("/v1/items?page=1") else {
            Issue.record("expected allow with query")
            return
        }
        #expect(q.path == "/v1/items")
        #expect(q.query == "page=1")
    }

    @Test("Refuses empty and fragment")
    func refusesEmptyFragment() {
        #expect(resolve("") == .refused(.empty))
        #expect(resolve("   ") == .refused(.empty))
        #expect(resolve("/health#x") == .refused(.fragmentPresent))
    }

    @Test("Refuses scheme escapes and foreign absolute URIs")
    func refusesSchemeEscapes() {
        #expect(resolve("//evil.example/steal") == .refused(.schemeEscape))
        #expect(resolve("/\\evil.example") == .refused(.schemeEscape))
        #expect(resolve("http://server.test:8443/health") == .refused(.schemeEscape))
        #expect(resolve("https://evil.example/health") == .refused(.absoluteForeignURI))
        #expect(resolve("https://server.test:9999/health") == .refused(.portMismatch))
        #expect(resolve("file:///etc/passwd") == .refused(.schemeEscape))
    }

    @Test("Refuses credentials and traversal")
    func refusesCredentialsTraversal() {
        #expect(resolve("/user:pass@host") == .refused(.credentialsPresent))
        #expect(resolve("https://user:pass@server.test:8443/x") == .refused(.credentialsPresent))
        #expect(resolve("/../etc/passwd") == .refused(.traversal))
        #expect(resolve("/v1/../../etc") == .refused(.traversal))
        #expect(resolve("/v1/./x") == .refused(.traversal))
    }

    @Test("Refuses relative non-root paths")
    func refusesRelative() {
        #expect(resolve("health") == .refused(.absoluteForeignURI))
        #expect(resolve("./health") == .refused(.traversal))
    }

    @Test("Allows same-origin absolute URL")
    func allowsSameOriginAbsolute() {
        guard case .allowed = resolve("https://server.test:8443/v1/ok") else {
            Issue.record("same-origin absolute should allow")
            return
        }
    }

    @Test("Refuses percent-encoded traversal and control characters")
    func refusesEncodedTraversalAndControls() {
        #expect(resolve("/%2e%2e/etc/passwd") == .refused(.percentEncodedTraversal))
        #expect(resolve("/%2E%2E/secret") == .refused(.percentEncodedTraversal))
        #expect(resolve("/v1/%2e%2e/x") == .refused(.percentEncodedTraversal))
        #expect(resolve("/%2f%2fevil") == .refused(.percentEncodedTraversal))
        #expect(resolve("/ok%00") == .refused(.controlCharacter))
        #expect(resolve("/ok\u{0001}") == .refused(.controlCharacter))
    }
}

@Suite("Deployment CA certificate requirements")
struct DeploymentCARequirementsTests {
    @Test("Rejects a leaf certificate used as the deployment CA anchor")
    func rejectsLeafAsAnchor() throws {
        let material = try TLSTestHarness.sharedMaterial()
        let leafDER = material.leafDER
        let leafPin = DeploymentTLSIdentity.sha256Hex(leafDER)
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(
                deploymentID: "d",
                host: "127.0.0.1",
                port: 443,
                caDER: leafDER,
                caFingerprintSHA256: leafPin
            )
        }
    }

    @Test("Rejects CA:TRUE certificate whose KeyUsage lacks keyCertSign")
    func rejectsCAWithoutKeyCertSign() throws {
        let material = try TLSTestHarness.sharedMaterial()
        let badDER = material.noKeySignCADER
        let badPin = DeploymentTLSIdentity.sha256Hex(badDER)
        #expect(throws: HelicoidError.self) {
            try DeploymentTLSIdentity(
                deploymentID: "d",
                host: "127.0.0.1",
                port: 443,
                caDER: badDER,
                caFingerprintSHA256: badPin
            )
        }
    }

    @Test("Accepts only CA BasicConstraints certificates as anchors")
    func acceptsRealCA() throws {
        let material = try TLSTestHarness.sharedMaterial()
        // Real generated CA is accepted (covered by identity tests too).
        _ = try DeploymentTLSIdentity(
            deploymentID: "d",
            host: "127.0.0.1",
            port: 443,
            caDER: material.caDER,
            caFingerprintSHA256: material.caFingerprint
        )
    }
}

@Suite("Pinned HTTPS configuration bounds")
struct PinnedHTTPSConfigurationTests {
    @Test("Rejects invalid bounds instead of clamping or crashing")
    func rejectsInvalidBounds() throws {
        let material = try TLSTestHarness.sharedMaterial()
        let identity = try DeploymentTLSIdentity(
            deploymentID: "d",
            host: "server.test",
            port: 443,
            caDER: material.caDER,
            caFingerprintSHA256: material.caFingerprint
        )
        // Oversized body bound is refused — never silently clamped.
        #expect(throws: HelicoidError.self) {
            try PinnedHTTPSConfiguration(
                identity: identity,
                requestTimeout: 1,
                operationTimeout: 1,
                maxResponseBytes: 10_000_000
            )
        }
        #expect(throws: HelicoidError.self) {
            try PinnedHTTPSConfiguration(identity: identity, requestTimeout: 1, operationTimeout: 1, maxResponseBytes: 0)
        }
        #expect(throws: HelicoidError.self) {
            try PinnedHTTPSConfiguration(identity: identity, requestTimeout: 1, operationTimeout: 1, maxResponseBytes: -1)
        }
        #expect(throws: HelicoidError.self) {
            try PinnedHTTPSConfiguration(identity: identity, requestTimeout: -1, operationTimeout: 1)
        }
        #expect(throws: HelicoidError.self) {
            try PinnedHTTPSConfiguration(identity: identity, requestTimeout: 0, operationTimeout: 1)
        }
        #expect(throws: HelicoidError.self) {
            try PinnedHTTPSConfiguration(identity: identity, requestTimeout: .infinity, operationTimeout: 1)
        }
        #expect(throws: HelicoidError.self) {
            try PinnedHTTPSConfiguration(identity: identity, requestTimeout: .nan, operationTimeout: 1)
        }
        #expect(throws: HelicoidError.self) {
            try PinnedHTTPSConfiguration(identity: identity, requestTimeout: 1, operationTimeout: -2)
        }
        // Huge finite timeout beyond representable sleep is refused, not trapped.
        #expect(throws: HelicoidError.self) {
            try PinnedHTTPSConfiguration(
                identity: identity,
                requestTimeout: 1,
                operationTimeout: PinnedHTTPSConfiguration.maxTimeoutSeconds + 1
            )
        }
    }

    @Test("Accepts valid bounds and maps huge-but-valid timeouts to safe nanoseconds")
    func acceptsValidBounds() throws {
        let material = try TLSTestHarness.sharedMaterial()
        let identity = try DeploymentTLSIdentity(
            deploymentID: "d",
            host: "server.test",
            port: 443,
            caDER: material.caDER,
            caFingerprintSHA256: material.caFingerprint
        )
        let ok = try PinnedHTTPSConfiguration(
            identity: identity,
            requestTimeout: 15,
            operationTimeout: 30,
            maxResponseBytes: 65_536
        )
        #expect(ok.hasFinitePositiveBounds)
        #expect(ok.maxResponseBytes == 65_536)

        // nanoseconds conversion must not trap on the maximum accepted timeout.
        let ns = PinnedHTTPSConfiguration.nanoseconds(from: PinnedHTTPSConfiguration.maxTimeoutSeconds)
        #expect(ns > 0)
        #expect(ns < UInt64.max)
    }
}
