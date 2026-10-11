import CryptoKit
import Foundation
import Security

/// Immutable deployment TLS trust inputs for a pinned HTTPS origin.
///
/// Trust is supplied by an operator or verified SSH bootstrap channel —
/// never learned from the HTTPS peer or a health response. This type
/// validates and holds those inputs; it does not persist trust or present
/// adoption UI. No TOFU and no fallback to OS/browser roots.
///
/// Contract: deployment TLS trust v1 (`deployment-tls-trust-v1.md`).
public struct DeploymentTLSIdentity: Sendable, Hashable {
    /// Maximum accepted deployment CA DER size (64 KiB).
    public static let maxCADerBytes = 65_536
    /// Maximum accepted deployment id length.
    public static let maxDeploymentIDLength = 128
    /// Maximum accepted host label/name length (DNS 253 octets).
    public static let maxHostLength = 253
    /// Maximum accepted SHA-256 hex fingerprint length (64 hex chars).
    public static let fingerprintHexLength = 64

    /// Immutable deployment identity. Nonempty and bounded.
    public let deploymentID: String
    /// Canonical HTTPS origin host (DNS name or IP literal), roundtripped.
    public let host: String
    /// Canonical HTTPS origin port.
    public let port: Int
    /// Canonical HTTPS origin URL. Built at init; never force-unwrapped later.
    public let originURL: URL
    /// Exactly one deployment CA certificate as DER.
    public let caDER: Data
    /// Independently verified SHA-256 hex fingerprint of `caDER`.
    public let caFingerprintSHA256: String

    /// Validate and freeze trust inputs before any request.
    ///
    /// - Throws: `HelicoidError.invalidInput` when any input fails validation
    ///   or when the provided fingerprint does not match the CA DER bytes.
    public init(
        deploymentID: String,
        host: String,
        port: Int,
        caDER: Data,
        caFingerprintSHA256: String
    ) throws {
        // MARK: deployment id
        let trimmedID = deploymentID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedID.isEmpty else {
            throw HelicoidError.invalidInput(field: "deployment_id", detail: "Deployment id must not be empty.")
        }
        guard trimmedID.count <= Self.maxDeploymentIDLength else {
            throw HelicoidError.invalidInput(
                field: "deployment_id",
                detail: "Deployment id exceeded \(Self.maxDeploymentIDLength) characters."
            )
        }
        guard !trimmedID.contains(where: { $0.isControlCharacter }) else {
            throw HelicoidError.invalidInput(field: "deployment_id", detail: "Deployment id must not contain control characters.")
        }

        // MARK: host + port → canonical origin URL
        guard (1...65_535).contains(port) else {
            throw HelicoidError.invalidInput(field: "port", detail: "Origin port must be in 1...65535.")
        }
        let canonicalHost = try Self.validateAndCanonicalizeHost(host)
        let origin = try Self.buildOriginURL(host: canonicalHost, port: port)

        // MARK: CA certificate
        guard !caDER.isEmpty else {
            throw HelicoidError.invalidInput(field: "ca_der", detail: "Deployment CA DER must not be empty.")
        }
        guard caDER.count <= Self.maxCADerBytes else {
            throw HelicoidError.invalidInput(
                field: "ca_der",
                detail: "Deployment CA DER exceeded \(Self.maxCADerBytes) bytes."
            )
        }
        guard let caCert = SecCertificateCreateWithData(nil, caDER as CFData) else {
            throw HelicoidError.invalidInput(field: "ca_der", detail: "Deployment CA DER is not a valid certificate.")
        }
        guard Self.isCertificateAuthority(caCert) else {
            throw HelicoidError.invalidInput(
                field: "ca_der",
                detail: "Deployment CA must be a certificate with CA BasicConstraints and keyCertSign use. A leaf certificate is refused."
            )
        }

        // MARK: pin binds to exact DER bytes
        let computed = Self.sha256Hex(caDER)
        let trimmedPin = caFingerprintSHA256.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard trimmedPin.count == Self.fingerprintHexLength,
              trimmedPin.allSatisfy(\.isHexDigit) else {
            throw HelicoidError.invalidInput(
                field: "ca_fingerprint",
                detail: "CA fingerprint must be a \(Self.fingerprintHexLength)-character SHA-256 hex string."
            )
        }
        // Pin matching alone does not replace certificate validation; this check
        // only binds the operator-supplied pin to the operator-supplied DER.
        guard trimmedPin == computed else {
            throw HelicoidError.invalidInput(
                field: "ca_fingerprint",
                detail: "CA fingerprint does not match the provided CA DER bytes."
            )
        }

        self.deploymentID = trimmedID
        self.host = canonicalHost
        self.port = port
        self.originURL = origin
        self.caDER = caDER
        self.caFingerprintSHA256 = trimmedPin
    }

    // MARK: - Host validation

    /// Accept bare DNS name, IPv4 literal, or IPv6 literal. Reject controls,
    /// percent-encoding, whitespace, scheme/path/credentials, and unbalanced
    /// brackets. Result is the canonical (lowercased, bracket-stripped) host
    /// that roundtrips through `URLComponents`.
    static func validateAndCanonicalizeHost(_ raw: String) throws -> String {
        // Reject leading/trailing whitespace as malformed rather than silently trimming.
        guard raw == raw.trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw HelicoidError.invalidInput(field: "host", detail: "Origin host must not include surrounding whitespace.")
        }
        let host = raw.lowercased()
        guard !host.isEmpty else {
            throw HelicoidError.invalidInput(field: "host", detail: "Origin host must not be empty.")
        }
        guard host.count <= maxHostLength else {
            throw HelicoidError.invalidInput(
                field: "host",
                detail: "Origin host exceeded \(maxHostLength) characters."
            )
        }
        if host.contains(where: { $0.isControlCharacter }) {
            throw HelicoidError.invalidInput(field: "host", detail: "Origin host must not contain control characters.")
        }
        if host.contains(where: { $0.isWhitespace }) {
            throw HelicoidError.invalidInput(field: "host", detail: "Origin host must not contain whitespace.")
        }
        if host.contains("%") {
            throw HelicoidError.invalidInput(field: "host", detail: "Origin host must not contain percent-encoding.")
        }
        if host.contains("://") || host.contains("/") || host.contains("?") || host.contains("#") || host.contains("@") {
            throw HelicoidError.invalidInput(field: "host", detail: "Origin host must be a bare host name or IP literal.")
        }

        // IPv6: [::1] or ::1 forms — require balanced brackets if present.
        if host.hasPrefix("[") || host.hasSuffix("]") || host.contains("]") || host.contains("[") {
            guard host.hasPrefix("["), host.hasSuffix("]") else {
                throw HelicoidError.invalidInput(field: "host", detail: "Origin host has unbalanced IPv6 brackets.")
            }
            let inner = String(host.dropFirst().dropLast())
            guard !inner.isEmpty, !inner.contains("["), !inner.contains("]"), inner.contains(":") else {
                throw HelicoidError.invalidInput(field: "host", detail: "Origin host IPv6 literal is malformed.")
            }
            return inner
        }

        // Bare IPv6 without brackets (e.g. ::1) — must contain ':' and roundtrip.
        if host.contains(":") {
            // Not a DNS name. Require IPv6 roundtrip via URLComponents.
            return host
        }

        // DNS / IPv4: reject empty labels and illegal characters.
        if host.hasPrefix(".") || host.hasSuffix(".") || host.contains("..") {
            throw HelicoidError.invalidInput(field: "host", detail: "Origin host has malformed DNS labels.")
        }
        for label in host.split(separator: ".", omittingEmptySubsequences: false) {
            if label.isEmpty {
                throw HelicoidError.invalidInput(field: "host", detail: "Origin host has empty DNS label.")
            }
            if label.count > 63 {
                throw HelicoidError.invalidInput(field: "host", detail: "Origin host DNS label exceeded 63 characters.")
            }
            if label.hasPrefix("-") || label.hasSuffix("-") {
                throw HelicoidError.invalidInput(field: "host", detail: "Origin host DNS label must not start or end with hyphen.")
            }
            for ch in label {
                let ok = ch.isLetter || ch.isNumber || ch == "-"
                if !ok {
                    throw HelicoidError.invalidInput(field: "host", detail: "Origin host contains illegal character.")
                }
            }
        }
        return host
    }

    /// Build `https://host:port/` from validated host/port. No force-unwrap.
    static func buildOriginURL(host: String, port: Int) throws -> URL {
        // IPv6 hosts must be bracketed in the authority form.
        let authorityHost = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        guard let url = URL(string: "https://\(authorityHost):\(port)/") else {
            throw HelicoidError.invalidInput(field: "host", detail: "Origin host/port do not form a canonical HTTPS origin URL.")
        }
        // Roundtrip: URLComponents must recover the same host and port.
        // Foundation may report IPv6 hosts with or without brackets — normalize.
        guard let round = URLComponents(url: url, resolvingAgainstBaseURL: false),
              round.scheme == "https",
              let roundHost = round.host.map(Self.normalizeHostForCompare),
              roundHost == normalizeHostForCompare(host),
              round.port == port,
              round.user == nil,
              round.password == nil,
              round.path == "/" || round.path.isEmpty,
              round.query == nil,
              round.fragment == nil else {
            throw HelicoidError.invalidInput(field: "host", detail: "Origin host/port do not roundtrip as a canonical HTTPS origin.")
        }
        return url
    }

    /// Strip IPv6 brackets and lowercase for host equality checks.
    static func normalizeHostForCompare(_ host: String) -> String {
        var h = host.lowercased()
        if h.hasPrefix("["), h.hasSuffix("]") {
            h = String(h.dropFirst().dropLast())
        }
        return h
    }

    /// True when the certificate is a CA (BasicConstraints CA:TRUE) and, when
    /// KeyUsage is present, actually has keyCertSign. Leaf certificates and
    /// malformed/unsupported structures are refused (no permissive fallback).
    ///
    /// Native KeyUsage `NSNumber` (see installed Security framework):
    /// critical bit `0x80000000`, keyCertSign bit `0x20`.
    static func isCertificateAuthority(_ cert: SecCertificate) -> Bool {
        let keys = ["2.5.29.19", "2.5.29.15"] as CFArray
        var error: Unmanaged<CFError>?
        guard let values = SecCertificateCopyValues(cert, keys, &error) else {
            return false
        }
        guard let dict = values as? [CFString: Any] else {
            return false
        }

        // BasicConstraints (2.5.29.19): exact native section structure required.
        guard let bc = dict["2.5.29.19" as CFString] as? [CFString: Any],
              let rows = bc[kSecPropertyKeyValue as CFString] as? [[CFString: Any]] else {
            return false
        }
        var isCA = false
        var sawCARow = false
        for row in rows {
            let label = (row[kSecPropertyKeyLabel as CFString] as? String) ?? ""
            let value = (row[kSecPropertyKeyValue as CFString] as? String) ?? ""
            if label == "Certificate Authority" {
                sawCARow = true
                if value == "Yes" {
                    isCA = true
                }
            }
        }
        guard sawCARow, isCA else {
            return false
        }

        // KeyUsage (2.5.29.15): when present must be an NSNumber with keyCertSign.
        // Absent KeyUsage is allowed only if BasicConstraints is a real CA.
        if dict.keys.contains("2.5.29.15" as CFString) {
            guard let ku = dict["2.5.29.15" as CFString] as? [CFString: Any],
                  let bits = ku[kSecPropertyKeyValue as CFString] as? NSNumber,
                  ku[kSecPropertyKeyType as CFString] as? String == "number" else {
                // Malformed or unsupported KeyUsage structure — refuse.
                return false
            }
            let raw = bits.uint64Value
            let keyCertSign: UInt64 = 0x20
            let criticalBit: UInt64 = 0x8000_0000
            // Ignore the native critical flag; require the real keyCertSign bit.
            let usage = raw & ~criticalBit
            if usage & keyCertSign == 0 {
                return false
            }
        }
        return true
    }

    /// CryptoKit SHA-256 of exact DER bytes, lowercase hex.
    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Character helpers

private extension Character {
    var isControlCharacter: Bool {
        guard let ascii = asciiValue else { return true }
        return ascii < 0x20 || ascii == 0x7F
    }
}

/// Path/origin policy for pinned HTTPS requests.
///
/// Only the configured origin may be addressed. Arbitrary absolute target
/// URIs, relative traversal, and scheme escapes are refused.
public enum DeploymentOriginPolicy: Sendable {
    public enum Decision: Equatable, Sendable {
        case allowed(URL)
        case refused(Reason)
    }

    public enum Reason: String, Equatable, Sendable {
        case empty
        case invalidURL
        case schemeEscape
        case hostMismatch
        case portMismatch
        case credentialsPresent
        case fragmentPresent
        case queryNotAllowed
        case traversal
        case absoluteForeignURI
        case controlCharacter
        case percentEncodedTraversal

        public var message: String {
            switch self {
            case .empty: "Request path must not be empty."
            case .invalidURL: "Request path is not a valid URL component."
            case .schemeEscape: "Scheme escapes such as //host or http: are refused."
            case .hostMismatch: "Request host does not match the configured deployment origin."
            case .portMismatch: "Request port does not match the configured deployment origin."
            case .credentialsPresent: "Credentials in request URLs are refused."
            case .fragmentPresent: "URL fragments are refused."
            case .queryNotAllowed: "Query strings are refused on the deployment origin address."
            case .traversal: "Path traversal segments are refused."
            case .absoluteForeignURI: "Absolute URIs outside the configured origin are refused."
            case .controlCharacter: "Control characters are refused in request paths."
            case .percentEncodedTraversal: "Percent-encoded traversal is refused."
            }
        }
    }

    /// Resolve a request path against the pinned origin.
    ///
    /// Accepts a root-relative path (`/v1/x`) or empty path. Refuses absolute
    /// foreign URIs, `//host` scheme escapes, `..` traversal (including
    /// percent-encoded forms), credentials, fragments, and control characters.
    public static func resolve(path: String, origin: URL) -> Decision {
        if path.contains(where: { ch -> Bool in
            guard let ascii = ch.asciiValue else { return true }
            return ascii < 0x20 || ascii == 0x7F
        }) {
            return .refused(.controlCharacter)
        }
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return .refused(.empty)
        }
        if trimmed.contains("#") {
            return .refused(.fragmentPresent)
        }
        // //host or /\host style scheme-relative escapes (before generic backslash check).
        if trimmed.hasPrefix("//") || trimmed.hasPrefix("/\\") {
            return .refused(.schemeEscape)
        }
        if trimmed.contains("\\") {
            return .refused(.traversal)
        }
        // Percent-encoded traversal / scheme escapes (%2e%2e, %2f%2f, %5c).
        if trimmed.contains("%") {
            if let decoded = decodedForInspection(trimmed) {
                if decoded.contains("..") || decoded.hasPrefix("//") || decoded.contains("\\") || decoded.hasPrefix("/\\") {
                    return .refused(.percentEncodedTraversal)
                }
                if decoded.contains(where: { ch -> Bool in
                    guard let ascii = ch.asciiValue else { return true }
                    return ascii < 0x20 || ascii == 0x7F
                }) {
                    return .refused(.controlCharacter)
                }
            }
        }

        // Absolute URI with a scheme: must be exactly the configured origin.
        if trimmed.contains("://") {
            guard let absolute = URL(string: trimmed) else {
                return .refused(.invalidURL)
            }
            guard let components = URLComponents(url: absolute, resolvingAgainstBaseURL: false) else {
                return .refused(.invalidURL)
            }
            if components.user != nil || components.password != nil {
                return .refused(.credentialsPresent)
            }
            guard components.scheme?.lowercased() == "https" else {
                return .refused(.schemeEscape)
            }
            guard let host = components.host.map(DeploymentTLSIdentity.normalizeHostForCompare),
                  host == DeploymentTLSIdentity.normalizeHostForCompare(origin.host ?? "") else {
                return .refused(.absoluteForeignURI)
            }
            let requestPort = components.port ?? 443
            let originPort = origin.port ?? 443
            guard requestPort == originPort else {
                return .refused(.portMismatch)
            }
            if hasTraversal(components.path) {
                return .refused(.traversal)
            }
            return .allowed(absolute)
        }

        // Credentials smuggled into a path.
        if trimmed.contains("@") {
            return .refused(.credentialsPresent)
        }

        // Relative segments including `.` / `..` are traversal.
        if hasTraversal(trimmed) {
            return .refused(.traversal)
        }

        // Root-relative path only.
        guard trimmed.hasPrefix("/") else {
            return .refused(.absoluteForeignURI)
        }

        var components = URLComponents(url: origin, resolvingAgainstBaseURL: false)
        components?.query = nil
        components?.fragment = nil
        // Split query so `/health?x=1` is addressable while origin stays clean.
        if let qIndex = trimmed.firstIndex(of: "?") {
            let pathPart = String(trimmed[trimmed.startIndex..<qIndex])
            let queryPart = String(trimmed[trimmed.index(after: qIndex)...])
            if hasTraversal(pathPart) {
                return .refused(.traversal)
            }
            components?.path = pathPart
            components?.query = queryPart.isEmpty ? nil : queryPart
        } else {
            components?.path = trimmed
        }
        guard let url = components?.url else {
            return .refused(.invalidURL)
        }
        return .allowed(url)
    }

    /// True when `path` contains `.` / `..` segments used for traversal.
    public static func hasTraversal(_ path: String) -> Bool {
        for segment in path.split(separator: "/", omittingEmptySubsequences: false) {
            if segment == ".." || segment == "." {
                return true
            }
        }
        return path.contains("/../") || path.hasPrefix("../") || path.hasSuffix("/..") || path == ".."
    }

    /// Percent-decode once for inspection only (not for I/O).
    private static func decodedForInspection(_ path: String) -> String? {
        // Foundation's removingPercentEncoding rejects invalid sequences.
        path.removingPercentEncoding
    }
}
