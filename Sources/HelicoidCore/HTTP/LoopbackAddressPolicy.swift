import Foundation

/// Loopback-only address policy for the development HTTP client.
///
/// Trust boundary: only a parsed literal IPv4 address in 127.0.0.0/8 or the
/// exact IPv6 loopback `::1` may be used. Hostnames (including `127.attacker.example`)
/// are refused. `localhost` is rewritten to `127.0.0.1` before any I/O so DNS
/// rebinding cannot escape loopback. Credentials, fragments, and ambiguous base
/// URLs (query or path beyond `/`) are refused. Redirects are never followed.
public enum LoopbackAddressPolicy: Sendable {

    public enum Decision: Equatable, Sendable {
        case allowed(CanonicalTarget)
        case refused(Reason)
    }

    /// Canonical, validated connection target. Only this form is sent to the transport.
    public struct CanonicalTarget: Equatable, Sendable {
        public let url: URL
        public let host: String
        public let port: Int?

        public var baseURL: URL { url }
    }

    public enum Reason: String, Equatable, Sendable {
        case empty
        case invalidURL
        case missingScheme
        case unsupportedScheme
        case embeddedCredentials
        case fragmentPresent
        case queryPresent
        case pathNotRoot
        case remoteHost
        case hostnameNotAllowed
        case nonLiteralHost
        case localhostNotRewritable
        case unexpected

        public var message: String {
            switch self {
            case .empty:
                "Enter a server address."
            case .invalidURL:
                "The address is not a valid URL."
            case .missingScheme:
                "Include an http:// scheme for local development."
            case .unsupportedScheme:
                "Only http:// is accepted for the loopback development server."
            case .embeddedCredentials:
                "Credentials in the address are refused. Sign in through the sign-in form."
            case .fragmentPresent:
                "URL fragments are refused."
            case .queryPresent:
                "Query strings are not allowed in the development server base address."
            case .pathNotRoot:
                "The development server base address must not include a path."
            case .remoteHost:
                "Remote hosts are refused. The development server must be loopback only."
            case .hostnameNotAllowed:
                "Only literal 127.0.0.0/8 or ::1 addresses are allowed. Hostnames such as 127.attacker.example are refused."
            case .nonLiteralHost:
                "Use a literal 127.x.x.x or [::1] address."
            case .localhostNotRewritable:
                "localhost could not be treated as loopback. Use 127.0.0.1 explicitly."
            case .unexpected:
                "The address could not be validated."
            }
        }
    }

    // MARK: - Public API

    /// Validate and canonicalize a candidate development server base URL.
    public static func validate(_ raw: String) -> Decision {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return .refused(.empty)
        }
        if trimmed.contains("#") {
            return .refused(.fragmentPresent)
        }
        guard trimmed.contains("://") else {
            return .refused(.invalidURL)
        }

        guard let components = URLComponents(string: trimmed) else {
            return .refused(.invalidURL)
        }

        if components.user != nil || components.password != nil {
            return .refused(.embeddedCredentials)
        }
        if components.fragment != nil {
            return .refused(.fragmentPresent)
        }
        if components.query != nil {
            return .refused(.queryPresent)
        }

        guard let scheme = components.scheme?.lowercased() else {
            return .refused(.missingScheme)
        }
        if scheme != "http" {
            return .refused(.unsupportedScheme)
        }

        // Path must be empty or "/".
        let path = components.path
        if !path.isEmpty && path != "/" {
            return .refused(.pathNotRoot)
        }

        guard let hostRaw = components.host, !hostRaw.isEmpty else {
            return .refused(.nonLiteralHost)
        }

        let host = hostRaw.lowercased()
        let port = components.port

        // localhost is rewritten to 127.0.0.1 before any transport (DNS-rebinding defense).
        // No live DNS lookup is used as an allow-list.
        if host == "localhost" {
            return canonical(host: "127.0.0.1", port: port, scheme: "http")
        }

        // Exact IPv6 loopback.
        if host == "::1" || host == "[::1]" || host == "0:0:0:0:0:0:0:1" {
            return canonical(host: "::1", port: port, scheme: "http")
        }

        // Literal IPv4 only (dotted decimal). Reject hostnames like 127.attacker.example.
        if let v4 = parseIPv4Literal(host) {
            // 127.0.0.0/8
            if (v4 & 0xFF000000) == 0x7F000000 {
                return canonical(host: host, port: port, scheme: "http")
            }
            return .refused(.remoteHost)
        }

        if host.contains(":") {
            // Other IPv6 literals are not loopback.
            return .refused(.remoteHost)
        }

        // Any other name — including 127.attacker.example — is not a literal loopback.
        if looksLikeIPv4Attempt(host) {
            return .refused(.hostnameNotAllowed)
        }
        return .refused(.hostnameNotAllowed)
    }

    /// Validate a full request URL (path allowed). Host must still be loopback.
    /// Credentials and fragments remain refused.
    public static func validateRequestURL(_ raw: String) -> Decision {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return .refused(.empty)
        }
        if trimmed.contains("#") {
            return .refused(.fragmentPresent)
        }
        guard trimmed.contains("://"), let components = URLComponents(string: trimmed) else {
            return .refused(.invalidURL)
        }
        if components.user != nil || components.password != nil {
            return .refused(.embeddedCredentials)
        }
        if components.fragment != nil {
            return .refused(.fragmentPresent)
        }
        guard let scheme = components.scheme?.lowercased(), scheme == "http" else {
            return .refused(.unsupportedScheme)
        }
        guard let hostRaw = components.host, !hostRaw.isEmpty else {
            return .refused(.nonLiteralHost)
        }
        let host = hostRaw.lowercased()
        if host == "localhost" {
            // Rewrite host for DNS-rebinding defense; keep path/query as-is.
            var rewritten = components
            rewritten.host = "127.0.0.1"
            if let url = rewritten.url {
                return .allowed(CanonicalTarget(url: url, host: "127.0.0.1", port: components.port))
            }
            return .refused(.invalidURL)
        }
        if host == "::1" || host == "[::1]" || host == "0:0:0:0:0:0:0:1" {
            guard let url = components.url else { return .refused(.invalidURL) }
            return .allowed(CanonicalTarget(url: url, host: "::1", port: components.port))
        }
        if let v4 = parseIPv4Literal(host) {
            if (v4 & 0xFF000000) == 0x7F000000 {
                guard let url = components.url else { return .refused(.invalidURL) }
                return .allowed(CanonicalTarget(url: url, host: host, port: components.port))
            }
            return .refused(.remoteHost)
        }
        return .refused(.hostnameNotAllowed)
    }

    /// Redirects are never followed, including other loopback ports.
    /// A bearer token must not leak to a different service.
    public static func allowRedirect(from original: URL, to target: URL) -> Bool {
        _ = original
        _ = target
        return false
    }

    // MARK: - Parsing

    /// Strict dotted-quad IPv4. Rejects short forms, octal, hex, and hostnames.
    static func parseIPv4Literal(_ host: String) -> UInt32? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.count <= 3, part.allSatisfy(\.isNumber) else {
                return nil
            }
            // Reject leading zeros (octal ambiguity) except the single digit 0.
            if part.count > 1 && part.hasPrefix("0") {
                return nil
            }
            guard let octet = UInt8(part) else { return nil }
            value = (value << 8) | UInt32(octet)
        }
        return value
    }

    private static func looksLikeIPv4Attempt(_ host: String) -> Bool {
        host.contains(".") || host.contains(":")
    }

    private static func canonical(host: String, port: Int?, scheme: String) -> Decision {
        // Build the URL string explicitly so IPv6 hosts get correct brackets.
        var authority = host
        if host.contains(":") && !host.hasPrefix("[") {
            authority = "[\(host)]"
        }
        if let port {
            authority += ":\(port)"
        }
        let urlString = "\(scheme)://\(authority)/"
        guard let url = URL(string: urlString) else {
            return .refused(.invalidURL)
        }
        return .allowed(CanonicalTarget(url: url, host: host, port: port))
    }
}
