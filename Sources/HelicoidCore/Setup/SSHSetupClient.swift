import Foundation

public struct SSHSetupAddress: Equatable, Sendable {
    public let user: String?
    public let host: String
    public let port: UInt16

    public init(_ value: String) throws {
        guard value == value.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty, value.utf8.count <= 255,
              value.unicodeScalars.allSatisfy({ $0.isASCII && !$0.properties.isWhitespace }),
              !value.contains("%"), !value.contains("\\"),
              let parts = URLComponents(string: "ssh://" + value),
              parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty, let hostname = parts.host, !hostname.isEmpty else {
            throw HelicoidError.invalidInput(field: "SSH address", detail: "Use user@host or user@host:port.")
        }
        let hostCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:[]")
        let userCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        guard !hostname.hasPrefix("-"), hostname.unicodeScalars.allSatisfy(hostCharacters.contains),
              parts.user.map({ !$0.isEmpty && !$0.hasPrefix("-") && $0.unicodeScalars.allSatisfy(userCharacters.contains) }) ?? true,
              (1...65535).contains(parts.port ?? 22) else {
            throw HelicoidError.invalidInput(field: "SSH address", detail: "Invalid host, user or port.")
        }
        user = parts.user
        host = hostname
        port = UInt16(parts.port ?? 22)
    }

    public var destination: String { user.map { $0 + "@" + host } ?? host }
}

public struct SSHHostPreflight: Decodable, Equatable, Sendable {
    public let version: Int
    public let osID: String
    public let osVersion: String
    public let architecture: String
    public let systemdAvailable: Bool
    public let sudoAvailable: Bool
    public let freeBytes: UInt64
    public let existingInstallation: Bool
    public let tcpPorts: [UInt16]
    public let udpPorts: [UInt16]

    enum CodingKeys: String, CodingKey {
        case version, architecture
        case osID = "os_id", osVersion = "os_version"
        case systemdAvailable = "systemd_available", sudoAvailable = "sudo_available"
        case freeBytes = "free_bytes", existingInstallation = "existing_installation"
        case tcpPorts = "tcp_ports", udpPorts = "udp_ports"
    }

    public func validate() throws {
        guard version == 1, osID.utf8.count <= 32, osVersion.utf8.count <= 32,
              architecture.utf8.count <= 32, tcpPorts.count <= 1024, udpPorts.count <= 1024,
              Set(tcpPorts).count == tcpPorts.count, Set(udpPorts).count == udpPorts.count else {
            throw HelicoidError.setupBlocked(reason: "Invalid host preflight response.")
        }
    }

    public func checks(authorityPort: UInt16 = 8920) -> [String: HostCheckStatus] {
        let conflict = tcpPorts.contains(authorityPort)
        let supportedUbuntu = osID == "ubuntu" && ["24.04", "26.04"].contains(osVersion)
            && architecture == "x86_64"
        return [
            "SSH reachability": .passed,
            "Operating system": supportedUbuntu
                ? .passed : .needsAttention(detail: "The Linux installer supports Ubuntu 24.04 or 26.04 on x86-64."),
            "Service manager": systemdAvailable ? .passed : .needsAttention(detail: "systemd is required."),
            "Administrator access": sudoAvailable ? .passed : .needsAttention(detail: "SSH key setup requires noninteractive sudo."),
            "Disk space": freeBytes >= 2_147_483_648 ? .passed : .needsAttention(detail: "At least 2 GiB of free space is required."),
            "Product ports": conflict ? .needsAttention(detail: "A selected Helicoid port is occupied.") : .passed,
            "Existing installation": existingInstallation ? .needsAttention(detail: "Inspect the existing installation before repair.") : .passed,
        ]
    }
}

public struct VerifiedSSHPreflight: Sendable {
    public let fingerprint: String
    public let host: SSHHostPreflight
}

public struct SSHSetupClient: Sendable {
    private let runner: any SetupCommandRunning

    public init(runner: any SetupCommandRunning = SystemSetupCommandRunner()) { self.runner = runner }

    /// Strict OpenSSH verification uses existing trusted host keys. Debug output
    /// is consumed only to extract the public fingerprint, never displayed/logged.
    public func preflight(address: SSHSetupAddress) async throws -> VerifiedSSHPreflight {
        let command = SetupCommand(executable: "/usr/bin/ssh", arguments: [
            "-v", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "UpdateHostKeys=no", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
            "-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no",
            "-o", "ControlPath=none", "-p", String(address.port),
            "--", address.destination, "/usr/bin/python3 -",
        ], input: Data(Self.preflightScript.utf8))
        let result = try await runner.run(command)
        guard result.exitStatus == 0 else {
            let error = String(decoding: result.errorOutput, as: UTF8.self)
            if error.contains("Host key verification failed") || error.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
                throw HelicoidError.hostIdentityUnverified
            }
            throw HelicoidError.setupBlocked(reason: "SSH preflight failed. Check trusted host identity, key authentication and Python 3 availability.")
        }
        guard let fingerprint = Self.hostFingerprint(result.errorOutput) else {
            throw HelicoidError.hostIdentityUnverified
        }
        let facts: SSHHostPreflight
        do { facts = try JSONDecoder().decode(SSHHostPreflight.self, from: result.output) }
        catch { throw HelicoidError.setupBlocked(reason: "Invalid host preflight response.") }
        try facts.validate()
        return VerifiedSSHPreflight(fingerprint: fingerprint, host: facts)
    }

    static func hostFingerprint(_ bytes: Data) -> String? {
        let lines = String(decoding: bytes, as: UTF8.self).split(whereSeparator: { $0.isNewline })
        let matches = lines.filter { $0.hasPrefix("debug1: Server host key: ") }.compactMap { line -> String? in
            let parts = line.split(separator: " ")
            guard let value = parts.last, value.hasPrefix("SHA256:"), value.count == 50,
                  value.dropFirst(7).allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "+" || $0 == "/") }) else { return nil }
            return String(value)
        }
        guard matches.count == 1 else { return nil }
        return matches[0]
    }

    private static let preflightScript = #"""
import json, os, platform, shutil, subprocess
def command(argv):
    result = subprocess.run(argv, capture_output=True, timeout=5, check=False)
    if len(result.stdout) + len(result.stderr) > 65536:
        raise RuntimeError("preflight output exceeds bound")
    return result
values = {}
with open('/etc/os-release', encoding='utf-8') as stream:
    for line in stream:
        key, sep, value = line.strip().partition('=')
        if sep:
            values[key] = value.strip('"')
def ports(flag):
    result = command(['/usr/bin/ss', '-H', '-l', '-n', flag])
    if result.returncode:
        raise RuntimeError("cannot inspect listeners")
    found = set()
    for row in result.stdout.decode('utf-8', errors='strict').splitlines():
        fields = row.split()
        if len(fields) < 5:
            raise RuntimeError("invalid listener row")
        found.add(int(fields[3].rsplit(':', 1)[1]))
    return sorted(found)
sudo = command(['/usr/bin/sudo', '-n', 'true'])
print(json.dumps({'version': 1, 'os_id': values.get('ID', ''),
    'os_version': values.get('VERSION_ID', ''), 'architecture': platform.machine(),
    'systemd_available': shutil.which('systemctl') is not None and os.path.isdir('/run/systemd/system'),
    'sudo_available': sudo.returncode == 0, 'free_bytes': shutil.disk_usage('/var').free,
    'existing_installation': os.path.lexists('/opt/helicoid'),
    'tcp_ports': ports('-t'), 'udp_ports': ports('-u')}))
"""#
}
