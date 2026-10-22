import Foundation
import Darwin

/// Ownership boundary a future verified installer would claim on this Mac.
/// This build never applies the plan; preflight only reads conflicts against it
/// so installer integration cannot invent paths or a launchd label later.
public struct LocalHostingOwnershipPlan: Equatable, Sendable {
    public let productRootPath: String
    public let dataPath: String
    public let launchdLabel: String
    public let launchdPlistPath: String

    public init(productRootPath: String, dataPath: String, launchdLabel: String, launchdPlistPath: String) {
        self.productRootPath = productRootPath
        self.dataPath = dataPath
        self.launchdLabel = launchdLabel
        self.launchdPlistPath = launchdPlistPath
    }

    public static let current = LocalHostingOwnershipPlan(
        productRootPath: "/Library/Application Support/Helicoid",
        dataPath: "/Library/Application Support/Helicoid/Data",
        launchdLabel: "com.helicoid.server",
        launchdPlistPath: "/Library/LaunchDaemons/com.helicoid.server.plist"
    )
}

/// Path resource state from `lstat`. Dangling symlinks are conflicts, not absences.
public enum ResourceState: Equatable, Sendable {
    case absent
    case present
    case brokenSymlink
    case unknown(detail: String)

    public var isConflict: Bool {
        switch self {
        case .absent: false
        case .present, .brokenSymlink: true
        case .unknown: true
        }
    }
}

/// launchd service state for the planned label. A loaded job can outlive its plist.
public enum LaunchdServiceState: Equatable, Sendable {
    case absent
    case conflicting(plist: ResourceState, loaded: Bool)
    case unknown(detail: String)

    public var isConflict: Bool {
        switch self {
        case .absent: false
        case .conflicting: true
        case .unknown: true
        }
    }
}

/// Listener observation completeness. Process-scoped listings cannot prove
/// system-owned listeners and must not be treated as a clean port table.
public enum ListenerInspection: Equatable, Sendable {
    case complete(tcpPorts: [UInt16], udpPorts: [UInt16])
    case incomplete(tcpPorts: [UInt16], udpPorts: [UInt16], detail: String)

    public var isComplete: Bool {
        if case .complete = self { return true }
        return false
    }

    public var tcpPorts: [UInt16] {
        switch self {
        case .complete(let tcp, _), .incomplete(let tcp, _, _): tcp
        }
    }

    public var udpPorts: [UInt16] {
        switch self {
        case .complete(_, let udp), .incomplete(_, let udp, _): udp
        }
    }
}

/// Read-only facts about this Mac. No privileged writes or elevation while gathering them.
/// Unknown required facts never count as passed.
public struct LocalHostPreflight: Equatable, Sendable {
    /// `HOST_NAME_MAX` on Darwin. Hostname is informational display text, not a product identity.
    public static let computerNameMaxUTF8 = 255
    /// Compact UI bound; display truncation never changes identity validation.
    public static let computerNameDisplayMaxUTF8 = 64

    public let version: Int
    public let computerName: String
    public let osVersion: String
    public let architecture: String
    public let launchdAvailable: Bool
    public let administratorAccess: Bool
    public let freeBytes: UInt64
    public let productPath: ResourceState
    public let launchdService: LaunchdServiceState
    public let listeners: ListenerInspection

    public init(version: Int = 1, computerName: String, osVersion: String, architecture: String,
                launchdAvailable: Bool, administratorAccess: Bool, freeBytes: UInt64,
                productPath: ResourceState, launchdService: LaunchdServiceState,
                listeners: ListenerInspection) {
        self.version = version
        self.computerName = computerName
        self.osVersion = osVersion
        self.architecture = architecture
        self.launchdAvailable = launchdAvailable
        self.administratorAccess = administratorAccess
        self.freeBytes = freeBytes
        self.productPath = productPath
        self.launchdService = launchdService
        self.listeners = listeners
    }

    public func validate() throws {
        guard version == 1,
              !computerName.isEmpty,
              computerName.utf8.count <= Self.computerNameMaxUTF8,
              osVersion.utf8.count <= 32,
              architecture.utf8.count <= 32,
              listeners.tcpPorts.count <= 1024, listeners.udpPorts.count <= 1024,
              Set(listeners.tcpPorts).count == listeners.tcpPorts.count,
              Set(listeners.udpPorts).count == listeners.udpPorts.count else {
            throw HelicoidError.setupBlocked(reason: "Invalid local host preflight response.")
        }
    }

    /// Display-only truncation for compact UI. Hostname is not treated as an identity.
    public static func displayComputerName(_ name: String, maxUTF8: Int = computerNameDisplayMaxUTF8) -> String {
        guard name.utf8.count > maxUTF8 else { return name }
        let ellipsis = "…"
        let budget = max(0, maxUTF8 - ellipsis.utf8.count)
        var truncated = String()
        var used = 0
        for character in name {
            let width = String(character).utf8.count
            if used + width > budget { break }
            truncated.append(character)
            used += width
        }
        return truncated + ellipsis
    }

    public func checks(authorityPort: UInt16 = 8920,
                       plan: LocalHostingOwnershipPlan = .current) -> [String: HostCheckStatus] {
        let tcpRequired: Set<UInt16> = [authorityPort]
        return [
            "Operating system": Self.isSupported(osVersion: osVersion, architecture: architecture)
                ? .passed : .needsAttention(detail: "This build supports macOS 15 or newer on Apple silicon or Intel."),
            "Administrator access": administratorAccess
                ? .passed : .needsAttention(detail: "Administrator privileges are required to install and manage the service."),
            "Disk space": freeBytes >= 2_147_483_648
                ? .passed : .needsAttention(detail: "At least 2 GiB of free space is required."),
            "Product path": productPathCheck(plan: plan),
            "Service manager": serviceManagerCheck(plan: plan),
            "Product ports": productPortsCheck(tcpRequired: tcpRequired),
        ]
    }

    private func productPathCheck(plan: LocalHostingOwnershipPlan) -> HostCheckStatus {
        switch productPath {
        case .absent:
            return .passed
        case .present:
            return .needsAttention(detail: "Inspect \(plan.productRootPath) before repair.")
        case .brokenSymlink:
            return .needsAttention(detail: "Broken symlink at \(plan.productRootPath). Inspect it before repair.")
        case .unknown(let detail):
            return .needsAttention(detail: "Product path could not be inspected: \(detail)")
        }
    }

    private func serviceManagerCheck(plan: LocalHostingOwnershipPlan) -> HostCheckStatus {
        guard launchdAvailable else {
            return .needsAttention(detail: "launchd is required.")
        }
        switch launchdService {
        case .absent:
            return .passed
        case .conflicting(let plist, let loaded):
            let state = loaded
                ? "is loaded in launchd"
                : "has a resource at \(plan.launchdPlistPath) (plist: \(plist))"
            return .needsAttention(detail: "launchd service \(plan.launchdLabel) \(state). Inspect it before repair.")
        case .unknown(let detail):
            return .needsAttention(detail: "Service state could not be inspected: \(detail)")
        }
    }

    private func productPortsCheck(tcpRequired: Set<UInt16>) -> HostCheckStatus {
        switch listeners {
        case .complete(let tcp, _):
            let conflict = !tcpRequired.isDisjoint(with: tcp)
            return conflict
                ? .needsAttention(detail: "A selected Helicoid port is occupied.")
                : .passed
        case .incomplete(_, _, let detail):
            return .needsAttention(detail: "Listening ports were not fully inspected: \(detail)")
        }
    }

    static func isSupported(osVersion: String, architecture: String) -> Bool {
        guard let major = osVersion.split(separator: ".").first.flatMap({ Int($0) }) else { return false }
        return major >= 15 && (architecture == "arm64" || architecture == "x86_64")
    }

    /// Strict lsof NAME-column parse. Malformed rows refuse rather than being skipped.
    /// Unbound sockets (`*:*`) have no port and are not rows.
    static func ports(fromLsof output: Data) throws -> [UInt16] {
        var found = Set<UInt16>()
        for line in String(decoding: output, as: UTF8.self).split(whereSeparator: { $0.isNewline }) {
            if line.isEmpty || line.hasPrefix("COMMAND") { continue }
            let fields = line.split(separator: " ")
            guard let protoIndex = fields.firstIndex(where: { $0 == "TCP" || $0 == "UDP" }),
                  protoIndex + 1 < fields.count else {
                throw HelicoidError.setupBlocked(reason: "Local preflight could not parse a listening port row.")
            }
            let address = fields[protoIndex + 1]
            guard let last = address.split(separator: ":").last else {
                throw HelicoidError.setupBlocked(reason: "Local preflight could not parse a listening port row.")
            }
            if last == "*" { continue }
            guard let port = UInt16(last) else {
                throw HelicoidError.setupBlocked(reason: "Local preflight could not parse a listening port row.")
            }
            found.insert(port)
        }
        return found.sorted()
    }
}

public protocol LocalHostingInspecting: Sendable {
    func inspect() async throws -> LocalHostPreflight
}

/// Gathers local facts read-only and within bounded command output/time limits.
/// Never elevates privileges or installs anything.
public struct SystemLocalHostingInspector: LocalHostingInspecting {
    private let runner: any SetupCommandRunning
    private let plan: LocalHostingOwnershipPlan

    public init(runner: any SetupCommandRunning = SystemSetupCommandRunner(),
                plan: LocalHostingOwnershipPlan = .current) {
        self.runner = runner
        self.plan = plan
    }

    public func inspect() async throws -> LocalHostPreflight {
        try Task.checkCancellation()
        let listeners = try await inspectListeners()
        try Task.checkCancellation()
        let launchdService = try await inspectLaunchdService()
        try Task.checkCancellation()
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return LocalHostPreflight(
            computerName: ProcessInfo.processInfo.hostName,
            osVersion: "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)",
            architecture: Self.machineArchitecture(),
            launchdAvailable: Self.launchdAvailable(),
            administratorAccess: Self.hasAdministratorAccess(),
            freeBytes: try Self.freeBytes(),
            productPath: Self.resourceState(at: plan.productRootPath),
            launchdService: launchdService,
            listeners: listeners
        )
    }

    private func inspectListeners() async throws -> ListenerInspection {
        let tcp = try await listeningPorts(kind: "TCP")
        try Task.checkCancellation()
        let udp = try await listeningPorts(kind: "UDP")
        // Default lsof is process-scoped: system-owned listeners may be hidden without elevation.
        // Preflight never elevates, so only a privileged run may claim a complete table.
        if geteuid() == 0 {
            return .complete(tcpPorts: tcp, udpPorts: udp)
        }
        return .incomplete(
            tcpPorts: tcp,
            udpPorts: udp,
            detail: "lsof without elevated privileges cannot prove system-owned listeners.")
    }

    private func listeningPorts(kind: String) async throws -> [UInt16] {
        let arguments: [String] = kind == "TCP"
            ? ["-nP", "-iTCP", "-sTCP:LISTEN"]
            : ["-nP", "-iUDP"]
        let result = try await runner.run(SetupCommand(
            executable: "/usr/sbin/lsof",
            arguments: arguments,
            timeoutSeconds: 5,
            outputLimit: 65_536))
        // lsof exit 1 means "no matches" only when both streams are silent.
        if result.exitStatus == 1 {
            guard result.output.isEmpty, result.errorOutput.isEmpty else {
                throw HelicoidError.setupBlocked(reason: "Local preflight could not inspect listening \(kind) ports.")
            }
            return []
        }
        guard result.exitStatus == 0 else {
            throw HelicoidError.setupBlocked(reason: "Local preflight could not inspect listening \(kind) ports.")
        }
        return try LocalHostPreflight.ports(fromLsof: result.output)
    }

    private func inspectLaunchdService() async throws -> LaunchdServiceState {
        guard Self.launchdAvailable() else {
            return .unknown(detail: "launchctl is not present.")
        }
        let plist = Self.resourceState(at: plan.launchdPlistPath)
        let result = try await runner.run(SetupCommand(
            executable: "/bin/launchctl",
            arguments: ["print", "system/\(plan.launchdLabel)"],
            timeoutSeconds: 5,
            outputLimit: 65_536))
        let loaded: Bool
        if result.exitStatus == 0 {
            loaded = true
        } else {
            let message = String(decoding: result.errorOutput, as: UTF8.self) + String(decoding: result.output, as: UTF8.self)
            // "Could not find service" is an authoritative absent answer, not a failed inspection.
            guard message.contains("Could not find service") else {
                throw HelicoidError.setupBlocked(reason: "Local preflight could not inspect launchd service state.")
            }
            loaded = false
        }
        switch plist {
        case .absent where !loaded:
            return .absent
        case .unknown(let detail):
            return .unknown(detail: detail)
        case .absent, .present, .brokenSymlink:
            // A loaded job can outlive its plist; any resource at the planned path is a conflict.
            return .conflicting(plist: plist, loaded: loaded)
        }
    }

    /// `lstat` so dangling symlinks are visible; `fileExists` would report them absent.
    static func resourceState(at path: String) -> ResourceState {
        var info = stat()
        if lstat(path, &info) == 0 {
            if (info.st_mode & S_IFMT) == S_IFLNK {
                var target = stat()
                return stat(path, &target) == 0 ? .present : .brokenSymlink
            }
            return .present
        }
        if errno == ENOENT { return .absent }
        return .unknown(detail: "lstat errno \(errno)")
    }

    static func launchdAvailable() -> Bool {
        if case .present = resourceState(at: "/bin/launchctl") { return true }
        return false
    }

    static func machineArchitecture() -> String {
        var info = utsname()
        guard uname(&info) == 0 else { return "unknown" }
        return withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
    }

    static let maxGroups = 64

    static func hasAdministratorAccess() -> Bool {
        if geteuid() == 0 { return true }
        // 80 is the macOS admin group; 20 is staff, the usual primary group.
        let username = NSUserName()
        var groups = [gid_t](repeating: 0, count: maxGroups)
        var count = Int32(maxGroups)
        var status = username.withCString { getgrouplist($0, 20, &groups, &count) }
        if status < 0 {
            let needed = Int(count)
            guard needed > 0, needed <= maxGroups else { return false }
            groups = [gid_t](repeating: 0, count: needed)
            count = Int32(needed)
            status = username.withCString { getgrouplist($0, 20, &groups, &count) }
        }
        guard status >= 0, count > 0, count <= maxGroups else { return false }
        return groups.prefix(Int(count)).contains(80)
    }

    static func freeBytes() throws -> UInt64 {
        let root = URL(fileURLWithPath: "/")
        do {
            let values = try root.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey, .volumeAvailableCapacityKey])
            if let capacity = values.volumeAvailableCapacityForImportantUsage, capacity > 0 {
                return UInt64(capacity)
            }
            if let capacity = values.volumeAvailableCapacity, capacity > 0 {
                return UInt64(capacity)
            }
        } catch {
            throw HelicoidError.setupBlocked(reason: "Local preflight could not inspect free disk space.")
        }
        throw HelicoidError.setupBlocked(reason: "Local preflight could not inspect free disk space.")
    }
}

/// Local This Mac preflight boundary. Read-only; installation stays unavailable.
public struct LocalMacSetupClient: Sendable {
    private let inspector: any LocalHostingInspecting

    public init(inspector: any LocalHostingInspecting = SystemLocalHostingInspector()) {
        self.inspector = inspector
    }

    public func preflight() async throws -> LocalHostPreflight {
        try Task.checkCancellation()
        let result = try await inspector.inspect()
        try Task.checkCancellation()
        try result.validate()
        return result
    }
}
