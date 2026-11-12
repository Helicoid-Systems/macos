import Darwin
import Foundation
import Testing
@testable import HelicoidCore

// Real-host integration acceptance for the packaged development Manager.
//
// This file is intentionally inert unless a disposable GitHub-hosted macOS
// runner is explicitly configured by scripts/run-manager-server-acceptance.sh.
// It never runs on a developer machine and it never changes the production
// authorization path: the packaged LocalServerInstallClient still builds the
// real AppleScript `do shell script ... with administrator privileges`
// invocation, and only this test's SetupCommandRunning boundary translates that
// exact, already-constructed command into `sudo -n /bin/sh -c <same command>`.
//
// The acceptance script performs a read-only precheck and owns marker-protected
// cleanup because it can still run after a crash in the test process. The test
// independently proves the clean state using root lstat, explicit dscl
// record-not-found, and explicit launchd not-found, and only then writes the
// run-bound marker that authorizes cleanup.

private enum ManagerAcceptancePaths {
    static let backup = "/Library/Application Support/Helicoid-Backups"
    static let product = "/Library/Application Support/Helicoid"
    static let state = "/Library/Application Support/Helicoid-Installer"
    static let lock = "/Library/Application Support/Helicoid-Installer.lock"
    static let payload = "/Library/Application Support/Helicoid-Installer-Payload"
    static let tls = "/etc/helicoid"
    static let plist = "/Library/LaunchDaemons/com.helicoid.server.plist"
    static let launchdLabel = "com.helicoid.server"

    /// Paths that must be absent before the acceptance may start. The backup
    /// path is never created by this installer; it is checked so an unexpected
    /// directory is never silently adopted or deleted.
    static let cleanStatePaths = [backup, product, state, lock, payload, tls, plist]
}

struct ManagerAcceptanceFailure: Error, CustomStringConvertible, Sendable {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}

enum ManagerAcceptanceEnvironment {
    static let appVariable = "HELICOID_ACCEPTANCE_MANAGER_APP"
    static let keyVariable = "HELICOID_MACOS_DEV_TRUST_KEY"
    static let markerVariable = "HELICOID_MANAGER_ACCEPTANCE_MARKER"
    static let proofVariable = "HELICOID_MANAGER_ACCEPTANCE_PROOF"
    static let nonceVariable = "HELICOID_MANAGER_ACCEPTANCE_NONCE"
    static let branchRef = "refs/heads/codex/macos-native-combined"

    static var isEnabled: Bool {
        let environment = ProcessInfo.processInfo.environment
        guard environment["HELICOID_MANAGER_ACCEPTANCE"] == "1",
              environment["GITHUB_ACTIONS"] == "true",
              getuid() != 0,
              environment["RUNNER_ENVIRONMENT"] == "github-hosted",
              environment["GITHUB_REPOSITORY"] == "Helicoid-Systems/macos",
              environment["GITHUB_REF"] == branchRef,
              environment["CI"] == "true",
              let runnerTemp = environment["RUNNER_TEMP"],
              runnerTemp.hasPrefix("/"),
              let nonce = environment[nonceVariable],
              isNonce(nonce),
              let marker = environment[markerVariable],
              marker.hasPrefix("/"),
              let proof = environment[proofVariable],
              proof.hasPrefix("/"),
              let app = environment[appVariable],
              app.hasPrefix("/"),
              let key = environment[keyVariable],
              key.count == 64,
              key.allSatisfy(\.isHexDigit) else {
            return false
        }
        return FileManager.default.fileExists(
            atPath: app + "/Contents/MacOS/HelicoidManager")
    }

    struct Configuration {
        let appURL: URL
        let trustKeyHex: String
        let proofURL: URL
        let markerURL: URL
        let nonce: String
        let runID: String
        let runAttempt: String
    }

    static func require() throws -> Configuration {
        let environment = ProcessInfo.processInfo.environment
        guard environment["HELICOID_MANAGER_ACCEPTANCE"] == "1" else {
            throw ManagerAcceptanceFailure(
                "HELICOID_MANAGER_ACCEPTANCE is not 1; this privileged test is disabled.")
        }
        guard environment["GITHUB_ACTIONS"] == "true",
              getuid() != 0,
              environment["RUNNER_ENVIRONMENT"] == "github-hosted" else {
            throw ManagerAcceptanceFailure(
                "Privileged Manager acceptance requires a GitHub-hosted runner as the normal runner user.")
        }
        guard environment["GITHUB_REPOSITORY"] == "Helicoid-Systems/macos" else {
            throw ManagerAcceptanceFailure(
                "Privileged Manager acceptance is restricted to the trusted repository.")
        }
        guard environment["GITHUB_REF"] == branchRef else {
            throw ManagerAcceptanceFailure(
                "Privileged Manager acceptance requires the exact trusted branch ref.")
        }
        guard environment["CI"] == "true" else {
            throw ManagerAcceptanceFailure(
                "Privileged Manager acceptance requires CI=true.")
        }
        guard let runnerTemp = environment["RUNNER_TEMP"],
              runnerTemp.hasPrefix("/"),
              let nonce = environment[nonceVariable],
              isNonce(nonce),
              let marker = environment[markerVariable],
              marker.hasPrefix("/"),
              let runID = environment["GITHUB_RUN_ID"],
              !runID.isEmpty,
              runID.allSatisfy(\.isNumber),
              let runAttempt = environment["GITHUB_RUN_ATTEMPT"],
              !runAttempt.isEmpty,
              runAttempt.allSatisfy(\.isNumber) else {
            throw ManagerAcceptanceFailure(
                "The run-bound acceptance marker identity is missing or malformed.")
        }
        let expectedMarker = runnerTemp
            + "/helicoid-manager-acceptance-\(runID)-\(runAttempt)-\(nonce).clean"
        guard marker == expectedMarker else {
            throw ManagerAcceptanceFailure(
                "The marker path is not bound to this run and nonce.")
        }
        guard let proof = environment[proofVariable],
              proof.hasPrefix("/"),
              FileManager.default.fileExists(
                atPath: (proof as NSString).deletingLastPathComponent) else {
            throw ManagerAcceptanceFailure(
                "The proof path from run-manager-server-acceptance.sh is missing.")
        }
        guard let app = environment[appVariable],
              app.hasPrefix("/"),
              FileManager.default.fileExists(
                atPath: app + "/Contents/MacOS/HelicoidManager") else {
            throw ManagerAcceptanceFailure(
                "The packaged development Manager app is missing.")
        }
        guard let key = environment[keyVariable],
              key.count == 64,
              key.allSatisfy(\.isHexDigit) else {
            throw ManagerAcceptanceFailure(
                "The build-pinned development Ed25519 key is missing or malformed.")
        }
        return Configuration(
            appURL: URL(fileURLWithPath: app, isDirectory: true),
            trustKeyHex: key.lowercased(),
            proofURL: URL(fileURLWithPath: proof),
            markerURL: URL(fileURLWithPath: marker),
            nonce: nonce,
            runID: runID,
            runAttempt: runAttempt)
    }

    static func isNonce(_ value: String) -> Bool {
        value.count == 32
            && value == value.lowercased()
            && value.allSatisfy(\.isHexDigit)
    }

    static func markerContent(_ configuration: Configuration) -> String {
        [
            "helicoid-manager-acceptance-v1",
            "repository=Helicoid-Systems/macos",
            "branch=codex/macos-native-combined",
            "run_id=\(configuration.runID)",
            "run_attempt=\(configuration.runAttempt)",
            "nonce=\(configuration.nonce)",
        ].joined(separator: "\n")
    }
}

enum ManagerAcceptancePathKind: String {
    case absent
    case file
    case directory
    case symlink
    case other
    case unknown
}

enum ManagerAcceptancePresence: String {
    case absent
    case present
    case unknown
}

enum ManagerAcceptanceHost {
    static func requireCleanAndEstablishMarker(
        configuration: ManagerAcceptanceEnvironment.Configuration
    ) throws {
        let sudo = try process("/usr/bin/sudo", ["-n", "/usr/bin/true"])
        guard sudo.status == 0 else {
            throw ManagerAcceptanceFailure(
                "Passwordless sudo is required on the disposable runner.")
        }

        for path in ManagerAcceptancePaths.cleanStatePaths {
            let kind = try rootPathKind(path)
            guard kind == .absent else {
                throw ManagerAcceptanceFailure(
                    "Refusing to adopt a resource at \(path): \(kind.rawValue).")
            }
        }
        let user = try recordPresence("Users/_helicoid")
        guard user == .absent else {
            throw ManagerAcceptanceFailure(
                "The _helicoid user is not proven absent: \(user.rawValue).")
        }
        let group = try recordPresence("Groups/_helicoid")
        guard group == .absent else {
            throw ManagerAcceptanceFailure(
                "The _helicoid group is not proven absent: \(group.rawValue).")
        }
        let service = try servicePresence()
        guard service == .absent else {
            throw ManagerAcceptanceFailure(
                "The launchd job is not proven absent: \(service.rawValue).")
        }

        let markerPath = configuration.markerURL.path
        let markerKind = try rootPathKind(markerPath)
        guard markerKind == .absent else {
            throw ManagerAcceptanceFailure(
                "The run-bound marker path is not absent: \(markerKind.rawValue).")
        }
        let content = ManagerAcceptanceEnvironment.markerContent(configuration)
        do {
            try Data(content.utf8).write(to: configuration.markerURL, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: 0o600)],
                ofItemAtPath: markerPath)
        } catch {
            try? FileManager.default.removeItem(at: configuration.markerURL)
            throw ManagerAcceptanceFailure(
                "The run-bound clean-state marker could not be written.")
        }
        var info = stat()
        guard lstat(markerPath, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(),
              (info.st_mode & 0o777) == 0o600,
              (try? String(contentsOf: configuration.markerURL, encoding: .utf8)) == content else {
            try? FileManager.default.removeItem(at: configuration.markerURL)
            throw ManagerAcceptanceFailure(
                "The run-bound clean-state marker is not a runner-owned 0600 regular file with the expected content.")
        }
    }

    private static func rootPathKind(_ path: String) throws -> ManagerAcceptancePathKind {
        let code = """
        import os
        import stat
        import sys

        try:
            info = os.lstat(sys.argv[1])
        except FileNotFoundError:
            print("absent")
            raise SystemExit(0)
        except OSError:
            print("unknown")
            raise SystemExit(0)

        mode = info.st_mode
        if stat.S_ISREG(mode):
            print("file")
        elif stat.S_ISDIR(mode):
            print("directory")
        elif stat.S_ISLNK(mode):
            print("symlink")
        else:
            print("other")
        """
        let result = try process(
            "/usr/bin/sudo",
            ["-n", "/usr/bin/python3", "-c", code, path])
        let value = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let kind = ManagerAcceptancePathKind(rawValue: value) else {
            throw ManagerAcceptanceFailure(
                "The root state of \(path) could not be determined.")
        }
        return kind
    }

    private static func recordPresence(_ record: String) throws -> ManagerAcceptancePresence {
        let result = try process(
            "/usr/bin/sudo",
            ["-n", "/usr/bin/dscl", ".", "-read", "/\(record)"])
        if result.status == 0 { return .present }
        if result.status == 56,
           result.output.contains("eDSRecordNotFound") {
            return .absent
        }
        return .unknown
    }

    private static func servicePresence() throws -> ManagerAcceptancePresence {
        let result = try process(
            "/usr/bin/sudo",
            ["-n", "/bin/launchctl", "print", "system/\(ManagerAcceptancePaths.launchdLabel)"])
        if result.status == 0 { return .present }
        if result.output.contains("Could not find service") { return .absent }
        return .unknown
    }

    /// Read-only verification that the installed launchd service actually
    /// started. The installer status is still the authoritative operation
    /// result; this only proves the host effect was real.
    static func launchdRunning() async throws -> Bool {
        for attempt in 0..<10 {
            if try launchdRunningOnce() { return true }
            if attempt < 9 {
                try await Task.sleep(for: .milliseconds(500))
            }
        }
        return false
    }

    private static func launchdRunningOnce() throws -> Bool {
        let result = try process(
            "/usr/bin/sudo",
            ["-n", "/bin/launchctl", "print", "system/\(ManagerAcceptancePaths.launchdLabel)"])
        return result.status == 0 && result.output.contains("state = running")
    }

    private static func process(
        _ executable: String,
        _ arguments: [String]
    ) throws -> (status: Int32, output: String) {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: executable)
        child.arguments = arguments
        let output = Pipe()
        child.standardOutput = output
        child.standardError = output
        do {
            try child.run()
        } catch {
            throw ManagerAcceptanceFailure("Could not start \(executable): \(error)")
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        child.waitUntilExit()
        return (child.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}

/// Reverses exactly the AppleScript string literal produced by
/// `PrivilegedHelperInvocation.appleScriptLiteral`. Any other shape is refused,
/// so this test cannot accidentally execute a different command.
enum ManagerAcceptanceAppleScript {
    static func shellCommand(from script: String) throws -> String {
        let prefix = "do shell script \""
        let suffix = "\" with administrator privileges"
        guard script.hasPrefix(prefix), script.hasSuffix(suffix) else {
            throw ManagerAcceptanceFailure(
                "The client did not produce the expected administrator-privileges wrapper.")
        }
        let literal = script.dropFirst(prefix.count).dropLast(suffix.count)
        var command = String()
        command.reserveCapacity(literal.utf8.count)
        var index = literal.startIndex
        while index < literal.endIndex {
            let character = literal[index]
            if character == "\\" {
                let escapedIndex = literal.index(after: index)
                guard escapedIndex < literal.endIndex else {
                    throw ManagerAcceptanceFailure("The AppleScript literal ends with an escape.")
                }
                let escaped = literal[escapedIndex]
                guard escaped == "\\" || escaped == "\"" else {
                    throw ManagerAcceptanceFailure(
                        "The AppleScript literal contains an unexpected escape.")
                }
                command.append(escaped)
                index = literal.index(after: escapedIndex)
                continue
            }
            guard character != "\"" else {
                throw ManagerAcceptanceFailure(
                    "The AppleScript literal contains an unescaped quote.")
            }
            guard String(character).unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F }) else {
                throw ManagerAcceptanceFailure(
                    "The AppleScript literal contains an unsupported control character.")
            }
            command.append(character)
            index = literal.index(after: index)
        }
        guard !command.isEmpty else {
            throw ManagerAcceptanceFailure("The administrator-privileges wrapper is empty.")
        }
        return command
    }
}

/// Test-only authorization translation. The production invocation is created
/// unchanged by LocalServerInstallClient; this seam replaces only the
/// osascript process with the exact same shell command under passwordless sudo.
struct ManagerAcceptanceSudoRunner: SetupCommandRunning {
    private let system = SystemSetupCommandRunner()

    init() {}

    func run(_ command: SetupCommand) async throws -> SetupCommandResult {
        if command.executable == "/usr/bin/osascript" {
            guard command.arguments.count == 2,
                  command.arguments[0] == "-e",
                  command.input.isEmpty else {
                throw SetupCommandError.launchFailed
            }
            let shellCommand = try ManagerAcceptanceAppleScript.shellCommand(
                from: command.arguments[1])
            let translated = SetupCommand(
                executable: "/usr/bin/sudo",
                arguments: ["-n", "/bin/sh", "-c", shellCommand],
                input: Data(),
                timeoutSeconds: command.timeoutSeconds,
                outputLimit: command.outputLimit)
            return try await system.run(translated)
        }
        // Capabilities and TLS generation are the only non-privileged direct
        // commands the packaged client runs.
        guard command.executable == "/usr/bin/env"
            || command.executable == "/usr/bin/openssl" else {
            throw SetupCommandError.launchFailed
        }
        return try await system.run(command)
    }
}

private func managerAcceptanceDevelopmentBuild(
    configuration: ManagerAcceptanceEnvironment.Configuration
) throws -> ServerDevelopmentBuild {
    let infoURL = configuration.appURL
        .appendingPathComponent("Contents", isDirectory: true)
        .appendingPathComponent("Info.plist")
    let data: Data
    do {
        data = try Data(contentsOf: infoURL)
    } catch {
        throw ManagerAcceptanceFailure(
            "The packaged development Manager Info.plist could not be read.")
    }
    guard let object = try? PropertyListSerialization.propertyList(from: data, format: nil),
          let info = object as? [String: Any] else {
        throw ManagerAcceptanceFailure(
            "The packaged development Manager Info.plist could not be parsed.")
    }
    let requested = (info["HelicoidServerDevelopmentInstall"] as? NSNumber)?.boolValue
        ?? (info["HelicoidServerDevelopmentInstall"] as? Bool)
        ?? false
    guard requested,
          let pinnedKey = info["HelicoidServerDevelopmentTrustKey"] as? String,
          pinnedKey.lowercased() == configuration.trustKeyHex,
          (info["CFBundleIdentifier"] as? String) == "systems.helicoid.manager.dev" else {
        throw ManagerAcceptanceFailure(
            "The packaged Manager is not the development build with the expected trust pin.")
    }
    return ServerDevelopmentBuild(
        isRequested: true,
        pinnedTrustKeyHex: pinnedKey)
}

private func managerAcceptanceProvider(
    configuration: ManagerAcceptanceEnvironment.Configuration
) throws -> BundledServerPackageProvider {
    BundledServerPackageProvider(
        rootURL: configuration.appURL,
        developmentBuild: try managerAcceptanceDevelopmentBuild(configuration: configuration),
        releaseTrust: .production)
}

private func managerAcceptancePackage(
    from provider: BundledServerPackageProvider
) throws -> TrustedServerPackage {
    switch provider.availability() {
    case .available(let package):
        return package
    case .unavailable(let reason), .invalid(let reason):
        throw ManagerAcceptanceFailure(
            "The packaged development Manager package is not available: \(reason)")
    }
}

private func managerAcceptanceConfiguration() -> InstallerDeploymentConfiguration {
    .macos(
        authorityPort: 8920,
        backupDirectory: ManagerAcceptancePaths.backup)
}

@Suite(
    "Manager server install acceptance",
    .serialized,
    .enabled(if: ManagerAcceptanceEnvironment.isEnabled))
struct ManagerServerInstallAcceptanceTests {
    @Test("Packaged development Manager provider installs through the real LocalServerInstallClient")
    func packagedDevelopmentManagerClient() async throws {
        let configuration = try ManagerAcceptanceEnvironment.require()
        try ManagerAcceptanceHost.requireCleanAndEstablishMarker(configuration: configuration)

        let provider = try managerAcceptanceProvider(configuration: configuration)
        #expect(provider.payloadKind == .development)
        let package = try managerAcceptancePackage(from: provider)
        let hostTarget = try ServerInstallTarget.current()
        #expect(package.isDevelopment)
        #expect(package.provenance == .development)
        #expect(package.product == "hs-server")
        #expect(package.target == hostTarget)
        let expectedHelperURL = configuration.appURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("Helpers", isDirectory: true)
            .appendingPathComponent("hs-server")
        #expect(package.helperURL.standardizedFileURL.path
            == expectedHelperURL.standardizedFileURL.path)

        let client = LocalServerInstallClient(
            helperURL: package.helperURL,
            runner: ManagerAcceptanceSudoRunner())
        let deployment = managerAcceptanceConfiguration()

        let capabilities = try await client.capabilities(package: package)
        #expect(capabilities.contractVersion == ServerInstallContract.lifecycleVersion)
        #expect(capabilities.supportsMacOSInstall)
        #expect(capabilities.supportedActions.contains("install"))

        let preflight = try await client.preflight(
            configuration: deployment,
            package: package)
        #expect(preflight.contractVersion == ServerInstallContract.lifecycleVersion)
        #expect(preflight.configuration == deployment)
        #expect(preflight.ok)
        #expect(preflight.hostChecks.ok)
        #expect(preflight.hostChecks.checks.privileges.isRoot)
        #expect(preflight.capabilities.supportsMacOSInstall)

        let tls = try await client.provisionDevelopmentTLSIfNeeded()
        #expect(tls == .provisioned)

        let plan = try await client.plan(
            configuration: deployment,
            preflight: preflight,
            package: package)
        #expect(plan.contractVersion == ServerInstallContract.lifecycleVersion)
        #expect(plan.configuration == deployment)
        #expect(plan.ok, "\(plan.error ?? "plan failed") \(plan.warnings.joined(separator: " "))")
        #expect(plan.plan?.product == "hs-server")
        #expect(plan.reviewedPlanDigest?.count == 64)

        let applied = try await client.apply(
            configuration: deployment,
            preflight: preflight,
            plan: plan,
            package: package)
        #expect(applied.contractVersion == ServerInstallContract.lifecycleVersion)
        #expect(applied.configuration == deployment)
        #expect(applied.state == "completed")
        #expect(applied.serviceInstalled)
        #expect(applied.result.code == "installed")
        #expect(applied.operationId != nil)
        #expect(applied.reviewedPlanDigest == plan.reviewedPlanDigest)
        // The private loopback server is installed but bootstrap/enrollment is a
        // separate operation and must not be claimed here.
        #expect(applied.bootstrapReady == false)
        #expect(applied.serverReadyForEnrollment == false)
        let serviceRunning = try await ManagerAcceptanceHost.launchdRunning()
        #expect(serviceRunning)

        let status = try await client.status(
            configuration: deployment,
            package: package)
        #expect(status.configuration == deployment)
        #expect(status.state == "completed")
        #expect(status.serviceInstalled)
        #expect(status.result.code == "installed")
        #expect(status.operationId == applied.operationId)

        let stored = try await client.storedConfiguration(package: package)
        #expect(stored == deployment)
        try Data("client\n".utf8).write(to: configuration.proofURL, options: .atomic)
    }
}

@Suite(
    "Manager server setup model acceptance",
    .serialized,
    .enabled(if: ManagerAcceptanceEnvironment.isEnabled))
struct ManagerServerModelAcceptanceTests {
    @Test("Packaged development Manager setup model drives the real install lifecycle")
    @MainActor
    func packagedDevelopmentManagerModel() async throws {
        let configuration = try ManagerAcceptanceEnvironment.require()
        try ManagerAcceptanceHost.requireCleanAndEstablishMarker(configuration: configuration)

        let provider = try managerAcceptanceProvider(configuration: configuration)
        #expect(provider.payloadKind == .development)
        _ = try managerAcceptancePackage(from: provider)

        let service = BundledServerInstallService(
            provider: provider,
            runner: ManagerAcceptanceSudoRunner())
        let store = ManagerAcceptanceConfigurationStore()
        let model = GuidedServerSetupModel(
            managerIdentityStore: ManagerIdentityStore(
                keyStore: ManagerAcceptanceIdentityKeyStore()),
            installService: service,
            configurationStore: store,
            demoMode: false)

        #expect(model.isRealInstallPathEnabled)
        #expect(model.installPayloadKind == .development)
        #expect(model.isDevelopmentInstall)
        #expect(model.canCheckInstallStatus)

        model.setRoute(.thisMac)
        model.setStoragePath(ServerInstallContract.fixedDataDirectory)
        model.setBackupDestination(ManagerAcceptancePaths.backup)
        model.setProductPort("8920")
        model.advance()
        #expect(model.phase == .checkHost)
        for check in GuidedServerSetupModel.requiredLocalChecks {
            model.setHostCheck(check, status: .passed)
        }
        model.advance()
        #expect(model.phase == .network)
        model.advance()
        #expect(model.phase == .deploymentIdentity)
        model.setDeploymentName("CI local server")
        model.advance()
        #expect(model.phase == .administrator)
        model.setAdministratorUsername("ciadmin")
        model.advance()
        #expect(model.phase == .storage)
        model.advance()
        #expect(model.phase == .review)
        #expect(model.reviewedInstallConfiguration == managerAcceptanceConfiguration())
        model.advance()
        #expect(model.phase == .install)
        #expect(model.installAction == .start)

        await model.startInstallation()

        switch model.installProgress {
        case .installedUnverified:
            break
        default:
            Issue.record(
                "Expected installedUnverified, got \(model.installProgressExplanation) (\(model.blocker ?? "no blocker"))")
        }
        #expect(model.installStatus?.state == "completed")
        #expect(model.installStatus?.serviceInstalled == true)
        #expect(model.installStatus?.result.code == "installed")
        #expect(model.installStatus?.bootstrapReady == false)
        #expect(model.installStatus?.serverReadyForEnrollment == false)
        #expect(model.installStatusSummary?.isEmpty == false)
        #expect(model.installAction == .refreshStatus)
        let serviceRunning = try await ManagerAcceptanceHost.launchdRunning()
        #expect(serviceRunning)

        await model.refreshInstallStatus()
        #expect(model.installStatus?.state == "completed")
        #expect(model.installStatus?.serviceInstalled == true)
        #expect(model.installStatus?.result.code == "installed")
        #expect(store.load() == managerAcceptanceConfiguration())
        try Data("model\n".utf8).write(to: configuration.proofURL, options: .atomic)
    }
}

private actor ManagerAcceptanceIdentityKeyStore: ManagerIdentityKeyStoring {
    private var bytes: Data?

    init() {}

    func read() async throws -> Data? { bytes }

    func insertIfAbsent(_ bytes: Data) async throws -> Bool {
        guard self.bytes == nil else { return false }
        self.bytes = bytes
        return true
    }
}

private final class ManagerAcceptanceConfigurationStore: ServerInstallConfigurationStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var value: InstallerDeploymentConfiguration?

    init() {}

    func load() -> InstallerDeploymentConfiguration? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func save(_ configuration: InstallerDeploymentConfiguration) throws {
        lock.lock()
        defer { lock.unlock() }
        value = configuration
    }
}
