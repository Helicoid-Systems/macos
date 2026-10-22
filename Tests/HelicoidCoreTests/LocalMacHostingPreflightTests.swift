import Foundation
import Darwin
import Testing
@testable import HelicoidCore

private actor StubLocalInspector: LocalHostingInspecting {
    enum Behavior {
        case facts(LocalHostPreflight)
        case failure(any Error)
        case slow(LocalHostPreflight, delayNanoseconds: UInt64)
    }

    let behavior: Behavior
    private(set) var inspectCount = 0

    init(_ behavior: Behavior) { self.behavior = behavior }

    func inspect() async throws -> LocalHostPreflight {
        inspectCount += 1
        switch behavior {
        case .facts(let preflight):
            return preflight
        case .failure(let error):
            throw error
        case .slow(let preflight, let delayNanoseconds):
            try await Task.sleep(nanoseconds: delayNanoseconds)
            try Task.checkCancellation()
            return preflight
        }
    }
}

private actor FixtureCommandRunner: SetupCommandRunning {
    struct Key: Hashable {
        let executable: String
        let arguments: [String]
    }

    let responses: [Key: SetupCommandResult]
    private(set) var commands: [SetupCommand] = []

    init(_ responses: [Key: SetupCommandResult]) { self.responses = responses }

    func run(_ command: SetupCommand) async throws -> SetupCommandResult {
        commands.append(command)
        let key = Key(executable: command.executable, arguments: command.arguments)
        guard let result = responses[key] else {
            throw HelicoidError.setupBlocked(reason: "Unexpected command \(command.executable)")
        }
        return result
    }
}

private func lsofKey(_ kind: String) -> FixtureCommandRunner.Key {
    let arguments = kind == "TCP" ? ["-nP", "-iTCP", "-sTCP:LISTEN"] : ["-nP", "-iUDP"]
    return .init(executable: "/usr/sbin/lsof", arguments: arguments)
}

private let launchdKey = FixtureCommandRunner.Key(
    executable: "/bin/launchctl", arguments: ["print", "system/com.helicoid.server"])

private let healthyFacts = LocalHostPreflight(
    computerName: "lab-mac",
    osVersion: "27.0.1",
    architecture: "arm64",
    launchdAvailable: true,
    administratorAccess: true,
    freeBytes: 8_000_000_000,
    productPath: .absent,
    launchdService: .absent,
    listeners: .complete(tcpPorts: [22, 7000], udpPorts: [5353])
)

private func facts(
    productPath: ResourceState = .absent,
    launchdAvailable: Bool = true,
    launchdService: LaunchdServiceState = .absent,
    listeners: ListenerInspection = .complete(tcpPorts: [22, 7000], udpPorts: [5353]),
    freeBytes: UInt64 = 8_000_000_000
) -> LocalHostPreflight {
    LocalHostPreflight(
        computerName: "lab-mac",
        osVersion: "27.0.1",
        architecture: "arm64",
        launchdAvailable: launchdAvailable,
        administratorAccess: true,
        freeBytes: freeBytes,
        productPath: productPath,
        launchdService: launchdService,
        listeners: listeners
    )
}

@Suite("Local Mac hosting preflight")
struct LocalMacHostingPreflightTests {
    @Test("Unrelated listeners do not reserve the retired engine ports")
    func unrelatedLegacyListenersDoNotBlockAuthorityHosting() {
        let host = facts(listeners: .complete(tcpPorts: [80, 443, 21115, 21116, 21117], udpPorts: [21116]))
        #expect(host.checks()["Product ports"] == .passed)
        #expect(host.checks(authorityPort: 21115)["Product ports"] != .passed)
    }

    @Test("Healthy facts pass every required local check")
    func healthyChecksPass() throws {
        try healthyFacts.validate()
        let checks = healthyFacts.checks()
        for name in GuidedServerSetupModel.requiredLocalChecks {
            #expect(checks[name] == .passed, "expected \(name) to pass")
        }
    }

    @Test("OS, privilege, disk, path, service and port conflicts need attention")
    func conflictsNeedAttention() {
        let conflicted = LocalHostPreflight(
            computerName: "lab-mac",
            osVersion: "14.0",
            architecture: "ppc64",
            launchdAvailable: true,
            administratorAccess: false,
            freeBytes: 1_000,
            productPath: .present,
            launchdService: .conflicting(plist: .present, loaded: true),
            listeners: .complete(tcpPorts: [8920, 21116], udpPorts: [21116])
        )
        let checks = conflicted.checks()
        for name in GuidedServerSetupModel.requiredLocalChecks {
            #expect(checks[name] != .passed, "expected \(name) to block")
        }
        if case .needsAttention(let detail) = checks["Product path"] {
            #expect(detail.contains(LocalHostingOwnershipPlan.current.productRootPath))
        } else {
            Issue.record("Product path should name the ownership plan path")
        }
        if case .needsAttention(let detail) = checks["Service manager"] {
            #expect(detail.contains(LocalHostingOwnershipPlan.current.launchdLabel))
        } else {
            Issue.record("Service manager should name the launchd label")
        }
    }

    @Test("Missing launchd blocks service manager")
    func missingLaunchdBlocks() {
        #expect(facts(launchdAvailable: false).checks()["Service manager"] != .passed)
    }

    @Test("Unknown required facts block rather than pass")
    func unknownFactsBlock() {
        let cases: [(LocalHostPreflight, String)] = [
            (facts(productPath: .unknown(detail: "lstat errno 13")), "Product path"),
            (facts(launchdService: .unknown(detail: "launchctl refused")), "Service manager"),
            (facts(listeners: .incomplete(tcpPorts: [], udpPorts: [], detail: "process-scoped lsof")), "Product ports"),
            (facts(productPath: .brokenSymlink), "Product path"),
            (facts(launchdService: .conflicting(plist: .absent, loaded: true)), "Service manager"),
        ]
        for (preflight, blockedName) in cases {
            let checks = preflight.checks()
            #expect(checks[blockedName] != .passed, "\(blockedName) must not pass with an unknown or conflicting fact")
        }
    }

    @Test("Broken symlink is a path conflict, not an absence")
    func brokenSymlinkIsConflict() {
        #expect(facts(productPath: .brokenSymlink).checks()["Product path"] != .passed)
        #expect(facts(launchdService: .conflicting(plist: .brokenSymlink, loaded: false)).checks()["Service manager"] != .passed)
    }

    @Test("Loaded launchd service without plist is a conflict")
    func loadedWithoutPlistIsConflict() {
        let state = facts(launchdService: .conflicting(plist: .absent, loaded: true))
        #expect(state.checks()["Service manager"] != .passed)
    }

    @Test("Incomplete listener inspection never clears product ports")
    func incompleteListenersBlock() {
        let state = facts(listeners: .incomplete(tcpPorts: [], udpPorts: [], detail: "cannot prove system-owned listeners"))
        #expect(state.checks()["Product ports"] != .passed)
    }

    @Test("lsof parser extracts TCP and UDP ports")
    func lsofParser() throws {
        let sample = Data("""
        COMMAND     PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
        ControlCe   660 barni    9u  IPv4 0xe4a7340f71b8c645      0t0  TCP *:7000 (LISTEN)
        ControlCe   660 barni   10u  IPv6 0x8a78f78a03a26194      0t0  TCP 127.0.0.1:8920 (LISTEN)
        identitys   689 barni   13u  IPv4 0xbd7cb8449ac1f65b      0t0  UDP *:*
        rapportd    674 barni   26u  IPv4 0xbfe85986d7c383e4      0t0  UDP *:3722
        browser     700 barni   20u  IPv6 0x1fc0a2f408f26d45      0t0  TCP [::1]:21115 (LISTEN)
        """.utf8)
        #expect(try LocalHostPreflight.ports(fromLsof: sample) == [3722, 7000, 8920, 21115])
    }

    @Test("lsof parser refuses malformed rows instead of skipping them")
    func lsofParserRejectsMalformed() {
        for sample in [
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nnot-a-socket-row\n",
            "COMMAND PID USER\nTCP\n",
            "COMMAND PID USER\nTCP *:notaport\n",
            "COMMAND PID USER\nUDP 127.0.0.1:99999\n",
            "COMMAND PID USER\nTCP localhost\n",
        ] {
            #expect(throws: HelicoidError.self) {
                try LocalHostPreflight.ports(fromLsof: Data(sample.utf8))
            }
        }
    }

    @Test("Invalid preflight payload refuses rather than passes checks")
    func invalidPayloadRefuses() async {
        let emptyName = LocalHostPreflight(
            computerName: "",
            osVersion: "27.0.1",
            architecture: "arm64",
            launchdAvailable: true,
            administratorAccess: true,
            freeBytes: 8_000_000_000,
            productPath: .absent,
            launchdService: .absent,
            listeners: .complete(tcpPorts: [], udpPorts: [])
        )
        await #expect(throws: HelicoidError.self) {
            try await LocalMacSetupClient(inspector: StubLocalInspector(.facts(emptyName))).preflight()
        }
        let oversized = LocalHostPreflight(
            computerName: String(repeating: "x", count: LocalHostPreflight.computerNameMaxUTF8 + 1),
            osVersion: "27.0.1",
            architecture: "arm64",
            launchdAvailable: true,
            administratorAccess: true,
            freeBytes: 8_000_000_000,
            productPath: .absent,
            launchdService: .absent,
            listeners: .complete(tcpPorts: [], udpPorts: [])
        )
        await #expect(throws: HelicoidError.self) {
            try await LocalMacSetupClient(inspector: StubLocalInspector(.facts(oversized))).preflight()
        }
        let duplicated = LocalHostPreflight(
            computerName: "lab-mac",
            osVersion: "27.0.1",
            architecture: "arm64",
            launchdAvailable: true,
            administratorAccess: true,
            freeBytes: 8_000_000_000,
            productPath: .absent,
            launchdService: .absent,
            listeners: .complete(tcpPorts: [8920, 8920], udpPorts: [])
        )
        await #expect(throws: HelicoidError.self) {
            try await LocalMacSetupClient(inspector: StubLocalInspector(.facts(duplicated))).preflight()
        }
    }

    @Test("Long legitimate hostnames validate; display truncation is not identity")
    func longHostnameValidates() throws {
        // Real CI/OS hostnames can exceed the old 64-byte product-friendly-name bound.
        let longName = "runner-" + String(repeating: "a", count: 200) + ".ci.example.internal"
        #expect(longName.utf8.count > 64)
        #expect(longName.utf8.count <= LocalHostPreflight.computerNameMaxUTF8)
        let preflight = LocalHostPreflight(
            computerName: longName,
            osVersion: "27.0.1",
            architecture: "arm64",
            launchdAvailable: true,
            administratorAccess: true,
            freeBytes: 8_000_000_000,
            productPath: .absent,
            launchdService: .absent,
            listeners: .complete(tcpPorts: [22], udpPorts: [5353])
        )
        try preflight.validate()
        let display = LocalHostPreflight.displayComputerName(longName)
        #expect(display.utf8.count <= LocalHostPreflight.computerNameDisplayMaxUTF8)
        #expect(display.hasSuffix("…"))
        #expect(LocalHostPreflight.displayComputerName("lab-mac") == "lab-mac")
    }

    @Test("Inspector failure surfaces as setup block")
    func inspectorFailure() async {
        let client = LocalMacSetupClient(inspector: StubLocalInspector(
            .failure(HelicoidError.setupBlocked(reason: "Local preflight could not inspect listening TCP ports."))))
        await #expect(throws: HelicoidError.self) {
            try await client.preflight()
        }
    }

    @Test("lsof exit 1 with stderr refuses empty-stdout acceptance")
    func lsofExitOneWithStderrRefuses() async {
        let runner = FixtureCommandRunner([
            lsofKey("TCP"): SetupCommandResult(exitStatus: 1, output: Data(), errorOutput: Data("permission denied\n".utf8)),
            lsofKey("UDP"): SetupCommandResult(exitStatus: 0, output: Data("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n".utf8)),
            launchdKey: SetupCommandResult(exitStatus: 1, output: Data(), errorOutput: Data("Bad request.\nCould not find service \"com.helicoid.server\" in domain for system\n".utf8)),
        ])
        await #expect(throws: HelicoidError.self) {
            try await SystemLocalHostingInspector(runner: runner).inspect()
        }
    }

    @Test("lsof exit 1 silent empty means no listeners")
    func lsofSilentEmptyIsAbsent() async throws {
        let silent = SetupCommandResult(exitStatus: 1, output: Data(), errorOutput: Data())
        let runner = FixtureCommandRunner([
            lsofKey("TCP"): silent,
            lsofKey("UDP"): silent,
            launchdKey: SetupCommandResult(exitStatus: 1, output: Data(), errorOutput: Data("Could not find service \"com.helicoid.server\" in domain for system\n".utf8)),
        ])
        let result = try await SystemLocalHostingInspector(runner: runner).inspect()
        #expect(result.listeners.tcpPorts.isEmpty)
        #expect(result.launchdService == .absent)
        #expect(result.launchdAvailable == SystemLocalHostingInspector.launchdAvailable())
    }

    @Test("lsof malformed output refuses inspection")
    func lsofMalformedOutputRefuses() async {
        let runner = FixtureCommandRunner([
            lsofKey("TCP"): SetupCommandResult(exitStatus: 0, output: Data("COMMAND PID\nbroken-row\n".utf8)),
            lsofKey("UDP"): SetupCommandResult(exitStatus: 1, output: Data(), errorOutput: Data()),
            launchdKey: SetupCommandResult(exitStatus: 1, output: Data(), errorOutput: Data("Could not find service\n".utf8)),
        ])
        await #expect(throws: HelicoidError.self) {
            try await SystemLocalHostingInspector(runner: runner).inspect()
        }
    }

    @Test("launchctl unexpected failure refuses inspection")
    func launchctlUnexpectedFailureRefuses() async {
        let emptyListen = SetupCommandResult(exitStatus: 1, output: Data(), errorOutput: Data())
        let runner = FixtureCommandRunner([
            lsofKey("TCP"): emptyListen,
            lsofKey("UDP"): emptyListen,
            launchdKey: SetupCommandResult(exitStatus: 5, output: Data(), errorOutput: Data("Bootstrap error\n".utf8)),
        ])
        await #expect(throws: HelicoidError.self) {
            try await SystemLocalHostingInspector(runner: runner).inspect()
        }
    }

    @Test("launchctl loaded service is a conflict even without plist")
    func launchctlLoadedWithoutPlist() async throws {
        let emptyListen = SetupCommandResult(exitStatus: 1, output: Data(), errorOutput: Data())
        let runner = FixtureCommandRunner([
            lsofKey("TCP"): emptyListen,
            lsofKey("UDP"): emptyListen,
            launchdKey: SetupCommandResult(exitStatus: 0, output: Data("system/com.helicoid.server = {\n}\n".utf8)),
        ])
        // Paths are absent by construction; loaded-without-plist must still conflict.
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("helicoid-launchd-\(UUID().uuidString)", isDirectory: true)
        let plan = LocalHostingOwnershipPlan(
            productRootPath: scratch.appendingPathComponent("no-product").path,
            dataPath: scratch.appendingPathComponent("no-product/Data").path,
            launchdLabel: "com.helicoid.server",
            launchdPlistPath: scratch.appendingPathComponent("no-product.plist").path
        )
        let result = try await SystemLocalHostingInspector(runner: runner, plan: plan).inspect()
        #expect(result.launchdService == .conflicting(plist: .absent, loaded: true))
        #expect(result.checks(plan: plan)["Service manager"] != .passed)
    }

    @Test("resourceState uses lstat so dangling symlinks are conflicts")
    func resourceStateDetectsDanglingSymlink() throws {
        // Unique owned directory under the process temporary root; cleanup only this directory.
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("helicoid-resource-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let link = dir.appendingPathComponent("dangling-link")
        let missingTarget = dir.appendingPathComponent("no-such-target")
        #expect(symlink(missingTarget.path, link.path) == 0)
        #expect(SystemLocalHostingInspector.resourceState(at: link.path) == .brokenSymlink)
        #expect(SystemLocalHostingInspector.resourceState(at: dir.appendingPathComponent("absent").path) == .absent)
        #expect(SystemLocalHostingInspector.resourceState(at: "/") == .present)
    }

    @Test("getgrouplist stays inside the configured bound")
    func getgrouplistBounded() {
        #expect(SystemLocalHostingInspector.maxGroups == 64)
        var groups = [gid_t](repeating: 0, count: SystemLocalHostingInspector.maxGroups)
        var count = Int32(groups.count)
        let name = NSUserName()
        let status = name.withCString { getgrouplist($0, 20, &groups, &count) }
        let listedAdmin = status >= 0 && count > 0 && count <= SystemLocalHostingInspector.maxGroups
            && groups.prefix(Int(count)).contains(80)
        #expect(SystemLocalHostingInspector.hasAdministratorAccess() == (geteuid() == 0 || listedAdmin))
    }

    @Test("Non-elevated listener inspection is explicitly incomplete")
    func nonElevatedListenersIncomplete() async throws {
        let row = Data("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nrapportd 1 barni 3u IPv4 0x1 0t0 UDP *:3722\n".utf8)
        let runner = FixtureCommandRunner([
            lsofKey("TCP"): SetupCommandResult(exitStatus: 1, output: Data(), errorOutput: Data()),
            lsofKey("UDP"): SetupCommandResult(exitStatus: 0, output: row),
            launchdKey: SetupCommandResult(exitStatus: 1, output: Data(), errorOutput: Data("Could not find service \"com.helicoid.server\" in domain for system\n".utf8)),
        ])
        let result = try await SystemLocalHostingInspector(runner: runner).inspect()
        if geteuid() == 0 {
            #expect(result.listeners.isComplete)
        } else {
            #expect(!result.listeners.isComplete)
            #expect(result.checks()["Product ports"] != .passed)
        }
    }

    @Test("Cancellation stops an in-flight local preflight")
    func cancellationStopsPreflight() async {
        let inspector = StubLocalInspector(.slow(healthyFacts, delayNanoseconds: 2_000_000_000))
        let client = LocalMacSetupClient(inspector: inspector)
        let operation = Task {
            try await client.preflight()
        }
        operation.cancel()
        await #expect(throws: (any Error).self) { try await operation.value }
    }

    @Test("This Mac route skips SSH phases and blocks on unknown checks")
    @MainActor
    func thisMacRouteSelection() {
        let model = GuidedServerSetupModel()
        model.setRoute(.thisMac)
        #expect(model.phase == .chooseHosting)
        model.advance()
        #expect(model.phase == .checkHost)
        #expect(!model.canContinueFromCurrentPhase)
        model.setHostCheck("Operating system", status: .passed)
        #expect(!model.canContinueFromCurrentPhase, "partial checks must not continue")
        for name in GuidedServerSetupModel.requiredLocalChecks {
            model.setHostCheck(name, status: .passed)
        }
        #expect(model.canContinueFromCurrentPhase)
        model.setHostCheck("Product ports", status: .pending)
        #expect(!model.canContinueFromCurrentPhase, "unknown/pending required checks block")
    }

    @Test("Route change resets verification and returns to choose hosting")
    @MainActor
    func routeChangeResets() {
        let model = GuidedServerSetupModel()
        model.setRoute(.thisMac)
        model.advance()
        for name in GuidedServerSetupModel.requiredLocalChecks {
            model.setHostCheck(name, status: .passed)
        }
        model.setRoute(.existingLinuxSSH)
        #expect(model.phase == .chooseHosting)
        #expect(model.hostChecks.isEmpty)
        #expect(model.localPreflight == nil)
    }

    @Test("Local preflight failure blocks continue and stays honest")
    @MainActor
    func preflightFailureBlocks() async {
        let model = GuidedServerSetupModel(localClient: LocalMacSetupClient(inspector: StubLocalInspector(
            .failure(HelicoidError.setupBlocked(reason: "Local preflight could not inspect listening TCP ports.")))))
        model.setRoute(.thisMac)
        model.advance()
        #expect(model.phase == .checkHost)
        await model.verifyAndInspectHost()
        #expect(model.localPreflight == nil)
        #expect(model.localPreflightFailure?.contains("could not inspect") == true)
        #expect(!model.canContinueFromCurrentPhase)
        #expect(model.blocker?.contains("could not inspect") == true)
    }

    @Test("Local preflight populates checks without claiming install or verified")
    @MainActor
    func preflightPopulatesWithoutPretendSuccess() async {
        let model = GuidedServerSetupModel(localClient: LocalMacSetupClient(
            inspector: StubLocalInspector(.facts(healthyFacts))))
        model.setRoute(.thisMac)
        model.advance()
        await model.verifyAndInspectHost()
        #expect(model.localPreflight == healthyFacts)
        #expect(model.hostIdentity == .notChecked)
        for name in GuidedServerSetupModel.requiredLocalChecks {
            #expect(model.hostChecks[name] == .passed)
        }
        // Accepted gate: without a verified package there is no network/admin/storage/review walk.
        model.advance()
        #expect(model.phase == .install)
        #expect(model.phase != .network)
        #expect(model.phase != .administrator)
        #expect(model.phase != .storage)
        #expect(model.phase != .review)
        #expect(model.administratorUsername.isEmpty)
        if case .refused(let reason) = model.installProgress {
            #expect(reason.contains("not performed"))
        } else {
            Issue.record("This Mac install must stay refused")
        }
        #expect(!model.isServerReadyForEnrollment)
    }

    @Test("Cancellation mid local check leaves model unchecked")
    @MainActor
    func cancellationLeavesUnchecked() async {
        let inspector = StubLocalInspector(.slow(healthyFacts, delayNanoseconds: 500_000_000))
        let model = GuidedServerSetupModel(localClient: LocalMacSetupClient(inspector: inspector))
        model.setRoute(.thisMac)
        model.advance()
        model.startHostCheck()
        model.cancelHostCheck()
        await Task.yield()
        #expect(model.localPreflight == nil)
        #expect(!model.canContinueFromCurrentPhase)
        #expect(!model.isCheckingHost)
    }

    @Test("Ownership plan is read-only documentation, not an installer")
    func ownershipPlanIsNotApplied() {
        let plan = LocalHostingOwnershipPlan.current
        #expect(plan.launchdPlistPath.contains(plan.launchdLabel))
        #expect(plan.dataPath.hasPrefix(plan.productRootPath))
        let checks = healthyFacts.checks(plan: plan)
        #expect(checks["Product path"] == .passed)
        #expect(checks["Service manager"] == .passed)
        let occupied = facts(productPath: .present, launchdService: .conflicting(plist: .present, loaded: true))
        let conflicts = occupied.checks(plan: plan)
        #expect(conflicts["Product path"] != .passed)
        #expect(conflicts["Service manager"] != .passed)
    }

    @Test("Live read-only preflight on this Mac is structurally valid")
    func liveLocalPreflight() async throws {
        let result = try await LocalMacSetupClient().preflight()
        // Validate the real OS/host/port facts; do not bypass validation or swallow failure.
        try result.validate()
        #expect(!result.computerName.isEmpty)
        #expect(result.computerName.utf8.count <= LocalHostPreflight.computerNameMaxUTF8)
        #expect(LocalHostPreflight.displayComputerName(result.computerName)
            .utf8.count <= LocalHostPreflight.computerNameDisplayMaxUTF8)
        #expect(result.osVersion.contains("."))
        #expect(result.architecture == "arm64" || result.architecture == "x86_64")
        #expect(result.listeners.tcpPorts.count <= 1024)
        #expect(result.listeners.udpPorts.count <= 1024)
        // Host state varies (occupied ports, existing paths, non-elevated listeners).
        #expect(result.checks().count == GuidedServerSetupModel.requiredLocalChecks.count)
        // Without elevation, listener completeness must be represented, not claimed.
        if geteuid() != 0 {
            #expect(!result.listeners.isComplete)
            #expect(result.checks()["Product ports"] != .passed)
        }
    }
}
