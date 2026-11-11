import Foundation
import Observation

/// Guided server setup (W17) for the Mac manager.
/// Mac manager offers This Mac and Existing Linux SSH. Windows hosting is installed
/// by opening the Windows app on the Windows host. Local installation stays
/// unavailable until a verified server adapter is integrated.
public enum HostingRoute: String, Hashable, Sendable, CaseIterable {
    case thisMac
    case existingLinuxSSH

    public var title: String {
        switch self {
        case .thisMac: "This Mac"
        case .existingLinuxSSH: "Existing Linux Server"
        }
    }

    public var detail: String {
        switch self {
        case .thisMac:
            "Check this Mac for local hosting."
        case .existingLinuxSSH:
            "Check an existing Linux server over SSH."
        }
    }

    public var defaultStoragePath: String {
        switch self {
        case .thisMac: LocalHostingOwnershipPlan.current.dataPath
        case .existingLinuxSSH: "/var/lib/helicoid"
        }
    }
}

public enum SSHAuthMethod: String, Hashable, Sendable, CaseIterable {
    case agentKey
    case password

    public var label: String {
        switch self {
        case .agentKey: "SSH key from your agent"
        case .password: "Password"
        }
    }
}

/// Host identity verification result. A changed key or refusal performs no writes.
public enum HostIdentityResult: Hashable, Sendable {
    case notChecked
    case checking
    case verified(fingerprint: String)
    case changed(expected: String?, actual: String)
    case refused(detail: String)

    public var isVerified: Bool {
        if case .verified = self { return true }
        return false
    }

    public var explanation: String {
        switch self {
        case .notChecked:
            return "Host identity has not been checked yet."
        case .checking:
            return "Checking SSH host identity…"
        case .verified(let fingerprint):
            return "SSH host identity verified. Fingerprint: \(fingerprint)"
        case .changed(let expected, let actual):
            let expectedText = expected ?? "no stored fingerprint"
            return "SSH host identity changed. Stored: \(expectedText). Received: \(actual). No writes were performed."
        case .refused(let detail):
            return "SSH host identity could not be established: \(detail). No writes were performed."
        }
    }
}

public enum SetupPhase: String, Hashable, Sendable, CaseIterable {
    case chooseHosting
    case connect
    case hostIdentity
    case checkHost
    case network
    case deploymentIdentity
    case administrator
    case storage
    case review
    case install
    case ready

    public var title: String {
        switch self {
        case .chooseHosting: "Choose Hosting"
        case .connect: "Connect"
        case .hostIdentity: "Host Identity"
        case .checkHost: "Check Host"
        case .network: "Network"
        case .deploymentIdentity: "Deployment Identity"
        case .administrator: "Administrator"
        case .storage: "Storage and Backups"
        case .review: "Review"
        case .install: "Install"
        case .ready: "Ready"
        }
    }
}

public enum InstallProgress: Hashable, Sendable {
    case notStarted
    case refused(reason: String)
    case preparing
    case preflighting
    case provisioningTLS
    case planning
    case applying
    case checkingStatus
    case cancelling
    case installedUnverified(summary: String)
    case attentionRequired(summary: String)
    case failed(reason: String)
    case cancelled(reason: String)
    case outcomeUnknown(reason: String)

    public var isReadyForEnrollment: Bool { false }

    public var isWorking: Bool {
        switch self {
        case .preparing, .preflighting, .provisioningTLS, .planning, .applying, .checkingStatus, .cancelling:
            true
        default:
            false
        }
    }
}

/// What the install phase's primary action does. `none` means the current
/// result is terminal and must be inspected rather than retried blindly.
public enum InstallAction: Hashable, Sendable {
    case start
    case refreshStatus
    case unavailable
    case none
}

/// State machine for H01–H12. Installation never claims success without a real installer path.
@MainActor
@Observable
public final class GuidedServerSetupModel {
    public private(set) var phase: SetupPhase = .chooseHosting
    public private(set) var route: HostingRoute = .thisMac
    public private(set) var sshAddress: String = ""
    public private(set) var sshAuthMethod: SSHAuthMethod = .agentKey
    public private(set) var hostIdentity: HostIdentityResult = .notChecked
    public private(set) var hostChecks: [String: HostCheckStatus] = [:]
    public private(set) var networkAddress: String = ""
    public private(set) var productPort: String = "8920"
    public private(set) var lanScope: String = ""
    public private(set) var deploymentName: String = ""
    public private(set) var generatedTrustIdentityNote: String = ""
    public private(set) var administratorUsername: String = ""
    public private(set) var storagePath: String = ""
    public private(set) var backupDestination: String = ""
    public private(set) var installProgress: InstallProgress = .notStarted
    public private(set) var blocker: String?
    public private(set) var isCheckingHost = false
    public private(set) var hostPreflight: SSHHostPreflight?
    public private(set) var localPreflight: LocalHostPreflight?
    public private(set) var localPreflightFailure: String?
    public private(set) var initiatingManagerPublicKey: Data?
    public private(set) var isPreparingManagerIdentity = false
    /// Human-readable result of the last privileged installer operation. Never
    /// promoted to "ready for enrollment" without server-reported evidence.
    public private(set) var installStatusSummary: String?
    public private(set) var installPackageNotice: String?
    private(set) var installStatus: InstallerOperationStatus?
    private(set) var installPlan: InstallerInstallPlan?
    /// Exact configuration used for the reviewed/apply operation. Status and
    /// cancellation reuse this even if the UI fields are edited later.
    private(set) var installOperationConfiguration: InstallerDeploymentConfiguration?
    /// Exact configuration shown on the Review screen and used for apply.
    private(set) var reviewedInstallConfiguration: InstallerDeploymentConfiguration?
    private(set) var installPackage: TrustedServerPackage?
    public private(set) var developmentTLSNotice: String?

    public nonisolated static let requiredHostChecks = [
        "SSH reachability", "Operating system", "Service manager", "Administrator access",
        "Disk space", "Product ports", "Existing installation",
    ]

    public nonisolated static let requiredLocalChecks = [
        "Operating system", "Administrator access", "Disk space",
        "Product path", "Service manager", "Product ports",
    ]

    public nonisolated static func requiredHostChecks(for route: HostingRoute) -> [String] {
        switch route {
        case .thisMac: requiredLocalChecks
        case .existingLinuxSSH: requiredHostChecks
        }
    }

    /// Default-build compatibility constant. A running model derives the real
    /// availability from the packaged release payload; this stays `false` so a
    /// build without that payload cannot accidentally enable installation.
    public nonisolated static let isServerPackageAvailable = false

    /// Concise H01/H05 blocker shown before any administrator or recovery detail.
    public nonisolated static let packageUnavailableNotice =
        "No signed hs-server package and independent release trust root are packaged, so local installation is disabled."

    public let isDemo: Bool
    private let sshClient: SSHSetupClient
    private let localClient: LocalMacSetupClient
    private let managerIdentityStore: ManagerIdentityStore
    private let installService: any ServerInstallServicing
    private let configurationStore: any ServerInstallConfigurationStoring
    private var managerIdentity: ManagerSigningIdentity?
    private var verificationTask: Task<Void, Never>?
    private var verificationGeneration = UUID()

    public init(sshClient: SSHSetupClient = SSHSetupClient(),
                localClient: LocalMacSetupClient = LocalMacSetupClient(),
                managerIdentityStore: ManagerIdentityStore = ManagerIdentityStore(),
                demoMode: Bool = false) {
        self.isDemo = demoMode
        if demoMode {
            self.networkAddress = "127.0.0.1"
            self.deploymentName = "My server"
            self.administratorUsername = "admin"
        }
        self.sshClient = sshClient
        self.localClient = localClient
        self.managerIdentityStore = managerIdentityStore
        self.installService = BundledServerInstallService()
        self.configurationStore = FileServerInstallConfigurationStore()
    }

    init(sshClient: SSHSetupClient = SSHSetupClient(),
         localClient: LocalMacSetupClient = LocalMacSetupClient(),
         managerIdentityStore: ManagerIdentityStore = ManagerIdentityStore(),
         installService: any ServerInstallServicing,
         configurationStore: any ServerInstallConfigurationStoring = FileServerInstallConfigurationStore(),
         demoMode: Bool = false) {
        self.isDemo = demoMode
        if demoMode {
            self.networkAddress = "127.0.0.1"
            self.deploymentName = "My server"
            self.administratorUsername = "admin"
        }
        self.sshClient = sshClient
        self.localClient = localClient
        self.managerIdentityStore = managerIdentityStore
        self.installService = installService
        self.configurationStore = configurationStore
    }

    /// True only for a This Mac walk whose bundle contains a release payload.
    /// The payload is still cryptographically verified and capability-gated
    /// before any privileged helper execution.
    public var isRealInstallPathEnabled: Bool {
        route == .thisMac && installService.installPayloadPresent
    }

    /// Demo setup can walk the full UI without creating secrets or installing.
    public var installPackageAvailable: Bool {
        isDemo || isRealInstallPathEnabled
    }

    var installPayloadKind: ServerInstallPayloadKind {
        guard !isDemo, route == .thisMac else { return .none }
        return installService.installPayloadKind
    }

    /// Clearly separates the development-only pinned-key path from release
    /// trust. The UI must show a persistent warning whenever this is true.
    public var isDevelopmentInstall: Bool {
        installPayloadKind == .development
    }

    public var installUnavailableNotice: String {
        if route == .existingLinuxSSH && !isDemo {
            return "Existing Linux Server installation is not implemented in this build. SSH host inspection remains read-only."
        }
        return Self.packageUnavailableNotice
    }

    public var isInstalling: Bool {
        installProgress.isWorking
    }

    /// Read-only status is always reachable when a verified payload is present,
    /// including on a fresh launch or after a failed attempt. It never requires
    /// a prior in-memory operation.
    public var canCheckInstallStatus: Bool {
        !isDemo && route == .thisMac && isRealInstallPathEnabled && !isInstalling
    }

    /// True only when the wizard reached Ready and the server reported
    /// enrollment readiness (or this is the demo walk).
    public var isSetupFinished: Bool {
        phase == .ready && (isDemo || isServerReadyForEnrollment)
    }

    public var canCancelInstallation: Bool {
        guard !isInstalling,
              let installStatus,
              installStatus.cancellationAvailable,
              installStatus.operationId != nil else {
            return false
        }
        return true
    }

    public var installStatusHasAttention: Bool {
        if case .attentionRequired = installProgress { return true }
        guard let installStatus else { return false }
        return installStatus.state == "attention_required" || !installStatus.result.errors.isEmpty
    }

    public var installAction: InstallAction {
        if isInstalling { return .none }
        if let installStatus {
            if installStatus.state == "not_installed" || installStatus.state == "cancelled" {
                return isRealInstallPathEnabled ? .start : .unavailable
            }
            return .refreshStatus
        }
        if case .outcomeUnknown = installProgress { return .refreshStatus }
        if case .attentionRequired = installProgress { return .refreshStatus }
        if case .refused = installProgress { return .none }
        if isDemo { return .unavailable }
        return isRealInstallPathEnabled ? .start : .unavailable
    }

    public func prepareManagerIdentity() async {
        // Demo never creates a real Keychain secret. No signed,
        // installation-capable package means no installer can consume a
        // manager key either.
        guard !isDemo, isRealInstallPathEnabled else { return }
        guard managerIdentity == nil, !isPreparingManagerIdentity else { return }
        let availability = await installService.packageAvailability()
        guard let package = availability.package else {
            installPackageNotice = availability.explanation
            blocker = availability.explanation
            return
        }
        installPackage = package
        do {
            let capabilities = try await installService.capabilities(package: package)
            try Self.requireInstallCapability(capabilities)
        } catch {
            blocker = Self.installMessage(error)
            return
        }
        isPreparingManagerIdentity = true
        defer { isPreparingManagerIdentity = false }
        do {
            let identity = try await managerIdentityStore.loadOrCreate()
            try Task.checkCancellation()
            managerIdentity = identity
            initiatingManagerPublicKey = identity.publicKey
            generatedTrustIdentityNote = "Initiating Manager public key: " + identity.publicKey.map { String(format: "%02x", $0) }.joined()
        } catch is CancellationError {
            return
        } catch {
            blocker = (error as? HelicoidError)?.explanation ?? "The Manager identity could not be saved. Setup is stopped."
        }
    }

    public var canContinueFromCurrentPhase: Bool {
        switch phase {
        case .chooseHosting:
            return true
        case .connect:
            return (try? SSHSetupAddress(sshAddress)) != nil && sshAuthMethod == .agentKey
        case .hostIdentity:
            return hostIdentity.isVerified
        case .checkHost:
            // Unknown or missing required checks never count as passed.
            let checksPass = Self.requiredHostChecks(for: route).allSatisfy { hostChecks[$0] == .passed }
            switch route {
            case .thisMac:
                return checksPass
            case .existingLinuxSSH:
                return hostIdentity.isVerified && checksPass
            }
        case .network:
            let validPort = UInt16(productPort).map { port in
                isRealInstallPathEnabled ? port >= 1024 : port > 0
            } == true
            return !networkAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && validPort
                && hostChecks["Product ports"] == .passed
        case .deploymentIdentity:
            return !deploymentName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .administrator:
            return !administratorUsername.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .storage:
            return !storagePath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .review:
            return true
        case .install:
            // A real install may interact with the helper; it may leave the
            // install phase only when the server reports readiness.
            return isDemo || (isRealInstallPathEnabled && !isInstalling)
        case .ready:
            return true
        }
    }

    /// SSH-only phases are skipped on This Mac. Both routes join at Check Host.
    /// Without a verified server package the walk ends at the install blocker:
    /// network/administrator/storage/review are never entered (H05).
    private var phaseOrder: [SetupPhase] {
        let installTail: [SetupPhase] = (isDemo || isRealInstallPathEnabled)
            ? [.network, .deploymentIdentity, .administrator, .storage, .review, .install, .ready]
            : [.install]
        switch route {
        case .thisMac:
            return [.chooseHosting, .checkHost] + installTail
        case .existingLinuxSSH:
            return [.chooseHosting, .connect, .hostIdentity, .checkHost] + installTail
        }
    }

    public func setRoute(_ value: HostingRoute) {
        guard !isDemo || value == .thisMac else { return }
        guard !isInstalling else {
            blocker = "Installation is in progress. Wait for it to finish before changing the hosting route."
            return
        }
        guard value != route else { return }
        route = value
        cancelHostCheck()
        hostIdentity = .notChecked
        hostChecks = [:]
        hostPreflight = nil
        localPreflight = nil
        localPreflightFailure = nil
        installProgress = .notStarted
        installStatus = nil
        installPlan = nil
        installStatusSummary = nil
        installPackageNotice = nil
        installOperationConfiguration = nil
        reviewedInstallConfiguration = nil
        installPackage = nil
        developmentTLSNotice = nil
        blocker = nil
        phase = .chooseHosting
    }

    public func setSSHAddress(_ value: String) {
        guard value != sshAddress else { return }
        invalidateHostVerification()
        sshAddress = value
    }

    public func setSSHAuthMethod(_ method: SSHAuthMethod) {
        guard method != sshAuthMethod else { return }
        invalidateHostVerification()
        sshAuthMethod = method
    }

    public func setNetworkAddress(_ value: String) {
        networkAddress = value
        reviewedInstallConfiguration = nil
    }

    public func setProductPort(_ value: String) {
        productPort = value
        reviewedInstallConfiguration = nil
        guard let port = UInt16(value), port > 0 else {
            if hostPreflight != nil || localPreflight != nil {
                hostChecks["Product ports"] = .needsAttention(detail: "Enter a valid port.")
            }
            return
        }
        switch route {
        case .thisMac:
            if let localPreflight {
                hostChecks = localPreflight.checks(authorityPort: port)
            }
        case .existingLinuxSSH:
            if let hostPreflight {
                hostChecks = hostPreflight.checks(authorityPort: port)
            }
        }
    }

    /// Suggestions are based on the last inspection, not a reservation.
    public var suggestedProductPorts: [UInt16] {
        let observedPorts: [UInt16]
        switch route {
        case .thisMac:
            observedPorts = localPreflight?.listeners.tcpPorts ?? []
        case .existingLinuxSSH:
            observedPorts = hostPreflight?.tcpPorts ?? []
        }
        let selected = UInt16(productPort)
        return [UInt16(8920), 8921, 8922, 8923, 8924, 8925]
            .filter { $0 != selected && !observedPorts.contains($0) }
            .prefix(3)
            .map { $0 }
    }

    public func setLanScope(_ value: String) {
        lanScope = value
        reviewedInstallConfiguration = nil
    }

    public func setDeploymentName(_ value: String) {
        deploymentName = value
    }

    public func setAdministratorUsername(_ value: String) {
        administratorUsername = value
    }

    public func setStoragePath(_ value: String) {
        storagePath = value
        reviewedInstallConfiguration = nil
    }

    public func setBackupDestination(_ value: String) {
        backupDestination = value
        reviewedInstallConfiguration = nil
    }

    public func setHostIdentity(_ result: HostIdentityResult) {
        hostIdentity = result
    }

    public func setHostCheck(_ name: String, status: HostCheckStatus) {
        hostChecks[name] = status
    }

    public func startHostCheck(usingAdministratorAccess: Bool = false) {
        guard !isCheckingHost else { return }
        verificationTask = Task { [weak self] in
            await self?.verifyAndInspectHost(usingAdministratorAccess: usingAdministratorAccess)
        }
    }

    public func cancelHostCheck() {
        verificationTask?.cancel()
        verificationTask = nil
        verificationGeneration = UUID()
        isCheckingHost = false
        if case .checking = hostIdentity { hostIdentity = .notChecked }
    }

    public func verifyAndInspectHost(usingAdministratorAccess: Bool = false) async {
        guard !Task.isCancelled, !isCheckingHost else { return }
        if isDemo {
            hostChecks = Dictionary(uniqueKeysWithValues: Self.requiredLocalChecks.map { ($0, .passed) })
            return
        }
        let generation = UUID()
        verificationGeneration = generation
        isCheckingHost = true
        hostChecks = [:]
        blocker = nil
        defer {
            if generation == verificationGeneration {
                isCheckingHost = false
                verificationTask = nil
            }
        }
        do {
            switch route {
            case .thisMac:
                localPreflight = nil
                localPreflightFailure = nil
                let result = try await localClient.preflight(usingAdministratorAccess: usingAdministratorAccess)
                try Task.checkCancellation()
                guard generation == verificationGeneration else { return }
                localPreflight = result
                hostChecks = result.checks(authorityPort: UInt16(productPort) ?? 8920)
            case .existingLinuxSSH:
                let previousFingerprint: String?
                if case .verified(let fingerprint) = hostIdentity { previousFingerprint = fingerprint }
                else { previousFingerprint = nil }
                hostIdentity = .checking
                hostPreflight = nil
                guard sshAuthMethod == .agentKey else {
                    throw HelicoidError.setupBlocked(reason: "Use an SSH key from your agent for this test installer.")
                }
                let result = try await sshClient.preflight(address: SSHSetupAddress(sshAddress))
                try Task.checkCancellation()
                guard generation == verificationGeneration else { return }
                if let previousFingerprint, previousFingerprint != result.fingerprint {
                    hostIdentity = .changed(expected: previousFingerprint, actual: result.fingerprint)
                    blocker = HelicoidError.hostIdentityUnverified.explanation
                    return
                }
                hostIdentity = .verified(fingerprint: result.fingerprint)
                hostPreflight = result.host
                hostChecks = result.host.checks(authorityPort: UInt16(productPort) ?? 8920)
                if networkAddress.isEmpty { networkAddress = try SSHSetupAddress(sshAddress).host }
            }
            // Reapply validation so an invalid edited port cannot fall back to 8920 as a pass.
            setProductPort(productPort)
        } catch {
            guard generation == verificationGeneration else { return }
            if error is CancellationError || error as? SetupCommandError == .cancelled {
                if route == .existingLinuxSSH { hostIdentity = .notChecked }
                else { localPreflightFailure = nil }
            } else {
                let detail = (error as? HelicoidError)?.explanation ?? "Host preflight failed or exceeded its time/output limit."
                switch route {
                case .thisMac:
                    localPreflightFailure = detail
                case .existingLinuxSSH:
                    hostIdentity = .refused(detail: detail)
                }
                blocker = detail
            }
        }
    }

    private func invalidateHostVerification() {
        cancelHostCheck()
        hostIdentity = .notChecked
        hostChecks = [:]
        hostPreflight = nil
        localPreflight = nil
        localPreflightFailure = nil
    }

    public func advance() {
        guard canContinueFromCurrentPhase else {
            blocker = "Complete the required fields before continuing."
            return
        }
        blocker = nil
        let order = phaseOrder
        guard let index = order.firstIndex(of: phase), index + 1 < order.count else {
            return
        }
        let next = order[index + 1]
        if next == .ready && !isDemo {
            guard installStatusReportsReady else {
                let reason: String
                if let installStatus, installStatus.serviceInstalled {
                    reason = "The service is installed, but the installer does not report server readiness or enrollment. No Ready state is claimed."
                } else {
                    reason = "A verified installation and server-reported readiness are required before enrollment."
                }
                blocker = reason
                if let installStatus, installStatus.serviceInstalled {
                    installProgress = .installedUnverified(summary: installStatus.result.summary)
                }
                return
            }
        }
        if next == .review && !isDemo {
            do {
                reviewedInstallConfiguration = try installerConfiguration()
            } catch {
                blocker = Self.installMessage(error)
                return
            }
        }
        if next == .install && !isDemo {
            if isRealInstallPathEnabled && reviewedInstallConfiguration == nil {
                do {
                    reviewedInstallConfiguration = try installerConfiguration()
                } catch {
                    blocker = Self.installMessage(error)
                    return
                }
            }
            installPlan = nil
            installStatusSummary = nil
            installPackageNotice = nil
            if isRealInstallPathEnabled {
                installProgress = .notStarted
            } else if route == .existingLinuxSSH {
                installProgress = .refused(reason:
                    "Remote installation is not performed in this build. Existing Linux Server installation is not implemented; SSH host inspection remains read-only.")
            } else {
                installProgress = .refused(reason: HelicoidError.installNotAvailable.explanation)
            }
        }
        if next == .network && route == .thisMac && networkAddress.isEmpty {
            networkAddress = "127.0.0.1"
        }
        if next == .deploymentIdentity {
            // Manager key is only created once a verified package can consume it.
            Task { await prepareManagerIdentity() }
        }
        phase = next
    }

    public func back() {
        guard !isInstalling else {
            blocker = "Installation is in progress. Wait for it to finish before leaving."
            return
        }
        let order = phaseOrder
        guard let index = order.firstIndex(of: phase), index > 0 else { return }
        if phase == .review {
            reviewedInstallConfiguration = nil
        }
        phase = order[index - 1]
        blocker = nil
    }

    public func reset() {
        guard !isInstalling else {
            blocker = "Installation is in progress. Wait for it to finish before closing setup."
            return
        }
        cancelHostCheck()
        phase = .chooseHosting
        hostIdentity = .notChecked
        hostChecks = [:]
        hostPreflight = nil
        localPreflight = nil
        localPreflightFailure = nil
        installProgress = .notStarted
        installStatus = nil
        installPlan = nil
        installStatusSummary = nil
        installPackageNotice = nil
        installOperationConfiguration = nil
        reviewedInstallConfiguration = nil
        installPackage = nil
        developmentTLSNotice = nil
        blocker = nil
    }

    /// Summary of the exact configuration the privileged installer will use.
    /// Deployment names and administrator names are UI/bootstrap inputs, not
    /// resources this installer creates.
    public func reviewChanges() -> [String] {
        switch route {
        case .thisMac:
            let plan = LocalHostingOwnershipPlan.current
            var lines = [
                "Route: This Mac",
                "This Mac: \(localPreflight?.computerName ?? "unknown"), \(localPreflight?.osVersion ?? "unknown"), \(localPreflight?.architecture ?? "unknown")",
            ]
            if isRealInstallPathEnabled {
                let configuration = reviewedInstallConfiguration
                    ?? (try? installerConfiguration())
                if let configuration {
                    lines.append("Deployment kind: \(configuration.deploymentKind)")
                    lines.append("Network: \(configuration.network.scope), literal 127.0.0.1:\(configuration.network.authorityPort)")
                    lines.append("Data directory: \(configuration.storage.dataDirectory)")
                    lines.append("Backup directory: \(configuration.storage.backupDirectory)")
                    lines.append("Preserve data on remove: \(configuration.storage.preserveDataOnRemove ? "yes" : "no")")
                } else {
                    lines.append("Installer configuration: incomplete or invalid; installation cannot start.")
                }
                if isDevelopmentInstall {
                    lines.append("DEVELOPMENT ONLY: helper and package are pinned by a build-time development Ed25519 key, not a release trust root.")
                    lines.append("TLS source: disposable self-signed 127.0.0.1 material will be generated at \(ServerInstallContract.operatorTLSDirectory) only when that path is absent; existing TLS is never overwritten.")
                } else {
                    lines.append("Signed helper: \(ServerInstallContract.helperRelativePath)")
                    lines.append("TLS source (operator-provided): \(ServerInstallContract.operatorTLSCertificatePath) and \(ServerInstallContract.operatorTLSPrivateKeyPath)")
                }
                lines.append("Executable: \(ServerInstallContract.executablePath)")
                lines.append("Service: \(plan.launchdLabel) at \(plan.launchdPlistPath)")
                lines.append("Deployment display name: \(deploymentName) (not created or installed by this local installer)")
                lines.append("First administrator: \(administratorUsername) (not created by this local installer; bootstrap remains separate)")
                lines.append("The installer requests macOS administrator authorization; it does not establish enrollment readiness.")
            } else {
                lines.append("Planned product path (not applied): \(plan.productRootPath)")
                lines.append("Planned launchd service (not applied): \(plan.launchdLabel) at \(plan.launchdPlistPath)")
                lines.append("Deployment display name: \(deploymentName) (not applied)")
                lines.append("First administrator: \(administratorUsername) (not applied; bootstrap remains separate)")
            }
            lines.append("Install: \(installProgressExplanation)")
            return lines
        case .existingLinuxSSH:
            return [
                "Route: Existing Linux Server",
                "Listeners: \(networkAddress):\(productPort), LAN scope: \(lanScope.isEmpty ? "unset" : lanScope)",
                "Deployment name: \(deploymentName) (not applied)",
                "First administrator: \(administratorUsername) (not applied; bootstrap remains separate)",
                "Host identity: \(hostIdentity.explanation)",
                "Install: \(installProgressExplanation)",
            ]
        }
    }

    public var installProgressExplanation: String {
        switch installProgress {
        case .notStarted:
            "Not started."
        case .refused(let reason):
            reason
        case .preparing:
            "Verifying the signed server package and installer capabilities…"
        case .preflighting:
            "Checking this Mac with administrator authorization…"
        case .provisioningTLS:
            "DEVELOPMENT ONLY: generating disposable self-signed TLS for 127.0.0.1 if the fixed operator path is absent…"
        case .planning:
            "Creating a configuration-bound reviewed installation plan…"
        case .applying:
            "Administrator authorization and installation are in progress. Do not quit the Manager."
        case .checkingStatus:
            "Reading the recorded installer status…"
        case .cancelling:
            "Rolling back the incomplete installation…"
        case .installedUnverified(let summary):
            summary
        case .attentionRequired(let summary):
            summary
        case .failed(let reason):
            reason
        case .cancelled(let reason):
            reason
        case .outcomeUnknown(let reason):
            reason
        }
    }

    /// Server evidence, independent of the current wizard phase. Reaching the
    /// Ready phase additionally requires `isServerReadyForEnrollment`.
    public var installStatusReportsReady: Bool {
        guard let installStatus,
              installStatus.serviceInstalled,
              installStatus.serverReadyForEnrollment else {
            return false
        }
        return true
    }

    public var isServerReadyForEnrollment: Bool {
        phase == .ready && installStatusReportsReady
    }

    // MARK: - Real local installation

    /// Runs capabilities → privileged preflight → privileged plan → privileged
    /// apply. Each stage that can mutate the host is preceded by the helper's
    /// own verification. A failure never becomes a success state.
    public func startInstallation() async {
        guard !isInstalling else { return }
        guard !isDemo else { return }
        guard route == .thisMac, isRealInstallPathEnabled else {
            installProgress = .refused(reason: HelicoidError.installNotAvailable.explanation)
            blocker = installProgressExplanation
            return
        }

        blocker = nil
        installPlan = nil
        installStatusSummary = nil
        installPackageNotice = nil
        developmentTLSNotice = nil
        installProgress = .preparing
        var dispatchStarted = false

        do {
            let availability = await installService.packageAvailability()
            guard let package = availability.package else {
                installPackageNotice = availability.explanation
                if case .invalid = availability {
                    installProgress = .failed(reason: availability.explanation)
                } else {
                    installProgress = .refused(reason: availability.explanation)
                }
                blocker = availability.explanation
                return
            }

            installPackage = package
            let capabilities = try await installService.capabilities(package: package)
            do {
                try Self.requireInstallCapability(capabilities)
            } catch {
                let reason = Self.installMessage(error)
                installProgress = .refused(reason: reason)
                blocker = reason
                return
            }

            guard let configuration = reviewedInstallConfiguration else {
                let reason = "Review the installation configuration again before starting the installer."
                installProgress = .failed(reason: reason)
                blocker = reason
                return
            }
            installOperationConfiguration = configuration
            do {
                try configurationStore.save(configuration)
            } catch {
                let message = "The exact installer configuration could not be saved, so restart recovery cannot be guaranteed. Nothing was installed."
                installProgress = .failed(reason: message)
                blocker = message
                return
            }
            installProgress = .preflighting
            let preflight = try await installService.preflight(
                configuration: configuration,
                package: package)
            try Self.requireMatchingContract(preflight, configuration: configuration)
            guard preflight.ok else {
                let details = preflight.hostChecks.checks.blockingSummaries
                let reason = details.isEmpty
                    ? "The installer preflight did not pass. No installation was attempted."
                    : details.joined(separator: " ")
                installProgress = .failed(reason: reason)
                blocker = reason
                return
            }

            if package.isDevelopment {
                installProgress = .provisioningTLS
                let tlsResult = try await installService.provisionDevelopmentTLSIfNeeded()
                switch tlsResult {
                case .provisioned:
                    developmentTLSNotice = "Development-only self-signed TLS was provisioned for loopback 127.0.0.1."
                case .existingUnverifiedMaterial:
                    developmentTLSNotice = "Existing TLS material was found without the development marker and was not modified. The reviewed plan will validate it."
                }
            }

            installProgress = .planning
            let planResult = try await installService.plan(
                configuration: configuration,
                preflight: preflight,
                package: package)
            try Self.requireMatchingContract(planResult, configuration: configuration)
            guard planResult.ok,
                  let plan = planResult.plan,
                  planResult.reviewedPlanDigest != nil else {
                var details = planResult.warnings
                if let error = planResult.error, !error.isEmpty { details.insert(error, at: 0) }
                let reason = details.isEmpty
                    ? "The installer refused to produce a reviewed installation plan."
                    : details.joined(separator: " ")
                installProgress = .failed(reason: reason)
                blocker = reason
                return
            }
            installPlan = plan

            installProgress = .applying
            dispatchStarted = true
            let status = try await installService.apply(
                configuration: configuration,
                preflight: preflight,
                plan: planResult,
                package: package)
            try Self.requireMatchingContract(status, configuration: configuration)
            applyInstallStatus(status)
        } catch {
            let message = Self.installMessage(error)
            if let local = error as? LocalServerInstallError {
                if local.isAuthorizationCancellation {
                    installProgress = .cancelled(reason: message)
                } else if case .privilegedOutcomeUnknown = local {
                    installProgress = .outcomeUnknown(reason: message)
                } else if case .returnedRefusal = local {
                    installProgress = .failed(reason: message)
                } else if case .helperFailed(let status, _) = local {
                    if status >= 128 {
                        installProgress = .outcomeUnknown(
                            reason: "The privileged installer ended without a normal exit status. \(message) Refresh status before any retry.")
                    } else {
                        installProgress = .failed(reason: message)
                    }
                } else if case .developmentTLSProvisioningFailed = local {
                    installProgress = .failed(reason: message)
                } else if local == .cancelled {
                    installProgress = dispatchStarted
                        ? .outcomeUnknown(reason: message)
                        : .cancelled(reason: message)
                } else if local == .timedOut || local == .outputExceeded {
                    installProgress = dispatchStarted
                        ? .outcomeUnknown(reason: message)
                        : .failed(reason: message)
                } else if case .invalidResponse = local {
                    installProgress = dispatchStarted
                        ? .outcomeUnknown(reason: message)
                        : .failed(reason: message)
                } else if case .authorizationFailed = local {
                    installProgress = .failed(reason: message)
                } else {
                    installProgress = .failed(reason: message)
                }
            } else if error is CancellationError {
                installProgress = .cancelled(reason: message)
            } else {
                installProgress = .failed(reason: message)
            }
            blocker = installProgressExplanation
        }
    }

    /// Read the durable operation record. Read-only; never inferred from the
    /// presence of files or a loaded launchd job.
    public func refreshInstallStatus() async {
        guard !isInstalling else { return }
        guard route == .thisMac, isRealInstallPathEnabled else { return }
        blocker = nil
        let package: TrustedServerPackage
        if let installPackage {
            package = installPackage
        } else {
            let availability = await installService.packageAvailability()
            guard let resolved = availability.package else {
                installProgress = .failed(reason: availability.explanation)
                blocker = availability.explanation
                return
            }
            installPackage = resolved
            package = resolved
        }
        let configuration: InstallerDeploymentConfiguration
        if let installOperationConfiguration {
            configuration = installOperationConfiguration
        } else {
            do {
                if let persisted = configurationStore.load() {
                    configuration = persisted
                    installOperationConfiguration = persisted
                } else if let fetched = try? await installService.storedConfiguration(package: package),
                          let stored = fetched {
                    // Server-authoritative recovery for installations created
                    // before this Manager persisted the configuration locally.
                    _ = try? configurationStore.save(stored)
                    configuration = stored
                    installOperationConfiguration = stored
                } else {
                    // No durable v2 operation is recorded. Ask status with the
                    // current valid configuration; the server reports
                    // `not_installed` rather than inventing an identity.
                    configuration = try installerConfiguration()
                    installOperationConfiguration = configuration
                }
            } catch {
                let message = Self.installMessage(error)
                installProgress = .attentionRequired(
                    summary: "The installer's recorded configuration could not be read. \(message)")
                blocker = installProgressExplanation
                return
            }
        }

        installProgress = .checkingStatus
        do {
            let status = try await installService.status(
                configuration: configuration,
                package: package)
            try Self.requireMatchingContract(status, configuration: configuration)
            _ = try? configurationStore.save(configuration)
            applyInstallStatus(status)
        } catch let statusError {
            // A stale local copy can make status-v2 reject the configuration.
            // Ask the durable record for the exact configuration and retry
            // once, so the operation identity is never abandoned.
            if let recovered = await recoveredConfigurationForStatusRetry(
                    package: package,
                    current: configuration) {
                do {
                    let status = try await installService.status(
                        configuration: recovered,
                        package: package)
                    try Self.requireMatchingContract(status, configuration: recovered)
                    installOperationConfiguration = recovered
                    _ = try? configurationStore.save(recovered)
                    applyInstallStatus(status)
                    return
                } catch {
                    // Fall through to the attention state below.
                }
            }
            let message = Self.installMessage(statusError)
            // Keep the last known operation identity and configuration. A
            // failed read must not erase the ability to cancel or retry.
            installProgress = .attentionRequired(
                summary: "Installer status could not be read. \(message)")
            blocker = installProgressExplanation
        }
    }

    private func recoveredConfigurationForStatusRetry(
        package: TrustedServerPackage,
        current: InstallerDeploymentConfiguration
    ) async -> InstallerDeploymentConfiguration? {
        guard let fetched = try? await installService.storedConfiguration(package: package),
              let recovered = fetched,
              recovered != current else {
            return nil
        }
        return recovered
    }

    /// Requests the helper's rollback for an incomplete operation. This is a
    /// separate privileged operation; it never pretends to stop a running
    /// apply by cancelling the local wait.
    public func cancelInstallation() async {
        guard canCancelInstallation,
              let installStatus,
              let operationId = installStatus.operationId else {
            return
        }
        guard let package = installPackage,
              let configuration = installOperationConfiguration else {
            installProgress = .attentionRequired(
                summary: "The exact applied configuration is unavailable, so cancellation was not attempted. Refresh status first.")
            blocker = installProgressExplanation
            return
        }
        blocker = nil
        installProgress = .cancelling
        do {
            let status = try await installService.cancel(
                configuration: configuration,
                operationId: operationId,
                confirmUnverifiedCompletion: false,
                package: package)
            try Self.requireMatchingContract(status, configuration: configuration)
            applyInstallStatus(status)
        } catch {
            let message = Self.installMessage(error)
            installProgress = .attentionRequired(
                summary: "Cancellation did not complete. \(message) Inspect status before retrying.")
            blocker = installProgressExplanation
        }
    }

    private func applyInstallStatus(_ status: InstallerOperationStatus) {
        installStatus = status
        installStatusSummary = Self.statusSummary(status)
        switch status.state {
        case "completed" where status.serviceInstalled:
            let summary = status.serverReadyForEnrollment
                ? "The service is installed and the server reports ready for enrollment."
                : "The service is installed. Bootstrap and enrollment readiness are not verified."
            installProgress = .installedUnverified(summary: summary)
            if status.serverReadyForEnrollment {
                blocker = nil
            } else {
                blocker = summary
            }
        case "cancelled":
            let summary = status.result.summary.isEmpty
                ? "The incomplete installation was rolled back."
                : status.result.summary
            installProgress = .cancelled(reason: summary)
            blocker = summary
        case "attention_required":
            let summary = status.result.summary.isEmpty
                ? "The installation requires attention. Inspect status before retrying."
                : status.result.summary
            installProgress = .attentionRequired(summary: summary)
            blocker = summary
        case "in_progress":
            let summary = status.result.summary.isEmpty
                ? "An installation operation is recorded as in progress or interrupted."
                : status.result.summary
            installProgress = .attentionRequired(summary: summary)
            blocker = summary
        case "not_installed":
            let summary = status.result.summary.isEmpty
                ? "No installation operation is recorded."
                : status.result.summary
            installProgress = .notStarted
            blocker = summary
        default:
            let summary = status.result.summary.isEmpty
                ? "The installer returned an unknown operation state '\(status.state)'."
                : status.result.summary
            installProgress = .failed(reason: summary)
            blocker = summary
        }
    }

    private func installerConfiguration() throws -> InstallerDeploymentConfiguration {
        guard let port = UInt16(productPort), (1024...65_535).contains(port) else {
            throw HelicoidError.invalidInput(
                field: "Connection port",
                detail: "Use an unprivileged port between 1024 and 65535 for the local server.")
        }

        let dataPath = storagePath.trimmingCharacters(in: .whitespacesAndNewlines)
        if !dataPath.isEmpty, dataPath != ServerInstallContract.fixedDataDirectory {
            throw HelicoidError.invalidInput(
                field: "Server data folder",
                detail: "This Mac installs only at \(ServerInstallContract.fixedDataDirectory).")
        }

        let rawBackup = backupDestination.trimmingCharacters(in: .whitespacesAndNewlines)
        let backup = rawBackup.isEmpty ? ServerInstallContract.defaultBackupDirectory : rawBackup
        try Self.validateNormalizedAbsolutePath(backup, label: "Backup destination")
        try Self.requireBackupOutsideProductPaths(backup)

        return .macos(authorityPort: port, backupDirectory: backup)
    }

    static func validateNormalizedAbsolutePath(_ path: String, label: String) throws {
        guard path.hasPrefix("/"),
              path != "/",
              !path.hasSuffix("/"),
              !path.contains("//"),
              path.unicodeScalars.allSatisfy({ scalar in
                  scalar.value >= 0x20 && scalar.value <= 0x7E
              }) else {
            throw HelicoidError.invalidInput(
                field: label,
                detail: "Enter a normalized absolute ASCII path.")
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw HelicoidError.invalidInput(
                field: label,
                detail: "The path must not contain empty, '.' or '..' components.")
        }
    }

    static func requireBackupOutsideProductPaths(_ path: String) throws {
        let backup = pathComponents(path)
        let forbidden = [
            ServerInstallContract.productRootPath,
            ServerInstallContract.fixedDataDirectory,
            ServerInstallContract.launchdPlistPath,
            "/Library/LaunchDaemons",
        ]
        for candidate in forbidden {
            if overlapsCaseInsensitive(backup, pathComponents(candidate)) {
                throw HelicoidError.invalidInput(
                    field: "Backup destination",
                    detail: "The backup directory must not overlap or contain the product, data, plist, or LaunchDaemons paths.")
            }
        }
    }

    static func requireMatchingContract(
        _ preflight: InstallerPreflightResult,
        configuration: InstallerDeploymentConfiguration
    ) throws {
        guard preflight.contractVersion == ServerInstallContract.lifecycleVersion,
              preflight.hostChecks.contractVersion == ServerInstallContract.hostContractVersion,
              preflight.configuration == configuration else {
            throw LocalServerInstallError.invalidResponse(
                "The installer preflight does not match the requested lifecycle configuration.")
        }
    }

    static func requireMatchingContract(
        _ plan: InstallerPlanResult,
        configuration: InstallerDeploymentConfiguration
    ) throws {
        guard plan.contractVersion == ServerInstallContract.lifecycleVersion,
              plan.configuration == configuration else {
            throw LocalServerInstallError.invalidResponse(
                "The installer plan does not match the requested lifecycle configuration.")
        }
    }

    static func requireMatchingContract(
        _ status: InstallerOperationStatus,
        configuration: InstallerDeploymentConfiguration
    ) throws {
        guard status.contractVersion == ServerInstallContract.lifecycleVersion,
              status.configuration == configuration else {
            throw LocalServerInstallError.invalidResponse(
                "The installer status does not match the requested lifecycle configuration.")
        }
    }

    static func requireInstallCapability(_ capabilities: InstallerCapabilities) throws {
        guard capabilities.contractVersion == ServerInstallContract.lifecycleVersion else {
            throw LocalServerInstallError.commandRejected(
                "The server installer reported lifecycle contract \(capabilities.contractVersion), not \(ServerInstallContract.lifecycleVersion).")
        }
        guard capabilities.supportsMacOSInstall else {
            throw LocalServerInstallError.commandRejected(capabilities.installUnavailableReason)
        }
    }

    static func installMessage(_ error: any Error) -> String {
        let text: String
        if let error = error as? LocalServerInstallError {
            text = error.description
        } else if let error = error as? HelicoidError {
            text = error.explanation
        } else if error is CancellationError {
            text = LocalServerInstallError.cancelled.description
        } else if let error = error as? SetupCommandError {
            switch error {
            case .timedOut:
                text = LocalServerInstallError.timedOut.description
            case .outputExceeded:
                text = LocalServerInstallError.outputExceeded.description
            case .cancelled:
                text = LocalServerInstallError.cancelled.description
            default:
                text = "The installer helper could not run."
            }
        } else {
            text = error.localizedDescription
        }
        return String(LocalServerInstallClient.sanitized(text).prefix(2_048))
    }

    static func statusSummary(_ status: InstallerOperationStatus) -> String {
        var parts: [String] = []
        let summary = status.result.summary.isEmpty ? status.result.code : status.result.summary
        parts.append(summary)
        parts.append("Operation state: \(status.state).")
        if let phase = status.currentPhase, !phase.isEmpty {
            parts.append("Phase: \(phase).")
        }
        parts.append("Service installed: \(status.serviceInstalled ? "yes" : "no").")
        parts.append("Bootstrap ready: \(status.bootstrapReady ? "yes" : "no").")
        parts.append("Ready for enrollment: \(status.serverReadyForEnrollment ? "yes" : "no").")
        if !status.result.errors.isEmpty {
            parts.append("Errors: " + status.result.errors.prefix(4).joined(separator: " "))
        }
        let joined = parts.joined(separator: " ")
        return String(LocalServerInstallClient.sanitized(joined).prefix(2_048))
    }

    private static func pathComponents(_ path: String) -> [String] {
        path.split(separator: "/").map { String($0) }
    }

    private static func overlapsCaseInsensitive(_ left: [String], _ right: [String]) -> Bool {
        guard !left.isEmpty, !right.isEmpty else { return false }
        let count = min(left.count, right.count)
        for index in 0..<count {
            if left[index].caseInsensitiveCompare(right[index]) != .orderedSame {
                return false
            }
        }
        return true
    }
}
