import Foundation
import Observation

/// Guided server setup (W17) for the Mac manager.
/// Mac manager exposes Linux SSH only. Windows local hosting is installed by opening
/// the Windows app on the Windows host. No local macOS server route exists in version 1.
public enum HostingRoute: String, Hashable, Sendable, CaseIterable {
    case existingLinuxSSH

    public var title: String { "Existing Linux Server" }

    public var detail: String {
        "Connect to an existing Linux server over SSH. Windows hosting is installed by opening the Helicoid Windows app on the Windows host."
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

public enum HostCheckStatus: Hashable, Sendable {
    case pending
    case checking
    case passed
    case needsAttention(detail: String)
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
    case failed(reason: String)

    public var isReadyForEnrollment: Bool { false }
}

/// State machine for H01–H12. Installation never claims success without a real installer path.
@MainActor
@Observable
public final class GuidedServerSetupModel {
    public private(set) var phase: SetupPhase = .chooseHosting
    public private(set) var route: HostingRoute = .existingLinuxSSH
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
    public private(set) var initiatingManagerPublicKey: Data?
    public private(set) var isPreparingManagerIdentity = false

    public static let requiredHostChecks = [
        "SSH reachability", "Operating system", "Service manager", "Administrator access",
        "Disk space", "Product ports", "Existing installation",
    ]
    private let sshClient: SSHSetupClient
    private let managerIdentityStore: ManagerIdentityStore
    private var managerIdentity: ManagerSigningIdentity?
    private var verificationTask: Task<Void, Never>?
    private var verificationGeneration = UUID()

    public init(sshClient: SSHSetupClient = SSHSetupClient(), managerIdentityStore: ManagerIdentityStore = ManagerIdentityStore()) {
        self.sshClient = sshClient
        self.managerIdentityStore = managerIdentityStore
    }

    public func prepareManagerIdentity() async {
        guard managerIdentity == nil, !isPreparingManagerIdentity else { return }
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
            return hostIdentity.isVerified && Self.requiredHostChecks.allSatisfy { hostChecks[$0] == .passed }
        case .network:
            return !networkAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && UInt16(productPort).map { $0 > 0 && ![21115, 21116, 21117].contains($0) } == true
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
            // Install cannot succeed in this build; Ready is not reachable by pretend success.
            return false
        case .ready:
            return true
        }
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
    }

    public func setProductPort(_ value: String) {
        productPort = value
        if let hostPreflight, let port = UInt16(value), port > 0 {
            hostChecks = hostPreflight.checks(authorityPort: port)
        } else if hostPreflight != nil {
            hostChecks["Product ports"] = .needsAttention(detail: "Enter a valid port.")
        }
    }

    public func setLanScope(_ value: String) {
        lanScope = value
    }

    public func setDeploymentName(_ value: String) {
        deploymentName = value
    }

    public func setAdministratorUsername(_ value: String) {
        administratorUsername = value
    }

    public func setStoragePath(_ value: String) {
        storagePath = value
    }

    public func setBackupDestination(_ value: String) {
        backupDestination = value
    }

    public func setHostIdentity(_ result: HostIdentityResult) {
        hostIdentity = result
    }

    public func setHostCheck(_ name: String, status: HostCheckStatus) {
        hostChecks[name] = status
    }

    public func startHostCheck() {
        guard !isCheckingHost else { return }
        verificationTask = Task { [weak self] in await self?.verifyAndInspectHost() }
    }

    public func cancelHostCheck() {
        verificationTask?.cancel()
        verificationTask = nil
        verificationGeneration = UUID()
        isCheckingHost = false
        if case .checking = hostIdentity { hostIdentity = .notChecked }
    }

    public func verifyAndInspectHost() async {
        guard !isCheckingHost else { return }
        let generation = UUID()
        verificationGeneration = generation
        isCheckingHost = true
        let previousFingerprint: String?
        if case .verified(let fingerprint) = hostIdentity { previousFingerprint = fingerprint }
        else { previousFingerprint = nil }
        hostIdentity = .checking
        hostChecks = [:]
        hostPreflight = nil
        blocker = nil
        defer {
            if generation == verificationGeneration {
                isCheckingHost = false
                verificationTask = nil
            }
        }
        do {
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
        } catch {
            guard generation == verificationGeneration else { return }
            if error is CancellationError || error as? SetupCommandError == .cancelled {
                hostIdentity = .notChecked
            } else {
                let detail = (error as? HelicoidError)?.explanation ?? "SSH preflight failed or exceeded its time/output limit."
                hostIdentity = .refused(detail: detail)
                blocker = detail
            }
        }
    }

    private func invalidateHostVerification() {
        cancelHostCheck()
        hostIdentity = .notChecked
        hostChecks = [:]
        hostPreflight = nil
    }

    public func advance() {
        guard canContinueFromCurrentPhase else {
            blocker = "Complete the required fields before continuing."
            return
        }
        blocker = nil
        let order = SetupPhase.allCases
        guard let index = order.firstIndex(of: phase), index + 1 < order.count else {
            return
        }
        let next = order[index + 1]
        if next == .ready {
            // Ready for Enrollment is only reachable after a real install.
            // This build has no integrated server package, so it stays on Install with an honest refusal.
            installProgress = .refused(reason: HelicoidError.installNotAvailable.explanation)
            blocker = HelicoidError.installNotAvailable.explanation
            return
        }
        if next == .install {
            installProgress = .refused(reason: HelicoidError.installNotAvailable.explanation)
        }
        phase = next
    }

    public func back() {
        let order = SetupPhase.allCases
        guard let index = order.firstIndex(of: phase), index > 0 else { return }
        phase = order[index - 1]
        blocker = nil
    }

    public func reset() {
        cancelHostCheck()
        phase = .chooseHosting
        hostIdentity = .notChecked
        hostChecks = [:]
        hostPreflight = nil
        installProgress = .notStarted
        blocker = nil
    }

    /// Summary of exact changes that *would* be applied. Never claims they were applied.
    public func reviewChanges() -> [String] {
        [
            "Route: \(route.title) (SSH \(sshAddress))",
            "Listeners: \(networkAddress):\(productPort), LAN scope: \(lanScope.isEmpty ? "unset" : lanScope)",
            "Deployment name: \(deploymentName)",
            "Administrator: \(administratorUsername) (MFA required; recovery handling not skipped)",
            "Storage: \(storagePath)",
            "Backup destination: \(backupDestination.isEmpty ? "unset" : backupDestination)",
            "Host identity: \(hostIdentity.explanation)",
            "Install: \(installProgressExplanation)",
        ]
    }

    public var installProgressExplanation: String {
        switch installProgress {
        case .notStarted:
            "Not started."
        case .refused(let reason):
            reason
        case .failed(let reason):
            reason
        }
    }

    public var isServerReadyForEnrollment: Bool {
        if case .ready = phase, case .notStarted = installProgress {
            return false
        }
        return false
    }
}
