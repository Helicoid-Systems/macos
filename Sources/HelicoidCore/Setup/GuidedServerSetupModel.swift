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

    public init() {}

    public var canContinueFromCurrentPhase: Bool {
        switch phase {
        case .chooseHosting:
            return true
        case .connect:
            return !sshAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .hostIdentity:
            return hostIdentity.isVerified
        case .checkHost:
            return hostChecks.values.allSatisfy { status in
                if case .passed = status { return true }
                return false
            } && !hostChecks.isEmpty
        case .network:
            return !networkAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && Int(productPort) != nil
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
        sshAddress = value
    }

    public func setSSHAuthMethod(_ method: SSHAuthMethod) {
        sshAuthMethod = method
    }

    public func setNetworkAddress(_ value: String) {
        networkAddress = value
    }

    public func setProductPort(_ value: String) {
        productPort = value
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
        phase = .chooseHosting
        hostIdentity = .notChecked
        hostChecks = [:]
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
