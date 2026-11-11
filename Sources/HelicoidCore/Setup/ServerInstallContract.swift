import Darwin
import Foundation

/// Frozen inputs shared by the Manager's local macOS installer UI and the
/// packaged `hs-server` lifecycle v2 commands.
///
/// The helper contract is owned by the server (`installer-lifecycle-v2`).
/// These are the only paths and bundle locations this client will use; a
/// caller cannot redirect the product root, data path, launchd label, or
/// installer state directory.
enum ServerInstallContract {
    static let lifecycleVersion = 2
    static let hostContractVersion = 1

    static let helperRelativePath = "Contents/Helpers/hs-server"
    static let releaseEvidenceRelativePath = "Contents/Resources/hs-server-release.json"
    static let developmentEvidenceRelativePath = "Contents/Resources/hs-server-development.json"
    static let packageTrustRootsRelativePath = "Contents/Resources/ServerPackage/trust-roots.json"
    static let packageDirectoryRelativePath = "Contents/Resources/ServerPackage/package"
    /// Clearly separated development-install payload. It is never consulted
    /// when release evidence exists and never enables a normal build.
    static let developmentInstallEvidenceRelativePath =
        "Contents/Resources/hs-server-development-install.json"
    static let developmentPackageDirectoryRelativePath =
        "Contents/Resources/ServerPackage/development/package"
    static let developmentInstallInfoKey = "HelicoidServerDevelopmentInstall"
    static let developmentTrustKeyInfoKey = "HelicoidServerDevelopmentTrustKey"
    static let developmentInstallEvidenceMode = "development-install"

    /// Release installation is authorized only when the Manager is signed with
    /// an independently verified Apple Developer ID identity and its packaged
    /// release trust roots exactly match these keys compiled into the binary.
    /// They are empty by default: an unpopulated build fails closed and never
    /// enables the release privileged path. A release pipeline populates them
    /// in a generated source file at build time.
    static let compiledReleaseTrustKeyHexes: [String] = []
    static let releaseManagerTeamIdentifier: String = ""

    static let installerStateDirectory = "/Library/Application Support/Helicoid-Installer"
    /// Root-owned staging parent for a verified helper/package copy. The
    /// privileged wrapper creates one fresh child per invocation, verifies its
    /// digests, runs only that copy, and removes it on exit.
    static let payloadStagingRoot = "/Library/Application Support/Helicoid-Installer-Payload"
    static let fixedDataDirectory = LocalHostingOwnershipPlan.current.dataPath
    static let defaultBackupDirectory = "/Library/Application Support/Helicoid Backups"
    static let productRootPath = LocalHostingOwnershipPlan.current.productRootPath
    static let launchdLabel = LocalHostingOwnershipPlan.current.launchdLabel
    static let launchdPlistPath = LocalHostingOwnershipPlan.current.launchdPlistPath

    static let executablePath = "/Library/Application Support/Helicoid/bin/hs-server"
    static let configurationPath = "/Library/Application Support/Helicoid/Configuration/service.json"
    static let installReceiptPath = "/Library/Application Support/Helicoid/Configuration/install-receipt.json"
    static let tlsDirectory = "/Library/Application Support/Helicoid/TLS"
    static let tlsCertificatePath = "/Library/Application Support/Helicoid/TLS/fullchain.pem"
    static let tlsPrivateKeyPath = "/Library/Application Support/Helicoid/TLS/private-key.pem"

    static let operatorTLSDirectory = "/etc/helicoid/tls"
    static let operatorTLSCertificatePath = "/etc/helicoid/tls/fullchain.pem"
    static let operatorTLSPrivateKeyPath = "/etc/helicoid/tls/private-key.pem"

    static let macosArm64Target = "macos-arm64"
    static let macosX86_64Target = "macos-x86_64"

    static let maximumHelperResponseBytes = 1_048_576
    static let maximumTimeoutSeconds: TimeInterval = 120
}

/// The trusted target selected from the Manager's local architecture, never
/// from a package field.
enum ServerInstallTarget: String, Equatable, Sendable {
    case macosArm64 = "macos-arm64"
    case macosX86_64 = "macos-x86_64"

    var architecture: String {
        switch self {
        case .macosArm64: "arm64"
        case .macosX86_64: "x86_64"
        }
    }

    static func current() throws -> ServerInstallTarget {
        switch machineArchitecture() {
        case "arm64": return .macosArm64
        case "x86_64": return .macosX86_64
        default:
            throw LocalServerInstallError.packageUnavailable(
                "This Mac reports an unsupported architecture for the macOS server package.")
        }
    }

    private static func machineArchitecture() -> String {
        var info = utsname()
        guard uname(&info) == 0 else { return "unknown" }
        return withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
    }
}

/// How the bundled server package was trusted. Release and development are
/// deliberately distinct; development never satisfies the release gate.
enum ServerPackageProvenance: String, Equatable, Sendable {
    case release
    case development
}

/// Cheap classification used by the wizard before any cryptographic work.
enum ServerInstallPayloadKind: String, Equatable, Sendable {
    case none
    case release
    case development

    var isInstalled: Bool { self != .none }
}

enum DevelopmentTLSProvisioningResult: Equatable, Sendable {
    case provisioned
    /// Existing material was found without the development marker. It was not
    /// modified; the reviewed server plan must validate it.
    case existingUnverifiedMaterial
}

enum LocalServerInstallError: Error, Equatable, Sendable, CustomStringConvertible {
    case packageUnavailable(String)
    case helperUnavailable(String)
    case invalidConfiguration(String)
    case authorizationCancelled
    case authorizationFailed(String)
    case helperFailed(status: Int32, detail: String)
    case timedOut
    case outputExceeded
    case invalidResponse(String)
    case commandRejected(String)
    case returnedRefusal(String)
    case privilegedOutcomeUnknown(String)
    case developmentTLSPreparationFailed(String)
    case developmentTLSProvisioningFailed(String)
    case cancelled

    var description: String {
        switch self {
        case .packageUnavailable(let reason):
            reason
        case .helperUnavailable(let detail):
            "The packaged server installer helper is not usable: \(detail)"
        case .invalidConfiguration(let detail):
            "The installation request is invalid: \(detail)"
        case .authorizationCancelled:
            "Administrator authorization was cancelled. The installer was not run and no host change was made by this attempt."
        case .authorizationFailed(let detail):
            "macOS could not authorize the privileged installer: \(detail)"
        case .helperFailed(let status, let detail):
            "The server installer helper refused or failed (exit \(status)). \(detail)"
        case .timedOut:
            "The privileged installer did not finish within its time limit. Its outcome is not assumed."
        case .outputExceeded:
            "The privileged installer produced more output than the bounded client accepts."
        case .invalidResponse(let detail):
            "The server installer returned an unusable response: \(detail)"
        case .commandRejected(let detail):
            detail
        case .returnedRefusal(let detail):
            detail
        case .privilegedOutcomeUnknown(let detail):
            detail
        case .developmentTLSPreparationFailed(let detail):
            "Development-only TLS material could not be prepared: \(detail)"
        case .developmentTLSProvisioningFailed(let detail):
            "Development-only TLS material could not be provisioned at /etc/helicoid/tls: \(detail)"
        case .cancelled:
            "The installation wait was cancelled. This does not prove the privileged installer stopped."
        }
    }

    /// True only when the helper definitely did not run because the macOS
    /// authorization prompt was dismissed before execution.
    var isAuthorizationCancellation: Bool {
        self == .authorizationCancelled
    }
}

/// Shared bounded JSON coding for the server installer contract.
enum InstallerJSON {
    static func decoder() -> JSONDecoder {
        JSONDecoder()
    }

    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }

    static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try decoder().decode(type, from: data)
        } catch {
            throw LocalServerInstallError.invalidResponse(
                "The JSON payload did not match the installer v2 contract.")
        }
    }

    /// Extracts one JSON object from helper output that may be preceded by
    /// bounded diagnostic lines. Nothing is trusted from the ignored text.
    static func jsonObjectData(from raw: Data) -> Data? {
        if let first = raw.firstIndex(of: UInt8(ascii: "{")),
           let last = raw.lastIndex(of: UInt8(ascii: "}")),
           first <= last {
            return Data(raw[first...last])
        }
        return nil
    }
}

// MARK: - v2 request inputs

struct InstallerPreflightInput: Encodable, Sendable {
    let contractVersion: Int
    let configuration: InstallerDeploymentConfiguration

    enum CodingKeys: String, CodingKey {
        case contractVersion = "contract_version"
        case configuration
    }
}

struct InstallerPlanInput: Encodable, Sendable {
    let contractVersion: Int
    let configuration: InstallerDeploymentConfiguration
    let preflight: InstallerPreflightResult
    let packageDirectory: String

    enum CodingKeys: String, CodingKey {
        case contractVersion = "contract_version"
        case configuration
        case preflight
        case packageDirectory = "package_dir"
    }
}

struct InstallerApplyInput: Encodable, Sendable {
    let contractVersion: Int
    let configuration: InstallerDeploymentConfiguration
    let preflight: InstallerPreflightResult
    let plan: InstallerInstallPlan
    let reviewedPlanDigest: String
    let confirm: Bool
    let packageDirectory: String
    let verifyingKeyHex: String

    enum CodingKeys: String, CodingKey {
        case contractVersion = "contract_version"
        case configuration
        case preflight
        case plan
        case reviewedPlanDigest = "reviewed_plan_digest"
        case confirm
        case packageDirectory = "package_dir"
        case verifyingKeyHex = "verify_key"
    }
}

struct InstallerStatusInput: Encodable, Sendable {
    let contractVersion: Int
    let configuration: InstallerDeploymentConfiguration

    enum CodingKeys: String, CodingKey {
        case contractVersion = "contract_version"
        case configuration
    }
}

struct InstallerCancelInput: Encodable, Sendable {
    let contractVersion: Int
    let configuration: InstallerDeploymentConfiguration
    let operationId: String
    let confirm: Bool
    let confirmUnverifiedCompletion: Bool

    enum CodingKeys: String, CodingKey {
        case contractVersion = "contract_version"
        case configuration
        case operationId = "operation_id"
        case confirm
        case confirmUnverifiedCompletion = "confirm_unverified_completion"
    }
}

// MARK: - Configuration

struct InstallerDeploymentConfiguration: Codable, Equatable, Sendable {
    let deploymentKind: String
    let network: InstallerNetworkConfiguration
    let storage: InstallerStorageConfiguration

    enum CodingKeys: String, CodingKey {
        case deploymentKind = "deployment_kind"
        case network
        case storage
    }

    static func macos(
        authorityPort: UInt16,
        dataDirectory: String = ServerInstallContract.fixedDataDirectory,
        backupDirectory: String
    ) -> InstallerDeploymentConfiguration {
        InstallerDeploymentConfiguration(
            deploymentKind: "macos_launchd",
            network: InstallerNetworkConfiguration(
                scope: "loopback_development",
                authorityPort: authorityPort,
                bindAddress: nil,
                clientHostname: nil),
            storage: InstallerStorageConfiguration(
                dataDirectory: dataDirectory,
                backupDirectory: backupDirectory,
                preserveDataOnRemove: true))
    }
}

struct InstallerNetworkConfiguration: Codable, Equatable, Sendable {
    let scope: String
    let authorityPort: UInt16
    let bindAddress: String?
    let clientHostname: String?

    enum CodingKeys: String, CodingKey {
        case scope
        case authorityPort = "authority_port"
        case bindAddress = "bind_address"
        case clientHostname = "client_hostname"
    }
}

struct InstallerStorageConfiguration: Codable, Equatable, Sendable {
    let dataDirectory: String
    let backupDirectory: String
    let preserveDataOnRemove: Bool

    enum CodingKeys: String, CodingKey {
        case dataDirectory = "data_directory"
        case backupDirectory = "backup_directory"
        case preserveDataOnRemove = "preserve_data_on_remove"
    }
}

// MARK: - Capabilities

struct InstallerCapabilities: Codable, Equatable, Sendable {
    let contractVersion: Int
    let supportedDeploymentKinds: [String]
    let supportedNetworkScopes: [String]
    let supportedActions: [String]
    let customStorageDirectories: Bool
    let durableOperationJournal: Bool
    let cancellation: Bool
    let onlineUpdate: Bool
    let backupAndRestore: Bool
    let publicEdgeIntegration: Bool
    let reasonsUnavailable: [String: String]

    enum CodingKeys: String, CodingKey {
        case contractVersion = "contract_version"
        case supportedDeploymentKinds = "supported_deployment_kinds"
        case supportedNetworkScopes = "supported_network_scopes"
        case supportedActions = "supported_actions"
        case customStorageDirectories = "custom_storage_directories"
        case durableOperationJournal = "durable_operation_journal"
        case cancellation
        case onlineUpdate = "online_update"
        case backupAndRestore = "backup_and_restore"
        case publicEdgeIntegration = "public_edge_integration"
        case reasonsUnavailable = "reasons_unavailable"
    }

    var supportsMacOSInstall: Bool {
        supportedDeploymentKinds.contains("macos_launchd")
            && supportedNetworkScopes.contains("loopback_development")
            && supportedActions.contains("install")
    }

    var installUnavailableReason: String {
        if let reason = reasonsUnavailable["macos_launchd"], !reason.isEmpty {
            return reason
        }
        if !supportedDeploymentKinds.contains("macos_launchd") {
            return "This hs-server build does not support the macOS launchd deployment."
        }
        if !supportedNetworkScopes.contains("loopback_development") {
            return "This hs-server build does not support the loopback development network scope."
        }
        return "This hs-server build does not advertise the install action."
    }
}

// MARK: - Preflight

struct InstallerPreflightResult: Codable, Equatable, Sendable {
    let contractVersion: Int
    let configuration: InstallerDeploymentConfiguration
    let ok: Bool
    let hostChecks: InstallerHostPreflight
    let tlsCertificateSha256: String?
    let tlsSubjectNameVerified: Bool
    let capabilities: InstallerCapabilities

    enum CodingKeys: String, CodingKey {
        case contractVersion = "contract_version"
        case configuration
        case ok
        case hostChecks = "host_checks"
        case tlsCertificateSha256 = "tls_certificate_sha256"
        case tlsSubjectNameVerified = "tls_subject_name_verified"
        case capabilities
    }
}

struct InstallerHostPreflight: Codable, Equatable, Sendable {
    let contractVersion: Int
    let ok: Bool
    let checks: InstallerHostChecks

    enum CodingKeys: String, CodingKey {
        case contractVersion = "contract_version"
        case ok
        case checks
    }
}

struct InstallerHostChecks: Codable, Equatable, Sendable {
    let os: InstallerCheckResult
    let arch: InstallerCheckResult
    let privileges: InstallerPrivilegesCheck
    let storage: InstallerStorageCheck
    let ports: InstallerPortsCheck
    let paths: InstallerPathsCheck
    let services: InstallerServicesCheck
    let existingInstall: InstallerExistingInstallCheck

    enum CodingKeys: String, CodingKey {
        case os
        case arch
        case privileges
        case storage
        case ports
        case paths
        case services
        case existingInstall = "existing_install"
    }

    var blockingSummaries: [String] {
        var summaries: [String] = []
        if !os.ok { summaries.append(os.reason ?? "Operating system check failed.") }
        if !arch.ok { summaries.append(arch.reason ?? "Architecture check failed.") }
        if !privileges.ok { summaries.append(privileges.reason ?? "Administrator access check failed.") }
        if !storage.ok { summaries.append(storage.reason ?? "Storage check failed.") }
        if !ports.ok {
            for conflict in ports.conflicts {
                summaries.append("Port \(conflict.port)/\(conflict.transportProtocol) is used by \(conflict.process).")
            }
            if ports.conflicts.isEmpty {
                summaries.append("The selected authority port could not be verified as free.")
            }
        }
        if !paths.ok {
            let details = paths.checked.compactMap(\.reason)
            summaries.append(contentsOf: details.isEmpty ? ["A reviewed installation path is not safe."] : details)
        }
        if !services.ok {
            summaries.append(contentsOf: services.conflicts.isEmpty
                ? ["An existing launchd service conflicts with this installation."]
                : services.conflicts)
        }
        if existingInstall.detected {
            summaries.append(existingInstall.state ?? "An existing Helicoid installation was detected.")
        }
        return Array(summaries.prefix(8))
    }
}

struct InstallerCheckResult: Codable, Equatable, Sendable {
    let ok: Bool
    let value: String
    let version: String?
    let reason: String?
}

struct InstallerPrivilegesCheck: Codable, Equatable, Sendable {
    let ok: Bool
    let isRoot: Bool
    let reason: String?

    enum CodingKeys: String, CodingKey {
        case ok
        case isRoot = "is_root"
        case reason
    }
}

struct InstallerStorageCheck: Codable, Equatable, Sendable {
    let ok: Bool
    let totalBytes: UInt64
    let availableBytes: UInt64
    let minRequiredBytes: UInt64
    let reason: String?

    enum CodingKeys: String, CodingKey {
        case ok
        case totalBytes = "total_bytes"
        case availableBytes = "available_bytes"
        case minRequiredBytes = "min_required_bytes"
        case reason
    }
}

struct InstallerPortsCheck: Codable, Equatable, Sendable {
    let ok: Bool
    let listeners: [InstallerPortListener]
    let conflicts: [InstallerPortConflict]
}

struct InstallerPortListener: Codable, Equatable, Sendable {
    let port: UInt16
    let transportProtocol: String
    let occupied: Bool
    let process: String?

    enum CodingKeys: String, CodingKey {
        case port
        case transportProtocol = "protocol"
        case occupied
        case process
    }
}

struct InstallerPortConflict: Codable, Equatable, Sendable {
    let port: UInt16
    let transportProtocol: String
    let process: String

    enum CodingKeys: String, CodingKey {
        case port
        case transportProtocol = "protocol"
        case process
    }
}

struct InstallerPathsCheck: Codable, Equatable, Sendable {
    let ok: Bool
    let checked: [InstallerPathCheck]
}

struct InstallerPathCheck: Codable, Equatable, Sendable {
    let path: String
    let exists: Bool
    let ownedByUs: Bool
    let reason: String?

    enum CodingKeys: String, CodingKey {
        case path
        case exists
        case ownedByUs = "owned_by_us"
        case reason
    }
}

struct InstallerServicesCheck: Codable, Equatable, Sendable {
    let ok: Bool
    let existingUnits: [String]
    let conflicts: [String]

    enum CodingKeys: String, CodingKey {
        case ok
        case existingUnits = "existing_units"
        case conflicts
    }
}

struct InstallerExistingInstallCheck: Codable, Equatable, Sendable {
    let detected: Bool
    let version: String?
    let state: String?
}

// MARK: - Plan

struct InstallerPlanResult: Codable, Equatable, Sendable {
    let contractVersion: Int
    let ok: Bool
    let configuration: InstallerDeploymentConfiguration
    let plan: InstallerInstallPlan?
    let reviewedPlanDigest: String?
    let packageEvidence: InstallerPackageEvidence?
    let tlsEvidence: InstallerTLSEvidence?
    let identityEvidence: InstallerIdentityEvidence?
    let capabilities: InstallerCapabilities
    let warnings: [String]
    let error: String?

    enum CodingKeys: String, CodingKey {
        case contractVersion = "contract_version"
        case ok
        case configuration
        case plan
        case reviewedPlanDigest = "reviewed_plan_digest"
        case packageEvidence = "package_evidence"
        case tlsEvidence = "tls_evidence"
        case identityEvidence = "identity_evidence"
        case capabilities
        case warnings
        case error
    }
}

struct InstallerPackageEvidence: Codable, Equatable, Sendable {
    let manifestSha256: String
    let verifyingKeySha256: String
    let target: String
    let artifactPath: String
    let artifactSha256: String
    let artifactSizeBytes: UInt64

    enum CodingKeys: String, CodingKey {
        case manifestSha256 = "manifest_sha256"
        case verifyingKeySha256 = "verifying_key_sha256"
        case target
        case artifactPath = "artifact_path"
        case artifactSha256 = "artifact_sha256"
        case artifactSizeBytes = "artifact_size_bytes"
    }
}

struct InstallerTLSEvidence: Codable, Equatable, Sendable {
    let certificateSha256: String
    let privateKeySha256: String

    enum CodingKeys: String, CodingKey {
        case certificateSha256 = "certificate_sha256"
        case privateKeySha256 = "private_key_sha256"
    }
}

struct InstallerIdentityEvidence: Codable, Equatable, Sendable {
    let serviceAccount: String
    let serviceGroup: String
    let decision: String

    enum CodingKeys: String, CodingKey {
        case serviceAccount = "service_account"
        case serviceGroup = "service_group"
        case decision
    }
}

struct InstallerInstallPlan: Codable, Equatable, Sendable {
    let reviewDigest: String
    let product: String
    let version: String
    let serviceUser: InstallerServiceUserSpec
    let directories: [InstallerDirectorySpec]
    let files: [InstallerFileSpec]
    let units: [InstallerUnitSpec]
    let firewall: [InstallerFirewallRule]
    let listeners: [InstallerListenerSpec]
    let migrations: InstallerMigrationSpec
    let notImplemented: [String]

    enum CodingKeys: String, CodingKey {
        case reviewDigest = "review_digest"
        case product
        case version
        case serviceUser = "service_user"
        case directories
        case files
        case units
        case firewall
        case listeners
        case migrations
        case notImplemented = "not_implemented"
    }
}

struct InstallerServiceUserSpec: Codable, Equatable, Sendable {
    let name: String
    let create: Bool
}

struct InstallerDirectorySpec: Codable, Equatable, Sendable {
    let path: String
    let owner: String
    let mode: String
    let create: Bool
}

struct InstallerFileSpec: Codable, Equatable, Sendable {
    let source: String
    let destination: String
    let mode: String
}

struct InstallerUnitSpec: Codable, Equatable, Sendable {
    let name: String
    let action: String
    let enabled: Bool
    let restartPolicy: String

    enum CodingKeys: String, CodingKey {
        case name
        case action
        case enabled
        case restartPolicy = "restart_policy"
    }
}

struct InstallerFirewallRule: Codable, Equatable, Sendable {
    let port: UInt16
    let transportProtocol: String
    let action: String
    let comment: String

    enum CodingKeys: String, CodingKey {
        case port
        case transportProtocol = "protocol"
        case action
        case comment
    }
}

struct InstallerListenerSpec: Codable, Equatable, Sendable {
    let port: UInt16
    let transportProtocol: String
    let description: String

    enum CodingKeys: String, CodingKey {
        case port
        case transportProtocol = "protocol"
        case description
    }
}

struct InstallerMigrationSpec: Codable, Equatable, Sendable {
    let schemaVersion: Int64
    let backupRequired: Bool

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case backupRequired = "backup_required"
    }
}

// MARK: - Operation status

struct InstallerOperationStatus: Codable, Equatable, Sendable {
    let contractVersion: Int
    let configuration: InstallerDeploymentConfiguration
    let operationId: String?
    let action: String?
    let state: String
    let reviewedPlanDigest: String?
    let currentPhase: String?
    let phases: [String: String]
    let cancellationAvailable: Bool
    let resumeAvailable: Bool
    let serviceInstalled: Bool
    let bootstrapReady: Bool
    let serverReadyForEnrollment: Bool
    let result: InstallerOperationResult

    enum CodingKeys: String, CodingKey {
        case contractVersion = "contract_version"
        case configuration
        case operationId = "operation_id"
        case action
        case state
        case reviewedPlanDigest = "reviewed_plan_digest"
        case currentPhase = "current_phase"
        case phases
        case cancellationAvailable = "cancellation_available"
        case resumeAvailable = "resume_available"
        case serviceInstalled = "service_installed"
        case bootstrapReady = "bootstrap_ready"
        case serverReadyForEnrollment = "server_ready_for_enrollment"
        case result
    }
}

struct InstallerOperationResult: Codable, Equatable, Sendable {
    let code: String
    let summary: String
    let errors: [String]
    let warnings: [String]
}
