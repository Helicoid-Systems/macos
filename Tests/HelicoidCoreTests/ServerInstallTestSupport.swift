import CryptoKit
import Foundation
@testable import HelicoidCore

enum ServerInstallTestSupport {
    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    /// Test-only release policy seam. It authorizes the release path without
    /// an Apple-signed test runner; production defaults to fail-closed.
    static func authorizedReleaseTrust(keys: [String]) -> ServerReleaseTrustPolicy {
        ServerReleaseTrustPolicy(
            compiledTrustKeyHexes: keys,
            managerIdentityIsTrusted: { true })
    }

    static let failClosedReleaseTrust = ServerReleaseTrustPolicy(
        compiledTrustKeyHexes: [],
        managerIdentityIsTrusted: { true })

    static func jsonData(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    static func dictionary<T: Encodable>(_ value: T) throws -> [String: Any] {
        let data = try InstallerJSON.encoder().encode(value)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw LocalServerInstallError.invalidResponse("Test fixture encoding failed.")
        }
        return object
    }

    static func decode<T: Decodable>(_ type: T.Type, from object: [String: Any]) throws -> T {
        try InstallerJSON.decode(type, from: jsonData(object))
    }

    static func configuration() -> InstallerDeploymentConfiguration {
        .macos(
            authorityPort: 8920,
            backupDirectory: "/private/tmp/helicoid-test-backups")
    }

    static func capabilities(
        actions: [String] = ["preflight", "plan", "install"],
        reasons: [String: String] = [:]
    ) throws -> InstallerCapabilities {
        try decode(InstallerCapabilities.self, from: [
            "contract_version": 2,
            "supported_deployment_kinds": ["macos_launchd"],
            "supported_network_scopes": ["loopback_development"],
            "supported_actions": actions,
            "custom_storage_directories": false,
            "durable_operation_journal": true,
            "cancellation": true,
            "online_update": false,
            "backup_and_restore": false,
            "public_edge_integration": false,
            "reasons_unavailable": reasons,
        ])
    }

    static func preflight(
        ok: Bool = true,
        configuration: InstallerDeploymentConfiguration = ServerInstallTestSupport.configuration()
    ) throws -> InstallerPreflightResult {
        let config = try dictionary(configuration)
        let architecture = try ServerInstallTarget.current().architecture
        return try decode(InstallerPreflightResult.self, from: [
            "contract_version": 2,
            "configuration": config,
            "ok": ok,
            "host_checks": [
                "contract_version": 1,
                "ok": ok,
                "checks": [
                    "os": ["ok": true, "value": "macos", "version": "27.0"],
                    "arch": ["ok": true, "value": architecture],
                    "privileges": ["ok": true, "is_root": true],
                    "storage": [
                        "ok": true,
                        "total_bytes": 8_000_000_000,
                        "available_bytes": 7_000_000_000,
                        "min_required_bytes": 2_147_483_648,
                    ],
                    "ports": ["ok": true, "listeners": [], "conflicts": []],
                    "paths": ["ok": true, "checked": []],
                    "services": ["ok": true, "existing_units": [], "conflicts": []],
                    "existing_install": ["detected": false],
                ],
            ],
            "tls_subject_name_verified": false,
            "capabilities": try capabilitiesDictionary(),
        ])
    }

    static func capabilitiesDictionary() throws -> [String: Any] {
        let value = try capabilities()
        return try dictionary(value)
    }

    static func installPlan() throws -> InstallerInstallPlan {
        try decode(InstallerInstallPlan.self, from: [
            "review_digest": String(repeating: "a", count: 64),
            "product": "hs-server",
            "version": "0.1.0",
            "service_user": ["name": "_helicoid", "create": true],
            "directories": [],
            "files": [],
            "units": [],
            "firewall": [],
            "listeners": [[
                "port": 8920,
                "protocol": "tcp",
                "description": "literal loopback HTTPS",
            ]],
            "migrations": ["schema_version": 1, "backup_required": true],
            "not_implemented": [],
        ])
    }

    static func planResult(
        ok: Bool = true,
        configuration: InstallerDeploymentConfiguration = ServerInstallTestSupport.configuration(),
        error: String? = nil
    ) throws -> InstallerPlanResult {
        let packageTarget = try ServerInstallTarget.current().rawValue
        var object: [String: Any] = [
            "contract_version": 2,
            "ok": ok,
            "configuration": try dictionary(configuration),
            "capabilities": try capabilitiesDictionary(),
            "warnings": [],
        ]
        if ok {
            object["plan"] = try dictionary(installPlan())
            object["reviewed_plan_digest"] = String(repeating: "d", count: 64)
            object["package_evidence"] = [
                "manifest_sha256": String(repeating: "b", count: 64),
                "verifying_key_sha256": String(repeating: "e", count: 64),
                "target": packageTarget,
                "artifact_path": "artifacts/hs-server",
                "artifact_sha256": String(repeating: "f", count: 64),
                "artifact_size_bytes": 1024,
            ]
            object["tls_evidence"] = [
                "certificate_sha256": String(repeating: "1", count: 64),
                "private_key_sha256": String(repeating: "2", count: 64),
            ]
            object["identity_evidence"] = [
                "service_account": "_helicoid",
                "service_group": "_helicoid",
                "decision": "account_absent_group_absent",
            ]
        }
        if let error { object["error"] = error }
        return try decode(InstallerPlanResult.self, from: object)
    }

    static func operationStatus(
        state: String = "completed",
        serviceInstalled: Bool = true,
        bootstrapReady: Bool = false,
        readyForEnrollment: Bool = false,
        cancellationAvailable: Bool = false,
        operationId: String? = "operation-1",
        configuration: InstallerDeploymentConfiguration = ServerInstallTestSupport.configuration()
    ) throws -> InstallerOperationStatus {
        var object: [String: Any] = [
            "contract_version": 2,
            "configuration": try dictionary(configuration),
            "action": "install",
            "state": state,
            "reviewed_plan_digest": String(repeating: "d", count: 64),
            "current_phase": state == "completed" ? "completed" : "launchd",
            "phases": state == "completed" ? ["completed": "completed"] : ["launchd": "in_progress"],
            "cancellation_available": cancellationAvailable,
            "resume_available": false,
            "service_installed": serviceInstalled,
            "bootstrap_ready": bootstrapReady,
            "server_ready_for_enrollment": readyForEnrollment,
            "result": [
                "code": state == "cancelled" ? "cancelled" : "completed",
                "summary": state == "cancelled"
                    ? "The incomplete install was rolled back."
                    : "The installer reported \(state).",
                "errors": [],
                "warnings": [],
            ],
        ]
        if let operationId { object["operation_id"] = operationId }
        return try decode(InstallerOperationStatus.self, from: object)
    }

    static func packageFixture(
        platform: String? = nil,
        tamperArtifact: Bool = false,
        developmentEvidence: Bool = false,
        developmentInstall: Bool = false,
        signingKey: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey(),
        trustedKey: Curve25519.Signing.PrivateKey? = nil,
        helperMatchesEvidence: Bool = true
    ) throws -> TestPackageFixture {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("helicoid-install-package-\(UUID().uuidString)", isDirectory: true)
        let helperDirectory = root.appendingPathComponent("Contents/Helpers", isDirectory: true)
        let resources = root.appendingPathComponent("Contents/Resources", isDirectory: true)
        let serverPackage = resources.appendingPathComponent("ServerPackage", isDirectory: true)
        let packageParent = developmentInstall
            ? serverPackage.appendingPathComponent("development", isDirectory: true)
            : serverPackage
        let packageDirectory = packageParent.appendingPathComponent("package", isDirectory: true)
        let artifacts = packageDirectory.appendingPathComponent("artifacts", isDirectory: true)
        try FileManager.default.createDirectory(at: helperDirectory, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: artifacts, withIntermediateDirectories: true)

        let helperData = Data("release-helper-fixture".utf8)
        let helperURL = helperDirectory.appendingPathComponent("hs-server")
        try helperData.write(to: helperURL)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o755)],
            ofItemAtPath: helperURL.path)

        let artifactData = Data("signed-server-artifact".utf8)
        let artifactURL = artifacts.appendingPathComponent("hs-server")
        let artifactBytes = tamperArtifact ? Data("tampered-server-artifact".utf8) : artifactData
        try artifactBytes.write(to: artifactURL)

        let target = try ServerInstallTarget.current()
        let manifest: [String: Any] = [
            "format_version": 1,
            "product": "hs-server",
            "version": "0.1.0",
            "platform": platform ?? target.rawValue,
            "min_schema_version": 1,
            "min_installer_version": "0.1.0",
            "artifacts": [[
                "path": "artifacts/hs-server",
                "sha256": hex(Data(SHA256.hash(data: artifactData))),
                "size_bytes": artifactData.count,
            ]],
        ]
        let manifestData = try jsonData(manifest)
        try manifestData.write(to: packageDirectory.appendingPathComponent("manifest.json"))
        let signature = try signingKey.signature(for: manifestData)
        try signature.write(to: packageDirectory.appendingPathComponent("manifest.sig"))

        let evidenceHelperData = helperMatchesEvidence
            ? helperData
            : Data("different-helper-bytes".utf8)
        let evidence: [String: Any] = [
            "schema": 1,
            "helper": "hs-server",
            "path": "Contents/Helpers/hs-server",
            "developmentOnly": developmentEvidence,
            "distributionSigned": !developmentEvidence,
            "securityFloor": false,
            "installationEnabled": !developmentEvidence,
            "serviceEnabled": !developmentEvidence,
            "signature": developmentEvidence ? "ad-hoc" : "developer-id",
            "sourceSHA256": hex(Data(SHA256.hash(data: evidenceHelperData))),
            "includedSHA256": hex(Data(SHA256.hash(data: evidenceHelperData))),
            "includedBytes": evidenceHelperData.count,
            "architectures": [target.architecture],
            "minos": ["15.0"],
            "managerMinimumMacOS": "15.0",
            "managerArchitectures": [target.architecture],
            "note": "fixture",
        ]
        let key = trustedKey ?? signingKey
        if developmentInstall {
            let keyHex = hex(key.publicKey.rawRepresentation)
            let devEvidence: [String: Any] = [
                "schema": 1,
                "mode": "development-install",
                "developmentOnly": true,
                "distributionSigned": false,
                "installationEnabled": true,
                "helperPath": "Contents/Helpers/hs-server",
                "helperSha256": hex(Data(SHA256.hash(data: helperData))),
                "packageDirectory": "Contents/Resources/ServerPackage/development/package",
                "packageManifestSha256": hex(Data(SHA256.hash(data: manifestData))),
                "packageArtifactPath": "artifacts/hs-server",
                "packageArtifactSha256": hex(Data(SHA256.hash(data: artifactData))),
                "packageArtifactSizeBytes": artifactData.count,
                "packageTarget": target.rawValue,
                "packageProduct": "hs-server",
                "packageVersion": "0.1.0",
                "verificationKeyHex": keyHex,
                "verificationKeySha256": hex(Data(SHA256.hash(data: key.publicKey.rawRepresentation))),
                "note": "test development-only fixture",
            ]
            try jsonData(devEvidence).write(
                to: resources.appendingPathComponent("hs-server-development-install.json"))
        } else {
            let evidenceName = developmentEvidence
                ? "hs-server-development.json"
                : "hs-server-release.json"
            try jsonData(evidence).write(to: resources.appendingPathComponent(evidenceName))

            let roots: [String: Any] = [
                "schema": 1,
                "releaseKeys": [hex(key.publicKey.rawRepresentation)],
            ]
            try FileManager.default.createDirectory(
                at: serverPackage,
                withIntermediateDirectories: true)
            try jsonData(roots).write(to: serverPackage.appendingPathComponent("trust-roots.json"))
        }

        return TestPackageFixture(
            root: root,
            helperURL: helperURL,
            packageDirectory: packageDirectory,
            trustedKey: key)
    }
}

struct TestPackageFixture {
    let root: URL
    let helperURL: URL
    let packageDirectory: URL
    let trustedKey: Curve25519.Signing.PrivateKey

    var trustRootsURL: URL {
        root.appendingPathComponent("Contents")
            .appendingPathComponent("Resources")
            .appendingPathComponent("ServerPackage")
            .appendingPathComponent("trust-roots.json")
    }

    var pinnedKeyHex: String {
        ServerInstallTestSupport.hex(trustedKey.publicKey.rawRepresentation)
    }

    var developmentBuild: ServerDevelopmentBuild {
        ServerDevelopmentBuild(isRequested: true, pinnedTrustKeyHex: pinnedKeyHex)
    }

    /// Test-only policy that authorizes the release path with the fixture's
    /// key. Production uses an Apple-signed Manager and compiled keys.
    var releaseTrust: ServerReleaseTrustPolicy {
        ServerInstallTestSupport.authorizedReleaseTrust(keys: [pinnedKeyHex])
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }
}

actor FakeInstallService: ServerInstallServicing {
    nonisolated let installPayloadPresent: Bool
    nonisolated let installPayloadKind: ServerInstallPayloadKind
    private let availabilityValue: ServerPackageAvailability
    private let capabilitiesValue: InstallerCapabilities
    private let preflightValue: InstallerPreflightResult
    private let planValue: InstallerPlanResult
    private let applyValue: InstallerOperationStatus
    private let statusValue: InstallerOperationStatus
    private let cancelValue: InstallerOperationStatus
    private let capabilitiesError: LocalServerInstallError?
    private let preflightError: LocalServerInstallError?
    private let planError: LocalServerInstallError?
    private let applyError: LocalServerInstallError?
    private let statusError: LocalServerInstallError?
    private let storedConfigurationValue: InstallerDeploymentConfiguration?
    private let storedConfigurationError: LocalServerInstallError?
    private let statusRejectsOtherConfigurations: Bool
    private let tlsProvisionError: LocalServerInstallError?
    private let tlsProvisionResult: DevelopmentTLSProvisioningResult
    private(set) var calls: [String] = []
    private(set) var lastCancellationOperationId: String?
    private(set) var preflightConfigurations: [InstallerDeploymentConfiguration] = []
    private(set) var planConfigurations: [InstallerDeploymentConfiguration] = []
    private(set) var applyConfigurations: [InstallerDeploymentConfiguration] = []
    private(set) var statusConfigurations: [InstallerDeploymentConfiguration] = []
    private(set) var cancelConfigurations: [InstallerDeploymentConfiguration] = []

    init(
        installPayloadPresent: Bool = true,
        installPayloadKind: ServerInstallPayloadKind = .release,
        package: TrustedServerPackage,
        availability: ServerPackageAvailability? = nil,
        capabilities: InstallerCapabilities,
        preflight: InstallerPreflightResult,
        plan: InstallerPlanResult,
        apply: InstallerOperationStatus,
        status: InstallerOperationStatus,
        cancel: InstallerOperationStatus,
        capabilitiesError: LocalServerInstallError? = nil,
        preflightError: LocalServerInstallError? = nil,
        planError: LocalServerInstallError? = nil,
        applyError: LocalServerInstallError? = nil,
        statusError: LocalServerInstallError? = nil,
        storedConfiguration: InstallerDeploymentConfiguration? = nil,
        storedConfigurationError: LocalServerInstallError? = nil,
        statusRejectsOtherConfigurations: Bool = false,
        tlsProvisionError: LocalServerInstallError? = nil,
        tlsProvisionResult: DevelopmentTLSProvisioningResult = .provisioned
    ) {
        self.installPayloadPresent = installPayloadPresent
        self.installPayloadKind = installPayloadKind
        self.availabilityValue = availability ?? .available(package)
        self.capabilitiesValue = capabilities
        self.preflightValue = preflight
        self.planValue = plan
        self.applyValue = apply
        self.statusValue = status
        self.cancelValue = cancel
        self.capabilitiesError = capabilitiesError
        self.preflightError = preflightError
        self.planError = planError
        self.applyError = applyError
        self.statusError = statusError
        self.storedConfigurationValue = storedConfiguration
        self.storedConfigurationError = storedConfigurationError
        self.statusRejectsOtherConfigurations = statusRejectsOtherConfigurations
        self.tlsProvisionError = tlsProvisionError
        self.tlsProvisionResult = tlsProvisionResult
    }

    func packageAvailability() async -> ServerPackageAvailability {
        calls.append("availability")
        return availabilityValue
    }

    func provisionDevelopmentTLSIfNeeded() async throws -> DevelopmentTLSProvisioningResult {
        calls.append("provisionTLS")
        if let tlsProvisionError { throw tlsProvisionError }
        return tlsProvisionResult
    }

    func capabilities() async throws -> InstallerCapabilities {
        calls.append("capabilities")
        if let capabilitiesError { throw capabilitiesError }
        return capabilitiesValue
    }

    func preflight(configuration: InstallerDeploymentConfiguration) async throws -> InstallerPreflightResult {
        calls.append("preflight")
        preflightConfigurations.append(configuration)
        if let preflightError { throw preflightError }
        return preflightValue
    }

    func plan(
        configuration: InstallerDeploymentConfiguration,
        preflight: InstallerPreflightResult,
        package: TrustedServerPackage
    ) async throws -> InstallerPlanResult {
        calls.append("plan")
        planConfigurations.append(configuration)
        if let planError { throw planError }
        return planValue
    }

    func apply(
        configuration: InstallerDeploymentConfiguration,
        preflight: InstallerPreflightResult,
        plan: InstallerPlanResult,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus {
        calls.append("apply")
        applyConfigurations.append(configuration)
        if let applyError { throw applyError }
        return applyValue
    }

    func status(configuration: InstallerDeploymentConfiguration) async throws -> InstallerOperationStatus {
        calls.append("status")
        statusConfigurations.append(configuration)
        if let statusError { throw statusError }
        if statusRejectsOtherConfigurations && configuration != statusValue.configuration {
            throw .helperFailed(
                status: 1,
                detail: "operation record does not match the requested deployment configuration")
        }
        return statusValue
    }

    func storedConfiguration(
        package: TrustedServerPackage
    ) async throws -> InstallerDeploymentConfiguration? {
        calls.append("storedConfiguration")
        if let storedConfigurationError { throw storedConfigurationError }
        return storedConfigurationValue
    }

    func cancel(
        configuration: InstallerDeploymentConfiguration,
        operationId: String,
        confirmUnverifiedCompletion: Bool
    ) async throws -> InstallerOperationStatus {
        calls.append("cancel")
        lastCancellationOperationId = operationId
        cancelConfigurations.append(configuration)
        return cancelValue
    }

    func recordedCalls() -> [String] { calls }
    func recordedCancellationOperationId() -> String? { lastCancellationOperationId }
    func recordedPreflightConfigurations() -> [InstallerDeploymentConfiguration] { preflightConfigurations }
    func recordedPlanConfigurations() -> [InstallerDeploymentConfiguration] { planConfigurations }
    func recordedApplyConfigurations() -> [InstallerDeploymentConfiguration] { applyConfigurations }
    func recordedStatusConfigurations() -> [InstallerDeploymentConfiguration] { statusConfigurations }
    func recordedCancelConfigurations() -> [InstallerDeploymentConfiguration] { cancelConfigurations }
}

actor InMemoryIdentityKeyStore: ManagerIdentityKeyStoring {
    private var bytes: Data?

    func read() async throws -> Data? { bytes }

    func insertIfAbsent(_ bytes: Data) async throws -> Bool {
        guard self.bytes == nil else { return false }
        self.bytes = bytes
        return true
    }
}

final class InMemoryInstallConfigurationStore: ServerInstallConfigurationStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var value: InstallerDeploymentConfiguration?

    init(_ value: InstallerDeploymentConfiguration? = nil) {
        self.value = value
    }

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

struct FailingInstallConfigurationStore: ServerInstallConfigurationStoring {
    struct Failure: Error {}
    func load() -> InstallerDeploymentConfiguration? { nil }
    func save(_ configuration: InstallerDeploymentConfiguration) throws { throw Failure() }
}

@MainActor
func makeGuidedInstallModel(
    service: FakeInstallService,
    configurationStore: any ServerInstallConfigurationStoring = InMemoryInstallConfigurationStore()
) -> GuidedServerSetupModel {
    GuidedServerSetupModel(
        managerIdentityStore: ManagerIdentityStore(keyStore: InMemoryIdentityKeyStore()),
        installService: service,
        configurationStore: configurationStore,
        demoMode: false)
}

@MainActor
func advanceToInstall(_ model: GuidedServerSetupModel) {
    model.setRoute(.thisMac)
    model.setStoragePath(LocalHostingOwnershipPlan.current.dataPath)
    model.setBackupDestination("/private/tmp/helicoid-test-backups")
    model.advance()
    for name in GuidedServerSetupModel.requiredLocalChecks {
        model.setHostCheck(name, status: .passed)
    }
    model.advance()
    model.setDeploymentName("Test server")
    model.setAdministratorUsername("admin")
    model.advance()
    model.advance()
    model.advance()
    model.advance()
    model.advance()
}

extension TrustedServerPackage {
    static func testFixture(
        helperURL: URL = URL(fileURLWithPath: "/private/tmp/hs-server"),
        provenance: ServerPackageProvenance = .release
    ) -> TrustedServerPackage {
        TrustedServerPackage(
            helperURL: helperURL,
            packageDirectory: URL(fileURLWithPath: "/private/tmp/package"),
            verifyingKeyHex: String(repeating: "a", count: 64),
            target: (try? ServerInstallTarget.current()) ?? .macosArm64,
            product: "hs-server",
            version: "0.1.0",
            manifestSha256: String(repeating: "b", count: 64),
            artifactPath: "artifacts/hs-server",
            artifactSha256: String(repeating: "c", count: 64),
            artifactSizeBytes: 1_024,
            helperSha256: String(repeating: "a", count: 64),
            provenance: provenance)
    }
}
