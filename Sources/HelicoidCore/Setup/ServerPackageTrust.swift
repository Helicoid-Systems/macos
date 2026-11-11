import CryptoKit
import Darwin
import Foundation
import Security

/// Release trust is a property of the Manager binary, not of files an attacker
/// may replace alongside it. The release privileged path is enabled only when
/// the running Manager has an independently verified Apple Developer ID
/// signature and the packaged release trust roots equal keys compiled into the
/// binary. The default has no compiled keys, so an ordinary or ad-hoc build
/// fails closed. Development installs remain explicitly ad-hoc.
struct ServerReleaseTrustPolicy: Sendable {
    let compiledTrustKeyHexes: [String]
    let managerIdentityIsTrusted: @Sendable () -> Bool

    init(
        compiledTrustKeyHexes: [String],
        managerIdentityIsTrusted: @escaping @Sendable () -> Bool
    ) {
        self.compiledTrustKeyHexes = compiledTrustKeyHexes
            .map { $0.lowercased() }
            .filter { value in value.count == 64 && value.allSatisfy(\.isHexDigit) }
        self.managerIdentityIsTrusted = managerIdentityIsTrusted
    }

    static let production = ServerReleaseTrustPolicy(
        compiledTrustKeyHexes: ServerInstallContract.compiledReleaseTrustKeyHexes,
        managerIdentityIsTrusted: {
            ManagerReleaseIdentity.isDeveloperIDTrusted(
                teamIdentifier: ServerInstallContract.releaseManagerTeamIdentifier)
        })

    var isAuthorized: Bool {
        !compiledTrustKeyHexes.isEmpty && managerIdentityIsTrusted()
    }
}

/// Independently verifies that the running Manager is signed by an Apple-
/// anchored Developer ID certificate for the expected team. An ad-hoc or
/// unsigned binary fails this check.
enum ManagerReleaseIdentity {
    /// Raw values from Security/SecCode.h. Using the numeric flag avoids
    /// depending on how CF_OPTIONS constants are imported into Swift.
    private static let signingInformationFlag: UInt32 = 1 << 1 // kSecCSSigningInformation
    private static let adHocSignatureFlag: UInt32 = 0x0002 // kSecCodeSignatureAdhoc

    static func isDeveloperIDTrusted(teamIdentifier: String) -> Bool {
        guard !teamIdentifier.isEmpty else { return false }

        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return false }

        let requirementText =
            "anchor apple generic and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
                requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecCodeCheckValidity(code, [], requirement) == errSecSuccess else {
            return false
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else {
            return false
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
                staticCode,
                SecCSFlags(rawValue: signingInformationFlag),
                &information) == errSecSuccess,
              let dictionary = information as? [String: Any] else {
            return false
        }
        let signatureFlags = (dictionary[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        return (signatureFlags & adHocSignatureFlag) == 0
    }
}

/// A package that passed the Manager's independent signature, product,
/// target, and artifact checks. The helper still re-verifies the package with
/// its own trusted release key; this value is not an authorization token.
struct TrustedServerPackage: Equatable, Sendable {
    let helperURL: URL
    let packageDirectory: URL
    let verifyingKeyHex: String
    let target: ServerInstallTarget
    let product: String
    let version: String
    let manifestSha256: String
    let artifactPath: String
    let artifactSha256: String
    let artifactSizeBytes: UInt64
    let helperSha256: String
    let provenance: ServerPackageProvenance

    init(
        helperURL: URL,
        packageDirectory: URL,
        verifyingKeyHex: String,
        target: ServerInstallTarget,
        product: String,
        version: String,
        manifestSha256: String,
        artifactPath: String,
        artifactSha256: String,
        artifactSizeBytes: UInt64,
        helperSha256: String = "",
        provenance: ServerPackageProvenance = .release
    ) {
        self.helperURL = helperURL
        self.packageDirectory = packageDirectory
        self.verifyingKeyHex = verifyingKeyHex
        self.target = target
        self.product = product
        self.version = version
        self.manifestSha256 = manifestSha256
        self.artifactPath = artifactPath
        self.artifactSha256 = artifactSha256
        self.artifactSizeBytes = artifactSizeBytes
        self.helperSha256 = helperSha256
        self.provenance = provenance
    }

    var isDevelopment: Bool { provenance == .development }
}

enum ServerPackageAvailability: Equatable, Sendable {
    case available(TrustedServerPackage)
    case unavailable(reason: String)
    case invalid(reason: String)

    var package: TrustedServerPackage? {
        if case .available(let package) = self { return package }
        return nil
    }

    var isAvailable: Bool { package != nil }

    var explanation: String {
        switch self {
        case .available(let package):
            if package.isDevelopment {
                return "DEVELOPMENT ONLY (ad-hoc development trust, not a signed release): build-pinned development package \(package.product) \(package.version) is present for \(package.target.rawValue)."
            }
            return "Signed macOS server package \(package.product) \(package.version) is present for \(package.target.rawValue)."
        case .unavailable(let reason), .invalid(let reason):
            return reason
        }
    }
}

/// Release evidence is added only by a release packaging step. The
/// development `hs-server-development.json` record explicitly says
/// installation is disabled and is never treated as release evidence.
struct ServerReleaseEvidence: Decodable, Equatable, Sendable {
    let schema: Int
    let helper: String
    let path: String
    let developmentOnly: Bool
    let distributionSigned: Bool
    let installationEnabled: Bool
    let serviceEnabled: Bool
    let signature: String
    let includedSHA256: String
    let architectures: [String]

    enum CodingKeys: String, CodingKey {
        case schema
        case helper
        case path
        case developmentOnly
        case distributionSigned
        case installationEnabled
        case serviceEnabled
        case signature
        case includedSHA256
        case architectures
    }
}

struct ServerPackageTrustRoots: Decodable, Equatable, Sendable {
    let schema: Int
    let releaseKeys: [String]

    enum CodingKeys: String, CodingKey {
        case schema
        case releaseKeys
    }
}

/// Build-time development pin from the Manager's Info.plist. Both keys are
/// written only by the development bundle packaging step; a normal build has
/// neither and can never activate the development path.
struct ServerDevelopmentBuild: Equatable, Sendable {
    let isRequested: Bool
    let pinnedTrustKeyHex: String?

    init(isRequested: Bool, pinnedTrustKeyHex: String?) {
        self.isRequested = isRequested
        let normalized = pinnedTrustKeyHex?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let normalized, Self.isHex32Bytes(normalized) {
            self.pinnedTrustKeyHex = normalized
        } else {
            self.pinnedTrustKeyHex = nil
        }
    }

    var isEnabled: Bool { isRequested && pinnedTrustKeyHex != nil }

    static let disabled = ServerDevelopmentBuild(isRequested: false, pinnedTrustKeyHex: nil)

    static var main: ServerDevelopmentBuild {
        let info = Bundle.main.infoDictionary
        var requested = false
        if let bool = info?[ServerInstallContract.developmentInstallInfoKey] as? Bool {
            requested = bool
        } else if let number = info?[ServerInstallContract.developmentInstallInfoKey] as? NSNumber {
            requested = number.boolValue
        }
        let key = info?[ServerInstallContract.developmentTrustKeyInfoKey] as? String
        return ServerDevelopmentBuild(isRequested: requested, pinnedTrustKeyHex: key)
    }

    private static func isHex32Bytes(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy(\.isHexDigit)
    }
}

/// One development evidence document binds the helper bytes and exact signed
/// package together. It is untrusted input: the Manager checks every digest
/// against actual bytes and requires the verification key to equal the
/// build-time Info.plist pin.
struct ServerDevelopmentInstallEvidence: Decodable, Equatable, Sendable {
    let schema: Int
    let mode: String
    let developmentOnly: Bool
    let distributionSigned: Bool
    let installationEnabled: Bool
    let helperPath: String
    let helperSha256: String
    let packageDirectory: String
    let packageManifestSha256: String
    let packageArtifactPath: String
    let packageArtifactSha256: String
    let packageArtifactSizeBytes: UInt64
    let packageTarget: String
    let packageProduct: String
    let packageVersion: String
    let verificationKeyHex: String
    let verificationKeySha256: String
    let note: String?

    enum CodingKeys: String, CodingKey {
        case schema
        case mode
        case developmentOnly
        case distributionSigned
        case installationEnabled
        case helperPath
        case helperSha256
        case packageDirectory
        case packageManifestSha256
        case packageArtifactPath
        case packageArtifactSha256
        case packageArtifactSizeBytes
        case packageTarget
        case packageProduct
        case packageVersion
        case verificationKeyHex
        case verificationKeySha256
        case note
    }
}

/// Reads a signed payload from the Manager bundle and validates it before any
/// privileged helper call. Absence is a normal, explicit unavailable state.
struct BundledServerPackageProvider: Sendable {
    let rootURL: URL
    let developmentBuild: ServerDevelopmentBuild
    let releaseTrust: ServerReleaseTrustPolicy
    private let releaseAuthorized: Bool

    init(
        rootURL: URL = Bundle.main.bundleURL,
        developmentBuild: ServerDevelopmentBuild = .main,
        releaseTrust: ServerReleaseTrustPolicy = .production
    ) {
        self.rootURL = rootURL
        self.developmentBuild = developmentBuild
        self.releaseTrust = releaseTrust
        self.releaseAuthorized = releaseTrust.isAuthorized
    }

    var helperURL: URL {
        bundleURL(ServerInstallContract.helperRelativePath)
    }

    var releaseEvidenceURL: URL {
        bundleURL(ServerInstallContract.releaseEvidenceRelativePath)
    }

    var developmentEvidenceURL: URL {
        bundleURL(ServerInstallContract.developmentEvidenceRelativePath)
    }

    var trustRootsURL: URL {
        bundleURL(ServerInstallContract.packageTrustRootsRelativePath)
    }

    var packageDirectoryURL: URL {
        bundleURL(ServerInstallContract.packageDirectoryRelativePath)
    }

    var developmentInstallEvidenceURL: URL {
        bundleURL(ServerInstallContract.developmentInstallEvidenceRelativePath)
    }

    var developmentPackageDirectoryURL: URL {
        bundleURL(ServerInstallContract.developmentPackageDirectoryRelativePath)
    }

    private func bundleURL(_ relativePath: String) -> URL {
        relativePath.split(separator: "/").reduce(rootURL) { partial, component in
            partial.appendingPathComponent(String(component))
        }
    }

    /// Release evidence always wins. A development payload is considered only
    /// when this Manager was built with the development pin and no release
    /// evidence is present.
    var payloadKind: ServerInstallPayloadKind {
        if FileManager.default.fileExists(atPath: releaseEvidenceURL.path) {
            return .release
        }
        if developmentBuild.isEnabled, developmentPayloadPresent {
            return .development
        }
        return .none
    }

    private var developmentPayloadPresent: Bool {
        guard developmentBuild.isEnabled,
              Self.isRegularFileWithoutSymlink(helperURL),
              Self.isExecutableFileWithoutSymlink(helperURL),
              Self.isRegularFileWithoutSymlink(developmentInstallEvidenceURL),
              Self.isDirectoryWithoutSymlink(developmentPackageDirectoryURL),
              Self.isRegularFileWithoutSymlink(developmentPackageDirectoryURL.appendingPathComponent("manifest.json")),
              Self.isRegularFileWithoutSymlink(developmentPackageDirectoryURL.appendingPathComponent("manifest.sig")),
              Self.isDirectoryWithoutSymlink(developmentPackageDirectoryURL.appendingPathComponent("artifacts")),
              Self.isRegularFileWithoutSymlink(
                developmentPackageDirectoryURL.appendingPathComponent("artifacts").appendingPathComponent("hs-server")) else {
            return false
        }
        guard let evidence = try? Self.readDevelopmentEvidence(developmentInstallEvidenceURL),
              Self.validateDevelopmentEvidenceShape(evidence, pinnedKey: developmentBuild.pinnedTrustKeyHex) else {
            return false
        }
        return true
    }

    /// Cheap existence and small-file shape check. Cryptographic validation is
    /// deliberately deferred to `availability()` so opening the wizard cannot
    /// block on hashing a large artifact.
    var installPayloadPresent: Bool {
        if FileManager.default.fileExists(atPath: releaseEvidenceURL.path) {
            return releasePayloadPresent
        }
        if developmentBuild.isEnabled {
            return developmentPayloadPresent
        }
        return false
    }

    private var releasePayloadPresent: Bool {
        guard releaseAuthorized else { return false }
        guard Self.isRegularFileWithoutSymlink(helperURL),
              Self.isExecutableFileWithoutSymlink(helperURL),
              Self.isRegularFileWithoutSymlink(releaseEvidenceURL),
              Self.isRegularFileWithoutSymlink(trustRootsURL),
              Self.isDirectoryWithoutSymlink(packageDirectoryURL),
              Self.isRegularFileWithoutSymlink(packageDirectoryURL.appendingPathComponent("manifest.json")),
              Self.isRegularFileWithoutSymlink(packageDirectoryURL.appendingPathComponent("manifest.sig")),
              Self.isDirectoryWithoutSymlink(packageDirectoryURL.appendingPathComponent("artifacts")),
              Self.isRegularFileWithoutSymlink(
                packageDirectoryURL.appendingPathComponent("artifacts").appendingPathComponent("hs-server")) else {
            return false
        }
        guard let evidence = try? Self.readEvidence(releaseEvidenceURL),
              Self.validateReleaseEvidenceShape(evidence),
              let roots = try? Self.readTrustRoots(trustRootsURL),
              roots.schema == 1,
              Self.releaseRootsMatch(roots, policy: releaseTrust) else {
            return false
        }
        return true
    }

    private static func releaseRootsMatch(
        _ roots: ServerPackageTrustRoots,
        policy: ServerReleaseTrustPolicy
    ) -> Bool {
        let packaged = Set(roots.releaseKeys.map { $0.lowercased() })
        let compiled = Set(policy.compiledTrustKeyHexes)
        return !packaged.isEmpty && packaged == compiled
    }

    func availability() -> ServerPackageAvailability {
        if FileManager.default.fileExists(atPath: releaseEvidenceURL.path) {
            return releaseAvailability()
        }
        if developmentBuild.isRequested {
            guard developmentBuild.isEnabled else {
                return .unavailable(reason:
                    "This Manager was built for development install but has no valid build-pinned Ed25519 trust key.")
            }
            guard FileManager.default.fileExists(atPath: developmentInstallEvidenceURL.path) else {
                if FileManager.default.fileExists(atPath: developmentEvidenceURL.path) {
                    return .unavailable(reason:
                        "A development-only helper is packaged, but no development install evidence/package is present.")
                }
                return .unavailable(reason:
                    "This Manager was built for development install, but no development install package is packaged.")
            }
            return developmentAvailability()
        }
        if FileManager.default.fileExists(atPath: developmentInstallEvidenceURL.path) {
            return .unavailable(reason:
                "A development install payload is present, but this Manager was not built with the development install pin.")
        }
        if FileManager.default.fileExists(atPath: developmentEvidenceURL.path) {
            return .unavailable(reason:
                "A development-only hs-server helper is packaged. Local installation remains disabled until a signed release helper, independent release trust root, and signed macOS package are present.")
        }
        return .unavailable(reason:
            "No signed hs-server package is packaged in this Manager build. Installation is disabled; nothing will be run as administrator.")
    }

    private func releaseAvailability() -> ServerPackageAvailability {
        guard releaseAuthorized else {
            return .unavailable(reason:
                "Release installation requires a Developer ID-signed Manager and release trust keys compiled into this binary. This build is not authorized, so the release privileged path is disabled.")
        }
        let evidence: ServerReleaseEvidence
        do {
            evidence = try Self.readEvidence(releaseEvidenceURL)
        } catch {
            return .invalid(reason: "Release helper evidence is unreadable: \(Self.boundedDetail(error))")
        }
        guard Self.validateReleaseEvidenceShape(evidence) else {
            return .invalid(reason:
                "Release helper evidence does not describe an installation-enabled, non-development, non-ad-hoc helper.")
        }

        guard Self.isRegularFileWithoutSymlink(helperURL),
              Self.isExecutableFileWithoutSymlink(helperURL) else {
            return .invalid(reason: "The release helper path is missing, a symlink, or not executable.")
        }
        let helperDigest: String
        do {
            helperDigest = try ServerPackageVerifier.sha256File(helperURL, maxBytes: 512 * 1024 * 1024)
        } catch {
            return .invalid(reason: "The release helper could not be verified: \(Self.boundedDetail(error))")
        }
        guard helperDigest == evidence.includedSHA256.lowercased() else {
            return .invalid(reason: "The packaged release helper bytes do not match its release evidence.")
        }

        let roots: ServerPackageTrustRoots
        do {
            roots = try Self.readTrustRoots(trustRootsURL)
        } catch {
            return .unavailable(reason: "No readable independent server trust root is packaged: \(Self.boundedDetail(error))")
        }
        guard roots.schema == 1, !roots.releaseKeys.isEmpty else {
            return .invalid(reason: "The server trust-root file is invalid or contains no release keys.")
        }
        guard Self.releaseRootsMatch(roots, policy: releaseTrust) else {
            return .invalid(reason:
                "The packaged release trust roots do not match the release trust keys compiled into this Manager.")
        }

        let target: ServerInstallTarget
        do {
            target = try ServerInstallTarget.current()
        } catch {
            return .unavailable(reason: Self.boundedDetail(error))
        }
        guard evidence.architectures.contains(target.architecture) else {
            return .invalid(reason:
                "The release helper does not contain this Mac's \(target.architecture) architecture.")
        }

        guard Self.isDirectoryWithoutSymlink(packageDirectoryURL) else {
            return .unavailable(reason: "No signed macOS server package directory is packaged.")
        }

        let normalizedKeys = roots.releaseKeys.map { $0.lowercased() }
        guard normalizedKeys.allSatisfy({ Self.isHex32Bytes($0) }) else {
            return .invalid(reason: "One or more packaged release trust keys are not 32-byte Ed25519 keys in hex.")
        }

        for key in normalizedKeys {
            do {
                let package = try ServerPackageVerifier.verify(
                    packageDirectory: packageDirectoryURL,
                    trustedKeyHex: key,
                    expectedTarget: target,
                    helperURL: helperURL,
                    helperSha256: helperDigest,
                    provenance: .release)
                return .available(package)
            } catch let error as LocalServerInstallError {
                // A signature failure with one candidate key is not conclusive
                // until every independently packaged trust key is tried.
                if normalizedKeys.count == 1 {
                    return .invalid(reason: error.description)
                }
            } catch {
                return .invalid(reason: "The signed server package could not be verified: \(Self.boundedDetail(error))")
            }
        }
        return .invalid(reason:
            "The signed server package does not verify with any packaged independent release trust key.")
    }

    private func developmentAvailability() -> ServerPackageAvailability {
        guard let pinnedKey = developmentBuild.pinnedTrustKeyHex,
              Self.isHex32Bytes(pinnedKey) else {
            return .unavailable(reason:
                "This Manager was built for development install but has no valid build-pinned Ed25519 trust key.")
        }

        let evidence: ServerDevelopmentInstallEvidence
        do {
            evidence = try Self.readDevelopmentEvidence(developmentInstallEvidenceURL)
        } catch {
            return .invalid(reason:
                "Development install evidence is unreadable: \(Self.boundedDetail(error))")
        }
        guard Self.validateDevelopmentEvidenceShape(evidence, pinnedKey: pinnedKey) else {
            return .invalid(reason:
                "Development install evidence is not a pinned, development-only helper/package binding.")
        }

        guard Self.isRegularFileWithoutSymlink(helperURL),
              Self.isExecutableFileWithoutSymlink(helperURL) else {
            return .invalid(reason: "The development helper path is missing, a symlink, or not executable.")
        }
        let helperDigest: String
        do {
            helperDigest = try ServerPackageVerifier.sha256File(helperURL, maxBytes: 512 * 1024 * 1024)
        } catch {
            return .invalid(reason:
                "The development helper could not be verified: \(Self.boundedDetail(error))")
        }
        guard helperDigest == evidence.helperSha256.lowercased() else {
            return .invalid(reason:
                "The packaged development helper bytes do not match the development evidence.")
        }

        let target: ServerInstallTarget
        do {
            target = try ServerInstallTarget.current()
        } catch {
            return .unavailable(reason: Self.boundedDetail(error))
        }
        guard evidence.packageTarget == target.rawValue else {
            return .invalid(reason:
                "The development package targets \(evidence.packageTarget), not this Mac's \(target.rawValue).")
        }
        guard Self.isDirectoryWithoutSymlink(developmentPackageDirectoryURL) else {
            return .unavailable(reason: "No development macOS server package directory is packaged.")
        }

        do {
            let package = try ServerPackageVerifier.verify(
                packageDirectory: developmentPackageDirectoryURL,
                trustedKeyHex: pinnedKey,
                expectedTarget: target,
                helperURL: helperURL,
                helperSha256: helperDigest,
                provenance: .development)
            guard package.product == evidence.packageProduct,
                  package.version == evidence.packageVersion,
                  package.manifestSha256 == evidence.packageManifestSha256.lowercased(),
                  package.artifactPath == evidence.packageArtifactPath,
                  package.artifactSha256 == evidence.packageArtifactSha256.lowercased(),
                  package.artifactSizeBytes == evidence.packageArtifactSizeBytes else {
                return .invalid(reason:
                    "The verified development package does not match its bound development evidence.")
            }
            return .available(package)
        } catch let error as LocalServerInstallError {
            return .invalid(reason: error.description)
        } catch {
            return .invalid(reason:
                "The development package could not be verified: \(Self.boundedDetail(error))")
        }
    }

    // MARK: - Evidence

    private static func readDevelopmentEvidence(_ url: URL) throws -> ServerDevelopmentInstallEvidence {
        let data = try ServerPackageVerifier.readRegularFile(url, maxBytes: 128 * 1024)
        do {
            return try JSONDecoder().decode(ServerDevelopmentInstallEvidence.self, from: data)
        } catch {
            throw LocalServerInstallError.invalidResponse(
                "Development install evidence is not valid JSON.")
        }
    }

    private static func validateDevelopmentEvidenceShape(
        _ evidence: ServerDevelopmentInstallEvidence,
        pinnedKey: String?
    ) -> Bool {
        guard let pinnedKey else { return false }
        return evidence.schema == 1
            && evidence.mode == ServerInstallContract.developmentInstallEvidenceMode
            && evidence.developmentOnly
            && !evidence.distributionSigned
            && evidence.installationEnabled
            && evidence.helperPath == ServerInstallContract.helperRelativePath
            && evidence.packageDirectory == ServerInstallContract.developmentPackageDirectoryRelativePath
            && evidence.packageArtifactPath == "artifacts/hs-server"
            && isHex32Bytes(evidence.helperSha256)
            && isHex32Bytes(evidence.packageManifestSha256)
            && isHex32Bytes(evidence.packageArtifactSha256)
            && evidence.packageArtifactSizeBytes > 0
            && evidence.packageArtifactSizeBytes <= 512 * 1024 * 1024
            && (evidence.packageTarget == ServerInstallContract.macosArm64Target
                || evidence.packageTarget == ServerInstallContract.macosX86_64Target)
            && evidence.packageProduct == "hs-server"
            && ServerPackageVerifier.isStrictSemanticVersion(evidence.packageVersion)
            && evidence.verificationKeyHex.lowercased() == pinnedKey
            && evidence.verificationKeySha256.lowercased() == Self.verificationKeySHA256(pinnedKey)
    }

    private static func verificationKeySHA256(_ keyHex: String) -> String {
        guard let keyBytes = try? ServerPackageVerifier.hexBytes(keyHex) else { return "" }
        return ServerPackageVerifier.sha256(keyBytes)
    }

    private static func readEvidence(_ url: URL) throws -> ServerReleaseEvidence {
        let data = try ServerPackageVerifier.readRegularFile(url, maxBytes: 64 * 1024)
        do {
            return try JSONDecoder().decode(ServerReleaseEvidence.self, from: data)
        } catch {
            throw LocalServerInstallError.invalidResponse("Release helper evidence is not valid JSON.")
        }
    }

    private static func readTrustRoots(_ url: URL) throws -> ServerPackageTrustRoots {
        let data = try ServerPackageVerifier.readRegularFile(url, maxBytes: 64 * 1024)
        do {
            return try JSONDecoder().decode(ServerPackageTrustRoots.self, from: data)
        } catch {
            throw LocalServerInstallError.invalidResponse("Server trust-root evidence is not valid JSON.")
        }
    }

    private static func validateReleaseEvidenceShape(_ evidence: ServerReleaseEvidence) -> Bool {
        evidence.schema == 1
            && evidence.helper == "hs-server"
            && evidence.path == ServerInstallContract.helperRelativePath
            && evidence.developmentOnly == false
            && evidence.distributionSigned == true
            && evidence.installationEnabled == true
            && evidence.serviceEnabled == true
            && evidence.signature.lowercased() != "ad-hoc"
            && isHex32Bytes(evidence.includedSHA256)
            && !evidence.architectures.isEmpty
    }

    // MARK: - Filesystem

    static func isRegularFileWithoutSymlink(_ url: URL) -> Bool {
        var info = stat()
        return lstat(url.path, &info) == 0
            && (info.st_mode & S_IFMT) == S_IFREG
    }

    static func isExecutableFileWithoutSymlink(_ url: URL) -> Bool {
        var info = stat()
        return lstat(url.path, &info) == 0
            && (info.st_mode & S_IFMT) == S_IFREG
            && (info.st_mode & 0o111) != 0
    }

    static func isDirectoryWithoutSymlink(_ url: URL) -> Bool {
        var info = stat()
        return lstat(url.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFDIR
    }

    static func isHex32Bytes(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy(\.isHexDigit)
    }

    static func boundedDetail(_ error: any Error) -> String {
        let text = (error as? LocalServerInstallError)?.description ?? error.localizedDescription
        let cleaned = text.unicodeScalars
            .filter { scalar in
                scalar.value >= 0x20 && scalar.value != 0x7F
            }
            .map { String($0) }
            .joined()
        return String(cleaned.prefix(512))
    }
}

/// Strict package verification mirroring the server's package-target contract.
/// The Manager never opens the package based on fields the package controls.
enum ServerPackageVerifier {
    static let manifestMaxBytes = 1_048_576
    static let artifactMaxBytes: UInt64 = 512 * 1024 * 1024
    static let signatureBytes = 64
    static let maximumArtifacts = 256

    struct PackageManifest: Decodable, Sendable {
        let formatVersion: Int
        let product: String
        let version: String
        let platform: String
        let minSchemaVersion: Int64
        let minInstallerVersion: String
        let artifacts: [PackageArtifact]

        enum CodingKeys: String, CodingKey {
            case formatVersion = "format_version"
            case product
            case version
            case platform
            case minSchemaVersion = "min_schema_version"
            case minInstallerVersion = "min_installer_version"
            case artifacts
        }
    }

    struct PackageArtifact: Decodable, Sendable {
        let path: String
        let sha256: String
        let sizeBytes: UInt64

        enum CodingKeys: String, CodingKey {
            case path
            case sha256
            case sizeBytes = "size_bytes"
        }
    }

    static func verify(
        packageDirectory: URL,
        trustedKeyHex: String,
        expectedTarget: ServerInstallTarget,
        helperURL: URL,
        helperSha256: String = "",
        provenance: ServerPackageProvenance = .release
    ) throws -> TrustedServerPackage {
        guard BundledServerPackageProvider.isHex32Bytes(trustedKeyHex) else {
            throw LocalServerInstallError.invalidConfiguration(
                "The packaged release trust key is not a 32-byte Ed25519 key in lowercase or uppercase hex.")
        }
        guard BundledServerPackageProvider.isDirectoryWithoutSymlink(packageDirectory) else {
            throw LocalServerInstallError.packageUnavailable(
                "The signed macOS server package directory is missing or is a symlink.")
        }

        let rootEntries = try regularDirectoryEntries(packageDirectory)
        guard rootEntries == ["artifacts", "manifest.json", "manifest.sig"] else {
            throw LocalServerInstallError.invalidResponse(
                "The macOS package root must contain exactly manifest.json, manifest.sig, and artifacts.")
        }

        let manifestURL = packageDirectory.appendingPathComponent("manifest.json")
        let signatureURL = packageDirectory.appendingPathComponent("manifest.sig")
        let artifactsURL = packageDirectory.appendingPathComponent("artifacts")
        guard BundledServerPackageProvider.isDirectoryWithoutSymlink(artifactsURL) else {
            throw LocalServerInstallError.invalidResponse("The macOS package artifacts directory is missing or unsafe.")
        }

        let manifestBytes = try readRegularFile(manifestURL, maxBytes: manifestMaxBytes)
        let signature = try readRegularFile(signatureURL, maxBytes: signatureBytes)
        guard signature.count == signatureBytes else {
            throw LocalServerInstallError.invalidResponse("The package signature must be 64 bytes.")
        }

        let keyBytes = try hexBytes(trustedKeyHex)
        guard keyBytes.count == 32,
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: keyBytes),
              publicKey.isValidSignature(signature, for: manifestBytes) else {
            throw LocalServerInstallError.commandRejected(
                "The package manifest signature does not verify with the packaged release trust key.")
        }

        let manifest: PackageManifest
        do {
            manifest = try JSONDecoder().decode(PackageManifest.self, from: manifestBytes)
        } catch {
            throw LocalServerInstallError.invalidResponse("The package manifest is not valid JSON.")
        }

        guard manifest.formatVersion == 1 else {
            throw LocalServerInstallError.commandRejected("Unsupported package manifest format version.")
        }
        guard manifest.product == "hs-server" else {
            throw LocalServerInstallError.commandRejected(
                "The package product is not the canonical hs-server product.")
        }
        guard isStrictSemanticVersion(manifest.version),
              isStrictSemanticVersion(manifest.minInstallerVersion) else {
            throw LocalServerInstallError.commandRejected(
                "The package version fields are not strict major.minor.patch values.")
        }
        guard (1...1_000_000).contains(manifest.minSchemaVersion) else {
            throw LocalServerInstallError.commandRejected(
                "The package minimum schema version is invalid.")
        }
        guard manifest.platform == expectedTarget.rawValue else {
            throw LocalServerInstallError.commandRejected(
                "The package targets \(manifest.platform), not this Mac's \(expectedTarget.rawValue).")
        }
        guard !manifest.artifacts.isEmpty,
              manifest.artifacts.count <= maximumArtifacts else {
            throw LocalServerInstallError.commandRejected("The package must declare 1...\(maximumArtifacts) artifacts.")
        }

        var seenPaths = Set<String>()
        for artifact in manifest.artifacts {
            guard validateArtifactPath(artifact.path) else {
                throw LocalServerInstallError.commandRejected(
                    "The package declares an unsafe artifact path.")
            }
            guard seenPaths.insert(artifact.path).inserted else {
                throw LocalServerInstallError.commandRejected("The package declares a duplicate artifact path.")
            }
            guard BundledServerPackageProvider.isHex32Bytes(artifact.sha256) else {
                throw LocalServerInstallError.commandRejected(
                    "A package artifact digest is not a SHA-256 hex value.")
            }
            guard artifact.sizeBytes > 0, artifact.sizeBytes <= artifactMaxBytes else {
                throw LocalServerInstallError.commandRejected(
                    "A package artifact size is outside the accepted bound.")
            }
        }
        guard !hasFileDirectoryPrefixCollision(seenPaths) else {
            throw LocalServerInstallError.commandRejected(
                "The package declares an artifact that is both a file and a directory prefix.")
        }
        guard manifest.artifacts.count == 1,
              manifest.artifacts[0].path == "artifacts/hs-server" else {
            throw LocalServerInstallError.commandRejected(
                "A macOS package must contain exactly one artifacts/hs-server executable.")
        }

        let artifactEntries = try regularDirectoryEntries(artifactsURL)
        guard artifactEntries == ["hs-server"] else {
            throw LocalServerInstallError.commandRejected(
                "The macOS package artifacts directory contains an undeclared entry.")
        }

        let artifact = manifest.artifacts[0]
        let artifactURL = artifactsURL.appendingPathComponent("hs-server")
        guard BundledServerPackageProvider.isRegularFileWithoutSymlink(artifactURL) else {
            throw LocalServerInstallError.commandRejected(
                "The signed server executable is missing, a symlink, or not a regular file.")
        }
        let actualSize = try fileSize(artifactURL)
        guard actualSize == artifact.sizeBytes else {
            throw LocalServerInstallError.commandRejected(
                "The signed server executable size does not match the signed manifest.")
        }
        let actualDigest = try sha256File(artifactURL, maxBytes: artifactMaxBytes)
        guard actualDigest == artifact.sha256.lowercased() else {
            throw LocalServerInstallError.commandRejected(
                "The signed server executable digest does not match the signed manifest.")
        }

        let actualHelperDigest: String
        if helperSha256.isEmpty {
            actualHelperDigest = try sha256File(helperURL, maxBytes: artifactMaxBytes)
        } else {
            actualHelperDigest = helperSha256.lowercased()
        }
        guard try sha256File(helperURL, maxBytes: artifactMaxBytes) == actualHelperDigest else {
            throw LocalServerInstallError.commandRejected(
                "The packaged helper bytes do not match the verified helper digest.")
        }

        return TrustedServerPackage(
            helperURL: helperURL,
            packageDirectory: packageDirectory,
            verifyingKeyHex: trustedKeyHex.lowercased(),
            target: expectedTarget,
            product: manifest.product,
            version: manifest.version,
            manifestSha256: sha256(manifestBytes),
            artifactPath: artifact.path,
            artifactSha256: actualDigest,
            artifactSizeBytes: actualSize,
            helperSha256: actualHelperDigest,
            provenance: provenance)
    }

    static func readRegularFile(_ url: URL, maxBytes: Int) throws -> Data {
        guard BundledServerPackageProvider.isRegularFileWithoutSymlink(url) else {
            throw LocalServerInstallError.invalidResponse(
                "An expected package file is missing, a symlink, or not a regular file.")
        }
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            throw LocalServerInstallError.invalidResponse("An expected package file could not be opened.")
        }
        defer { try? handle.close() }

        var data = Data()
        while true {
            let chunk: Data
            do {
                chunk = try handle.read(upToCount: 65_536) ?? Data()
            } catch {
                throw LocalServerInstallError.invalidResponse("An expected package file could not be read.")
            }
            if chunk.isEmpty { break }
            if data.count + chunk.count > maxBytes {
                throw LocalServerInstallError.commandRejected(
                    "A package file exceeds its accepted size bound.")
            }
            data.append(chunk)
        }
        return data
    }

    static func sha256File(_ url: URL, maxBytes: UInt64) throws -> String {
        guard BundledServerPackageProvider.isRegularFileWithoutSymlink(url) else {
            throw LocalServerInstallError.invalidResponse(
                "An artifact is missing, a symlink, or not a regular file.")
        }
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            throw LocalServerInstallError.invalidResponse("An artifact could not be opened.")
        }
        defer { try? handle.close() }

        var hasher = SHA256()
        var total: UInt64 = 0
        while true {
            let chunk: Data
            do {
                chunk = try handle.read(upToCount: 65_536) ?? Data()
            } catch {
                throw LocalServerInstallError.invalidResponse("An artifact could not be read.")
            }
            if chunk.isEmpty { break }
            total += UInt64(chunk.count)
            if total > maxBytes {
                throw LocalServerInstallError.commandRejected(
                    "An artifact exceeds its accepted size bound.")
            }
            hasher.update(data: chunk)
        }
        return hex(Data(hasher.finalize()))
    }

    static func sha256(_ data: Data) -> String {
        hex(Data(SHA256.hash(data: data)))
    }

    static func regularDirectoryEntries(_ directory: URL) throws -> [String] {
        guard BundledServerPackageProvider.isDirectoryWithoutSymlink(directory) else {
            throw LocalServerInstallError.invalidResponse("An expected package directory is missing or unsafe.")
        }
        do {
            return try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
        } catch {
            throw LocalServerInstallError.invalidResponse("A package directory could not be listed.")
        }
    }

    static func fileSize(_ url: URL) throws -> UInt64 {
        var info = stat()
        guard lstat(url.path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size >= 0 else {
            throw LocalServerInstallError.invalidResponse("An artifact size could not be inspected.")
        }
        return UInt64(info.st_size)
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func hexBytes(_ value: String) throws -> Data {
        guard value.count % 2 == 0 else {
            throw LocalServerInstallError.invalidConfiguration("A hex value has an odd length.")
        }
        var bytes = Data()
        bytes.reserveCapacity(value.count / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            let pair = value[index..<next]
            guard let byte = UInt8(String(pair), radix: 16) else {
                throw LocalServerInstallError.invalidConfiguration("A hex value is malformed.")
            }
            bytes.append(byte)
            index = next
        }
        return bytes
    }

    static func isStrictSemanticVersion(_ value: String) -> Bool {
        let components = value.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 3 else { return false }
        for component in components {
            guard !component.isEmpty,
                  component.count <= 10,
                  component.allSatisfy(\.isNumber),
                  UInt32(String(component)) != nil,
                  component.count == 1 || component.first != "0" else {
                return false
            }
        }
        return true
    }

    static func validateArtifactPath(_ path: String) -> Bool {
        guard !path.isEmpty,
              path.utf8.count <= 256,
              path.hasPrefix("artifacts/"),
              !path.contains("\\"),
              !path.contains(":"),
              path == path.lowercased(),
              path.utf8.allSatisfy({ $0 >= 0x21 && $0 <= 0x7E }) else {
            return false
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty, components.count <= 16 else { return false }
        for component in components {
            guard !component.isEmpty,
                  component.utf8.count <= 64,
                  component != ".",
                  component != "..",
                  !component.hasSuffix("."),
                  !component.hasSuffix(" "),
                  component.utf8.allSatisfy({ byte in
                      (byte >= 0x61 && byte <= 0x7A)
                          || (byte >= 0x30 && byte <= 0x39)
                          || byte == 0x2E || byte == 0x5F || byte == 0x2D
                  }) else {
                return false
            }
            let basename = component.split(separator: ".", maxSplits: 1).first.map { String($0) } ?? ""
            let reserved = ["con", "prn", "aux", "nul"]
                + (1...9).flatMap { ["com\($0)", "lpt\($0)"] }
            guard !reserved.contains(basename) else { return false }
        }
        return true
    }

    static func hasFileDirectoryPrefixCollision(_ paths: Set<String>) -> Bool {
        let sorted = paths.sorted()
        for path in sorted {
            for other in sorted where other != path && other.hasPrefix(path + "/") {
                return true
            }
        }
        return false
    }
}
