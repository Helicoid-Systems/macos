import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

@Suite("Server package trust")
struct ServerPackageTrustTests {
    @Test("A correctly signed, target-bound package is available")
    func signedPackageAvailable() throws {
        let fixture = try ServerInstallTestSupport.packageFixture()
        defer { fixture.remove() }

        let provider = BundledServerPackageProvider(rootURL: fixture.root)
        #expect(provider.installPayloadPresent)
        let availability = provider.availability()
        guard let package = availability.package else {
            Issue.record("Expected the fixture package to verify: \(availability.explanation)")
            return
        }
        #expect(package.product == "hs-server")
        #expect(package.version == "0.1.0")
        let currentTarget = try ServerInstallTarget.current()
        #expect(package.target == currentTarget)
        #expect(package.verifyingKeyHex == ServerInstallTestSupport.hex(
            fixture.trustedKey.publicKey.rawRepresentation))
    }

    @Test("Development-only evidence never enables installation")
    func developmentEvidenceUnavailable() throws {
        let fixture = try ServerInstallTestSupport.packageFixture(developmentEvidence: true)
        defer { fixture.remove() }

        let provider = BundledServerPackageProvider(rootURL: fixture.root)
        #expect(!provider.installPayloadPresent)
        guard case .unavailable(let reason) = provider.availability() else {
            Issue.record("Development evidence must remain unavailable")
            return
        }
        #expect(reason.contains("development-only"))
    }

    @Test("A tampered artifact is refused")
    func tamperedArtifactRefused() throws {
        let fixture = try ServerInstallTestSupport.packageFixture(tamperArtifact: true)
        defer { fixture.remove() }

        let provider = BundledServerPackageProvider(rootURL: fixture.root)
        guard case .invalid(let reason) = provider.availability() else {
            Issue.record("Tampered artifact must be invalid")
            return
        }
        #expect(reason.localizedCaseInsensitiveContains("digest")
            || reason.localizedCaseInsensitiveContains("size"))
    }

    @Test("A package signed by an untrusted key is refused")
    func untrustedKeyRefused() throws {
        let fixture = try ServerInstallTestSupport.packageFixture()
        defer { fixture.remove() }
        let differentKey = Curve25519.Signing.PrivateKey()
        let roots: [String: Any] = [
            "schema": 1,
            "releaseKeys": [ServerInstallTestSupport.hex(differentKey.publicKey.rawRepresentation)],
        ]
        try ServerInstallTestSupport.jsonData(roots).write(to: fixture.trustRootsURL)

        let provider = BundledServerPackageProvider(rootURL: fixture.root)
        guard case .invalid(let reason) = provider.availability() else {
            Issue.record("Untrusted signing key must be invalid")
            return
        }
        #expect(reason.localizedCaseInsensitiveContains("signature")
            || reason.localizedCaseInsensitiveContains("trust"))
    }

    @Test("Development install requires the build-pinned key and helper/package binding")
    func developmentInstallRequiresPinnedBinding() throws {
        let fixture = try ServerInstallTestSupport.packageFixture(developmentInstall: true)
        defer { fixture.remove() }

        let enabled = BundledServerPackageProvider(
            rootURL: fixture.root,
            developmentBuild: fixture.developmentBuild)
        #expect(enabled.installPayloadPresent)
        #expect(enabled.payloadKind == .development)
        guard let package = enabled.availability().package else {
            Issue.record("Expected the development fixture to verify")
            return
        }
        #expect(package.provenance == .development)
        #expect(package.verifyingKeyHex == fixture.pinnedKeyHex)

        let disabled = BundledServerPackageProvider(
            rootURL: fixture.root,
            developmentBuild: .disabled)
        #expect(!disabled.installPayloadPresent)
        #expect(disabled.payloadKind == .none)
        guard case .unavailable = disabled.availability() else {
            Issue.record("A normal build must not accept a development payload")
            return
        }

        let wrongPin = ServerDevelopmentBuild(
            isRequested: true,
            pinnedTrustKeyHex: String(repeating: "b", count: 64))
        let mismatched = BundledServerPackageProvider(
            rootURL: fixture.root,
            developmentBuild: wrongPin)
        #expect(!mismatched.installPayloadPresent)
        guard case .invalid = mismatched.availability() else {
            Issue.record("A mismatched build pin must be refused")
            return
        }
    }

    @Test("Development evidence helper digest must match the bundled helper")
    func developmentHelperDigestMismatchRefused() throws {
        let fixture = try ServerInstallTestSupport.packageFixture(
            developmentInstall: true,
            helperMatchesEvidence: false)
        defer { fixture.remove() }
        let provider = BundledServerPackageProvider(
            rootURL: fixture.root,
            developmentBuild: fixture.developmentBuild)
        guard case .invalid(let reason) = provider.availability() else {
            Issue.record("Development helper digest mismatch must be invalid")
            return
        }
        #expect(reason.localizedCaseInsensitiveContains("helper"))
    }

    @Test("Release evidence blocks development fallback")
    func releaseEvidenceBlocksDevelopmentFallback() throws {
        let fixture = try ServerInstallTestSupport.packageFixture()
        defer { fixture.remove() }
        let development = try ServerInstallTestSupport.packageFixture(developmentInstall: true)
        defer { development.remove() }
        // Leave release evidence present but invalid. The provider must choose
        // release and fail rather than fall back to a development pin.
        try Data("not-release-evidence".utf8).write(
            to: fixture.root.appendingPathComponent("Contents/Resources/hs-server-release.json"))

        let provider = BundledServerPackageProvider(
            rootURL: fixture.root,
            developmentBuild: development.developmentBuild)
        #expect(provider.payloadKind == .release)
        guard case .invalid = provider.availability() else {
            Issue.record("Broken release evidence must not fall back to development")
            return
        }
    }

    @Test("A package for another architecture is refused")
    func wrongTargetRefused() throws {
        let current = try ServerInstallTarget.current()
        let other = current == .macosArm64
            ? ServerInstallContract.macosX86_64Target
            : ServerInstallContract.macosArm64Target
        let fixture = try ServerInstallTestSupport.packageFixture(platform: other)
        defer { fixture.remove() }

        let provider = BundledServerPackageProvider(rootURL: fixture.root)
        guard case .invalid(let reason) = provider.availability() else {
            Issue.record("Wrong target must be invalid")
            return
        }
        #expect(reason.localizedCaseInsensitiveContains("targets"))
    }

    @Test("A symlinked artifact is never followed")
    func symlinkedArtifactRefused() throws {
        let fixture = try ServerInstallTestSupport.packageFixture()
        defer { fixture.remove() }
        let artifact = fixture.packageDirectory
            .appendingPathComponent("artifacts")
            .appendingPathComponent("hs-server")
        try FileManager.default.removeItem(at: artifact)
        try FileManager.default.createSymbolicLink(
            at: artifact,
            withDestinationURL: fixture.helperURL)

        let provider = BundledServerPackageProvider(rootURL: fixture.root)
        #expect(!provider.installPayloadPresent)
        guard case .invalid = provider.availability() else {
            Issue.record("Symlinked artifact must be refused")
            return
        }
    }

    @Test("Release evidence with a different helper digest is refused")
    func helperDigestMismatchRefused() throws {
        let fixture = try ServerInstallTestSupport.packageFixture(helperMatchesEvidence: false)
        defer { fixture.remove() }

        let provider = BundledServerPackageProvider(rootURL: fixture.root)
        guard case .invalid(let reason) = provider.availability() else {
            Issue.record("Helper digest mismatch must be invalid")
            return
        }
        #expect(reason.localizedCaseInsensitiveContains("helper"))
    }

    @Test("A malformed trust-root file is an explicit unavailable state")
    func malformedTrustRootsUnavailable() throws {
        let fixture = try ServerInstallTestSupport.packageFixture()
        defer { fixture.remove() }
        try Data("not-json".utf8).write(to: fixture.trustRootsURL)

        let provider = BundledServerPackageProvider(rootURL: fixture.root)
        #expect(!provider.installPayloadPresent)
        guard case .unavailable(let reason) = provider.availability() else {
            Issue.record("Malformed trust roots must be unavailable")
            return
        }
        #expect(reason.localizedCaseInsensitiveContains("trust root"))
    }

    @Test("Strict artifact paths reject traversal and Windows aliases")
    func strictArtifactPaths() {
        #expect(ServerPackageVerifier.validateArtifactPath("artifacts/hs-server"))
        #expect(!ServerPackageVerifier.validateArtifactPath("../artifacts/hs-server"))
        #expect(!ServerPackageVerifier.validateArtifactPath("artifacts/../hs-server"))
        #expect(!ServerPackageVerifier.validateArtifactPath("artifacts/hs\\server"))
        #expect(!ServerPackageVerifier.validateArtifactPath("artifacts/CON"))
        #expect(!ServerPackageVerifier.validateArtifactPath("artifacts/hs-server/"))
        #expect(!ServerPackageVerifier.validateArtifactPath("artifacts//hs-server"))
    }

    @Test("Strict semantic versions reject leading zeroes and malformed triples")
    func strictVersions() {
        #expect(ServerPackageVerifier.isStrictSemanticVersion("0.1.0"))
        #expect(ServerPackageVerifier.isStrictSemanticVersion("12.34.56"))
        #expect(!ServerPackageVerifier.isStrictSemanticVersion("1.2"))
        #expect(!ServerPackageVerifier.isStrictSemanticVersion("1.02.3"))
        #expect(!ServerPackageVerifier.isStrictSemanticVersion("01.2.3"))
        #expect(!ServerPackageVerifier.isStrictSemanticVersion("1.2.3.4"))
        #expect(!ServerPackageVerifier.isStrictSemanticVersion("1.2.x"))
    }
}
