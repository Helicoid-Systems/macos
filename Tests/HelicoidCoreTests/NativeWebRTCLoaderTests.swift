import Foundation
import Testing
@testable import HelicoidCore

/// These tests cover the pure loader/contract rules. They never `dlopen` a
/// library and never negotiate a peer: the native bridge is not part of the
/// Swift test build, so any test that reached `dlopen` would be testing the
/// host rather than this source.
@Suite("Native WebRTC bundled loader")
struct NativeWebRTCLoaderTests {
    private let libraryName = NativeWebRTCContract.bundledLibraryName

    @Test("resolves only Contents/Frameworks/libhs_webrtc_shared.dylib")
    func resolvesBundledLibrary() throws {
        let fixture = try makeBundleFixture()
        defer { fixture.dispose() }

        let resolved = try NativeWebRTCBundleResolver.resolve(
            bundleURL: fixture.bundle,
            executableURL: fixture.executable
        )
        #expect(
            resolved
                == fixture.bundle
                    .appendingPathComponent("Contents/Frameworks", isDirectory: true)
                    .appendingPathComponent(libraryName)
                    .resolvingSymlinksInPath()
                    .standardizedFileURL
        )
    }

    @Test("rejects a missing bundled library")
    func rejectsMissingLibrary() throws {
        let fixture = try makeBundleFixture(writeLibrary: false)
        defer { fixture.dispose() }

        do {
            _ = try NativeWebRTCBundleResolver.resolve(
                bundleURL: fixture.bundle,
                executableURL: fixture.executable
            )
            Issue.record("A missing bundled library must not resolve")
        } catch let error as NativeWebRTCError {
            guard case .libraryMissing = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
        }
    }

    @Test("rejects a symlink in place of the bundled library")
    func rejectsLibrarySymlink() throws {
        let fixture = try makeBundleFixture(writeLibrary: false)
        defer { fixture.dispose() }

        let outside = fixture.root.deletingLastPathComponent()
            .appendingPathComponent("outside-\(UUID().uuidString).dylib")
        try Data([0x01]).write(to: outside)
        defer { try? FileManager.default.removeItem(at: outside) }

        let link = fixture.frameworks.appendingPathComponent(libraryName)
        try FileManager.default.createSymbolicLink(
            at: link, withDestinationURL: outside)

        do {
            _ = try NativeWebRTCBundleResolver.resolve(
                bundleURL: fixture.bundle,
                executableURL: fixture.executable
            )
            Issue.record("A symlinked bundled library must not resolve")
        } catch let error as NativeWebRTCError {
            guard case .libraryNotRegularFile = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
        }
    }

    @Test("rejects a Frameworks directory that resolves outside the bundle")
    func rejectsFrameworksOutsideBundle() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-native-\(UUID().uuidString).app", isDirectory: true)
        let contents = root.appendingPathComponent("Contents", isDirectory: true)
        let executables = contents.appendingPathComponent("MacOS", isDirectory: true)
        let outside = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-frameworks-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: executables, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: outside, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: root)
            try? FileManager.default.removeItem(at: outside)
        }

        let executable = executables.appendingPathComponent("HelicoidManager")
        try Data([0x01]).write(to: executable)
        try Data([0x01]).write(
            to: outside.appendingPathComponent(libraryName))
        try FileManager.default.createSymbolicLink(
            at: contents.appendingPathComponent("Frameworks"),
            withDestinationURL: outside
        )

        do {
            _ = try NativeWebRTCBundleResolver.resolve(
                bundleURL: root,
                executableURL: executable
            )
            Issue.record("A Frameworks symlink outside the bundle must not resolve")
        } catch let error as NativeWebRTCError {
            guard case .libraryOutsideBundle = error else {
                Issue.record("Unexpected error: \(error)")
                return
            }
        }
    }

    @Test("rejects an executable outside the application bundle")
    func rejectsExecutableOutsideBundle() throws {
        let fixture = try makeBundleFixture()
        defer { fixture.dispose() }

        let outside = fixture.root.deletingLastPathComponent()
            .appendingPathComponent("outside-executable")
        try Data([0x01]).write(to: outside)
        defer { try? FileManager.default.removeItem(at: outside) }

        do {
            _ = try NativeWebRTCBundleResolver.resolve(
                bundleURL: fixture.bundle,
                executableURL: outside
            )
            Issue.record("An outside executable must not resolve")
        } catch let error as NativeWebRTCError {
            #expect(error == .bundleUnavailable)
        }
    }

    @Test("rejects a non-app bundle")
    func rejectsNonApplicationBundle() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-native-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent("Contents/Frameworks"),
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        try Data([0x01]).write(
            to: root.appendingPathComponent("Contents/Frameworks/\(libraryName)"))

        do {
            _ = try NativeWebRTCBundleResolver.resolve(
                bundleURL: root, executableURL: nil)
            Issue.record("A non-.app directory must not resolve")
        } catch let error as NativeWebRTCError {
            #expect(error == .bundleUnavailable)
        }
    }

    @Test("rejects an ABI other than 3")
    func rejectsUnknownABI() {
        do {
            try NativeWebRTCValidation.validateContract(
                abiVersion: 2,
                capabilityStatus: NativeWebRTCStatus.ok.rawValue,
                capabilities: NativeWebRTCContract.requiredConnectionCapabilities
            )
            Issue.record("ABI 2 must be rejected")
        } catch let error as NativeWebRTCError {
            #expect(error == .abiMismatch(expected: 3, actual: 2))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("rejects a partial connection capability mask")
    func rejectsMissingCapabilities() {
        let capabilities = NativeWebRTCContract.requiredConnectionCapabilities
            & ~NativeWebRTCContract.drainCapability
        do {
            try NativeWebRTCValidation.validateContract(
                abiVersion: NativeWebRTCContract.abiVersion,
                capabilityStatus: NativeWebRTCStatus.ok.rawValue,
                capabilities: capabilities
            )
            Issue.record("A missing drain capability must be rejected")
        } catch let error as NativeWebRTCError {
            #expect(error == .requiredCapabilitiesMissing(
                missing: NativeWebRTCContract.drainCapability))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("surfaces a failed capability query")
    func rejectsFailedCapabilityQuery() {
        do {
            try NativeWebRTCValidation.validateContract(
                abiVersion: NativeWebRTCContract.abiVersion,
                capabilityStatus: NativeWebRTCStatus.internalError.rawValue,
                capabilities: NativeWebRTCContract.requiredConnectionCapabilities
            )
            Issue.record("A failed capability query must be rejected")
        } catch let error as NativeWebRTCError {
            #expect(error == .capabilityQueryFailed(.internalError))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("observation capabilities are reported, never synthesized")
    func observationCapabilitiesAreHonest() {
        #expect(!NativeWebRTCValidation.supportsObservation(
            NativeWebRTCContract.requiredConnectionCapabilities))
        #expect(NativeWebRTCValidation.supportsObservation(
            NativeWebRTCContract.requiredObservationCapabilities))
    }

    @Test("only OK or an already-retired token proves quiescence")
    func teardownQuiescenceIsFailClosed() {
        #expect(NativeWebRTCValidation.isProvenQuiescence(.ok))
        #expect(NativeWebRTCValidation.isProvenQuiescence(.null))
        #expect(!NativeWebRTCValidation.isProvenQuiescence(.timeout))
        #expect(!NativeWebRTCValidation.isProvenQuiescence(.state))
        #expect(!NativeWebRTCValidation.isProvenQuiescence(.handshake))
        #expect(!NativeWebRTCValidation.isProvenQuiescence(.internalError))
    }

    @Test("unknown native status fails closed as internal")
    func unknownStatusIsInternal() {
        #expect(NativeWebRTCStatus.from(99) == .internalError)
    }

    @Test("peer drain retires only on OK or an already-retired token")
    func peerDrainRetirementIsFailClosed() {
        #expect(NativeWebRTCTeardown.peerRetired(.ok))
        #expect(NativeWebRTCTeardown.peerRetired(.null))
        #expect(!NativeWebRTCTeardown.peerRetired(.timeout))
        #expect(!NativeWebRTCTeardown.peerRetired(.state))
        #expect(!NativeWebRTCTeardown.peerRetired(.handshake))
        #expect(!NativeWebRTCTeardown.peerRetired(.bounds))
    }

    @Test("orphan drain retries are bounded and never infer quiescence")
    func orphanDrainRetriesAreBounded() {
        #expect(NativeWebRTCTeardown.orphanAttemptOutcome(
            status: .ok, attempt: 1) == .retired)
        #expect(NativeWebRTCTeardown.orphanAttemptOutcome(
            status: .null, attempt: 3) == .retired)

        #expect(NativeWebRTCTeardown.orphanAttemptOutcome(
            status: .timeout, attempt: 1) == .retry)
        #expect(NativeWebRTCTeardown.orphanAttemptOutcome(
            status: .timeout, attempt: 2) == .retry)
        #expect(NativeWebRTCTeardown.orphanAttemptOutcome(
            status: .timeout, attempt: 3) == .releaseUnproven)

        #expect(NativeWebRTCTeardown.orphanAttemptOutcome(
            status: .state, attempt: 1) == .retry)
        #expect(NativeWebRTCTeardown.orphanAttemptOutcome(
            status: .state, attempt: 3) == .releaseUnproven)

        #expect(NativeWebRTCTeardown.orphanAttemptOutcome(
            status: .timeout, attempt: 1, maximumAttempts: 1)
            == .releaseUnproven)
        #expect(NativeWebRTCTeardown.maximumOrphanDrainAttempts == 3)
    }

    @Test("orphan retries divide the close timeout instead of extending it")
    func orphanRetryTimeoutIsBounded() {
        #expect(NativeWebRTCTeardown.orphanAttemptTimeout(
            totalMilliseconds: 5_000, attemptCount: 2) == 2_500)
        #expect(NativeWebRTCTeardown.orphanAttemptTimeout(
            totalMilliseconds: 1, attemptCount: 4) == 1)
        #expect(NativeWebRTCTeardown.orphanAttemptTimeout(
            totalMilliseconds: 0, attemptCount: 3) == 1)
        #expect(NativeWebRTCTeardown.orphanAttemptTimeout(
            totalMilliseconds: 5_000, attemptCount: 0) == 0)
    }

    @Test("engine refuses shutdown while any peer token remains live")
    func engineShutdownRequiresDrainedPeers() {
        #expect(NativeWebRTCTeardown.engineMayShutDown(livePeers: 0))
        #expect(!NativeWebRTCTeardown.engineMayShutDown(livePeers: 1))
        #expect(!NativeWebRTCTeardown.engineMayShutDown(livePeers: 8))
    }

    @Test("engine teardown retains on either unproven barrier")
    func engineTeardownIsFailClosed() {
        #expect(NativeWebRTCTeardown.engineTeardown(drain: .ok, shutdown: .ok)
            == NativeWebRTCEngineTeardown(retired: true, reported: .ok))
        #expect(NativeWebRTCTeardown.engineTeardown(drain: .null, shutdown: .ok)
            == NativeWebRTCEngineTeardown(retired: true, reported: .ok))

        let drainTimeout = NativeWebRTCTeardown.engineTeardown(
            drain: .timeout, shutdown: .ok)
        #expect(!drainTimeout.retired)
        #expect(drainTimeout.reported == .timeout)

        let drainState = NativeWebRTCTeardown.engineTeardown(
            drain: .state, shutdown: .ok)
        #expect(!drainState.retired)
        #expect(drainState.reported == .state)

        let shutdownTimeout = NativeWebRTCTeardown.engineTeardown(
            drain: .ok, shutdown: .timeout)
        #expect(!shutdownTimeout.retired)
        #expect(shutdownTimeout.reported == .timeout)

        let bothTimeout = NativeWebRTCTeardown.engineTeardown(
            drain: .timeout, shutdown: .timeout)
        #expect(!bothTimeout.retired)
        #expect(bothTimeout.reported == .timeout)

        let shutdownState = NativeWebRTCTeardown.engineTeardown(
            drain: .ok, shutdown: .state)
        #expect(!shutdownState.retired)
        #expect(shutdownState.reported == .state)
    }

    @Test("zero-length product messages follow the bridge")
    func zeroLengthProductMessagesAreValid() {
        #expect(NativeWebRTCPeerValidation.acceptsProductMessageLength(0))
        #expect(NativeWebRTCPeerValidation.acceptsProductMessageLength(
            NativeWebRTCContract.maximumMessageBytes))
        #expect(!NativeWebRTCPeerValidation.acceptsProductMessageLength(
            NativeWebRTCContract.maximumMessageBytes + 1))
        #expect(!NativeWebRTCPeerValidation.acceptsProductMessageLength(-1))
    }

    @Test("invalid native channel validity is not reported as status OK")
    func verifiedChannelValidityErrorsAreHonest() {
        #expect(NativeWebRTCPeerValidation.verifiedChannelValidityError(
            status: .ok, valid: 1) == nil)
        #expect(NativeWebRTCPeerValidation.verifiedChannelValidityError(
            status: .ok, valid: 0) == NativeWebRTCError.verifiedChannelInvalid)
        #expect(NativeWebRTCPeerValidation.verifiedChannelValidityError(
            status: .ok, valid: 2) == NativeWebRTCError.verifiedChannelInvalid)
        #expect(NativeWebRTCPeerValidation.verifiedChannelValidityError(
            status: .handshake, valid: 1)
            == NativeWebRTCError.nativeFailure(
                operation: "read verified channel validity", status: .handshake))
    }

    @Test("channel and peer generation mismatches are explicit")
    func verifiedChannelGenerationErrorsAreHonest() {
        #expect(NativeWebRTCPeerValidation.verifiedChannelGenerationError(
            channelStatus: .ok, channelGeneration: 4,
            peerStatus: .ok, peerGeneration: 4) == nil)
        #expect(NativeWebRTCPeerValidation.verifiedChannelGenerationError(
            channelStatus: .ok, channelGeneration: 4,
            peerStatus: .ok, peerGeneration: 5)
            == NativeWebRTCError.generationMismatch(channel: 4, peer: 5))
        #expect(NativeWebRTCPeerValidation.verifiedChannelGenerationError(
            channelStatus: .ok, channelGeneration: 4,
            peerStatus: .ok, peerGeneration: 0)
            == NativeWebRTCError.invalidHandle("read peer generation"))
        #expect(NativeWebRTCPeerValidation.verifiedChannelGenerationError(
            channelStatus: .handshake, channelGeneration: 4,
            peerStatus: .ok, peerGeneration: 4)
            == NativeWebRTCError.nativeFailure(
                operation: "read verified channel generation", status: .handshake))
        #expect(NativeWebRTCPeerValidation.verifiedChannelGenerationError(
            channelStatus: .ok, channelGeneration: 4,
            peerStatus: .null, peerGeneration: 4)
            == NativeWebRTCError.nativeFailure(operation: "read peer generation", status: .null))
    }

    @Test("certificate pins require exact canonical PEM bytes")
    func certificatePinIsCanonical() {
        let valid = Data(
            "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n".utf8)
        #expect(NativeWebRTCPeerValidation.isCanonicalCertificatePEM(valid))

        #expect(!NativeWebRTCPeerValidation.isCanonicalCertificatePEM(Data()))
        #expect(!NativeWebRTCPeerValidation.isCanonicalCertificatePEM(
            Data("-----BEGIN CERTIFICATE-----\r\nAQIDBA==\r\n-----END CERTIFICATE-----\r\n".utf8)))
        #expect(!NativeWebRTCPeerValidation.isCanonicalCertificatePEM(
            Data("-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----".utf8)))
        #expect(!NativeWebRTCPeerValidation.isCanonicalCertificatePEM(
            Data("-----BEGIN CERTIFICATE-----\nAQID\0BA==\n-----END CERTIFICATE-----\n".utf8)))
    }

    @Test("certificate comparison is exact over the whole value")
    func certificateComparisonIsExact() {
        let first = Data([0x01, 0x02, 0x03])
        #expect(NativeWebRTCPeerValidation.constantTimeEqual(first, first))
        #expect(!NativeWebRTCPeerValidation.constantTimeEqual(
            first, Data([0x01, 0x02, 0x04])))
        #expect(!NativeWebRTCPeerValidation.constantTimeEqual(
            first, Data([0x01, 0x02])))
    }

    @Test("SDP and ICE inputs stay inside the native bounds")
    func negotiationInputsAreBounded() {
        #expect(NativeWebRTCPeerValidation.isValidSDP("v=0\r\ns=-\r\n"))
        #expect(!NativeWebRTCPeerValidation.isValidSDP("v=1\r\n"))
        #expect(!NativeWebRTCPeerValidation.isValidSDP("v=0\0"))
        #expect(!NativeWebRTCPeerValidation.isValidSDP(""))

        #expect(NativeWebRTCPeerValidation.isValidICECandidate(
            "candidate:1 1 udp 1 127.0.0.1 5000 typ host"))
        #expect(!NativeWebRTCPeerValidation.isValidICECandidate("   "))
        #expect(!NativeWebRTCPeerValidation.isValidICECandidate("candidate:\u{00e9}"))
        #expect(!NativeWebRTCPeerValidation.isValidICECandidate(
            String(repeating: "a", count: 4_097)))
    }

    private struct BundleFixture {
        let root: URL
        let bundle: URL
        let frameworks: URL
        let executable: URL

        func dispose() {
            try? FileManager.default.removeItem(at: root)
        }
    }

    private func makeBundleFixture(writeLibrary: Bool = true) throws -> BundleFixture {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-native-\(UUID().uuidString).app", isDirectory: true)
        let frameworks = root.appendingPathComponent(
            "Contents/Frameworks", isDirectory: true)
        let executables = root.appendingPathComponent(
            "Contents/MacOS", isDirectory: true)
        try FileManager.default.createDirectory(
            at: frameworks, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: executables, withIntermediateDirectories: true)

        let executable = executables.appendingPathComponent("HelicoidManager")
        try Data([0x01]).write(to: executable)
        if writeLibrary {
            try Data([0x01]).write(
                to: frameworks.appendingPathComponent(libraryName))
        }
        return BundleFixture(
            root: root,
            bundle: root,
            frameworks: frameworks,
            executable: executable
        )
    }
}
