import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

/// Production pinning must be bound to the transport's actual configured TLS
/// identity, not merely to the concrete transport type.
@Suite("Native v2 pinned identity binding")
struct NativeV2AuthPinnedIdentityTests {
    private func makeIdentity(
        host: String,
        deploymentID: String = "dep_" + String(repeating: "a", count: 32)
    ) async throws -> DeploymentTLSIdentity {
        let material = try await TLSTestHarness.sharedMaterial()
        return try DeploymentTLSIdentity(
            deploymentID: deploymentID,
            host: host,
            port: 8443,
            caDER: material.caDER,
            caFingerprintSHA256: material.caFingerprint
        )
    }

    private func makeSigningIdentity() throws -> ManagerSigningIdentity {
        try ManagerSigningIdentity(
            storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation
        )
    }

    private func makePinnedTransport(
        _ identity: DeploymentTLSIdentity
    ) throws -> PinnedHTTPSTransport {
        try PinnedHTTPSTransport(
            configuration: PinnedHTTPSConfiguration(identity: identity)
        )
    }

    @Test("Matching transport identity is production pinned")
    func matchingPinnedIdentity() async throws {
        let identity = try await makeIdentity(host: "server.test")
        let transport = try makePinnedTransport(identity)
        defer { transport.dispose() }
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: identity,
            signingIdentity: try makeSigningIdentity()
        )
        let isProductionPinned = client.isProductionPinned
        #expect(isProductionPinned)
    }

    @Test("Pinned transport for another CA never satisfies the gate")
    func mismatchedPinnedCA() async throws {
        let material = try await TLSTestHarness.sharedMaterial()
        let deploymentID = "dep_" + String(repeating: "a", count: 32)
        let pinned = try DeploymentTLSIdentity(
            deploymentID: deploymentID,
            host: "server.test",
            port: 8443,
            caDER: material.caDER,
            caFingerprintSHA256: material.caFingerprint
        )
        let declared = try DeploymentTLSIdentity(
            deploymentID: deploymentID,
            host: "server.test",
            port: 8443,
            caDER: material.foreignCADER,
            caFingerprintSHA256: DeploymentTLSIdentity.sha256Hex(
                material.foreignCADER
            )
        )
        let transport = try makePinnedTransport(pinned)
        defer { transport.dispose() }
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: declared,
            signingIdentity: try makeSigningIdentity()
        )
        let isProductionPinned = client.isProductionPinned
        #expect(!isProductionPinned)
    }

    @Test("Pinned transport for another host never satisfies the gate")
    func mismatchedPinnedIdentity() async throws {
        let pinnedIdentity = try await makeIdentity(host: "server.test")
        let declaredIdentity = try await makeIdentity(host: "other.test")
        let transport = try makePinnedTransport(pinnedIdentity)
        defer { transport.dispose() }
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: declaredIdentity,
            signingIdentity: try makeSigningIdentity()
        )
        let isProductionPinned = client.isProductionPinned
        let trustedIdentity = client.trustedIdentity
        #expect(!isProductionPinned)
        #expect(trustedIdentity == declaredIdentity)
    }
}
