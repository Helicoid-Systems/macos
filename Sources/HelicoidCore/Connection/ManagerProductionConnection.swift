import Foundation

/// Production composition gate for one independently trusted deployment.
///
/// The caller supplies the pinned TLS identity and the Keychain-backed authority
/// store. `makeVerifiedClient` reads the authority over the pinned origin,
/// requires an exact match with the saved checkpoint, and only then returns a
/// client that can begin sign-in. A missing checkpoint, rollback, or
/// same-generation key change keeps the connection closed.
///
/// `observeAuthority` is deliberately unverified. Use it only to read the
/// published tuple for out-of-band review before calling
/// `ManagerAuthorityTrustStore.adopt` with a separate confirmation.
public struct ManagerProductionConnection: Sendable {
    public let tlsIdentity: DeploymentTLSIdentity
    public let authorityTrust: ManagerAuthorityTrustStore

    public init(
        tlsIdentity: DeploymentTLSIdentity,
        authorityTrust: ManagerAuthorityTrustStore
    ) {
        self.tlsIdentity = tlsIdentity
        self.authorityTrust = authorityTrust
    }

    /// Read the published tuple over the pinned origin for out-of-band review.
    ///
    /// This never saves or adopts a checkpoint. The returned value is an
    /// observation only; compare it through a trusted channel and call
    /// `ManagerAuthorityTrustStore.adopt` with a separate confirmation.
    public func observeAuthority(
        signingIdentity: ManagerSigningIdentity
    ) async throws -> DeploymentAuthorityCheckpoint {
        let client = try makePinnedClient(signingIdentity: signingIdentity)
        return try await client.fetchDeploymentAuthority()
    }

    /// Fetch the published authority and require it to match the saved
    /// checkpoint exactly. Nothing is adopted here.
    ///
    /// This is a point-in-time gate. Callers should call
    /// `ManagerAuthorityTrustStore.requireCurrent` again before any later
    /// protected operation.
    public func makeVerifiedClient(
        signingIdentity: ManagerSigningIdentity
    ) async throws -> NativeV2AuthClient {
        let saved = try await authorityTrust.savedCheckpoint(
            deploymentID: tlsIdentity.deploymentID
        )
        guard saved != nil else {
            throw HelicoidError.authenticationFailed(
                detail: "No independently verified deployment authority checkpoint is saved. Complete out-of-band trust setup before connecting."
            )
        }
        let client = try makePinnedClient(signingIdentity: signingIdentity)
        let observed = try await client.fetchDeploymentAuthority()
        _ = try await authorityTrust.requireCurrent(observed)
        return client
    }

    /// TLS-pinned client with no authority-checkpoint admission. Kept private so
    /// callers cannot accidentally treat an unverified observation as a
    /// production connection.
    private func makePinnedClient(
        signingIdentity: ManagerSigningIdentity
    ) throws -> NativeV2AuthClient {
        let configuration = try PinnedHTTPSConfiguration(identity: tlsIdentity)
        let transport = try PinnedHTTPSTransport(configuration: configuration)
        return NativeV2AuthClient(
            transport: transport,
            trustedAuthority: tlsIdentity,
            signingIdentity: signingIdentity
        )
    }
}
