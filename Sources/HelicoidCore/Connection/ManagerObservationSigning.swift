import CryptoKit
import Foundation

/// A Manager offer that already carries one signature-bound
/// `a=hs-observation-cert-v1:` certificate attribute.
///
/// The initializer is file-private: arbitrary SDP cannot be promoted to this
/// type. The HTTP lease accepts only this value for offer relay, so a caller
/// cannot accidentally publish an unattested offer.
public struct ManagerObservationAttestedOffer: Sendable, Equatable {
    public let sdp: String
    let grantID: String
    let endpointNonceHex: String
    let certificatePEM: Data
    let signature: Data

    fileprivate init(
        sdp: String,
        grantID: String,
        endpointNonceHex: String,
        certificatePEM: Data,
        signature: Data
    ) {
        self.sdp = sdp
        self.grantID = grantID
        self.endpointNonceHex = endpointNonceHex
        self.certificatePEM = certificatePEM
        self.signature = signature
    }
}

extension VerifiedObservationAdmissionGrant {
    /// Sign the supplied local Manager certificate and return an offer that is
    /// safe to relay. The certificate must be the live native peer's exported
    /// certificate; the resulting SDP carries the exact signed attribute.
    public func attestedOffer(
        sdp: String,
        certificatePEM: Data,
        endpointNonceHex: String,
        identity: ManagerSigningIdentity,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> ManagerObservationAttestedOffer {
        let signature = try signPeerCertificateAttestation(
            certificatePEM: certificatePEM,
            endpointNonceHex: endpointNonceHex,
            identity: identity,
            nowUnixSeconds: nowUnixSeconds
        )
        let attestedSDP = try ManagerObservationSDP.appendCertificateAttestation(
            to: sdp,
            certificatePEM: certificatePEM,
            signature: signature
        )
        return ManagerObservationAttestedOffer(
            sdp: attestedSDP,
            grantID: grantID,
            endpointNonceHex: endpointNonceHex,
            certificatePEM: certificatePEM,
            signature: signature
        )
    }
}

/// Manager-only signing and SDP helpers for one verified observation grant.
///
/// These helpers never establish trust. They only sign the exact transcripts
/// already defined by the server contract and the verified grant, and they
/// refuse an identity or lease that no longer matches. Native peer creation,
/// certificate pinning, offer/answer exchange, and frame delivery remain
/// separate callers.
extension VerifiedObservationAdmissionGrant {
    /// Sign the channel-bound `observation_admission_proof` transcript with the
    /// active Manager device identity. Returns lowercase hex, the form the
    /// endpoint expects in its data-channel proof message.
    public func signManagerProof(
        endpointNonceHex: String,
        channelBindingHex: String,
        identity: ManagerSigningIdentity,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> String {
        guard expiresAtUnix > nowUnixSeconds else {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        guard AuthV2Canonical.lowercaseHex(identity.publicKey) == managerPublicKeyHex else {
            throw HelicoidError.identityMismatch
        }
        let message = try managerProofMessage(
            endpointNonceHex: endpointNonceHex,
            channelBindingHex: channelBindingHex
        )
        return AuthV2Canonical.lowercaseHex(
            try identity.sign(canonicalMessage: message)
        )
    }

    /// Sign the Manager's local DTLS certificate for this grant and endpoint
    /// nonce. The signature must be inserted into the offer before the endpoint
    /// is allowed to accept remote SDP.
    public func signPeerCertificateAttestation(
        certificatePEM: Data,
        endpointNonceHex: String,
        identity: ManagerSigningIdentity,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> Data {
        guard AuthV2Canonical.lowercaseHex(identity.publicKey) == managerPublicKeyHex else {
            throw HelicoidError.identityMismatch
        }
        let message = try peerCertificateAttestationMessage(
            certificatePEM: certificatePEM,
            endpointNonceHex: endpointNonceHex,
            role: .manager,
            nowUnixSeconds: nowUnixSeconds
        )
        return try identity.sign(canonicalMessage: message)
    }

    /// Sign the local certificate and insert the single session-level
    /// `a=hs-observation-cert-v1:` attribute into the Manager offer before the
    /// first media line.
    public func appendManagerCertificateAttestationToSDP(
        _ sdp: String,
        certificatePEM: Data,
        endpointNonceHex: String,
        identity: ManagerSigningIdentity,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> String {
        let signature = try signPeerCertificateAttestation(
            certificatePEM: certificatePEM,
            endpointNonceHex: endpointNonceHex,
            identity: identity,
            nowUnixSeconds: nowUnixSeconds
        )
        return try ManagerObservationSDP.appendCertificateAttestation(
            to: sdp,
            certificatePEM: certificatePEM,
            signature: signature
        )
    }

    /// Build the exact `observation_admission_proof` JSON sent over the
    /// verified product data channel after the Manager and endpoint have each
    /// exported the current channel binding.
    public func managerAdmissionProofMessage(
        endpointNonceHex: String,
        channelBindingHex: String,
        identity: ManagerSigningIdentity,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> Data {
        let proof = try signManagerProof(
            endpointNonceHex: endpointNonceHex,
            channelBindingHex: channelBindingHex,
            identity: identity,
            nowUnixSeconds: nowUnixSeconds
        )
        return try JSONEncoder().encode(
            ManagerObservationAdmissionProofWire(
                grantID: grantID,
                endpointNonce: endpointNonceHex,
                channelBinding: channelBindingHex,
                managerProof: proof
            )
        )
    }
}

/// Pure SDP helper for the Manager certificate attestation. Kept separate so
/// callers can test the exact attribute insertion without a native peer.
public enum ManagerObservationSDP {
    public static let maximumSDPBytes = ManagerObservationSignalingSession.maximumAnswerBytes
    public static let certificateAttributePrefix = "a=hs-observation-cert-v1:"

    /// Insert one signature-bound certificate attribute before the first media
    /// line. Existing attributes, non-CRLF line endings, a missing media
    /// section, and an oversized result are all refused.
    public static func appendCertificateAttestation(
        to sdp: String,
        certificatePEM: Data,
        signature: Data
    ) throws -> String {
        guard signature.count == 64,
              ObservationEndpointChallengeVerifier.isCanonicalCertificatePEM(certificatePEM) else {
            throw invalidSDP("The Manager offer certificate or attestation signature is invalid.")
        }
        let bytes = Data(sdp.utf8)
        guard !bytes.isEmpty,
              bytes.count <= maximumSDPBytes,
              bytes.allSatisfy({ $0 < 0x80 && $0 != 0 }),
              sdp.hasPrefix("v=0\r\n") else {
            throw invalidSDP("The Manager offer is empty, oversized, or not a canonical SDP document.")
        }
        for index in bytes.indices {
            if bytes[index] == 0x0A,
               index == bytes.startIndex || bytes[index - 1] != 0x0D {
                throw invalidSDP("The Manager offer has invalid line endings.")
            }
            if bytes[index] == 0x0D,
               index + 1 >= bytes.endIndex || bytes[index + 1] != 0x0A {
                throw invalidSDP("The Manager offer has invalid line endings.")
            }
        }
        let prefix = Data(certificateAttributePrefix.utf8)
        guard bytes.range(of: prefix) == nil else {
            throw invalidSDP("The Manager offer already contains a certificate attestation.")
        }
        let mediaMarker = Data("\r\nm=".utf8)
        guard let media = bytes.range(of: mediaMarker) else {
            throw invalidSDP("The Manager offer has no media section.")
        }

        let encodedCertificate = certificatePEM.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let attribute = Data(
            (certificateAttributePrefix + encodedCertificate + "."
                + AuthV2Canonical.lowercaseHex(signature) + "\r\n").utf8
        )
        var result = Data()
        let insertionPoint = media.lowerBound + 2
        result.append(contentsOf: bytes[bytes.startIndex..<insertionPoint])
        result.append(contentsOf: attribute)
        result.append(contentsOf: bytes[insertionPoint..<bytes.endIndex])
        guard result.count <= maximumSDPBytes,
              let attested = String(data: result, encoding: .utf8) else {
            throw invalidSDP("The attested Manager offer exceeds the signaling size limit.")
        }
        return attested
    }

    private static func invalidSDP(_ detail: String) -> HelicoidError {
        .observationProtocolViolation(detail: detail)
    }
}

private struct ManagerObservationAdmissionProofWire: Encodable {
    let type = "observation_admission_proof"
    let grantID: String
    let endpointNonce: String
    let channelBinding: String
    let managerProof: String

    enum CodingKeys: String, CodingKey {
        case type
        case grantID = "grant_id"
        case endpointNonce = "endpoint_nonce"
        case channelBinding = "channel_binding"
        case managerProof = "manager_proof"
    }
}
