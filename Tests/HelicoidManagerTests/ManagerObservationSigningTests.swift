import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

/// Manager-only proof and SDP helpers must sign the exact contract transcript
/// and refuse any identity or lease that does not match the verified grant.
@Suite("Manager observation signing")
struct ManagerObservationSigningTests {
    private static let now: Int64 = 1_800_000_000
    private static let deploymentID = "dep_" + String(repeating: "a", count: 32)
    private static let grantID = "b8eeedb7-1d8d-4c29-9e13-05ec6045a173"
    private static let accountID = "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d"
    private static let managerID = "7a01cf88-6fdb-4cc1-a72f-d155f5309355"
    private static let computerID = "6b7b0f41-8af7-4a09-90d0-91c9cd1c0dc9"
    private static let endpointSessionID = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1"
    private static let nonce = String(repeating: "ab", count: 32)
    private static let certificatePEM = Data(
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".utf8
    )

    private struct Keys {
        let server: Curve25519.Signing.PrivateKey
        let manager: Curve25519.Signing.PrivateKey
        let endpoint: Curve25519.Signing.PrivateKey
    }

    private struct Fixture {
        let grant: VerifiedObservationAdmissionGrant
        let identity: ManagerSigningIdentity
    }

    private func makeFixture() throws -> Fixture {
        let keys = Keys(
            server: Curve25519.Signing.PrivateKey(),
            manager: Curve25519.Signing.PrivateKey(),
            endpoint: Curve25519.Signing.PrivateKey()
        )
        let managerKeyHex = lowerHex(keys.manager.publicKey.rawRepresentation)
        let endpointKeyHex = lowerHex(keys.endpoint.publicKey.rawRepresentation)
        let payload = Data(
            "{\"version\":1,\"grant_id\":\"\(Self.grantID)\",\"deployment_id\":\"\(Self.deploymentID)\",\"account_id\":\"\(Self.accountID)\",\"manager_id\":\"\(Self.managerID)\",\"manager_public_key\":\"\(managerKeyHex)\",\"computer_id\":\"\(Self.computerID)\",\"endpoint_public_key\":\"\(endpointKeyHex)\",\"endpoint_session_id\":\"\(Self.endpointSessionID)\",\"enrollment_epoch\":1,\"issued_at_unix\":\(Self.now - 1),\"expires_at_unix\":\(Self.now + 9),\"capability\":\"observe\"}".utf8
        )
        let signature = try keys.server.signature(
            for: Data("hs-observation-grant-v1\0".utf8) + payload
        )
        let token = payload.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            + "." + lowerHex(signature)
        let grant = try ObservationAdmissionGrantVerifier.verifyForManager(
            token: token,
            serverPublicKeyHex: lowerHex(keys.server.publicKey.rawRepresentation),
            expected: ObservationAdmissionManagerExpectation(
                deploymentID: Self.deploymentID,
                accountID: Self.accountID,
                computerID: Self.computerID,
                managerID: Self.managerID,
                managerPublicKeyHex: managerKeyHex
            ),
            nowUnixSeconds: Self.now
        )
        let identity = try ManagerSigningIdentity(
            storedBytes: Data([1]) + keys.manager.rawRepresentation
        )
        return Fixture(grant: grant, identity: identity)
    }

    private func channelBindingHex() throws -> String {
        var bytes = Data("HS-WEBRTC-DTLS-SCTP-V1\0".utf8)
        bytes.append(contentsOf: [0, 10])
        bytes.append(Data("hs-product".utf8))
        bytes.append(contentsOf: [0, 7])
        bytes.append(Data(repeating: 0x11, count: 32))
        bytes.append(Data(repeating: 0x22, count: 32))
        return try #require(
            ObservationAdmissionGrantVerifier.canonicalChannelBindingHex(bytes)
        )
    }

    private func lowerHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    @Test("Matches literal server grant, proof, attestation, and SDP transcripts")
    func matchesGoldenTranscripts() throws {
        let deploymentID = "dep_" + String(repeating: "a", count: 32)
        let grantID = "b8eeedb7-1d8d-4c29-9e13-05ec6045a173"
        let accountID = "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d"
        let managerID = "7a01cf88-6fdb-4cc1-a72f-d155f5309355"
        let computerID = "6b7b0f41-8af7-4a09-90d0-91c9cd1c0dc9"
        let endpointSessionID = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1"
        let managerPublicKey = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
        let endpointPublicKey = "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1"
        let serverPublicKey = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        let now: Int64 = 1_800_000_000
        let nonce = String(repeating: "ab", count: 32)
        let channelBinding = "48532d5745425254432d44544c532d534354502d563100000a68732d70726f64756374000711111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222"
        let goldenPayload = "{\"version\":1,\"grant_id\":\"\(grantID)\",\"deployment_id\":\"\(deploymentID)\",\"account_id\":\"\(accountID)\",\"manager_id\":\"\(managerID)\",\"manager_public_key\":\"\(managerPublicKey)\",\"computer_id\":\"\(computerID)\",\"endpoint_public_key\":\"\(endpointPublicKey)\",\"endpoint_session_id\":\"\(endpointSessionID)\",\"enrollment_epoch\":1,\"issued_at_unix\":1799999999,\"expires_at_unix\":1800000009,\"capability\":\"observe\"}"
        let goldenToken = "eyJ2ZXJzaW9uIjoxLCJncmFudF9pZCI6ImI4ZWVlZGI3LTFkOGQtNGMyOS05ZTEzLTA1ZWM2MDQ1YTE3MyIsImRlcGxveW1lbnRfaWQiOiJkZXBfYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEiLCJhY2NvdW50X2lkIjoiZWYyNTVlMGQtNGY4Yy00YzA4LWJmZjItNGUxMWNiZDIzZjlkIiwibWFuYWdlcl9pZCI6IjdhMDFjZjg4LTZmZGItNGNjMS1hNzJmLWQxNTVmNTMwOTM1NSIsIm1hbmFnZXJfcHVibGljX2tleSI6IjgxMzk3NzBlYTg3ZDE3NWY1NmEzNTQ2NmMzNGM3ZWNjY2I4ZDhhOTFiNGVlMzdhMjVkZjYwZjViOGZjOWIzOTQiLCJjb21wdXRlcl9pZCI6IjZiN2IwZjQxLThhZjctNGEwOS05MGQwLTkxYzljZDFjMGRjOSIsImVuZHBvaW50X3B1YmxpY19rZXkiOiJlZDQ5MjhjNjI4ZDFjMmM2ZWFlOTAzMzg5MDU5OTU2MTI5NTkyNzNhNWM2M2Y5MzYzNmMxNDYxNGFjODczN2QxIiwiZW5kcG9pbnRfc2Vzc2lvbl9pZCI6ImI0YTNmNjZkLTRhYzEtNGFjNi04ODQ3LWU1MGQwYzZmNTVhMSIsImVucm9sbG1lbnRfZXBvY2giOjEsImlzc3VlZF9hdF91bml4IjoxNzk5OTk5OTk5LCJleHBpcmVzX2F0X3VuaXgiOjE4MDAwMDAwMDksImNhcGFiaWxpdHkiOiJvYnNlcnZlIn0.c8b48c3b80ef3b9ac723301aaa4397cb3ed090313d44701a66c28471f5ce3d2c17c7bd0c0d44f326ed0142c1c5f5c19caa53959d7697f2c43190654a5f43ae07"
        let grant = try ObservationAdmissionGrantVerifier.verifyForManager(
            token: goldenToken,
            serverPublicKeyHex: serverPublicKey,
            expected: ObservationAdmissionManagerExpectation(
                deploymentID: deploymentID,
                accountID: accountID,
                computerID: computerID,
                managerID: managerID,
                managerPublicKeyHex: managerPublicKey
            ),
            nowUnixSeconds: now
        )
        let managerIdentity = try ManagerSigningIdentity(
            storedBytes: Data([1]) + Data(repeating: 0x02, count: 32)
        )
        #expect(lowerHex(managerIdentity.publicKey) == managerPublicKey)
        let tokenParts = goldenToken.split(separator: ".", omittingEmptySubsequences: false)
        #expect(tokenParts.count == 2)
        let encodedPayloadPart = try #require(tokenParts.first)
        let encodedPayload = String(encodedPayloadPart)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let paddedPayload = encodedPayload + String(
            repeating: "=",
            count: (4 - encodedPayload.count % 4) % 4
        )
        let decodedPayload = try #require(Data(base64Encoded: paddedPayload))
        let decodedText = try #require(String(data: decodedPayload, encoding: .utf8))
        #expect(decodedText == goldenPayload)

        let proof = try grant.managerProofMessage(
            endpointNonceHex: nonce,
            channelBindingHex: channelBinding
        )
        let expectedProof = "hs-observation-peer-proof-v2|deployment:\(deploymentID)|grant:\(grantID)|computer:\(computerID)|endpoint_session:\(endpointSessionID)|epoch:1|nonce:\(nonce)|channel_binding:\(channelBinding)"
        #expect(proof == Data(expectedProof.utf8))
        let proofHex = try grant.signManagerProof(
            endpointNonceHex: nonce,
            channelBindingHex: channelBinding,
            identity: managerIdentity,
            nowUnixSeconds: now
        )
        #expect(proofHex == "c8d79dc7d43ca82a80baaf58f20ad5e3d1140f832c370dd6636b8df9f7b3a7da3e4c6684f60a00c261da63df5f250d36869e94c898ba67076e229dabe1c5e507")

        let certificatePEM = Data("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".utf8)
        let attestation = try grant.peerCertificateAttestationMessage(
            certificatePEM: certificatePEM,
            endpointNonceHex: nonce,
            role: .manager,
            nowUnixSeconds: now
        )
        let expectedAttestation = "hs-observation-peer-certificate-v1|deployment:\(deploymentID)|grant:\(grantID)|computer:\(computerID)|endpoint_session:\(endpointSessionID)|epoch:1|nonce:\(nonce)|role:manager|certificate_sha256:8010bfcee1842b2a4ce8f67c3e9455f0188f7a15bf39ec61a26feb75cd785821"
        #expect(attestation == Data(expectedAttestation.utf8))
        let certificateSignature = try grant.signPeerCertificateAttestation(
            certificatePEM: certificatePEM,
            endpointNonceHex: nonce,
            identity: managerIdentity,
            nowUnixSeconds: now
        )
        #expect(lowerHex(certificateSignature) == "bac19a368ea97e5b61af61572692e3bf7c118337f485d7f68728d9cdd73426dd5df9a227fcd62fb90f8cf069bff60e91c4aa1eb9a9280feefb9d51c8b8ab4c0a")

        let zeroSignature = Data(repeating: 0, count: 64)
        let goldenSDP = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=hs-observation-cert-v1:LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo.\(String(repeating: "0", count: 128))\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        let attested = try ManagerObservationSDP.appendCertificateAttestation(
            to: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n",
            certificatePEM: certificatePEM,
            signature: zeroSignature
        )
        #expect(attested == goldenSDP)
    }

    @Test("Signs the channel-bound Manager proof and admission proof message")
    func signsManagerProof() throws {
        let fixture = try makeFixture()
        let binding = try channelBindingHex()
        let proof = try fixture.grant.signManagerProof(
            endpointNonceHex: Self.nonce,
            channelBindingHex: binding,
            identity: fixture.identity,
            nowUnixSeconds: Self.now
        )
        #expect(proof.count == 128)
        #expect(proof == proof.lowercased())
        let signature = try #require(
            ObservationAdmissionGrantVerifier.lowerHexBytes(proof)
        )
        #expect(fixture.grant.verifiesManagerProof(
            endpointNonceHex: Self.nonce,
            channelBindingHex: binding,
            signature: signature
        ))

        let message = try fixture.grant.managerAdmissionProofMessage(
            endpointNonceHex: Self.nonce,
            channelBindingHex: binding,
            identity: fixture.identity,
            nowUnixSeconds: Self.now
        )
        let objectJSON = try JSONSerialization.jsonObject(with: message)
        let object = try #require(objectJSON as? [String: Any])
        #expect(Set(object.keys) == Set([
            "type", "grant_id", "endpoint_nonce", "channel_binding", "manager_proof",
        ]))
        #expect(object["type"] as? String == "observation_admission_proof")
        #expect(object["grant_id"] as? String == fixture.grant.grantID)
        #expect(object["endpoint_nonce"] as? String == Self.nonce)
        #expect(object["channel_binding"] as? String == binding)
        #expect(object["manager_proof"] as? String == proof)

        let otherIdentity = try ManagerSigningIdentity(
            storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation
        )
        #expect(throws: HelicoidError.identityMismatch) {
            _ = try fixture.grant.signManagerProof(
                endpointNonceHex: Self.nonce,
                channelBindingHex: binding,
                identity: otherIdentity,
                nowUnixSeconds: Self.now
            )
        }
        #expect(throws: HelicoidError.self) {
            _ = try fixture.grant.signManagerProof(
                endpointNonceHex: Self.nonce,
                channelBindingHex: binding,
                identity: fixture.identity,
                nowUnixSeconds: fixture.grant.expiresAtUnix
            )
        }
    }

    @Test("Signs and verifies the Manager certificate attestation")
    func signsCertificateAttestation() throws {
        let fixture = try makeFixture()
        let signature = try fixture.grant.signPeerCertificateAttestation(
            certificatePEM: Self.certificatePEM,
            endpointNonceHex: Self.nonce,
            identity: fixture.identity,
            nowUnixSeconds: Self.now
        )
        #expect(signature.count == 64)
        #expect(fixture.grant.verifiesPeerCertificateAttestation(
            certificatePEM: Self.certificatePEM,
            endpointNonceHex: Self.nonce,
            role: .manager,
            signature: signature,
            nowUnixSeconds: Self.now
        ))
        #expect(!fixture.grant.verifiesPeerCertificateAttestation(
            certificatePEM: Self.certificatePEM,
            endpointNonceHex: Self.nonce,
            role: .endpoint,
            signature: signature,
            nowUnixSeconds: Self.now
        ))

        let otherIdentity = try ManagerSigningIdentity(
            storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation
        )
        #expect(throws: HelicoidError.identityMismatch) {
            _ = try fixture.grant.signPeerCertificateAttestation(
                certificatePEM: Self.certificatePEM,
                endpointNonceHex: Self.nonce,
                identity: otherIdentity,
                nowUnixSeconds: Self.now
            )
        }
    }

    @Test("Inserts exactly one verified certificate attribute before media")
    func appendsCertificateAttestationToSDP() throws {
        let fixture = try makeFixture()
        let sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        let attested = try fixture.grant.appendManagerCertificateAttestationToSDP(
            sdp,
            certificatePEM: Self.certificatePEM,
            endpointNonceHex: Self.nonce,
            identity: fixture.identity,
            nowUnixSeconds: Self.now
        )
        let attributeRange = try #require(
            attested.range(of: ManagerObservationSDP.certificateAttributePrefix)
        )
        let mediaRange = try #require(attested.range(of: "m="))
        #expect(attributeRange.lowerBound < mediaRange.lowerBound)

        let line = try #require(
            attested.components(separatedBy: "\r\n")
                .first(where: {
                    $0.hasPrefix(ManagerObservationSDP.certificateAttributePrefix)
                })
        )
        let value = line.dropFirst(
            ManagerObservationSDP.certificateAttributePrefix.count
        )
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        #expect(parts.count == 2)
        let encoded = String(parts[0])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padded = encoded + String(
            repeating: "=",
            count: (4 - encoded.count % 4) % 4
        )
        let decodedCertificate = try #require(Data(base64Encoded: padded))
        #expect(decodedCertificate == Self.certificatePEM)
        let signature = try #require(
            ObservationAdmissionGrantVerifier.lowerHexBytes(String(parts[1]))
        )
        #expect(fixture.grant.verifiesPeerCertificateAttestation(
            certificatePEM: Self.certificatePEM,
            endpointNonceHex: Self.nonce,
            role: .manager,
            signature: signature,
            nowUnixSeconds: Self.now
        ))

        #expect(throws: HelicoidError.observationProtocolViolation(
            detail: "The Manager offer already contains a certificate attestation."
        )) {
            _ = try fixture.grant.appendManagerCertificateAttestationToSDP(
                attested,
                certificatePEM: Self.certificatePEM,
                endpointNonceHex: Self.nonce,
                identity: fixture.identity,
                nowUnixSeconds: Self.now
            )
        }
        #expect(throws: HelicoidError.self) {
            _ = try fixture.grant.appendManagerCertificateAttestationToSDP(
                "v=0\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\n",
                certificatePEM: Self.certificatePEM,
                endpointNonceHex: Self.nonce,
                identity: fixture.identity,
                nowUnixSeconds: Self.now
            )
        }
        #expect(throws: HelicoidError.self) {
            _ = try fixture.grant.appendManagerCertificateAttestationToSDP(
                "v=0\r\ns=-\r\n",
                certificatePEM: Self.certificatePEM,
                endpointNonceHex: Self.nonce,
                identity: fixture.identity,
                nowUnixSeconds: Self.now
            )
        }
        #expect(throws: HelicoidError.self) {
            _ = try fixture.grant.appendManagerCertificateAttestationToSDP(
                "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
                    + String(repeating: "a", count: 65_536),
                certificatePEM: Self.certificatePEM,
                endpointNonceHex: Self.nonce,
                identity: fixture.identity,
                nowUnixSeconds: Self.now
            )
        }
        #expect(throws: HelicoidError.self) {
            _ = try ManagerObservationSDP.appendCertificateAttestation(
                to: sdp,
                certificatePEM: Data("not a certificate".utf8),
                signature: Data(repeating: 0, count: 64)
            )
        }
        #expect(throws: HelicoidError.self) {
            _ = try ManagerObservationSDP.appendCertificateAttestation(
                to: sdp,
                certificatePEM: Self.certificatePEM,
                signature: Data(repeating: 0, count: 63)
            )
        }
    }
}
