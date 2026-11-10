import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

/// The endpoint challenge is unsigned JSON. The Manager may trust it only after
/// every identity claim matches the server-signed grant and the endpoint's
/// certificate attestation verifies under the endpoint key named by that grant.
@Suite("Manager endpoint observation challenge")
struct ManagerObservationEndpointChallengeTests {
    private static let now: Int64 = 1_700_000_000
    private static let deploymentID = "dep_" + String(repeating: "a", count: 32)
    private static let grantID = "b8eeedb7-1d8d-4c29-9e13-05ec6045a173"
    private static let otherGrantID = "c14aed02-2397-4d25-9029-2e2c4e39b338"
    private static let accountID = "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d"
    private static let managerID = "7a01cf88-6fdb-4cc1-a72f-d155f5309355"
    private static let computerID = "6b7b0f41-8af7-4a09-90d0-91c9cd1c0dc9"
    private static let endpointSessionID = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1"
    private static let nonce = String(repeating: "4", count: 64)
    private static let certificatePEM =
        "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n"
    private static let otherCertificatePEM =
        "-----BEGIN CERTIFICATE-----\nBQYHCA==\n-----END CERTIFICATE-----\n"

    private struct Keys {
        let server: Curve25519.Signing.PrivateKey
        let manager: Curve25519.Signing.PrivateKey
        let endpoint: Curve25519.Signing.PrivateKey
        let foreign: Curve25519.Signing.PrivateKey
    }

    private func makeKeys() -> Keys {
        Keys(
            server: Curve25519.Signing.PrivateKey(),
            manager: Curve25519.Signing.PrivateKey(),
            endpoint: Curve25519.Signing.PrivateKey(),
            foreign: Curve25519.Signing.PrivateKey()
        )
    }

    private func makeGrant(
        _ keys: Keys,
        at nowUnix: Int64 = ManagerObservationEndpointChallengeTests.now,
        grantID: String = ManagerObservationEndpointChallengeTests.grantID
    ) throws -> VerifiedObservationAdmissionGrant {
        let managerPublicKey = lowerHex(keys.manager.publicKey.rawRepresentation)
        let endpointPublicKey = lowerHex(keys.endpoint.publicKey.rawRepresentation)
        let payload = "{\"version\":1,\"grant_id\":\"\(grantID)\",\"deployment_id\":\"\(Self.deploymentID)\",\"account_id\":\"\(Self.accountID)\",\"manager_id\":\"\(Self.managerID)\",\"manager_public_key\":\"\(managerPublicKey)\",\"computer_id\":\"\(Self.computerID)\",\"endpoint_public_key\":\"\(endpointPublicKey)\",\"endpoint_session_id\":\"\(Self.endpointSessionID)\",\"enrollment_epoch\":1,\"issued_at_unix\":\(nowUnix - 1),\"expires_at_unix\":\(nowUnix + 9),\"capability\":\"observe\"}"
        return try ObservationAdmissionGrantVerifier.verifyForManager(
            token: try token(payload: Data(payload.utf8), signedBy: keys.server),
            serverPublicKeyHex: lowerHex(keys.server.publicKey.rawRepresentation),
            expected: ObservationAdmissionManagerExpectation(
                deploymentID: Self.deploymentID,
                accountID: Self.accountID,
                computerID: Self.computerID,
                managerID: Self.managerID,
                managerPublicKeyHex: managerPublicKey
            ),
            nowUnixSeconds: nowUnix
        )
    }

    private func token(payload: Data, signedBy key: Curve25519.Signing.PrivateKey) throws -> String {
        let signed = Data("hs-observation-grant-v1\0".utf8) + payload
        let signature = try key.signature(for: signed)
        return base64URL(payload) + "." + lowerHex(signature)
    }

    private func attestationSignature(
        grant: VerifiedObservationAdmissionGrant,
        certificatePEM: String = ManagerObservationEndpointChallengeTests.certificatePEM,
        nonce: String = ManagerObservationEndpointChallengeTests.nonce,
        role: ObservationPeerRole = .endpoint,
        key: Curve25519.Signing.PrivateKey,
        at nowUnix: Int64 = ManagerObservationEndpointChallengeTests.now
    ) throws -> Data {
        let message = try grant.peerCertificateAttestationMessage(
            certificatePEM: Data(certificatePEM.utf8),
            endpointNonceHex: nonce,
            role: role,
            nowUnixSeconds: nowUnix
        )
        return try key.signature(for: message)
    }

    private func challengeJSON(
        signatureHex: String,
        computerID: String = ManagerObservationEndpointChallengeTests.computerID,
        endpointSessionID: String = ManagerObservationEndpointChallengeTests.endpointSessionID,
        nonce: String = ManagerObservationEndpointChallengeTests.nonce,
        expiresAtUnix: Any = ManagerObservationEndpointChallengeTests.now + 9,
        includeCertificate: Bool = true,
        certificateValue: Any = ManagerObservationEndpointChallengeTests.certificatePEM,
        includeSignature: Bool = true
    ) throws -> String {
        var object: [String: Any] = [
            "computer_id": computerID,
            "endpoint_session_id": endpointSessionID,
            "endpoint_nonce": nonce,
            "expires_at_unix": expiresAtUnix,
        ]
        if includeCertificate {
            object["endpoint_certificate_pem"] = certificateValue
        }
        if includeSignature {
            object["endpoint_certificate_signature"] = signatureHex
        }
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private func lowerHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Encode a JSON string the way Windows System.Text.Json's default encoder
    /// does: control characters and HTML-sensitive `+` use JSON escapes.
    private func windowsJSONString(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "+", with: "\\u002B")
        return "\"\(escaped)\""
    }

    @Test("Verifies endpoint challenge identity and certificate attestation")
    func verifiesEndpointChallenge() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let signature = try attestationSignature(grant: grant, key: keys.endpoint)

        let challenge = try ObservationEndpointChallengeVerifier.verify(
            payload: try challengeJSON(signatureHex: lowerHex(signature)),
            grant: grant,
            nowUnixSeconds: Self.now
        )

        #expect(challenge.computerID == Self.computerID)
        #expect(challenge.endpointSessionID == Self.endpointSessionID)
        #expect(challenge.endpointNonceHex == Self.nonce)
        #expect(challenge.expiresAtUnix == Self.now + 9)
        #expect(challenge.endpointCertificatePEM == Data(Self.certificatePEM.utf8))
    }

    @Test("Builds the canonical certificate attestation message")
    func buildsCanonicalAttestationMessage() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let message = try grant.peerCertificateAttestationMessage(
            certificatePEM: Data(Self.certificatePEM.utf8),
            endpointNonceHex: Self.nonce,
            role: .endpoint,
            nowUnixSeconds: Self.now
        )
        let expected = "hs-observation-peer-certificate-v1|deployment:\(Self.deploymentID)|grant:\(Self.grantID)|computer:\(Self.computerID)|endpoint_session:\(Self.endpointSessionID)|epoch:1|nonce:\(Self.nonce)|role:endpoint|certificate_sha256:72819a0afb337bd0fc91ee666a5f9db0e75f7ea8068caad8e391c2c442495af7"
        #expect(message == Data(expected.utf8))
    }

    @Test("Accepts a realistic line-wrapped PEM serialized like Windows System.Text.Json")
    func acceptsWindowsEscapedLineWrappedPEM() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let certificatePEM =
            "-----BEGIN CERTIFICATE-----\n" +
            "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n" +
            "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P\n" +
            "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaan+//+AQID+//+AQID+//+AQID+//+AQID\n" +
            "+//+AQID+//+AQID+//+AQID+//+AQID\n" +
            "-----END CERTIFICATE-----\n"
        let signatureHex = lowerHex(try attestationSignature(
            grant: grant,
            certificatePEM: certificatePEM,
            key: keys.endpoint
        ))
        let payload =
            "{\"computer_id\":\"\(Self.computerID)\"," +
            "\"endpoint_session_id\":\"\(Self.endpointSessionID)\"," +
            "\"endpoint_nonce\":\"\(Self.nonce)\"," +
            "\"expires_at_unix\":\(Self.now + 9)," +
            "\"endpoint_certificate_pem\":\(windowsJSONString(certificatePEM))," +
            "\"endpoint_certificate_signature\":\"\(signatureHex)\"}"

        let challenge = try ObservationEndpointChallengeVerifier.verify(
            payload: payload,
            grant: grant,
            nowUnixSeconds: Self.now
        )
        #expect(challenge.endpointCertificatePEM == Data(certificatePEM.utf8))
    }

    @Test("Explicitly rejects a challenge with no certificate attestation")
    func rejectsChallengeWithoutAttestation() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let signatureHex = lowerHex(try attestationSignature(grant: grant, key: keys.endpoint))
        let payload = try challengeJSON(
            signatureHex: signatureHex,
            includeCertificate: false,
            includeSignature: false
        )

        do {
            _ = try ObservationEndpointChallengeVerifier.verify(
                payload: payload,
                grant: grant,
                nowUnixSeconds: Self.now
            )
            Issue.record("a four-field challenge without attestation must fail")
        } catch let error as HelicoidError {
            #expect(error == .authenticationFailed(
                detail: "The endpoint observation challenge has no certificate attestation, so the endpoint identity cannot be pinned."
            ))
        } catch {
            Issue.record("expected authenticationFailed, got \(error)")
        }
    }

    @Test("Rejects endpoint challenge identity and expiry mismatches")
    func rejectsIdentityAndExpiryMismatches() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let signatureHex = lowerHex(try attestationSignature(grant: grant, key: keys.endpoint))

        let cases: [(String, Int64)] = [
            (try challengeJSON(
                signatureHex: signatureHex,
                computerID: "00000000-0000-4000-8000-000000000002"
            ), Self.now),
            (try challengeJSON(
                signatureHex: signatureHex,
                endpointSessionID: "00000000-0000-4000-8000-000000000002"
            ), Self.now),
            (try challengeJSON(signatureHex: signatureHex, nonce: "not-lower-hex"), Self.now),
            (try challengeJSON(signatureHex: signatureHex, nonce: Self.nonce.uppercased()), Self.now),
            (try challengeJSON(signatureHex: signatureHex, expiresAtUnix: Self.now + 8), Self.now),
            (try challengeJSON(signatureHex: signatureHex, expiresAtUnix: Self.now + 10), Self.now),
            (try challengeJSON(signatureHex: signatureHex), Self.now + 9),
        ]

        for (payload, verifyAt) in cases {
            #expect(throws: HelicoidError.self) {
                _ = try ObservationEndpointChallengeVerifier.verify(
                    payload: payload,
                    grant: grant,
                    nowUnixSeconds: verifyAt
                )
            }
        }
    }

    @Test("Rejects certificate attestation signature mismatches")
    func rejectsSignatureMismatches() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let otherNonce = String(repeating: "5", count: 64)

        let signatures = [
            lowerHex(try attestationSignature(grant: grant, key: keys.foreign)),
            lowerHex(try attestationSignature(grant: grant, nonce: otherNonce, key: keys.endpoint)),
            lowerHex(try attestationSignature(
                grant: grant,
                certificatePEM: Self.otherCertificatePEM,
                key: keys.endpoint
            )),
            lowerHex(try attestationSignature(grant: grant, key: keys.manager)),
            lowerHex(try attestationSignature(grant: grant, key: keys.endpoint)).uppercased(),
            String(lowerHex(try attestationSignature(grant: grant, key: keys.endpoint)).dropLast(2)),
            "",
        ]

        for signatureHex in signatures {
            #expect(throws: HelicoidError.self) {
                _ = try ObservationEndpointChallengeVerifier.verify(
                    payload: try challengeJSON(signatureHex: signatureHex),
                    grant: grant,
                    nowUnixSeconds: Self.now
                )
            }
        }
    }

    @Test("Rejects an attestation made for another grant")
    func rejectsAttestationForAnotherGrant() throws {
        let keys = makeKeys()
        let firstGrant = try makeGrant(keys)
        let secondGrant = try makeGrant(keys, grantID: Self.otherGrantID)
        let signature = try attestationSignature(grant: firstGrant, key: keys.endpoint)

        #expect(throws: HelicoidError.self) {
            _ = try ObservationEndpointChallengeVerifier.verify(
                payload: try challengeJSON(signatureHex: lowerHex(signature)),
                grant: secondGrant,
                nowUnixSeconds: Self.now
            )
        }
    }

    @Test("Checks attestation expiry and peer role against the grant keys")
    func checksAttestationExpiryAndRole() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let certificate = Data(Self.certificatePEM.utf8)
        let endpointSignature = try attestationSignature(grant: grant, key: keys.endpoint)
        let managerSignature = try attestationSignature(
            grant: grant,
            role: .manager,
            key: keys.manager
        )

        #expect(grant.verifiesPeerCertificateAttestation(
            certificatePEM: certificate,
            endpointNonceHex: Self.nonce,
            role: .endpoint,
            signature: endpointSignature,
            nowUnixSeconds: Self.now
        ))
        #expect(!grant.verifiesPeerCertificateAttestation(
            certificatePEM: certificate,
            endpointNonceHex: Self.nonce,
            role: .endpoint,
            signature: endpointSignature,
            nowUnixSeconds: grant.expiresAtUnix
        ))
        #expect(grant.verifiesPeerCertificateAttestation(
            certificatePEM: certificate,
            endpointNonceHex: Self.nonce,
            role: .manager,
            signature: managerSignature,
            nowUnixSeconds: Self.now
        ))
        #expect(!grant.verifiesPeerCertificateAttestation(
            certificatePEM: certificate,
            endpointNonceHex: Self.nonce,
            role: .endpoint,
            signature: managerSignature,
            nowUnixSeconds: Self.now
        ))

        #expect(throws: HelicoidError.self) {
            _ = try grant.peerCertificateAttestationMessage(
                certificatePEM: certificate,
                endpointNonceHex: Self.nonce,
                role: .endpoint,
                nowUnixSeconds: grant.expiresAtUnix
            )
        }
        #expect(throws: HelicoidError.self) {
            _ = try grant.peerCertificateAttestationMessage(
                certificatePEM: Data("not a certificate".utf8),
                endpointNonceHex: Self.nonce,
                role: .endpoint,
                nowUnixSeconds: Self.now
            )
        }
    }

    @Test("Rejects malformed or unsupported challenge claims")
    func rejectsMalformedChallenges() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let signature = try attestationSignature(grant: grant, key: keys.endpoint)
        let signatureHex = lowerHex(signature)
        let valid = try challengeJSON(signatureHex: signatureHex)

        let cases: [String] = [
            "",
            "[]",
            String(repeating: " ", count: 4 * 1024 + 1),
            "{\"computer_id\":\"\u{00E9}\"}",
            String(valid.dropLast()) + ",\"extra\":\"x\"}",
            String(valid.dropLast()) + ",\"computer_id\":\"\(Self.computerID)\"}",
            String(valid.dropLast()) + ",}",
            try challengeJSON(signatureHex: signatureHex, includeCertificate: false),
            try challengeJSON(
                signatureHex: signatureHex,
                includeCertificate: false,
                includeSignature: false
            ),
            try challengeJSON(signatureHex: signatureHex, certificateValue: NSNull()),
            try challengeJSON(signatureHex: signatureHex, includeSignature: false),
            try challengeJSON(signatureHex: signatureHex, expiresAtUnix: String(Self.now + 9)),
            try challengeJSON(signatureHex: signatureHex, expiresAtUnix: Double(Self.now + 9) + 0.5),
            try challengeJSON(signatureHex: signatureHex, certificateValue: "not a certificate"),
        ]

        for payload in cases {
            #expect(throws: HelicoidError.self) {
                _ = try ObservationEndpointChallengeVerifier.verify(
                    payload: payload,
                    grant: grant,
                    nowUnixSeconds: Self.now
                )
            }
        }
    }
}
