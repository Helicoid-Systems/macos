import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

/// Manager-side grant verification must bind only the signed server payload
/// to the current Manager session. Endpoint key, session, and epoch are read
/// from that payload and never supplied as unsigned endpoint claims.
@Suite("Manager observation admission")
struct ManagerObservationAdmissionTests {
    private static let now: Int64 = 1_700_000_000
    private static let deploymentID = "dep_" + String(repeating: "a", count: 32)
    private static let grantID = "b8eeedb7-1d8d-4c29-9e13-05ec6045a173"
    private static let accountID = "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d"
    private static let managerID = "7a01cf88-6fdb-4cc1-a72f-d155f5309355"
    private static let computerID = "6b7b0f41-8af7-4a09-90d0-91c9cd1c0dc9"
    private static let endpointSessionID = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1"

    private struct Keys {
        let server: Curve25519.Signing.PrivateKey
        let manager: Curve25519.Signing.PrivateKey
        let endpoint: Curve25519.Signing.PrivateKey
        let foreign: Curve25519.Signing.PrivateKey
    }

    private struct Payload {
        var version = 1
        var grantID = ManagerObservationAdmissionTests.grantID
        var deploymentID = ManagerObservationAdmissionTests.deploymentID
        var accountID = ManagerObservationAdmissionTests.accountID
        var managerID = ManagerObservationAdmissionTests.managerID
        var managerPublicKey: String
        var computerID = ManagerObservationAdmissionTests.computerID
        var endpointPublicKey: String
        var endpointSessionID = ManagerObservationAdmissionTests.endpointSessionID
        var enrollmentEpoch: Int64 = 1
        var issuedAtUnix = ManagerObservationAdmissionTests.now - 1
        var expiresAtUnix = ManagerObservationAdmissionTests.now + 9
        var capability = "observe"

        /// Canonical bytes, in the exact order the server signs.
        var data: Data {
            Data(
                "{\"version\":\(version),\"grant_id\":\"\(grantID)\",\"deployment_id\":\"\(deploymentID)\",\"account_id\":\"\(accountID)\",\"manager_id\":\"\(managerID)\",\"manager_public_key\":\"\(managerPublicKey)\",\"computer_id\":\"\(computerID)\",\"endpoint_public_key\":\"\(endpointPublicKey)\",\"endpoint_session_id\":\"\(endpointSessionID)\",\"enrollment_epoch\":\(enrollmentEpoch),\"issued_at_unix\":\(issuedAtUnix),\"expires_at_unix\":\(expiresAtUnix),\"capability\":\"\(capability)\"}".utf8
            )
        }
    }

    private func makeKeys() -> Keys {
        Keys(
            server: Curve25519.Signing.PrivateKey(),
            manager: Curve25519.Signing.PrivateKey(),
            endpoint: Curve25519.Signing.PrivateKey(),
            foreign: Curve25519.Signing.PrivateKey()
        )
    }

    private func makePayload(_ keys: Keys) -> Payload {
        Payload(
            managerPublicKey: lowerHex(keys.manager.publicKey.rawRepresentation),
            endpointPublicKey: lowerHex(keys.endpoint.publicKey.rawRepresentation)
        )
    }

    private func makeExpectation(_ keys: Keys) -> ObservationAdmissionManagerExpectation {
        ObservationAdmissionManagerExpectation(
            deploymentID: Self.deploymentID,
            accountID: Self.accountID,
            computerID: Self.computerID,
            managerID: Self.managerID,
            managerPublicKeyHex: lowerHex(keys.manager.publicKey.rawRepresentation)
        )
    }

    private func token(payload: Data, signedBy key: Curve25519.Signing.PrivateKey) throws -> String {
        let signed = Data("hs-observation-grant-v1\0".utf8) + payload
        let signature = try key.signature(for: signed)
        return base64URL(payload) + "." + lowerHex(signature)
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

    private func expectRejected(
        _ token: String,
        serverPublicKey: Curve25519.Signing.PrivateKey,
        expectation: ObservationAdmissionManagerExpectation
    ) {
        #expect(throws: HelicoidError.self) {
            try ObservationAdmissionGrantVerifier.verifyForManager(
                token: token,
                serverPublicKeyHex: lowerHex(serverPublicKey.publicKey.rawRepresentation),
                expected: expectation,
                nowUnixSeconds: Self.now
            )
        }
    }

    @Test("Verifies a manager-bound grant and leaves endpoint verification intact")
    func verifiesManagerGrant() throws {
        let keys = makeKeys()
        let payload = makePayload(keys)
        let token = try token(payload: payload.data, signedBy: keys.server)
        let verified = try ObservationAdmissionGrantVerifier.verifyForManager(
            token: token,
            serverPublicKeyHex: lowerHex(keys.server.publicKey.rawRepresentation),
            expected: makeExpectation(keys),
            nowUnixSeconds: Self.now
        )

        #expect(verified.grantID == Self.grantID)
        #expect(verified.deploymentID == Self.deploymentID)
        #expect(verified.accountID == Self.accountID)
        #expect(verified.managerID == Self.managerID)
        #expect(verified.managerPublicKeyHex == lowerHex(keys.manager.publicKey.rawRepresentation))
        #expect(verified.computerID == Self.computerID)
        #expect(verified.endpointPublicKeyHex == lowerHex(keys.endpoint.publicKey.rawRepresentation))
        #expect(verified.endpointSessionID == Self.endpointSessionID)
        #expect(verified.enrollmentEpoch == 1)
        #expect(verified.issuedAtUnix == payload.issuedAtUnix)
        #expect(verified.expiresAtUnix == payload.expiresAtUnix)

        // The unchanged endpoint verifier accepts the same canonical token.
        let endpointVerified = try ObservationAdmissionGrantVerifier.verify(
            token: token,
            serverPublicKeyHex: lowerHex(keys.server.publicKey.rawRepresentation),
            expected: ObservationAdmissionEndpoint(
                deploymentID: Self.deploymentID,
                computerID: Self.computerID,
                endpointPublicKeyHex: payload.endpointPublicKey,
                endpointSessionID: Self.endpointSessionID,
                enrollmentEpoch: 1
            ),
            nowUnixSeconds: Self.now
        )
        #expect(endpointVerified.grantID == Self.grantID)
    }

    @Test("Rejects grants bound to another deployment, account, computer, or manager")
    func rejectsCrossBinding() throws {
        let keys = makeKeys()
        let base = makePayload(keys)

        var otherDeployment = base
        otherDeployment.deploymentID = "dep_" + String(repeating: "b", count: 32)
        expectRejected(
            try token(payload: otherDeployment.data, signedBy: keys.server),
            serverPublicKey: keys.server,
            expectation: makeExpectation(keys)
        )

        var otherAccount = base
        otherAccount.accountID = "11111111-1111-4111-8111-111111111111"
        expectRejected(
            try token(payload: otherAccount.data, signedBy: keys.server),
            serverPublicKey: keys.server,
            expectation: makeExpectation(keys)
        )

        var otherComputer = base
        otherComputer.computerID = "22222222-2222-4222-8222-222222222222"
        expectRejected(
            try token(payload: otherComputer.data, signedBy: keys.server),
            serverPublicKey: keys.server,
            expectation: makeExpectation(keys)
        )

        var otherManager = base
        otherManager.managerID = "33333333-3333-4333-8333-333333333333"
        expectRejected(
            try token(payload: otherManager.data, signedBy: keys.server),
            serverPublicKey: keys.server,
            expectation: makeExpectation(keys)
        )
    }

    @Test("Rejects another signing key or another active manager key")
    func rejectsCrossKey() throws {
        let keys = makeKeys()
        let payload = makePayload(keys)

        // Signed by a key other than the pinned deployment grant key.
        expectRejected(
            try token(payload: payload.data, signedBy: keys.foreign),
            serverPublicKey: keys.server,
            expectation: makeExpectation(keys)
        )

        // Signed correctly, but the grant names a different manager key.
        var otherManagerKey = payload
        otherManagerKey.managerPublicKey = lowerHex(keys.foreign.publicKey.rawRepresentation)
        expectRejected(
            try token(payload: otherManagerKey.data, signedBy: keys.server),
            serverPublicKey: keys.server,
            expectation: makeExpectation(keys)
        )
    }

    @Test("Rejects expired, stale, future-dated, and overlong grants")
    func rejectsTimeBounds() throws {
        let keys = makeKeys()

        var expired = makePayload(keys)
        expired.issuedAtUnix = Self.now - 10
        expired.expiresAtUnix = Self.now
        expectRejected(
            try token(payload: expired.data, signedBy: keys.server),
            serverPublicKey: keys.server,
            expectation: makeExpectation(keys)
        )

        var future = makePayload(keys)
        future.issuedAtUnix = Self.now + 6
        future.expiresAtUnix = Self.now + 10
        expectRejected(
            try token(payload: future.data, signedBy: keys.server),
            serverPublicKey: keys.server,
            expectation: makeExpectation(keys)
        )

        var overlong = makePayload(keys)
        overlong.issuedAtUnix = Self.now - 1
        overlong.expiresAtUnix = Self.now + 10
        expectRejected(
            try token(payload: overlong.data, signedBy: keys.server),
            serverPublicKey: keys.server,
            expectation: makeExpectation(keys)
        )
    }

    @Test("Accepts the maximum documented future clock skew")
    func acceptsMaximumFutureSkew() throws {
        let keys = makeKeys()
        var payload = makePayload(keys)
        payload.issuedAtUnix = Self.now + 5
        payload.expiresAtUnix = Self.now + 9

        let verified = try ObservationAdmissionGrantVerifier.verifyForManager(
            token: try token(payload: payload.data, signedBy: keys.server),
            serverPublicKeyHex: lowerHex(keys.server.publicKey.rawRepresentation),
            expected: makeExpectation(keys),
            nowUnixSeconds: Self.now
        )
        #expect(verified.issuedAtUnix == Self.now + 5)
        #expect(verified.expiresAtUnix == Self.now + 9)
    }

    @Test("Rejects oversize and non-ASCII tokens and payloads")
    func rejectsOversizeAndNonASCII() throws {
        let keys = makeKeys()
        let payload = makePayload(keys)
        let valid = try token(payload: payload.data, signedBy: keys.server)
        let expected = makeExpectation(keys)

        expectRejected(
            valid + String(repeating: "a", count: 8 * 1024),
            serverPublicKey: keys.server,
            expectation: expected
        )
        expectRejected(
            valid + "\u{00E9}",
            serverPublicKey: keys.server,
            expectation: expected
        )

        // Oversized signed payload, while the overall token remains under the
        // token limit.
        let oversizePayload = Data(repeating: 0x61, count: 4 * 1024 + 1)
        expectRejected(
            try token(payload: oversizePayload, signedBy: keys.server),
            serverPublicKey: keys.server,
            expectation: expected
        )

        // Signed but non-ASCII claim text is not canonical.
        let nonASCIIPayload = Data(
            String(decoding: payload.data, as: UTF8.self)
                .replacingOccurrences(of: Self.accountID, with: "\u{00E9}")
                .utf8
        )
        expectRejected(
            try token(payload: nonASCIIPayload, signedBy: keys.server),
            serverPublicKey: keys.server,
            expectation: expected
        )
    }

    @Test("Rejects malformed token encodings and payload shapes")
    func rejectsMalformedGrants() throws {
        let keys = makeKeys()
        let payload = makePayload(keys)
        let valid = try token(payload: payload.data, signedBy: keys.server)
        let expected = makeExpectation(keys)
        let serverKey = lowerHex(keys.server.publicKey.rawRepresentation)

        let malformedTokens: [String] = [
            "",
            "no-separator",
            valid + ".00",
            valid.replacingOccurrences(of: ".", with: ""),
            valid + "=",
            base64URL(payload.data) + "." + String(repeating: "0", count: 127),
            base64URL(payload.data) + ".zz" + String(repeating: "0", count: 62),
        ]
        for token in malformedTokens {
            #expect(throws: HelicoidError.self) {
                try ObservationAdmissionGrantVerifier.verifyForManager(
                    token: token,
                    serverPublicKeyHex: serverKey,
                    expected: expected,
                    nowUnixSeconds: Self.now
                )
            }
        }

        // Signed but noncanonical or unsupported payloads must still fail.
        let canonical = String(decoding: payload.data, as: UTF8.self)
        let duplicateKey = canonical.replacingOccurrences(
            of: "\"version\":1,",
            with: "\"version\":1,\"grant_id\":\"\(Self.grantID)\","
        )
        let reorderedKeys = canonical
            .replacingOccurrences(of: ",\"capability\":\"observe\"}", with: "}")
            .replacingOccurrences(
                of: "{\"version\":1,",
                with: "{\"capability\":\"observe\",\"version\":1,"
            )
        let malformedPayloads: [Data] = [
            Data(duplicateKey.utf8),
            Data(reorderedKeys.utf8),
            Data((" " + canonical).utf8),
            Data((canonical + " ").utf8),
            Data(canonical.replacingOccurrences(of: "\"version\":1", with: "\"version\":2").utf8),
            Data(canonical.replacingOccurrences(of: "\"capability\":\"observe\"", with: "\"capability\":\"view\"").utf8),
            Data(canonical.replacingOccurrences(of: "\"enrollment_epoch\":1", with: "\"enrollment_epoch\":0").utf8),
            Data(canonical.replacingOccurrences(of: Self.accountID, with: Self.accountID.uppercased()).utf8),
            Data(canonical.replacingOccurrences(of: payload.endpointPublicKey, with: payload.endpointPublicKey.uppercased()).utf8),
            Data(canonical.replacingOccurrences(of: ",\"capability\":\"observe\"", with: "").utf8),
            Data(canonical.replacingOccurrences(of: "\"capability\":\"observe\"", with: "\"capability\":\"observe\",\"extra\":true").utf8),
            Data("not json".utf8),
        ]
        for malformed in malformedPayloads {
            let signed = try token(payload: malformed, signedBy: keys.server)
            expectRejected(signed, serverPublicKey: keys.server, expectation: expected)
        }
    }
}
