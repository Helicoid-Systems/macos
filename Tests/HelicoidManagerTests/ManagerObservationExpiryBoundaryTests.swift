import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

/// The signed grant is live strictly before `expires_at_unix` and invalid at
/// the exact expiry second.
@Suite("Manager observation grant expiry boundary")
struct ManagerObservationExpiryBoundaryTests {
    private static let now: Int64 = 1_800_000_000
    private static let deploymentID = "dep_" + String(repeating: "a", count: 32)
    private static let grantID = "b8eeedb7-1d8d-4c29-9e13-05ec6045a173"
    private static let accountID = "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d"
    private static let managerID = "7a01cf88-6fdb-4cc1-a72f-d155f5309355"
    private static let computerID = "6b7b0f41-8af7-4a09-90d0-91c9cd1c0dc9"
    private static let endpointSessionID = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1"

    private struct Fixture {
        let token: String
        let serverPublicKey: String
        let managerPublicKey: String
    }

    private func lowerHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private func makeFixture() throws -> Fixture {
        let server = Curve25519.Signing.PrivateKey()
        let manager = Curve25519.Signing.PrivateKey()
        let endpoint = Curve25519.Signing.PrivateKey()
        let managerPublicKey = lowerHex(manager.publicKey.rawRepresentation)
        let payload = Data(
            "{\"version\":1,\"grant_id\":\"\(Self.grantID)\",\"deployment_id\":\"\(Self.deploymentID)\",\"account_id\":\"\(Self.accountID)\",\"manager_id\":\"\(Self.managerID)\",\"manager_public_key\":\"\(managerPublicKey)\",\"computer_id\":\"\(Self.computerID)\",\"endpoint_public_key\":\"\(lowerHex(endpoint.publicKey.rawRepresentation))\",\"endpoint_session_id\":\"\(Self.endpointSessionID)\",\"enrollment_epoch\":1,\"issued_at_unix\":\(Self.now - 9),\"expires_at_unix\":\(Self.now + 1),\"capability\":\"observe\"}".utf8
        )
        let signature = try server.signature(
            for: Data("hs-observation-grant-v1\0".utf8) + payload
        )
        let token = payload.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            + "." + lowerHex(signature)
        return Fixture(
            token: token,
            serverPublicKey: lowerHex(server.publicKey.rawRepresentation),
            managerPublicKey: managerPublicKey
        )
    }

    @Test("Accepts one second before expiry and rejects the exact expiry second")
    func exactExpiryBoundary() throws {
        let fixture = try makeFixture()
        let expectation = ObservationAdmissionManagerExpectation(
            deploymentID: Self.deploymentID,
            accountID: Self.accountID,
            computerID: Self.computerID,
            managerID: Self.managerID,
            managerPublicKeyHex: fixture.managerPublicKey
        )
        _ = try ObservationAdmissionGrantVerifier.verifyForManager(
            token: fixture.token,
            serverPublicKeyHex: fixture.serverPublicKey,
            expected: expectation,
            nowUnixSeconds: Self.now
        )
        #expect(throws: HelicoidError.self) {
            _ = try ObservationAdmissionGrantVerifier.verifyForManager(
                token: fixture.token,
                serverPublicKeyHex: fixture.serverPublicKey,
                expected: expectation,
                nowUnixSeconds: Self.now + 1
            )
        }
    }
}
