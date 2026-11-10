import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

/// Relayed signaling values are unsigned JSON. The Manager may trust only an
/// endpoint challenge whose envelope says `sender: endpoint`, `kind: challenge`
/// and whose payload matches the verified grant and attested endpoint
/// certificate. Post-admission values must also come from the endpoint.
@Suite("Manager observation signaling")
struct ManagerObservationSignalingTests {
    private static let now: Int64 = 1_700_000_000
    private static let deploymentID = "dep_" + String(repeating: "a", count: 32)
    private static let grantID = "b8eeedb7-1d8d-4c29-9e13-05ec6045a173"
    private static let accountID = "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d"
    private static let managerID = "7a01cf88-6fdb-4cc1-a72f-d155f5309355"
    private static let computerID = "6b7b0f41-8af7-4a09-90d0-91c9cd1c0dc9"
    private static let endpointSessionID = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1"
    private static let nonce = String(repeating: "4", count: 64)
    private static let certificatePEM =
        "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n"

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

    private func makeGrant(_ keys: Keys) throws -> VerifiedObservationAdmissionGrant {
        let managerPublicKey = lowerHex(keys.manager.publicKey.rawRepresentation)
        let endpointPublicKey = lowerHex(keys.endpoint.publicKey.rawRepresentation)
        let payload = "{\"version\":1,\"grant_id\":\"\(Self.grantID)\",\"deployment_id\":\"\(Self.deploymentID)\",\"account_id\":\"\(Self.accountID)\",\"manager_id\":\"\(Self.managerID)\",\"manager_public_key\":\"\(managerPublicKey)\",\"computer_id\":\"\(Self.computerID)\",\"endpoint_public_key\":\"\(endpointPublicKey)\",\"endpoint_session_id\":\"\(Self.endpointSessionID)\",\"enrollment_epoch\":1,\"issued_at_unix\":\(Self.now - 1),\"expires_at_unix\":\(Self.now + 9),\"capability\":\"observe\"}"
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
            nowUnixSeconds: Self.now
        )
    }

    private func token(payload: Data, signedBy key: Curve25519.Signing.PrivateKey) throws -> String {
        let signed = Data("hs-observation-grant-v1\0".utf8) + payload
        let signature = try key.signature(for: signed)
        return base64URL(payload) + "." + lowerHex(signature)
    }

    private func challengePayload(
        grant: VerifiedObservationAdmissionGrant,
        signature: Data,
        certificatePEM: String = ManagerObservationSignalingTests.certificatePEM,
        nonce: String = ManagerObservationSignalingTests.nonce
    ) throws -> String {
        let object: [String: Any] = [
            "computer_id": Self.computerID,
            "endpoint_session_id": Self.endpointSessionID,
            "endpoint_nonce": nonce,
            "expires_at_unix": Self.now + 9,
            "endpoint_certificate_pem": certificatePEM,
            "endpoint_certificate_signature": lowerHex(signature),
        ]
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private func attestationSignature(
        grant: VerifiedObservationAdmissionGrant,
        certificatePEM: String = ManagerObservationSignalingTests.certificatePEM,
        nonce: String = ManagerObservationSignalingTests.nonce,
        key: Curve25519.Signing.PrivateKey
    ) throws -> Data {
        let message = try grant.peerCertificateAttestationMessage(
            certificatePEM: Data(certificatePEM.utf8),
            endpointNonceHex: nonce,
            role: .endpoint,
            nowUnixSeconds: Self.now
        )
        return try key.signature(for: message)
    }

    private typealias Signal = (UInt64, String, String, String)

    private func batch(cursor: UInt64, messages: [Signal]) throws -> Data {
        let encodedMessages: [[String: Any]] = messages.map { message in
            [
                "sequence": message.0,
                "sender": message.1,
                "kind": message.2,
                "payload": message.3,
            ]
        }
        let object: [String: Any] = ["cursor": cursor, "messages": encodedMessages]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private func verifiedChallengeSession(
        _ keys: Keys
    ) throws -> (ManagerObservationSignalingSession, VerifiedObservationEndpointChallenge) {
        let grant = try makeGrant(keys)
        let signature = try attestationSignature(grant: grant, key: keys.endpoint)
        let payload = try challengePayload(grant: grant, signature: signature)
        var session = ManagerObservationSignalingSession(grant: grant)
        let verified = try session.acceptChallengeBatch(
            batch(cursor: 1, messages: [(1, "endpoint", "challenge", payload)]),
            nowUnixSeconds: Self.now
        )
        let challenge = try #require(verified)
        return (session, challenge)
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

    @Test("Accepts only an endpoint challenge and returns the attested certificate")
    func acceptsEndpointChallenge() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let signature = try attestationSignature(grant: grant, key: keys.endpoint)
        let payload = try challengePayload(grant: grant, signature: signature)
        var session = ManagerObservationSignalingSession(grant: grant)

        let challenge = try session.acceptChallengeBatch(
            batch(cursor: 1, messages: [(1, "endpoint", "challenge", payload)]),
            nowUnixSeconds: Self.now
        )

        #expect(challenge?.computerID == Self.computerID)
        #expect(challenge?.endpointSessionID == Self.endpointSessionID)
        #expect(challenge?.endpointNonceHex == Self.nonce)
        #expect(challenge?.endpointCertificatePEM == Data(Self.certificatePEM.utf8))
        #expect(session.phase == .awaitingAnswer)
        #expect(session.cursor == 1)
        #expect(session.challenge == challenge)
        #expect(!session.hasRemoteAnswer)
    }

    @Test("Accepts a terminal endpoint close before the first challenge")
    func acceptsCloseInInitialPhase() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        var session = ManagerObservationSignalingSession(grant: grant)

        let challenge = try session.acceptChallengeBatch(
            batch(cursor: 1, messages: [(1, "endpoint", "close", "")]),
            nowUnixSeconds: Self.now
        )

        #expect(challenge == nil)
        #expect(session.phase == .closed)
        #expect(session.cursor == 1)
        #expect(session.challenge == nil)
    }

    @Test("A challenge followed by close in the same batch yields no usable challenge")
    func challengeThenCloseReturnsNil() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let signature = try attestationSignature(grant: grant, key: keys.endpoint)
        let payload = try challengePayload(grant: grant, signature: signature)
        var session = ManagerObservationSignalingSession(grant: grant)

        let challenge = try session.acceptChallengeBatch(
            batch(cursor: 2, messages: [
                (1, "endpoint", "challenge", payload),
                (2, "endpoint", "close", ""),
            ]),
            nowUnixSeconds: Self.now
        )

        #expect(challenge == nil)
        #expect(session.phase == .closed)
        #expect(session.cursor == 2)
        #expect(session.challenge == nil)
    }

    @Test("Accepts a legal server batch whose JSON escaping exceeds the raw mailbox limit")
    func acceptsBoundedEscapedServerBatch() throws {
        let payload = String(repeating: "\"", count: 4_096)
        let messages: [Signal] = (1...64).map { sequence in
            (UInt64(sequence), "endpoint", "ice", payload)
        }
        let data = try batch(cursor: 64, messages: messages)

        #expect(data.count > 256 * 1024)
        #expect(data.count <= ManagerObservationSignalingSession.maximumBatchBytes)
        let decoded = try ManagerObservationSignalingSession.decodeBatch(data)
        #expect(decoded.cursor == 64)
        #expect(decoded.messages.count == 64)

        #expect(throws: HelicoidError.self) {
            _ = try ManagerObservationSignalingSession.decodeBatch(
                Data(repeating: 0x61, count: ManagerObservationSignalingSession.maximumBatchBytes + 1)
            )
        }
    }

    @Test("Accepts valid UTF-8 SDP and ICE payloads from the server")
    func acceptsUTF8SignalPayloads() throws {
        let keys = makeKeys()
        let (session, _) = try verifiedChallengeSession(keys)
        var mutableSession = session

        let answer = "v=0\r\na=fmtp:1 label=Grüße 日本\r\n"
        let ice = "candidate:1 1 UDP 1 127.0.0.1 5000 typ host ü"
        let updates = try mutableSession.acceptNegotiationBatch(
            batch(cursor: 4, messages: [
                (3, "endpoint", "answer", answer),
                (4, "endpoint", "ice", ice),
            ]),
            nowUnixSeconds: Self.now
        )

        #expect(updates.map(\.payload) == [answer, ice])
        #expect(mutableSession.phase == .negotiating)
    }

    @Test("Malformed endpoint signals are protocol errors, not authentication failures")
    func malformedSignalIsProtocolError() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let signature = try attestationSignature(grant: grant, key: keys.endpoint)
        let payload = try challengePayload(grant: grant, signature: signature)
        let unattested = String(decoding: try JSONSerialization.data(withJSONObject: [
            "computer_id": Self.computerID,
            "endpoint_session_id": Self.endpointSessionID,
            "endpoint_nonce": Self.nonce,
            "expires_at_unix": Self.now + 9,
        ], options: [.sortedKeys]), as: UTF8.self)
        let cases: [(String, String, String)] = [
            ("manager", "challenge", payload),
            ("endpoint", "challenge", unattested),
        ]

        for (sender, kind, candidate) in cases {
            var session = ManagerObservationSignalingSession(grant: grant)
            do {
                _ = try session.acceptChallengeBatch(
                    batch(cursor: 1, messages: [(1, sender, kind, candidate)]),
                    nowUnixSeconds: Self.now
                )
                Issue.record("malformed endpoint signaling must be rejected")
            } catch let error as HelicoidError {
                guard case .observationProtocolViolation = error else {
                    Issue.record("expected observationProtocolViolation, got \(error)")
                    continue
                }
            }
            #expect(session.phase == .awaitingChallenge)
            #expect(session.cursor == 0)
        }
    }

    @Test("Rejects challenge envelopes from another sender or with another kind")
    func rejectsWrongSenderAndKind() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let signature = try attestationSignature(grant: grant, key: keys.endpoint)
        let payload = try challengePayload(grant: grant, signature: signature)
        let cases: [(String, String)] = [
            ("manager", "challenge"),
            ("server", "challenge"),
            ("endpoint", "offer"),
            ("endpoint", "answer"),
            ("endpoint", "ice"),
        ]

        for (sender, kind) in cases {
            var session = ManagerObservationSignalingSession(grant: grant)
            #expect(throws: HelicoidError.self) {
                _ = try session.acceptChallengeBatch(
                    batch(cursor: 1, messages: [(1, sender, kind, payload)]),
                    nowUnixSeconds: Self.now
                )
            }
            #expect(session.phase == .awaitingChallenge)
            #expect(session.cursor == 0)
            #expect(session.challenge == nil)
        }
    }

    @Test("Rejects a challenge without certificate attestation or with a foreign certificate signature")
    func rejectsUnattestedCertificate() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let signature = try attestationSignature(grant: grant, key: keys.endpoint)

        let unattested = try JSONSerialization.data(withJSONObject: [
            "computer_id": Self.computerID,
            "endpoint_session_id": Self.endpointSessionID,
            "endpoint_nonce": Self.nonce,
            "expires_at_unix": Self.now + 9,
        ], options: [.sortedKeys])
        let foreignSignature = try attestationSignature(grant: grant, key: keys.foreign)

        for payload in [
            String(decoding: unattested, as: UTF8.self),
            try challengePayload(grant: grant, signature: foreignSignature),
        ] {
            var session = ManagerObservationSignalingSession(grant: grant)
            #expect(throws: HelicoidError.self) {
                _ = try session.acceptChallengeBatch(
                    batch(cursor: 1, messages: [(1, "endpoint", "challenge", payload)]),
                    nowUnixSeconds: Self.now
                )
            }
            #expect(session.phase == .awaitingChallenge)
        }

        // The valid attestation remains accepted, proving the failure above is
        // the certificate check and not a broken fixture.
        let validPayload = try challengePayload(grant: grant, signature: signature)
        var session = ManagerObservationSignalingSession(grant: grant)
        let accepted = try session.acceptChallengeBatch(
            batch(cursor: 1, messages: [(1, "endpoint", "challenge", validPayload)]),
            nowUnixSeconds: Self.now
        )
        #expect(accepted != nil)
    }

    @Test("Rejects malformed, oversized, and out-of-order signal batches")
    func rejectsMalformedBatches() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        let signature = try attestationSignature(grant: grant, key: keys.endpoint)
        let payload = try challengePayload(grant: grant, signature: signature)

        let invalidBatches: [Data] = [
            Data(),
            Data("{}".utf8),
            Data("[]".utf8),
            try JSONSerialization.data(withJSONObject: [
                "cursor": true, "messages": [],
            ]),
            try JSONSerialization.data(withJSONObject: [
                "cursor": 129, "messages": [],
            ]),
            try JSONSerialization.data(withJSONObject: [
                "cursor": 1, "messages": [],
                "extra": true,
            ]),
            try JSONSerialization.data(withJSONObject: [
                "cursor": 1,
                "messages": [[
                    "sequence": 1,
                    "sender": "endpoint",
                    "kind": "challenge",
                    "payload": payload,
                    "extra": true,
                ]],
            ]),
            try JSONSerialization.data(withJSONObject: [
                "cursor": 1,
                "messages": [[
                    "sequence": 0,
                    "sender": "endpoint",
                    "kind": "challenge",
                    "payload": payload,
                ]],
            ]),
            try JSONSerialization.data(withJSONObject: [
                "cursor": 2,
                "messages": [[
                    "sequence": 3,
                    "sender": "endpoint",
                    "kind": "challenge",
                    "payload": payload,
                ]],
            ]),
        ]

        for data in invalidBatches {
            var session = ManagerObservationSignalingSession(grant: grant)
            #expect(throws: HelicoidError.self) {
                _ = try session.acceptChallengeBatch(data, nowUnixSeconds: Self.now)
            }
            #expect(session.phase == .awaitingChallenge)
        }

        let tooManyMessages = (1...65).map { sequence in
            [
                "sequence": sequence,
                "sender": "endpoint",
                "kind": "challenge",
                "payload": payload,
            ] as [String: Any]
        }
        let oversizedBatch = try JSONSerialization.data(withJSONObject: [
            "cursor": 65, "messages": tooManyMessages,
        ])
        var session = ManagerObservationSignalingSession(grant: grant)
        #expect(throws: HelicoidError.self) {
            _ = try session.acceptChallengeBatch(oversizedBatch, nowUnixSeconds: Self.now)
        }
    }

    @Test("Accepts endpoint answer and ICE only after the verified challenge")
    func acceptsNegotiationAfterChallenge() throws {
        let keys = makeKeys()
        let (session, _) = try verifiedChallengeSession(keys)
        var mutableSession = session

        let updates = try mutableSession.acceptNegotiationBatch(
            batch(cursor: 4, messages: [
                (3, "endpoint", "answer", "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n"),
                (4, "endpoint", "ice", "candidate:1 1 UDP 1 127.0.0.1 5000 typ host"),
            ]),
            nowUnixSeconds: Self.now
        )

        #expect(updates.map(\.kind) == [.answer, .ice])
        #expect(updates.map(\.sequence) == [3, 4])
        #expect(mutableSession.phase == .negotiating)
        #expect(mutableSession.hasRemoteAnswer)
        #expect(mutableSession.cursor == 4)
    }

    @Test("Rejects a second answer, relayed offers, repeated challenges, and non-endpoint senders")
    func rejectsInvalidNegotiationSignals() throws {
        let keys = makeKeys()
        let (session, _) = try verifiedChallengeSession(keys)
        var mutableSession = session
        _ = try mutableSession.acceptNegotiationBatch(
            batch(cursor: 3, messages: [
                (3, "endpoint", "answer", "v=0\r\n"),
            ]),
            nowUnixSeconds: Self.now
        )

        let cases: [(String, String, String)] = [
            ("endpoint", "answer", "v=0\r\n"),
            ("endpoint", "offer", "v=0\r\n"),
            ("endpoint", "challenge", "{}"),
            ("manager", "answer", "v=0\r\n"),
            ("manager", "ice", "candidate:1"),
            ("manager", "close", ""),
        ]
        for (sender, kind, payload) in cases {
            #expect(throws: HelicoidError.self) {
                _ = try mutableSession.acceptNegotiationBatch(
                    batch(cursor: 4, messages: [(4, sender, kind, payload)]),
                    nowUnixSeconds: Self.now
                )
            }
            #expect(mutableSession.phase == .negotiating)
            #expect(mutableSession.cursor == 3)
        }
    }

    @Test("Rejects answer, ICE, and close payloads outside their contract bounds")
    func rejectsInvalidNegotiationPayloads() throws {
        let keys = makeKeys()
        let (session, _) = try verifiedChallengeSession(keys)
        var mutableSession = session

        let invalid: [(String, String)] = [
            ("answer", ""),
            ("answer", "not-sdp"),
            ("answer", "v=0\u{0000}"),
            ("answer", "v=0\u{0007}"),
            ("answer", "v=0\u{007F}"),
            ("answer", "v=0" + String(
                repeating: "a",
                count: Int(ManagerObservationSignalingSession.maximumAnswerBytes)
            )),
            ("ice", ""),
            ("ice", String(repeating: "a", count: 4_097)),
            ("ice", "candidate:1\u{0000}"),
            ("close", "not-empty"),
        ]
        for (kind, payload) in invalid {
            #expect(throws: HelicoidError.self) {
                _ = try mutableSession.acceptNegotiationBatch(
                    batch(cursor: 4, messages: [(4, "endpoint", kind, payload)]),
                    nowUnixSeconds: Self.now
                )
            }
            #expect(mutableSession.phase == .awaitingAnswer)
            #expect(mutableSession.cursor == 1)
        }
    }

    @Test("Close is terminal and a batch may not continue after close")
    func closeIsTerminal() throws {
        let keys = makeKeys()
        let (session, _) = try verifiedChallengeSession(keys)
        var mutableSession = session

        let closed = try mutableSession.acceptNegotiationBatch(
            batch(cursor: 2, messages: [(2, "endpoint", "close", "")]),
            nowUnixSeconds: Self.now
        )
        #expect(closed.map(\.kind) == [.close])
        #expect(mutableSession.phase == .closed)

        #expect(throws: HelicoidError.self) {
            _ = try mutableSession.acceptNegotiationBatch(
                batch(cursor: 3, messages: [(3, "endpoint", "ice", "candidate:1")]),
                nowUnixSeconds: Self.now
            )
        }

        var stillNegotiating = session
        #expect(throws: HelicoidError.self) {
            _ = try stillNegotiating.acceptNegotiationBatch(
                batch(cursor: 3, messages: [
                    (2, "endpoint", "close", ""),
                    (3, "endpoint", "ice", "candidate:1"),
                ]),
                nowUnixSeconds: Self.now
            )
        }
        #expect(stillNegotiating.phase == .awaitingAnswer)
        #expect(stillNegotiating.cursor == 1)
    }

    @Test("Rejects negotiation after the short observation grant expires")
    func rejectsExpiredGrant() throws {
        let keys = makeKeys()
        let (session, _) = try verifiedChallengeSession(keys)
        var mutableSession = session

        #expect(throws: HelicoidError.self) {
            _ = try mutableSession.acceptNegotiationBatch(
                batch(cursor: 3, messages: [(3, "endpoint", "answer", "v=0\r\n")]),
                nowUnixSeconds: session.grant.expiresAtUnix
            )
        }
        #expect(mutableSession.phase == .awaitingAnswer)
        #expect(mutableSession.cursor == 1)
    }

    @Test("An empty challenge poll advances the cursor without admitting a peer")
    func emptyChallengePollAdvancesCursor() throws {
        let keys = makeKeys()
        let grant = try makeGrant(keys)
        var session = ManagerObservationSignalingSession(grant: grant)

        let challenge = try session.acceptChallengeBatch(
            batch(cursor: 0, messages: []),
            nowUnixSeconds: Self.now
        )
        #expect(challenge == nil)
        #expect(session.phase == .awaitingChallenge)
        #expect(session.cursor == 0)

        #expect(throws: HelicoidError.self) {
            _ = try session.acceptNegotiationBatch(
                batch(cursor: 1, messages: [(1, "endpoint", "answer", "v=0\r\n")]),
                nowUnixSeconds: Self.now
            )
        }
    }
}
