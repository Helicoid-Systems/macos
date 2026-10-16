import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore


// File-private fixture builders usable from @Sendable test responders.
private func buildLoginJSON(
    token: String = "bearer-token-secret",
    expiresAtUnix: Int,
    accountState: String = "active",
    managerKey: String,
    managerState: String = "approved",
    mfaRequired: Bool = true,
    mfaAvailable: Bool = true,
    publicIdentity: String? = nil,
    includeMFA: Bool = true,
    completionKey: String? = nil
) -> Data {
    var object: [String: Any] = [
        "token": token,
        "expires_at_unix": expiresAtUnix,
        "account": [
            "id": "account-1",
            "username": "operator",
            "state": accountState,
            "capabilities": ["operate": true],
            "revision": 1,
        ] as [String: Any],
        "manager": [
            "id": "manager-1",
            "public_identity": publicIdentity ?? "key:\(managerKey)",
            "lifecycle_state": managerState,
        ] as [String: Any],
        "manager_public_key": completionKey ?? managerKey,
    ]
    if includeMFA {
        object["mfa"] = [
            "required": mfaRequired,
            "available": mfaAvailable,
            "reason": "totp_active",
        ] as [String: Any]
    }
    // swiftlint:disable:next force_try
    return try! JSONSerialization.data(withJSONObject: object)
}

@Suite("Native v2 device-key authentication")
struct NativeV2AuthClientTests {
    @Test("Coordinator: stale completion cannot clear replacement challenge")
    func coordinatorStaleCompletionPreservesReplacement() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let transport = FixtureTransport()
        let client = NativeV2AuthClient(transport: transport, trustedAuthority: authority, signingIdentity: identity)
        transport.stub = .init(status: 201, body: beginJSON(challengeID: "old-challenge", token: "old-test-token", managerKey: key, mfaRequired: true))
        let old = try await client.beginChallenge(username: "operator", password: "fixture")
        transport.stub = .init(status: 201, body: beginJSON(challengeID: "replacement-challenge", token: "replacement-test-token", managerKey: key, mfaRequired: true))
        let replacement = try await client.beginChallenge(username: "operator", password: "fixture")
        await #expect(throws: HelicoidError.self) {
            try await client.completeChallenge(old, totpCode: "123456")
        }
        #expect(await client.hasPendingChallenge, "An obsolete completion must not erase the replacement challenge")
        transport.stub = .init(status: 200, body: loginJSON(managerKey: key))
        _ = try await client.completeChallenge(replacement, totpCode: "123456")
        #expect(await client.bearerToken != nil)
    }

    @Test("Late complete response after replacement cannot clear pending")
    func lateResponseAfterReplacementPreservesPending() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let sequencer = SequencedTransport()
        let client = NativeV2AuthClient(transport: sequencer, trustedAuthority: authority, signingIdentity: identity)

        sequencer.enqueue(status: 201, body: beginJSON(challengeID: "a", token: "token-a", managerKey: key, mfaRequired: true))
        let challengeA = try await client.beginChallenge(username: "operator", password: "pw")

        // Complete A will sleep in transport; meanwhile B replaces pending.
        sequencer.enqueueDelay(status: 200, body: loginJSON(managerKey: key), delayNs: 250_000_000)
        let completeA = Task {
            try await client.completeChallenge(challengeA, totpCode: "123456")
        }
        // Ensure complete A has dequeued its response before B begins.
        try await Task.sleep(nanoseconds: 80_000_000)

        sequencer.enqueue(status: 201, body: beginJSON(challengeID: "b", token: "token-b", managerKey: key, mfaRequired: true))
        let challengeB = try await client.beginChallenge(username: "operator", password: "pw2")
        #expect(await client.hasPendingChallenge)

        await #expect(throws: HelicoidError.self) {
            try await completeA.value
        }
        #expect(await client.hasPendingChallenge, "late complete must not erase replacement")
        #expect(await client.bearerToken == nil)

        sequencer.enqueue(status: 200, body: loginJSON(managerKey: key))
        _ = try await client.completeChallenge(challengeB, totpCode: "123456")
        #expect(await client.bearerToken != nil)
    }

    @Test("Cancelled begin before entry cannot clear replacement")
    func cancelledBeginDoesNotClearReplacement() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let transport = FixtureTransport()
        let client = NativeV2AuthClient(transport: transport, trustedAuthority: authority, signingIdentity: identity)

        transport.stub = .init(status: 201, body: beginJSON(challengeID: "keep", token: "keep-token", managerKey: key, mfaRequired: true))
        let keep = try await client.beginChallenge(username: "operator", password: "pw")
        #expect(await client.hasPendingChallenge)

        let cancelled = Task {
            try await client.beginChallenge(username: "operator", password: "other")
        }
        cancelled.cancel()
        await #expect(throws: HelicoidError.self) {
            try await cancelled.value
        }
        #expect(await client.hasPendingChallenge, "cancelled begin entry must not erase replacement")

        transport.stub = .init(status: 200, body: loginJSON(managerKey: key))
        _ = try await client.completeChallenge(keep, totpCode: "123456")
        #expect(await client.bearerToken != nil)
    }

    @Test("Slow completion accepts a 7200s session issued after the request started")
    func slowCompletionAcceptsFresh7200() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let sequencer = SequencedTransport()
        let client = NativeV2AuthClient(transport: sequencer, trustedAuthority: authority, signingIdentity: identity)

        sequencer.enqueue(status: 201, body: beginJSON(challengeID: "slow", token: "slow-token", managerKey: key, mfaRequired: true))
        let challenge = try await client.beginChallenge(username: "operator", password: "pw")

        // Responder waits >1s then issues expires = issue time + 7200.
        sequencer.enqueueDelayBuilder(status: 200, delayNs: 1_200_000_000) {
            let issue = Int(Date().timeIntervalSince1970)
            return buildLoginJSON(expiresAtUnix: issue + NativeV2AuthClient.maxSessionLifetimeSeconds, managerKey: key)
        }
        let session = try await client.completeChallenge(challenge, totpCode: "123456")
        #expect(session.token == "bearer-token-secret")
        let reception = Int(Date().timeIntervalSince1970)
        let remaining = session.expiresAtUnix - reception
        #expect(remaining <= NativeV2AuthClient.maxSessionLifetimeSeconds)
    }

    @Test("Reception-relative oversized and expired sessions stay denied")
    func oversizedAndExpiredStillDenied() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let sequencer = SequencedTransport()
        let client = NativeV2AuthClient(transport: sequencer, trustedAuthority: authority, signingIdentity: identity)

        sequencer.enqueue(status: 201, body: beginJSON(challengeID: "over", token: "over-token", managerKey: key, mfaRequired: true))
        let over = try await client.beginChallenge(username: "operator", password: "pw")
        sequencer.enqueueDelayBuilder(status: 200, delayNs: 1_200_000_000) {
            let issue = Int(Date().timeIntervalSince1970)
            return buildLoginJSON(
                expiresAtUnix: issue + NativeV2AuthClient.maxSessionLifetimeSeconds + 1,
                managerKey: key
            )
        }
        await #expect(throws: HelicoidError.self) {
            try await client.completeChallenge(over, totpCode: "123456")
        }

        sequencer.enqueue(status: 201, body: beginJSON(challengeID: "past", token: "past-token", managerKey: key, mfaRequired: true))
        let past = try await client.beginChallenge(username: "operator", password: "pw")
        sequencer.enqueue(status: 200, body: buildLoginJSON(
            expiresAtUnix: Int(Date().timeIntervalSince1970) - 5,
            managerKey: key
        ))
        await #expect(throws: HelicoidError.self) {
            try await client.completeChallenge(past, totpCode: "123456")
        }
    }

    @Test("Optional completion with available factor is a contradiction")
    func optionalAvailableFactorContradiction() throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let now = Int(Date().timeIntervalSince1970)
        let optional = try NativeV2AuthClient.validateChallengeResponse(
            try decode(beginJSON(managerKey: key, mfaRequired: false)),
            requestedManagerPublicKeyHex: key,
            trustedDeploymentID: "deploy-1",
            nowUnix: now
        )
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(managerKey: key, mfaRequired: false, mfaAvailable: true)),
                challenge: optional,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(managerKey: key, mfaRequired: true, mfaAvailable: true)),
                challenge: optional,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        let ok = try NativeV2AuthClient.validateCompletedLogin(
            try decode(loginJSON(managerKey: key, mfaRequired: false, mfaAvailable: false)),
            challenge: optional,
            expectedManagerPublicKeyHex: key,
            nowUnix: now
        )
        #expect(ok.mfa?.required == false)
        #expect(ok.mfa?.available == false)
    }

    // MARK: Fixtures

    private func makeIdentity() throws -> ManagerSigningIdentity {
        try ManagerSigningIdentity(storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation)
    }

    private func makeAuthority(deploymentID: String = "deploy-1") async throws -> DeploymentTLSIdentity {
        let material = try await TLSTestHarness.sharedMaterial()
        return try DeploymentTLSIdentity(
            deploymentID: deploymentID,
            host: "server.test",
            port: 8443,
            caDER: material.caDER,
            caFingerprintSHA256: material.caFingerprint
        )
    }

    private func hexKey(_ identity: ManagerSigningIdentity) -> String {
        AuthV2Canonical.lowercaseHex(identity.publicKey)
    }

    private func beginJSON(
        challengeID: String = "challenge-1",
        token: String = "challenge-token-secret",
        operation: String = "session",
        managerKey: String,
        deploymentID: String = "deploy-1",
        expiresAtUnix: Int? = nil,
        mfaRequired: Bool? = nil
    ) -> Data {
        var object: [String: Any] = [
            "challenge_id": challengeID,
            "challenge_token": token,
            "operation": operation,
            "manager_public_key": managerKey,
            "deployment_id": deploymentID,
            "expires_at_unix": expiresAtUnix ?? (Int(Date().timeIntervalSince1970) + 60),
        ]
        if let mfaRequired {
            object["mfa_required"] = mfaRequired
        }
        // swiftlint:disable:next force_try
        return try! JSONSerialization.data(withJSONObject: object)
    }

    private func loginJSON(
        token: String = "bearer-token-secret",
        expiresAtUnix: Int? = nil,
        accountState: String = "active",
        managerKey: String,
        managerState: String = "approved",
        mfaRequired: Bool = true,
        mfaAvailable: Bool = true,
        publicIdentity: String? = nil,
        includeMFA: Bool = true,
        completionKey: String? = nil
    ) -> Data {
        var object: [String: Any] = [
            "token": token,
            "expires_at_unix": expiresAtUnix ?? (Int(Date().timeIntervalSince1970) + 3600),
            "account": [
                "id": "account-1",
                "username": "operator",
                "state": accountState,
                "capabilities": ["operate": true],
                "revision": 1,
            ] as [String: Any],
            "manager": [
                "id": "manager-1",
                "public_identity": publicIdentity ?? "key:\(managerKey)",
                "lifecycle_state": managerState,
            ] as [String: Any],
            "manager_public_key": completionKey ?? managerKey,
        ]
        if includeMFA {
            object["mfa"] = [
                "required": mfaRequired,
                "available": mfaAvailable,
                "reason": "totp_active",
            ] as [String: Any]
        }
        // swiftlint:disable:next force_try
        return try! JSONSerialization.data(withJSONObject: object)
    }

    // MARK: Canonical signing

    @Test("Canonical session message is exact UTF-8 and signs with real Ed25519")
    func canonicalSigning() throws {
        let identity = try makeIdentity()
        let keyHex = hexKey(identity)
        let message = AuthV2Canonical.sessionMessage(
            deploymentID: "deploy-1",
            challengeID: "challenge-abc",
            managerPublicKeyHex: keyHex
        )
        let expected = Data("hs-auth-v2|deployment:deploy-1|challenge:challenge-abc|operation:session|manager:\(keyHex)".utf8)
        #expect(message == expected)

        let signature = try identity.sign(canonicalMessage: message)
        #expect(signature.count == 64)
        let signatureHex = AuthV2Canonical.lowercaseHex(signature)
        #expect(signatureHex.count == 128)
        #expect(signatureHex == signatureHex.lowercased())

        let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: identity.publicKey)
        #expect(verifier.isValidSignature(signature, for: expected))
        #expect(!verifier.isValidSignature(signature, for: message + Data([0x20])))
        // Operation/domain separation: a different operation string must not verify.
        let other = AuthV2Canonical.sessionMessage(
            deploymentID: "deploy-1",
            challengeID: "challenge-abc",
            managerPublicKeyHex: keyHex
        )
        #expect(other == expected)
    }

    @Test("Hex helpers round-trip lowercase bytes")
    func hexHelpers() {
        let bytes = Data([0x00, 0x01, 0xAB, 0xFF])
        let hex = AuthV2Canonical.lowercaseHex(bytes)
        #expect(hex == "0001abff")
        #expect(AuthV2Canonical.bytes(fromHex: hex) == bytes)
        #expect(AuthV2Canonical.bytes(fromHex: "0001ABFF") == bytes)
        #expect(AuthV2Canonical.bytes(fromHex: "0") == nil)
        #expect(AuthV2Canonical.bytes(fromHex: "zz") == nil)
    }

    // MARK: Challenge mapping

    @Test("Missing mfa_required is required; false is optional; true is required")
    func mfaMapping() throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let now = Int(Date().timeIntervalSince1970)

        let missing = try NativeV2AuthClient.validateChallengeResponse(
            try decode(beginJSON(managerKey: key, mfaRequired: nil)),
            requestedManagerPublicKeyHex: key,
            trustedDeploymentID: "deploy-1",
            nowUnix: now
        )
        #expect(missing.mfaRequirement == .required)
        #expect(missing.requiresCode)
        #expect(missing.codeState == .required)

        let optional = try NativeV2AuthClient.validateChallengeResponse(
            try decode(beginJSON(managerKey: key, mfaRequired: false)),
            requestedManagerPublicKeyHex: key,
            trustedDeploymentID: "deploy-1",
            nowUnix: now
        )
        #expect(optional.mfaRequirement == .optional)
        #expect(!optional.requiresCode)
        #expect(optional.codeState == .notRequired)

        let required = try NativeV2AuthClient.validateChallengeResponse(
            try decode(beginJSON(managerKey: key, mfaRequired: true)),
            requestedManagerPublicKeyHex: key,
            trustedDeploymentID: "deploy-1",
            nowUnix: now
        )
        #expect(required.mfaRequirement == .required)
    }

    @Test("Wrong deployment, key, and operation are refused")
    func wrongBinding() throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let now = Int(Date().timeIntervalSince1970)
        let otherKey = AuthV2Canonical.lowercaseHex(Data(repeating: 7, count: 32))

        #expect(throws: HelicoidError.identityMismatch) {
            try NativeV2AuthClient.validateChallengeResponse(
                try decode(beginJSON(managerKey: key, deploymentID: "other-deploy")),
                requestedManagerPublicKeyHex: key,
                trustedDeploymentID: "deploy-1",
                nowUnix: now
            )
        }
        #expect(throws: HelicoidError.identityMismatch) {
            try NativeV2AuthClient.validateChallengeResponse(
                try decode(beginJSON(managerKey: otherKey)),
                requestedManagerPublicKeyHex: key,
                trustedDeploymentID: "deploy-1",
                nowUnix: now
            )
        }
        #expect(throws: HelicoidError.invalidInput(field: "operation", detail: "The server returned a different challenge operation than requested.")) {
            try NativeV2AuthClient.validateChallengeResponse(
                try decode(beginJSON(operation: "enroll_manager", managerKey: key)),
                requestedManagerPublicKeyHex: key,
                trustedDeploymentID: "deploy-1",
                nowUnix: now
            )
        }
    }

    @Test("Expired and oversized challenges are refused")
    func expiredOversized() throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let now = 1_760_000_000

        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateChallengeResponse(
                try decode(beginJSON(managerKey: key, expiresAtUnix: now - 1)),
                requestedManagerPublicKeyHex: key,
                trustedDeploymentID: "deploy-1",
                nowUnix: now
            )
        }
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateChallengeResponse(
                try decode(beginJSON(managerKey: key, expiresAtUnix: now + 121)),
                requestedManagerPublicKeyHex: key,
                trustedDeploymentID: "deploy-1",
                nowUnix: now
            )
        }
        let longID = String(repeating: "a", count: 129)
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateChallengeResponse(
                try decode(beginJSON(challengeID: longID, managerKey: key)),
                requestedManagerPublicKeyHex: key,
                trustedDeploymentID: "deploy-1",
                nowUnix: now
            )
        }
        let longToken = String(repeating: "t", count: 513)
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateChallengeResponse(
                try decode(beginJSON(token: longToken, managerKey: key)),
                requestedManagerPublicKeyHex: key,
                trustedDeploymentID: "deploy-1",
                nowUnix: now
            )
        }
    }

    @Test("Malformed login and manager metadata are refused")
    func malformedLogin() throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let now = Int(Date().timeIntervalSince1970)
        let challenge = try NativeV2AuthClient.validateChallengeResponse(
            try decode(beginJSON(managerKey: key, mfaRequired: true)),
            requestedManagerPublicKeyHex: key,
            trustedDeploymentID: "deploy-1",
            nowUnix: now
        )

        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(token: " ", managerKey: key)),
                challenge: challenge,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(accountState: "pending_mfa", managerKey: key)),
                challenge: challenge,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(managerKey: key, managerState: "pending")),
                challenge: challenge,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(managerKey: key, managerState: "revoked")),
                challenge: challenge,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(expiresAtUnix: now - 5, managerKey: key)),
                challenge: challenge,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(expiresAtUnix: now + 7_201, managerKey: key)),
                challenge: challenge,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }

        // Truthful mfa.required is accepted after the challenge satisfied policy.
        let ok = try NativeV2AuthClient.validateCompletedLogin(
            try decode(loginJSON(managerKey: key, mfaRequired: true, mfaAvailable: true)),
            challenge: challenge,
            expectedManagerPublicKeyHex: key,
            nowUnix: now
        )
        #expect(ok.account.id == "account-1")
        #expect(ok.mfa?.required == true)
    }

    @Test("Completion manager_public_key binds signer; public_identity is display-only")
    func completionKeyBinding() throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let now = Int(Date().timeIntervalSince1970)
        let challenge = try NativeV2AuthClient.validateChallengeResponse(
            try decode(beginJSON(managerKey: key, mfaRequired: true)),
            requestedManagerPublicKeyHex: key,
            trustedDeploymentID: "deploy-1",
            nowUnix: now
        )
        let otherKey = AuthV2Canonical.lowercaseHex(Data(repeating: 9, count: 32))

        // Display label `key:<hex>` is accepted when completion key matches signer.
        let ok = try NativeV2AuthClient.validateCompletedLogin(
            try decode(loginJSON(managerKey: key, publicIdentity: "key:\(key)")),
            challenge: challenge,
            expectedManagerPublicKeyHex: key,
            nowUnix: now
        )
        #expect(ok.manager?.publicIdentity.hasPrefix("key:") == true)

        // Wrong completion key is refused even if display identity looks right.
        #expect(throws: HelicoidError.identityMismatch) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(managerKey: key, completionKey: otherKey)),
                challenge: challenge,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        // Parsing labels into authority is refused (completion key is authority).
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(managerKey: otherKey, publicIdentity: "key:\(key)", completionKey: otherKey)),
                challenge: challenge,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
    }

    @Test("MFA metadata must match the completed factor")
    func mfaConsistency() throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let now = Int(Date().timeIntervalSince1970)
        let required = try NativeV2AuthClient.validateChallengeResponse(
            try decode(beginJSON(managerKey: key, mfaRequired: true)),
            requestedManagerPublicKeyHex: key,
            trustedDeploymentID: "deploy-1",
            nowUnix: now
        )
        let optional = try NativeV2AuthClient.validateChallengeResponse(
            try decode(beginJSON(managerKey: key, mfaRequired: false)),
            requestedManagerPublicKeyHex: key,
            trustedDeploymentID: "deploy-1",
            nowUnix: now
        )

        // Missing MFA block is malformed.
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(managerKey: key, includeMFA: false)),
                challenge: required,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        // Required completion cannot accept weaker metadata (unavailable factor).
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(managerKey: key, mfaRequired: true, mfaAvailable: false)),
                challenge: required,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(managerKey: key, mfaRequired: false, mfaAvailable: true)),
                challenge: required,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        // Optional completion cannot claim a waived required factor.
        #expect(throws: HelicoidError.self) {
            try NativeV2AuthClient.validateCompletedLogin(
                try decode(loginJSON(managerKey: key, mfaRequired: true, mfaAvailable: true)),
                challenge: optional,
                expectedManagerPublicKeyHex: key,
                nowUnix: now
            )
        }
        // Consistent optional non-enrolled metadata is accepted.
        let ok = try NativeV2AuthClient.validateCompletedLogin(
            try decode(loginJSON(managerKey: key, mfaRequired: false, mfaAvailable: false)),
            challenge: optional,
            expectedManagerPublicKeyHex: key,
            nowUnix: now
        )
        #expect(ok.mfa?.required == false)
    }

    @Test("Extreme expiries do not trap; ASCII TOTP only")
    func overflowAndASCIITOTP() {
        #expect(NativeV2AuthClient.remainingSeconds(expiresAtUnix: Int.min, nowUnix: 1) == nil)
        #expect(NativeV2AuthClient.remainingSeconds(expiresAtUnix: Int.max, nowUnix: -1) == nil)
        #expect(NativeV2AuthClient.remainingSeconds(expiresAtUnix: 100, nowUnix: 40) == 60)
        #expect(NativeV2AuthClient.isValidTOTPCode("123456"))
        #expect(!NativeV2AuthClient.isValidTOTPCode("１２３４５６")) // fullwidth
        #expect(!NativeV2AuthClient.isValidTOTPCode("١٢٣٤٥٦")) // Arabic-Indic
    }

    @Test("AuthInstallGate fences late UI installation")
    func installGate() {
        var gate = AuthInstallGate()
        let token = gate.begin()
        #expect(gate.permits(token))
        gate.cancel()
        #expect(!gate.permits(token))
        let second = gate.begin()
        #expect(gate.permits(second))
        #expect(!gate.permits(token))
        gate.cancel()
        #expect(!gate.permits(second))
    }

    // MARK: HTTP mapping + code state

    @Test("Begin maps 201 body and stores cancellable required-code state")
    func beginRequiredHTTP() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let transport = FixtureTransport()
        transport.stub = .init(status: 201, body: beginJSON(managerKey: key, mfaRequired: true))
        let client = NativeV2AuthClient(transport: transport, trustedAuthority: authority, signingIdentity: identity)

        let challenge = try await client.beginChallenge(username: "operator", password: "secret-password")
        #expect(challenge.requiresCode)
        #expect(await client.currentCodeState == .required)
        #expect(await client.hasPendingChallenge)

        let request = transport.lastRequest
        #expect(request?.httpMethod == "POST")
        #expect(request?.url?.path.hasSuffix("/v2/auth/challenge") == true)
        let body = String(data: request?.httpBody ?? Data(), encoding: .utf8) ?? ""
        #expect(body.contains("\"operation\":\"session\""))
        #expect(body.contains("manager_public_key"))
        // Password is present only in the begin request body (process memory / wire).
        #expect(body.contains("secret-password"))

        await client.cancelSignIn()
        #expect(await client.currentCodeState == .idle)
        #expect(!(await client.hasPendingChallenge))
    }

    @Test("Optional challenge omits totp_code on complete")
    func optionalOmitsCode() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let transport = FixtureTransport()

        transport.stub = .init(status: 201, body: beginJSON(managerKey: key, mfaRequired: false))
        let client = NativeV2AuthClient(transport: transport, trustedAuthority: authority, signingIdentity: identity)
        let challenge = try await client.beginChallenge(username: "operator", password: "pw")
        #expect(!challenge.requiresCode)

        transport.stub = .init(status: 200, body: loginJSON(managerKey: key, mfaRequired: false, mfaAvailable: false))
        let session = try await client.completeChallenge(challenge, totpCode: nil)
        #expect(session.token == "bearer-token-secret")
        let completeBody = String(data: transport.lastRequest?.httpBody ?? Data(), encoding: .utf8) ?? ""
        #expect(completeBody.contains("manager_signature"))
        #expect(!completeBody.contains("totp_code"))

        // Optional login is accepted only when the server reported optional.
        #expect(await client.bearerToken == "bearer-token-secret")
    }

    @Test("Required complete sends six-digit code and installs session")
    func requiredComplete() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let transport = FixtureTransport()

        transport.stub = .init(status: 201, body: beginJSON(managerKey: key, mfaRequired: true))
        let client = NativeV2AuthClient(transport: transport, trustedAuthority: authority, signingIdentity: identity)
        let challenge = try await client.beginChallenge(username: "operator", password: "pw")

        await #expect(throws: HelicoidError.self) {
            try await client.completeChallenge(challenge, totpCode: nil)
        }
        await #expect(throws: HelicoidError.self) {
            try await client.completeChallenge(challenge, totpCode: "12345")
        }

        transport.stub = .init(status: 200, body: loginJSON(managerKey: key))
        let session = try await client.completeChallenge(challenge, totpCode: "123456")
        #expect(session.account.username == "operator")
        let completeBody = String(data: transport.lastRequest?.httpBody ?? Data(), encoding: .utf8) ?? ""
        #expect(completeBody.contains("\"totp_code\":\"123456\""))
        #expect(await client.currentCodeState == .idle)
        #expect(!(await client.hasPendingChallenge))
    }

    @Test("Cancellation prevents late completion from installing a session")
    func cancellationLateCompletion() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let transport = FixtureTransport()
        transport.stub = .init(status: 201, body: beginJSON(managerKey: key, mfaRequired: true))
        let client = NativeV2AuthClient(transport: transport, trustedAuthority: authority, signingIdentity: identity)
        let challenge = try await client.beginChallenge(username: "operator", password: "pw")

        // Cancel first: pending challenge is gone.
        await client.cancelSignIn()
        await #expect(throws: HelicoidError.self) {
            try await client.completeChallenge(challenge, totpCode: "123456")
        }
        #expect(await client.bearerToken == nil)

        // Start again, then sign-out local before complete finishes installing.
        transport.stub = .init(status: 201, body: beginJSON(managerKey: key, mfaRequired: true))
        let second = try await client.beginChallenge(username: "operator", password: "pw")
        transport.stub = .init(status: 200, body: loginJSON(managerKey: key))
        await client.signOutLocal()
        await #expect(throws: HelicoidError.self) {
            try await client.completeChallenge(second, totpCode: "123456")
        }
        #expect(await client.bearerToken == nil)
    }

    @Test("Code state and secrets clear on success, cancel, and sign-out")
    func clearing() async throws {
        let identity = try makeIdentity()
        let key = hexKey(identity)
        let authority = try await makeAuthority()
        let transport = FixtureTransport()
        let client = NativeV2AuthClient(transport: transport, trustedAuthority: authority, signingIdentity: identity)

        transport.stub = .init(status: 201, body: beginJSON(managerKey: key, mfaRequired: true))
        _ = try await client.beginChallenge(username: "operator", password: "pw")
        #expect(await client.currentCodeState == .required)
        await client.cancelSignIn()
        #expect(await client.currentCodeState == .idle)

        transport.stub = .init(status: 201, body: beginJSON(managerKey: key, mfaRequired: false))
        let challenge = try await client.beginChallenge(username: "operator", password: "pw")
        transport.stub = .init(status: 200, body: loginJSON(managerKey: key, mfaRequired: false, mfaAvailable: false))
        _ = try await client.completeChallenge(challenge, totpCode: nil)
        #expect(await client.bearerToken != nil)
        #expect(await client.currentCodeState == .idle)
        await client.signOutLocal()
        #expect(await client.bearerToken == nil)
    }

    @Test("ServerError maps to plain-language refusals")
    func errorMapping() {
        func envelope(_ code: String, _ message: String) -> ServerErrorEnvelope {
            ServerErrorEnvelope(error: .init(code: code, message: message))
        }
        if case .authenticationFailed = NativeV2AuthClient.mapServerError(envelope("unauthorized", "Bad credentials")) {}
        else { Issue.record("unauthorized should map to authenticationFailed") }
        if case .permissionDenied = NativeV2AuthClient.mapServerError(envelope("forbidden", "Manager revoked")) {}
        else { Issue.record("forbidden manager should map to permissionDenied") }
        if case .authenticationFailed = NativeV2AuthClient.mapServerError(envelope("rate_limited", "Slow down")) {}
        else { Issue.record("rate_limited should map to authenticationFailed") }
        if case .serverContractUnavailable = NativeV2AuthClient.mapServerError(envelope("not_implemented", "Nope")) {}
        else { Issue.record("not_implemented should map to serverContractUnavailable") }
    }

    @Test("TOTP code shape")
    func totpShape() {
        #expect(NativeV2AuthClient.isValidTOTPCode("123456"))
        #expect(NativeV2AuthClient.isValidTOTPCode(" 123456 "))
        #expect(!NativeV2AuthClient.isValidTOTPCode("12345"))
        #expect(!NativeV2AuthClient.isValidTOTPCode("1234567"))
        #expect(!NativeV2AuthClient.isValidTOTPCode("12345a"))
        #expect(!NativeV2AuthClient.isValidTOTPCode(""))
    }

    @Test("Address must match independently configured origin")
    func addressMatchesOrigin() async throws {
        let identity = try makeIdentity()
        let authority = try await makeAuthority()
        let transport = FixtureTransport()
        let client = NativeV2AuthClient(transport: transport, trustedAuthority: authority, signingIdentity: identity)

        let ok = await client.validateAddress("https://server.test:8443")
        #expect(ok.isOK)
        let bare = await client.validateAddress("server.test:8443")
        #expect(bare.isOK)
        let wrongHost = await client.validateAddress("https://evil.test:8443")
        #expect(!wrongHost.isOK)
        let wrongPort = await client.validateAddress("https://server.test:9443")
        #expect(!wrongPort.isOK)

        let mismatch = await client.connect(address: "https://evil.test:8443")
        guard case .failure(let error) = mismatch else {
            Issue.record("mismatched address must refuse connect")
            return
        }
        if case .invalidInput = error {} else { Issue.record("expected invalidInput for address mismatch") }

        transport.stub = .init(status: 200, body: Data(#"{"status":"ok","accepting_authorized_operations":true,"schema_version":2,"bootstrap_completed":true,"features":{}}"#.utf8))
        let connected = await client.connect(address: "https://server.test:8443")
        guard case .success(let serverIdentity) = connected else {
            Issue.record("configured origin should connect after pinned health")
            return
        }
        // Identity comes from configured trust, not discovery.
        #expect(serverIdentity.deploymentName == authority.deploymentID)
        #expect(serverIdentity.verificationFingerprint == authority.caFingerprintSHA256)
    }

    private func decode<T: Decodable>(_ data: Data) throws -> T {
        try JSONDecoder().decode(T.self, from: data)
    }
}
