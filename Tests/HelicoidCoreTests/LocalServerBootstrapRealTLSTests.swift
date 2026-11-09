import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

/// Production pinned-HTTPS bootstrap path against a disposable loopback TLS
/// server. The server is a test fixture; no real server, credentials, or
/// account state is used.
@Suite("Local bootstrap real TLS", .serialized)
struct LocalServerBootstrapRealTLSTests {
    private let deploymentID = "tls-deploy-test"
    private let token = "fixture-bootstrap-token"
    private let username = "admin"
    private let password = "fixture password 123"
    private let totpSecret = "JBSWY3DPEHPK3PXP"
    private let recoveryCodes = [
        "AAAA-BBBB-CCCC-DDDD",
        "EEEE-FFFF-GGGG-HHHH",
    ]

    @Test("Production pinned transport bootstraps and retries a wrong-TOTP 401")
    func productionTransportBootstrapAndTOTPRetry() async throws {
        let pki = try await TLSTestHarness.makePKI()
        defer { try? FileManager.default.removeItem(at: pki.directory) }
        let server = try TLSTestHarness.startServer(cert: pki.goodCertPEM, key: pki.goodKeyPEM)
        defer {
            do { try server.stop() }
            catch { Issue.record("Unexpected TLS server teardown failure: \(error)") }
        }

        let identity = try DeploymentTLSIdentity(
            deploymentID: deploymentID,
            host: "127.0.0.1",
            port: server.port,
            caDER: pki.caDER,
            caFingerprintSHA256: pki.caFingerprint
        )
        let trust = try LocalBootstrapTrust(identity: identity)
        let signingIdentity = try ManagerSigningIdentity(
            storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation
        )
        // Production initializer: builds PinnedHTTPSTransport. No mock
        // transport is injected.
        let client = try LocalServerBootstrapClient(
            trust: trust,
            signingIdentity: signingIdentity
        )

        let enrollment = try await client.bootstrapFirstAdministrator(
            token: token,
            username: username,
            password: password,
            managerFriendlyName: "Installer",
            acknowledgement: .operatorWillStoreMFASecretAndRecoveryCodesIndependently
        )
        #expect(enrollment.accountID == "account-1")
        #expect(enrollment.username == username)
        #expect(enrollment.mfaEnrollmentID == "enrollment-1")
        #expect(
            enrollment.managerPublicKey
                == AuthV2Canonical.lowercaseHex(signingIdentity.publicKey)
        )
        #expect(enrollment.accountState == "pending_mfa")
        #expect(enrollment.serverState == "awaiting_mfa_confirmation")
        #expect(await client.state == .awaitingMFAConfirmation)
        #expect(await client.hasActiveEnrollment)
        #expect(enrollment.hasSecrets)

        // First confirmation is the contractually determinate wrong-TOTP 401.
        do {
            _ = try await client.confirmMFAEnrollment(
                enrollment,
                totpCode: "123456",
                recoveryCodesStoredIndependently: true
            )
            Issue.record("The first confirmation must be refused with 401")
        } catch let error as HelicoidError {
            if case .authenticationFailed = error {
                // Expected.
            } else {
                Issue.record("Expected authenticationFailed, got \(error)")
            }
        }
        #expect(await client.state == .awaitingMFAConfirmation)
        #expect(await client.hasActiveEnrollment)
        #expect(enrollment.hasSecrets)
        #expect(await !client.isOperationInFlight)
        #expect(await !client.isIrreversibleRequestInFlight)

        let secrets = try #require(enrollment.takeSecrets())
        #expect(secrets.totpSecretBase32 == totpSecret)
        #expect(secrets.recoveryCodes == recoveryCodes)

        // The same enrollment remains valid and succeeds on the next attempt.
        let confirmation = try await client.confirmMFAEnrollment(
            enrollment,
            totpCode: "123456",
            recoveryCodesStoredIndependently: true
        )
        #expect(confirmation.accountID == "account-1")
        #expect(confirmation.mfaStatus == "active")
        #expect(confirmation.accountState == "active")
        #expect(await client.state == .confirmed)
        #expect(await !client.hasActiveEnrollment)
        #expect(!enrollment.hasSecrets)
        #expect(await !client.isOperationInFlight)
        #expect(await !client.isIrreversibleRequestInFlight)

        try await client.dispose()
    }
}
