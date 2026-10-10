import Foundation
import Testing
@testable import HelicoidCore

@Suite("Required development response fields")
struct RequiredResponseTests {
    private func login(expiry: Int? = Int(Date().timeIntervalSince1970) + 3600,
                       revision: Int? = 1, includeCapabilities: Bool = true,
                       includeMFA: Bool = true) -> LoginResponseDTO {
        LoginResponseDTO(
            token: "test-session",
            expiresAtUnix: expiry,
            account: AccountDTO(id: "account-1", username: "test", state: "active",
                capabilities: includeCapabilities ? AccountCapabilitiesDTO(operate: true) : nil,
                revision: revision),
            mfa: includeMFA ? MFADTO(required: false, available: false) : nil
        )
    }

    @Test("Complete response accepted; missing expiry refused")
    func requiredExpiry() {
        #expect(LoopbackDevelopmentClient.validateLogin(login(), requestedManagerIdentity: nil) == nil)
        #expect(LoopbackDevelopmentClient.validateLogin(login(expiry: nil), requestedManagerIdentity: nil) != nil)
        #expect(LoopbackDevelopmentClient.validateLogin(login(expiry: Int.max), requestedManagerIdentity: nil) != nil)
    }

    @Test("Missing account revision and capabilities refused")
    func requiredAccountState() {
        #expect(LoopbackDevelopmentClient.validateLogin(login(revision: nil), requestedManagerIdentity: nil) != nil)
        #expect(LoopbackDevelopmentClient.validateLogin(login(revision: 0), requestedManagerIdentity: nil) != nil)
        #expect(LoopbackDevelopmentClient.validateLogin(login(includeCapabilities: false), requestedManagerIdentity: nil) != nil)
    }

    @Test("Missing MFA state refused")
    func requiredMFAState() {
        #expect(LoopbackDevelopmentClient.validateLogin(login(includeMFA: false), requestedManagerIdentity: nil) != nil)
    }

    @Test("Unknown and contradictory health readiness refused")
    func healthReadiness() {
        func health(_ status: String, _ accepting: Bool, _ bootstrap: Bool) -> HealthDTO {
            HealthDTO(status: status, acceptingAuthorizedOperations: accepting, schemaVersion: 1,
                      bootstrapCompleted: bootstrap, features: [:])
        }
        #expect(LoopbackDevelopmentClient.validateHealth(health("ok", true, true)))
        #expect(LoopbackDevelopmentClient.validateHealth(health("degraded", false, false)))
        #expect(!LoopbackDevelopmentClient.validateHealth(health("unexpected", true, true)))
        #expect(!LoopbackDevelopmentClient.validateHealth(health("degraded", true, true)))
        #expect(!LoopbackDevelopmentClient.validateHealth(health("ok", true, false)))
    }
}
