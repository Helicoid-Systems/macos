import Foundation
import Testing
@testable import HelicoidCore

@Suite("Live read-only SSH preflight")
struct SSHLiveSetupTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["HELICOID_SSH_TEST_ADDRESS"] != nil))
    func suppliedHostUsesActualRunnerAndTrustedSSH() async throws {
        guard let address = ProcessInfo.processInfo.environment["HELICOID_SSH_TEST_ADDRESS"] else {
            throw HelicoidError.notConfigured
        }
        let result = try await SSHSetupClient().preflight(address: SSHSetupAddress(address))
        #expect(result.fingerprint.hasPrefix("SHA256:"))
        #expect(result.host.osID == "ubuntu")
        #expect(result.host.osVersion == "26.04")
        #expect(result.host.architecture == "x86_64")
        #expect(result.host.checks().values.allSatisfy { $0 == .passed })
        #expect(result.host.tcpPorts.contains(80))
        #expect(result.host.tcpPorts.contains(443))
    }
}
