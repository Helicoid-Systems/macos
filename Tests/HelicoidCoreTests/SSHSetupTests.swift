import Foundation
import Testing
@testable import HelicoidCore

private actor SSHFixtureRunner: SetupCommandRunning {
    let result: SetupCommandResult
    private(set) var commands: [SetupCommand] = []
    init(_ result: SetupCommandResult) { self.result = result }
    func run(_ command: SetupCommand) async throws -> SetupCommandResult {
        commands.append(command)
        return result
    }
}

@Suite("Verified SSH setup boundary")
struct SSHSetupTests {
    private let facts = Data(#"{"version":1,"os_id":"ubuntu","os_version":"26.04","architecture":"x86_64","systemd_available":true,"sudo_available":true,"free_bytes":3000000000,"existing_installation":false,"tcp_ports":[22,80,443],"udp_ports":[53]}"#.utf8)
    private let fingerprint = "SHA256:" + String(repeating: "A", count: 43)

    @Test func addressesRejectOptionsShellAndPassword() throws {
        for value in ["-oProxyCommand=evil", "ubuntu@host;touch", "a:b@host", "user@host/command", "u@host?x=1", "u@host#x", "u@host%20", "u@host:0", "u@host:65536", " user@host", "user@host\n", "-user@host"] {
            #expect(throws: (any Error).self) { try SSHSetupAddress(value) }
        }
        let address = try SSHSetupAddress("ubuntu@57.131.161.27:2222")
        #expect(address.destination == "ubuntu@57.131.161.27")
        #expect(address.port == 2222)
    }

    @Test func preflightUsesStrictTrustAndFixedRemoteProgram() async throws {
        let runner = SSHFixtureRunner(SetupCommandResult(exitStatus: 0, output: facts,
            errorOutput: Data("debug1: Server host key: ssh-ed25519 \(fingerprint)\n".utf8)))
        let verified = try await SSHSetupClient(runner: runner).preflight(address: SSHSetupAddress("ubuntu@host"))
        #expect(verified.fingerprint == fingerprint)
        #expect(verified.host.checks().values.allSatisfy { $0 == .passed })
        let commands = await runner.commands
        #expect(commands.count == 1)
        #expect(commands[0].arguments.contains("StrictHostKeyChecking=yes"))
        #expect(commands[0].arguments.contains("UpdateHostKeys=no"))
        #expect(commands[0].arguments.last == "/usr/bin/python3 -")
        #expect(!String(decoding: commands[0].input, as: UTF8.self).contains("ubuntu@host"))
    }

    @Test func unsuccessfulSSHNeverAcceptsValidLookingOutput() async throws {
        let runner = SSHFixtureRunner(SetupCommandResult(exitStatus: 255, output: facts,
            errorOutput: Data("debug1: Server host key: ssh-ed25519 \(fingerprint)\nHost key verification failed".utf8)))
        await #expect(throws: HelicoidError.hostIdentityUnverified) {
            try await SSHSetupClient(runner: runner).preflight(address: SSHSetupAddress("ubuntu@host"))
        }
    }

    @Test func absentOrAmbiguousFingerprintRefuses() async throws {
        for debug in ["", "debug1: Server host key: ssh-ed25519 bad", String(repeating: "debug1: Server host key: ssh-ed25519 \(fingerprint)\n", count: 2)] {
            let runner = SSHFixtureRunner(SetupCommandResult(exitStatus: 0, output: facts, errorOutput: Data(debug.utf8)))
            await #expect(throws: HelicoidError.hostIdentityUnverified) {
                try await SSHSetupClient(runner: runner).preflight(address: SSHSetupAddress("ubuntu@host"))
            }
        }
    }

    @Test func openSSHCarriageReturnLinesPreserveFingerprint() {
        #expect(SSHSetupClient.hostFingerprint(Data("debug1: Server host key: ssh-ed25519 \(fingerprint)\r\n".utf8)) == fingerprint)
    }

    @Test func missingFactsRefuseRatherThanPassChecks() async throws {
        let runner = SSHFixtureRunner(SetupCommandResult(exitStatus: 0, output: Data("{}".utf8),
            errorOutput: Data("debug1: Server host key: ssh-ed25519 \(fingerprint)\n".utf8)))
        await #expect(throws: (any Error).self) {
            try await SSHSetupClient(runner: runner).preflight(address: SSHSetupAddress("ubuntu@host"))
        }
        let occupied = String(decoding: facts, as: UTF8.self).replacingOccurrences(of: "[22,80,443]", with: "[22,8920]")
        let parsed = try JSONDecoder().decode(SSHHostPreflight.self, from: Data(occupied.utf8))
        #expect(parsed.checks()["Product ports"] != .passed)
    }

    @Test func realProcessCapturesExitAndBothPipes() async throws {
        let result = try await SystemSetupCommandRunner().run(SetupCommand(
            executable: "/bin/sh", arguments: ["-c", "printf actual; printf diagnostic >&2; exit 7"]))
        #expect(result.exitStatus == 7)
        #expect(String(decoding: result.output, as: UTF8.self) == "actual")
        #expect(String(decoding: result.errorOutput, as: UTF8.self) == "diagnostic")
    }

    @Test func realOutputFloodIsBounded() async {
        await #expect(throws: SetupCommandError.outputExceeded) {
            try await SystemSetupCommandRunner().run(SetupCommand(
                executable: "/usr/bin/yes", arguments: ["bounded"], timeoutSeconds: 2, outputLimit: 32))
        }
    }

    @Test func timeoutDoesNotWaitForInheritedPipeWriter() async {
        let clock = ContinuousClock()
        let start = clock.now
        await #expect(throws: SetupCommandError.timedOut) {
            try await SystemSetupCommandRunner().run(SetupCommand(
                executable: "/bin/sh", arguments: ["-c", "sleep 2 & wait"], timeoutSeconds: 0.05))
        }
        #expect(start.duration(to: clock.now) < .seconds(1))
    }

    @Test func cancellationEndsChild() async {
        let operation = Task {
            try await SystemSetupCommandRunner().run(SetupCommand(executable: "/bin/sleep", arguments: ["10"]))
        }
        operation.cancel()
        await #expect(throws: (any Error).self) { try await operation.value }
    }

    @Test @MainActor func modelInvalidatesTrustWhenAddressChanges() async throws {
        let runner = SSHFixtureRunner(SetupCommandResult(exitStatus: 0, output: facts,
            errorOutput: Data("debug1: Server host key: ssh-ed25519 \(fingerprint)\n".utf8)))
        let model = GuidedServerSetupModel(sshClient: SSHSetupClient(runner: runner))
        model.setSSHAddress("ubuntu@host")
        await model.verifyAndInspectHost()
        #expect(model.hostIdentity.isVerified)
        #expect(model.hostPreflight != nil)
        model.setSSHAddress("ubuntu@replacement")
        #expect(!model.hostIdentity.isVerified)
        #expect(model.hostPreflight == nil)
        #expect(model.hostChecks.isEmpty)
    }

    @Test @MainActor func modelRechecksSelectedPortAndRefusesPasswordFallback() async throws {
        let runner = SSHFixtureRunner(SetupCommandResult(exitStatus: 0, output: facts,
            errorOutput: Data("debug1: Server host key: ssh-ed25519 \(fingerprint)\n".utf8)))
        let model = GuidedServerSetupModel(sshClient: SSHSetupClient(runner: runner))
        model.setSSHAddress("ubuntu@host")
        await model.verifyAndInspectHost()
        model.setProductPort("443")
        #expect(model.hostChecks["Product ports"] != .passed)
        model.setProductPort("8920")
        #expect(model.hostChecks["Product ports"] == .passed)
        model.setSSHAuthMethod(.password)
        await model.verifyAndInspectHost()
        #expect(!model.hostIdentity.isVerified)
        #expect(await runner.commands.count == 1)
    }
}
