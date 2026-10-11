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
        do {
            _ = try await operation.value
            Issue.record("Cancelled command unexpectedly succeeded")
        } catch {
            #expect(error is CancellationError || error as? SetupCommandError == .cancelled)
        }
    }

    @Test func successfulCommandRetainsTrailingOutputUntilEOF() async throws {
        let result = try await SystemSetupCommandRunner().run(SetupCommand(
            executable: "/bin/sh",
            arguments: ["-c", "printf head; sleep 0.2; printf tail"],
            timeoutSeconds: 5))
        #expect(result.exitStatus == 0)
        #expect(String(decoding: result.output, as: UTF8.self) == "headtail")
    }

    @Test func timeoutWithNonReadingStdinIsBounded() async {
        let clock = ContinuousClock()
        let start = clock.now
        await #expect(throws: SetupCommandError.timedOut) {
            try await SystemSetupCommandRunner().run(SetupCommand(
                executable: "/bin/sh",
                arguments: ["-c", "sleep 10"],
                input: Data(repeating: 0x41, count: 65_536),
                timeoutSeconds: 0.05))
        }
        #expect(start.duration(to: clock.now) < .seconds(1))
    }

    @Test func cancelledChildIsGoneWhenReturnIsObserved() async throws {
        let marker = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-ssh-owned-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: marker) }
        let operation = Task {
            try await SystemSetupCommandRunner().run(SetupCommand(
                executable: "/bin/sh",
                arguments: ["-c", "echo $$ > \"$1\"; sleep 10", "helicoid-test", marker.path],
                timeoutSeconds: 30))
        }
        var ownedPID: pid_t = 0
        for _ in 0..<200 {
            if let text = try? String(contentsOf: marker, encoding: .utf8),
               let value = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)),
               value > 0 {
                ownedPID = value
                break
            }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(ownedPID > 0)
        operation.cancel()
        do {
            _ = try await operation.value
            Issue.record("Cancelled command unexpectedly succeeded")
        } catch {
            #expect(error is CancellationError || error as? SetupCommandError == .cancelled)
        }
        // Reap owner must have recorded exit before the runner returned.
        #expect(Darwin.kill(ownedPID, 0) == -1)
        #expect(errno == ESRCH)
    }

    @Test func cancellationBeforeLaunchDoesNotLeaveChild() async {
        let marker = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-ssh-prestart-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: marker) }
        let operation = Task {
            try await SystemSetupCommandRunner().run(SetupCommand(
                executable: "/bin/sh",
                arguments: ["-c", "sleep 0.15; printf ran > \"$1\"", "helicoid-test", marker.path],
                timeoutSeconds: 5))
        }
        operation.cancel()
        do {
            _ = try await operation.value
            Issue.record("Cancelled command unexpectedly succeeded")
        } catch {
            #expect(error is CancellationError || error as? SetupCommandError == .cancelled)
        }
        // After return, a pre-start cancel never spawned; a launched child was
        // reaped. A delayed marker would mean an unreaped child outlived us.
        try? await Task.sleep(for: .milliseconds(250))
        #expect(!FileManager.default.fileExists(atPath: marker.path))
    }

    @Test func closedStdinDoesNotGenerateSIGPIPEOrHideFailedInput() async throws {
        do {
            let result = try await SystemSetupCommandRunner().run(SetupCommand(
                executable: "/bin/sh",
                arguments: ["-c", "exec 0<&-; printf done"],
                input: Data(repeating: 0x41, count: 65_536),
                timeoutSeconds: 5))
            // The kernel may accept all bounded input before the child closes
            // stdin. Otherwise the runner must report inputFailed, never hide it.
            #expect(result.exitStatus == 0)
            #expect(String(decoding: result.output, as: UTF8.self) == "done")
        } catch {
            #expect(error as? SetupCommandError == .inputFailed)
        }
    }

    @Test func exitedChildWithInheritedWriterStillTimesOut() async {
        await #expect(throws: SetupCommandError.timedOut) {
            try await SystemSetupCommandRunner().run(SetupCommand(
                executable: "/bin/sh",
                arguments: ["-c", "sleep 2 & printf partial; exit 0"],
                timeoutSeconds: 0.05))
        }
    }

    @Test func outputOverflowReapsOwnedChildBeforeReturning() async throws {
        let marker = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-ssh-overflow-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: marker) }
        await #expect(throws: SetupCommandError.outputExceeded) {
            try await SystemSetupCommandRunner().run(SetupCommand(
                executable: "/bin/sh",
                arguments: ["-c", "echo $$ > \"$1\"; exec /usr/bin/yes bounded",
                            "helicoid-test", marker.path],
                timeoutSeconds: 5, outputLimit: 32))
        }
        let text = try String(contentsOf: marker, encoding: .utf8)
        let pid = try #require(Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)))
        try #require(pid > 0)
        #expect(Darwin.kill(pid, 0) == -1)
        #expect(errno == ESRCH)
    }

    @Test func embeddedNULArgumentIsRefusedBeforeLaunch() async throws {
        let marker = FileManager.default.temporaryDirectory
            .appendingPathComponent("hs-ssh-nul-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: marker) }
        await #expect(throws: SetupCommandError.launchFailed) {
            try await SystemSetupCommandRunner().run(SetupCommand(
                executable: "/bin/sh",
                arguments: ["-c", "printf ran > \"$1\"", "helicoid-test", marker.path, "a\0b"]))
        }
        #expect(!FileManager.default.fileExists(atPath: marker.path))
    }

    @Test func secondInvocationIsUnaffectedByPriorTimeout() async throws {
        await #expect(throws: SetupCommandError.timedOut) {
            try await SystemSetupCommandRunner().run(SetupCommand(
                executable: "/bin/sh", arguments: ["-c", "sleep 2 & wait"], timeoutSeconds: 0.05))
        }
        let result = try await SystemSetupCommandRunner().run(SetupCommand(
            executable: "/bin/sh", arguments: ["-c", "printf second; exit 3"]))
        #expect(result.exitStatus == 3)
        #expect(String(decoding: result.output, as: UTF8.self) == "second")
    }

    @Test @MainActor func modelInvalidatesTrustWhenAddressChanges() async throws {
        let runner = SSHFixtureRunner(SetupCommandResult(exitStatus: 0, output: facts,
            errorOutput: Data("debug1: Server host key: ssh-ed25519 \(fingerprint)\n".utf8)))
        let model = GuidedServerSetupModel(sshClient: SSHSetupClient(runner: runner))
        model.setRoute(.existingLinuxSSH)
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
        model.setRoute(.existingLinuxSSH)
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
