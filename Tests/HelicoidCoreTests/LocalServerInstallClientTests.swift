import Foundation
import Testing
@testable import HelicoidCore

private let testNonce = "0123456789abcdef0123456789abcdef"

private func makeClient(
    helper: URL,
    runner: any SetupCommandRunning
) -> LocalServerInstallClient {
    LocalServerInstallClient(
        helperURL: helper,
        runner: runner,
        markerNonce: { testNonce })
}

private actor ScriptedCommandRunner: SetupCommandRunning {
    private var responses: [Result<SetupCommandResult, SetupCommandError>]
    private var recorded: [SetupCommand] = []

    init(_ responses: [Result<SetupCommandResult, SetupCommandError>]) {
        self.responses = responses
    }

    func run(_ command: SetupCommand) async throws -> SetupCommandResult {
        recorded.append(command)
        guard !responses.isEmpty else {
            throw SetupCommandError.launchFailed
        }
        return try responses.removeFirst().get()
    }

    func commands() -> [SetupCommand] { recorded }
}

private func executableHelper() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("helicoid-helper-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let helper = root.appendingPathComponent("hs-server")
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: helper)
    try FileManager.default.setAttributes(
        [.posixPermissions: NSNumber(value: 0o755)],
        ofItemAtPath: helper.path)
    return helper
}

private func removeHelper(_ helper: URL) {
    try? FileManager.default.removeItem(at: helper.deletingLastPathComponent())
}

private func helperOutput(_ json: Data, status: Int32 = 0) -> SetupCommandResult {
    var output = json
    output.append(Data("\n\(PrivilegedInvocationMarker.helperStatus(testNonce))\(status)\n".utf8))
    return SetupCommandResult(exitStatus: 0, output: output)
}

private actor TLSProvisioningRunner: SetupCommandRunning {
    private var recorded: [SetupCommand] = []
    private let shellStatus: Int32
    private let shellError: Data
    private let shellThrows: SetupCommandError?
    private let createFiles: Bool

    init(
        shellStatus: Int32 = 0,
        shellError: Data = Data(),
        shellThrows: SetupCommandError? = nil,
        createFiles: Bool = true
    ) {
        self.shellStatus = shellStatus
        self.shellError = shellError
        self.shellThrows = shellThrows
        self.createFiles = createFiles
    }

    func run(_ command: SetupCommand) async throws -> SetupCommandResult {
        recorded.append(command)
        if command.executable == "/usr/bin/openssl" {
            if createFiles {
                guard let certificateIndex = command.arguments.firstIndex(of: "-out"),
                      let keyIndex = command.arguments.firstIndex(of: "-keyout") else {
                    throw SetupCommandError.launchFailed
                }
                try Data("test-certificate".utf8).write(
                    to: URL(fileURLWithPath: command.arguments[certificateIndex + 1]))
                try Data("test-private-key".utf8).write(
                    to: URL(fileURLWithPath: command.arguments[keyIndex + 1]))
            }
            return SetupCommandResult(exitStatus: 0, output: Data())
        }
        if command.executable == "/usr/bin/osascript" {
            if let shellThrows {
                throw shellThrows
            }
            if shellStatus == 0 {
                return SetupCommandResult(
                    exitStatus: 0,
                    output: Data("\n\(PrivilegedInvocationMarker.shellStatus(testNonce))0\n".utf8))
            }
            return SetupCommandResult(
                exitStatus: 0,
                output: Data("\n\(PrivilegedInvocationMarker.shellStatus(testNonce))\(shellStatus)\n".utf8),
                errorOutput: shellError)
        }
        throw SetupCommandError.launchFailed
    }

    func commands() -> [SetupCommand] { recorded }
}

private func stagedShellScript(from appleScript: String) -> String? {
    guard let start = appleScript.range(of: "printf '%s' '")?.upperBound,
          let end = appleScript[start...].range(of: "' | /usr/bin/base64 -D")?.lowerBound else {
        return nil
    }
    guard let data = Data(base64Encoded: String(appleScript[start..<end])) else {
        return nil
    }
    return String(data: data, encoding: .utf8)
}

private func base64Request(from script: String) -> Data? {
    guard let start = script.range(of: "printf '%s' '")?.upperBound,
          let end = script[start...].range(of: "' |")?.lowerBound else {
        return nil
    }
    return Data(base64Encoded: String(script[start..<end]))
}

@Suite("Local server install client")
struct LocalServerInstallClientTests {
    @Test("Capabilities are read directly without an administrator prompt")
    func capabilitiesAreDirect() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let capabilities = try ServerInstallTestSupport.capabilities()
        let data = try InstallerJSON.encoder().encode(capabilities)
        let runner = ScriptedCommandRunner([
            .success(SetupCommandResult(exitStatus: 0, output: data))
        ])
        let client = makeClient(helper: helper, runner: runner)

        let result = try await client.capabilities()
        #expect(result.supportedActions.contains("install"))
        let commands = await runner.commands()
        #expect(commands.count == 1)
        #expect(commands[0].executable == "/usr/bin/env")
        #expect(commands[0].arguments == ["RUST_LOG=error", helper.path, "installer", "capabilities-v2"])
        #expect(commands[0].input.isEmpty)
    }

    @Test("Preflight uses osascript administrator authorization and bounded JSON")
    func preflightUsesPrivilegedHelper() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let configuration = ServerInstallTestSupport.configuration()
        let preflight = try ServerInstallTestSupport.preflight(configuration: configuration)
        let data = try InstallerJSON.encoder().encode(preflight)
        let runner = ScriptedCommandRunner([.success(helperOutput(data))])
        let client = makeClient(helper: helper, runner: runner)

        let package = TrustedServerPackage.testFixture(helperURL: helper)
        let result = try await client.preflight(configuration: configuration, package: package)
        #expect(result.ok)

        let commands = await runner.commands()
        #expect(commands.count == 1)
        #expect(commands[0].executable == "/usr/bin/osascript")
        #expect(commands[0].arguments.count == 2)
        let script = commands[0].arguments[1]
        #expect(script.contains("with administrator privileges"))
        guard let shell = stagedShellScript(from: script),
              shell.contains(helper.path),
              let request = base64Request(from: shell),
              let object = try JSONSerialization.jsonObject(with: request) as? [String: Any] else {
            Issue.record("Could not recover the bounded JSON request")
            return
        }
        let deploymentKind = (object["configuration"] as? [String: Any])?["deployment_kind"] as? String
        let contractVersion = object["contract_version"] as? Int
        #expect(contractVersion == 2)
        #expect(deploymentKind == "macos_launchd")
    }

    @Test("Apply sends confirm, reviewed digest, package path, and state directory")
    func applySendsReviewedContract() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let configuration = ServerInstallTestSupport.configuration()
        let plan = try ServerInstallTestSupport.planResult(configuration: configuration)
        let status = try ServerInstallTestSupport.operationStatus(configuration: configuration)
        let data = try InstallerJSON.encoder().encode(status)
        let runner = ScriptedCommandRunner([.success(helperOutput(data))])
        let client = makeClient(helper: helper, runner: runner)
        let preflight = try ServerInstallTestSupport.preflight(configuration: configuration)

        _ = try await client.apply(
            configuration: configuration,
            preflight: preflight,
            plan: plan,
            package: .testFixture(helperURL: helper))

        let commands = await runner.commands()
        #expect(commands.count == 1)
        #expect(commands[0].arguments[1].contains("--state-dir"))
        guard let script = commands[0].arguments.last,
              let shell = stagedShellScript(from: script),
              let request = base64Request(from: shell),
              let object = try JSONSerialization.jsonObject(with: request) as? [String: Any] else {
            Issue.record("Could not recover the apply request")
            return
        }
        let product = (object["plan"] as? [String: Any])?["product"] as? String
        let confirm = object["confirm"] as? Bool
        let reviewedDigest = object["reviewed_plan_digest"] as? String
        let packageDirectory = object["package_dir"] as? String
        let verifyKey = object["verify_key"] as? String
        #expect(confirm == true)
        #expect(reviewedDigest == String(repeating: "d", count: 64))
        #expect(packageDirectory?.hasPrefix(ServerInstallContract.payloadStagingRoot + "/") == true)
        #expect(packageDirectory?.hasSuffix("/package") == true)
        #expect(verifyKey == String(repeating: "a", count: 64))
        #expect(product == "hs-server")
        #expect(shell.contains(ServerInstallContract.payloadStagingRoot))
        #expect(shell.contains("shasum -a 256"))
        #expect(shell.contains("staged helper bytes do not match"))
        #expect(shell.contains("staged package manifest does not match"))
        #expect(shell.contains("stage_refuse"))
    }

    @Test("Cancel binds the recorded operation identity and confirmation")
    func cancelSendsOperationIdentity() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let configuration = ServerInstallTestSupport.configuration()
        let status = try ServerInstallTestSupport.operationStatus(
            state: "cancelled",
            serviceInstalled: false,
            operationId: "operation-9")
        let data = try InstallerJSON.encoder().encode(status)
        let runner = ScriptedCommandRunner([.success(helperOutput(data))])
        let client = makeClient(helper: helper, runner: runner)

        _ = try await client.cancel(
            configuration: configuration,
            operationId: "operation-9",
            confirmUnverifiedCompletion: false,
            package: .testFixture(helperURL: helper))

        let commands = await runner.commands()
        #expect(commands.count == 1)
        #expect(commands[0].arguments[1].contains("--state-dir"))
        guard let script = commands[0].arguments.last,
              let shell = stagedShellScript(from: script),
              let request = base64Request(from: shell),
              let object = try JSONSerialization.jsonObject(with: request) as? [String: Any] else {
            Issue.record("Could not recover the cancel request")
            return
        }
        let operationId = object["operation_id"] as? String
        let confirm = object["confirm"] as? Bool
        let confirmUnverified = object["confirm_unverified_completion"] as? Bool
        #expect(operationId == "operation-9")
        #expect(confirm == true)
        #expect(confirmUnverified == false)
    }

    @Test("A dismissed administrator prompt is a cancellation, not a result")
    func authorizationCancellation() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = ScriptedCommandRunner([
            .success(SetupCommandResult(
                exitStatus: 1,
                output: Data(),
                errorOutput: Data("execution error: User canceled. (-128)".utf8)))
        ])
        let client = makeClient(helper: helper, runner: runner)
        await #expect(throws: LocalServerInstallError.authorizationCancelled) {
            try await client.preflight(
                configuration: ServerInstallTestSupport.configuration(),
                package: .testFixture(helperURL: helper))
        }
    }

    @Test("Staged payload refusal is a returned refusal before the helper runs")
    func stagedPayloadRefusal() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let output = Data("""
        \n\(PrivilegedInvocationMarker.stagingRefusal(testNonce))staged helper bytes do not match the verified helper
        \n\(PrivilegedInvocationMarker.helperStatus(testNonce))0
        """.utf8)
        let runner = ScriptedCommandRunner([
            .success(SetupCommandResult(exitStatus: 0, output: output))
        ])
        let client = makeClient(helper: helper, runner: runner)
        do {
            _ = try await client.preflight(
                configuration: ServerInstallTestSupport.configuration(),
                package: .testFixture(helperURL: helper))
            Issue.record("Expected a staged payload refusal")
        } catch let error as LocalServerInstallError {
            guard case .returnedRefusal(let detail) = error else {
                Issue.record("Expected returnedRefusal, got \(error)")
                return
            }
            #expect(detail.contains("staged helper bytes"))
        }
    }

    @Test("Privileged preflight script pins and stages helper bytes before execution")
    func preflightStagesHelper() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let configuration = ServerInstallTestSupport.configuration()
        let preflight = try ServerInstallTestSupport.preflight(configuration: configuration)
        let data = try InstallerJSON.encoder().encode(preflight)
        let runner = ScriptedCommandRunner([.success(helperOutput(data))])
        let client = makeClient(helper: helper, runner: runner)
        let package = TrustedServerPackage.testFixture(helperURL: helper)

        _ = try await client.preflight(configuration: configuration, package: package)

        let commands = await runner.commands()
        guard let shell = stagedShellScript(from: commands[0].arguments[1]) else {
            Issue.record("Could not recover the staged helper script")
            return
        }
        #expect(shell.contains(ServerInstallContract.payloadStagingRoot))
        #expect(shell.contains("shasum -a 256"))
        #expect(shell.contains(package.helperSha256))
        #expect(shell.contains("stage_refuse"))
        #expect(shell.contains("staged helper bytes do not match the verified helper"))
        #expect(shell.contains("install -m 0755 -o root -g wheel"))
        #expect(shell.contains("trap cleanup"))
        #expect(shell.contains("root_uid"))
        #expect(shell.contains("root_mode"))
        #expect(shell.contains("the staging directory already exists"))
    }

    @Test("A nonzero helper status is an honest failure")
    func helperFailure() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = ScriptedCommandRunner([
            .success(SetupCommandResult(
                exitStatus: 0,
                output: Data("\n\(PrivilegedInvocationMarker.helperStatus(testNonce))2\n".utf8),
                errorOutput: Data("no independently trusted release root is configured".utf8)))
        ])
        let client = makeClient(helper: helper, runner: runner)
        await #expect(throws: LocalServerInstallError.helperFailed(
            status: 2,
            detail: "no independently trusted release root is configured")) {
            try await client.preflight(
                configuration: ServerInstallTestSupport.configuration(),
                package: .testFixture(helperURL: helper))
        }
    }

    @Test("Missing completion marker is an invalid response")
    func missingMarker() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = ScriptedCommandRunner([
            .success(SetupCommandResult(exitStatus: 0, output: Data("{\"contract_version\":2}".utf8)))
        ])
        let client = makeClient(helper: helper, runner: runner)
        await #expect(throws: LocalServerInstallError.self) {
            try await client.preflight(
                configuration: ServerInstallTestSupport.configuration(),
                package: .testFixture(helperURL: helper))
        }
    }

    @Test("Timeout and output bounds are mapped without claiming success")
    func timeoutAndOutputBounds() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let timeoutRunner = ScriptedCommandRunner([.failure(.timedOut)])
        let timeoutClient = makeClient(helper: helper, runner: timeoutRunner)
        await #expect(throws: LocalServerInstallError.timedOut) {
            try await timeoutClient.preflight(
                configuration: ServerInstallTestSupport.configuration(),
                package: .testFixture(helperURL: helper))
        }

        let overflowRunner = ScriptedCommandRunner([.failure(.outputExceeded)])
        let overflowClient = makeClient(helper: helper, runner: overflowRunner)
        await #expect(throws: LocalServerInstallError.outputExceeded) {
            try await overflowClient.preflight(
                configuration: ServerInstallTestSupport.configuration(),
                package: .testFixture(helperURL: helper))
        }
    }

    @Test("A missing helper never launches osascript")
    func missingHelperStopsBeforePrompt() async throws {
        let runner = ScriptedCommandRunner([])
        let helper = FileManager.default.temporaryDirectory
            .appendingPathComponent("missing-helper-\(UUID().uuidString)")
            .appendingPathComponent("hs-server")
        let client = makeClient(helper: helper, runner: runner)
        await #expect(throws: LocalServerInstallError.self) {
            try await client.preflight(
                configuration: ServerInstallTestSupport.configuration(),
                package: .testFixture(helperURL: helper))
        }
        let commands = await runner.commands()
        #expect(commands.isEmpty)
    }

    @Test("Development TLS is generated then installed through one privileged shell")
    func developmentTLSProvisioning() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = TLSProvisioningRunner()
        let client = makeClient(helper: helper, runner: runner)

        _ = try await client.provisionDevelopmentTLSIfNeeded()

        let commands = await runner.commands()
        #expect(commands.count == 2)
        #expect(commands[0].executable == "/usr/bin/openssl")
        #expect(commands[0].arguments.contains("-extensions"))
        #expect(commands[1].executable == "/usr/bin/osascript")
        guard let shell = stagedShellScript(from: commands[1].arguments[1]) else {
            Issue.record("Could not recover the TLS install script")
            return
        }
        #expect(shell.contains("if [ -L \"$tls\" ] || [ -e \"$tls\" ]"))
        #expect(shell.contains("/etc/helicoid/tls"))
        #expect(shell.contains("-m 0600"))
        #expect(shell.contains("-o root -g wheel"))
        #expect(shell.contains("exit 0"))
    }

    @Test("Development TLS provisioning failure is honest and never reports success")
    func developmentTLSProvisioningFailure() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = TLSProvisioningRunner(
            shellStatus: 52,
            shellError: Data("install refused".utf8))
        let client = makeClient(helper: helper, runner: runner)

        await #expect(throws: LocalServerInstallError.self) {
            _ = try await client.provisionDevelopmentTLSIfNeeded()
        }
    }

    @Test("Existing unverified TLS is left untouched and reported")
    func developmentTLSExistingUnverified() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = TLSProvisioningRunner(shellStatus: 42)
        let client = makeClient(helper: helper, runner: runner)

        let result = try await client.provisionDevelopmentTLSIfNeeded()
        #expect(result == .existingUnverifiedMaterial)
        let commands = await runner.commands()
        guard let appleScript = commands.last?.arguments.last,
              let shell = stagedShellScript(from: appleScript) else {
            Issue.record("Could not recover the TLS install script")
            return
        }
        #expect(shell.contains("exit 42"))
        #expect(shell.contains(".helicoid-development-tls-v1"))
        #expect(shell.contains("created_tls=1"))
        #expect(shell.contains("cert_installed=1"))
        #expect(shell.contains("key_installed=1"))
        #expect(shell.contains("marker_installed=1"))
        #expect(shell.contains("/bin/rmdir \"$tls\""))
        #expect(!shell.contains("rm -rf '/etc/helicoid/tls'"))
    }

    @Test("Privileged TLS timeout after dispatch is an unknown outcome")
    func developmentTLSTimeoutUnknown() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = TLSProvisioningRunner(shellThrows: .timedOut)
        let client = makeClient(helper: helper, runner: runner)

        do {
            _ = try await client.provisionDevelopmentTLSIfNeeded()
            Issue.record("Expected an unknown TLS outcome")
        } catch let error as LocalServerInstallError {
            guard case .privilegedOutcomeUnknown = error else {
                Issue.record("Expected privilegedOutcomeUnknown, got \(error)")
                return
            }
        }
    }

    @Test("Development TLS script pins source digests and stages root-owned copies")
    func developmentTLSScriptPinsDigests() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = TLSProvisioningRunner()
        let client = makeClient(helper: helper, runner: runner)
        _ = try await client.provisionDevelopmentTLSIfNeeded()

        let commands = await runner.commands()
        guard let appleScript = commands.last?.arguments.last,
              let shell = stagedShellScript(from: appleScript) else {
            Issue.record("Could not recover the TLS install script")
            return
        }
        let certificateHash = ServerPackageVerifier.sha256(Data("test-certificate".utf8))
        let privateKeyHash = ServerPackageVerifier.sha256(Data("test-private-key".utf8))
        #expect(shell.contains("stage="))
        #expect(shell.contains(ServerInstallContract.payloadStagingRoot))
        #expect(shell.contains("actual_cert="))
        #expect(shell.contains("actual_key="))
        #expect(shell.contains(certificateHash))
        #expect(shell.contains(privateKeyHash))
        #expect(shell.contains("install -d -m 0700 -o root -g wheel"))
        #expect(shell.contains("if [ -L \"$tls\" ] || [ -e \"$tls\" ]"))
        #expect(shell.contains("check_root_file"))
        #expect(shell.contains("exit 42"))
        #expect(shell.contains("exit 43"))
        #expect(shell.contains("marker_tmp"))
        #expect(shell.contains("/bin/mv -f"))
        if let certRange = shell.range(of: "\"$tls/fullchain.pem\" || exit 90"),
           let markerWrite = shell.range(of: "printf 'helicoid-development-tls-v1"),
           let markerRename = shell.range(of: "/bin/mv -f \"$marker_tmp\" \"$marker\"") {
            #expect(certRange.lowerBound < markerWrite.lowerBound)
            #expect(markerWrite.lowerBound < markerRename.lowerBound)
        } else {
            Issue.record("Expected certificate install before atomic marker rename")
        }
    }

    @Test("A signal-style TLS installer status is an unknown outcome")
    func developmentTLSSignalUnknown() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = TLSProvisioningRunner(shellStatus: 137)
        let client = makeClient(helper: helper, runner: runner)

        do {
            _ = try await client.provisionDevelopmentTLSIfNeeded()
            Issue.record("Expected an unknown TLS outcome")
        } catch let error as LocalServerInstallError {
            guard case .privilegedOutcomeUnknown = error else {
                Issue.record("Expected privilegedOutcomeUnknown, got \(error)")
                return
            }
        }
    }

    @Test("Existing owned TLS that is not exact root-owned 0600 fails closed untouched")
    func developmentTLSExistingOwnedInvalid() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = TLSProvisioningRunner(shellStatus: 43)
        let client = makeClient(helper: helper, runner: runner)

        do {
            _ = try await client.provisionDevelopmentTLSIfNeeded()
            Issue.record("Expected a refusal for inexact existing TLS")
        } catch let error as LocalServerInstallError {
            guard case .developmentTLSProvisioningFailed(let detail) = error else {
                Issue.record("Expected developmentTLSProvisioningFailed, got \(error)")
                return
            }
            #expect(detail.contains("left untouched"))
        }
    }

    @Test("Development TLS generator that writes no files is refused")
    func developmentTLSGeneratorWithoutFiles() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = TLSProvisioningRunner(createFiles: false)
        let client = makeClient(helper: helper, runner: runner)

        await #expect(throws: LocalServerInstallError.self) {
            _ = try await client.provisionDevelopmentTLSIfNeeded()
        }
    }

    @Test("Only the final nonce-bound status marker is trusted")
    func markerMustBeFinal() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let configuration = ServerInstallTestSupport.configuration()
        let preflight = try ServerInstallTestSupport.preflight(configuration: configuration)
        let status = PrivilegedInvocationMarker.helperStatus(testNonce)
        let preflightJSON = try InstallerJSON.encoder().encode(preflight)
        let preflightText = String(decoding: preflightJSON, as: UTF8.self)
        let forgedFirst = Data("""
        \(preflightText)
        \n\(status)0
        \n\(status)2
        """.utf8)
        let runner = ScriptedCommandRunner([
            .success(SetupCommandResult(exitStatus: 0, output: forgedFirst))
        ])
        let client = makeClient(helper: helper, runner: runner)

        do {
            _ = try await client.preflight(
                configuration: configuration,
                package: .testFixture(helperURL: helper))
            Issue.record("Expected the final status to win")
        } catch let error as LocalServerInstallError {
            guard case .helperFailed(let status, _) = error else {
                Issue.record("Expected helperFailed, got \(error)")
                return
            }
            #expect(status == 2)
        }
    }

    @Test("A status marker followed by more output is not accepted")
    func statusMarkerMustBeLast() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let configuration = ServerInstallTestSupport.configuration()
        let preflight = try ServerInstallTestSupport.preflight(configuration: configuration)
        let status = PrivilegedInvocationMarker.helperStatus(testNonce)
        var output = try InstallerJSON.encoder().encode(preflight)
        output.append(Data("\n\(status)0\ntrailing data\n".utf8))
        let runner = ScriptedCommandRunner([
            .success(SetupCommandResult(exitStatus: 0, output: output))
        ])
        let client = makeClient(helper: helper, runner: runner)

        await #expect(throws: LocalServerInstallError.self) {
            _ = try await client.preflight(
                configuration: configuration,
                package: .testFixture(helperURL: helper))
        }
    }

    @Test("A staging refusal with extra payload is not trusted")
    func malformedStagingRefusal() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let refusal = PrivilegedInvocationMarker.stagingRefusal(testNonce)
        let status = PrivilegedInvocationMarker.helperStatus(testNonce)
        let output = Data("""
        \n\(refusal)staged helper bytes do not match
        \nnot part of a refusal
        \n\(status)0
        """.utf8)
        let runner = ScriptedCommandRunner([
            .success(SetupCommandResult(exitStatus: 0, output: output))
        ])
        let client = makeClient(helper: helper, runner: runner)

        do {
            _ = try await client.preflight(
                configuration: ServerInstallTestSupport.configuration(),
                package: .testFixture(helperURL: helper))
            Issue.record("Expected an invalid response")
        } catch let error as LocalServerInstallError {
            guard case .invalidResponse = error else {
                Issue.record("Expected invalidResponse, got \(error)")
                return
            }
        }
    }

    @Test("A signal-style helper status is an unknown outcome")
    func signalStatusIsUnknown() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let status = PrivilegedInvocationMarker.helperStatus(testNonce)
        let output = Data("\n\(status)137\n".utf8)
        let runner = ScriptedCommandRunner([
            .success(SetupCommandResult(exitStatus: 0, output: output))
        ])
        let client = makeClient(helper: helper, runner: runner)

        do {
            _ = try await client.preflight(
                configuration: ServerInstallTestSupport.configuration(),
                package: .testFixture(helperURL: helper))
            Issue.record("Expected an unknown outcome")
        } catch let error as LocalServerInstallError {
            guard case .privilegedOutcomeUnknown = error else {
                Issue.record("Expected privilegedOutcomeUnknown, got \(error)")
                return
            }
        }
    }

    @Test("configuration-v2 null means no recorded operation")
    func storedConfigurationNull() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let status = PrivilegedInvocationMarker.helperStatus(testNonce)
        let runner = ScriptedCommandRunner([
            .success(SetupCommandResult(
                exitStatus: 0,
                output: Data("null\n\(status)0\n".utf8)))
        ])
        let client = makeClient(helper: helper, runner: runner)

        let configuration = try await client.storedConfiguration(
            package: .testFixture(helperURL: helper))
        #expect(configuration == nil)
        let commands = await runner.commands()
        guard let shell = stagedShellScript(from: commands[0].arguments[1]) else {
            Issue.record("Could not recover the configuration-v2 script")
            return
        }
        #expect(shell.contains("configuration-v2"))
        #expect(shell.contains("--state-dir"))
    }

    @Test("configuration-v2 returns the exact recorded configuration")
    func storedConfigurationDecodes() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let expected = ServerInstallTestSupport.configuration()
        let status = PrivilegedInvocationMarker.helperStatus(testNonce)
        var output = try InstallerJSON.encoder().encode(expected)
        output.append(Data("\n\(status)0\n".utf8))
        let runner = ScriptedCommandRunner([
            .success(SetupCommandResult(exitStatus: 0, output: output))
        ])
        let client = makeClient(helper: helper, runner: runner)

        let configuration = try await client.storedConfiguration(
            package: .testFixture(helperURL: helper))
        #expect(configuration == expected)
    }

    @Test("Shell quoting keeps paths with apostrophes and spaces literal")
    func shellQuoting() {
        #expect(PrivilegedHelperInvocation.shellQuote("/tmp/a b's") == "'/tmp/a b'\\''s'")
        #expect(PrivilegedHelperInvocation.appleScriptLiteral("a\"b\\c") == "\"a\\\"b\\\\c\"")
    }
}
