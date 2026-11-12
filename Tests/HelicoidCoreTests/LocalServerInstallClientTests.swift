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

private func tlsMaterialResponse(
    outcome: String = "provisioned",
    certificatePath: String = ServerInstallContract.operatorTLSCertificatePath,
    privateKeyPath: String = ServerInstallContract.operatorTLSPrivateKeyPath,
    certificateSHA256: String = String(repeating: "a", count: 64),
    privateKeySHA256: String = String(repeating: "b", count: 64),
    authorityHost: String = ServerInstallContract.developmentTLSHost,
    additional: [String: Any] = [:],
    remove: [String] = []
) throws -> Data {
    var object: [String: Any] = [
        "outcome": outcome,
        "certificate_path": certificatePath,
        "private_key_path": privateKeyPath,
        "certificate_sha256": certificateSHA256,
        "private_key_sha256": privateKeySHA256,
        "authority_host": authorityHost,
    ]
    for (key, value) in additional { object[key] = value }
    for key in remove { object.removeValue(forKey: key) }
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

private func tlsExistingResponse(
    outcome: String = "existing_unverified",
    certificatePath: String = ServerInstallContract.operatorTLSCertificatePath,
    privateKeyPath: String = ServerInstallContract.operatorTLSPrivateKeyPath,
    certificatePresent: Bool = true,
    privateKeyPresent: Bool = false,
    authorityHost: String = ServerInstallContract.developmentTLSHost,
    detail: String = "operator TLS material is present",
    additional: [String: Any] = [:],
    remove: [String] = []
) throws -> Data {
    var object: [String: Any] = [
        "outcome": outcome,
        "certificate_path": certificatePath,
        "private_key_path": privateKeyPath,
        "certificate_present": certificatePresent,
        "private_key_present": privateKeyPresent,
        "authority_host": authorityHost,
        "detail": detail,
    ]
    for (key, value) in additional { object[key] = value }
    for key in remove { object.removeValue(forKey: key) }
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

private func rawTLSResponse(_ object: [String: Any]) throws -> Data {
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
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

    @Test("Development TLS accepts provisioned and recovered outcomes")
    func developmentTLSProvisioning() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let package = TrustedServerPackage.testFixture(
            helperURL: helper,
            provenance: .development)

        for outcome in ["provisioned", "recovered"] {
            let runner = ScriptedCommandRunner([
                .success(helperOutput(try tlsMaterialResponse(outcome: outcome)))
            ])
            let client = makeClient(helper: helper, runner: runner)

            let result = try await client.provisionDevelopmentTLSIfNeeded(package: package)
            #expect(result == .provisioned)

            let commands = await runner.commands()
            #expect(commands.count == 1)
            guard let shell = stagedShellScript(from: commands[0].arguments[1]) else {
                Issue.record("Could not recover the staged TLS helper script")
                continue
            }
            #expect(shell.contains("provision-macos-tls"))
            #expect(shell.contains(package.helperSha256))
            #expect(shell.contains(ServerInstallContract.payloadStagingRoot))
            #expect(shell.contains("shasum -a 256"))
        }
    }

    @Test("Existing unverified TLS continues to the reviewed plan")
    func developmentTLSExistingUnverified() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let package = TrustedServerPackage.testFixture(
            helperURL: helper,
            provenance: .development)
        let runner = ScriptedCommandRunner([
            .success(helperOutput(try tlsExistingResponse()))
        ])
        let client = makeClient(helper: helper, runner: runner)

        let result = try await client.provisionDevelopmentTLSIfNeeded(package: package)
        #expect(result == .existingUnverifiedMaterial)
    }

    @Test("Post-dispatch TLS result validation failures are unknown outcomes")
    func developmentTLSStrictResponse() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let package = TrustedServerPackage.testFixture(
            helperURL: helper,
            provenance: .development)
        let responses: [Data] = [
            try tlsMaterialResponse(certificatePath: "/etc/helicoid/tls/other.pem"),
            try tlsMaterialResponse(authorityHost: "example.com"),
            try tlsMaterialResponse(certificateSHA256: "not-a-digest"),
            try tlsMaterialResponse(privateKeySHA256: String(repeating: "z", count: 64)),
            try tlsMaterialResponse(additional: ["note": "unexpected"]),
            try tlsMaterialResponse(remove: ["certificate_sha256"]),
            try tlsExistingResponse(certificatePath: "/etc/helicoid/tls/other.pem"),
            try tlsExistingResponse(authorityHost: "example.com"),
            try tlsExistingResponse(detail: ""),
            try tlsExistingResponse(additional: ["certificate_sha256": String(repeating: "a", count: 64)]),
            try tlsExistingResponse(remove: ["detail"]),
            try rawTLSResponse([
                "outcome": "existing_unverified",
                "certificate_path": ServerInstallContract.operatorTLSCertificatePath,
                "private_key_path": ServerInstallContract.operatorTLSPrivateKeyPath,
                "certificate_present": "yes",
                "private_key_present": true,
                "authority_host": ServerInstallContract.developmentTLSHost,
                "detail": "bad boolean type",
            ]),
            try rawTLSResponse([
                "outcome": "unknown",
                "certificate_path": ServerInstallContract.operatorTLSCertificatePath,
                "private_key_path": ServerInstallContract.operatorTLSPrivateKeyPath,
                "certificate_sha256": String(repeating: "a", count: 64),
                "private_key_sha256": String(repeating: "b", count: 64),
                "authority_host": ServerInstallContract.developmentTLSHost,
            ]),
            try rawTLSResponse(["outcome": 7]),
        ]

        for response in responses {
            let runner = ScriptedCommandRunner([.success(helperOutput(response))])
            let client = makeClient(helper: helper, runner: runner)
            do {
                _ = try await client.provisionDevelopmentTLSIfNeeded(package: package)
                Issue.record("Expected the strict TLS response to be treated as an unknown outcome")
            } catch let error as LocalServerInstallError {
                guard case .privilegedOutcomeUnknown = error else {
                    Issue.record("Expected privilegedOutcomeUnknown, got \(error)")
                    continue
                }
            }
        }
    }

    @Test("A dispatched TLS provisioner timeout is an unknown outcome")
    func developmentTLSTimeoutUnknown() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let package = TrustedServerPackage.testFixture(
            helperURL: helper,
            provenance: .development)
        let runner = ScriptedCommandRunner([.failure(.timedOut)])
        let client = makeClient(helper: helper, runner: runner)

        do {
            _ = try await client.provisionDevelopmentTLSIfNeeded(package: package)
            Issue.record("Expected an unknown TLS outcome")
        } catch let error as LocalServerInstallError {
            guard case .privilegedOutcomeUnknown = error else {
                Issue.record("Expected privilegedOutcomeUnknown, got \(error)")
                return
            }
        }
    }

    @Test("Release packages cannot request development TLS")
    func developmentTLSRequiresDevelopmentProvenance() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let package = TrustedServerPackage.testFixture(
            helperURL: helper,
            provenance: .release)
        let runner = ScriptedCommandRunner([])
        let client = makeClient(helper: helper, runner: runner)

        do {
            _ = try await client.provisionDevelopmentTLSIfNeeded(package: package)
            Issue.record("Expected a provenance refusal")
        } catch let error as LocalServerInstallError {
            guard case .developmentTLSProvisioningFailed(let detail) = error else {
                Issue.record("Expected developmentTLSProvisioningFailed, got \(error)")
                return
            }
            #expect(detail.contains("development-only"))
            #expect(detail.contains("No helper was run"))
        }
        let commands = await runner.commands()
        #expect(commands.isEmpty)
    }

    @Test("The no-package TLS entry point never executes a helper")
    func developmentTLSNoPackageGated() async throws {
        let helper = try executableHelper()
        defer { removeHelper(helper) }
        let runner = ScriptedCommandRunner([])
        let client = makeClient(helper: helper, runner: runner)

        do {
            _ = try await client.provisionDevelopmentTLSIfNeeded()
            Issue.record("Expected the no-package entry point to be gated")
        } catch let error as LocalServerInstallError {
            guard case .developmentTLSProvisioningFailed(let detail) = error else {
                Issue.record("Expected developmentTLSProvisioningFailed, got \(error)")
                return
            }
            #expect(detail.contains("verified development package"))
        }
        let commands = await runner.commands()
        #expect(commands.isEmpty)
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
