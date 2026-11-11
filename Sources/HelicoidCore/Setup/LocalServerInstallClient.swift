import Darwin
import Foundation

/// Production boundary for the packaged `hs-server installer` lifecycle.
///
/// Every mutating or root-observing command is run through macOS Authorization
/// Services via `osascript` + `do shell script ... with administrator
/// privileges`. The helper receives bounded JSON on stdin. A unique completion
/// marker keeps helper stdout parsing independent of AppleScript error text.
struct LocalServerInstallClient: Sendable {
    static let operationTimeLimit: TimeInterval = 120
    static let statusTimeLimit: TimeInterval = 60
    static let capabilitiesTimeLimit: TimeInterval = 30

    let helperURL: URL
    let stateDirectory: String
    let runner: any SetupCommandRunning
    /// Unique per invocation. It binds wrapper control markers to this process
    /// so helper stdout cannot spoof a completion or staging refusal.
    let markerNonce: @Sendable () -> String

    init(
        helperURL: URL,
        stateDirectory: String = ServerInstallContract.installerStateDirectory,
        runner: any SetupCommandRunning = SystemSetupCommandRunner(),
        markerNonce: @escaping @Sendable () -> String = { PrivilegedInvocationMarker.randomNonce() }
    ) {
        self.helperURL = helperURL
        self.stateDirectory = stateDirectory
        self.runner = runner
        self.markerNonce = markerNonce
    }

    func capabilities() async throws -> InstallerCapabilities {
        try await capabilities(helperURL: helperURL)
    }

    func capabilities(package: TrustedServerPackage) async throws -> InstallerCapabilities {
        let expected = try Self.expectedHelperDigest(for: package)
        let actual = try ServerPackageVerifier.sha256File(
            package.helperURL,
            maxBytes: 512 * 1024 * 1024)
        guard actual == expected else {
            throw LocalServerInstallError.returnedRefusal(
                "The helper bytes changed after package verification. No privileged command was run.")
        }
        return try await capabilities(helperURL: package.helperURL)
    }

    private func capabilities(helperURL: URL) async throws -> InstallerCapabilities {
        guard BundledServerPackageProvider.isExecutableFileWithoutSymlink(helperURL) else {
            throw LocalServerInstallError.helperUnavailable("The packaged helper is missing or not executable.")
        }
        let result: SetupCommandResult
        do {
            result = try await runner.run(SetupCommand(
                executable: "/usr/bin/env",
                arguments: ["RUST_LOG=error", helperURL.path, "installer", "capabilities-v2"],
                timeoutSeconds: Self.capabilitiesTimeLimit,
                outputLimit: ServerInstallContract.maximumHelperResponseBytes))
        } catch let error as SetupCommandError {
            throw Self.map(error)
        } catch {
            throw LocalServerInstallError.helperUnavailable("The helper could not be started.")
        }
        guard result.exitStatus == 0 else {
            throw LocalServerInstallError.helperFailed(
                status: result.exitStatus,
                detail: Self.boundedDiagnostic(result))
        }
        let json = InstallerJSON.jsonObjectData(from: result.output) ?? result.output
        return try decode(InstallerCapabilities.self, from: json)
    }

    static func expectedHelperDigest(for package: TrustedServerPackage) throws -> String {
        if !package.helperSha256.isEmpty {
            guard PrivilegedHelperInvocation.isSHA256Hex(package.helperSha256) else {
                throw LocalServerInstallError.invalidConfiguration(
                    "The verified helper digest is malformed.")
            }
            return package.helperSha256.lowercased()
        }
        return try ServerPackageVerifier.sha256File(
            package.helperURL,
            maxBytes: 512 * 1024 * 1024)
    }

    static func stagedPackagePath(stagingName: String) -> String {
        ServerInstallContract.payloadStagingRoot + "/" + stagingName + "/package"
    }

    func preflight(
        configuration: InstallerDeploymentConfiguration
    ) async throws -> InstallerPreflightResult {
        throw LocalServerInstallError.packageUnavailable(
            "A verified package is required before privileged preflight.")
    }

    func preflight(
        configuration: InstallerDeploymentConfiguration,
        package: TrustedServerPackage
    ) async throws -> InstallerPreflightResult {
        let input = InstallerPreflightInput(
            contractVersion: ServerInstallContract.lifecycleVersion,
            configuration: configuration)
        let request = try encode(input)
        let data = try await runPrivileged(
            arguments: ["installer", "preflight-v2"],
            request: request,
            package: package,
            stagingName: UUID().uuidString,
            stagePackage: false,
            timeout: Self.operationTimeLimit)
        return try decode(InstallerPreflightResult.self, from: data)
    }

    func plan(
        configuration: InstallerDeploymentConfiguration,
        preflight: InstallerPreflightResult,
        package: TrustedServerPackage
    ) async throws -> InstallerPlanResult {
        let stagingName = UUID().uuidString
        let stagedPackage = Self.stagedPackagePath(stagingName: stagingName)
        let input = InstallerPlanInput(
            contractVersion: ServerInstallContract.lifecycleVersion,
            configuration: configuration,
            preflight: preflight,
            packageDirectory: stagedPackage)
        let request = try encode(input)
        let data = try await runPrivileged(
            arguments: [
                "installer", "plan-v2",
                "--package-dir", stagedPackage,
                "--verify-key", package.verifyingKeyHex,
            ],
            request: request,
            package: package,
            stagingName: stagingName,
            stagePackage: true,
            timeout: Self.operationTimeLimit)
        return try decode(InstallerPlanResult.self, from: data)
    }

    func apply(
        configuration: InstallerDeploymentConfiguration,
        preflight: InstallerPreflightResult,
        plan: InstallerPlanResult,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus {
        guard plan.ok,
              let installPlan = plan.plan,
              let reviewedPlanDigest = plan.reviewedPlanDigest else {
            throw LocalServerInstallError.invalidConfiguration(
                "The reviewed plan did not include a plan and reviewed-plan digest.")
        }
        let stagingName = UUID().uuidString
        let stagedPackage = Self.stagedPackagePath(stagingName: stagingName)
        let input = InstallerApplyInput(
            contractVersion: ServerInstallContract.lifecycleVersion,
            configuration: configuration,
            preflight: preflight,
            plan: installPlan,
            reviewedPlanDigest: reviewedPlanDigest,
            confirm: true,
            packageDirectory: stagedPackage,
            verifyingKeyHex: package.verifyingKeyHex)
        let request = try encode(input)
        let data = try await runPrivileged(
            arguments: ["installer", "apply-v2", "--state-dir", stateDirectory],
            request: request,
            package: package,
            stagingName: stagingName,
            stagePackage: true,
            timeout: Self.operationTimeLimit)
        return try decode(InstallerOperationStatus.self, from: data)
    }

    func status(
        configuration: InstallerDeploymentConfiguration
    ) async throws -> InstallerOperationStatus {
        throw LocalServerInstallError.packageUnavailable(
            "A verified package is required before privileged status.")
    }

    func status(
        configuration: InstallerDeploymentConfiguration,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus {
        let input = InstallerStatusInput(
            contractVersion: ServerInstallContract.lifecycleVersion,
            configuration: configuration)
        let request = try encode(input)
        let data = try await runPrivileged(
            arguments: ["installer", "status-v2", "--state-dir", stateDirectory],
            request: request,
            package: package,
            stagingName: UUID().uuidString,
            stagePackage: false,
            timeout: Self.statusTimeLimit)
        return try decode(InstallerOperationStatus.self, from: data)
    }

    func cancel(
        configuration: InstallerDeploymentConfiguration,
        operationId: String,
        confirmUnverifiedCompletion: Bool
    ) async throws -> InstallerOperationStatus {
        throw LocalServerInstallError.packageUnavailable(
            "A verified package is required before privileged cancellation.")
    }

    func cancel(
        configuration: InstallerDeploymentConfiguration,
        operationId: String,
        confirmUnverifiedCompletion: Bool,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus {
        let input = InstallerCancelInput(
            contractVersion: ServerInstallContract.lifecycleVersion,
            configuration: configuration,
            operationId: operationId,
            confirm: true,
            confirmUnverifiedCompletion: confirmUnverifiedCompletion)
        let request = try encode(input)
        let data = try await runPrivileged(
            arguments: ["installer", "cancel-v2", "--state-dir", stateDirectory],
            request: request,
            package: package,
            stagingName: UUID().uuidString,
            stagePackage: false,
            timeout: Self.operationTimeLimit)
        return try decode(InstallerOperationStatus.self, from: data)
    }

    /// Reads the exact configuration recorded by the durable v2 operation
    /// record. `null` means no v2 operation is recorded. This is read-only and
    /// lets a restarted Manager recover status/removal identity without local
    /// persistence.
    func storedConfiguration(package: TrustedServerPackage) async throws -> InstallerDeploymentConfiguration? {
        let data = try await runPrivileged(
            arguments: ["installer", "configuration-v2", "--state-dir", stateDirectory],
            request: Data(),
            package: package,
            stagingName: UUID().uuidString,
            stagePackage: false,
            requireJSONObject: false,
            timeout: Self.statusTimeLimit)
        let text = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if text == "null" {
            return nil
        }
        return try decode(InstallerDeploymentConfiguration.self, from: data)
    }

    /// Development-only convenience: create disposable self-signed TLS for
    /// literal 127.0.0.1 when the fixed operator TLS path is absent.
    ///
    /// Existing TLS material is never modified or overwritten. The generated
    /// certificate/key are installed root-owned 0600 in a root-owned 0700
    /// directory, matching what the server's reviewed plan validates. This is
    /// not production or public PKI material.
    func provisionDevelopmentTLSIfNeeded() async throws -> DevelopmentTLSProvisioningResult {
        let temp = FileManager.default.temporaryDirectory
            .appendingPathComponent("helicoid-development-tls-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: temp,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: NSNumber(value: 0o700)])
        } catch {
            throw LocalServerInstallError.developmentTLSPreparationFailed(
                "a private temporary directory could not be created")
        }
        defer { try? FileManager.default.removeItem(at: temp) }

        let config = temp.appendingPathComponent("openssl.cnf")
        let certificate = temp.appendingPathComponent("fullchain.pem")
        let privateKey = temp.appendingPathComponent("private-key.pem")
        do {
            try Data(DevelopmentTLSMaterial.opensslConfiguration.utf8).write(to: config, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: 0o600)],
                ofItemAtPath: config.path)
        } catch {
            throw LocalServerInstallError.developmentTLSPreparationFailed(
                "the temporary OpenSSL configuration could not be written")
        }

        let generation: SetupCommandResult
        do {
            generation = try await runner.run(SetupCommand(
                executable: "/usr/bin/openssl",
                arguments: DevelopmentTLSMaterial.opensslArguments(
                    configPath: config.path,
                    certificatePath: certificate.path,
                    privateKeyPath: privateKey.path),
                timeoutSeconds: 60,
                outputLimit: 65_536))
        } catch let error as SetupCommandError {
            throw Self.mapDevelopmentTLS(error, stage: "generate")
        } catch {
            throw LocalServerInstallError.developmentTLSPreparationFailed(
                "the TLS generator could not be started")
        }
        guard generation.exitStatus == 0,
              Self.isNonemptyRegularFile(certificate),
              Self.isNonemptyRegularFile(privateKey) else {
            throw LocalServerInstallError.developmentTLSPreparationFailed(
                Self.boundedDiagnostic(generation))
        }

        let certificateSHA256: String
        let privateKeySHA256: String
        do {
            certificateSHA256 = try ServerPackageVerifier.sha256File(
                certificate,
                maxBytes: 64 * 1024)
            privateKeySHA256 = try ServerPackageVerifier.sha256File(
                privateKey,
                maxBytes: 64 * 1024)
        } catch {
            throw LocalServerInstallError.developmentTLSPreparationFailed(
                "the generated TLS material could not be digested")
        }

        let nonce = markerNonce()
        let installScript = DevelopmentTLSMaterial.installScript(
            stagingRoot: ServerInstallContract.payloadStagingRoot,
            stagingName: "tls-\(UUID().uuidString)",
            certificatePath: certificate.path,
            privateKeyPath: privateKey.path,
            certificateSHA256: certificateSHA256,
            privateKeySHA256: privateKeySHA256)
        let command = try PrivilegedShellInvocation.setupCommand(
            shellScript: installScript,
            timeoutSeconds: ServerInstallContract.maximumTimeoutSeconds,
            statusMarker: PrivilegedInvocationMarker.shellStatus(nonce))

        let installation: SetupCommandResult
        do {
            installation = try await runner.run(command)
        } catch let error as SetupCommandError {
            switch error {
            case .timedOut, .cancelled, .outputExceeded:
                throw LocalServerInstallError.privilegedOutcomeUnknown(
                    "The privileged development TLS installer was dispatched but its completion was not observed (\(error)). It may have installed, partially installed, or left no material. Inspect /etc/helicoid/tls before retrying.")
            default:
                throw LocalServerInstallError.developmentTLSProvisioningFailed(
                    "the privileged TLS installer could not be started")
            }
        } catch {
            if Task.isCancelled {
                throw LocalServerInstallError.privilegedOutcomeUnknown(
                    "The privileged development TLS installer was dispatched but local waiting was cancelled. Its outcome is unknown.")
            }
            throw LocalServerInstallError.privilegedOutcomeUnknown(
                "The privileged development TLS installer was dispatched but its transport failed. Its outcome is unknown.")
        }

        let status = try Self.shellStatus(
            installation,
            stage: "install",
            marker: PrivilegedInvocationMarker.shellStatus(nonce))
        switch status {
        case 0:
            return .provisioned
        case 42:
            return .existingUnverifiedMaterial
        case 43:
            throw LocalServerInstallError.developmentTLSProvisioningFailed(
                "existing development TLS material is not the exact root-owned 0600 layout; it was left untouched")
        default:
            throw LocalServerInstallError.developmentTLSProvisioningFailed(
                "the privileged development TLS installer returned exit \(status); it did not report success")
        }
    }

    // MARK: - Invocation

    private func runPrivileged(
        arguments: [String],
        request: Data,
        package: TrustedServerPackage,
        stagingName: String,
        stagePackage: Bool,
        requireJSONObject: Bool = true,
        timeout: TimeInterval
    ) async throws -> Data {
        guard BundledServerPackageProvider.isExecutableFileWithoutSymlink(package.helperURL) else {
            throw LocalServerInstallError.helperUnavailable(
                "The packaged helper is missing or not executable.")
        }
        let nonce = markerNonce()
        let expectedHelper = try Self.expectedHelperDigest(for: package)
        let command = try PrivilegedHelperInvocation.setupCommand(
            helperURL: package.helperURL,
            expectedHelperSHA256: expectedHelper,
            installerArguments: arguments,
            request: request,
            packageSourceURL: stagePackage ? package.packageDirectory : nil,
            expectedPackageManifestSHA256: stagePackage ? package.manifestSha256 : nil,
            expectedPackageArtifactSHA256: stagePackage ? package.artifactSha256 : nil,
            expectedPackageArtifactSizeBytes: stagePackage ? package.artifactSizeBytes : nil,
            stagingName: stagingName,
            nonce: nonce,
            timeoutSeconds: min(timeout, ServerInstallContract.maximumTimeoutSeconds))
        let result: SetupCommandResult
        do {
            result = try await runner.run(command)
        } catch let error as SetupCommandError {
            throw Self.map(error)
        } catch {
            if Task.isCancelled {
                throw LocalServerInstallError.cancelled
            }
            throw LocalServerInstallError.helperUnavailable("The privileged helper could not be started.")
        }
        return try Self.extractResponse(
            result,
            nonce: nonce,
            requireJSONObject: requireJSONObject)
    }

    private func encode<T: Encodable>(_ value: T) throws -> Data {
        do {
            return try InstallerJSON.encoder().encode(value)
        } catch {
            throw LocalServerInstallError.invalidConfiguration(
                "The installer request could not be encoded.")
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try InstallerJSON.decoder().decode(type, from: data)
        } catch {
            throw LocalServerInstallError.invalidResponse(
                "The helper response did not match the installer v2 contract.")
        }
    }

    // MARK: - Result classification

    private static func map(_ error: SetupCommandError) -> LocalServerInstallError {
        switch error {
        case .timedOut: .timedOut
        case .cancelled: .cancelled
        case .outputExceeded: .outputExceeded
        case .invalidBounds: .invalidConfiguration("The installer request exceeded its bounds.")
        case .launchFailed: .helperUnavailable("The helper process could not be launched.")
        case .inputFailed: .invalidConfiguration("The installer request could not be delivered.")
        }
    }

    private static func mapDevelopmentTLS(
        _ error: SetupCommandError,
        stage: String
    ) -> LocalServerInstallError {
        switch error {
        case .timedOut:
            return .developmentTLSProvisioningFailed("\(stage) timed out")
        case .cancelled:
            return .cancelled
        case .outputExceeded:
            return .developmentTLSProvisioningFailed("\(stage) produced too much output")
        default:
            return .developmentTLSProvisioningFailed("\(stage) could not be started")
        }
    }

    private static func shellStatus(
        _ result: SetupCommandResult,
        stage: String,
        marker: String
    ) throws -> Int32 {
        guard result.exitStatus == 0 else {
            if result.exitStatus >= 128 {
                throw LocalServerInstallError.privilegedOutcomeUnknown(
                    "\(stage) ended without a normal exit status (\(result.exitStatus)); its outcome is unknown.")
            }
            let detail = boundedCombinedDiagnostic(result)
            let lower = detail.lowercased()
            if lower.contains("user canceled") || lower.contains("user cancelled")
                || lower.contains("(-128)") {
                throw LocalServerInstallError.authorizationCancelled
            }
            throw LocalServerInstallError.developmentTLSProvisioningFailed(
                detail.isEmpty ? "\(stage) failed" : detail)
        }
        let text = normalizedOutput(result)
        guard let parsed = finalStatus(in: text, marker: marker) else {
            throw LocalServerInstallError.privilegedOutcomeUnknown(
                "\(stage) completed without a verifiable final status marker; its outcome is unknown")
        }
        guard parsed.status < 128 else {
            throw LocalServerInstallError.privilegedOutcomeUnknown(
                "\(stage) ended with signal-style status \(parsed.status); its outcome is unknown")
        }
        return parsed.status
    }

    static func isNonemptyRegularFile(_ url: URL) -> Bool {
        var info = stat()
        return lstat(url.path, &info) == 0
            && (info.st_mode & S_IFMT) == S_IFREG
            && info.st_size > 0
    }

    /// Requires the nonce-bound marker to be the final non-empty line and
    /// permits only whitespace after it. This prevents helper output from
    /// spoofing a completion marker.
    static func finalStatus(
        in text: String,
        marker: String
    ) -> (payload: Substring, status: Int32)? {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard let lastNonEmpty = lines.lastIndex(where: {
            !$0.trimmingCharacters(in: .whitespaces).isEmpty
        }) else {
            return nil
        }
        let line = lines[lastNonEmpty].trimmingCharacters(in: .whitespaces)
        guard line.hasPrefix(marker) else { return nil }
        let digits = line.dropFirst(marker.count)
        guard !digits.isEmpty,
              digits.allSatisfy(\.isNumber),
              let status = Int32(digits) else {
            return nil
        }
        return (text[..<lines[lastNonEmpty].startIndex], status)
    }

    /// A staging refusal is trusted only when the entire payload before the
    /// final status line is exactly one nonce-bound refusal line.
    static func strictRefusalDetail(
        payload: Substring,
        marker: String
    ) -> String? {
        let lines = payload.split(separator: "\n", omittingEmptySubsequences: true)
        guard lines.count == 1, lines[0].hasPrefix(marker) else { return nil }
        return String(lines[0].dropFirst(marker.count))
            .trimmingCharacters(in: .whitespaces)
    }

    private static func extractResponse(
        _ result: SetupCommandResult,
        nonce: String,
        requireJSONObject: Bool
    ) throws -> Data {
        let statusMarker = PrivilegedInvocationMarker.helperStatus(nonce)
        let refusalMarker = PrivilegedInvocationMarker.stagingRefusal(nonce)
        guard result.exitStatus == 0 else {
            if result.exitStatus >= 128 {
                throw LocalServerInstallError.privilegedOutcomeUnknown(
                    "The privileged installer ended without a normal exit status (\(result.exitStatus)). Its outcome is unknown.")
            }
            let detail = boundedCombinedDiagnostic(result)
            let lower = detail.lowercased()
            if lower.contains("user canceled") || lower.contains("user cancelled")
                || lower.contains("(-128)") {
                throw LocalServerInstallError.authorizationCancelled
            }
            throw LocalServerInstallError.authorizationFailed(
                detail.isEmpty ? "macOS did not grant administrator authorization." : detail)
        }

        let text = normalizedOutput(result)
        guard let parsed = finalStatus(in: text, marker: statusMarker) else {
            if text.contains(refusalMarker) {
                throw LocalServerInstallError.invalidResponse(
                    "The privileged wrapper produced a malformed staging refusal.")
            }
            throw LocalServerInstallError.invalidResponse(
                "The privileged installer did not report a final completion status.")
        }
        if let detail = strictRefusalDetail(payload: parsed.payload, marker: refusalMarker) {
            guard parsed.status == 0 else {
                throw LocalServerInstallError.invalidResponse(
                    "The privileged wrapper reported a staging refusal with a non-zero status.")
            }
            throw LocalServerInstallError.returnedRefusal(
                detail.isEmpty
                    ? "The privileged wrapper refused the staged payload before running the helper."
                    : "The privileged wrapper refused the staged payload before running the helper: \(detail)")
        }
        if String(parsed.payload).contains(refusalMarker) {
            throw LocalServerInstallError.invalidResponse(
                "The privileged wrapper produced an ambiguous staging refusal.")
        }
        guard parsed.status < 128 else {
            throw LocalServerInstallError.privilegedOutcomeUnknown(
                "The privileged installer ended with signal-style status \(parsed.status). Its outcome is unknown.")
        }
        guard parsed.status == 0 else {
            throw LocalServerInstallError.helperFailed(
                status: parsed.status,
                detail: boundedDiagnostic(result))
        }
        let payload = Data(parsed.payload.utf8)
        guard requireJSONObject else { return payload }
        guard let json = InstallerJSON.jsonObjectData(from: payload) else {
            throw LocalServerInstallError.invalidResponse(
                "The privileged installer returned no JSON result.")
        }
        return json
    }

    private static func normalizedOutput(_ result: SetupCommandResult) -> String {
        String(decoding: result.output, as: UTF8.self)
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
    }

    private static func boundedDiagnostic(_ result: SetupCommandResult) -> String {
        let stderrText = String(decoding: result.errorOutput, as: UTF8.self)
        let stdoutText = String(decoding: result.output, as: UTF8.self)
        return sanitized(stderrText.isEmpty ? stdoutText : stderrText)
    }

    private static func boundedCombinedDiagnostic(_ result: SetupCommandResult) -> String {
        sanitized(String(decoding: result.errorOutput, as: UTF8.self)
            + String(decoding: result.output, as: UTF8.self))
    }

    static func sanitized(_ text: String) -> String {
        let printable = text.unicodeScalars
            .filter { scalar in
                scalar.value == 0x0A || (scalar.value >= 0x20 && scalar.value != 0x7F)
            }
            .map { String($0) }
            .joined()
        return String(printable.prefix(2_048))
    }
}

/// Builds the bounded AppleScript/shell invocation. Internal so tests can
/// inspect exactly what is handed to `osascript`.
/// Nonce-bound control markers. The nonce is generated by the Manager and is
/// never passed to the helper, so helper output cannot forge a completion or
/// staging-refusal marker.
enum PrivilegedInvocationMarker {
    static func randomNonce() -> String {
        UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    }

    static func helperStatus(_ nonce: String) -> String {
        "__HELICOID_STATUS_\(nonce)__:"
    }

    static func stagingRefusal(_ nonce: String) -> String {
        "__HELICOID_STAGING_REFUSAL_\(nonce)__:"
    }

    static func shellStatus(_ nonce: String) -> String {
        "__HELICOID_SHELL_STATUS_\(nonce)__:"
    }
}

enum PrivilegedHelperInvocation {
    static func setupCommand(
        helperURL: URL,
        expectedHelperSHA256: String,
        installerArguments: [String],
        request: Data,
        packageSourceURL: URL?,
        expectedPackageManifestSHA256: String?,
        expectedPackageArtifactSHA256: String?,
        expectedPackageArtifactSizeBytes: UInt64?,
        stagingName: String,
        nonce: String,
        timeoutSeconds: TimeInterval
    ) throws -> SetupCommand {
        guard helperURL.path.hasPrefix("/"),
              !containsControlCharacters(helperURL.path) else {
            throw LocalServerInstallError.invalidConfiguration(
                "The installer helper path must be absolute and contain no control characters.")
        }
        guard installerArguments.allSatisfy({ !containsControlCharacters($0) }) else {
            throw LocalServerInstallError.invalidConfiguration(
                "Installer arguments must not contain control characters.")
        }
        guard isSHA256Hex(expectedHelperSHA256) else {
            throw LocalServerInstallError.invalidConfiguration(
                "The expected helper digest is not a SHA-256 hex value.")
        }
        guard !stagingName.isEmpty,
              stagingName.count <= 64,
              stagingName.utf8.allSatisfy({ byte in
                  (byte >= 0x30 && byte <= 0x39)
                      || (byte >= 0x41 && byte <= 0x5A)
                      || (byte >= 0x61 && byte <= 0x7A)
                      || byte == 0x2D
              }) else {
            throw LocalServerInstallError.invalidConfiguration(
                "The staging name is not a bounded identifier.")
        }

        // The wrapper pins the exact verified bytes. The helper still performs
        // the Ed25519 manifest verification against its own compile-time pin;
        // this staging step prevents replacement between UI verification and
        // the administrator prompt.
        let root = ServerInstallContract.payloadStagingRoot
        let stage = root + "/" + stagingName
        let statusMarker = PrivilegedInvocationMarker.helperStatus(nonce)
        let refusalMarker = PrivilegedInvocationMarker.stagingRefusal(nonce)
        var script = """
        umask 077
        root=\(shellQuote(root))
        stage=\(shellQuote(stage))
        stage_owned=0
        err=""
        cleanup() {
          [ -z "$err" ] || /bin/rm -f "$err"
          if [ "$stage_owned" = 1 ]; then
            /bin/rm -rf "$stage"
          fi
        }
        trap cleanup 0 1 2 15
        stage_refuse() {
          printf '\n\(refusalMarker)%s\n' "$1"
          printf '\n\(statusMarker)0\n'
          exit 0
        }
        if [ -L "$root" ] || { [ -e "$root" ] && [ ! -d "$root" ]; }; then
          stage_refuse "staging root is not a real directory"
        fi
        if ! /usr/bin/install -d -m 0700 -o root -g wheel "$root"; then
          stage_refuse "cannot create the root-owned staging directory"
        fi
        root_uid=$(/usr/bin/stat -f '%u' "$root") || stage_refuse "cannot inspect the staging root owner"
        root_mode=$(/usr/bin/stat -f '%Lp' "$root") || stage_refuse "cannot inspect the staging root mode"
        if [ "$root_uid" != "0" ] || [ "$root_mode" != "700" ]; then
          stage_refuse "the staging root is not root-owned 0700"
        fi
        if [ -e "$stage" ] || [ -L "$stage" ]; then
          stage_refuse "the staging directory already exists; refusing to reuse it"
        fi
        stage_owned=1
        if ! /usr/bin/install -d -m 0700 -o root -g wheel "$stage"; then
          stage_refuse "cannot create the per-run staging directory"
        fi
        if ! /usr/bin/install -m 0755 -o root -g wheel \(shellQuote(helperURL.path)) "$stage/hs-server"; then
          stage_refuse "cannot stage the helper"
        fi
        actual_helper=$(/usr/bin/shasum -a 256 "$stage/hs-server" | /usr/bin/awk '{print $1}') \
          || stage_refuse "cannot digest the staged helper"
        if [ "$actual_helper" != \(shellQuote(expectedHelperSHA256.lowercased())) ]; then
          stage_refuse "staged helper bytes do not match the verified helper"
        fi
        """

        if let packageSourceURL {
            guard let expectedPackageManifestSHA256,
                  let expectedPackageArtifactSHA256,
                  let expectedPackageArtifactSizeBytes,
                  isSHA256Hex(expectedPackageManifestSHA256),
                  isSHA256Hex(expectedPackageArtifactSHA256),
                  expectedPackageArtifactSizeBytes > 0,
                  packageSourceURL.path.hasPrefix("/") else {
                throw LocalServerInstallError.invalidConfiguration(
                    "A staged package requires manifest, artifact, and size expectations.")
            }
            let source = packageSourceURL.path
            script += """

        if ! /usr/bin/install -d -m 0700 -o root -g wheel "$stage/package" "$stage/package/artifacts"; then
          stage_refuse "cannot create the staged package directory"
        fi
        if ! /usr/bin/install -m 0644 -o root -g wheel \(shellQuote(source + "/manifest.json")) "$stage/package/manifest.json"; then
          stage_refuse "cannot stage the package manifest"
        fi
        if ! /usr/bin/install -m 0644 -o root -g wheel \(shellQuote(source + "/manifest.sig")) "$stage/package/manifest.sig"; then
          stage_refuse "cannot stage the package signature"
        fi
        if ! /usr/bin/install -m 0755 -o root -g wheel \(shellQuote(source + "/artifacts/hs-server")) "$stage/package/artifacts/hs-server"; then
          stage_refuse "cannot stage the package artifact"
        fi
        actual_manifest=$(/usr/bin/shasum -a 256 "$stage/package/manifest.json" | /usr/bin/awk '{print $1}') \
          || stage_refuse "cannot digest the staged manifest"
        if [ "$actual_manifest" != \(shellQuote(expectedPackageManifestSHA256.lowercased())) ]; then
          stage_refuse "staged package manifest does not match the verified manifest"
        fi
        actual_artifact=$(/usr/bin/shasum -a 256 "$stage/package/artifacts/hs-server" | /usr/bin/awk '{print $1}') \
          || stage_refuse "cannot digest the staged artifact"
        if [ "$actual_artifact" != \(shellQuote(expectedPackageArtifactSHA256.lowercased())) ]; then
          stage_refuse "staged package artifact does not match the verified artifact"
        fi
        actual_size=$(/usr/bin/stat -f '%z' "$stage/package/artifacts/hs-server") \
          || stage_refuse "cannot inspect the staged artifact size"
        if [ "$actual_size" != "\(expectedPackageArtifactSizeBytes)" ]; then
          stage_refuse "staged package artifact size does not match the verified artifact"
        fi
        """
        }

        let base64 = request.base64EncodedString()
        var invocation = ""
        if !base64.isEmpty {
            invocation += "printf '%s' '\(base64)' | /usr/bin/base64 -D | "
        }
        invocation += "RUST_LOG=error \(shellQuote(stage + "/hs-server")) "
        invocation += installerArguments.map { shellQuote($0) }.joined(separator: " ")
        invocation += " 2>\"$err\"; status=$?"
        script += """

        err=$(/usr/bin/mktemp /private/tmp/helicoid-installer.XXXXXX) \
          || stage_refuse "cannot create a diagnostic staging file"
        \(invocation)
        /bin/cat "$err" >&2
        printf '\n\(statusMarker)%d\n' "$status"
        exit 0
        """

        return try PrivilegedShellInvocation.setupCommand(
            shellScript: script,
            timeoutSeconds: timeoutSeconds,
            outputLimit: ServerInstallContract.maximumHelperResponseBytes,
            appendShellStatus: false)
    }

    static func isSHA256Hex(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy(\.isHexDigit)
    }

    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func appleScriptLiteral(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\"\(escaped)\""
    }

    private static func containsControlCharacters(_ value: String) -> Bool {
        value.unicodeScalars.contains { scalar in
            scalar.value < 0x20 || scalar.value == 0x7F
        }
    }
}

/// Runs one bounded shell script as root. Used only for development-only TLS
/// material installation, never for package or helper trust decisions.
enum PrivilegedShellInvocation {
    static func setupCommand(
        shellScript: String,
        timeoutSeconds: TimeInterval,
        outputLimit: Int = 65_536,
        appendShellStatus: Bool = true,
        statusMarker: String = PrivilegedInvocationMarker.shellStatus(PrivilegedInvocationMarker.randomNonce())
    ) throws -> SetupCommand {
        guard !shellScript.unicodeScalars.contains(where: { scalar in
            scalar.value < 0x20 && scalar.value != 0x0A
        }) else {
            throw LocalServerInstallError.invalidConfiguration(
                "The privileged shell script contains unsupported control characters.")
        }
        let encoded = Data(shellScript.utf8).base64EncodedString()
        var command = "printf '%s' '\(encoded)' | /usr/bin/base64 -D | /bin/sh -s"
        if appendShellStatus {
            command += "; status=$?; printf '\\n\(statusMarker)%d\\n' \"$status\"; exit 0"
        }
        let script = "do shell script \(PrivilegedHelperInvocation.appleScriptLiteral(command)) with administrator privileges"
        return SetupCommand(
            executable: "/usr/bin/osascript",
            arguments: ["-e", script],
            timeoutSeconds: max(1, min(timeoutSeconds, ServerInstallContract.maximumTimeoutSeconds)),
            outputLimit: outputLimit)
    }
}

/// Disposable development TLS generation. Certificate is self-signed for
/// literal 127.0.0.1 and is not production or public PKI material.
enum DevelopmentTLSMaterial {
    static let opensslConfiguration = """
    [req]
    distinguished_name = dn
    x509_extensions = v3_req
    prompt = no
    [dn]
    CN = 127.0.0.1
    [v3_req]
    subjectAltName = IP:127.0.0.1
    basicConstraints = critical,CA:FALSE
    keyUsage = critical,digitalSignature,keyEncipherment
    extendedKeyUsage = serverAuth
    """

    static func opensslArguments(
        configPath: String,
        certificatePath: String,
        privateKeyPath: String
    ) -> [String] {
        [
            "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "2",
            "-keyout", privateKeyPath,
            "-out", certificatePath,
            "-config", configPath,
            "-extensions", "v3_req",
        ]
    }

    static func installScript(
        stagingRoot: String,
        stagingName: String,
        certificatePath: String,
        privateKeyPath: String,
        certificateSHA256: String,
        privateKeySHA256: String
    ) -> String {
        let root = PrivilegedHelperInvocation.shellQuote(stagingRoot)
        let stage = PrivilegedHelperInvocation.shellQuote(stagingRoot + "/" + stagingName)
        let certSource = PrivilegedHelperInvocation.shellQuote(certificatePath)
        let keySource = PrivilegedHelperInvocation.shellQuote(privateKeyPath)
        let certExpected = PrivilegedHelperInvocation.shellQuote(certificateSHA256.lowercased())
        let keyExpected = PrivilegedHelperInvocation.shellQuote(privateKeySHA256.lowercased())
        return """
        umask 077
        root=\(root)
        stage=\(stage)
        tls='/etc/helicoid/tls'
        marker='/etc/helicoid/tls/.helicoid-development-tls-v1'
        marker_tmp='/etc/helicoid/tls/.helicoid-development-tls-v1.tmp'
        stage_owned=0
        created_base=0
        created_tls=0
        cert_installed=0
        key_installed=0
        marker_installed=0
        marker_tmp_installed=0
        cleanup() {
          if [ "$marker_tmp_installed" = 1 ]; then /bin/rm -f "$marker_tmp"; fi
          if [ "$marker_installed" = 1 ]; then /bin/rm -f "$marker"; fi
          if [ "$cert_installed" = 1 ]; then /bin/rm -f "$tls/fullchain.pem"; fi
          if [ "$key_installed" = 1 ]; then /bin/rm -f "$tls/private-key.pem"; fi
          if [ "$stage_owned" = 1 ]; then /bin/rm -rf "$stage"; fi
          if [ "$created_tls" = 1 ]; then /bin/rmdir "$tls" 2>/dev/null || true; fi
          if [ "$created_base" = 1 ]; then /bin/rmdir '/etc/helicoid' 2>/dev/null || true; fi
        }
        trap cleanup 0 1 2 15

        check_root_file() {
          # exact root-owned regular 0600 file with non-zero size
          [ -L "$1" ] && return 1
          [ -f "$1" ] || return 1
          uid=$(/usr/bin/stat -f '%u' "$1" 2>/dev/null) || return 1
          mode=$(/usr/bin/stat -f '%Lp' "$1" 2>/dev/null) || return 1
          size=$(/usr/bin/stat -f '%z' "$1" 2>/dev/null) || return 1
          [ "$uid" = "0" ] && [ "$mode" = "600" ] && [ "$size" -gt 0 ]
        }

        if [ -L "$root" ] || { [ -e "$root" ] && [ ! -d "$root" ]; }; then exit 70; fi
        /usr/bin/install -d -m 0700 -o root -g wheel "$root" || exit 71
        root_uid=$(/usr/bin/stat -f '%u' "$root") || exit 72
        root_mode=$(/usr/bin/stat -f '%Lp' "$root") || exit 73
        if [ "$root_uid" != "0" ] || [ "$root_mode" != "700" ]; then exit 74; fi
        if [ -e "$stage" ] || [ -L "$stage" ]; then exit 75; fi
        stage_owned=1
        /usr/bin/install -d -m 0700 -o root -g wheel "$stage" || exit 76
        /usr/bin/install -m 0600 -o root -g wheel \(certSource) "$stage/fullchain.pem" || exit 77
        /usr/bin/install -m 0600 -o root -g wheel \(keySource) "$stage/private-key.pem" || exit 78
        actual_cert=$(/usr/bin/shasum -a 256 "$stage/fullchain.pem" | /usr/bin/awk '{print $1}') || exit 79
        if [ "$actual_cert" != \(certExpected) ]; then exit 80; fi
        actual_key=$(/usr/bin/shasum -a 256 "$stage/private-key.pem" | /usr/bin/awk '{print $1}') || exit 81
        if [ "$actual_key" != \(keyExpected) ]; then exit 82; fi

        if [ -L "$tls" ] || [ -e "$tls" ]; then
          if [ -L "$tls" ] || [ ! -d "$tls" ]; then exit 42; fi
          if [ -e "$marker" ] || [ -L "$marker" ]; then
            # This workflow's own material. Require the exact root-owned
            # regular-file layout; never repair or delete anything here.
            tls_uid=$(/usr/bin/stat -f '%u' "$tls" 2>/dev/null) || exit 43
            tls_mode=$(/usr/bin/stat -f '%Lp' "$tls" 2>/dev/null) || exit 43
            [ "$tls_uid" = "0" ] && [ "$tls_mode" = "700" ] || exit 43
            check_root_file "$marker" || exit 43
            [ "$(/bin/cat "$marker" 2>/dev/null)" = 'helicoid-development-tls-v1' ] || exit 43
            check_root_file "$tls/fullchain.pem" || exit 43
            check_root_file "$tls/private-key.pem" || exit 43
            exit 0
          fi
          # Existing material without our marker is operator-owned or unknown.
          # Leave it exactly as found; the reviewed plan validates it.
          exit 42
        fi

        if [ -L '/etc/helicoid' ]; then exit 85; fi
        if [ -e '/etc/helicoid' ] && [ ! -d '/etc/helicoid' ]; then exit 85; fi
        if [ ! -e '/etc/helicoid' ]; then
          created_base=1
          /usr/bin/install -d -m 0700 -o root -g wheel '/etc/helicoid' || exit 86
        fi
        if [ -e "$tls" ] || [ -L "$tls" ]; then exit 75; fi
        created_tls=1
        /usr/bin/install -d -m 0700 -o root -g wheel "$tls" || exit 87

        # Mark cleanup before each install so a partial write is removed.
        cert_installed=1
        /usr/bin/install -m 0600 -o root -g wheel "$stage/fullchain.pem" "$tls/fullchain.pem" || exit 90
        key_installed=1
        /usr/bin/install -m 0600 -o root -g wheel "$stage/private-key.pem" "$tls/private-key.pem" || exit 91
        check_root_file "$tls/fullchain.pem" || exit 95
        check_root_file "$tls/private-key.pem" || exit 95

        # The marker is written atomically last: a complete certificate and key
        # layout is what makes the development TLS material recognizable.
        marker_tmp_installed=1
        printf 'helicoid-development-tls-v1\n' > "$marker_tmp" || exit 92
        /bin/chmod 0600 "$marker_tmp" || exit 93
        check_root_file "$marker_tmp" || exit 95
        marker_installed=1
        /bin/mv -f "$marker_tmp" "$marker" || exit 94
        marker_tmp_installed=0
        check_root_file "$marker" || exit 95

        cert_installed=0
        key_installed=0
        marker_installed=0
        created_tls=0
        created_base=0
        exit 0
        """
    }
}

/// Model-facing install service. The Manager always uses the bundled release
/// provider; tests supply bounded fakes through the same seam.
protocol ServerInstallServicing: Sendable {
    var installPayloadPresent: Bool { get }
    var installPayloadKind: ServerInstallPayloadKind { get }
    func packageAvailability() async -> ServerPackageAvailability
    func provisionDevelopmentTLSIfNeeded() async throws -> DevelopmentTLSProvisioningResult
    func capabilities() async throws -> InstallerCapabilities
    func capabilities(package: TrustedServerPackage) async throws -> InstallerCapabilities
    func preflight(configuration: InstallerDeploymentConfiguration) async throws -> InstallerPreflightResult
    func preflight(
        configuration: InstallerDeploymentConfiguration,
        package: TrustedServerPackage
    ) async throws -> InstallerPreflightResult
    func plan(
        configuration: InstallerDeploymentConfiguration,
        preflight: InstallerPreflightResult,
        package: TrustedServerPackage
    ) async throws -> InstallerPlanResult
    func apply(
        configuration: InstallerDeploymentConfiguration,
        preflight: InstallerPreflightResult,
        plan: InstallerPlanResult,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus
    func status(configuration: InstallerDeploymentConfiguration) async throws -> InstallerOperationStatus
    func status(
        configuration: InstallerDeploymentConfiguration,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus
    /// Recovers the exact durable operation configuration after a restart.
    /// `nil` means no v2 operation is recorded.
    func storedConfiguration(
        package: TrustedServerPackage
    ) async throws -> InstallerDeploymentConfiguration?
    func cancel(
        configuration: InstallerDeploymentConfiguration,
        operationId: String,
        confirmUnverifiedCompletion: Bool
    ) async throws -> InstallerOperationStatus
    func cancel(
        configuration: InstallerDeploymentConfiguration,
        operationId: String,
        confirmUnverifiedCompletion: Bool,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus
}

extension ServerInstallServicing {
    var installPayloadKind: ServerInstallPayloadKind { .release }
    func provisionDevelopmentTLSIfNeeded() async throws -> DevelopmentTLSProvisioningResult {
        throw LocalServerInstallError.developmentTLSProvisioningFailed(
            "This install service does not implement development TLS provisioning.")
    }
    func capabilities(package: TrustedServerPackage) async throws -> InstallerCapabilities {
        try await capabilities()
    }
    func preflight(
        configuration: InstallerDeploymentConfiguration,
        package: TrustedServerPackage
    ) async throws -> InstallerPreflightResult {
        try await preflight(configuration: configuration)
    }
    func status(
        configuration: InstallerDeploymentConfiguration,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus {
        try await status(configuration: configuration)
    }
    func storedConfiguration(
        package: TrustedServerPackage
    ) async throws -> InstallerDeploymentConfiguration? {
        nil
    }
    func cancel(
        configuration: InstallerDeploymentConfiguration,
        operationId: String,
        confirmUnverifiedCompletion: Bool,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus {
        try await cancel(
            configuration: configuration,
            operationId: operationId,
            confirmUnverifiedCompletion: confirmUnverifiedCompletion)
    }
}

struct BundledServerInstallService: ServerInstallServicing {
    let provider: BundledServerPackageProvider
    let stateDirectory: String
    let runner: any SetupCommandRunning
    private let payloadPresent: Bool
    private let payloadKindValue: ServerInstallPayloadKind

    init(
        provider: BundledServerPackageProvider = BundledServerPackageProvider(),
        stateDirectory: String = ServerInstallContract.installerStateDirectory,
        runner: any SetupCommandRunning = SystemSetupCommandRunner()
    ) {
        self.provider = provider
        self.stateDirectory = stateDirectory
        self.runner = runner
        self.payloadPresent = provider.installPayloadPresent
        self.payloadKindValue = provider.payloadKind
    }

    var installPayloadPresent: Bool { payloadPresent }
    var installPayloadKind: ServerInstallPayloadKind { payloadKindValue }

    func packageAvailability() async -> ServerPackageAvailability {
        let provider = self.provider
        return await Task.detached(priority: .userInitiated) {
            provider.availability()
        }.value
    }

    func provisionDevelopmentTLSIfNeeded() async throws -> DevelopmentTLSProvisioningResult {
        let installClient = try client()
        return try await installClient.provisionDevelopmentTLSIfNeeded()
    }

    func capabilities() async throws -> InstallerCapabilities {
        let installClient = try client()
        return try await installClient.capabilities()
    }

    func capabilities(package: TrustedServerPackage) async throws -> InstallerCapabilities {
        let installClient = try client()
        return try await installClient.capabilities(package: package)
    }

    func preflight(
        configuration: InstallerDeploymentConfiguration
    ) async throws -> InstallerPreflightResult {
        let availability = await packageAvailability()
        guard let package = availability.package else {
            throw LocalServerInstallError.packageUnavailable(
                "A verified package is required before privileged preflight.")
        }
        return try await preflight(configuration: configuration, package: package)
    }

    func preflight(
        configuration: InstallerDeploymentConfiguration,
        package: TrustedServerPackage
    ) async throws -> InstallerPreflightResult {
        let installClient = try client()
        return try await installClient.preflight(configuration: configuration, package: package)
    }

    func plan(
        configuration: InstallerDeploymentConfiguration,
        preflight: InstallerPreflightResult,
        package: TrustedServerPackage
    ) async throws -> InstallerPlanResult {
        let installClient = try client()
        return try await installClient.plan(
            configuration: configuration,
            preflight: preflight,
            package: package)
    }

    func apply(
        configuration: InstallerDeploymentConfiguration,
        preflight: InstallerPreflightResult,
        plan: InstallerPlanResult,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus {
        let installClient = try client()
        return try await installClient.apply(
            configuration: configuration,
            preflight: preflight,
            plan: plan,
            package: package)
    }

    func status(
        configuration: InstallerDeploymentConfiguration
    ) async throws -> InstallerOperationStatus {
        let availability = await packageAvailability()
        guard let package = availability.package else {
            throw LocalServerInstallError.packageUnavailable(
                "A verified package is required before privileged status.")
        }
        return try await status(configuration: configuration, package: package)
    }

    func status(
        configuration: InstallerDeploymentConfiguration,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus {
        let installClient = try client()
        return try await installClient.status(configuration: configuration, package: package)
    }

    func storedConfiguration(
        package: TrustedServerPackage
    ) async throws -> InstallerDeploymentConfiguration? {
        let installClient = try client()
        return try await installClient.storedConfiguration(package: package)
    }

    func cancel(
        configuration: InstallerDeploymentConfiguration,
        operationId: String,
        confirmUnverifiedCompletion: Bool
    ) async throws -> InstallerOperationStatus {
        let availability = await packageAvailability()
        guard let package = availability.package else {
            throw LocalServerInstallError.packageUnavailable(
                "A verified package is required before privileged cancellation.")
        }
        return try await cancel(
            configuration: configuration,
            operationId: operationId,
            confirmUnverifiedCompletion: confirmUnverifiedCompletion,
            package: package)
    }

    func cancel(
        configuration: InstallerDeploymentConfiguration,
        operationId: String,
        confirmUnverifiedCompletion: Bool,
        package: TrustedServerPackage
    ) async throws -> InstallerOperationStatus {
        let installClient = try client()
        return try await installClient.cancel(
            configuration: configuration,
            operationId: operationId,
            confirmUnverifiedCompletion: confirmUnverifiedCompletion,
            package: package)
    }

    private func client() throws -> LocalServerInstallClient {
        guard BundledServerPackageProvider.isExecutableFileWithoutSymlink(provider.helperURL) else {
            throw LocalServerInstallError.helperUnavailable(
                "The packaged helper is missing or not executable.")
        }
        return LocalServerInstallClient(
            helperURL: provider.helperURL,
            stateDirectory: stateDirectory,
            runner: runner)
    }
}
