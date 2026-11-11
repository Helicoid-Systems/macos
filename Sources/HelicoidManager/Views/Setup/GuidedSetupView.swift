import SwiftUI
import HelicoidCore

/// W17 Guided server setup — Mac manager: This Mac and Linux SSH (H01–H12).
/// With no verified server package this is a read-only host check (H05).
struct GuidedSetupView: View {
    @Environment(ManagerSession.self) private var session
    @State private var model = GuidedServerSetupModel(
        demoMode: Bundle.main.bundleIdentifier == "systems.helicoid.manager.setup-demo"
            || CommandLine.arguments.contains("--server-setup-demo")
    )
    @FocusState private var focusedField: Field?
    @State private var demoVerificationCode = ""

    private enum Field: Hashable {
        case sshAddress
        case networkAddress
        case deploymentName
        case administratorUsername
        case storagePath
    }

    var body: some View {
        VStack(spacing: 0) {
            if model.isDemo {
                Label("DEMO — simulated setup; nothing is installed or checked", systemImage: "eye")
                    .font(.callout.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(8)
                    .background(.yellow.opacity(0.25))
            }
            if model.isDevelopmentInstall {
                Label("DEVELOPMENT ONLY — build-pinned dev key and disposable self-signed TLS; not a production release trust root",
                      systemImage: "exclamationmark.triangle")
                    .font(.callout.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(8)
                    .background(.orange.opacity(0.20))
            }
            if session.showDevelopmentBanner {
                DevelopmentBanner()
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    ConnectionHeading(title: phaseTitle)
                    phaseForm
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(24)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            if let blocker = model.blocker {
                Label(blocker, systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .frame(maxWidth: Self.formWidth, alignment: .leading)
                    .padding(.horizontal, 24)
                    .padding(.bottom, 12)
            }

            Divider()
            HStack(spacing: 12) {
                Button("Cancel") {
                    model.reset()
                    if !model.isInstalling {
                        withAnimation(.easeOut(duration: 0.22)) {
                            session.screen = .connect
                        }
                    }
                }
                .keyboardShortcut(.cancelAction)
                .disabled(model.isInstalling)

                Spacer()

                if model.phase != .chooseHosting && model.phase != .connect {
                    Button("Back", action: goBack)
                        .disabled(model.isInstalling)
                }

                Button(nextButtonTitle, action: continueSetup)
                .keyboardShortcut(.defaultAction)
                .disabled(nextButtonDisabled)
                .help(model.canContinueFromCurrentPhase ? nextButtonTitle : continueDisabledReason)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 16)
        }
        .preference(key: SetupWindowHeightKey.self, value: contentSize.height)
        .onDisappear { model.cancelHostCheck() }
    }

    private static let formWidth: CGFloat = 472

    private var contentSize: NSSize {
        switch model.phase {
        case .chooseHosting: NSSize(width: 680, height: 340)
        case .connect: NSSize(width: 680, height: 320)
        case .hostIdentity, .checkHost: NSSize(width: 680, height: 620)
        default: NSSize(width: 680, height: 500)
        }
    }

    private var phaseTitle: String {
        switch model.phase {
        case .chooseHosting:
            return "Set Up Server"
        case .connect:
            return "Connect to Linux Server"
        case .hostIdentity, .checkHost:
            return model.route == .thisMac ? "Check This Mac" : "Check Server"
        case .network:
            return "Network"
        case .deploymentIdentity:
            return "Deployment Identity"
        case .administrator:
            return "Administrator"
        case .storage:
            return "Storage and Backups"
        case .review:
            return "Review Installation"
        case .install:
            return "Installation"
        case .ready:
            if model.isDemo || model.isServerReadyForEnrollment {
                return "Server Ready"
            }
            return "Server Installed"
        }
    }

    private var continueDisabledReason: String {
        switch model.phase {
        case .chooseHosting:
            return "Choose a hosting route before continuing."
        case .connect:
            return "Enter a valid SSH address and use key authentication."
        case .hostIdentity:
            return "Verify the SSH host identity before continuing. A changed key or refusal performs no writes."
        case .checkHost:
            return "Every required check must pass before continuing. Unknown checks block."
        case .network:
            return "Enter the server address and a valid product port."
        case .deploymentIdentity:
            return "Enter a deployment display name."
        case .administrator:
            return "Enter an administrator username."
        case .storage:
            return "Enter a storage path."
        case .install:
            if !model.installPackageAvailable {
                return model.installUnavailableNotice
            }
            return model.installProgressExplanation
        default:
            return "Complete the required fields before continuing."
        }
    }

    private var isHostCheck: Bool {
        model.phase == .hostIdentity || model.phase == .checkHost
    }

    private var requiredChecks: [String] {
        GuidedServerSetupModel.requiredHostChecks(for: model.route)
    }

    private var hostChecksPassed: Bool {
        let checksPass = requiredChecks.allSatisfy { model.hostChecks[$0] == .passed }
        switch model.route {
        case .thisMac:
            return checksPass
        case .existingLinuxSSH:
            return model.hostIdentity.isVerified && checksPass
        }
    }

    private var nextButtonTitle: String {
        switch model.phase {
        case .connect:
            return "Check Server"
        case .hostIdentity, .checkHost:
            if model.isCheckingHost {
                return "Checking"
            } else if hostChecksPassed {
                return "Continue"
            } else if model.hostChecks.isEmpty {
                return model.route == .thisMac ? "Check This Mac" : "Check Server"
            } else {
                return "Check Again"
            }
        case .review:
            return model.isDemo ? "Preview Installation" : "Install"
        case .install:
            if model.isDemo { return "Simulate Installation" }
            if model.isInstalling { return "Installing…" }
            if model.installStatusReportsReady { return "Continue" }
            switch model.installAction {
            case .start: return "Install"
            case .refreshStatus: return "Refresh Status"
            case .unavailable: return "Install Unavailable"
            case .none: return "Install Unavailable"
            }
        case .ready:
            if model.isDemo || model.isServerReadyForEnrollment {
                return "Done"
            }
            return "Not Ready"
        default:
            return "Continue"
        }
    }

    private var reviewNotice: String {
        if model.isDemo {
            return "Demo only — these changes will not be applied."
        }
        guard model.installPackageAvailable else {
            return model.installUnavailableNotice
        }
        if model.isDevelopmentInstall {
            return "DEVELOPMENT ONLY: the installer will generate disposable self-signed TLS for 127.0.0.1 if absent, then request macOS administrator authorization. Installed is not production readiness."
        }
        return "The installer will request macOS administrator authorization. No success is shown until the helper returns a verified operation status."
    }

    private var installHeadline: String {
        if model.isInstalling { return "Installing Local Server" }
        switch model.installProgress {
        case .installedUnverified(_):
            return model.installStatusReportsReady ? "Server Ready for Enrollment" : "Server Installed — Readiness Unverified"
        case .attentionRequired(_):
            return "Installation Requires Attention"
        case .cancelled(_):
            return "Installation Cancelled"
        case .failed(_), .outcomeUnknown(_):
            return "Installation Did Not Complete"
        case .refused(_):
            return "Installation Unavailable"
        case .notStarted:
            return "Install Local Server"
        default:
            return "Installing Local Server"
        }
    }

    private var installSymbol: String {
        if model.isInstalling { return "gearshape.2" }
        switch model.installProgress {
        case .installedUnverified(_):
            return model.installStatusReportsReady ? "checkmark.circle" : "externaldrive.badge.checkmark"
        case .attentionRequired(_):
            return "exclamationmark.triangle"
        case .cancelled(_):
            return "xmark.circle"
        case .failed(_), .outcomeUnknown(_):
            return "xmark.octagon"
        case .refused(_):
            return "lock.shield"
        default:
            return "arrow.down.circle"
        }
    }

    private var nextButtonDisabled: Bool {
        if model.isCheckingHost || model.isInstalling { return true }
        if model.phase == .connect || model.phase == .hostIdentity || model.phase == .checkHost {
            return !model.canContinueFromCurrentPhase
        }
        if model.phase == .install {
            if model.isDemo {
                return demoVerificationCode != "123456"
            }
            return model.installAction == .unavailable || model.installAction == .none
        }
        if model.phase == .ready {
            return !model.isDemo && !model.isServerReadyForEnrollment
        }
        return !model.canContinueFromCurrentPhase
    }

    private func continueSetup() {
        if model.phase == .chooseHosting {
            model.setStoragePath(model.route.defaultStoragePath)
            model.advance()
        } else if model.phase == .connect {
            model.advance()
            model.startHostCheck()
        } else if isHostCheck {
            if hostChecksPassed {
                if model.phase == .hostIdentity { model.advance() }
                model.advance()
            } else {
                model.startHostCheck()
            }
        } else if model.phase == .install && !model.isDemo {
            if model.installStatusReportsReady {
                model.advance()
                return
            }
            switch model.installAction {
            case .start:
                Task { await model.startInstallation() }
            case .refreshStatus:
                Task { await model.refreshInstallStatus() }
            case .unavailable, .none:
                break
            }
        } else if model.phase == .ready && model.isDemo {
            model.reset()
            session.screen = .connect
        } else {
            model.advance()
        }
    }

    private func goBack() {
        model.cancelHostCheck()
        if model.phase == .checkHost && model.route == .existingLinuxSSH { model.back() }
        model.back()
    }

    @ViewBuilder
    private var phaseForm: some View {
        switch model.phase {
        case .chooseHosting:
            VStack(alignment: .leading, spacing: 20) {
                Picker("Hosting", selection: Binding(
                    get: { model.route },
                    set: { model.setRoute($0) }
                )) {
                    Label("This Mac", systemImage: "desktopcomputer").tag(HostingRoute.thisMac)
                    if !model.isDemo {
                        Label("Existing Linux Server", systemImage: "server.rack").tag(HostingRoute.existingLinuxSSH)
                    }
                }
                .pickerStyle(.radioGroup)
                .labelsHidden()
                .accessibilityLabel("Hosting route")

                if !model.installPackageAvailable && !model.isDemo {
                    Text(model.installUnavailableNotice)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .onAppear { focusedField = nil }

        case .connect:
            VStack(alignment: .leading, spacing: 8) {
                Text("SSH address").font(.callout)
                TextField("ubuntu@server.example.com", text: Binding(
                    get: { model.sshAddress },
                    set: { model.setSSHAddress($0) }
                ))
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel("SSH address")
                .focused($focusedField, equals: .sshAddress)
                .textContentType(.username)
                Text("Uses a key from your SSH agent.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .onAppear { focusedField = .sshAddress }

        case .hostIdentity, .checkHost:
            VStack(alignment: .leading, spacing: 16) {
                if model.isCheckingHost {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Checking compatibility").foregroundStyle(.secondary)
                    }
                }

                VStack(spacing: 12) {
                    ForEach(requiredChecks, id: \.self) { name in
                        summaryCheckRow(name)
                    }
                }

                if model.route == .thisMac, model.localPreflight?.listeners.isComplete == false {
                    VStack(alignment: .leading, spacing: 4) {
                        Button("Check Ports with Administrator Access") {
                            model.startHostCheck(usingAdministratorAccess: true)
                        }
                        .disabled(model.isCheckingHost)
                        Text("macOS will ask for administrator authorization to inspect system-owned listeners.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                if model.localPreflight != nil || model.hostPreflight != nil {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Connection port")
                            TextField("Port", text: Binding(
                                get: { model.productPort },
                                set: { model.setProductPort($0) }
                            ))
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 90)
                            .accessibilityLabel("Connection port")
                        }
                        if !model.suggestedProductPorts.isEmpty {
                            HStack {
                                Text("Alternatives:")
                                ForEach(model.suggestedProductPorts, id: \.self) { port in
                                    Button(String(port)) { model.setProductPort(String(port)) }
                                }
                            }
                            .font(.caption)
                            Text("Suggestions are not reserved; an incomplete check cannot verify availability.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                DisclosureGroup("Details") {
                    VStack(alignment: .leading, spacing: 12) {
                        if model.route == .thisMac {
                            if let local = model.localPreflight {
                                Text(LocalHostPreflight.displayComputerName(local.computerName))
                                Text("\(local.osVersion)  \(local.architecture)")
                                    .foregroundStyle(.secondary)
                            } else if let failure = model.localPreflightFailure {
                                Text(failure).textSelection(.enabled)
                            }
                        } else {
                            Text(model.hostIdentity.explanation).textSelection(.enabled)
                        }
                        ForEach(requiredChecks, id: \.self) { name in
                            if case .needsAttention(let detail) = model.hostChecks[name] {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(name).fontWeight(.medium)
                                    Text(detail).foregroundStyle(.secondary).textSelection(.enabled)
                                }
                            }
                        }
                    }
                    .font(.caption)
                    .padding(.top, 8)
                }
            }

        case .network:
            Form {
                Section {
                    if model.route == .thisMac && model.isRealInstallPathEnabled {
                        Text("Local server address")
                        Text("127.0.0.1 (literal loopback only)")
                            .foregroundStyle(.secondary)
                    } else {
                        TextField("Server address", text: Binding(
                            get: { model.networkAddress },
                            set: { model.setNetworkAddress($0) }
                        ))
                        .focused($focusedField, equals: .networkAddress)
                    }
                    DisclosureGroup("Advanced") {
                        TextField("Connection port", text: Binding(
                            get: { model.productPort },
                            set: { model.setProductPort($0) }
                        ))
                        if !(model.route == .thisMac && model.isRealInstallPathEnabled) {
                            TextField("LAN scope (optional)", text: Binding(
                                get: { model.lanScope },
                                set: { model.setLanScope($0) }
                            ))
                        }
                        Text("Default: 8920. This Mac installs the literal loopback listener only.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)
            .onAppear { focusedField = .networkAddress }

        case .deploymentIdentity:
            Form {
                Section {
                    TextField("Deployment name", text: Binding(
                        get: { model.deploymentName },
                        set: { model.setDeploymentName($0) }
                    ))
                    .focused($focusedField, equals: .deploymentName)
                    if model.isPreparingManagerIdentity {
                        ProgressView("Preparing Manager identity")
                    } else if !model.generatedTrustIdentityNote.isEmpty {
                        DisclosureGroup("Manager identity") {
                            Label("Saved in Keychain", systemImage: "checkmark.shield")
                            Text(model.generatedTrustIdentityNote)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                            Text(model.isRealInstallPathEnabled
                                ? "The server service initializes its deployment identity when it starts. This installer does not bootstrap an administrator."
                                : "The server will create its own trust identity during installation.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } else if model.isDemo {
                        Label("Manager identity will be created during a real installation", systemImage: "info.circle")
                    } else {
                        Label("Manager identity unavailable", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                        Button("Retry Keychain") { Task { await model.prepareManagerIdentity() } }
                    }
                }
            }
            .formStyle(.grouped)
            .onAppear { focusedField = .deploymentName }

        case .administrator:
            Form {
                Section {
                    TextField("Administrator username", text: Binding(
                        get: { model.administratorUsername },
                        set: { model.setAdministratorUsername($0) }
                    ))
                    .focused($focusedField, equals: .administratorUsername)
                    Text(model.isRealInstallPathEnabled
                        ? "The local installer creates only the server service. First-administrator bootstrap and MFA remain a separate, not-yet-integrated step."
                        : "You’ll add an authenticator app during installation. Viewing permissions are assigned separately.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            .onAppear { focusedField = .administratorUsername }

        case .storage:
            Form {
                Section(model.route == .thisMac ? "Mac storage" : "Linux server storage") {
                    TextField("Server data folder", text: Binding(
                        get: { model.storagePath },
                        set: { model.setStoragePath($0) }
                    ), prompt: Text(model.route.defaultStoragePath))
                    .focused($focusedField, equals: .storagePath)
                    .disabled(model.route == .thisMac && model.isRealInstallPathEnabled)
                    if model.route == .thisMac && model.isRealInstallPathEnabled {
                        Text("The macOS installer uses the fixed product-owned data path \(LocalHostingOwnershipPlan.current.dataPath).")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    DisclosureGroup("Backup location (optional)") {
                        TextField("Encrypted backup folder", text: Binding(
                            get: { model.backupDestination },
                            set: { model.setBackupDestination($0) }
                        ), prompt: Text(model.route == .thisMac ? "/path/on/this/mac" : "/path/on/linux/server"))
                    }
                }
            }
            .formStyle(.grouped)
            .onAppear { focusedField = .storagePath }

        case .review:
            Form {
                Section {
                    ForEach(model.reviewChanges(), id: \.self) { line in
                        Text(line)
                            .font(.callout)
                    }
                    Text(reviewNotice)
                        .font(.caption)
                        .foregroundStyle(model.installPackageAvailable ? Color.gray : Color.orange)
                }
            }
            .formStyle(.grouped)

        case .install:
            if model.isDemo {
                VStack(alignment: .leading, spacing: 12) {
                    Label("Ready to simulate installation", systemImage: "play.circle")
                        .font(.headline)
                    Text("Demo authenticator: enter the example code 123456. Do not enter a real password or authenticator code.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    TextField("Example code: 123456", text: $demoVerificationCode)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 220)
                    Text("No server, account, authenticator, or service will be created.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else if !model.installPackageAvailable {
                VStack(alignment: .leading, spacing: 12) {
                    Label(model.route == .existingLinuxSSH
                        ? "Remote Installation Unavailable"
                        : "Signed Server Package Required",
                        systemImage: "lock.shield")
                        .font(.headline)
                    Text(model.installUnavailableNotice)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    Text("Only a payload that passed the independent release trust root, or a development build with the matching build-time pinned key, can enable installation. Nothing is installed from an unverified bundle.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("The server helper must also advertise the install capability. A helper that reports only preflight and plan is refused before any privileged install call.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            } else {
                VStack(alignment: .leading, spacing: 14) {
                    Label(installHeadline, systemImage: installSymbol)
                        .font(.headline)
                    Text(model.installProgressExplanation)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    if model.isInstalling {
                        HStack(spacing: 8) {
                            ProgressView().controlSize(.small)
                            Text("Privileged installer running")
                                .foregroundStyle(.secondary)
                        }
                    }
                    if let summary = model.installStatusSummary {
                        Text(summary)
                            .font(.callout)
                            .textSelection(.enabled)
                    }
                    if let tlsNotice = model.developmentTLSNotice {
                        Text(tlsNotice)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    if case .installedUnverified = model.installProgress {
                        Text("Installation succeeded, but this server does not expose enrollment readiness. No Continue/Done step is offered.")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                    if model.installStatusHasAttention {
                        Label("The operation requires inspection. Do not retry blindly.", systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                    HStack(spacing: 12) {
                        if model.canCancelInstallation {
                            Button("Cancel Incomplete Install", role: .destructive) {
                                Task { await model.cancelInstallation() }
                            }
                        }
                        if model.installAction == .refreshStatus && !model.isInstalling {
                            Button("Refresh Status") {
                                Task { await model.refreshInstallStatus() }
                            }
                        }
                    }
                    Text("Installed is not the same as ready for enrollment. Readiness is shown only when the installer reports verified server evidence.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

        case .ready:
            VStack(alignment: .leading, spacing: 12) {
                if model.isDemo {
                    Label("Demo setup complete", systemImage: "checkmark.circle")
                        .font(.headline)
                    Text("No server was installed, and no computer can be enrolled from this demo.")
                        .foregroundStyle(.secondary)
                } else if model.isServerReadyForEnrollment {
                    Label("Server Ready for Enrollment", systemImage: "checkmark.circle")
                        .font(.headline)
                    Text("The installed server explicitly reported readiness. Next, enroll a computer.")
                        .foregroundStyle(.secondary)
                } else {
                    Label("Readiness Not Exposed", systemImage: "exclamationmark.triangle")
                        .font(.headline)
                    Text("The installer completed, but the server did not expose enrollment readiness. No Done step is offered.")
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func summaryCheckRow(_ name: String) -> some View {
        let status = model.hostChecks[name] ?? .pending
        return HStack(spacing: 12) {
            Image(systemName: checkSymbol(status))
                .foregroundStyle(checkColor(status))
                .frame(width: 18)
                .accessibilityHidden(true)
            Text(name)
            Spacer(minLength: 12)
            Text(model.isDemo && status == .passed ? "Simulated" : checkLabel(status))
                .foregroundStyle(.secondary)
        }
        .font(.callout)
        .accessibilityElement(children: .combine)
    }

    private func checkSymbol(_ status: HostCheckStatus) -> String {
        switch status {
        case .pending, .checking: "circle.dotted"
        case .passed: "checkmark.circle"
        case .needsAttention: "exclamationmark.triangle"
        }
    }

    private func checkColor(_ status: HostCheckStatus) -> Color {
        switch status {
        case .passed: .secondary
        case .needsAttention: .orange
        default: .secondary
        }
    }

    private func checkLabel(_ status: HostCheckStatus) -> String {
        switch status {
        case .pending: "Not Checked"
        case .checking: "Checking"
        case .passed: "Passed"
        case .needsAttention: "Needs Attention"
        }
    }
}
