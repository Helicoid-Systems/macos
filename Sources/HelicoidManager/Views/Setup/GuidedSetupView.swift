import SwiftUI
import HelicoidCore

/// W17 Guided server setup — Mac manager: This Mac and Linux SSH (H01–H12).
/// With no verified server package this is a read-only host check (H05).
struct GuidedSetupView: View {
    @Environment(ManagerSession.self) private var session
    @State private var model = GuidedServerSetupModel()
    @FocusState private var focusedField: Field?

    private enum Field: Hashable {
        case sshAddress
        case networkAddress
        case deploymentName
        case administratorUsername
        case storagePath
    }

    var body: some View {
        VStack(spacing: 0) {
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
                    withAnimation(.easeOut(duration: 0.22)) {
                        session.screen = .connect
                    }
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                if model.phase != .chooseHosting && model.phase != .connect {
                    Button("Back", action: goBack)
                }

                Button(nextButtonTitle, action: continueSetup)
                .keyboardShortcut(.defaultAction)
                .disabled(model.isCheckingHost || (!isHostCheck && !model.canContinueFromCurrentPhase))
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
        case .chooseHosting: NSSize(width: 520, height: 280)
        case .connect: NSSize(width: 520, height: 260)
        case .hostIdentity, .checkHost: NSSize(width: 520, height: 420)
        default: NSSize(width: 520, height: 400)
        }
    }

    private var phaseTitle: String {
        switch model.phase {
        case .chooseHosting: "Set Up Server"
        case .connect: "Connect to Linux Server"
        case .hostIdentity, .checkHost: model.route == .thisMac ? "Check This Mac" : "Check Server"
        case .network: "Network"
        case .deploymentIdentity: "Deployment Identity"
        case .administrator: "Administrator"
        case .storage: "Storage and Backups"
        case .review: "Review Installation"
        case .install: "Installation"
        case .ready: "Server Ready"
        }
    }

    private var continueDisabledReason: String {
        switch model.phase {
        case .chooseHosting:
            "Choose a hosting route before continuing."
        case .connect:
            "Enter a valid SSH address and use key authentication."
        case .hostIdentity:
            "Verify the SSH host identity before continuing. A changed key or refusal performs no writes."
        case .checkHost:
            "Every required check must pass before continuing. Unknown checks block."
        case .network:
            "Enter the server address and a valid product port."
        case .deploymentIdentity:
            "Enter a deployment display name."
        case .administrator:
            "Enter an administrator username."
        case .storage:
            "Enter a storage path."
        case .install:
            "Installation is not available in this build. Setup will not claim success."
        default:
            "Complete the required fields before continuing."
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
        case .connect: "Check Server"
        case .hostIdentity, .checkHost:
            if model.isCheckingHost {
                "Checking"
            } else if hostChecksPassed {
                "Continue"
            } else if model.hostChecks.isEmpty {
                model.route == .thisMac ? "Check This Mac" : "Check Server"
            } else {
                "Check Again"
            }
        case .review: "Install"
        case .install: "Install Unavailable"
        case .ready: "Done"
        default: "Continue"
        }
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
                    Label("Existing Linux Server", systemImage: "server.rack").tag(HostingRoute.existingLinuxSSH)
                }
                .pickerStyle(.radioGroup)
                .labelsHidden()
                .accessibilityLabel("Hosting route")

                if !GuidedServerSetupModel.isServerPackageAvailable {
                    Text(GuidedServerSetupModel.packageUnavailableNotice)
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
                Section("Network") {
                    TextField("Server address", text: Binding(
                        get: { model.networkAddress },
                        set: { model.setNetworkAddress($0) }
                    ))
                    .focused($focusedField, equals: .networkAddress)
                    DisclosureGroup("Advanced") {
                        TextField("Connection port", text: Binding(
                            get: { model.productPort },
                            set: { model.setProductPort($0) }
                        ))
                        TextField("LAN scope (optional)", text: Binding(
                            get: { model.lanScope },
                            set: { model.setLanScope($0) }
                        ))
                        Text("Default: 8920.")
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
                            Text("The server will create its own trust identity during installation.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
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
                    Text("You’ll add an authenticator app during installation. Viewing permissions are assigned separately.")
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
                Section("Review Changes") {
                    ForEach(model.reviewChanges(), id: \.self) { line in
                        Text(line)
                            .font(.callout)
                    }
                    Text(GuidedServerSetupModel.packageUnavailableNotice)
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            .formStyle(.grouped)

        case .install:
            VStack(alignment: .leading, spacing: 12) {
                Label("Install Not Performed", systemImage: "xmark.octagon")
                    .font(.headline)
                Text(model.installProgressExplanation)
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }

        case .ready:
            VStack(alignment: .leading, spacing: 12) {
                Label("Server Ready for Enrollment", systemImage: "checkmark.circle")
                    .font(.headline)
                Text("Next, enroll a computer.")
                    .foregroundStyle(.secondary)
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
            Text(checkLabel(status))
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
