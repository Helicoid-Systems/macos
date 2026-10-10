import SwiftUI
import HelicoidCore

/// W17 Guided server setup — Mac manager: Linux SSH only (H01–H12).
struct GuidedSetupView: View {
    @Environment(ManagerSession.self) private var session
    @State private var model = GuidedServerSetupModel()

    var body: some View {
        VStack(spacing: 0) {
            if session.showDevelopmentBanner {
                DevelopmentBanner()
            }

            HStack(spacing: 0) {
                Spacer(minLength: 0)
                phaseForm
                    .frame(maxWidth: 560)
                Spacer(minLength: 0)
            }
            .frame(maxHeight: .infinity)
            .padding(.horizontal, 24)

            if let blocker = model.blocker {
                Label(blocker, systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .frame(maxWidth: 560, alignment: .leading)
                    .padding(.horizontal, 24)
                    .padding(.bottom, 12)
            }

            HStack(spacing: 12) {
                Button("Cancel") {
                    model.reset()
                    session.screen = .connect
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
            .padding(.vertical, 20)
        }
        .onDisappear { model.cancelHostCheck() }
        .task {
            if model.phase == .chooseHosting {
                model.advance()
                model.setStoragePath("/var/lib/helicoid")
            }
            await model.prepareManagerIdentity()
        }
    }

    private var continueDisabledReason: String {
        switch model.phase {
        case .connect:
            "Enter a valid SSH address and use key authentication."
        case .hostIdentity:
            "Verify the SSH host identity before continuing. A changed key or refusal performs no writes."
        case .checkHost:
            "Every host check must pass before continuing."
        case .network:
            "Enter the server address and a valid product port."
        case .deploymentIdentity:
            "Enter a deployment display name."
        case .administrator:
            "Enter an administrator username."
        case .storage:
            "Enter a storage path."
        case .install:
            "Install is not available in this build. Setup will not claim success."
        default:
            "Complete the required fields before continuing."
        }
    }

    private var isHostCheck: Bool {
        model.phase == .hostIdentity || model.phase == .checkHost
    }

    private var hostChecksPassed: Bool {
        model.hostIdentity.isVerified && GuidedServerSetupModel.requiredHostChecks.allSatisfy {
            model.hostChecks[$0] == .passed
        }
    }

    private var nextButtonTitle: String {
        switch model.phase {
        case .connect: "Check Server"
        case .hostIdentity, .checkHost:
            model.isCheckingHost ? "Checking…" : hostChecksPassed ? "Continue" : "Check Again"
        case .review: "Install"
        case .install: "Install Unavailable"
        case .ready: "Done"
        default: "Continue"
        }
    }

    private func continueSetup() {
        if model.phase == .connect {
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
        if model.phase == .checkHost { model.back() }
        model.back()
    }

    @ViewBuilder
    private var phaseForm: some View {
        switch model.phase {
        case .chooseHosting, .connect:
            Form {
                Section {
                    TextField("SSH address", text: Binding(
                        get: { model.sshAddress },
                        set: { model.setSSHAddress($0) }
                    ), prompt: Text("ubuntu@server.example.com"))
                    Text("Connect with your Mac’s SSH key. For a custom port, use username@host:port.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

        case .hostIdentity, .checkHost:
            Form {
                Section {
                    if model.isCheckingHost {
                        ProgressView("Checking server…")
                    } else if hostChecksPassed {
                        Label("Server checks passed", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else if !model.hostIdentity.isVerified {
                        Text(model.hostIdentity.explanation)
                    }
                    if !model.isCheckingHost && !hostChecksPassed {
                        ForEach(GuidedServerSetupModel.requiredHostChecks, id: \.self) { name in
                            if case .needsAttention = model.hostChecks[name] { checkRow(name) }
                        }
                    }
                    DisclosureGroup("Details") {
                        Text(model.hostIdentity.explanation)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                        ForEach(GuidedServerSetupModel.requiredHostChecks, id: \.self) { checkRow($0) }
                    }
                }
            }
            .formStyle(.grouped)

        case .network:
            Form {
                Section("Network") {
                    TextField("Server address", text: Binding(
                        get: { model.networkAddress },
                        set: { model.setNetworkAddress($0) }
                    ))
                    DisclosureGroup("Advanced") {
                        TextField("Connection port", text: Binding(
                            get: { model.productPort },
                            set: { model.setProductPort($0) }
                        ))
                        TextField("LAN scope (optional)", text: Binding(
                            get: { model.lanScope },
                            set: { model.setLanScope($0) }
                        ))
                        Text("Default: 8920. Rendezvous and relay: 21115–21117.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)

        case .deploymentIdentity:
            Form {
                Section {
                    TextField("Deployment name", text: Binding(
                        get: { model.deploymentName },
                        set: { model.setDeploymentName($0) }
                    ))
                    if model.isPreparingManagerIdentity {
                        ProgressView("Preparing Manager identity…")
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

        case .administrator:
            Form {
                Section {
                    TextField("Administrator username", text: Binding(
                        get: { model.administratorUsername },
                        set: { model.setAdministratorUsername($0) }
                    ))
                    Text("You’ll add an authenticator app during installation. Viewing permissions are assigned separately.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

        case .storage:
            Form {
                Section("Linux server storage") {
                    TextField("Server data folder", text: Binding(
                        get: { model.storagePath },
                        set: { model.setStoragePath($0) }
                    ), prompt: Text("/var/lib/helicoid"))
                    DisclosureGroup("Backup location (optional)") {
                        TextField("Encrypted backup folder", text: Binding(
                            get: { model.backupDestination },
                            set: { model.setBackupDestination($0) }
                        ), prompt: Text("/path/on/linux/server"))
                    }
                }
            }
            .formStyle(.grouped)

        case .review:
            Form {
                Section("Review Changes") {
                    ForEach(model.reviewChanges(), id: \.self) { line in
                        Text(line)
                            .font(.callout)
                    }
                    Text("Installation is unavailable until verified server packages are integrated.")
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
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .padding(.top, 24)

        case .ready:
            VStack(alignment: .leading, spacing: 12) {
                Label("Server Ready for Enrollment", systemImage: "checkmark.circle")
                    .font(.headline)
                Text("Next, enroll a Windows computer.")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .padding(.top, 24)
        }
    }

    @ViewBuilder
    private func checkRow(_ name: String) -> some View {
        let status = model.hostChecks[name] ?? .pending
        HStack {
            Text(name)
            Spacer()
            switch status {
            case .pending:
                Text("Pending").foregroundStyle(.secondary)
            case .checking:
                ProgressView().controlSize(.small)
            case .passed:
                Label("Passed", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            case .needsAttention(let detail):
                Label(detail, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
        }
    }
}
