import SwiftUI
import HelicoidCore

/// W17 Guided server setup — Mac manager: This Mac and Linux SSH (H01–H12).
struct GuidedSetupView: View {
    @Environment(ManagerSession.self) private var session
    @State private var model = GuidedServerSetupModel()

    var body: some View {
        VStack(spacing: 0) {
            if session.showDevelopmentBanner {
                DevelopmentBanner()
            }

            phaseForm
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 560)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
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
            .padding(.vertical, 20)
        }
        .onDisappear { model.cancelHostCheck() }
        .task {
            await model.prepareManagerIdentity()
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
            "Install is not available in this build. Setup will not claim success."
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
                "Checking…"
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
            Form {
                Section {
                    Picker("Hosting route", selection: Binding(
                        get: { model.route },
                        set: { model.setRoute($0) }
                    )) {
                        ForEach(HostingRoute.allCases, id: \.self) { route in
                            Text(route.title).tag(route)
                        }
                    }
                    .pickerStyle(.radioGroup)
                    Text(model.route.detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

        case .connect:
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
                        ProgressView(model.route == .thisMac ? "Checking this Mac…" : "Checking server…")
                    } else if hostChecksPassed {
                        Label("Host checks passed", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else if model.route == .thisMac {
                        if let failure = model.localPreflightFailure {
                            Text(failure)
                        } else {
                            Text("Run the read-only preflight to inspect this Mac. No privileged writes are performed.")
                                .foregroundStyle(.secondary)
                        }
                    } else if !model.hostIdentity.isVerified {
                        Text(model.hostIdentity.explanation)
                    }
                    if !model.isCheckingHost && !hostChecksPassed {
                        ForEach(requiredChecks, id: \.self) { name in
                            if case .needsAttention = model.hostChecks[name] { checkRow(name) }
                        }
                    }
                    DisclosureGroup("Details") {
                        if model.route == .thisMac {
                            if let local = model.localPreflight {
                                Text("Computer: \(local.computerName)")
                                    .font(.caption.monospaced())
                                Text("\(local.osVersion) · \(local.architecture)")
                                    .font(.caption.monospaced())
                                Text("Preflight is read-only. Installation is not performed by this build.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            } else if let failure = model.localPreflightFailure {
                                Text(failure)
                                    .font(.caption.monospaced())
                                    .textSelection(.enabled)
                            }
                        } else {
                            Text(model.hostIdentity.explanation)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                        }
                        ForEach(requiredChecks, id: \.self) { checkRow($0) }
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
                Section(model.route == .thisMac ? "Mac storage" : "Linux server storage") {
                    TextField("Server data folder", text: Binding(
                        get: { model.storagePath },
                        set: { model.setStoragePath($0) }
                    ), prompt: Text(model.route.defaultStoragePath))
                    DisclosureGroup("Backup location (optional)") {
                        TextField("Encrypted backup folder", text: Binding(
                            get: { model.backupDestination },
                            set: { model.setBackupDestination($0) }
                        ), prompt: Text(model.route == .thisMac ? "/path/on/this/mac" : "/path/on/linux/server"))
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

        case .ready:
            VStack(alignment: .leading, spacing: 12) {
                Label("Server Ready for Enrollment", systemImage: "checkmark.circle")
                    .font(.headline)
                Text("Next, enroll a Windows computer.")
                    .foregroundStyle(.secondary)
            }
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
