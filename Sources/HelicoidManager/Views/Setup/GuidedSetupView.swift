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

            VStack(alignment: .leading, spacing: 8) {
                Text(stepDescription)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(stepTitle)
                    .font(.title2.weight(.semibold))
                Text(subtitle)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: 560, alignment: .leading)
            .padding(.horizontal, 24)
            .padding(.top, 40)
            .padding(.bottom, 8)

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

                if model.phase != .chooseHosting {
                    Button("Back") { model.back() }
                }

                Button(nextButtonTitle) {
                    if model.phase == .hostIdentity && !model.hostIdentity.isVerified {
                        model.startHostCheck()
                    } else {
                        model.advance()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(model.isCheckingHost || (model.phase != .hostIdentity && !model.canContinueFromCurrentPhase))
                .help(model.canContinueFromCurrentPhase ? nextButtonTitle : continueDisabledReason)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 20)
        }
        .ignoresSafeArea(.container, edges: .top)
        .onDisappear { model.cancelHostCheck() }
        .task { await model.prepareManagerIdentity() }
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

    private var nextButtonTitle: String {
        switch model.phase {
        case .chooseHosting: "Get Started"
        case .hostIdentity where model.isCheckingHost: "Checking…"
        case .hostIdentity where !model.hostIdentity.isVerified: "Verify Server"
        case .review: "Install"
        case .install: "Install Unavailable"
        case .ready: "Done"
        default: "Continue"
        }
    }

    private var stepDescription: String {
        let preparation = SetupPhase.allCases.prefix(while: { $0 != .install })
        if let index = preparation.firstIndex(of: model.phase) {
            return "Server Setup · Step \(index + 1) of \(preparation.count)"
        }
        return "Server Setup"
    }

    private var stepTitle: String {
        switch model.phase {
        case .chooseHosting: "Set up your Helicoid server"
        case .connect: "Where is your Linux server?"
        case .hostIdentity: "Verify your server"
        case .checkHost: "Check compatibility"
        case .network: "How will computers connect?"
        case .deploymentIdentity: "Name your deployment"
        case .administrator: "Choose an administrator"
        case .storage: "Choose storage locations"
        case .review: "Review your installation"
        case .install: "Installation unavailable"
        case .ready: "Your server is ready for enrollment"
        }
    }

    private var subtitle: String {
        switch model.phase {
        case .chooseHosting:
            "Connect to an existing Linux server. We’ll check it and show you the installation changes before you apply them."
        case .connect:
            "Use the same username and host you use to connect with SSH."
        case .hostIdentity:
            "Check the server against your Mac’s trusted SSH hosts before continuing."
        case .checkHost:
            "All checks must pass. If something needs attention, resolve it and check again."
        case .network:
            "Use an address reachable by your Manager and Windows computers."
        case .deploymentIdentity:
            "Pick a name you’ll recognize when connecting to this server."
        case .administrator:
            "This account will manage enrollment and permissions. Set up MFA during installation."
        case .storage:
            "These folders are on the Linux server, not on your Mac."
        case .review:
            "Check the services, files, ports, and storage changes before installing."
        case .install:
            "This development build cannot install the server yet."
        case .ready:
            "Next, enroll a Windows computer and verify live viewing."
        }
    }

    @ViewBuilder
    private var phaseForm: some View {
        switch model.phase {
        case .chooseHosting:
            Form {
                Section("You’ll need") {
                    Label("An Ubuntu 26.04 server", systemImage: "server.rack")
                    Label("SSH key access from this Mac", systemImage: "key")
                    Label("Administrator privileges on the server", systemImage: "person.badge.key")
                }
                Section {
                    Text("Setup checks your server first. You’ll review every installation change before anything is installed.")
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

        case .connect:
            Form {
                Section("Linux SSH") {
                    TextField("SSH address", text: Binding(
                        get: { model.sshAddress },
                        set: { model.setSSHAddress($0) }
                    ), prompt: Text("ubuntu@server.example.com"))
                    LabeledContent("Authentication", value: "SSH key from this Mac")
                    Text("For a custom SSH port, use username@host:port.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

        case .hostIdentity:
            Form {
                Section("Host Identity") {
                    LabeledContent("Current result") {
                        Text(model.hostIdentity.explanation)
                            .multilineTextAlignment(.trailing)
                    }
                    if model.isCheckingHost { ProgressView().controlSize(.small) }
                    Text("Uses your existing trusted SSH host keys. An unknown or changed key stops setup; verify it independently through the server provider before adding it to SSH trust.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

        case .checkHost:
            Form {
                Section("Host Checks") {
                    ForEach(GuidedServerSetupModel.requiredHostChecks, id: \.self) { checkRow($0) }
                    Button("Refresh Checks") { model.startHostCheck() }
                        .disabled(model.isCheckingHost)
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
                    TextField("Connection port", text: Binding(
                        get: { model.productPort },
                        set: { model.setProductPort($0) }
                    ))
                    TextField("LAN scope (optional)", text: Binding(
                        get: { model.lanScope },
                        set: { model.setLanScope($0) }
                    ))
                    Text("The default connection port is 8920. Rendezvous and relay use ports 21115–21117.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

        case .deploymentIdentity:
            Form {
                Section("Deployment Identity") {
                    TextField("Deployment name", text: Binding(
                        get: { model.deploymentName },
                        set: { model.setDeploymentName($0) }
                    ))
                    if model.isPreparingManagerIdentity {
                        ProgressView("Preparing Manager identity…")
                    } else if !model.generatedTrustIdentityNote.isEmpty {
                        Label("Manager identity saved in Keychain", systemImage: "checkmark.shield")
                        DisclosureGroup("Identity details") {
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
                Section("Administrator") {
                    TextField("Administrator username", text: Binding(
                        get: { model.administratorUsername },
                        set: { model.setAdministratorUsername($0) }
                    ))
                    Text("Installation will ask you to enroll an authenticator app and save recovery material. This account does not receive viewing permission automatically.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

        case .storage:
            Form {
                Section("Storage and Backups") {
                    TextField("Server data folder", text: Binding(
                        get: { model.storagePath },
                        set: { model.setStoragePath($0) }
                    ), prompt: Text("/var/lib/helicoid"))
                    TextField("Encrypted backup folder (optional)", text: Binding(
                        get: { model.backupDestination },
                        set: { model.setBackupDestination($0) }
                    ), prompt: Text("/path/on/linux/server"))
                    Text("Enter absolute Linux paths. You’ll review them before installation.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
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
                Text("Server Ready for Enrollment is not claimed. No partial install is reported as success.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .padding(.top, 24)

        case .ready:
            VStack(alignment: .leading, spacing: 12) {
                Label("Server Ready for Enrollment", systemImage: "checkmark.circle")
                    .font(.headline)
                Text("Deployment Verified requires later enrolled endpoint evidence and is never marked by setup alone.")
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
