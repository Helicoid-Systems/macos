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

            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.phase.title)
                        .font(.title2.weight(.semibold))
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel Setup") {
                    model.reset()
                    session.screen = .connect
                }
            }
            .padding()

            Divider()

            ScrollView {
                phaseForm
                    .padding()
                    .frame(maxWidth: 560)
            }

            Divider()

            HStack {
                Button("Back") {
                    model.back()
                }
                .disabled(model.phase == .chooseHosting)

                Spacer()

                if !model.canContinueFromCurrentPhase {
                    Text(continueDisabledReason)
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.trailing)
                        .frame(maxWidth: 320)
                        .accessibilityLabel(continueDisabledReason)
                } else if let blocker = model.blocker {
                    Text(blocker)
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .multilineTextAlignment(.trailing)
                        .frame(maxWidth: 320)
                }

                Button(nextButtonTitle) {
                    model.advance()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canContinueFromCurrentPhase && model.phase != .install && model.phase != .ready)
                .help(model.canContinueFromCurrentPhase ? nextButtonTitle : continueDisabledReason)
            }
            .padding()
        }
    }

    private var continueDisabledReason: String {
        switch model.phase {
        case .connect:
            "Enter an SSH address to continue."
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
        case .review: "Install"
        case .install: "Continue"
        case .ready: "Done"
        default: "Continue"
        }
    }

    private var subtitle: String {
        switch model.phase {
        case .chooseHosting:
            "Mac manager offers Linux SSH only. Windows hosting is installed by opening the Helicoid Windows app on the Windows host."
        case .connect:
            "Enter SSH address and authentication. No writes before host identity is verified."
        case .hostIdentity:
            "Verify the actual SSH host identity. A changed key or refusal performs no writes."
        case .checkHost:
            "Platform checks must pass before continuing. Conflicts and alternatives stay visible."
        case .network:
            "Address, product port, and intended LAN scope. Listeners are not exposed by this setup UI alone."
        case .deploymentIdentity:
            "Display name and actual generated trust identity. Identity replacement is explained before save."
        case .administrator:
            "Named local account with required MFA and recovery handling."
        case .storage:
            "Writable paths, limits, and encrypted backup destination."
        case .review:
            "Exact service, files, listeners, firewall, storage, and startup changes."
        case .install:
            "Install runs only with real server packages. This development build will not claim a successful install."
        case .ready:
            "Server Ready for Enrollment. Deployment is not yet Verified."
        }
    }

    @ViewBuilder
    private var phaseForm: some View {
        switch model.phase {
        case .chooseHosting:
            Form {
                Section("Hosting Route") {
                    Picker("Route", selection: Binding(
                        get: { model.route },
                        set: { _ in }
                    )) {
                        Text(HostingRoute.existingLinuxSSH.title)
                            .tag(HostingRoute.existingLinuxSSH)
                    }
                    .pickerStyle(.radioGroup)
                    .accessibilityLabel("Hosting route")
                    .disabled(true)
                    .help("Version 1 offers Linux SSH only on this Mac.")

                    Text(HostingRoute.existingLinuxSSH.detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("There is no local macOS server or remote Windows installation route in version 1.")
                        .font(.caption)
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
                    ))
                    Picker("Authentication", selection: Binding(
                        get: { model.sshAuthMethod },
                        set: { model.setSSHAuthMethod($0) }
                    )) {
                        ForEach(SSHAuthMethod.allCases, id: \.self) { method in
                            Text(method.label).tag(method)
                        }
                    }
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
                    Text("SSH host verification is unavailable in this development build. Setup cannot continue until it can compare the server’s actual host key with a trusted value.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

        case .checkHost:
            Form {
                Section("Host Checks") {
                    checkRow("SSH reachability")
                    checkRow("Disk space")
                    checkRow("Operating system")
                    Text("Continue is enabled only when every required check passes.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
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
                    TextField("Product port", text: Binding(
                        get: { model.productPort },
                        set: { model.setProductPort($0) }
                    ))
                    TextField("Intended LAN scope", text: Binding(
                        get: { model.lanScope },
                        set: { model.setLanScope($0) }
                    ))
                    Text("This form records intent. It does not open listeners or change firewall rules by itself.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

        case .deploymentIdentity:
            Form {
                Section("Deployment Identity") {
                    TextField("Deployment display name", text: Binding(
                        get: { model.deploymentName },
                        set: { model.setDeploymentName($0) }
                    ))
                    Text("Trust identity is generated at install time on the server. Identity replacement stops prior trust.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
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
                    Text("MFA is required. Recovery handling is not skipped in a successful install.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)

        case .storage:
            Form {
                Section("Storage and Backups") {
                    TextField("Storage path", text: Binding(
                        get: { model.storagePath },
                        set: { model.setStoragePath($0) }
                    ))
                    TextField("Encrypted backup destination", text: Binding(
                        get: { model.backupDestination },
                        set: { model.setBackupDestination($0) }
                    ))
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
                    Text("Install will not claim success without integrated server packages.")
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
            .padding()

        case .ready:
            VStack(alignment: .leading, spacing: 12) {
                Label("Server Ready for Enrollment", systemImage: "checkmark.circle")
                    .font(.headline)
                Text("Deployment Verified requires later enrolled endpoint evidence and is never marked by setup alone.")
                    .foregroundStyle(.secondary)
            }
            .padding()
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
                Button("Pass") { model.setHostCheck(name, status: .passed) }
                Button("Attention") {
                    model.setHostCheck(name, status: .needsAttention(detail: "Needs attention"))
                }
            case .checking:
                ProgressView().controlSize(.small)
            case .passed:
                Label("Passed", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            case .needsAttention(let detail):
                Label(detail, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                Button("Pass") { model.setHostCheck(name, status: .passed) }
            }
        }
    }
}
