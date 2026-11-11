import HelicoidCore
import SwiftUI
import UniformTypeIdentifiers

/// Production trust entry screen. All trust inputs are supplied by the
/// operator; the network observation only verifies the entered deployment ID,
/// key fingerprint, and generation before any local trust record is committed.
struct ProductionTrustView: View {
    @Environment(ManagerSession.self) private var session
    @State private var model = ManagerProductionBootstrapModel()
    @State private var isImportingCA = false
    @State private var isConfirmingClear = false
    @FocusState private var focusedField: Field?

    private enum Field: Hashable {
        case host
        case port
        case pin
        case deploymentID
        case keyFingerprint
        case generation
    }

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    ConnectionHeading(title: "Production Connection")

                    Text("Enter the deployment CA and the deployment authority values supplied through a trusted organization channel. The Manager checks the live authority over that pinned TLS identity; it never adopts a key learned only from the network.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)

                    fieldGroup("Server origin") {
                        labeledField("Hostname", text: $model.host, prompt: "server.example.com", field: .host)
                            .textContentType(.URL)
                        labeledField("Port", text: $model.port, prompt: "8920", field: .port)
                    }

                    fieldGroup("Deployment CA") {
                        HStack(spacing: 12) {
                            Button("Choose CA Certificate…") {
                                isImportingCA = true
                            }
                            .accessibilityLabel("Choose deployment CA certificate")
                            Text(model.caFileName ?? "No CA certificate selected")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                            Spacer()
                        }
                        if let fingerprint = model.loadedCAFingerprint {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Selected CA SHA-256")
                                    .font(.caption.weight(.semibold))
                                Text(fingerprint)
                                    .font(.caption.monospaced())
                                    .textSelection(.enabled)
                                Text("Compare this with the pin you received independently. The pin field is not filled automatically.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .accessibilityElement(children: .combine)
                        }
                        labeledField(
                            "CA SHA-256 pin",
                            text: $model.caPin,
                            prompt: "64-character lowercase or uppercase hex",
                            field: .pin
                        )
                    }

                    fieldGroup("Deployment identity") {
                        labeledField(
                            "Deployment ID",
                            text: $model.deploymentID,
                            prompt: "dep_…",
                            field: .deploymentID
                        )
                        Text("Use the exact deployment ID supplied through the trusted channel.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    if model.savedConfiguration != nil || model.savedCheckpoint != nil {
                        fieldGroup("Saved local checkpoint") {
                            if let checkpoint = model.savedCheckpoint {
                                LabeledContent("Key fingerprint", value: checkpoint.grantSigningKeyFingerprintSHA256)
                                    .textSelection(.enabled)
                                LabeledContent("Generation", value: String(checkpoint.authorityGeneration))
                                Toggle("Replace saved trust checkpoint", isOn: Binding(
                                    get: { model.isReplacingTrust },
                                    set: { model.setReplacingTrust($0) }
                                ))
                                .accessibilityLabel("Replace saved trust checkpoint")
                                Text("Leave this off to connect only if the server still matches the saved checkpoint.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                if model.savedConfiguration == nil {
                                    Text("This checkpoint has no usable atomically bound TLS configuration. Enable replacement after independent verification or reset production trust.")
                                        .font(.caption)
                                        .foregroundStyle(.red)
                                }
                            } else {
                                Text("No readable authority checkpoint is saved. Reset production trust to set it up again.")
                                    .font(.caption)
                                    .foregroundStyle(.red)
                            }
                        }
                    }

                    if model.needsOperatorTrustValues {
                        fieldGroup("Out-of-band authority values") {
                            labeledField(
                                "Grant-signing key SHA-256 fingerprint",
                                text: $model.keyFingerprint,
                                prompt: "64-character SHA-256 fingerprint",
                                field: .keyFingerprint
                            )
                            labeledField(
                                "Authority generation",
                                text: $model.generation,
                                prompt: "1",
                                field: .generation
                            )
                            Text("These values must match the live authority before the checkpoint is adopted. A mismatch saves nothing.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }

                    if let error = model.errorMessage {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.red)
                            .textSelection(.enabled)
                            .accessibilityElement(children: .combine)
                    }
                    if let status = model.statusMessage {
                        Text(status)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .accessibilityElement(children: .combine)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(24)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()
            HStack(spacing: 12) {
                if model.isBusy {
                    ProgressView()
                        .controlSize(.small)
                }
                Button("Set Up Server") {
                    model.openGuidedSetup(in: session)
                }
                .disabled(model.isBusy)
                .help("Check or prepare a Helicoid server installation")
                Button("Reset Production Trust…", role: .destructive) {
                    isConfirmingClear = true
                }
                .disabled(model.isBusy)
                .help("Remove the saved production trust record for the selected deployment")
                Spacer()
                Button(connectTitle) {
                    Task { _ = await model.connect(into: session) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canSubmit || model.isBusy)
                .help(connectTitle)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 16)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear {
            focusedField = .host
        }
        .task {
            await model.loadSavedConfiguration()
            if model.errorMessage == nil, let failure = session.connectError {
                model.errorMessage = failure.explanation
            }
        }
        .fileImporter(
            isPresented: $isImportingCA,
            allowedContentTypes: [.data],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                loadCA(from: url)
            case .failure(let error):
                model.errorMessage = error.localizedDescription
            }
        }
        .alert("Reset production trust?", isPresented: $isConfirmingClear) {
            Button("Cancel", role: .cancel) {}
            Button("Reset", role: .destructive) {
                Task {
                    await model.clearSavedTrust()
                    session.uninstallProductionConnection()
                }
            }
        } message: {
            Text("This removes the saved authority checkpoint and CA configuration record for the selected deployment. Set up trust again from independently verified values.")
        }
    }

    private var connectTitle: String {
        if model.savedConfiguration != nil,
           model.savedCheckpoint != nil,
           !model.isReplacingTrust {
            return "Connect with Saved Trust"
        }
        return "Verify and Save Trust"
    }

    @ViewBuilder
    private func fieldGroup<Content: View>(
        _ title: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.callout.weight(.semibold))
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
    }

    private func labeledField(
        _ label: String,
        text: Binding<String>,
        prompt: String,
        field: Field
    ) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label).font(.caption)
            TextField(prompt, text: text)
                .textFieldStyle(.roundedBorder)
                .focused($focusedField, equals: field)
                .accessibilityLabel(label)
        }
    }

    private func loadCA(from url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer {
            if accessed { url.stopAccessingSecurityScopedResource() }
        }
        do {
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            let data = (try handle.read(
                upToCount: DeploymentTLSIdentity.maxCADerBytes + 1
            )) ?? Data()
            guard data.count <= DeploymentTLSIdentity.maxCADerBytes else {
                model.errorMessage = "The selected CA certificate is too large."
                return
            }
            model.setCADER(data, fileName: url.lastPathComponent)
        } catch {
            model.errorMessage = error.localizedDescription
        }
    }
}
