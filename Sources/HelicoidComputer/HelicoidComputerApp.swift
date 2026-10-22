import SwiftUI
import UniformTypeIdentifiers
import HelicoidCore

private enum ComputerDevelopmentMode {
    static let launchFlag = "--development-fixtures"
    static let banner = "Development fixtures — not production inventory"

    static var isRequested: Bool {
        CommandLine.arguments.contains(launchFlag)
    }
}

@main
struct HelicoidComputerApp: App {
    @StateObject private var model: ComputerStatusModel

    init() {
        let fixtures = ComputerDevelopmentMode.isRequested
        let model = fixtures ? ComputerDevelopmentFixtures.model() : ComputerStatusModel()
        if !fixtures {
            // Startup query without prompting.
            model.refreshPermissions()
        }
        _model = StateObject(wrappedValue: model)
        if !fixtures {
            Task { @MainActor in model.startEndpointFileDeliveryPolling() }
        }
    }

    var body: some Scene {
        MenuBarExtra {
            StatusMenuContent()
                .environmentObject(model)
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                    // Reactivation query without prompting.
                    model.refreshPermissions()
                }
        } label: {
            Image(systemName: menuSymbol)
                .accessibilityLabel("Helicoid Computer status: \(model.connection.label)")
        }
        .menuBarExtraStyle(.menu)

        Window("Helicoid Computer", id: "status") {
            StatusWindowView()
                .environmentObject(model)
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                    model.refreshPermissions()
                }
        }
        .windowResizability(.contentSize)

        Window("Helicoid Computer Settings", id: "settings") {
            ComputerSettingsView()
                .environmentObject(model)
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                    model.refreshPermissions()
                }
        }
    }

    private var menuSymbol: String {
        switch model.connection {
        case .notConfigured: "desktopcomputer.trianglebadge.exclamationmark"
        case .connecting: "desktopcomputer"
        case .connected:
            switch model.screenAccess {
            case .none: "desktopcomputer"
            case .observed: "eye"
            case .controlled: "cursorarrow.rays"
            }
        case .disconnected: "desktopcomputer.slash"
        }
    }
}

struct StatusMenuContent: View {
    @EnvironmentObject private var model: ComputerStatusModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Section {
            Text("Connection: \(model.connection.label)")
            Text(model.screenAccess.headline)
        }

        if model.isFixturesMode {
            Section {
                Text(ComputerDevelopmentMode.banner)
            }
        }

        Section {
            Button("Open Status Window") {
                NSApp.activate(ignoringOtherApps: true)
                openWindow(id: "status")
            }

            Button("Settings…") {
                NSApp.activate(ignoringOtherApps: true)
                openWindow(id: "settings")
            }
            .keyboardShortcut(",", modifiers: .command)
        }

        if model.hasSavedEndpointConfiguration {
            Section {
                Text("File delivery: \(model.fileDeliveryStatus)")
                Button("Open Received Files") { model.openReceivedFilesFolder() }
            }
        }

        Section {
            Button("Quit Helicoid Computer") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q", modifiers: .command)
        }
    }
}

/// Fixture-only synthetic help. Explicitly labeled; absent from normal builds
/// until a real help transport exists.
struct HelpRequestSection: View {
    @EnvironmentObject private var model: ComputerStatusModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Synthetic Help (Development Fixtures)")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.orange)

            Text("No production help transport exists. This form is fixture-only.")
                .font(.caption)
                .foregroundStyle(.secondary)

            TextField("Optional message", text: Binding(
                get: { model.helpRequestText },
                set: { model.helpRequestText = $0 }
            ))
            .disabled(!model.isHelpAvailable)

            HStack(spacing: 8) {
                Button("Request Help") {
                    model.requestHelp()
                }
                .disabled(!model.isHelpAvailable)

                if model.helpRequestState == .pending {
                    Button("Cancel Request") {
                        model.cancelHelpRequest()
                    }
                }
            }

            if model.helpRequestState == .pending {
                Text("Help request pending.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

struct StatusWindowView: View {
    @EnvironmentObject private var model: ComputerStatusModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            LabeledContent("Connection", value: model.connection.label)

            if case .disconnected(let reason) = model.connection {
                Text(reason)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel(reason)
            }

            Text(model.screenAccess.headline)
                .font(.headline)

            if let names = observedNames, names.count > 1 {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(names, id: \.self) { name in
                        Text(name)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Observers: \(names.joined(separator: ", "))")
            }

            DisclosureGroup {
                ComputerPermissionSection()
            } label: {
                Text("Technical Details")
            }

            FileDeliverySection()

            if model.isFixturesMode {
                Text(ComputerDevelopmentMode.banner)
                    .font(.caption)
                    .foregroundStyle(.orange)
                Text(ComputerFixturePermissionProbe.banner)
                    .font(.caption)
                    .foregroundStyle(.orange)
                HelpRequestSection()
            }
        }
        .padding(20)
        .frame(width: 420, alignment: .top)
        .fixedSize(horizontal: false, vertical: true)
    }

    private var observedNames: [String]? {
        if case .observed(let names) = model.screenAccess {
            return names
        }
        return nil
    }
}

struct ComputerSettingsView: View {
    @EnvironmentObject private var model: ComputerStatusModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            EndpointEnrollmentSection()
            FileDeliverySection()
            ComputerPermissionSection()

            if model.isFixturesMode {
                Text(ComputerFixturePermissionProbe.banner)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .padding(24)
        .frame(width: 600, alignment: .top)
        .fixedSize(horizontal: false, vertical: true)
        .background(ComputerSettingsWindowChrome())
    }
}

/// User-driven endpoint setup. The invitation code is sent only to the
/// entered HTTPS origin and is cleared from the form after successful use.
struct EndpointEnrollmentSection: View {
    @EnvironmentObject private var model: ComputerStatusModel
    @State private var showingForgetConfirmation = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Server Enrollment", systemImage: "person.badge.key")
                .font(.headline)

            Text("This registers the Mac as pending. An administrator must approve it before file delivery is available. Screen viewing and control are not available in this build.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            TextField("HTTPS server address", text: binding(\.enrollmentServerAddress))
                .autocorrectionDisabled()
                .disabled(model.hasSavedEndpointConfiguration || model.isForgettingEndpointIdentity)
                .accessibilityLabel("HTTPS server address")

            TextField("Deployment ID", text: binding(\.enrollmentDeploymentID))
                .autocorrectionDisabled()
                .disabled(model.hasSavedEndpointConfiguration || model.isForgettingEndpointIdentity)
                .accessibilityLabel("Deployment ID")

            TextField("Invitation ID", text: binding(\.enrollmentInvitationID))
                .autocorrectionDisabled()
                .disabled(model.hasSavedEndpointConfiguration || model.isForgettingEndpointIdentity)
                .accessibilityLabel("Invitation ID")

            SecureField("One-time enrollment code", text: binding(\.enrollmentCode))
                .autocorrectionDisabled()
                .disabled(model.hasSavedEndpointConfiguration || model.isForgettingEndpointIdentity)
                .accessibilityLabel("One-time enrollment code")

            HStack(alignment: .top, spacing: 12) {
                Button("Enroll This Mac") {
                    Task { await model.enrollEndpoint() }
                }
                .disabled(model.isEnrolling || model.isForgettingEndpointIdentity || model.hasSavedEndpointConfiguration)

                if model.hasSavedEndpointConfiguration {
                    Button("Forget Saved Identity", role: .destructive) {
                        showingForgetConfirmation = true
                    }
                    .disabled(model.isForgettingEndpointIdentity || model.isEnrolling || model.isSubmittingFileRequest)
                }

                Text(model.enrollmentStatus)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .accessibilityElement(children: .combine)
            }
        }
        .confirmationDialog(
            "Forget this Mac's saved endpoint identity?",
            isPresented: $showingForgetConfirmation,
            titleVisibility: .visible
        ) {
            Button("Forget and Re-enroll", role: .destructive) {
                Task { await model.forgetSavedEndpointIdentity() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes the local identity and stops endpoint polling. The old computer remains a separate server-side identity; ask the Manager to quarantine it after recovery. Queued work will not move to a new identity, and files already in Received Files stay on this Mac.")
        }
    }

    private func binding(_ keyPath: ReferenceWritableKeyPath<ComputerStatusModel, String>) -> Binding<String> {
        Binding(get: { model[keyPath: keyPath] }, set: { model[keyPath: keyPath] = $0 })
    }
}

struct FileDeliverySection: View {
    @EnvironmentObject private var model: ComputerStatusModel
    @State private var showingFileRequestSheet = false
    @State private var initialRequestID: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("File Delivery", systemImage: "tray.and.arrow.down")
                .font(.headline)
            Text(model.fileDeliveryStatus)
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            Button("Open Received Files") { model.openReceivedFilesFolder() }
                .disabled(!model.hasSavedEndpointConfiguration)

            Divider()

            HStack {
                Text("File Requests")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Button("Refresh") {
                    Task { await model.refreshFileRequests() }
                }
                .disabled(!model.hasSavedEndpointConfiguration || model.isRefreshingFileRequests)
            }
            Text(model.fileRequestStatus)
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)

            ForEach(model.availableFileRequests) { request in
                Button {
                    initialRequestID = request.id
                    showingFileRequestSheet = true
                } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(request.title)
                                .font(.callout.weight(.medium))
                            Text("\(request.allowedExtensionSummary) · Closes \(Date(timeIntervalSince1970: TimeInterval(request.closesAtUnix)).formatted(date: .abbreviated, time: .shortened))")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("Review")
                            .font(.caption.weight(.medium))
                    }
                }
                .buttonStyle(.plain)
                .accessibilityHint("Review the request instructions and choose files to submit.")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .sheet(isPresented: $showingFileRequestSheet) {
            FileRequestSubmissionSheet(initialRequestID: initialRequestID)
                .environmentObject(model)
        }
    }
}

struct FileRequestSubmissionSheet: View {
    @EnvironmentObject private var model: ComputerStatusModel
    @Environment(\.dismiss) private var dismiss
    @State private var selectedRequestID: String?
    @State private var showingFileImporter = false
    @State private var showingReplacementPrompt = false
    @State private var pendingFileURLs: [URL] = []
    @State private var pickerError: String?

    init(initialRequestID: String? = nil) {
        _selectedRequestID = State(initialValue: initialRequestID)
    }

    private var selectedRequest: EndpointFileRequest? {
        model.availableFileRequests.first(where: { $0.id == selectedRequestID })
    }

    private var latestReceivedSubmission: EndpointFileRequestSubmission? {
        model.fileRequestSubmissions
            .filter { $0.state == "received" }
            .max(by: { $0.createdAtUnix < $1.createdAtUnix })
    }

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                if model.availableFileRequests.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "tray")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("No Open Requests")
                            .font(.headline)
                        Text(model.fileRequestStatus)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(model.availableFileRequests) { request in
                        Button {
                            selectedRequestID = request.id
                        } label: {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(request.title)
                                    .font(.headline)
                                Text("Allowed: \(request.allowedExtensionSummary) · \(ByteCountFormatter.string(fromByteCount: Int64(request.maxTotalSizeBytes), countStyle: .file)) maximum")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .listRowBackground(selectedRequestID == request.id ? Color.accentColor.opacity(0.12) : Color.clear)
                    }
                    .frame(minHeight: 180, maxHeight: 250)
                }

                if let selectedRequest {
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        Text(selectedRequest.title)
                            .font(.title3.weight(.semibold))
                        if !selectedRequest.instructions.isEmpty {
                            Text(selectedRequest.instructions)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Text("Allowed: \(selectedRequest.allowedExtensionSummary)")
                        Text("Up to \(selectedRequest.maxFileCount) files and \(ByteCountFormatter.string(fromByteCount: Int64(selectedRequest.maxTotalSizeBytes), countStyle: .file)) total")
                        Text("Closes \(Date(timeIntervalSince1970: TimeInterval(selectedRequest.closesAtUnix)).formatted(date: .long, time: .shortened))")
                        if !model.fileRequestSubmissionStatus.isEmpty {
                            Text(model.fileRequestSubmissionStatus)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                        ForEach(model.fileRequestSubmissions) { submission in
                            Text("\(submission.state.capitalized) · \(submission.files.count) file\(submission.files.count == 1 ? "" : "s") · \(Date(timeIntervalSince1970: TimeInterval(submission.createdAtUnix)).formatted(date: .abbreviated, time: .shortened))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        if let pickerError {
                            Text(pickerError)
                                .font(.caption)
                                .foregroundStyle(.red)
                        }
                        Button("Choose Files…") {
                            pickerError = nil
                            showingFileImporter = true
                        }
                        .disabled(model.isRefreshingFileRequestSubmissions || model.isSubmittingFileRequest)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    Text("Select a request to review its instructions and your earlier submissions.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(20)
            .navigationTitle("File Requests")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                        .disabled(model.isSubmittingFileRequest)
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Refresh") {
                        Task { await model.refreshFileRequests() }
                    }
                    .disabled(model.isRefreshingFileRequests || model.isSubmittingFileRequest)
                }
            }
        }
        .frame(minWidth: 580, minHeight: 500)
        .interactiveDismissDisabled(model.isSubmittingFileRequest)
        .task {
            await model.refreshFileRequests()
            if let selectedRequestID,
               model.availableFileRequests.contains(where: { $0.id == selectedRequestID }) {
                await model.refreshFileRequestSubmissions(requestID: selectedRequestID)
            }
        }
        .onChange(of: selectedRequestID) { requestID in
            guard let requestID else { return }
            Task { await model.refreshFileRequestSubmissions(requestID: requestID) }
        }
        .fileImporter(
            isPresented: $showingFileImporter,
            allowedContentTypes: [.item],
            allowsMultipleSelection: true,
            onCompletion: handleFileSelection
        )
        .confirmationDialog(
            "A Received submission already exists for this user.",
            isPresented: $showingReplacementPrompt,
            titleVisibility: .visible
        ) {
            Button("Add as Another Submission") {
                submitPendingFiles(replacing: nil)
            }
            if selectedRequest?.replacementAllowed == true,
               let latestReceivedSubmission {
                Button("Replace Submission \(latestReceivedSubmission.id)", role: .destructive) {
                    submitPendingFiles(replacing: latestReceivedSubmission.id)
                }
            }
            Button("Cancel", role: .cancel) { pendingFileURLs = [] }
        } message: {
            Text("Replacing is explicit. The existing files remain available until the replacement has been verified.")
        }
    }

    private func handleFileSelection(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard !urls.isEmpty else { return }
            guard selectedRequest != nil else {
                pickerError = "Select an open request first."
                return
            }
            pendingFileURLs = urls
            if latestReceivedSubmission != nil {
                showingReplacementPrompt = true
            } else {
                submitPendingFiles(replacing: nil)
            }
        case .failure:
            pickerError = "The file chooser could not return the selected files."
        }
    }

    private func submitPendingFiles(replacing submissionID: String?) {
        guard let selectedRequest, !pendingFileURLs.isEmpty else { return }
        let urls = pendingFileURLs
        pendingFileURLs = []
        Task {
            let submitted = await model.submitFilesToRequest(
                selectedRequest,
                fileURLs: urls,
                replaceSubmissionID: submissionID,
                confirmReplacement: submissionID != nil
            )
            if submitted { dismiss() }
        }
    }
}

/// Permission readiness UI. Separate from connection and screen access.
/// The single row action is the only path that may prompt, and only once.
struct ComputerPermissionSection: View {
    @EnvironmentObject private var model: ComputerStatusModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Permissions", systemImage: "lock.shield")
                .font(.headline)

            VStack(alignment: .leading, spacing: 8) {
                ForEach(ComputerPermissionKind.allCases, id: \.self) { kind in
                    permissionRow(kind)
                }
            }
        }
        .task {
            model.refreshPermissions()
        }
    }

    @ViewBuilder
    private func permissionRow(_ kind: ComputerPermissionKind) -> some View {
        let status = model.permissionStatus(for: kind)
        let action = model.permissionRowAction(for: kind)
        HStack(spacing: 16) {
            Image(systemName: symbolName(for: kind))
                .font(.body)
                .foregroundStyle(.secondary)
                .frame(width: 24)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(kind.title)
                Text(roleSubtitle(for: kind))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 8)

            Label(status.label, systemImage: statusSymbol(status))
                .foregroundStyle(.secondary)
                .accessibilityLabel("\(kind.title) status: \(status.label)")

            switch action {
            case .allow:
                Button("Allow") {
                    model.performPermissionRowAction(kind)
                }
                .accessibilityLabel("Allow \(kind.title) permission")
                .accessibilityHint(kind.purpose)
            case .openSettings:
                Button("Open Settings") {
                    model.performPermissionRowAction(kind)
                }
                .accessibilityLabel("Open Settings for \(kind.title) permission")
                .accessibilityHint(kind.purpose)
            case .none:
                EmptyView()
            }
        }
        .help(kind.purpose)
    }

    private func symbolName(for kind: ComputerPermissionKind) -> String {
        switch kind {
        case .screenRecording: "display"
        case .accessibility: "cursorarrow"
        }
    }

    private func roleSubtitle(for kind: ComputerPermissionKind) -> String {
        switch kind {
        case .screenRecording: "View screen"
        case .accessibility: "Keyboard and mouse"
        }
    }

    private func statusSymbol(_ status: ComputerPermissionStatus) -> String {
        switch status {
        case .granted: "checkmark.circle"
        case .missing: "xmark.circle"
        case .unknown: "questionmark.circle"
        }
    }
}
