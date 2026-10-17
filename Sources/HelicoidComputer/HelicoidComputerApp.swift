import SwiftUI
import HelicoidCore

@main
struct HelicoidComputerApp: App {
    @State private var model: ComputerStatusModel

    init() {
        let fixtures = DevelopmentFixtures.isRequested()
        let model = fixtures ? ComputerDevelopmentFixtures.model() : ComputerStatusModel()
        if !fixtures {
            // Startup query without prompting.
            model.refreshPermissions()
        }
        _model = State(initialValue: model)
    }

    var body: some Scene {
        MenuBarExtra {
            StatusMenuContent()
                .environment(model)
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
                .environment(model)
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                    model.refreshPermissions()
                }
        }
        .windowResizability(.contentSize)

        Settings {
            ComputerSettingsView()
                .environment(model)
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
    @Environment(ComputerStatusModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Section {
            Text("Connection: \(model.connection.label)")
            Text(model.screenAccess.headline)
        }

        if model.isFixturesMode {
            Section {
                Text(DevelopmentFixtures.banner)
            }
        }

        Section {
            Button("Open Status Window") {
                NSApp.activate(ignoringOtherApps: true)
                openWindow(id: "status")
            }

            Button("Settings…") {
                NSApp.activate(ignoringOtherApps: true)
                openSettings()
            }
            .keyboardShortcut(",", modifiers: .command)
        }

        Section {
            Button("Quit Helicoid Computer") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q", modifiers: .command)
        }
    }
}

struct HelpRequestSection: View {
    @Environment(ComputerStatusModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Help")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

            TextField("Optional message", text: Binding(
                get: { model.helpRequestText },
                set: { model.helpRequestText = $0 }
            ))
            .disabled(!model.isHelpAvailable)

            HStack {
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

            if !model.isHelpAvailable {
                Text(model.helpUnavailableReason)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel(model.helpUnavailableReason)
            } else if model.helpRequestState == .pending {
                Text("Help request pending.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

struct StatusWindowView: View {
    @Environment(ComputerStatusModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Helicoid Computer")
                .font(.title2.weight(.semibold))

            LabeledContent("Connection", value: model.connection.label)

            if case .disconnected(let reason) = model.connection {
                Text(reason)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel(reason)
            }

            GroupBox {
                VStack(alignment: .leading, spacing: 6) {
                    Text(model.screenAccess.headline)
                        .font(.headline)
                    Text(accessDetail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            GroupBox {
                HelpRequestSection()
            }

            GroupBox {
                ComputerPermissionSection()
            }

            if model.isFixturesMode {
                Text(DevelopmentFixtures.banner)
                    .font(.caption)
                    .foregroundStyle(.orange)
                Text(ComputerFixturePermissionProbe.banner)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            Text("Managed computers have no user Stop Control command. Operators or authorized IT stop access, and automatic security teardown still applies.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(minWidth: 360, minHeight: 320)
    }

    private var accessDetail: String {
        switch model.screenAccess {
        case .none:
            "Status only. No observation or control is active."
        case .observed(let names):
            names.isEmpty
                ? "An authorized operator is viewing this screen."
                : "Observers: \(names.joined(separator: ", "))"
        case .controlled(let names):
            names.isEmpty
                ? "An authorized operator is controlling this computer."
                : "Controller: \(names.joined(separator: ", "))"
        }
    }
}

struct ComputerSettingsView: View {
    @Environment(ComputerStatusModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ComputerPermissionSection()

            if model.isFixturesMode {
                Text(ComputerFixturePermissionProbe.banner)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .padding(.horizontal, 24)
        .padding(.top, 36)
        .padding(.bottom, 20)
        .frame(width: 600, height: 400)
        .background(ComputerSettingsWindowChrome())
    }
}

/// Permission readiness UI. Separate from connection and screen access.
/// Request buttons are the only path that may prompt.
struct ComputerPermissionSection: View {
    @Environment(ComputerStatusModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Permissions", systemImage: "lock.shield")
                .font(.title2.weight(.semibold))
                .help("Permissions alone do not connect, share, or control this computer.")

            ForEach(ComputerPermissionKind.allCases, id: \.self) { kind in
                permissionRow(kind)
            }
        }
        .task {
            model.refreshPermissions()
        }
    }

    @ViewBuilder
    private func permissionRow(_ kind: ComputerPermissionKind) -> some View {
        let status = model.permissionStatus(for: kind)
        HStack(spacing: 12) {
            Image(systemName: symbolName(for: kind))
                .font(.title2)
                .foregroundStyle(.secondary)
                .frame(width: 28)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(kind.title)
                    .fontWeight(.medium)
                Text(roleSubtitle(for: kind))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 8)

            Label(status.label, systemImage: statusSymbol(status))
                .font(.caption.weight(.medium))
                .foregroundStyle(status == .granted ? Color.green : Color.secondary)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(.quaternary, in: Capsule())
                .accessibilityLabel("\(kind.title) status: \(status.label)")

            if !status.isAvailable {
                Button("Allow…") {
                    model.requestPermission(kind)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityLabel("Allow \(kind.title) permission")
            }

            Button {
                model.openPermissionSettings(kind)
            } label: {
                Image(systemName: "gearshape")
            }
            .help("Open System Settings for \(kind.title)")
            .accessibilityLabel("Open System Settings for \(kind.title)")
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
        .help(kind.purpose)
        .accessibilityHint(kind.purpose)
    }

    private func symbolName(for kind: ComputerPermissionKind) -> String {
        switch kind {
        case .screenRecording: "rectangle.on.rectangle"
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
        case .granted: "checkmark.circle.fill"
        case .missing: "xmark.circle"
        case .unknown: "questionmark.circle"
        }
    }

}
