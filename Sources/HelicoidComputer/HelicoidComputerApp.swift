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
        .menuBarExtraStyle(.window)

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

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            LabeledContent("Connection", value: model.connection.label)
            Text(model.screenAccess.headline)
                .font(.callout.weight(.medium))

            if case .disconnected(let reason) = model.connection {
                Text(reason)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Divider()

            HelpRequestSection()

            Divider()

            Button("Open Status Window") {
                NSApp.activate(ignoringOtherApps: true)
                openWindow(id: "status")
            }

            Button("Quit Helicoid Computer") {
                NSApplication.shared.terminate(nil)
            }
        }
        .padding(12)
        .frame(minWidth: 260)
        .accessibilityElement(children: .contain)
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
        Form {
            LabeledContent("Product", value: "Helicoid")
            LabeledContent("Company", value: "Helicoid Systems")
            LabeledContent("Role", value: "Helicoid Computer")
            Text("This app reports connection and screen-access status for a monitored computer. It does not grant operators access by itself.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Section("Permissions") {
                ComputerPermissionSection()
            }

            if model.isFixturesMode {
                Text(ComputerFixturePermissionProbe.banner)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .formStyle(.grouped)
        .frame(width: 420, height: 320)
    }
}

/// Permission readiness UI. Separate from connection and screen access.
/// Request buttons are the only path that may prompt.
struct ComputerPermissionSection: View {
    @Environment(ComputerStatusModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Permissions")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

            ForEach(ComputerPermissionKind.allCases, id: \.self) { kind in
                permissionRow(kind)
            }

            Text("Grants alone do not connect, share, or control this computer.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .task {
            model.refreshPermissions()
        }
    }

    @ViewBuilder
    private func permissionRow(_ kind: ComputerPermissionKind) -> some View {
        let status = model.permissionStatus(for: kind)
        VStack(alignment: .leading, spacing: 4) {
            LabeledContent(kind.title, value: status.label)
                .accessibilityLabel("\(kind.title): \(status.label)")

            Text(kind.purpose)
                .font(.caption)
                .foregroundStyle(.secondary)

            if !status.isAvailable {
                HStack(spacing: 8) {
                    Button("Request \(kind.title)…") {
                        model.requestPermission(kind)
                    }
                    Button("Open Settings") {
                        model.openPermissionSettings(kind)
                    }
                }
                .controlSize(.small)
            }
        }
    }
}
