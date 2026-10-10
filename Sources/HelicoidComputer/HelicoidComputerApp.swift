import SwiftUI
import HelicoidCore

@main
struct HelicoidComputerApp: App {
    @State private var model: ComputerStatusModel

    init() {
        let fixtures = DevelopmentFixtures.isRequested()
        _model = State(initialValue: fixtures ? ComputerDevelopmentFixtures.model() : ComputerStatusModel())
    }

    var body: some Scene {
        MenuBarExtra {
            StatusMenuContent()
                .environment(model)
        } label: {
            Image(systemName: menuSymbol)
                .accessibilityLabel("Helicoid Computer status: \(model.connection.label)")
        }
        .menuBarExtraStyle(.window)

        Window("Helicoid Computer", id: "status") {
            StatusWindowView()
                .environment(model)
        }
        .windowResizability(.contentSize)

        Settings {
            ComputerSettingsView()
                .environment(model)
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
                if let window = NSApp.windows.first(where: { $0.identifier?.rawValue == "status" }) {
                    window.makeKeyAndOrderFront(nil)
                } else {
                    NSApp.sendAction(Selector(("showWindows:")), to: nil, from: nil)
                }
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

            if model.isFixturesMode {
                Text(DevelopmentFixtures.banner)
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
    var body: some View {
        Form {
            LabeledContent("Product", value: "Helicoid")
            LabeledContent("Company", value: "Helicoid Systems")
            LabeledContent("Role", value: "Helicoid Computer")
            Text("This app reports connection and screen-access status for a monitored computer. It does not grant operators access by itself.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .frame(width: 420, height: 220)
    }
}
