import SwiftUI
import HelicoidCore

@main
struct HelicoidManagerApp: App {
    @State private var session: ManagerSession

    init() {
        let config = ManagerLaunchConfiguration.parse(arguments: CommandLine.arguments)
        _session = State(initialValue: ManagerSession(configuration: config))
    }

    var body: some Scene {
        WindowGroup("Helicoid Manager") {
            RootView()
                .environment(session)
        }
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Helicoid Manager") {
                    NSApplication.shared.orderFrontStandardAboutPanel(options: [
                        .applicationName: "Helicoid Manager",
                        .applicationVersion: "0.1.0",
                        .credits: NSAttributedString(
                            string: "Helicoid Systems. Computer monitoring."
                        ),
                    ])
                }
            }
            // Use the system View menu; do not add a second View command menu.
            CommandGroup(after: .sidebar) {
                Button("Show Inclusion Panel") {
                    session.showInclusionPanel.toggle()
                }
                .keyboardShortcut("i", modifiers: [.command, .shift])
            }
        }

        Settings {
            SettingsView()
                .environment(session)
        }
    }
}

struct RootView: View {
    @Environment(ManagerSession.self) private var session

    var body: some View {
        Group {
            switch session.screen {
            case .connect:
                ConnectView()
            case .verify:
                VerifyServerView()
            case .signIn:
                SignInView()
            case .computers:
                ComputersView()
            case .guidedSetup:
                GuidedSetupView()
            }
        }
        .frame(minWidth: 720, minHeight: 480)
    }
}

struct SettingsView: View {
    @Environment(ManagerSession.self) private var session

    var body: some View {
        Form {
            LabeledContent("Product", value: "Helicoid")
            LabeledContent("Company", value: "Helicoid Systems")
            LabeledContent("Role", value: "Helicoid Manager")
            LabeledContent("Transport", value: session.transportDescription)
            if let identity = session.managerPublicIdentity, !identity.isEmpty {
                LabeledContent("Manager identity", value: identity)
            }
        }
        .formStyle(.grouped)
        .frame(width: 460, height: 220)
    }
}
