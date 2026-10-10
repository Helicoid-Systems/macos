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
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Helicoid Manager") {
                    AboutWindow.show()
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
        .id(session.screen)
        .transition(.opacity.combined(with: .scale(scale: 0.98)))
        .animation(.easeOut(duration: 0.22), value: session.screen)
        .frame(
            minWidth: session.screen == .guidedSetup ? 560 : 720,
            maxWidth: .infinity,
            minHeight: session.screen == .guidedSetup ? 360 : 480,
            maxHeight: .infinity
        )
        .background(SetupWindowChrome(isEnabled: session.screen == .guidedSetup))
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
