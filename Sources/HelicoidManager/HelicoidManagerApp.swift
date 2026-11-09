import SwiftUI
import HelicoidCore

@main
struct HelicoidManagerApp: App {
    @State private var session: ManagerSession

    init() {
        var config = ManagerLaunchConfiguration.parse(arguments: CommandLine.arguments)
        if Bundle.main.bundleIdentifier == "systems.helicoid.manager.main-demo" {
            config = ManagerLaunchConfiguration(useSourceFixtures: true)
        }
        _session = State(initialValue: ManagerSession(configuration: config))
    }

    var body: some Scene {
        WindowGroup("Helicoid Manager") {
            RootView()
                .environment(session)
                .disclosureGroupStyle(FullWidthDisclosureGroupStyle())
        }
        .defaultSize(width: 620, height: 300)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Helicoid Manager") {
                    AboutWindow.show()
                }
            }
            // Use the system View menu; do not add a second View command menu.
            CommandGroup(after: .sidebar) {
                Button(session.presentation.isComputersPanelShown ? "Hide Computers Panel" : "Show Computers Panel") {
                    session.toggleComputersPanel()
                }
                .keyboardShortcut("i", modifiers: [.command, .shift])
                .disabled(session.screen != .computers)

                Divider()

                Picker("Layout", selection: Binding(
                    get: { session.presentation.layout },
                    set: { session.setPresentationLayout($0) }
                )) {
                    ForEach(ManagerLayoutKind.allCases) { kind in
                        Text(kind.label).tag(kind)
                    }
                }
                .disabled(session.screen != .computers)

                Picker("Preview Size", selection: Binding(
                    get: { session.presentation.previewSize },
                    set: { session.setPresentationPreviewSize($0) }
                )) {
                    ForEach(ManagerPreviewSize.allCases) { size in
                        Text(size.label).tag(size)
                    }
                }
                .disabled(session.screen != .computers)

                Divider()

                Button("Refresh Inventory") {
                    Task { await session.reloadInventory() }
                }
                .keyboardShortcut("r")
                .disabled(
                    session.screen != .computers
                        || session.isFixturesMode
                        || session.phase != .signedIn
                        || session.isReloadingInventory
                )

                Button("Pause Monitoring") {
                    session.overview.pauseMonitoring()
                }
                .disabled(session.screen != .computers || session.overview.isMonitoringPaused)

                Button("Resume Monitoring") {
                    session.overview.resumeMonitoring()
                }
                .disabled(session.screen != .computers || !session.overview.isMonitoringPaused)
            }
        }

        // Independent native view-only windows. One demand per computer+generation key.
        WindowGroup("View Computer", id: ManagerWindowID.computerView, for: ComputerViewWindowKey.self) { $windowKey in
            ComputerViewWindowRoot(windowKey: windowKey)
                .environment(session)
        }
        .defaultSize(width: 960, height: 640)

        Settings {
            SettingsView()
                .environment(session)
        }
    }
}

enum ManagerWindowID {
    static let computerView = "computer-view"
}

struct RootView: View {
    @Environment(ManagerSession.self) private var session
    @State private var setupWindowHeight: CGFloat = 280

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
        .frame(
            minWidth: rootSize.minWidth,
            idealWidth: rootSize.idealWidth,
            maxWidth: .infinity,
            minHeight: rootSize.minHeight,
            idealHeight: rootSize.idealHeight,
            maxHeight: .infinity
        )
        .background(SetupWindowChrome(screen: session.screen, setupHeight: setupWindowHeight))
        .onPreferenceChange(SetupWindowHeightKey.self) { height in
            if let height { setupWindowHeight = height }
        }
    }

    private var rootSize: (minWidth: CGFloat, idealWidth: CGFloat, minHeight: CGFloat, idealHeight: CGFloat) {
        switch session.screen {
        case .connect:
            (620, 620, 300, 300)
        case .signIn:
            (620, 620, 440, 440)
        case .verify:
            (680, 680, 520, 520)
        case .guidedSetup:
            (680, 680, 200, setupWindowHeight)
        case .computers:
            (720, 1120, 480, 760)
        }
    }
}

struct SettingsView: View {
    @Environment(ManagerSession.self) private var session
    @State private var selectedTab: SettingsTab = .general

    enum SettingsTab: String, CaseIterable, Identifiable {
        case general
        case server
        var id: String { rawValue }
        var title: String {
            switch self {
            case .general: "General"
            case .server: "Server & Account"
            }
        }
    }

    var body: some View {
        @Bindable var session = session
        TabView(selection: $selectedTab) {
            Form {
                Section("Inventory") {
                    Picker("Layout", selection: Binding(
                        get: { session.presentation.layout },
                        set: { session.setPresentationLayout($0) }
                    )) {
                        ForEach(ManagerLayoutKind.allCases) { kind in
                            Text(kind.label).tag(kind)
                        }
                    }
                    Picker("Preview size", selection: Binding(
                        get: { session.presentation.previewSize },
                        set: { session.setPresentationPreviewSize($0) }
                    )) {
                        ForEach(ManagerPreviewSize.allCases) { size in
                            Text(size.label).tag(size)
                        }
                    }
                    Toggle("Show Computers Panel", isOn: Binding(
                        get: { session.presentation.isComputersPanelShown },
                        set: { session.setComputersPanelShown($0) }
                    ))
                }
            }
            .formStyle(.grouped)
            .tabItem { Text(SettingsTab.general.title) }
            .tag(SettingsTab.general)

            Form {
                Section("Server") {
                    LabeledContent("Transport", value: session.transportDescription)
                    if let identity = session.verifiedIdentity {
                        LabeledContent("Deployment", value: identity.deploymentName)
                    } else {
                        LabeledContent("Deployment", value: "Not verified")
                    }
                }
                Section("Account") {
                    if session.phase == .signedIn {
                        LabeledContent("Status", value: "Signed in")
                    } else {
                        LabeledContent("Status", value: "Not signed in")
                    }
                    Button("Sign Out") {
                        Task { await session.signOut() }
                    }
                    .disabled(session.phase == .notConfigured)
                    if let error = session.signOutError {
                        Text(error.explanation)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
                Section("Identity Details") {
                    if let identity = session.verifiedIdentity {
                        LabeledContent("Fingerprint", value: identity.verificationFingerprint)
                    }
                    if let managerIdentity = session.managerPublicIdentity, !managerIdentity.isEmpty {
                        LabeledContent("Manager identity", value: managerIdentity)
                    }
                    if let accountID = session.presentationPreferenceScope?.accountID {
                        LabeledContent("Account ID", value: accountID)
                    }
                }
            }
            .formStyle(.grouped)
            .tabItem { Text(SettingsTab.server.title) }
            .tag(SettingsTab.server)
        }
        .frame(width: 560, height: 360)
    }
}
