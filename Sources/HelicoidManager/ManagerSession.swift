import Foundation
import HelicoidCore

/// App-level session for Helicoid Manager.
/// Connection, overview, and setup state stay separate objects.
@MainActor
@Observable
public final class ManagerSession {
    public enum Screen: Hashable, Sendable {
        case connect
        case verify
        case signIn
        case computers
        case guidedSetup
    }

    public var screen: Screen
    public var phase: ConnectionPhase
    public var serverAddress: String
    public var trustedProfiles: [ServerProfile]
    public var pendingIdentity: ServerIdentity?
    public var verifiedIdentity: ServerIdentity?
    public var username: String
    public var password: String
    public var signInError: HelicoidError?
    public var connectError: ConnectionFailure?
    public var signOutError: HelicoidError?
    public var overview: OverviewModel
    public var openRemoteWindows: [ComputerID]
    public var isFixturesMode: Bool
    public var isDevelopmentServerMode: Bool
    public var managerPublicIdentity: String?
    public var showInclusionPanel: Bool
    public var showDevelopmentBanner: Bool

    /// True when a connection path is actually available.
    public var allowsConnect: Bool {
        isFixturesMode || isDevelopmentServerMode
    }

    private let client: any ConnectionClient
    private let developmentClient: LoopbackDevelopmentClient?

    public init(
        configuration: ManagerLaunchConfiguration = ManagerLaunchConfiguration(),
        client: (any ConnectionClient)? = nil
    ) {
        self.isFixturesMode = configuration.useSourceFixtures
        self.isDevelopmentServerMode = configuration.useDevelopmentServer
        self.managerPublicIdentity = configuration.managerPublicIdentity
        self.screen = configuration.useSourceFixtures ? .computers : .connect
        self.phase = configuration.useSourceFixtures ? .signedIn : .notConfigured
        self.serverAddress = configuration.developmentServerAddress
        self.trustedProfiles = []
        self.pendingIdentity = nil
        self.verifiedIdentity = nil
        self.username = ""
        self.password = ""
        self.signInError = nil
        self.connectError = nil
        self.signOutError = nil
        self.openRemoteWindows = []
        self.showInclusionPanel = false
        self.showDevelopmentBanner = configuration.useSourceFixtures

        if configuration.useSourceFixtures {
            self.overview = DevelopmentFixtures.overviewModel()
            self.developmentClient = nil
            self.client = client ?? UnavailableConnectionClient()
        } else if configuration.useDevelopmentServer {
            let base = URL(string: configuration.developmentServerAddress)
                ?? URL(string: "http://127.0.0.1:8787") ?? URL(fileURLWithPath: "/")
            let dev = LoopbackDevelopmentClient(
                configuration: LoopbackDevelopmentClient.Configuration(
                    baseURL: base,
                    managerPublicIdentity: configuration.managerPublicIdentity
                )
            )
            self.developmentClient = dev
            self.client = client ?? dev
            self.overview = OverviewModel()
        } else {
            self.developmentClient = nil
            self.client = client ?? UnavailableConnectionClient()
            self.overview = OverviewModel()
        }
    }

    /// Human-readable transport description. Never claims production trust.
    public var transportDescription: String {
        if isFixturesMode {
            return "Source fixtures — not production inventory"
        }
        if isDevelopmentServerMode {
            return "Local development loopback server. No production server identity is verified."
        }
        return "Production connection is closed until a trusted server identity is available."
    }

    // MARK: - Connection flow

    public func connect() async {
        connectError = nil
        signInError = nil
        signOutError = nil
        clearSessionMaterial()

        guard allowsConnect else {
            connectError = .serverContractUnavailable
            phase = .failed(.serverContractUnavailable)
            return
        }

        phase = .connecting
        let address = serverAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        let validation = await client.validateAddress(address)
        if case .invalid(let detail) = validation.outcome {
            connectError = .invalidAddress(detail: detail)
            phase = .notConfigured
            return
        }

        if let dev = developmentClient {
            let outcome = await dev.connectDevelopment(address: address)
            switch outcome {
            case .success(let result):
                switch result {
                case .developmentReady(let canonical, _):
                    // Bind the exact connected address for subsequent calls.
                    serverAddress = canonical.url.absoluteString
                    // Development transport: verifiedIdentity stays nil (no synthesized trust).
                    pendingIdentity = nil
                    verifiedIdentity = nil
                    phase = .needsSignIn
                    screen = .signIn
                case .needsSetup:
                    connectError = .serverContractUnavailable
                    phase = .failed(.serverContractUnavailable)
                case .notAcceptingOperations:
                    connectError = .unreachable
                    phase = .failed(.unreachable)
                }
            case .failure(let error):
                applyConnectFailure(error)
            }
            return
        }

        let result = await client.connect(address: address)
        switch result {
        case .success(let identity):
            if isDevelopmentServerMode {
                pendingIdentity = nil
                verifiedIdentity = nil
                phase = .needsSignIn
                screen = .signIn
            } else {
                pendingIdentity = identity
                phase = .needsVerification
                screen = .verify
            }
        case .failure(let error):
            applyConnectFailure(error)
        }
    }

    private func applyConnectFailure(_ error: HelicoidError) {
        switch error {
        case .serverContractUnavailable:
            connectError = .serverContractUnavailable
        case .invalidInput(_, let detail):
            connectError = .invalidAddress(detail: detail)
        case .cancelled:
            connectError = .cancelled
        case .engineUnavailable:
            connectError = .engineUnavailable
        default:
            connectError = .unreachable
        }
        phase = .failed(connectError ?? .unreachable)
    }

    public func trustPendingIdentity() async {
        guard let identity = pendingIdentity else {
            connectError = .identityUnverified
            return
        }
        connectError = nil
        let result = await client.trust(identity: identity, address: serverAddress)
        switch result {
        case .success:
            verifiedIdentity = identity
            phase = .needsSignIn
            screen = .signIn
        case .failure:
            connectError = .identityUnverified
            phase = .failed(.identityUnverified)
        }
    }

    public func signIn() async {
        connectError = nil
        signInError = nil
        // Failed sign-in must never retain previous inventory.
        overview.setInventory([])

        let result = await client.signIn(username: username, password: password)
        switch result {
        case .success:
            phase = .signedIn
            screen = .computers
            password = ""
            await reloadInventory()
        case .failure(let error):
            signInError = error
            overview.setInventory([])
            openRemoteWindows = []
            if case .permissionDenied(let detail) = error, detail.lowercased().contains("manager") {
                phase = .pendingManagerApproval
            } else {
                phase = .needsSignIn
            }
        }
    }

    public func reloadInventory() async {
        if isFixturesMode { return }
        let result = await client.authorizedInventory()
        switch result {
        case .success(let computers):
            overview.setInventory(computers)
        case .failure(let error):
            signInError = error
            if case .permissionDenied = error {
                overview.setInventory([])
                openRemoteWindows = []
                phase = .needsSignIn
                screen = .signIn
            }
        }
    }

    /// Clears token, identity, and inventory even if remote logout fails.
    public func signOut() async {
        signOutError = nil
        if let dev = developmentClient {
            signOutError = await dev.signOutReportingRemoteFailure()
        } else {
            await client.signOut()
        }
        clearSessionMaterial()
        if isFixturesMode {
            isFixturesMode = false
            showDevelopmentBanner = false
        }
        phase = .notConfigured
        screen = .connect
    }

    private func clearSessionMaterial() {
        pendingIdentity = nil
        verifiedIdentity = nil
        username = ""
        password = ""
        overview = OverviewModel()
        openRemoteWindows = []
    }

    // MARK: - Remote windows (view-only; engine honestly unavailable)

    public func openRemoteView(for id: ComputerID) {
        if !openRemoteWindows.contains(id) {
            openRemoteWindows.append(id)
        }
    }

    public func closeRemoteView(for id: ComputerID) {
        openRemoteWindows.removeAll { $0 == id }
    }

    public func computer(with id: ComputerID) -> Computer? {
        overview.authorizedInventory.first(where: { $0.id == id })
    }
}
