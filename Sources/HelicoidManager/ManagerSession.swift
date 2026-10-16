import Foundation
import HelicoidCore

/// App-level session for Helicoid Manager.
/// Connection, overview, and setup state stay separate objects.
@MainActor
@Observable
public final class ManagerSession: AuthSignInObserving {
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
    /// Cancellable required-code state for v2 device-key sign-in.
    public var authCodeState: AuthCodeState {
        authCoordinator?.authCodeState ?? .idle
    }
    /// UI buffer for the six-digit code. Submitted value is passed explicitly.
    public var authCode: String = ""
    /// Facade error field; synced from the coordinator after each step.
    public var authCodeError: HelicoidError?

    /// True when a connection path is actually available.
    public var allowsConnect: Bool {
        isFixturesMode || isDevelopmentServerMode || productionAuthClient != nil
    }

    private let client: any ConnectionClient
    private let developmentClient: LoopbackDevelopmentClient?
    private let productionAuthClient: NativeV2AuthClient?
    /// Actual v2 sign-in state owner (causal generation fencing lives here).
    private var authCoordinator: AuthSignInCoordinator?

    public init(
        configuration: ManagerLaunchConfiguration = ManagerLaunchConfiguration(),
        client: (any ConnectionClient)? = nil,
        productionAuthClient: NativeV2AuthClient? = nil
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
        self.authCode = ""
        self.productionAuthClient = configuration.useDevelopmentServer ? nil : productionAuthClient
        self.authCoordinator = (configuration.useDevelopmentServer || configuration.useSourceFixtures)
            ? nil
            : productionAuthClient.map { AuthSignInCoordinator(client: $0) }

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
            if let productionAuthClient, !configuration.useDevelopmentServer {
                self.client = client ?? productionAuthClient
            } else {
                self.client = client ?? UnavailableConnectionClient()
            }
            self.overview = OverviewModel()
        }
        // Automatic expiry/401 must reach this facade without a user action.
        // Set after full initialization (weak observer, no retain cycle).
        self.authCoordinator?.observer = self
    }

    /// Human-readable transport description. Never claims production trust.
    public var transportDescription: String {
        if isFixturesMode {
            return "Source fixtures — not production inventory"
        }
        if isDevelopmentServerMode {
            return "Local development loopback server. No production server identity is verified."
        }
        if productionAuthClient != nil {
            return "Pinned HTTPS with independently supplied deployment trust. No fallback to development login."
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


        if let auth = productionAuthClient, !isDevelopmentServerMode, !isFixturesMode {
            // Trust configuration is already supplied. Discovery does not
            // establish trust and is never used to mint a deployment identity.
            phase = .connecting
            let result = await auth.connect(address: serverAddress.trimmingCharacters(in: .whitespacesAndNewlines))
            switch result {
            case .success(let identity):
                pendingIdentity = nil
                verifiedIdentity = identity
                phase = .needsSignIn
                screen = .signIn
            case .failure(let error):
                applyConnectFailure(error)
            }
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
        authCodeError = nil
        overview.setInventory([])

        if let coordinator = authCoordinator, !isDevelopmentServerMode, !isFixturesMode {
            let username = self.username
            let password = self.password
            self.password = ""
            await coordinator.signIn(username: username, password: password)
            syncAuthUIFromCoordinator()
            if case .signedIn = coordinator.phase {
                overview.setInventory(coordinator.inventory)
            }
            return
        }

        let result = await client.signIn(username: username, password: password)
        switch result {
        case .success:
            phase = .signedIn
            screen = .computers
            password = ""
            await reloadInventory()
        case .failure(let error):
            signInError = error
            password = ""
            overview.setInventory([])
            openRemoteWindows = []
            if case .permissionDenied(let detail) = error, detail.lowercased().contains("manager") {
                phase = .pendingManagerApproval
            } else {
                phase = .needsSignIn
            }
        }
    }

    /// Submit the required six-digit code. Cancellable via `cancelAuthCode()`.
    public func submitAuthCode() async {
        guard let coordinator = authCoordinator else {
            authCodeError = .authenticationFailed(detail: "Start sign-in again.")
            authCode = ""
            return
        }
        // Push the UI buffer into the coordinator before submit.
        coordinator.setAuthCode(authCode)
        await coordinator.submitAuthCode()
        authCode = ""
        syncAuthUIFromCoordinator()
        if case .signedIn = coordinator.phase {
            overview.setInventory(coordinator.inventory)
        }
    }

    /// Cancel required-code collection and clear challenge secrets.
    public func cancelAuthCode() async {
        authCode = ""
        password = ""
        if let coordinator = authCoordinator {
            await coordinator.cancelAuthCode()
            syncAuthUIFromCoordinator()
        } else {
            phase = .needsSignIn
            screen = .signIn
        }
    }

    private func syncAuthUIFromCoordinator() {
        guard let coordinator = authCoordinator else { return }
        switch coordinator.phase {
        case .idle:
            break
        case .awaitingCredentials:
            phase = .needsSignIn
            screen = .signIn
        case .awaitingRequiredCode:
            phase = .needsSignIn
            screen = .signIn
        case .signedIn:
            phase = .signedIn
            screen = .computers
        case .pendingManagerApproval:
            phase = .pendingManagerApproval
            screen = .signIn
        case .failed(let error):
            signInError = error
            phase = .needsSignIn
            screen = .signIn
        }
        if let error = coordinator.signInError {
            signInError = error
        }
        authCodeError = coordinator.authCodeError
        // Mirror coordinator inventory into the actual overview facade.
        if case .signedIn = coordinator.phase {
            overview.setInventory(coordinator.inventory)
        } else if coordinator.inventory.isEmpty {
            overview.setInventory([])
        } else {
            overview.setInventory(coordinator.inventory)
        }
        // Expiry / credential loss must drop remote windows and selection.
        if case .sessionExpired = coordinator.signInError {
            openRemoteWindows = []
            overview.setInventory([])
        }
    }

    /// Automatic facade sync when the coordinator changes (expiry, 401, …).
    public func authSignInCoordinatorDidUpdate(_ coordinator: AuthSignInCoordinator) {
        syncAuthUIFromCoordinator()
    }

    public func reloadInventory() async {
        if isFixturesMode { return }
        if let coordinator = authCoordinator, productionAuthClient != nil, !isDevelopmentServerMode {
            await coordinator.reloadInventory()
            syncAuthUIFromCoordinator()
            overview.setInventory(coordinator.inventory)
            return
        }
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
        authCode = ""
        password = ""
        if let coordinator = authCoordinator {
            await coordinator.signOut()
            syncAuthUIFromCoordinator()
        }
        if let dev = developmentClient {
            signOutError = await dev.signOutReportingRemoteFailure()
        } else if authCoordinator == nil {
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
