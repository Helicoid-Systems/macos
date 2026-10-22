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
    public var showDevelopmentBanner: Bool
    /// Session-owned inventory presentation (layout, size, panel). Survives view identity resets.
    public var presentation: ManagerPresentationPreferences
    /// Real account+deployment scope for preference persistence. Never invented from URL/name.
    public private(set) var presentationPreferenceScope: PresentationPreferenceScope?
    /// True when a new session generation is live. Stale view-window content must invalidate.
    public private(set) var sessionGeneration: UInt64 = 0
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
        self.serverAddress = configuration.useDevelopmentServer || productionAuthClient != nil
            ? configuration.developmentServerAddress : ""
        self.trustedProfiles = []
        self.pendingIdentity = nil
        self.verifiedIdentity = nil
        self.username = ""
        self.password = ""
        self.signInError = nil
        self.connectError = nil
        self.signOutError = nil
        self.openRemoteWindows = []
        self.presentation = ManagerPresentationPreferences()
        self.presentationPreferenceScope = nil
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
        bumpSessionGeneration()

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
                await refreshPresentationPreferenceScope()
                overview.setInventory(coordinator.inventory)
            }
            return
        }

        let result = await client.signIn(username: username, password: password)
        switch result {
        case .success:
            bumpSessionGeneration()
            await refreshPresentationPreferenceScope()
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
            await refreshPresentationPreferenceScope()
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
            if phase != .signedIn {
                bumpSessionGeneration()
            }
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
            bumpSessionGeneration()
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
        bumpSessionGeneration()
        presentationPreferenceScope = nil
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

    /// Opens or focuses the native view-only window for `id`.
    /// Unauthorized / unknown IDs refuse to open. Re-open dedupes demand.
    /// Returns the generation-scoped window key for this demand.
    @discardableResult
    public func openRemoteView(for id: ComputerID) -> ComputerViewWindowKey? {
        guard isFixturesMode || phase == .signedIn else { return nil }
        guard computer(with: id) != nil else { return nil }
        if !openRemoteWindows.contains(id) {
            openRemoteWindows.append(id)
        }
        return ComputerViewWindowKey(computerID: id, sessionGeneration: sessionGeneration)
    }

    /// Closing one window removes only its own demand.
    /// Generation-scoped: an old window cannot drop a newer same-computer demand.
    public func closeRemoteView(for key: ComputerViewWindowKey) {
        guard key.sessionGeneration == sessionGeneration else { return }
        openRemoteWindows.removeAll { $0 == key.computerID }
    }

    /// Convenience for tests and call sites that already hold the live generation.
    public func closeRemoteView(for id: ComputerID) {
        closeRemoteView(for: ComputerViewWindowKey(computerID: id, sessionGeneration: sessionGeneration))
    }

    public func computer(with id: ComputerID) -> Computer? {
        overview.authorizedInventory.first(where: { $0.id == id })
    }

    // MARK: - Presentation preferences

    public var preferenceStore: PresentationPreferenceStore {
        PresentationPreferenceStore(scope: presentationPreferenceScope)
    }

    /// Session-only presentation updates. Persistence runs only with a real scope.
    public func setPresentationLayout(_ layout: ManagerLayoutKind) {
        presentation.layout = layout
        preferenceStore.save(presentation)
    }

    public func setPresentationPreviewSize(_ size: ManagerPreviewSize) {
        presentation.previewSize = size
        preferenceStore.save(presentation)
    }

    public func setComputersPanelShown(_ shown: Bool) {
        presentation.isComputersPanelShown = shown
        preferenceStore.save(presentation)
    }

    public func toggleComputersPanel() {
        setComputersPanelShown(!presentation.isComputersPanelShown)
    }

    /// Reset search and status filters. Filter changes clear temporary selection.
    /// Open action snapshots are not modified.
    public func clearInventoryFilters() {
        overview.setSearchText("")
        overview.setStatusFilter(.all)
    }

    public var inventoryEmptyReason: InventoryEmptyReason {
        InventoryEmptyReason.reason(
            authorizedCount: overview.authorizedInventory.count,
            includedCount: overview.inclusion.includedIDs(from: overview.authorizedInventory.map(\.id)).count,
            displayedCount: overview.scope.displayedIDs.count,
            filterActive: overview.filter.isActive
        )
    }

    /// Tri-state for the All Computers checkbox against current authorized IDs.
    public var allComputersCheckState: CheckState {
        overview.inclusion.allComputersCheckState(authorized: overview.authorizedInventory.map(\.id))
    }

    /// Tri-state for a group checkbox against current inclusion and authorized membership.
    public func groupCheckState(groupID: String) -> CheckState {
        let authorizedIDs = Set(overview.authorizedInventory.map(\.id))
        let members = Set(overview.groups.computerIDs(inGroup: groupID)).intersection(authorizedIDs)
        guard !members.isEmpty else { return .off }
        let included = overview.inclusion.includedIDs(from: authorizedIDs)
        let includedMembers = members.intersection(included)
        if includedMembers.count == members.count { return .on }
        if includedMembers.isEmpty { return .off }
        return .mixed
    }

    /// Applies a tri-state click for All Computers.
    public func applyAllComputersCheckState(_ state: CheckState) {
        switch state {
        case .off:
            overview.clearAllComputersMode()
        case .on, .mixed:
            overview.selectAllComputersMode()
        }
    }

    /// Applies a tri-state click for a group.
    public func applyGroupCheckState(groupID: String, state: CheckState) {
        overview.setGroupIncluded(groupID, included: state != .off)
    }

    // MARK: - Session identity for presentation scope

    private func refreshPresentationPreferenceScope() async {
        // Fence against sign-out/replacement while deploymentID is awaited.
        let installGeneration = sessionGeneration
        let expectedAccountID = authCoordinator?.session?.account.id
        let next = await makePresentationPreferenceScope()
        guard sessionGeneration == installGeneration,
              authCoordinator?.session?.account.id == expectedAccountID else {
            return
        }
        guard next != presentationPreferenceScope else { return }
        presentationPreferenceScope = next
        if let loaded = preferenceStore.load() {
            presentation = loaded
        } else {
            // New scope with no stored prefs must not inherit the previous account.
            presentation = ManagerPresentationPreferences()
        }
    }

    private func makePresentationPreferenceScope() async -> PresentationPreferenceScope? {
        guard let accountID = authCoordinator?.session?.account.id,
              !accountID.isEmpty,
              let client = productionAuthClient else {
            return nil
        }
        let deploymentID = await client.deploymentID
        guard !deploymentID.isEmpty else {
            return nil
        }
        return PresentationPreferenceScope(deploymentID: deploymentID, accountID: accountID)
    }

    private func bumpSessionGeneration() {
        sessionGeneration &+= 1
        // Session change invalidates every view-only demand immediately.
        openRemoteWindows = []
    }
}
