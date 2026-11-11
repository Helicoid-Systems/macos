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

    private enum SessionMode: Sendable {
        case fixtures
        case development
        case production
    }

    /// Immutable for the lifetime of the session. Trust gates must not be
    /// derived from mutable UI/state flags.
    private let sessionMode: SessionMode

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
    /// Immutable launch mode. These flags are derived, never mutable gate input.
    public var isFixturesMode: Bool { sessionMode == .fixtures }
    public var isDevelopmentServerMode: Bool { sessionMode == .development }
    public var managerPublicIdentity: String?
    public var showDevelopmentBanner: Bool
    /// Session-owned inventory presentation (layout, size, panel). Survives view identity resets.
    public var presentation: ManagerPresentationPreferences
    /// Real account+deployment scope for preference persistence. Never invented from URL/name.
    public private(set) var presentationPreferenceScope: PresentationPreferenceScope?
    /// True when a new session generation is live. Stale view-window content must invalidate.
    public private(set) var sessionGeneration: UInt64 = 0
    /// Manual inventory refresh in progress. Automatic sign-in loading also uses this.
    public private(set) var isReloadingInventory = false
    /// Last manual inventory refresh failure. A failed refresh keeps the previous inventory.
    public private(set) var inventoryReloadError: HelicoidError?
    /// Fences overlapping refreshes so an older response cannot replace a newer one.
    private var inventoryReloadGeneration: UInt64 = 0
    /// Fences asynchronous authority checks so a stale result cannot overwrite
    /// a newer connect/sign-in/sign-out state.
    private var authorityCheckGeneration: UInt64 = 0
    /// Cancellable required-code state for v2 device-key sign-in.
    public var authCodeState: AuthCodeState {
        authCoordinator?.authCodeState ?? .idle
    }
    /// UI buffer for the six-digit code. Submitted value is passed explicitly.
    public var authCode: String = ""
    /// Facade error field; synced from the coordinator after each step.
    public var authCodeError: HelicoidError?

    /// True when this session is on the real production path.
    private var requiresProductionTrust: Bool {
        sessionMode == .production && productionAuthClient != nil
    }

    /// True when a connection path is actually available.
    ///
    /// Production requires both a pinned client and a persisted authority
    /// checkpoint store. Source fixtures and the explicit loopback development
    /// mode remain independent and do not require production trust. A generic
    /// `ConnectionClient` injection cannot satisfy the production gate.
    public var allowsConnect: Bool {
        switch sessionMode {
        case .fixtures, .development:
            return true
        case .production:
            return productionAuthClient?.isProductionPinned == true
                && authorityTrust != nil
        }
    }

    /// True when the app must present the production trust setup screen.
    public var requiresProductionBootstrap: Bool {
        guard sessionMode == .production else { return false }
        if !allowsConnect { return true }
        return connectError == .identityChanged && authCoordinator?.session == nil
    }

    private let client: any ConnectionClient
    private let developmentClient: LoopbackDevelopmentClient?
    private var productionAuthClient: NativeV2AuthClient?
    /// Persisted, independently confirmed deployment authority checkpoint.
    /// When supplied, production connect and sign-in require an exact match.
    private var authorityTrust: ManagerAuthorityTrustStore?
    /// Actual v2 sign-in state owner (causal generation fencing lives here).
    private var authCoordinator: AuthSignInCoordinator?

    /// Internal seam for fixtures/previews/tests. Production launch uses the
    /// checked `installProductionConnection` path; arbitrary injected clients do
    /// not satisfy the production gates.
    init(
        configuration: ManagerLaunchConfiguration = ManagerLaunchConfiguration(),
        client: (any ConnectionClient)? = nil,
        productionAuthClient: NativeV2AuthClient? = nil,
        authorityTrust: ManagerAuthorityTrustStore? = nil
    ) {
        let mode: SessionMode
        if configuration.useSourceFixtures {
            mode = .fixtures
        } else if configuration.useDevelopmentServer {
            mode = .development
        } else {
            mode = .production
        }
        self.sessionMode = mode
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
        self.productionAuthClient = mode == .production ? productionAuthClient : nil
        self.authorityTrust = mode == .production ? authorityTrust : nil
        self.authCoordinator = (mode == .production ? productionAuthClient : nil).map {
            AuthSignInCoordinator(client: $0)
        }

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
        if productionAuthClient != nil, authorityTrust != nil {
            return "Pinned HTTPS with independently supplied deployment trust and an authority checkpoint store. No fallback to development login."
        }
        if productionAuthClient != nil {
            return "Production connection is closed until a saved deployment authority checkpoint is available."
        }
        return "Production connection is closed until a trusted server identity is available."
    }

    /// Install a verified production client and its saved authority checkpoint
    /// store. The session must be on the immutable production path, and the
    /// store must already contain a checkpoint for the client's deployment.
    ///
    /// This method does not fetch or adopt anything. The caller must complete the
    /// independent CA/authority verification flow first and must build `client`
    /// from the TLS identity bound in the same production trust record.
    @discardableResult
    public func installProductionConnection(
        client: NativeV2AuthClient,
        authorityTrust: ManagerAuthorityTrustStore,
        serverAddress: String,
        expectedRecord: ManagerAuthorityTrustRecord? = nil
    ) async -> Bool {
        guard sessionMode == .production,
              self.productionAuthClient == nil,
              self.authorityTrust == nil,
              client.isProductionPinned else {
            return false
        }
        let identity = client.trustedIdentity
        guard !identity.deploymentID.isEmpty else { return false }
        let saved: ManagerAuthorityTrustRecord?
        do {
            saved = try await authorityTrust.productionTrustRecord(
                deploymentID: identity.deploymentID
            )
        } catch {
            return false
        }
        // A legacy checkpoint-only record, a mixed record, or a record bound to
        // a different host/port/CA/deployment must not install a production
        // client. Core owns the full typed comparison.
        guard let saved,
              expectedRecord == nil || saved == expectedRecord else {
            return false
        }
        do {
            try saved.requireBoundTLSIdentity(identity)
        } catch {
            return false
        }

        self.productionAuthClient = client
        self.authorityTrust = authorityTrust
        self.authCoordinator = AuthSignInCoordinator(client: client)
        self.authCoordinator?.observer = self
        if !serverAddress.isEmpty {
            self.serverAddress = serverAddress
        }
        presentationPreferenceScope = nil
        connectError = nil
        signInError = nil
        authCodeError = nil
        inventoryReloadError = nil
        phase = .notConfigured
        screen = .connect
        bumpSessionGeneration()
        return true
    }

    /// Detach a production client/store after a failed connect so the bootstrap
    /// screen can review or replace trust. Never detaches a live session.
    public func uninstallProductionConnection() {
        guard sessionMode == .production,
              authCoordinator?.session == nil,
              productionAuthClient != nil,
              authorityTrust != nil else {
            return
        }
        productionAuthClient = nil
        authorityTrust = nil
        authCoordinator = nil
        authCode = ""
        password = ""
        presentationPreferenceScope = nil
        bumpSessionGeneration()
        phase = .notConfigured
        screen = .connect
    }

    /// Example edits exist only in the in-memory fixture session.
    public func saveExampleComputer(_ computer: Computer) {
        guard isFixturesMode, !computer.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        overview.upsert(computer)
        overview.includeComputer(computer.id)
    }

    // MARK: - Connection flow

    public func connect() async {
        connectError = nil
        signInError = nil
        signOutError = nil
        clearSessionMaterial()
        bumpSessionGeneration()
        let authorityCheck = beginAuthorityCheck()

        guard allowsConnect else {
            let failure: ConnectionFailure = sessionMode == .production
                ? .identityUnverified
                : .serverContractUnavailable
            connectError = failure
            phase = .failed(failure)
            return
        }


        if let auth = productionAuthClient, sessionMode == .production {
            // Trust configuration is already supplied. Discovery does not
            // establish trust and is never used to mint a deployment identity.
            phase = .connecting
            if let error = await verifyAuthorityBeforeProductionUse() {
                guard !Task.isCancelled, isCurrentAuthorityCheck(authorityCheck) else { return }
                applyConnectFailure(error)
                return
            }
            guard !Task.isCancelled, isCurrentAuthorityCheck(authorityCheck) else { return }
            let result = await auth.connect(address: serverAddress.trimmingCharacters(in: .whitespacesAndNewlines))
            guard !Task.isCancelled, isCurrentAuthorityCheck(authorityCheck) else { return }
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
        let failure = Self.connectionFailure(for: error)
        connectError = failure
        phase = .failed(failure)
    }

    /// Honest mapping from authority/production failures to connection UI.
    private static func connectionFailure(for error: HelicoidError) -> ConnectionFailure {
        switch error {
        case .serverContractUnavailable:
            return .serverContractUnavailable
        case .invalidInput(_, let detail):
            return .invalidAddress(detail: detail)
        case .identityMismatch:
            return .identityChanged
        case .authenticationFailed(let detail):
            return .authenticationFailed(detail: detail)
        case .permissionDenied(let detail):
            return .authenticationFailed(detail: detail)
        case .cancelled:
            return .cancelled
        case .engineUnavailable:
            return .engineUnavailable
        case .notConfigured, .sessionExpired(_), .computerOutOfScope,
             .observationProtocolViolation(_), .setupBlocked(_), .hostIdentityUnverified,
             .installNotAvailable, .unreachable, .offline:
            return .unreachable
        }
    }

    /// Re-read the published deployment authority and require the exact saved
    /// checkpoint before production connect or sign-in. The caller must supply a
    /// store on the production path; without one, `allowsConnect` is false and
    /// this method is not reached.
    private func verifyAuthorityBeforeProductionUse() async -> HelicoidError? {
        guard sessionMode == .production else {
            return nil
        }
        guard productionAuthClient != nil else {
            return nil
        }
        guard let auth = productionAuthClient, let authorityTrust else {
            // A production client without a checkpoint store must not be
            // treated as verified. Callers surface this as identityUnverified.
            return .authenticationFailed(
                detail: "No independently verified deployment authority checkpoint is saved. Complete out-of-band trust setup before connecting."
            )
        }
        guard auth.isProductionPinned else {
            return .authenticationFailed(
                detail: "The production connection client is not pinned to the deployment CA. Complete production trust setup before connecting."
            )
        }
        do {
            // Fail before touching the authority endpoint when this deployment
            // has no locally adopted checkpoint or no exact typed TLS binding.
            // Fetching alone would not adopt anything, but there is no reason
            // to contact the server first.
            guard let record = try await authorityTrust.productionTrustRecord(
                deploymentID: auth.trustedIdentity.deploymentID
            ) else {
                return .authenticationFailed(
                    detail: "No atomically bound deployment TLS trust record is saved. Complete out-of-band production trust setup before connecting."
                )
            }
            try record.requireBoundTLSIdentity(auth.trustedIdentity)
            let observed = try await auth.fetchDeploymentAuthority()
            _ = try await authorityTrust.requireCurrent(observed)
            return nil
        } catch let error as HelicoidError {
            return error
        } catch {
            return .identityMismatch
        }
    }

    public func trustPendingIdentity() async {
        guard allowsConnect else {
            connectError = sessionMode == .production
                ? .identityUnverified
                : .serverContractUnavailable
            phase = .failed(connectError ?? .serverContractUnavailable)
            return
        }
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
        guard allowsConnect else {
            password = ""
            let failure: ConnectionFailure = sessionMode == .production
                ? .identityUnverified
                : .serverContractUnavailable
            signInError = .authenticationFailed(
                detail: sessionMode == .production
                    ? "No independently verified deployment authority checkpoint is available. Complete out-of-band trust setup before signing in."
                    : "Connect to a Helicoid server before signing in."
            )
            phase = .failed(failure)
            screen = .signIn
            return
        }
        connectError = nil
        signInError = nil
        authCodeError = nil
        inventoryReloadError = nil
        overview.setInventory([])
        let authorityCheck = beginAuthorityCheck()

        if requiresProductionTrust, authorityTrust == nil {
            password = ""
            signInError = .authenticationFailed(
                detail: "No independently verified deployment authority checkpoint is saved. Complete out-of-band trust setup before signing in."
            )
            phase = .failed(.identityUnverified)
            screen = .signIn
            return
        }

        if let error = await verifyAuthorityBeforeProductionUse() {
            guard !Task.isCancelled, isCurrentAuthorityCheck(authorityCheck) else { return }
            password = ""
            signInError = error
            phase = .failed(Self.connectionFailure(for: error))
            screen = .signIn
            return
        }
        guard !Task.isCancelled, isCurrentAuthorityCheck(authorityCheck) else { return }

        if let coordinator = authCoordinator, sessionMode == .production {
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
        let authorityCheck = beginAuthorityCheck()

        // Required MFA completion is a later trust decision. Recheck the full
        // authority checkpoint immediately before completing the challenge.
        if sessionMode == .production {
            if let error = await verifyAuthorityBeforeProductionUse() {
                guard !Task.isCancelled, isCurrentAuthorityCheck(authorityCheck) else { return }
                // Clear the pending challenge without letting its observer
                // overwrite the fail-closed error below.
                await coordinator.cancelAuthCode()
                guard !Task.isCancelled, isCurrentAuthorityCheck(authorityCheck) else { return }
                authCode = ""
                password = ""
                authCodeError = error
                signInError = error
                phase = .failed(Self.connectionFailure(for: error))
                screen = .signIn
                return
            }
            guard !Task.isCancelled, isCurrentAuthorityCheck(authorityCheck) else { return }
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
        _ = beginAuthorityCheck()
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
        let hadLiveSession = phase == .signedIn
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
        // Coordinator is the authoritative sign-in error surface. Assigning the
        // optional directly is what lets a successful retry clear a stale
        // transient refresh failure mirrored onto this facade.
        signInError = coordinator.signInError
        authCodeError = coordinator.authCodeError
        // Mirror coordinator inventory into the actual overview facade.
        if case .signedIn = coordinator.phase {
            overview.setInventory(coordinator.inventory)
        } else if coordinator.inventory.isEmpty {
            overview.setInventory([])
        } else {
            overview.setInventory(coordinator.inventory)
        }
        // Expiry, revoked credentials, or permission loss must drop remote
        // windows and advance the session generation, exactly once.
        if hadLiveSession,
           coordinator.session == nil,
           let error = coordinator.signInError,
           Self.endsLiveSession(error) {
            bumpSessionGeneration()
            overview.setInventory([])
            openRemoteWindows = []
            phase = .needsSignIn
            screen = .signIn
        }
    }

    /// Errors after a live session that must invalidate window/session stamps.
    private static func endsLiveSession(_ error: HelicoidError) -> Bool {
        switch error {
        case .sessionExpired, .authenticationFailed, .permissionDenied:
            true
        default:
            false
        }
    }

    /// Automatic facade sync when the coordinator changes (expiry, 401, …).
    public func authSignInCoordinatorDidUpdate(_ coordinator: AuthSignInCoordinator) {
        syncAuthUIFromCoordinator()
    }

    public func reloadInventory() async {
        guard !isFixturesMode, phase == .signedIn else { return }

        inventoryReloadGeneration &+= 1
        let reloadGeneration = inventoryReloadGeneration
        let sessionGenerationAtStart = sessionGeneration
        inventoryReloadError = nil
        isReloadingInventory = true
        defer {
            if reloadGeneration == inventoryReloadGeneration {
                isReloadingInventory = false
            }
        }

        if sessionMode == .production {
            guard let coordinator = authCoordinator,
                  productionAuthClient != nil,
                  coordinator.session != nil else {
                let error = HelicoidError.authenticationFailed(
                    detail: "No verified production authority session is available. Sign in again after trust setup."
                )
                bumpSessionGeneration()
                inventoryReloadError = error
                signInError = error
                overview.setInventory([])
                phase = .failed(.identityUnverified)
                screen = .signIn
                return
            }
            await coordinator.reloadInventory()
            let coordinatorError = coordinator.signInError
            guard reloadGeneration == inventoryReloadGeneration,
                  sessionGenerationAtStart == sessionGeneration else {
                // A fail-closed coordinator teardown invalidated this refresh.
                // Preserve the terminal cause consistently with the direct path.
                if coordinator.session == nil,
                   let coordinatorError,
                   Self.endsLiveSession(coordinatorError) {
                    inventoryReloadError = coordinatorError
                    signInError = coordinatorError
                }
                return
            }
            syncAuthUIFromCoordinator()
            guard reloadGeneration == inventoryReloadGeneration,
                  sessionGenerationAtStart == sessionGeneration else { return }
            overview.setInventory(coordinator.inventory)
            inventoryReloadError = coordinatorError
            signInError = coordinatorError
            return
        }

        // Nonproduction development path. Fixtures returned above.
        let result = await client.authorizedInventory()
        // A late response after sign-out, replacement, or a newer refresh is stale.
        guard reloadGeneration == inventoryReloadGeneration,
              sessionGenerationAtStart == sessionGeneration else { return }
        switch result {
        case .success(let computers):
            overview.setInventory(computers)
            // A successful retry supersedes any prior refresh failure.
            signInError = nil
        case .failure(let error):
            // Keep the last known inventory for transient failures. Confirmed
            // credential loss or permission revocation fails closed, matching
            // the coordinator's automatic load behavior.
            inventoryReloadError = error
            signInError = error
            switch error {
            case .sessionExpired, .authenticationFailed, .permissionDenied:
                bumpSessionGeneration()
                // Preserve the refresh error that prompted teardown even though
                // a session-generation bump normally clears stale refresh state.
                inventoryReloadError = error
                signInError = error
                overview.setInventory([])
                phase = .needsSignIn
                screen = .signIn
            default:
                break
            }
        }
    }

    /// Clears token, identity, and inventory even if remote logout fails.
    public func signOut() async {
        // Invalidate any in-flight authority check before awaiting remote or
        // coordinator work, so it cannot re-enter sign-in during teardown.
        _ = beginAuthorityCheck()
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
        showDevelopmentBanner = false
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
        inventoryReloadError = nil
    }

    // MARK: - Remote windows (view-only; engine honestly unavailable)

    /// Opens or focuses the native view-only window for `id`.
    /// Unauthorized / unknown IDs refuse to open. Re-open dedupes demand.
    /// Returns the generation-scoped window key for this demand.
    @discardableResult
    public func openRemoteView(for id: ComputerID) -> ComputerViewWindowKey? {
        guard isFixturesMode || phase == .signedIn else { return nil }
        if sessionMode == .production, authCoordinator?.session == nil {
            return nil
        }
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

    /// Start a new authority-check operation and return its fence token.
    private func beginAuthorityCheck() -> UInt64 {
        authorityCheckGeneration &+= 1
        return authorityCheckGeneration
    }

    /// True only while no newer connect, sign-in, or session teardown occurred.
    private func isCurrentAuthorityCheck(_ token: UInt64) -> Bool {
        token == authorityCheckGeneration
    }

    private func bumpSessionGeneration() {
        sessionGeneration &+= 1
        // Session change invalidates every view-only demand, in-flight
        // inventory refresh, and authority-check result from the prior state.
        inventoryReloadGeneration &+= 1
        authorityCheckGeneration &+= 1
        isReloadingInventory = false
        inventoryReloadError = nil
        openRemoteWindows = []
    }
}
