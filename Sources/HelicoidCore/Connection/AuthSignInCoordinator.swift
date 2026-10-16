import Foundation

/// Causal ownership coordinator for native v2 sign-in UI state.
///
/// Every sign-in, code submit, inventory reload, and cancel is stamped with an
/// operation generation. Stale branches may finish after a newer operation
/// begins; they must never clear, cancel, sign out, or install over the
/// replacement. This type is the actual state code ManagerSession drives.
/// Weak facade hook. ManagerSession copies UI state on every coordinator
/// change so automatic expiry reaches the actual app without polling.
@MainActor
public protocol AuthSignInObserving: AnyObject {
    func authSignInCoordinatorDidUpdate(_ coordinator: AuthSignInCoordinator)
}

@MainActor
public final class AuthSignInCoordinator {
    public enum Phase: Hashable, Sendable {
        case idle
        case awaitingCredentials
        case awaitingRequiredCode
        case signedIn
        case pendingManagerApproval
        case failed(HelicoidError)
    }

    public private(set) var phase: Phase = .idle
    public private(set) var authCodeState: AuthCodeState = .idle
    public private(set) var authCode: String = ""
    public private(set) var authCodeError: HelicoidError?
    public private(set) var signInError: HelicoidError?
    public private(set) var pendingChallenge: PendingAuthChallenge?
    public private(set) var session: AuthenticatedSession?
    public private(set) var inventory: [Computer] = []

    /// Weak observer — no retain cycle with ManagerSession.
    public weak var observer: AuthSignInObserving?

    private let client: NativeV2AuthClient
    /// Install fence for session UI installation.
    private var installGate = AuthInstallGate()
    /// Inventory fence: bumped on sign-out/cancel so late inventory cannot re-install.
    private var inventoryGeneration: UInt64 = 0
    private var signInTask: Task<Void, Never>?
    private var ownedSignInToken: UInt64?
    /// Owned session-expiry sleeper. Cancelled on replacement/sign-out.
    private var sessionExpiryTask: Task<Void, Never>?
    private var sessionExpiryInstallToken: UInt64?

    public init(client: NativeV2AuthClient) {
        self.client = client
    }

    // MARK: - Ownership

    /// True when `token` is still the current sign-in operation.
    public func ownsOperation(_ token: UInt64) -> Bool {
        installGate.permits(token)
    }

    /// Begin a new sign-in operation. Invalidates in-flight work.
    @discardableResult
    public func beginOperation() -> UInt64 {
        let token = installGate.begin()
        ownedSignInToken = token
        if let task = signInTask {
            task.cancel()
            signInTask = nil
        }
        cancelSessionExpiryTask()
        return token
    }

    private func cancelSessionExpiryTask() {
        sessionExpiryTask?.cancel()
        sessionExpiryTask = nil
        sessionExpiryInstallToken = nil
    }

    // MARK: - Sign-in

    public func signIn(username: String, password: String) async {
        let token = beginOperation()
        signInError = nil
        authCodeError = nil
        inventory = []
        session = nil
        pendingChallenge = nil
        authCodeState = .idle
        authCode = ""

        let task = Task { @MainActor in
            await self.runSignIn(username: username, password: password, token: token)
        }
        signInTask = task
        await task.value
        clearOwnedTask(if: token)
    }

    private func runSignIn(username: String, password: String, token: UInt64) async {
        do {
            let challenge = try await client.beginChallenge(username: username, password: password)
            guard ownsOperation(token) else {
                // A newer operation owns the client. Do not cancel/clear it.
                return
            }
            pendingChallenge = challenge
            if challenge.requiresCode {
                authCodeState = .required
                authCode = ""
                authCodeError = nil
                phase = .awaitingRequiredCode
                return
            }
            authCodeState = .notRequired
            let session = try await client.completeChallenge(challenge, totpCode: nil)
            try await applyCompletedSession(session, installToken: token)
        } catch let error as HelicoidError {
            await applyFailure(error, installToken: token)
        } catch {
            await applyFailure(.authenticationFailed(detail: "Sign-in failed."), installToken: token)
        }
    }

    public func submitAuthCode() async {
        guard let challenge = pendingChallenge else {
            authCodeError = .authenticationFailed(detail: "Start sign-in again.")
            return
        }
        let token = beginOperation()
        signInError = nil
        authCodeError = nil
        let code = authCode
        let task = Task { @MainActor in
            do {
                let session = try await self.client.completeChallenge(challenge, totpCode: code)
                try await self.applyCompletedSession(session, installToken: token)
            } catch let error as HelicoidError {
                await self.applyFailure(error, installToken: token, keepCodeState: true)
            } catch {
                await self.applyFailure(.authenticationFailed(detail: "Sign-in failed."), installToken: token, keepCodeState: true)
            }
        }
        signInTask = task
        await task.value
        clearOwnedTask(if: token)
    }

    /// Install a completed session only when this operation still owns UI state.
    /// Causal gate after client success and before UI installation.
    public func applyCompletedSession(_ session: AuthenticatedSession, installToken: UInt64) async throws {
        guard ownsOperation(installToken) else {
            // Late completion must not install. Do not touch the replacement
            // operation's client challenge/session material.
            return
        }
        self.session = session
        pendingChallenge = nil
        authCode = ""
        authCodeError = nil
        authCodeState = .idle
        signInError = nil
        phase = .signedIn
        startSessionExpiryWatch(installToken: installToken)
        await reloadInventory(installToken: installToken)
        noteStateChanged()
    }

    /// Publish UI-relevant state to the weak facade observer.
    func noteStateChanged() {
        observer?.authSignInCoordinatorDidUpdate(self)
    }

    /// Watch live session deadline. On expiry, clear session/inventory and
    /// return to sign-in with useful copy. Stale timers cannot clear a
    /// replacement. Cancellation never reports expiry.
    private func startSessionExpiryWatch(installToken: UInt64) {
        cancelSessionExpiryTask()
        sessionExpiryInstallToken = installToken
        // Weak self + hold only the client across the sleep so this task does
        // not retain the coordinator for the whole session lifetime.
        sessionExpiryTask = Task { @MainActor [weak self] in
            guard let client = self?.client else { return }
            let outcome = await client.waitForSessionExpiry()
            guard let self else { return }
            guard self.ownsOperation(installToken), self.sessionExpiryInstallToken == installToken else {
                return
            }
            // Only a real deadline becomes expired UI. cancelled/cleared do not.
            if case .expired = outcome {
                self.applySessionExpired(installToken: installToken)
            }
        }
    }

    /// UI expiry: clear session + inventory and return to sign-in.
    /// Not a public mutation knob — tests advance a wakeable clock instead.
    func applySessionExpired(installToken: UInt64) {
        guard ownsOperation(installToken) else { return }
        cancelSessionExpiryTask()
        inventoryGeneration &+= 1
        session = nil
        inventory = []
        pendingChallenge = nil
        authCode = ""
        authCodeError = nil
        authCodeState = .idle
        signInError = .sessionExpired(detail: "Your session expired. Sign in again.")
        phase = .awaitingCredentials
        noteStateChanged()
    }

    /// Apply a failure only for the owning operation.
    public func applyFailure(
        _ error: HelicoidError,
        installToken: UInt64,
        keepCodeState: Bool = false
    ) async {
        guard ownsOperation(installToken) else {
            // Stale cleanup cannot clear a replacement challenge or password UI.
            return
        }
        if case .cancelled = error {
            pendingChallenge = nil
            authCode = ""
            authCodeError = nil
            authCodeState = .idle
            signInError = error
            phase = .awaitingCredentials
            return
        }
        if keepCodeState, pendingChallenge != nil {
            authCodeError = error
            authCode = ""
            phase = .awaitingRequiredCode
            return
        }
        pendingChallenge = nil
        authCode = ""
        authCodeError = nil
        authCodeState = .idle
        signInError = error
        inventory = []
        session = nil
        if case .permissionDenied(let detail) = error, detail.lowercased().contains("manager") {
            phase = .pendingManagerApproval
        } else {
            phase = .awaitingCredentials
        }
        noteStateChanged()
    }

    /// Update the UI factor-code buffer (process memory only).
    public func setAuthCode(_ code: String) {
        authCode = code
    }

    /// Explicit user cancel. Fences install and clears current secrets.
    public func cancelAuthCode() async {
        let token = beginOperation()
        _ = token
        // User intent: cancel whatever is current, then clear UI.
        pendingChallenge = nil
        authCode = ""
        authCodeError = nil
        authCodeState = .idle
        signInError = nil
        phase = .awaitingCredentials
        await client.cancelSignIn()
        noteStateChanged()
    }

    /// Explicit sign-out. Invalidates inventory and session install.
    public func signOut() async {
        beginOperation()
        cancelSessionExpiryTask()
        inventoryGeneration &+= 1
        pendingChallenge = nil
        authCode = ""
        authCodeError = nil
        authCodeState = .idle
        session = nil
        inventory = []
        signInError = nil
        phase = .idle
        await client.signOut()
        noteStateChanged()
    }

    /// Inventory reload fenced against sign-out and newer operations.
    public func reloadInventory() async {
        await reloadInventory(installToken: installGate.generation)
    }

    private func reloadInventory(installToken: UInt64) async {
        let inventoryToken = inventoryGeneration
        guard ownsOperation(installToken) else { return }
        let result = await client.authorizedInventory()
        // A late inventory response must not restore prior inventory after
        // sign-out, cancel, or a newer sign-in.
        guard ownsOperation(installToken), inventoryToken == inventoryGeneration else {
            return
        }
        switch result {
        case .success(let computers):
            inventory = computers
        case .failure(let error):
            switch error {
            case .sessionExpired, .authenticationFailed:
                // Confirmed credential loss for this request. Clear auth state.
                guard ownsOperation(installToken) else { return }
                applySessionExpired(installToken: installToken)
                signInError = error
            case .permissionDenied:
                // Operation denial only — keep the permitted session.
                inventory = []
                signInError = error
                noteStateChanged()
            default:
                signInError = error
                noteStateChanged()
            }
        }
        noteStateChanged()
    }

    // MARK: - Test/inspection seams for causal gates

    /// Current install generation (diagnostics).
    public var currentGeneration: UInt64 { installGate.generation }

    /// Current inventory fence (diagnostics).
    public var currentInventoryGeneration: UInt64 { inventoryGeneration }

    /// Clear the owned task only when this operation still owns the slot.
    private func clearOwnedTask(if token: UInt64) {
        guard installGate.permits(token) || ownedSignInToken == token else {
            // A newer operation owns the slot.
            return
        }
        if ownedSignInToken == token {
            signInTask = nil
            ownedSignInToken = nil
        }
    }
}
