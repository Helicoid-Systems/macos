import Foundation
import Testing
@testable import HelicoidCore
@testable import HelicoidManager

/// Session/presentation seam acceptance for UI03.
@Suite("Manager presentation and view windows")
@MainActor
struct ManagerPresentationTests {
    private func makeFixtureSession() -> ManagerSession {
        ManagerSession(configuration: ManagerLaunchConfiguration(useSourceFixtures: true))
    }

    private func makeSessionWithInventory() -> ManagerSession {
        let session = makeFixtureSession()
        return session
    }

    @Test("Example edits stay in fixture sessions")
    func exampleEdits() {
        let example = Computer(id: ComputerID("example-test"), name: "Example", isOnline: true)
        let demo = makeFixtureSession()
        #expect(demo.screen == .computers)
        demo.saveExampleComputer(example)
        #expect(demo.computer(with: example.id) == example)
        var renamed = example
        renamed.name = "Renamed"
        demo.saveExampleComputer(renamed)
        #expect(demo.computer(with: example.id)?.name == "Renamed")
        let normal = ManagerSession(configuration: ManagerLaunchConfiguration())
        normal.saveExampleComputer(example)
        #expect(normal.computer(with: example.id) == nil)
        #expect(makeFixtureSession().computer(with: example.id) == nil)
    }

    // MARK: - View window demand

    @Test("Open dedupes per computer")
    func viewWindowDedupe() {
        let session = makeFixtureSession()
        let id = ComputerID("fixture-lab-01")
        #expect(session.openRemoteView(for: id) != nil)
        #expect(session.openRemoteView(for: id) != nil)
        #expect(session.openRemoteWindows == [id])
    }

    @Test("Close one removes only its own demand")
    func closeOneWindow() {
        let session = makeFixtureSession()
        let a = ComputerID("fixture-lab-01")
        let b = ComputerID("fixture-lab-02")
        #expect(session.openRemoteView(for: a) != nil)
        #expect(session.openRemoteView(for: b) != nil)
        #expect(session.openRemoteWindows.count == 2)
        session.closeRemoteView(for: a)
        #expect(session.openRemoteWindows == [b])
        #expect(session.openRemoteWindows.contains(a) == false)
    }

    @Test("Unauthorized ID refuses open")
    func unauthorizedIDRefusesOpen() {
        let session = makeFixtureSession()
        #expect(session.openRemoteView(for: ComputerID("not-in-inventory")) == nil)
        #expect(session.openRemoteWindows.isEmpty)
    }

    @Test("Session expiry clears view-window demand and bumps generation")
    func sessionExpiryClearsDemand() async {
        let session = makeFixtureSession()
        let id = ComputerID("fixture-lab-01")
        #expect(session.openRemoteView(for: id) != nil)
        let generation = session.sessionGeneration
        await session.signOut()
        #expect(session.openRemoteWindows.isEmpty)
        #expect(session.sessionGeneration > generation)
        // Reopen after sign-out is refused until a new session is live.
        #expect(session.openRemoteView(for: id) == nil)
    }

    @Test("Delayed old-window close cannot remove a replacement session demand")
    func staleWindowClose() async throws {
        let session = makeFixtureSession()
        let id = ComputerID("fixture-lab-01")
        let oldKey = try #require(session.openRemoteView(for: id))
        await session.signOut()
        session.isFixturesMode = true
        session.phase = .signedIn
        session.overview = DevelopmentFixtures.overviewModel()
        let newKey = try #require(session.openRemoteView(for: id))
        #expect(oldKey.sessionGeneration != newKey.sessionGeneration)
        session.closeRemoteView(for: oldKey)
        #expect(session.openRemoteWindows == [id])
        session.closeRemoteView(for: newKey)
        #expect(session.openRemoteWindows.isEmpty)
    }

    @Test("Preference keys cannot collide when identity components contain separators")
    func preferenceKeyCollision() {
        let store = PresentationPreferenceStore(scope: nil)
        let a = PresentationPreferenceScope(deploymentID: "a.b", accountID: "c")
        let b = PresentationPreferenceScope(deploymentID: "a", accountID: "b.c")
        #expect(store.storageKey(for: a) != store.storageKey(for: b))
    }

    // MARK: - Preference / layout selection invariants

    @Test("Layout and preview size changes preserve selection, filter, and scope")
    func layoutSelectionInvariants() {
        let session = makeFixtureSession()
        let id = ComputerID("fixture-lab-01")
        session.overview.selectOnly(id)
        session.overview.setSearchText("Lab")
        session.overview.setStatusFilter(.online)
        let scopeBefore = session.overview.scope.displayedIDs
        let selectionBefore = session.overview.selection.selectedIDs

        session.setPresentationLayout(.list)
        session.setPresentationPreviewSize(.compact)

        #expect(session.presentation.layout == .list)
        #expect(session.presentation.previewSize == .compact)
        #expect(session.overview.selection.selectedIDs == selectionBefore)
        #expect(session.overview.filter.searchText == "Lab")
        #expect(session.overview.filter.status == .online)
        #expect(session.overview.scope.displayedIDs == scopeBefore)
    }

    @Test("Preview presets use accepted logical widths")
    func previewPresetWidths() {
        #expect(ManagerPreviewSize.compact.tileWidth == 192)
        #expect(ManagerPreviewSize.standard.tileWidth == 256)
        #expect(ManagerPreviewSize.large.tileWidth == 320)
        #expect(ManagerPreviewSize.extraLarge.tileWidth == 448)
        #expect(ManagerPreviewSize.default == .large)
    }

    @Test("Presentation preferences are session-only without a real scope")
    func preferenceSessionOnlyWithoutScope() {
        let session = makeFixtureSession()
        let store = PresentationPreferenceStore(
            scope: nil,
            defaults: UserDefaults(suiteName: "hs-ui03-tests-nil-scope")!
        )
        #expect(store.canPersist == false)
        #expect(store.missingPrerequisite != nil)
        store.save(ManagerPresentationPreferences(layout: .list, previewSize: .compact))
        #expect(store.load() == nil)
        #expect(session.presentationPreferenceScope == nil)
    }

    @Test("Preference store isolates account+deployment scopes")
    func preferenceScopeIsolation() {
        let suiteName = "hs-ui03-tests-scope-isolation"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let scopeA = PresentationPreferenceScope(deploymentID: "deploy-a", accountID: "acct-1")
        let scopeB = PresentationPreferenceScope(deploymentID: "deploy-a", accountID: "acct-2")
        let storeA = PresentationPreferenceStore(scope: scopeA, defaults: defaults)
        let storeB = PresentationPreferenceStore(scope: scopeB, defaults: defaults)

        var prefsA = ManagerPresentationPreferences()
        prefsA.layout = .list
        prefsA.previewSize = .compact
        storeA.save(prefsA)

        var prefsB = ManagerPresentationPreferences()
        prefsB.layout = .grid
        prefsB.previewSize = .extraLarge
        storeB.save(prefsB)

        #expect(storeA.load()?.layout == .list)
        #expect(storeA.load()?.previewSize == .compact)
        #expect(storeB.load()?.layout == .grid)
        #expect(storeB.load()?.previewSize == .extraLarge)
    }

    @Test("Clear filters resets only search and status")
    func clearFiltersOnly() {
        let session = makeFixtureSession()
        let id = ComputerID("fixture-lab-01")
        session.setPresentationLayout(.list)
        session.setPresentationPreviewSize(.standard)
        session.overview.setSearchText("zzz")
        session.overview.setStatusFilter(.online)
        // A subsequent filter change must clear temporary selection.
        session.overview.selectOnly(id)

        session.clearInventoryFilters()

        #expect(session.overview.filter.searchText.isEmpty)
        #expect(session.overview.filter.status == .all)
        #expect(session.overview.selection.selectedIDs.isEmpty)
        #expect(session.presentation.layout == .list)
        #expect(session.presentation.previewSize == .standard)
    }

    // MARK: - Empty reason

    @Test("Distinct empty reasons for inventory, inclusion, and filters")
    func filterEmptyReason() {
        let empty = ManagerSession(configuration: ManagerLaunchConfiguration())
        #expect(empty.inventoryEmptyReason == .noAuthorizedInventory)

        let session = makeFixtureSession()
        session.overview.clearAllComputersMode()
        #expect(session.inventoryEmptyReason == .noneIncluded)

        session.overview.selectAllComputersMode()
        session.overview.setSearchText("no-such-computer")
        #expect(session.inventoryEmptyReason == .noResults)

        session.clearInventoryFilters()
        #expect(session.overview.scope.displayedIDs.isEmpty == false)
    }

    @Test("Only the no-results empty state owns Clear Filters")
    func clearFiltersActionOwnership() {
        #expect(InventoryEmptyReason.noResults.offersClearFiltersAction)
        #expect(InventoryEmptyReason.noAuthorizedInventory.offersClearFiltersAction == false)
        #expect(InventoryEmptyReason.noneIncluded.offersClearFiltersAction == false)
    }

    @Test("Choose Computers opens panel and does not auto-select All")
    func chooseComputersOpensPanelOnly() {
        let session = makeFixtureSession()
        session.overview.clearAllComputersMode()
        session.setComputersPanelShown(false)

        // Empty-state action must only open the panel.
        session.setComputersPanelShown(true)

        #expect(session.presentation.isComputersPanelShown)
        #expect(session.overview.inclusion == .explicit([]))
    }

    // MARK: - Tri-state

    @Test("Tri-state All and group checkboxes follow real inclusion")
    func triStateCheckboxes() {
        let session = makeFixtureSession()
        #expect(session.allComputersCheckState == .on)

        session.overview.excludeComputer(ComputerID("fixture-lab-01"))
        #expect(session.allComputersCheckState == .mixed)

        session.overview.clearAllComputersMode()
        #expect(session.allComputersCheckState == .off)
        #expect(session.groupCheckState(groupID: "group-lab") == .off)

        session.overview.includeComputer(ComputerID("fixture-lab-01"))
        #expect(session.groupCheckState(groupID: "group-lab") == .mixed)

        session.overview.includeComputer(ComputerID("fixture-lab-02"))
        #expect(session.groupCheckState(groupID: "group-lab") == .on)
        #expect(session.allComputersCheckState == .mixed)

        session.applyAllComputersCheckState(.on)
        #expect(session.allComputersCheckState == .on)
    }

    // MARK: - Natural name order

    @Test("Displayed order is stable natural name then ID")
    func naturalNameOrder() {
        let session = makeFixtureSession()
        let names = session.overview.scope.computers.map(\.name)
        #expect(names == ["Lab Mac A", "Lab Mac B", "Office PC 01", "Office PC 02", "Spare Laptop"])
        #expect(session.overview.scope.displayedIDs == session.overview.scope.computers.map(\.id))
    }

    // MARK: - Pause / resume

    @Test("Pause and resume use overview monitoring methods")
    func pauseResumeMonitoring() {
        let session = makeFixtureSession()
        session.overview.requestAdmission(ComputerID("fixture-lab-01"))
        session.overview.pauseMonitoring()
        #expect(session.overview.isMonitoringPaused)
        #expect(session.overview.admittedStreams[ComputerID("fixture-lab-01")] == .idle)
        session.overview.resumeMonitoring()
        #expect(session.overview.isMonitoringPaused == false)
        #expect(session.overview.admittedStreams[ComputerID("fixture-lab-01")] == .requesting)
    }

    // MARK: - Inventory refresh

    @Test("Manual refresh shows progress and applies authorized inventory")
    func inventoryRefreshProgressAndSuccess() async {
        let client = ScriptedInventoryClient()
        let session = ManagerSession(configuration: ManagerLaunchConfiguration(), client: client)
        session.phase = .signedIn
        session.screen = .computers
        let refreshed = Computer(id: ComputerID("refresh-1"), name: "Refresh One", isOnline: true)

        let task = Task { await session.reloadInventory() }
        await client.waitUntilRequested()
        #expect(session.isReloadingInventory)

        client.enqueue(.success([refreshed]))
        await task.value

        #expect(session.overview.authorizedInventory == [refreshed])
        #expect(session.inventoryReloadError == nil)
        #expect(session.isReloadingInventory == false)
        #expect(session.phase == .signedIn)
    }

    @Test("Failed refresh keeps last known inventory and exposes Retry")
    func inventoryRefreshFailurePreservesInventory() async {
        let client = ScriptedInventoryClient()
        let session = ManagerSession(configuration: ManagerLaunchConfiguration(), client: client)
        session.phase = .signedIn
        session.screen = .computers
        let existing = Computer(id: ComputerID("known-1"), name: "Known One", isOnline: true)
        session.overview.setInventory([existing])

        client.enqueue(.failure(.unreachable))
        await session.reloadInventory()

        #expect(session.overview.authorizedInventory == [existing])
        #expect(session.inventoryReloadError == .unreachable)
        #expect(session.isReloadingInventory == false)
        #expect(session.phase == .signedIn)
        #expect(session.screen == .computers)
    }

    @Test("Permission loss during refresh ends the session instead of keeping stale access")
    func inventoryRefreshPermissionLoss() async {
        let client = ScriptedInventoryClient()
        let session = ManagerSession(configuration: ManagerLaunchConfiguration(), client: client)
        session.phase = .signedIn
        session.screen = .computers
        session.overview.setInventory([
            Computer(id: ComputerID("known-1"), name: "Known One", isOnline: true)
        ])

        client.enqueue(.failure(.permissionDenied(detail: "Access was revoked.")))
        await session.reloadInventory()

        #expect(session.overview.authorizedInventory.isEmpty)
        #expect(session.screen == .signIn)
        #expect(session.phase == .needsSignIn)
        #expect(session.inventoryReloadError == .permissionDenied(detail: "Access was revoked."))
    }

    @Test(
        "Credential loss during refresh ends the session and clears inventory",
        arguments: [
            HelicoidError.sessionExpired(detail: "Your session expired. Sign in again."),
            HelicoidError.authenticationFailed(detail: "Sign-in was refused."),
        ]
    )
    func inventoryRefreshCredentialLoss(error: HelicoidError) async {
        let client = ScriptedInventoryClient()
        let session = ManagerSession(configuration: ManagerLaunchConfiguration(), client: client)
        session.phase = .signedIn
        session.screen = .computers
        let existing = Computer(id: ComputerID("known-1"), name: "Known One", isOnline: true)
        session.overview.setInventory([existing])
        #expect(session.openRemoteView(for: existing.id) != nil)

        client.enqueue(.failure(error))
        await session.reloadInventory()

        #expect(session.overview.authorizedInventory.isEmpty)
        #expect(session.openRemoteWindows.isEmpty)
        #expect(session.screen == .signIn)
        #expect(session.phase == .needsSignIn)
        #expect(session.inventoryReloadError == error)
        #expect(session.signInError == error)
        #expect(session.isReloadingInventory == false)
    }

    @Test("Failed refresh then successful retry clears the stale error")
    func inventoryRefreshRetryClearsError() async {
        let client = ScriptedInventoryClient()
        let session = ManagerSession(configuration: ManagerLaunchConfiguration(), client: client)
        session.phase = .signedIn
        session.screen = .computers
        let existing = Computer(id: ComputerID("known-1"), name: "Known One", isOnline: true)
        session.overview.setInventory([existing])

        client.enqueue(.failure(.unreachable))
        await session.reloadInventory()
        #expect(session.overview.authorizedInventory == [existing])
        #expect(session.inventoryReloadError == .unreachable)
        #expect(session.signInError == .unreachable)
        #expect(session.phase == .signedIn)

        let refreshed = Computer(id: ComputerID("refresh-2"), name: "Refresh Two", isOnline: true)
        client.enqueue(.success([refreshed]))
        await session.reloadInventory()

        #expect(session.overview.authorizedInventory == [refreshed])
        #expect(session.inventoryReloadError == nil)
        #expect(session.signInError == nil)
        #expect(session.phase == .signedIn)
        #expect(session.isReloadingInventory == false)
    }

    @Test("Refresh response after sign-out cannot repopulate inventory")
    func staleRefreshAfterSignOut() async {
        let client = ScriptedInventoryClient()
        let session = ManagerSession(configuration: ManagerLaunchConfiguration(), client: client)
        session.phase = .signedIn
        session.screen = .computers

        let task = Task { await session.reloadInventory() }
        await client.waitUntilRequested()
        #expect(session.isReloadingInventory)

        await session.signOut()
        client.enqueue(.success([
            Computer(id: ComputerID("late-1"), name: "Late One", isOnline: true)
        ]))
        await task.value

        #expect(session.overview.authorizedInventory.isEmpty)
        #expect(session.inventoryReloadError == nil)
        #expect(session.isReloadingInventory == false)
        #expect(session.screen == .connect)
        #expect(session.phase == .notConfigured)
    }

    @Test("Newer refresh wins when an older response arrives later")
    func newerRefreshSupersedesOlderResponse() async {
        let client = ScriptedInventoryClient()
        let session = ManagerSession(configuration: ManagerLaunchConfiguration(), client: client)
        session.phase = .signedIn
        session.screen = .computers
        let older = Computer(id: ComputerID("older-1"), name: "Older", isOnline: true)
        let newer = Computer(id: ComputerID("newer-1"), name: "Newer", isOnline: true)

        let first = Task { await session.reloadInventory() }
        await client.waitUntilRequested(count: 1)
        let second = Task { await session.reloadInventory() }
        await client.waitUntilRequested(count: 2)

        // Complete the newer request first, then let the superseded one return.
        client.enqueue(.success([newer]))
        await second.value
        client.enqueue(.success([older]))
        await first.value

        #expect(session.overview.authorizedInventory == [newer])
        #expect(session.inventoryReloadError == nil)
        #expect(session.isReloadingInventory == false)
    }

    @Test("Fixture sessions do not refresh or replace edited examples")
    func fixturesRefreshIsNoOp() async {
        let session = makeFixtureSession()
        let before = session.overview.authorizedInventory

        await session.reloadInventory()

        #expect(session.overview.authorizedInventory == before)
        #expect(session.inventoryReloadError == nil)
        #expect(session.isReloadingInventory == false)
    }
}

/// Scripted inventory boundary. Without a queued result the request suspends
/// so progress and stale-response fencing are observable.
private final class ScriptedInventoryClient: ConnectionClient, @unchecked Sendable {
    private let lock = NSLock()
    private var queued: [Result<[Computer], HelicoidError>] = []
    private var pending: [CheckedContinuation<Result<[Computer], HelicoidError>, Never>] = []
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var requestCount = 0

    func enqueue(_ result: Result<[Computer], HelicoidError>) {
        lock.lock()
        if pending.isEmpty {
            queued.append(result)
            lock.unlock()
        } else {
            // LIFO lets a test release a newer request before an older one.
            let continuation = pending.removeLast()
            lock.unlock()
            continuation.resume(returning: result)
        }
    }

    func waitUntilRequested(count: Int = 1) async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if requestCount >= count {
                lock.unlock()
                continuation.resume()
            } else {
                startWaiters.append(continuation)
                lock.unlock()
            }
        }
    }

    func validateAddress(_ address: String) async -> AddressValidation {
        _ = address
        return AddressValidation(outcome: .ok)
    }

    func connect(address: String) async -> Result<ServerIdentity, HelicoidError> {
        _ = address
        return .failure(.serverContractUnavailable)
    }

    func trust(identity: ServerIdentity, address: String) async -> Result<Void, HelicoidError> {
        _ = identity
        _ = address
        return .failure(.serverContractUnavailable)
    }

    func signIn(username: String, password: String) async -> Result<OperatorID, HelicoidError> {
        _ = username
        _ = password
        return .failure(.serverContractUnavailable)
    }

    func authorizedInventory() async -> Result<[Computer], HelicoidError> {
        await withCheckedContinuation { continuation in
            lock.lock()
            requestCount += 1
            let starts = startWaiters
            startWaiters.removeAll()
            if queued.isEmpty {
                pending.append(continuation)
                lock.unlock()
                starts.forEach { $0.resume() }
            } else {
                let result = queued.removeFirst()
                lock.unlock()
                starts.forEach { $0.resume() }
                continuation.resume(returning: result)
            }
        }
    }

    func managerApprovalState() async -> Result<ManagerApprovalState, HelicoidError> {
        .success(.approved)
    }

    func signOut() async {}
}
