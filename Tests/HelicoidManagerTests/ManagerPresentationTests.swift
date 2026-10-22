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
}
