import Testing
import Foundation
@testable import HelicoidCore

@Suite("Monitoring inclusion")
struct MonitoringInclusionTests {
    let inventory = [
        Computer(id: ComputerID("a"), name: "Alpha"),
        Computer(id: ComputerID("b"), name: "Beta"),
        Computer(id: ComputerID("c"), name: "Gamma"),
    ]
    let authorizedIDs = [ComputerID("a"), ComputerID("b"), ComputerID("c")]

    @Test("All mode includes every authorized ID")
    func allModeIncludesEverything() {
        let inclusion = MonitoringInclusion.all
        #expect(inclusion.includedIDs(from: authorizedIDs) == Set(authorizedIDs))
        #expect(inclusion.includes(ComputerID("a")))
        #expect(inclusion.allComputersCheckState(authorized: authorizedIDs) == .on)
    }

    @Test("Explicit mode never expands silently")
    func explicitNeverExpands() {
        let inclusion = MonitoringInclusion.explicit([ComputerID("a")])
        #expect(inclusion.includedIDs(from: authorizedIDs) == [ComputerID("a")])
        #expect(inclusion.allComputersCheckState(authorized: authorizedIDs) == .mixed)
        // New inventory ID "d" is not added to explicit inclusion.
        let afterAdd = [ComputerID("a"), ComputerID("b"), ComputerID("c"), ComputerID("d")]
        #expect(inclusion.includedIDs(from: afterAdd) == [ComputerID("a")])
    }

    @Test("Excluding from All converts to explicit remaining IDs")
    func excludingFromAll() {
        let inclusion = MonitoringInclusion.all
        let next = inclusion.excludingFromAll(ComputerID("b"), authorized: authorizedIDs)
        #expect(next == .explicit([ComputerID("a"), ComputerID("c")]))
    }

    @Test("Saved unknown IDs are dropped, not invented")
    func unknownSavedIDsAreDropped() {
        let inclusion = MonitoringInclusion.explicit([ComputerID("a"), ComputerID("ghost")])
        #expect(inclusion.includedIDs(from: authorizedIDs) == [ComputerID("a")])
    }

    @Test("Empty explicit is mixed-free off when nothing authorized is included")
    func emptyExplicit() {
        let inclusion = MonitoringInclusion.emptyExplicit
        #expect(inclusion.includedIDs(from: authorizedIDs).isEmpty)
        #expect(inclusion.allComputersCheckState(authorized: authorizedIDs) == .off)
    }

    @Test("Group membership never duplicates a tile")
    func groupMembershipUnique() {
        let membership = GroupMembership(groups: [
            ComputerGroup(id: "g1", name: "One", computerIDs: [ComputerID("a"), ComputerID("b")]),
            ComputerGroup(id: "g2", name: "Two", computerIDs: [ComputerID("b"), ComputerID("c")]),
        ])
        let unique = membership.uniqueComputerIDs(inGroupIDs: ["g1", "g2"])
        #expect(unique == [ComputerID("a"), ComputerID("b"), ComputerID("c")])
    }
}

@Suite("Inventory filter")
struct InventoryFilterTests {
    let computers = [
        Computer(id: ComputerID("1"), name: "Lab Mac", trustedUserName: "Alex", isOnline: true),
        Computer(id: ComputerID("2"), name: "Office PC", trustedUserName: "Sam", isOnline: false, needsAttention: true),
        Computer(id: ComputerID("3"), name: "Spare", isOnline: true),
    ]

    @Test("Empty search matches all status-passing computers")
    func emptySearch() {
        let filter = InventoryFilter()
        #expect(filter.applying(to: computers).count == 3)
    }

    @Test("Search matches computer name")
    func searchName() {
        let filter = InventoryFilter(searchText: "lab")
        #expect(filter.applying(to: computers).map(\.id) == [ComputerID("1")])
    }

    @Test("Search matches trusted user name")
    func searchUser() {
        let filter = InventoryFilter(searchText: "sam")
        #expect(filter.applying(to: computers).map(\.id) == [ComputerID("2")])
    }

    @Test("Status filter online")
    func statusOnline() {
        let filter = InventoryFilter(status: .online)
        #expect(filter.applying(to: computers).map(\.id) == [ComputerID("1"), ComputerID("3")])
    }

    @Test("Status filter needs attention")
    func statusAttention() {
        let filter = InventoryFilter(status: .needsAttention)
        #expect(filter.applying(to: computers).map(\.id) == [ComputerID("2")])
    }

    @Test("Filters never grant access or erase enrollment")
    func filterIsNotAuthority() {
        let filter = InventoryFilter(searchText: "zzz-no-match")
        #expect(filter.applying(to: computers).isEmpty)
        // Source inventory unchanged.
        #expect(computers.count == 3)
    }
}

@Suite("Action selection and snapshots")
struct ActionSelectionTests {
    let displayed = [ComputerID("a"), ComputerID("b"), ComputerID("c"), ComputerID("d")]

    @Test("Toggle adds and removes")
    func toggle() {
        var selection = ActionSelection()
        selection.toggle(ComputerID("a"))
        #expect(selection.selectedIDs == [ComputerID("a")])
        selection.toggle(ComputerID("a"))
        #expect(selection.isEmpty)
    }

    @Test("Select only replaces selection")
    func selectOnly() {
        var selection = ActionSelection(selectedIDs: [ComputerID("a"), ComputerID("b")])
        selection.selectOnly(ComputerID("c"))
        #expect(selection.selectedIDs == [ComputerID("c")])
    }

    @Test("Range selection covers displayed order")
    func rangeSelection() {
        var selection = ActionSelection()
        selection.selectRange(from: ComputerID("a"), to: ComputerID("c"), displayedOrder: displayed)
        #expect(selection.selectedIDs == [ComputerID("a"), ComputerID("b"), ComputerID("c")])
    }

    @Test("Snapshot freezes IDs and never expands")
    func snapshotFrozen() {
        let snapshot = ActionSnapshot(actionKind: "Message", computerIDs: [ComputerID("a"), ComputerID("b")])
        #expect(snapshot.targetCount == 2)
        #expect(snapshot.contains(ComputerID("a")))
        #expect(!snapshot.contains(ComputerID("c")))
    }

    @Test("Default action targets use displayed set when selection empty")
    func defaultTargets() {
        let inventory = [
            Computer(id: ComputerID("a"), name: "A", isOnline: true),
            Computer(id: ComputerID("b"), name: "B", isOnline: true),
            Computer(id: ComputerID("c"), name: "C", isOnline: true),
        ]
        let scope = OverviewScope(
            authorizedInventory: inventory,
            inclusion: .all,
            filter: InventoryFilter()
        )
        #expect(scope.defaultActionTargetIDs(selection: ActionSelection()) == [ComputerID("a"), ComputerID("b"), ComputerID("c")])
        var selection = ActionSelection()
        selection.selectOnly(ComputerID("b"))
        #expect(scope.defaultActionTargetIDs(selection: selection) == [ComputerID("b")])
    }

    @Test("Scope line text")
    func scopeLine() {
        let inventory = [
            Computer(id: ComputerID("a"), name: "A", isOnline: true),
            Computer(id: ComputerID("b"), name: "B", isOnline: true),
        ]
        let scope = OverviewScope(authorizedInventory: inventory, inclusion: .all, filter: InventoryFilter())
        #expect(scope.scopeLine(selection: ActionSelection()).text == "All 2 Displayed Computers")
        var selection = ActionSelection()
        selection.selectOnly(ComputerID("a"))
        let line = scope.scopeLine(selection: selection)
        #expect(line.text == "1 Computer Selected")
        #expect(line.showsClearSelection)
    }
}

@Suite("Overview model separation")
struct OverviewModelTests {
    @Test("Inclusion and filter changes clear selection; snapshots do not expand")
    @MainActor
    func separation() {
        let model = OverviewModel(
            authorizedInventory: [
                Computer(id: ComputerID("a"), name: "Alpha", isOnline: true),
                Computer(id: ComputerID("b"), name: "Beta", isOnline: true),
            ],
            inclusion: .all
        )

        model.selectOnly(ComputerID("a"))
        #expect(model.selection.count == 1)

        let snapshot = model.openSnapshot(actionKind: "Message")
        #expect(snapshot.computerIDs == [ComputerID("a")])

        model.setSearchText("Beta")
        #expect(model.selection.isEmpty)
        // Snapshot unchanged after search.
        #expect(snapshot.computerIDs == [ComputerID("a")])
        #expect(model.openSnapshots.first?.computerIDs == [ComputerID("a")])

        model.upsert(Computer(id: ComputerID("c"), name: "Gamma", isOnline: true))
        #expect(model.scope.displayedIDs == [ComputerID("b")])
        #expect(model.openSnapshots.first?.computerIDs == [ComputerID("a")])
    }

    @Test("All mode admits newly eligible inventory after fresh admission")
    @MainActor
    func d18AllMode() {
        let model = OverviewModel(authorizedInventory: [], inclusion: .all)
        model.upsert(Computer(id: ComputerID("new"), name: "New", isOnline: true))
        #expect(model.scope.displayedIDs == [ComputerID("new")])
    }

    @Test("Explicit inclusion never silently adds a new computer")
    @MainActor
    func d18Explicit() {
        let model = OverviewModel(
            authorizedInventory: [Computer(id: ComputerID("a"), name: "A")],
            inclusion: .explicit([ComputerID("a")])
        )
        model.upsert(Computer(id: ComputerID("new"), name: "New", isOnline: true))
        #expect(model.scope.displayedIDs == [ComputerID("a")])
    }

    @Test("Pause clears admitted streams; resume re-requests")
    @MainActor
    func pauseResume() {
        let model = OverviewModel(
            authorizedInventory: [Computer(id: ComputerID("a"), name: "A", isOnline: true)],
            inclusion: .all
        )
        model.admit(ComputerID("a"))
        #expect(model.admittedStreams[ComputerID("a")] == .admitted)
        model.pauseMonitoring()
        #expect(model.admittedStreams[ComputerID("a")] == .idle)
        model.resumeMonitoring()
        #expect(model.admittedStreams[ComputerID("a")] == .requesting)
    }
}

@Suite("Guided server setup")
struct GuidedServerSetupTests {
    @Test("Mac manager exposes only Linux SSH route")
    @MainActor
    func linuxSSHOnly() {
        let model = GuidedServerSetupModel()
        #expect(HostingRoute.allCases == [.existingLinuxSSH])
        #expect(model.phase == .chooseHosting)
    }

    @Test("Host identity gate blocks continue")
    @MainActor
    func hostIdentityGate() {
        let model = GuidedServerSetupModel()
        model.setSSHAddress("server.lan")
        model.advance()
        #expect(model.phase == .connect)
        model.advance()
        #expect(model.phase == .hostIdentity)
        #expect(!model.canContinueFromCurrentPhase)
        model.setHostIdentity(.changed(expected: "AA:BB", actual: "CC:DD"))
        #expect(!model.canContinueFromCurrentPhase)
        #expect(!model.hostIdentity.isVerified)
        model.setHostIdentity(.verified(fingerprint: "SHA256:test"))
        #expect(model.canContinueFromCurrentPhase)
    }

    @Test("Install never claims success in this build")
    @MainActor
    func installNeverClaimsSuccess() {
        let model = GuidedServerSetupModel()
        model.setSSHAddress("server.lan")
        model.advance()
        model.advance()
        model.setHostIdentity(.verified(fingerprint: "SHA256:test"))
        model.advance()
        model.setHostCheck("SSH reachability", status: .passed)
        model.setHostCheck("Disk space", status: .passed)
        for name in GuidedServerSetupModel.requiredHostChecks { model.setHostCheck(name, status: .passed) }
        model.advance()
        model.setNetworkAddress("192.168.1.10")
        model.advance()
        model.setDeploymentName("HQ Lab")
        model.advance()
        model.setAdministratorUsername("admin")
        model.advance()
        model.setStoragePath("/var/lib/helicoid")
        model.advance()
        #expect(model.phase == .review)
        model.advance()
        #expect(model.phase == .install)
        if case .refused(let reason) = model.installProgress {
            #expect(reason.contains("not performed"))
        } else {
            Issue.record("Install progress should be refused, not started/succeeded")
        }
        #expect(!model.isServerReadyForEnrollment)
    }

    @Test("Check host requires all passed")
    @MainActor
    func checkHostRequiresPassed() {
        let model = GuidedServerSetupModel()
        model.setSSHAddress("server.lan")
        model.advance()
        model.advance()
        model.setHostIdentity(.verified(fingerprint: "x"))
        model.advance()
        #expect(model.phase == .checkHost)
        #expect(!model.canContinueFromCurrentPhase)
        model.setHostCheck("SSH reachability", status: .needsAttention(detail: "refused"))
        #expect(!model.canContinueFromCurrentPhase)
        model.setHostCheck("SSH reachability", status: .passed)
        #expect(!model.canContinueFromCurrentPhase)
        for name in GuidedServerSetupModel.requiredHostChecks { model.setHostCheck(name, status: .passed) }
        #expect(model.canContinueFromCurrentPhase)
    }
}

@Suite("Connection client boundary")
struct ConnectionClientTests {
    @Test("Unavailable client never invents a server identity")
    func unavailableClientIsHonest() async {
        let client = UnavailableConnectionClient()
        let validation = await client.validateAddress("")
        #expect(!validation.isOK)

        let good = await client.validateAddress("192.168.1.10")
        #expect(good.isOK)

        let result = await client.connect(address: "192.168.1.10")
        switch result {
        case .success:
            Issue.record("Unavailable client must not invent a server identity")
        case .failure(let error):
            #expect(error == .serverContractUnavailable)
        }

        let inventory = await client.authorizedInventory()
        switch inventory {
        case .success(let list):
            #expect(list.isEmpty)
        case .failure:
            Issue.record("Empty inventory is the honest result when not signed in")
        }
    }
}

@Suite("Development fixtures")
struct DevelopmentFixturesTests {
    @Test("Fixtures require explicit launch flag")
    func flagRequired() {
        #expect(DevelopmentFixtures.isRequested(arguments: ["HelicoidManager"]) == false)
        #expect(DevelopmentFixtures.isRequested(arguments: ["HelicoidManager", "--development-fixtures"]))
    }

    @Test("Fixture inventory is labeled and non-empty")
    func fixtureInventory() {
        let computers = DevelopmentFixtures.computers()
        #expect(!computers.isEmpty)
        #expect(DevelopmentFixtures.banner.contains("Development"))
    }
}
