import Foundation
import Observation

/// Overview demand model. The five state objects stay distinct:
/// inclusion, displayed IDs, tile selection, action snapshots, and admitted streams.
@MainActor
@Observable
public final class OverviewModel {
    public private(set) var authorizedInventory: [Computer]
    public private(set) var groups: GroupMembership
    public private(set) var inclusion: MonitoringInclusion
    public private(set) var filter: InventoryFilter
    public private(set) var selection: ActionSelection
    public private(set) var openSnapshots: [ActionSnapshot]
    public private(set) var admittedStreams: [ComputerID: ObservationAdmission]
    public private(set) var isMonitoringPaused: Bool

    public init(
        authorizedInventory: [Computer] = [],
        groups: GroupMembership = GroupMembership(),
        inclusion: MonitoringInclusion = .all,
        filter: InventoryFilter = InventoryFilter(),
        selection: ActionSelection = ActionSelection(),
        openSnapshots: [ActionSnapshot] = [],
        admittedStreams: [ComputerID: ObservationAdmission] = [:],
        isMonitoringPaused: Bool = false
    ) {
        self.authorizedInventory = authorizedInventory
        self.groups = groups
        self.inclusion = inclusion
        self.filter = filter
        self.selection = selection
        self.openSnapshots = openSnapshots
        self.admittedStreams = admittedStreams
        self.isMonitoringPaused = isMonitoringPaused
    }

    public var scope: OverviewScope {
        OverviewScope(
            authorizedInventory: authorizedInventory,
            inclusion: inclusion,
            filter: filter
        )
    }

    // MARK: - Inventory

    /// Replace authorized inventory. Does not expand explicit inclusion or open snapshots.
    public func setInventory(_ inventory: [Computer]) {
        authorizedInventory = inventory
        // Drop selection IDs that are no longer displayed after inventory replacement is applied later;
        // selection itself is only cleared by inclusion/filter changes per M04.
    }

    public func upsert(_ computer: Computer) {
        if let index = authorizedInventory.firstIndex(where: { $0.id == computer.id }) {
            authorizedInventory[index] = computer
        } else {
            // D18: newly eligible inventory is added to the authorized list.
            // All mode includes it in the overview; explicit inclusion does not.
            authorizedInventory.append(computer)
        }
    }

    // MARK: - Inclusion

    public func selectAllComputersMode() {
        inclusion = .all
        clearSelection()
    }

    public func clearAllComputersMode() {
        inclusion = .explicit([])
        clearSelection()
    }

    public func includeComputer(_ id: ComputerID) {
        inclusion.include(id)
        clearSelection()
    }

    public func excludeComputer(_ id: ComputerID) {
        inclusion = inclusion.excludingFromAll(id, authorized: authorizedInventory.map(\.id))
        clearSelection()
    }

    public func setGroupIncluded(_ groupID: String, included: Bool) {
        let memberIDs = groups.computerIDs(inGroup: groupID)
        var working = inclusion.includedIDs(from: authorizedInventory.map(\.id))
        if included {
            working.formUnion(memberIDs)
            inclusion = .explicit(working)
        } else {
            working.subtract(memberIDs)
            inclusion = .explicit(working)
        }
        clearSelection()
    }

    // MARK: - Filter (clears temporary selection; preserves stable sort)

    public func setSearchText(_ text: String) {
        filter.searchText = text
        clearSelection()
    }

    public func setStatusFilter(_ status: StatusFilter) {
        filter.status = status
        clearSelection()
    }

    // MARK: - Temporary selection

    public func toggleSelection(_ id: ComputerID) {
        selection.toggle(id)
    }

    public func selectOnly(_ id: ComputerID) {
        selection.selectOnly(id)
    }

    public func selectRange(from anchor: ComputerID?, to target: ComputerID) {
        selection.selectRange(from: anchor, to: target, displayedOrder: scope.displayedIDs)
    }

    public func clearSelection() {
        selection.clear()
    }

    public func replaceSelection(with ids: Set<ComputerID>) {
        selection = ActionSelection(selectedIDs: ids)
    }

    // MARK: - Action snapshots

    /// Freeze targets when an action composer opens. Zero targets disable dispatch.
    public func openSnapshot(actionKind: String) -> ActionSnapshot {
        let targets = scope.defaultActionTargetIDs(selection: selection)
        let snapshot = ActionSnapshot(actionKind: actionKind, computerIDs: targets)
        openSnapshots.append(snapshot)
        return snapshot
    }

    public func closeSnapshot(_ id: UUID) {
        openSnapshots.removeAll { $0.id == id }
    }

    // MARK: - Observation streams

    public func requestAdmission(_ id: ComputerID) {
        guard !isMonitoringPaused else {
            admittedStreams[id] = .idle
            return
        }
        guard inclusion.includes(id) else {
            admittedStreams[id] = .denied(reason: "Not included in monitoring inclusion.")
            return
        }
        admittedStreams[id] = .requesting
    }

    public func admit(_ id: ComputerID) {
        guard !isMonitoringPaused else {
            admittedStreams[id] = .idle
            return
        }
        admittedStreams[id] = .admitted
    }

    public func denyAdmission(_ id: ComputerID, reason: String) {
        admittedStreams[id] = .denied(reason: reason)
    }

    public func pauseMonitoring() {
        isMonitoringPaused = true
        for (id, _) in admittedStreams {
            admittedStreams[id] = .idle
        }
    }

    public func resumeMonitoring() {
        isMonitoringPaused = false
        for id in scope.displayedIDs {
            admittedStreams[id] = .requesting
        }
    }
}
