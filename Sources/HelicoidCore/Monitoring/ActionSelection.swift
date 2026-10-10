import Foundation

/// Compact status filter for the overview. Filters never erase enrollment or grant permissions.
public enum StatusFilter: String, Hashable, Sendable, Codable, CaseIterable {
    case all
    case online
    case needsAttention

    public var label: String {
        switch self {
        case .all: "All"
        case .online: "Online"
        case .needsAttention: "Needs Attention"
        }
    }
}

/// Inventory filter: search text plus optional status filter applied to included IDs.
public struct InventoryFilter: Hashable, Sendable, Codable {
    public var searchText: String
    public var status: StatusFilter

    public init(searchText: String = "", status: StatusFilter = .all) {
        self.searchText = searchText
        self.status = status
    }

    public var isActive: Bool {
        !searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || status != .all
    }

    /// Search computer name and trusted current user name (case/diacritic-insensitive).
    public func matches(_ computer: Computer) -> Bool {
        switch status {
        case .all:
            break
        case .online:
            if !computer.isOnline { return false }
        case .needsAttention:
            if !computer.needsAttention { return false }
        }

        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        if query.isEmpty { return true }

        if computer.name.range(of: query, options: [.caseInsensitive, .diacriticInsensitive]) != nil {
            return true
        }
        if let user = computer.trustedUserName,
           user.range(of: query, options: [.caseInsensitive, .diacriticInsensitive]) != nil {
            return true
        }
        return false
    }

    public func applying(to computers: [Computer]) -> [Computer] {
        computers.filter { matches($0) }
    }
}

/// Temporary action selection on overview tiles. Cleared when inclusion, search, or status filters change.
public struct ActionSelection: Hashable, Sendable, Codable {
    public private(set) var selectedIDs: Set<ComputerID>

    public init(selectedIDs: Set<ComputerID> = []) {
        self.selectedIDs = selectedIDs
    }

    public var isEmpty: Bool { selectedIDs.isEmpty }
    public var count: Int { selectedIDs.count }

    public mutating func select(_ id: ComputerID) {
        selectedIDs.insert(id)
    }

    public mutating func toggle(_ id: ComputerID) {
        if selectedIDs.contains(id) {
            selectedIDs.remove(id)
        } else {
            selectedIDs.insert(id)
        }
    }

    public mutating func selectOnly(_ id: ComputerID) {
        selectedIDs = [id]
    }

    public mutating func selectRange(
        from anchor: ComputerID?,
        to target: ComputerID,
        displayedOrder: [ComputerID]
    ) {
        guard let anchor, let start = displayedOrder.firstIndex(of: anchor),
              let end = displayedOrder.firstIndex(of: target) else {
            selectedIDs.insert(target)
            return
        }
        let range = displayedOrder[min(start, end)...max(start, end)]
        selectedIDs.formUnion(range)
    }

    public mutating func clear() {
        selectedIDs.removeAll()
    }

    /// Selection restricted to currently displayed IDs (stale selections drop out of the set for display).
    public func selected(in displayed: [ComputerID]) -> Set<ComputerID> {
        selectedIDs.intersection(Set(displayed))
    }
}

/// Immutable computer IDs captured when an action composer opens.
/// Search, selection, reconnect, enrollment, and group edits cannot expand it.
public struct ActionSnapshot: Hashable, Sendable, Codable, Identifiable {
    public let id: UUID
    public let actionKind: String
    public let computerIDs: [ComputerID]
    public let capturedAt: Date

    public init(
        actionKind: String,
        computerIDs: [ComputerID],
        capturedAt: Date = Date(),
        id: UUID = UUID()
    ) {
        self.id = id
        self.actionKind = actionKind
        // Freeze a stable order at capture time.
        self.computerIDs = computerIDs
        self.capturedAt = capturedAt
    }

    public var targetCount: Int { computerIDs.count }

    /// Snapshots never expand. This is intentionally immutable.
    public func contains(_ id: ComputerID) -> Bool {
        computerIDs.contains(id)
    }
}

/// Derived displayed computers after inclusion and filters. Never used as authority.
public struct OverviewScope: Hashable, Sendable {
    public let includedIDs: [ComputerID]
    public let displayedIDs: [ComputerID]
    public let computers: [Computer]

    public init(
        authorizedInventory: [Computer],
        inclusion: MonitoringInclusion,
        filter: InventoryFilter
    ) {
        let includedSet = inclusion.includedIDs(from: authorizedInventory.map(\.id))
        self.includedIDs = authorizedInventory.map(\.id).filter { includedSet.contains($0) }
        self.computers = authorizedInventory.filter { includedSet.contains($0.id) && filter.matches($0) }
        self.displayedIDs = computers.map(\.id)
    }

    public var displayedCount: Int { displayedIDs.count }

    /// Default target set for a new bulk action when no tiles are selected.
    public func defaultActionTargetIDs(selection: ActionSelection) -> [ComputerID] {
        if selection.isEmpty {
            return displayedIDs
        }
        return displayedIDs.filter { selection.selectedIDs.contains($0) }
    }

    public func scopeLine(selection: ActionSelection) -> ScopeLine {
        if selection.isEmpty {
            if displayedIDs.isEmpty {
                return .noComputersDisplayed
            }
            return .allDisplayed(count: displayedIDs.count)
        }
        let selectedCount = selection.selected(in: displayedIDs).count
        return .selected(count: selectedCount)
    }
}

public enum ScopeLine: Hashable, Sendable {
    case allDisplayed(count: Int)
    case selected(count: Int)
    case noComputersDisplayed

    public var text: String {
        switch self {
        case .allDisplayed(let count):
            count == 1 ? "All 1 Displayed Computer" : "All \(count) Displayed Computers"
        case .selected(let count):
            count == 1 ? "1 Computer Selected" : "\(count) Computers Selected"
        case .noComputersDisplayed:
            "No Computers Displayed"
        }
    }

    public var showsClearSelection: Bool {
        if case .selected = self { return true }
        return false
    }
}
