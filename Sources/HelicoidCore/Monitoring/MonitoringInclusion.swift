import Foundation

/// Monitoring inclusion: the remembered choice of which authorized computers appear in the overview.
/// Separate from temporary tile selection and from authorization.
public enum MonitoringInclusion: Hashable, Sendable, Codable {
    /// All currently authorized inventory is included (D18: newly eligible inventory may appear after fresh admission).
    case all
    /// Explicit computer IDs only. Never expands silently when inventory changes.
    case explicit(Set<ComputerID>)

    public static let emptyExplicit = MonitoringInclusion.explicit([])

    public func includes(_ id: ComputerID) -> Bool {
        switch self {
        case .all: true
        case .explicit(let ids): ids.contains(id)
        }
    }

    /// Included IDs against current authorized inventory. Unknown saved IDs are dropped, not invented.
    public func includedIDs(from authorized: some Sequence<ComputerID>) -> Set<ComputerID> {
        let authorizedSet = Set(authorized)
        switch self {
        case .all:
            return authorizedSet
        case .explicit(let ids):
            return ids.intersection(authorizedSet)
        }
    }

    /// Check state for the All Computers checkbox: checked when every current authorized ID is included.
    public func allComputersCheckState(authorized: some Sequence<ComputerID>) -> CheckState {
        let included = includedIDs(from: authorized)
        let total = Set(authorized).count
        if total == 0 { return .off }
        if included.count == total { return .on }
        if included.isEmpty { return .off }
        return .mixed
    }

    public mutating func include(_ id: ComputerID) {
        switch self {
        case .all:
            break
        case .explicit(var ids):
            ids.insert(id)
            self = .explicit(ids)
        }
    }

    public mutating func exclude(_ id: ComputerID) {
        switch self {
        case .all:
            // Leaving All mode with an explicit set of the remaining IDs is done by the caller
            // with full inventory; excluding one ID from All converts to explicit minus that ID.
            // The caller must pass current inventory via `excludingFromAll`.
            break
        case .explicit(var ids):
            ids.remove(id)
            self = .explicit(ids)
        }
    }

    /// Convert All to explicit current inventory minus `id` (used when unchecking one computer while in All mode).
    public func excludingFromAll(_ id: ComputerID, authorized: some Sequence<ComputerID>) -> MonitoringInclusion {
        switch self {
        case .all:
            var ids = Set(authorized)
            ids.remove(id)
            return .explicit(ids)
        case .explicit(var ids):
            ids.remove(id)
            return .explicit(ids)
        }
    }

    public func selectingAll(authorized: some Sequence<ComputerID>) -> MonitoringInclusion {
        _ = authorized
        return .all
    }

    public func clearingAll() -> MonitoringInclusion {
        .explicit([])
    }
}

public enum CheckState: Hashable, Sendable {
    case off
    case on
    case mixed
}

/// Optional flat group membership used only for inclusion UI and filtering.
public struct GroupMembership: Hashable, Sendable, Codable {
    public var groups: [ComputerGroup]

    public init(groups: [ComputerGroup] = []) {
        self.groups = groups
    }

    public func groups(containing id: ComputerID) -> [ComputerGroup] {
        groups.filter { $0.computerIDs.contains(id) }
    }

    public func computerIDs(inGroup groupID: String) -> [ComputerID] {
        groups.first(where: { $0.id == groupID })?.computerIDs ?? []
    }

    /// Duplicate membership never duplicates a tile: return unique IDs.
    public func uniqueComputerIDs(inGroupIDs groupIDs: [String]) -> [ComputerID] {
        var seen = Set<ComputerID>()
        var ordered: [ComputerID] = []
        for groupID in groupIDs {
            for id in computerIDs(inGroup: groupID) where !seen.contains(id) {
                seen.insert(id)
                ordered.append(id)
            }
        }
        return ordered
    }
}
