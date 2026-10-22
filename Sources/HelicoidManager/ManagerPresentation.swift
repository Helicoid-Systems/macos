import CoreGraphics
import Foundation
import HelicoidCore

/// Inventory presentation layout. Session-owned so layout changes survive view resets.
public enum ManagerLayoutKind: String, CaseIterable, Identifiable, Hashable, Sendable, Codable {
    case grid
    case list

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .grid: "Grid"
        case .list: "List"
        }
    }
}

/// Preview tile presets. Logical widths used by adaptive grid columns.
public enum ManagerPreviewSize: String, CaseIterable, Identifiable, Hashable, Sendable, Codable {
    case compact
    case standard
    case large
    case extraLarge

    public var id: String { rawValue }

    public static let `default`: ManagerPreviewSize = .large

    public var label: String {
        switch self {
        case .compact: "Compact"
        case .standard: "Standard"
        case .large: "Large"
        case .extraLarge: "Extra Large"
        }
    }

    /// Logical tile width for the adaptive grid (192 / 256 / 320 / 448).
    public var tileWidth: CGFloat {
        switch self {
        case .compact: 192
        case .standard: 256
        case .large: 320
        case .extraLarge: 448
        }
    }
}

/// Distinct empty-inventory reasons. Filters, inclusion, and authorization stay separate.
public enum InventoryEmptyReason: Hashable, Sendable {
    case noAuthorizedInventory
    case noneIncluded
    case noResults

    public var title: String {
        switch self {
        case .noAuthorizedInventory: "No Computers"
        case .noneIncluded: "No Computers Included"
        case .noResults: "No Results"
        }
    }

    public var message: String {
        switch self {
        case .noAuthorizedInventory:
            "No enrolled computers are authorized for this account yet."
        case .noneIncluded:
            "No computers are included. Choose computers to show in the panel."
        case .noResults:
            "No computers match the current search or status filter."
        }
    }

    public static func reason(
        authorizedCount: Int,
        includedCount: Int,
        displayedCount: Int,
        filterActive: Bool
    ) -> InventoryEmptyReason {
        if authorizedCount == 0 { return .noAuthorizedInventory }
        if includedCount == 0 { return .noneIncluded }
        if displayedCount == 0 && filterActive { return .noResults }
        return .noAuthorizedInventory
    }
}

/// Session presentation preferences for inventory density and panel visibility.
/// View `@State` must not own these — layout changes would reset on navigation.
public struct ManagerPresentationPreferences: Hashable, Sendable, Codable {
    public var layout: ManagerLayoutKind
    public var previewSize: ManagerPreviewSize
    public var isComputersPanelShown: Bool

    public init(
        layout: ManagerLayoutKind = .grid,
        previewSize: ManagerPreviewSize = .large,
        isComputersPanelShown: Bool = false
    ) {
        self.layout = layout
        self.previewSize = previewSize
        self.isComputersPanelShown = isComputersPanelShown
    }
}

/// Independent identity pair required before any preference persistence.
/// Never minted from URL, display name, or username alone.
public struct PresentationPreferenceScope: Hashable, Sendable, Codable {
    public let deploymentID: String
    public let accountID: String

    public init(deploymentID: String, accountID: String) {
        self.deploymentID = deploymentID
        self.accountID = accountID
    }
}

/// Immutable identity of one native view-only window.
/// Generation fences delayed close so an old window cannot drop a newer demand.
public struct ComputerViewWindowKey: Hashable, Sendable, Codable {
    public let computerID: ComputerID
    public let sessionGeneration: UInt64

    public init(computerID: ComputerID, sessionGeneration: UInt64) {
        self.computerID = computerID
        self.sessionGeneration = sessionGeneration
    }
}

/// Typed preference store. Persistence is allowed only for a real account+deployment scope.
/// Missing prerequisite stays session-only; no global UserDefaults key is used.
public struct PresentationPreferenceStore: Sendable {
    public static let keyPrefix = "hs.manager.presentation.v1"

    public let scope: PresentationPreferenceScope?
    private let defaults: UserDefaults

    public init(scope: PresentationPreferenceScope?, defaults: UserDefaults = .standard) {
        self.scope = scope
        self.defaults = defaults
    }

    public var canPersist: Bool {
        guard let scope else { return false }
        return !scope.deploymentID.isEmpty && !scope.accountID.isEmpty
    }

    /// Exact missing prerequisite when persistence is not allowed.
    public var missingPrerequisite: String? {
        if canPersist { return nil }
        return "Presentation preferences stay in session memory until an authenticated account ID and independently verified deployment ID are both available."
    }

    /// Length-prefixed pair so IDs containing dots cannot collide.
    public func storageKey(for scope: PresentationPreferenceScope) -> String {
        "\(Self.keyPrefix).\(scope.deploymentID.count).\(scope.deploymentID).\(scope.accountID.count).\(scope.accountID)"
    }

    public func load() -> ManagerPresentationPreferences? {
        guard canPersist, let scope else { return nil }
        let key = storageKey(for: scope)
        guard let data = defaults.data(forKey: key) else { return nil }
        return try? JSONDecoder().decode(ManagerPresentationPreferences.self, from: data)
    }

    public func save(_ preferences: ManagerPresentationPreferences) {
        guard canPersist, let scope else { return }
        let key = storageKey(for: scope)
        guard let data = try? JSONEncoder().encode(preferences) else { return }
        defaults.set(data, forKey: key)
    }

    public func clear() {
        guard canPersist, let scope else { return }
        defaults.removeObject(forKey: storageKey(for: scope))
    }
}
