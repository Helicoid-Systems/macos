import Foundation
import HelicoidCore

/// Status model for the managed computer (Helicoid Computer).
/// Menu-bar status prioritizes operator identity and current access.
@MainActor
@Observable
public final class ComputerStatusModel {
    public enum ConnectionState: Hashable, Sendable {
        case notConfigured
        case connecting
        case connected
        case disconnected(reason: String)

        public var label: String {
            switch self {
            case .notConfigured: "Not Configured"
            case .connecting: "Connecting"
            case .connected: "Connected"
            case .disconnected: "Disconnected"
            }
        }
    }

    public enum ScreenAccess: Hashable, Sendable {
        case none
        case observed(operators: [String])
        case controlled(operators: [String])

        public var headline: String {
            switch self {
            case .none:
                "No Active Screen Access"
            case .observed(let names):
                if names.count == 1, let name = names.first {
                    "Your Screen Is Being Viewed by \(name)"
                } else {
                    "Your Screen Is Being Viewed"
                }
            case .controlled(let names):
                if let name = names.first {
                    "\(name) Is Controlling This Computer"
                } else {
                    "This Computer Is Being Controlled"
                }
            }
        }
    }

    public var connection: ConnectionState
    public var screenAccess: ScreenAccess
    public var helpRequestText: String
    public var helpRequestState: HelpRequestState
    public var isFixturesMode: Bool

    // MARK: - Permission readiness
    // Independent of connection, admission, and actual screen access.
    // Grants alone never mark connected/observed/controlled or enable capture/media/input.
    public private(set) var screenRecordingPermission: ComputerPermissionStatus = .unknown
    public private(set) var accessibilityPermission: ComputerPermissionStatus = .unknown

    private let permissionProbe: any ComputerPermissionProbing

    public init(
        connection: ConnectionState = .notConfigured,
        screenAccess: ScreenAccess = .none,
        helpRequestText: String = "",
        helpRequestState: HelpRequestState = .idle,
        isFixturesMode: Bool = false,
        permissionProbe: any ComputerPermissionProbing = NativeComputerPermissionProbe()
    ) {
        self.connection = connection
        self.screenAccess = screenAccess
        self.helpRequestText = helpRequestText
        self.helpRequestState = helpRequestState
        self.isFixturesMode = isFixturesMode
        self.permissionProbe = permissionProbe
    }

    public func permissionStatus(for kind: ComputerPermissionKind) -> ComputerPermissionStatus {
        switch kind {
        case .screenRecording: screenRecordingPermission
        case .accessibility: accessibilityPermission
        }
    }

    /// Non-prompting refresh. Startup, status refresh, and app reactivation only.
    /// A fresh native query replaces stale granted state after revoke.
    public func refreshPermissions() {
        screenRecordingPermission = permissionProbe.currentStatus(for: .screenRecording)
        accessibilityPermission = permissionProbe.currentStatus(for: .accessibility)
    }

    /// Explicit user button only. May prompt.
    /// Status stays unavailable until a fresh native query confirms.
    public func requestPermission(_ kind: ComputerPermissionKind) {
        permissionProbe.requestAccess(for: kind)
        switch kind {
        case .screenRecording:
            screenRecordingPermission = permissionProbe.currentStatus(for: .screenRecording)
        case .accessibility:
            accessibilityPermission = permissionProbe.currentStatus(for: .accessibility)
        }
    }

    /// Opens the exact System Settings privacy pane. Never prompts.
    public func openPermissionSettings(_ kind: ComputerPermissionKind) {
        permissionProbe.openSystemSettings(for: kind)
    }

    public var isHelpAvailable: Bool {
        if case .connected = connection {
            return true
        }
        return false
    }

    public var helpUnavailableReason: String {
        "Help requests require an active connection to the Helicoid server. Connect first."
    }

    public func requestHelp() {
        guard isHelpAvailable else { return }
        // Deduplicate repeated taps.
        if helpRequestState == .pending { return }
        helpRequestState = .pending
    }

    public func cancelHelpRequest() {
        guard isHelpAvailable else { return }
        helpRequestState = .idle
    }
}

public enum HelpRequestState: String, Hashable, Sendable {
    case idle
    case pending
    case sent
    case cancelled
}

/// Development fixtures for the managed computer status UI.
/// Permission facts here are synthetic and clearly labeled — never live TCC.
public enum ComputerDevelopmentFixtures {
    public static func model() -> ComputerStatusModel {
        let model = ComputerStatusModel(
            connection: .connected,
            screenAccess: .observed(operators: ["Morgan"]),
            helpRequestText: "",
            helpRequestState: .idle,
            isFixturesMode: true,
            permissionProbe: ComputerFixturePermissionProbe()
        )
        model.refreshPermissions()
        return model
    }
}
