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

    public init(
        connection: ConnectionState = .notConfigured,
        screenAccess: ScreenAccess = .none,
        helpRequestText: String = "",
        helpRequestState: HelpRequestState = .idle,
        isFixturesMode: Bool = false
    ) {
        self.connection = connection
        self.screenAccess = screenAccess
        self.helpRequestText = helpRequestText
        self.helpRequestState = helpRequestState
        self.isFixturesMode = isFixturesMode
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
public enum ComputerDevelopmentFixtures {
    public static func model() -> ComputerStatusModel {
        ComputerStatusModel(
            connection: .connected,
            screenAccess: .observed(operators: ["Morgan"]),
            helpRequestText: "",
            helpRequestState: .idle,
            isFixturesMode: true
        )
    }
}
