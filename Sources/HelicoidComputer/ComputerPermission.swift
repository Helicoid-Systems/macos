import AppKit
import ApplicationServices
import CoreGraphics
import Foundation

/// TCC permission kinds Helicoid Computer inspects for readiness only.
/// Readiness is independent of connection, admission, and actual screen access.
public enum ComputerPermissionKind: String, CaseIterable, Hashable, Sendable {
    case screenRecording
    case accessibility

    public var title: String {
        switch self {
        case .screenRecording: "Screen Recording"
        case .accessibility: "Accessibility"
        }
    }

    /// Short plain copy. Grants alone never start capture, input, or control.
    public var purpose: String {
        switch self {
        case .screenRecording:
            "Needed so authorized operators can view this screen. Granting alone does not share it."
        case .accessibility:
            "Needed so authorized operators can control this computer. Granting alone does not allow control."
        }
    }
}

/// Current-process permission status. `unknown` is treated as unavailable.
public enum ComputerPermissionStatus: String, Hashable, Sendable {
    case granted
    case missing
    case unknown

    /// Only a confirmed grant is available. Unknown is unavailable.
    public var isAvailable: Bool {
        self == .granted
    }

    public var label: String {
        switch self {
        case .granted: "Granted"
        case .missing: "Not Granted"
        case .unknown: "Unknown"
        }
    }
}

/// Injected native probe seam.
///
/// `currentStatus` is read-only and must never prompt.
/// `requestAccess` may prompt and must only run from an explicit user button.
/// `openSystemSettings` opens the exact privacy pane without prompting.
public protocol ComputerPermissionProbing: Sendable {
    func currentStatus(for kind: ComputerPermissionKind) -> ComputerPermissionStatus
    func requestAccess(for kind: ComputerPermissionKind)
    func openSystemSettings(for kind: ComputerPermissionKind)
}

/// Production probe using installed SDK APIs only.
/// No shell, TCC database inspection, or private APIs.
public struct NativeComputerPermissionProbe: ComputerPermissionProbing {
    public init() {}

    public func currentStatus(for kind: ComputerPermissionKind) -> ComputerPermissionStatus {
        switch kind {
        case .screenRecording:
            // CGPreflightScreenCaptureAccess does not prompt.
            CGPreflightScreenCaptureAccess() ? .granted : .missing
        case .accessibility:
            // AXIsProcessTrusted() does not prompt.
            AXIsProcessTrusted() ? .granted : .missing
        }
    }

    public func requestAccess(for kind: ComputerPermissionKind) {
        switch kind {
        case .screenRecording:
            // May present the system prompt. User-button path only.
            _ = CGRequestScreenCaptureAccess()
        case .accessibility:
            // Documented option key; avoids the shared mutable CFString global.
            _ = AXIsProcessTrustedWithOptions(
                ["AXTrustedCheckOptionPrompt": true] as CFDictionary
            )
        }
    }

    public func openSystemSettings(for kind: ComputerPermissionKind) {
        let pane: String
        switch kind {
        case .screenRecording:
            pane = "Privacy_ScreenCapture"
        case .accessibility:
            pane = "Privacy_Accessibility"
        }
        // Exact System Settings privacy pane for this permission.
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?\(pane)") else {
            return
        }
        NSWorkspace.shared.open(url)
    }
}

/// Labeled synthetic probe for development fixtures only.
/// Never supplies live TCC facts and never prompts.
public struct ComputerFixturePermissionProbe: ComputerPermissionProbing {
    public static let banner = "Development fixtures — synthetic permission facts, not live TCC"

    public init() {}

    public func currentStatus(for kind: ComputerPermissionKind) -> ComputerPermissionStatus {
        // Synthetic fixture values only; UI must show the fixtures banner.
        .missing
    }

    public func requestAccess(for kind: ComputerPermissionKind) {
        // Fixtures never prompt or touch TCC.
    }

    public func openSystemSettings(for kind: ComputerPermissionKind) {
        // Fixtures do not open System Settings.
    }
}
