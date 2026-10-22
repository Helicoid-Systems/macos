import SwiftUI
import HelicoidCore

/// Root for one native per-computer view-only window.
/// Demand is owned by ManagerSession; closing here removes only this computer
/// and only for the generation that opened the window.
struct ComputerViewWindowRoot: View {
    @Environment(ManagerSession.self) private var session
    let windowKey: ComputerViewWindowKey?
    @Environment(\.dismiss) private var dismiss

    private var computerID: ComputerID? { windowKey?.computerID }

    var body: some View {
        Group {
            if let windowKey,
               windowKey.sessionGeneration == session.sessionGeneration,
               session.openRemoteWindows.contains(windowKey.computerID),
               let computer = session.computer(with: windowKey.computerID) {
                RemoteViewWindow(windowKey: windowKey, computer: computer)
            } else {
                invalidDemand
            }
        }
        .onDisappear {
            // Close only the demand opened under this window's generation.
            if let windowKey {
                session.closeRemoteView(for: windowKey)
            }
        }
        .onChange(of: session.openRemoteWindows) { _, windows in
            if let computerID, !windows.contains(computerID) {
                dismiss()
            }
        }
        .onChange(of: session.sessionGeneration) { _, generation in
            // New session cannot expose previous context in a lingering window.
            if let windowKey, windowKey.sessionGeneration != generation {
                dismiss()
            }
        }
    }

    private var invalidDemand: some View {
        ContentUnavailableView(
            "Screen Unavailable",
            systemImage: "display.slash",
            description: Text("No authorized computer is attached to this window.")
        )
        .frame(minWidth: 560, minHeight: 360)
    }
}

/// M06 View Screen — native view-only remote window content.
/// Pixels are honest: Screen Unavailable. No fictional remote bridge.
struct RemoteViewWindow: View {
    let windowKey: ComputerViewWindowKey
    let computer: Computer
    @State private var showsDetails = false

    private var computerID: ComputerID { windowKey.computerID }

    var body: some View {
        RemoteCanvasPlaceholder()
            .frame(minWidth: 560, minHeight: 360)
            .navigationTitle("Viewing \(computer.name)")
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    // Fit / Actual Size wait for real frame geometry from the engine.
                    // Take Control stays hidden until an engine control path exists.
                    Button {
                        showsDetails.toggle()
                    } label: {
                        Label("Details", systemImage: "info.circle")
                    }
                    .accessibilityLabel("Computer details")
                    .help("Show computer identity and session details")
                }
            }
            .popover(isPresented: $showsDetails) {
                RemoteDetailsPopover(computer: computer, computerID: computerID)
            }
    }
}

/// Honest remote surface. Short title and one relevant reason only.
struct RemoteCanvasPlaceholder: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "display.trianglebadge.exclamationmark")
                .font(.system(size: 36, weight: .light))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("Screen Unavailable")
                .font(.title3.weight(.semibold))
            Text("The remote-view engine is not available in this build.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 320)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.quaternary.opacity(0.25))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Screen Unavailable. The remote-view engine is not available in this build.")
    }
}

struct RemoteDetailsPopover: View {
    let computer: Computer
    let computerID: ComputerID

    var body: some View {
        Form {
            LabeledContent("Name", value: computer.name)
            LabeledContent("ID", value: computerID.rawValue)
            if let user = computer.trustedUserName {
                LabeledContent("Trusted user", value: user)
            }
            LabeledContent("Enrollment", value: computer.enrollmentState ?? "unknown")
            if let status = computer.statusLabel {
                LabeledContent("Status", value: status)
            }
            if computer.needsAttention {
                LabeledContent("Attention", value: computer.statusLabel ?? "Needs attention")
            }
        }
        .formStyle(.grouped)
        .frame(width: 320)
    }
}
