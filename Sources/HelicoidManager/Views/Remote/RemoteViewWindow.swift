import SwiftUI
import HelicoidCore

/// M06 View Screen — separate view-only remote window.
/// Pixels are honest: Engine Unavailable. No fictional remote bridge.
struct RemoteViewWindow: View {
    @Environment(ManagerSession.self) private var session
    let computerID: ComputerID
    @Environment(\.dismiss) private var dismiss

    private var computer: Computer? {
        session.computer(with: computerID)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(computer.map { "Viewing \($0.name)" } ?? "Viewing Computer")
                    .font(.headline)
                Spacer()
                Button("Close") {
                    session.closeRemoteView(for: computerID)
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
            }
            .padding(12)

            Divider()

            EngineUnavailableCanvas(computerName: computer?.name ?? computerID.rawValue)

            Divider()

            HStack {
                Text("View-only. Take Control is not available while the engine is unavailable.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Take Control") {
                    // Explicit unavailable control. No fictional bridge.
                }
                .disabled(true)
                .help(HelicoidError.engineUnavailable.explanation)
            }
            .padding(12)
        }
        .frame(minWidth: 560, minHeight: 360)
    }
}

/// Honest remote surface. Never renders mock computer pixels as production frames.
struct EngineUnavailableCanvas: View {
    let computerName: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "display.trianglebadge.exclamationmark")
                .font(.system(size: 40, weight: .light))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("Engine Unavailable")
                .font(.title3.weight(.semibold))
            Text(HelicoidError.engineUnavailable.explanation)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
            Text("No screen pixels are produced for \(computerName).")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.quaternary.opacity(0.25))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Engine Unavailable. \(HelicoidError.engineUnavailable.explanation)")
    }
}

/// Presents remote view-only windows for computers the operator opened.
struct RemoteWindowPresenter: View {
    @Environment(ManagerSession.self) private var session
    let computerID: ComputerID

    var body: some View {
        RemoteViewWindow(computerID: computerID)
            .onDisappear {
                session.closeRemoteView(for: computerID)
            }
    }
}
