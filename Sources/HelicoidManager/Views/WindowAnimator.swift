import AppKit

/// Native window open/close/resize. Call signatures are stable for parallel owners;
/// motion is NSWindow.animationBehavior and native frame updates — no custom timer.
enum WindowAnimator {
    /// Open with the system document-window animation. Never blocks ordering.
    static func animateOpen(_ window: NSWindow, activate: Bool = true) {
        window.animationBehavior = prefersReducedMotion ? .none : .documentWindow
        window.alphaValue = 1
        if activate {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        } else {
            window.orderFrontRegardless()
        }
    }

    /// Close never waits on animation. Completion runs immediately so teardown is not delayed.
    static func animateClose(_ window: NSWindow, completion: @escaping @Sendable () -> Void) {
        window.animationBehavior = prefersReducedMotion ? .none : .documentWindow
        completion()
    }

    /// Resize the content frame. `center` is honored only for genuine first-appearance
    /// geometry; later phase size changes keep the user's position.
    static func animateResize(
        _ window: NSWindow,
        to contentSize: NSSize,
        center: Bool = true,
        title: String? = nil,
        titleVisibility: NSWindow.TitleVisibility? = nil
    ) {
        let startFrame = window.frame
        var endFrame = window.frameRect(forContentRect: NSRect(
            x: startFrame.origin.x,
            y: startFrame.origin.y,
            width: contentSize.width,
            height: contentSize.height
        ))
        if center, let screen = window.screen ?? NSScreen.main {
            let visible = screen.visibleFrame
            endFrame.origin.x = visible.midX - endFrame.width / 2
            endFrame.origin.y = visible.midY - endFrame.height / 2
        } else {
            endFrame.origin = startFrame.origin
        }

        if let title { window.title = title }
        if let titleVisibility { window.titleVisibility = titleVisibility }

        applyFrame(window, endFrame)
    }

    /// Apply an existing frame target (phase geometry restore). No recentering.
    static func animateFrame(
        _ window: NSWindow,
        to endFrame: NSRect,
        title: String? = nil,
        titleVisibility: NSWindow.TitleVisibility? = nil
    ) {
        if let title { window.title = title }
        if let titleVisibility { window.titleVisibility = titleVisibility }
        applyFrame(window, endFrame)
    }

    // MARK: - Internals

    private static var prefersReducedMotion: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
    }

    private static func applyFrame(_ window: NSWindow, _ endFrame: NSRect) {
        guard !prefersReducedMotion else {
            window.setFrame(endFrame, display: true, animate: false)
            return
        }
        window.setFrame(endFrame, display: true, animate: true)
    }
}

/// Kept for call-signature stability. Close uses native `NSWindow.animationBehavior`;
/// this no longer installs a delegate proxy or delays close.
final class WindowCloseAnimator: NSObject {
    static func attach(to window: NSWindow) {
        guard !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion else {
            window.animationBehavior = .none
            return
        }
        window.animationBehavior = .documentWindow
    }
}
