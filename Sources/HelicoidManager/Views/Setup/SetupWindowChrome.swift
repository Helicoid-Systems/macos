import AppKit
import SwiftUI

/// Strips titlebar material so the top bar has no background.
/// Guided setup additionally gets a setup title and content size.
/// Restores the previous chrome when the Manager leaves setup or the view goes away.
struct SetupWindowChrome: NSViewRepresentable {
    var isEnabled: Bool

    func makeNSView(context: Context) -> WindowChromeView {
        let view = WindowChromeView()
        view.isEnabled = isEnabled
        return view
    }

    func updateNSView(_ nsView: WindowChromeView, context: Context) {
        nsView.isEnabled = isEnabled
        nsView.applyChrome()
    }

    static func dismantleNSView(_ nsView: WindowChromeView, coordinator: ()) {
        nsView.restoreChrome()
    }
}

enum WindowCentering {
    static func center(_ window: NSWindow) {
        if let screen = window.screen ?? NSScreen.main {
            let visible = screen.visibleFrame
            let size = window.frame.size
            window.setFrameOrigin(NSPoint(
                x: visible.midX - size.width / 2,
                y: visible.midY - size.height / 2
            ))
        } else {
            window.center()
        }
    }
}

final class WindowChromeView: NSView {
    var isEnabled = false
    private weak var styledWindow: NSWindow?
    private var savedTitle = ""
    private var savedFrame = NSRect.zero
    private var savedTitleVisibility: NSWindow.TitleVisibility = .visible
    private var savedTransparency = false
    private var savedFullSizeContent = false
    private var savedSeparatorStyle: NSTitlebarSeparatorStyle = .automatic
    private var isSetupStyled = false
    private var didCenterInitial = false

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if styledWindow !== window { restoreChrome() }
        applyChrome()
    }

    func applyChrome() {
        guard let window else {
            restoreChrome()
            return
        }
        if styledWindow !== window {
            restoreChrome()
            styledWindow = window
            savedTitle = window.title
            savedFrame = window.frame
            savedTitleVisibility = window.titleVisibility
            savedTransparency = window.titlebarAppearsTransparent
            savedFullSizeContent = window.styleMask.contains(.fullSizeContentView)
            savedSeparatorStyle = window.titlebarSeparatorStyle
            if !didCenterInitial {
                didCenterInitial = true
                WindowCentering.center(window)
                WindowCloseAnimator.attach(to: window)
                WindowAnimator.animateOpen(window, activate: false)
            }
        }

        // No titlebar material or separator on the main window.
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.titlebarSeparatorStyle = .none
        window.styleMask.insert(.fullSizeContentView)
        window.backgroundColor = .windowBackgroundColor

        if isEnabled {
            if !isSetupStyled {
                isSetupStyled = true
                window.styleMask.insert(.fullSizeContentView)
                WindowAnimator.animateResize(
                    window,
                    to: NSSize(width: 600, height: 400),
                    center: true,
                    title: "Server Setup · Helicoid Manager",
                    titleVisibility: .visible
                )
            }
        } else if isSetupStyled {
            isSetupStyled = false
            if !savedFullSizeContent { window.styleMask.remove(.fullSizeContentView) }
            var target = savedFrame
            if let screen = window.screen ?? NSScreen.main {
                let visible = screen.visibleFrame
                target.origin.x = visible.midX - target.width / 2
                target.origin.y = visible.midY - target.height / 2
            }
            WindowAnimator.animateFrame(
                window,
                to: target,
                title: savedTitle,
                titleVisibility: savedTitleVisibility
            )
        }
    }

    func restoreChrome() {
        guard let styledWindow else { return }
        styledWindow.title = savedTitle
        styledWindow.titleVisibility = savedTitleVisibility
        styledWindow.titlebarAppearsTransparent = savedTransparency
        styledWindow.titlebarSeparatorStyle = savedSeparatorStyle
        if !savedFullSizeContent { styledWindow.styleMask.remove(.fullSizeContentView) }
        styledWindow.setFrame(savedFrame, display: true)
        self.styledWindow = nil
        self.isSetupStyled = false
    }
}
