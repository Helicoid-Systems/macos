import AppKit
import SwiftUI

/// Compact setup uses integrated chrome; Computers keeps its native toolbar.
struct SetupWindowChrome: NSViewRepresentable {
    var screen: ManagerSession.Screen
    var setupHeight: CGFloat

    func makeNSView(context: Context) -> WindowChromeView {
        let view = WindowChromeView()
        view.screen = screen
        view.setupHeight = setupHeight
        return view
    }

    func updateNSView(_ nsView: WindowChromeView, context: Context) {
        nsView.screen = screen
        nsView.setupHeight = setupHeight
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
            window.setFrameOrigin(NSPoint(
                x: visible.midX - window.frame.width / 2,
                y: visible.midY - window.frame.height / 2
            ))
        } else {
            window.center()
        }
    }
}

final class WindowChromeView: NSView {
    var screen: ManagerSession.Screen = .connect
    var setupHeight: CGFloat = 280
    private var appliedSetupHeight: CGFloat?
    private weak var styledWindow: NSWindow?
    private var appliedScreen: ManagerSession.Screen?
    private var savedTitleVisibility: NSWindow.TitleVisibility = .visible
    private var savedTransparency = false
    private var savedFullSizeContent = false
    private var savedSeparatorStyle: NSTitlebarSeparatorStyle = .automatic

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        applyChrome()
    }

    func applyChrome() {
        guard let window else { return }
        let firstAppearance = styledWindow !== window
        if firstAppearance {
            restoreChrome()
            styledWindow = window
            savedTitleVisibility = window.titleVisibility
            savedTransparency = window.titlebarAppearsTransparent
            savedFullSizeContent = window.styleMask.contains(.fullSizeContentView)
            savedSeparatorStyle = window.titlebarSeparatorStyle
            WindowCloseAnimator.attach(to: window)
        }
        guard firstAppearance || appliedScreen != screen || appliedSetupHeight != setupHeight else { return }
        appliedScreen = screen
        appliedSetupHeight = setupHeight

        let inventory = screen == .computers
        window.titleVisibility = inventory ? .visible : .hidden
        window.titlebarAppearsTransparent = !inventory
        window.titlebarSeparatorStyle = inventory ? .automatic : .none
        if inventory {
            window.styleMask.remove(.fullSizeContentView)
        } else {
            window.styleMask.insert(.fullSizeContentView)
        }

        let size: NSSize
        switch screen {
        case .connect: window.title = "Connect"; size = NSSize(width: 520, height: 220)
        case .signIn: window.title = "Sign In"; size = NSSize(width: 520, height: 360)
        case .verify: window.title = "Verify Server"; size = NSSize(width: 600, height: 440)
        case .guidedSetup: window.title = "Server Setup"; size = NSSize(width: 520, height: setupHeight)
        case .computers: window.title = "Computers"; size = NSSize(width: 1120, height: 760)
        }
        let expectedScreen = screen
        let expectedSetupHeight = setupHeight
        Task { @MainActor [weak self, weak window] in
            // Let SwiftUI replace the previous screen's minimum-size constraints first.
            await Task.yield()
            guard let self, let window, self.styledWindow === window,
                  self.appliedScreen == expectedScreen,
                  self.setupHeight == expectedSetupHeight else { return }
            window.contentView?.layoutSubtreeIfNeeded()
            WindowContentSizing.resize(window, to: size)
            if firstAppearance { WindowCentering.center(window) }
        }
    }

    func restoreChrome() {
        guard let styledWindow else { return }
        styledWindow.titleVisibility = savedTitleVisibility
        styledWindow.titlebarAppearsTransparent = savedTransparency
        styledWindow.titlebarSeparatorStyle = savedSeparatorStyle
        if !savedFullSizeContent { styledWindow.styleMask.remove(.fullSizeContentView) }
        self.styledWindow = nil
        appliedScreen = nil
    }
}

/// One geometry owner per surface; a phase resize preserves the window's top edge.
enum WindowContentSizing {
    static func resize(_ window: NSWindow, to size: NSSize) {
        let topLeft = NSPoint(x: window.frame.minX, y: window.frame.maxY)
        window.setContentSize(size)
        window.setFrameTopLeftPoint(topLeft)
    }
}

struct SetupWindowHeightKey: PreferenceKey {
    static let defaultValue: CGFloat? = nil
    static func reduce(value: inout CGFloat?, nextValue: () -> CGFloat?) {
        if let next = nextValue() { value = next }
    }
}
