import AppKit
import SwiftUI

/// Keeps a native setup title and window controls without a separate navigation strip.
/// Restores the previous chrome when the Manager leaves setup.
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

final class WindowChromeView: NSView {
    var isEnabled = false
    private weak var styledWindow: NSWindow?
    private var savedTitle = ""
    private var savedFrame = NSRect.zero
    private var savedTitleVisibility: NSWindow.TitleVisibility = .visible
    private var savedTransparency = false
    private var savedFullSizeContent = false
    private var savedSeparatorStyle: NSTitlebarSeparatorStyle = .automatic

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if styledWindow !== window { restoreChrome() }
        applyChrome()
    }

    func applyChrome() {
        guard isEnabled, let window else {
            restoreChrome()
            return
        }
        guard styledWindow !== window else { return }
        styledWindow = window
        savedTitle = window.title
        savedFrame = window.frame
        savedTitleVisibility = window.titleVisibility
        savedTransparency = window.titlebarAppearsTransparent
        savedFullSizeContent = window.styleMask.contains(.fullSizeContentView)
        savedSeparatorStyle = window.titlebarSeparatorStyle
        window.title = "Server Setup · Helicoid Manager"
        window.titleVisibility = .visible
        window.titlebarAppearsTransparent = true
        window.titlebarSeparatorStyle = .none
        window.styleMask.insert(.fullSizeContentView)
        window.setContentSize(NSSize(width: 600, height: 400))
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
    }
}
