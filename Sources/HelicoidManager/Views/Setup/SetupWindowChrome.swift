import AppKit
import SwiftUI

/// Keeps the setup dialog's window controls while removing the title-bar strip.
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
        savedTitleVisibility = window.titleVisibility
        savedTransparency = window.titlebarAppearsTransparent
        savedFullSizeContent = window.styleMask.contains(.fullSizeContentView)
        savedSeparatorStyle = window.titlebarSeparatorStyle
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.titlebarSeparatorStyle = .none
        window.styleMask.insert(.fullSizeContentView)
    }

    func restoreChrome() {
        guard let styledWindow else { return }
        styledWindow.titleVisibility = savedTitleVisibility
        styledWindow.titlebarAppearsTransparent = savedTransparency
        styledWindow.titlebarSeparatorStyle = savedSeparatorStyle
        if !savedFullSizeContent { styledWindow.styleMask.remove(.fullSizeContentView) }
        self.styledWindow = nil
    }
}
