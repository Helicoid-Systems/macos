import AppKit
import SwiftUI

/// Uses the Manager setup's integrated titlebar without changing other windows.
struct ComputerSettingsWindowChrome: NSViewRepresentable {
    func makeNSView(context: Context) -> ComputerSettingsChromeView {
        ComputerSettingsChromeView()
    }

    func updateNSView(_ nsView: ComputerSettingsChromeView, context: Context) {
        nsView.applyChrome()
    }

    static func dismantleNSView(_ nsView: ComputerSettingsChromeView, coordinator: ()) {
        nsView.restoreChrome()
    }
}

final class ComputerSettingsChromeView: NSView {
    private weak var styledWindow: NSWindow?
    private var savedTitleVisibility: NSWindow.TitleVisibility = .visible
    private var savedTransparency = false
    private var savedFullSizeContent = false
    private var savedSeparatorStyle: NSTitlebarSeparatorStyle = .automatic
    private var savedBackgroundColor: NSColor?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if styledWindow !== window {
            restoreChrome()
        }
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
            savedTitleVisibility = window.titleVisibility
            savedTransparency = window.titlebarAppearsTransparent
            savedFullSizeContent = window.styleMask.contains(.fullSizeContentView)
            savedSeparatorStyle = window.titlebarSeparatorStyle
            savedBackgroundColor = window.backgroundColor
        }

        // Manager setup look: no titlebar material or separator.
        window.titleVisibility = .visible
        window.titlebarAppearsTransparent = true
        window.titlebarSeparatorStyle = .none
        window.styleMask.insert(.fullSizeContentView)
        window.backgroundColor = .windowBackgroundColor
    }

    func restoreChrome() {
        guard let styledWindow else { return }
        styledWindow.titleVisibility = savedTitleVisibility
        styledWindow.titlebarAppearsTransparent = savedTransparency
        styledWindow.titlebarSeparatorStyle = savedSeparatorStyle
        if !savedFullSizeContent {
            styledWindow.styleMask.remove(.fullSizeContentView)
        }
        if let savedBackgroundColor {
            styledWindow.backgroundColor = savedBackgroundColor
        }
        self.styledWindow = nil
        self.savedBackgroundColor = nil
    }
}
