import AppKit
import SwiftUI

/// P04 About — app icon, display name, version, company identity.
struct AboutView: View {
    private var appName: String { "Helicoid Manager" }
    private var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1.0"
    }
    private var build: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "1"
    }

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 24)

            VStack(spacing: 0) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 128, height: 128)
                    .accessibilityHidden(true)

                Text(appName)
                    .font(.system(size: 22, weight: .semibold))
                    .padding(.top, 24)

                Text("Open-Source school computer management system")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 8)
                    .frame(maxWidth: 280)

                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 8) {
                    GridRow {
                        Text("Version")
                            .foregroundStyle(.secondary)
                            .gridColumnAlignment(.trailing)
                        Text(version)
                            .gridColumnAlignment(.leading)
                    }
                    GridRow {
                        Text("Build")
                            .foregroundStyle(.secondary)
                        Text(build)
                    }
                    GridRow {
                        Text("Company")
                            .foregroundStyle(.secondary)
                        Text("Helicoid Systems")
                    }
                    GridRow {
                        Text("Role")
                            .foregroundStyle(.secondary)
                        Text("Helicoid Manager")
                    }
                }
                .font(.body)
                .padding(.top, 36)
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            HStack {
                Spacer()
                Button("OK") {
                    NSApp.keyWindow?.close()
                }
                .keyboardShortcut(.defaultAction)
                Spacer()
            }
            .padding(.bottom, 28)
            .padding(.horizontal, 28)
        }
        .frame(width: 420, height: 560)
        .background(AboutWindowChrome())
    }
}

/// Same material-free top bar as the main Manager window.
private struct AboutWindowChrome: NSViewRepresentable {
    func makeNSView(context: Context) -> ChromeView { ChromeView() }
    func updateNSView(_ nsView: ChromeView, context: Context) { nsView.apply() }

    final class ChromeView: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            apply()
        }

        func apply() {
            guard let window else { return }
            window.titleVisibility = .hidden
            window.titlebarAppearsTransparent = true
            window.titlebarSeparatorStyle = .none
            window.styleMask.insert(.fullSizeContentView)
            window.backgroundColor = .windowBackgroundColor
        }
    }
}

enum AboutWindow {
    private static var panel: NSWindow?

    static func show() {
        if let panel {
            panel.alphaValue = 1
            panel.setContentSize(NSSize(width: 420, height: 560))
            WindowCentering.center(panel)
            WindowAnimator.animateOpen(panel)
            return
        }

        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 420, height: 560),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        panel.title = "About Helicoid Manager"
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.titlebarSeparatorStyle = .none
        panel.isReleasedWhenClosed = false
        panel.isMovableByWindowBackground = true
        panel.backgroundColor = .windowBackgroundColor
        panel.level = .floating

        let host = NSHostingController(rootView: AboutView())
        panel.contentViewController = host
        panel.setContentSize(NSSize(width: 420, height: 560))
        WindowCentering.center(panel)
        WindowCloseAnimator.attach(to: panel)
        WindowAnimator.animateOpen(panel)
        self.panel = panel
    }
}
