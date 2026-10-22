import AppKit
import SwiftUI

/// P04 About — compact app icon, display name, version, company identity.
struct AboutView: View {
    @Environment(\.openURL) private var openURL
    private var appName: String { "Helicoid Manager" }
    private var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
    }
    private var build: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "—"
    }
    private var sourceURL: URL? { URL(string: "https://github.com/Helicoid-Systems/macos") }

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 12)

            VStack(spacing: 0) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 64, height: 64)
                    .accessibilityHidden(true)

                Text(appName)
                    .font(.title3.weight(.semibold))
                    .padding(.top, 12)

                Text("Computer monitoring and remote assistance")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 4)
                    .frame(maxWidth: 280)

                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                    GridRow {
                        Text("Version")
                            .foregroundStyle(.secondary)
                            .gridColumnAlignment(.trailing)
                        Text(version)
                            .gridColumnAlignment(.leading)
                            .textSelection(.enabled)
                    }
                    GridRow {
                        Text("Build")
                            .foregroundStyle(.secondary)
                        Text(build)
                            .textSelection(.enabled)
                    }
                    GridRow {
                        Text("Company")
                            .foregroundStyle(.secondary)
                        Text("Helicoid Systems")
                    }
                }
                .font(.callout)
                .padding(.top, 16)
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            HStack(spacing: 12) {
                Spacer()
                if let sourceURL {
                    Button {
                        openURL(sourceURL)
                    } label: {
                        HStack(spacing: 6) {
                            GitHubMark()
                                .frame(width: 15, height: 15)
                            Text("Source")
                        }
                    }
                    .buttonStyle(.bordered)
                    .help(sourceURL.absoluteString)
                }
                Button("Done") {
                    NSApp.keyWindow?.close()
                }
                .buttonStyle(.bordered)
                .keyboardShortcut(.cancelAction)
                Spacer()
            }
            .padding(.bottom, 16)
            .padding(.horizontal, 16)
        }
        .frame(minWidth: 320, idealWidth: 360, maxWidth: 420)
        .frame(minHeight: 300, idealHeight: 340, maxHeight: 400)
        .background(AboutWindowChrome())
    }
}

/// GitHub mark (24x24 viewBox), drawn to match the button title color.
private struct GitHubMark: View {
    var body: some View {
        GitHubMarkShape()
            .fill(.primary)
    }
}

private struct GitHubMarkShape: Shape {
    nonisolated func path(in rect: CGRect) -> Path {
        var path = Path()
        let s = min(rect.width, rect.height) / 24.0
        let dx = rect.minX
        let dy = rect.minY
        func p(_ x: Double, _ y: Double) -> CGPoint {
            CGPoint(x: dx + x * s, y: dy + y * s)
        }
        path.move(to: p(12, 0.297))
        path.addCurve(to: p(0, 12.297), control1: p(5.37, 0.297), control2: p(0, 5.67))
        path.addCurve(to: p(8.205, 23.682), control1: p(0, 17.6), control2: p(3.438, 22.097))
        path.addCurve(to: p(9.025, 23.105), control1: p(8.805, 23.795), control2: p(9.025, 23.424))
        path.addCurve(to: p(9.01, 21.065), control1: p(9.025, 22.82), control2: p(9.015, 22.065))
        path.addCurve(to: p(4.968, 19.455), control1: p(5.672, 21.789), control2: p(4.968, 19.455))
        path.addCurve(to: p(3.633, 17.7), control1: p(4.422, 18.07), control2: p(3.633, 17.7))
        path.addCurve(to: p(3.717, 16.971), control1: p(2.546, 16.956), control2: p(3.717, 16.971))
        path.addCurve(to: p(5.555, 18.207), control1: p(4.922, 17.055), control2: p(5.555, 18.207))
        path.addCurve(to: p(9.05, 19.205), control1: p(6.625, 20.042), control2: p(8.364, 19.512))
        path.addCurve(to: p(9.81, 17.6), control1: p(9.158, 18.429), control2: p(9.467, 17.9))
        path.addCurve(to: p(4.344, 11.67), control1: p(7.145, 17.3), control2: p(4.344, 16.268))
        path.addCurve(to: p(5.579, 8.45), control1: p(4.344, 10.36), control2: p(4.809, 9.29))
        path.addCurve(to: p(5.684, 5.274), control1: p(5.444, 8.147), control2: p(5.039, 6.927))
        path.addCurve(to: p(8.984, 6.504), control1: p(5.684, 5.274), control2: p(6.689, 4.952))
        path.addCurve(to: p(11.984, 6.099), control1: p(9.944, 6.237), control2: p(10.964, 6.105))
        path.addCurve(to: p(14.984, 6.504), control1: p(13.004, 6.105), control2: p(14.024, 6.237))
        path.addCurve(to: p(18.269, 5.274), control1: p(17.264, 4.952), control2: p(18.269, 5.274))
        path.addCurve(to: p(18.389, 8.45), control1: p(18.914, 6.927), control2: p(18.509, 8.147))
        path.addCurve(to: p(19.619, 11.67), control1: p(19.154, 9.29), control2: p(19.619, 10.36))
        path.addCurve(to: p(14.144, 17.59), control1: p(19.619, 16.28), control2: p(16.814, 17.295))
        path.addCurve(to: p(14.954, 19.81), control1: p(14.564, 17.95), control2: p(14.954, 18.686))
        path.addCurve(to: p(14.939, 23.096), control1: p(14.954, 21.416), control2: p(14.939, 22.706))
        path.addCurve(to: p(15.764, 23.666), control1: p(14.939, 23.411), control2: p(15.149, 23.786))
        path.addCurve(to: p(24, 12.297), control1: p(20.565, 22.092), control2: p(24, 17.592))
        path.addCurve(to: p(12, 0.297), control1: p(24, 5.67), control2: p(18.627, 0.297))
        path.closeSubpath()
        return path
    }
}

/// Same material-free top bar as the compact setup window.
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
    private static var window: NSWindow?
    private static let contentSize = NSSize(width: 360, height: 340)

    static func show() {
        if let window {
            // Reopen focuses without recentering or resizing the user's placement.
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: contentSize),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "About Helicoid Manager"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.titlebarSeparatorStyle = .none
        window.isReleasedWhenClosed = false
        window.isMovableByWindowBackground = true
        window.backgroundColor = .windowBackgroundColor
        window.animationBehavior = .documentWindow

        let host = NSHostingController(rootView: AboutView())
        window.contentViewController = host
        window.setContentSize(contentSize)
        WindowCentering.center(window)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        self.window = window
    }
}
