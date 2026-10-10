import AppKit
import QuartzCore

/// Window transforms: content scale/fade for open/close, animated window resize.
/// Open/close never touch `NSWindow.setFrame` — SwiftUI/NSHosting layout clamps
/// sub-min-size frames back on the next pass, which makes grow/shrink invisible.
enum WindowAnimator {
    private static let openDuration: TimeInterval = 0.3
    private static let closeDuration: TimeInterval = 0.22
    private static let resizeDuration: TimeInterval = 0.28

    private static var runners: [ObjectIdentifier: Runner] = [:]

    /// Open: content scales up from slightly smaller while fading in.
    static func animateOpen(_ window: NSWindow, activate: Bool = true) {
        stop(for: window)

        window.animationBehavior = .none
        window.alphaValue = 1

        guard !prefersReducedMotion else {
            setContentAlpha(window, 1)
            setContentScale(window, 1)
            if activate {
                window.makeKeyAndOrderFront(nil)
                NSApp.activate(ignoringOtherApps: true)
            } else {
                window.orderFrontRegardless()
            }
            return
        }

        prepareContentLayer(window)
        setContentAlpha(window, 0)
        setContentScale(window, 0.92)

        if activate {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        } else {
            window.orderFrontRegardless()
        }

        run(
            window: window,
            mode: .contentScale(from: 0.92, to: 1),
            fromContentAlpha: 0,
            toContentAlpha: 1,
            duration: openDuration,
            easing: .easeOut
        )
    }

    /// Close: content scales down and fades out, then the window closes.
    /// The completion intentionally does not restore alpha/frame — that caused a
    /// full-size flash immediately before `close()`.
    static func animateClose(_ window: NSWindow, completion: @escaping @Sendable () -> Void) {
        stop(for: window)
        window.animationBehavior = .none

        guard !prefersReducedMotion else {
            completion()
            return
        }

        prepareContentLayer(window)

        run(
            window: window,
            mode: .contentScale(from: 1, to: 0.92),
            fromContentAlpha: 1,
            toContentAlpha: 0,
            duration: closeDuration,
            easing: .easeIn
        ) {
            completion()
        }
    }

    /// Animate the window frame (and optional re-center) with a real size interpolation.
    static func animateResize(
        _ window: NSWindow,
        to contentSize: NSSize,
        center: Bool = true,
        title: String? = nil,
        titleVisibility: NSWindow.TitleVisibility? = nil
    ) {
        stop(for: window)
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
        }

        if let title { window.title = title }
        if let titleVisibility { window.titleVisibility = titleVisibility }

        guard !prefersReducedMotion else {
            window.setFrame(endFrame, display: true, animate: false)
            return
        }

        window.animationBehavior = .none
        run(
            window: window,
            mode: .frame(from: startFrame, to: endFrame),
            fromContentAlpha: contentAlpha(window),
            toContentAlpha: contentAlpha(window),
            duration: resizeDuration,
            easing: .easeOut
        )
    }

    /// Animate an existing frame change (for restoring setup chrome).
    static func animateFrame(
        _ window: NSWindow,
        to endFrame: NSRect,
        title: String? = nil,
        titleVisibility: NSWindow.TitleVisibility? = nil
    ) {
        stop(for: window)
        let startFrame = window.frame

        if let title { window.title = title }
        if let titleVisibility { window.titleVisibility = titleVisibility }

        guard !prefersReducedMotion else {
            window.setFrame(endFrame, display: true, animate: false)
            return
        }

        window.animationBehavior = .none
        run(
            window: window,
            mode: .frame(from: startFrame, to: endFrame),
            fromContentAlpha: contentAlpha(window),
            toContentAlpha: contentAlpha(window),
            duration: resizeDuration,
            easing: .easeOut
        )
    }

    // MARK: - Internals

    private static var prefersReducedMotion: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
    }

    private static func run(
        window: NSWindow,
        mode: Runner.Mode,
        fromContentAlpha: CGFloat,
        toContentAlpha: CGFloat,
        duration: TimeInterval,
        easing: Runner.Easing,
        completion: @escaping () -> Void = {}
    ) {
        let runner = Runner(window: window)
        runners[ObjectIdentifier(window)] = runner
        runner.start(
            mode: mode,
            fromContentAlpha: fromContentAlpha,
            toContentAlpha: toContentAlpha,
            duration: duration,
            easing: easing
        ) { [weak window] in
            if let window {
                runners[ObjectIdentifier(window)] = nil
            }
            completion()
        }
    }

    private static func stop(for window: NSWindow) {
        runners[ObjectIdentifier(window)]?.cancel()
        runners[ObjectIdentifier(window)] = nil
        setContentAlpha(window, 1)
        setContentScale(window, 1)
    }

    private static func prepareContentLayer(_ window: NSWindow) {
        window.contentView?.wantsLayer = true
        window.contentView?.layer?.anchorPoint = CGPoint(x: 0.5, y: 0.5)
    }

    private static func contentAlpha(_ window: NSWindow) -> CGFloat {
        window.contentView?.alphaValue ?? 1
    }

    private static func setContentAlpha(_ window: NSWindow, _ value: CGFloat) {
        window.contentView?.alphaValue = value
    }

    private static func setContentScale(_ window: NSWindow, _ scale: CGFloat) {
        guard let layer = window.contentView?.layer else { return }
        if scale == 1 {
            layer.transform = CATransform3DIdentity
        } else {
            layer.transform = CATransform3DMakeScale(scale, scale, 1)
        }
    }

    private final class Runner {
        enum Easing {
            case easeIn
            case easeOut

            func apply(_ t: Double) -> Double {
                switch self {
                case .easeIn: t * t * t
                case .easeOut: 1 - pow(1 - t, 3)
                }
            }
        }

        enum Mode {
            case contentScale(from: CGFloat, to: CGFloat)
            case frame(from: NSRect, to: NSRect)
        }

        private weak var window: NSWindow?
        private var timer: Timer?
        private var startTime = CACurrentMediaTime()
        private var duration: TimeInterval = 0
        private var mode = Mode.contentScale(from: 1, to: 1)
        private var fromContentAlpha: CGFloat = 1
        private var toContentAlpha: CGFloat = 1
        private var easing = Easing.easeOut
        private var completion: (() -> Void)?

        init(window: NSWindow) {
            self.window = window
        }

        func cancel() {
            timer?.invalidate()
            timer = nil
            completion = nil
        }

        func start(
            mode: Mode,
            fromContentAlpha: CGFloat,
            toContentAlpha: CGFloat,
            duration: TimeInterval,
            easing: Easing,
            completion: @escaping () -> Void
        ) {
            self.mode = mode
            self.fromContentAlpha = fromContentAlpha
            self.toContentAlpha = toContentAlpha
            self.duration = duration
            self.easing = easing
            self.completion = completion
            self.startTime = CACurrentMediaTime()

            let timer = Timer(timeInterval: 1 / 120, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?.tick()
                }
            }
            RunLoop.main.add(timer, forMode: .common)
            self.timer = timer
            tick()
        }

        private func tick() {
            guard let window else {
                cancel()
                return
            }
            let raw = min(1, (CACurrentMediaTime() - startTime) / duration)
            let t = easing.apply(raw)

            switch mode {
            case let .contentScale(from, to):
                let scale = from + (to - from) * CGFloat(t)
                if let layer = window.contentView?.layer {
                    if scale == 1 {
                        layer.transform = CATransform3DIdentity
                    } else {
                        layer.transform = CATransform3DMakeScale(scale, scale, 1)
                    }
                }
            case let .frame(from, to):
                let frame = NSRect(
                    x: from.origin.x + (to.origin.x - from.origin.x) * t,
                    y: from.origin.y + (to.origin.y - from.origin.y) * t,
                    width: from.size.width + (to.size.width - from.size.width) * t,
                    height: from.size.height + (to.size.height - from.size.height) * t
                )
                if frame != window.frame {
                    window.setFrame(frame, display: true, animate: false)
                }
            }

            let alpha = fromContentAlpha + (toContentAlpha - fromContentAlpha) * CGFloat(t)
            window.contentView?.alphaValue = alpha

            if raw >= 1 {
                timer?.invalidate()
                timer = nil
                let done = completion
                completion = nil
                done?()
            }
        }
    }
}

/// Animates window close while still forwarding SwiftUI/AppKit delegate calls.
final class WindowCloseAnimator: NSObject, NSWindowDelegate {
    private nonisolated(unsafe) weak var originalDelegate: NSWindowDelegate?
    private nonisolated(unsafe) weak var animatedWindow: NSWindow?
    private nonisolated(unsafe) var isAnimatingClose = false

    static func attach(to window: NSWindow) {
        if let existing = window.delegate as? WindowCloseAnimator, existing.animatedWindow === window {
            return
        }
        let animator = WindowCloseAnimator()
        animator.originalDelegate = window.delegate
        animator.animatedWindow = window
        window.delegate = animator
    }

    override nonisolated func responds(to aSelector: Selector!) -> Bool {
        if super.responds(to: aSelector) { return true }
        return originalDelegate?.responds(to: aSelector) == true
    }

    override nonisolated func forwardingTarget(for aSelector: Selector!) -> Any? {
        if let originalDelegate, originalDelegate.responds(to: aSelector) {
            return originalDelegate
        }
        return super.forwardingTarget(for: aSelector)
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if isAnimatingClose {
            return true
        }
        // `forwardingTarget` never sees methods this proxy implements — ask the
        // original delegate explicitly before claiming the close.
        if let originalDelegate = originalDelegate,
           originalDelegate.responds(to: #selector(NSWindowDelegate.windowShouldClose(_:))),
           originalDelegate.windowShouldClose?(sender) == false {
            return false
        }
        isAnimatingClose = true
        WindowAnimator.animateClose(sender) {
            MainActor.assumeIsolated {
                sender.close()
                self.isAnimatingClose = false
            }
        }
        return false
    }
}
