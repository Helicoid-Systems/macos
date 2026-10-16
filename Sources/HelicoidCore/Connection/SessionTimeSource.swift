import Foundation

/// Time source for session deadline checks.
///
/// Live deployments interpret contracted `expires_at_unix` with wall time and
/// hold the live deadline on **Swift `ContinuousClock`** so sleep/suspend (and
/// system sleep) cannot stretch a session the way `DispatchTime` uptime can.
/// Deadline arithmetic and `sleepUntil` share the same clock origin.
///
/// Production always uses `LiveSessionTimeSource`. Manual clocks are a test
/// seam and live in the test target only.
protocol SessionTimeSource: Sendable {
    /// Contract wall clock (unix seconds), used for reception-relative bounds.
    var wallUnix: Int { get }
    /// Monotonic nanoseconds since this source's `ContinuousClock` origin.
    /// Never decreases across suspend.
    var monotonicNanos: UInt64 { get }
    /// Sleep until the monotonic deadline on the **same** clock scale.
    /// Throws `CancellationError` on cancellation. Never busy-polls.
    func sleepUntil(monotonicNanos deadline: UInt64) async throws
}

/// Production time source: wall clock + `ContinuousClock` monotonic scale.
public struct LiveSessionTimeSource: SessionTimeSource {
    private let origin: ContinuousClock.Instant

    public init() {
        self.origin = ContinuousClock.now
    }

    public var wallUnix: Int { Int(Date().timeIntervalSince1970) }

    public var monotonicNanos: UInt64 {
        Self.nanos(from: origin, to: ContinuousClock.now)
    }

    public func sleepUntil(monotonicNanos deadline: UInt64) async throws {
        let now = monotonicNanos
        guard deadline > now else { return }
        let remaining = Duration.nanoseconds(Int64(min(deadline &- now, UInt64(Int64.max))))
        // ContinuousClock.sleep — suspending the task does not extend the wait.
        try await ContinuousClock().sleep(until: ContinuousClock.now.advanced(by: remaining))
    }

    /// Checked duration → nanoseconds on the ContinuousClock scale.
    /// Positive fractional seconds (e.g. 500ms) must not collapse to zero.
    static func nanos(from start: ContinuousClock.Instant, to end: ContinuousClock.Instant) -> UInt64 {
        let duration = start.duration(to: end)
        let (seconds, attoseconds) = duration.components
        // Negative durations (end before start) report 0; never wrap.
        if seconds < 0 { return 0 }
        if seconds == 0 && attoseconds <= 0 { return 0 }
        // attoseconds: 1e18 per second; nanoseconds: 1e9.
        // For nonnegative Duration, attoseconds share the sign of the duration
        // when seconds >= 0 (fractional part is nonnegative).
        let (secNanos, overflow) = UInt64(seconds).multipliedReportingOverflow(by: 1_000_000_000)
        if overflow { return UInt64.max }
        let frac = UInt64(clamping: attoseconds / 1_000_000_000)
        let (sum, addOverflow) = secNanos.addingReportingOverflow(frac)
        return addOverflow ? UInt64.max : sum
    }
}
