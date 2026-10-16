import Foundation
@testable import HelicoidCore

/// Deterministic wakeable clock for session expiry tests.
/// Belongs in the test target only — not shipped product sources.
/// `sleepUntil` parks until `advance`/`advanceMonotonic` reaches the deadline
/// or the waiting task is cancelled (returns `CancellationError` promptly).
final class ManualSessionTimeSource: SessionTimeSource, @unchecked Sendable {
    private let lock = NSLock()
    private var _wall: Int
    private var _mono: UInt64
    private var nextWaiter: UInt64 = 0
    private var waiters: [UInt64: (deadline: UInt64, continuation: CheckedContinuation<Void, Error>)] = [:]
    private var cancelledBeforeRegister: Set<UInt64> = []

    /// Number of sleepers actually parked (deadline timer evidence).
    var coordinatorSleeperCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return waiters.count
    }

    init(wallUnix: Int = 1_760_000_000, monotonicNanos: UInt64 = 1_000_000_000) {
        self._wall = wallUnix
        self._mono = monotonicNanos
    }

    var wallUnix: Int {
        lock.lock()
        defer { lock.unlock() }
        return _wall
    }

    var monotonicNanos: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return _mono
    }

    func advance(seconds: Int) {
        precondition(seconds >= 0)
        advanceMonotonic(seconds: seconds)
        lock.lock()
        _wall &+= seconds
        lock.unlock()
    }

    func rollbackWall(seconds: Int) {
        precondition(seconds >= 0)
        lock.lock()
        _wall &-= seconds
        lock.unlock()
    }

    func advanceMonotonic(seconds: Int) {
        precondition(seconds >= 0)
        lock.lock()
        _mono &+= UInt64(seconds) &* 1_000_000_000
        let due = waiters.filter { $0.value.deadline <= _mono }
        for (id, waiter) in due {
            waiters.removeValue(forKey: id)
            waiter.continuation.resume()
        }
        lock.unlock()
    }

    func sleepUntil(monotonicNanos deadline: UInt64) async throws {
        try Task.checkCancellation()
        let id: UInt64 = lock.withLock {
            nextWaiter &+= 1
            return nextWaiter
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                lock.lock()
                if cancelledBeforeRegister.contains(id) {
                    cancelledBeforeRegister.remove(id)
                    lock.unlock()
                    continuation.resume(throwing: CancellationError())
                    return
                }
                if _mono >= deadline {
                    lock.unlock()
                    continuation.resume()
                    return
                }
                waiters[id] = (deadline, continuation)
                lock.unlock()
            }
        } onCancel: {
            lock.lock()
            if let waiter = waiters.removeValue(forKey: id) {
                lock.unlock()
                waiter.continuation.resume(throwing: CancellationError())
            } else {
                // Cancel raced registration — latch so the park throws.
                cancelledBeforeRegister.insert(id)
                lock.unlock()
            }
        }
    }
}
