import Foundation
import Darwin

public struct SetupCommand: Sendable {
    public let executable: String
    public let arguments: [String]
    public let input: Data
    public let timeoutSeconds: TimeInterval
    public let outputLimit: Int

    public init(executable: String, arguments: [String], input: Data = Data(),
                timeoutSeconds: TimeInterval = 30, outputLimit: Int = 65_536) {
        self.executable = executable
        self.arguments = arguments
        self.input = input
        self.timeoutSeconds = timeoutSeconds
        self.outputLimit = outputLimit
    }
}

public struct SetupCommandResult: Sendable {
    public let exitStatus: Int32
    public let output: Data
    public let errorOutput: Data

    public init(exitStatus: Int32, output: Data, errorOutput: Data = Data()) {
        self.exitStatus = exitStatus
        self.output = output
        self.errorOutput = errorOutput
    }
}

public enum SetupCommandError: Error, Equatable, Sendable {
    case invalidBounds
    case launchFailed
    case timedOut
    case outputExceeded
    case inputFailed
    case cancelled
}

public protocol SetupCommandRunning: Sendable {
    func run(_ command: SetupCommand) async throws -> SetupCommandResult
}

public struct SystemSetupCommandRunner: SetupCommandRunning {
    public init() {}

    public func run(_ command: SetupCommand) async throws -> SetupCommandResult {
        // NaN fails both comparisons and is rejected; finite bounds only.
        guard command.timeoutSeconds > 0, command.timeoutSeconds <= 120,
              command.outputLimit > 0, command.outputLimit <= 1_048_576,
              command.input.count <= 65_536 else {
            throw SetupCommandError.invalidBounds
        }
        let startedAt = ContinuousClock.now
        let job = SetupProcessJob(command: command, startedAt: startedAt)
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                job.start(continuation)
            }
        } onCancel: {
            job.stop(.cancelled)
        }
    }
}

// Single serial owner for one posix_spawn child. Nonblocking pipes and
// waitpid(WNOHANG) live only on `queue`, so cancellation, I/O, and reap
// cannot race, and an fd is closed only after the owner stops using it.
// Signaling is limited to this job's still-unreaped direct child.
private final class SetupProcessJob: @unchecked Sendable {
    private let queue = DispatchQueue(label: "HelicoidCore.SetupProcessJob")
    private let command: SetupCommand
    private let deadline: ContinuousClock.Instant

    private var continuation: CheckedContinuation<SetupCommandResult, any Error>?
    private var poll: DispatchSourceTimer?
    private var finished = false
    private var launched = false
    private var pendingFailure: SetupCommandError?

    private var childPID: pid_t = -1
    private var reaped = false
    private var reapUncertain = false
    private var rawStatus: Int32 = -1

    private var stdinWriteFD: Int32 = -1
    private var stdoutReadFD: Int32 = -1
    private var stderrReadFD: Int32 = -1

    private var output = Data()
    private var errorOutput = Data()
    private var outputEOF = false
    private var errorEOF = false
    private var inputOffset = 0

    init(command: SetupCommand, startedAt: ContinuousClock.Instant) {
        self.command = command
        self.deadline = startedAt.advanced(by: .seconds(command.timeoutSeconds))
    }

    func start(_ continuation: CheckedContinuation<SetupCommandResult, any Error>) {
        queue.async {
            guard self.continuation == nil, !self.finished else {
                continuation.resume(throwing: SetupCommandError.cancelled)
                return
            }
            self.continuation = continuation
            if let pendingFailure = self.pendingFailure {
                self.completeFailure(pendingFailure)
                return
            }
            self.launch()
        }
    }

    func stop(_ error: SetupCommandError) {
        queue.async {
            if self.finished { return }
            if self.pendingFailure == nil {
                self.pendingFailure = error
            }
            guard let failure = self.pendingFailure else { return }
            if self.continuation == nil {
                // Cancellation before start registers: never spawn.
                return
            }
            if !self.launched {
                self.completeFailure(failure)
                return
            }
            self.abort(failure)
        }
    }

    private func launch() {
        guard ContinuousClock.now < deadline else {
            completeFailure(.timedOut)
            return
        }
        do {
            try spawnOwnedChild()
        } catch let error as SetupCommandError {
            completeFailure(error)
            return
        } catch {
            completeFailure(.launchFailed)
            return
        }
        launched = true
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .milliseconds(1), repeating: .milliseconds(1))
        timer.setEventHandler { [weak self] in
            self?.tick()
        }
        poll = timer
        timer.resume()
    }

    private func tick() {
        guard !finished else { return }
        if ContinuousClock.now >= deadline {
            // Inherited pipe writers and unread bytes are part of the same
            // command deadline. Never return partial output as success.
            abort(.timedOut)
            return
        }
        drainStdout()
        guard !finished else { return }
        drainStderr()
        guard !finished else { return }
        pumpStdin()
        guard !finished else { return }
        reapOwnedChild(blocking: false)
        guard !finished else { return }
        if reaped && outputEOF && errorEOF {
            completeSuccess()
        }
    }

    private func drainStdout() {
        guard !outputEOF, stdoutReadFD >= 0 else {
            outputEOF = true
            return
        }
        while true {
            var chunk = [UInt8](repeating: 0, count: 16_384)
            let n = read(stdoutReadFD, &chunk, chunk.count)
            if n > 0 {
                guard appendOutput(Data(bytes: chunk, count: n), isError: false) else { return }
                continue
            }
            if n == 0 {
                outputEOF = true
                return
            }
            if errno == EINTR {
                continue
            }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                return
            }
            // Hard read error: never claim success with truncated output.
            completeFailure(.launchFailed)
            return
        }
    }

    private func drainStderr() {
        guard !errorEOF, stderrReadFD >= 0 else {
            errorEOF = true
            return
        }
        while true {
            var chunk = [UInt8](repeating: 0, count: 16_384)
            let n = read(stderrReadFD, &chunk, chunk.count)
            if n > 0 {
                guard appendOutput(Data(bytes: chunk, count: n), isError: true) else { return }
                continue
            }
            if n == 0 {
                errorEOF = true
                return
            }
            if errno == EINTR {
                continue
            }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                return
            }
            completeFailure(.launchFailed)
            return
        }
    }

    @discardableResult
    private func appendOutput(_ bytes: Data, isError: Bool) -> Bool {
        guard !bytes.isEmpty else { return true }
        if output.count + errorOutput.count + bytes.count > command.outputLimit {
            completeFailure(.outputExceeded)
            return false
        }
        if isError {
            errorOutput.append(bytes)
        } else {
            output.append(bytes)
        }
        return true
    }

    private func pumpStdin() {
        guard stdinWriteFD >= 0 else { return }
        while inputOffset < command.input.count {
            let slice = command.input[inputOffset...]
            let written = slice.withUnsafeBytes { raw -> Int in
                guard let base = raw.baseAddress else { return 0 }
                return write(stdinWriteFD, base, raw.count)
            }
            if written > 0 {
                inputOffset += written
                continue
            }
            if written < 0 && errno == EINTR {
                continue
            }
            if written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                return
            }
            closeStdinFD()
            completeFailure(.inputFailed)
            return
        }
        closeStdinFD()
    }

    // Sole reaper. WNOHANG records actual exit before this PID can be reused.
    private func reapOwnedChild(blocking: Bool) {
        guard !reaped, !reapUncertain, childPID > 0 else { return }
        var status: Int32 = 0
        let options: Int32 = blocking ? 0 : Int32(WNOHANG)
        while true {
            let rc = waitpid(childPID, &status, options)
            if rc == childPID {
                reaped = true
                rawStatus = status
                return
            }
            if rc == 0 {
                return
            }
            if errno == EINTR {
                continue
            }
            // ECHILD / other: ownership is no longer certain. Do not fabricate
            // a normal exit and never signal this PID again.
            reapUncertain = true
            completeFailure(.launchFailed)
            return
        }
    }

    private func abort(_ error: SetupCommandError) {
        guard !finished else { return }
        closeStdinFD()
        reapOwnedChild(blocking: false)
        if !reaped, !reapUncertain, childPID > 0 {
            _ = Darwin.kill(childPID, SIGKILL)
            reapOwnedChild(blocking: true)
        }
        completeFailure(error)
    }

    private func completeSuccess() {
        guard !finished else { return }
        reapOwnedChild(blocking: true)
        guard !finished else { return }
        guard reaped, !reapUncertain else {
            completeFailure(.timedOut)
            return
        }
        finished = true
        stopPollingAndCloseFDs()
        let result = SetupCommandResult(
            exitStatus: decodedWaitStatus(rawStatus),
            output: output,
            errorOutput: errorOutput)
        let continuation = self.continuation
        self.continuation = nil
        continuation?.resume(returning: result)
    }

    private func completeFailure(_ error: SetupCommandError) {
        guard !finished else { return }
        // Every failure path owns cleanup, including overflow and hard I/O
        // errors. An unread/rejected input cannot leave a live child or zombie.
        closeStdinFD()
        reapOwnedChild(blocking: false)
        guard !finished else { return }
        if !reaped, !reapUncertain, childPID > 0 {
            _ = Darwin.kill(childPID, SIGKILL)
            reapOwnedChild(blocking: true)
        }
        guard !finished else { return }
        finished = true
        stopPollingAndCloseFDs()
        let continuation = self.continuation
        self.continuation = nil
        if let continuation {
            continuation.resume(throwing: error)
        } else {
            pendingFailure = error
        }
    }

    private func stopPollingAndCloseFDs() {
        if let poll {
            self.poll = nil
            poll.cancel()
        }
        // No queued read/write remains after `finished` is set on this serial
        // owner; closing here cannot race a later I/O call.
        closeStdinFD()
        closeStdoutFD()
        closeStderrFD()
    }

    private func closeStdinFD() {
        if stdinWriteFD >= 0 {
            close(stdinWriteFD)
            stdinWriteFD = -1
        }
    }

    private func closeStdoutFD() {
        if stdoutReadFD >= 0 {
            close(stdoutReadFD)
            stdoutReadFD = -1
        }
    }

    private func closeStderrFD() {
        if stderrReadFD >= 0 {
            close(stderrReadFD)
            stderrReadFD = -1
        }
    }

    private func spawnOwnedChild() throws {
        guard !command.executable.utf8.contains(0),
              command.arguments.allSatisfy({ !$0.utf8.contains(0) }) else {
            throw SetupCommandError.launchFailed
        }

        var stdinPipe: [Int32] = [-1, -1]
        var stdoutPipe: [Int32] = [-1, -1]
        var stderrPipe: [Int32] = [-1, -1]
        guard pipe(&stdinPipe) == 0, pipe(&stdoutPipe) == 0, pipe(&stderrPipe) == 0 else {
            closePipe(&stdinPipe)
            closePipe(&stdoutPipe)
            closePipe(&stderrPipe)
            throw SetupCommandError.launchFailed
        }
        // Never steal or close redirected standard descriptors.
        for fd in [stdinPipe[0], stdinPipe[1], stdoutPipe[0], stdoutPipe[1],
                   stderrPipe[0], stderrPipe[1]] where fd < 3 {
            closePipe(&stdinPipe)
            closePipe(&stdoutPipe)
            closePipe(&stderrPipe)
            throw SetupCommandError.launchFailed
        }

        do {
            for fd in stdinPipe + stdoutPipe + stderrPipe {
                let flags = fcntl(fd, F_GETFD)
                guard flags >= 0, fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0 else {
                    throw SetupCommandError.launchFailed
                }
            }
        } catch {
            closePipe(&stdinPipe)
            closePipe(&stdoutPipe)
            closePipe(&stderrPipe)
            throw error
        }

        var fileActions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&fileActions) == 0 else {
            closePipe(&stdinPipe)
            closePipe(&stdoutPipe)
            closePipe(&stderrPipe)
            throw SetupCommandError.launchFailed
        }
        defer { posix_spawn_file_actions_destroy(&fileActions) }

        var attr: posix_spawnattr_t?
        guard posix_spawnattr_init(&attr) == 0 else {
            closePipe(&stdinPipe)
            closePipe(&stdoutPipe)
            closePipe(&stderrPipe)
            throw SetupCommandError.launchFailed
        }
        defer { posix_spawnattr_destroy(&attr) }

        // Keep unrelated parent descriptors out of concurrent children.
        let cloexecDefault = Int16(bitPattern: 0x4000) // POSIX_SPAWN_CLOEXEC_DEFAULT
        guard posix_spawnattr_setflags(&attr, cloexecDefault) == 0 else {
            closePipe(&stdinPipe)
            closePipe(&stdoutPipe)
            closePipe(&stderrPipe)
            throw SetupCommandError.launchFailed
        }

        guard posix_spawn_file_actions_adddup2(&fileActions, stdinPipe[0], STDIN_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&fileActions, stdoutPipe[1], STDOUT_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&fileActions, stderrPipe[1], STDERR_FILENO) == 0 else {
            closePipe(&stdinPipe)
            closePipe(&stdoutPipe)
            closePipe(&stderrPipe)
            throw SetupCommandError.launchFailed
        }
        for fd in [stdinPipe[0], stdinPipe[1], stdoutPipe[0], stdoutPipe[1],
                   stderrPipe[0], stderrPipe[1]] {
            guard posix_spawn_file_actions_addclose(&fileActions, fd) == 0 else {
                closePipe(&stdinPipe)
                closePipe(&stdoutPipe)
                closePipe(&stderrPipe)
                throw SetupCommandError.launchFailed
            }
        }

        var pid: pid_t = 0
        let spawnStatus: Int32
        do {
            spawnStatus = try withCStrings([command.executable] + command.arguments) { argv in
                try withCStrings(environmentStrings()) { envp in
                    posix_spawn(&pid, command.executable, &fileActions, &attr, argv, envp)
                }
            }
        } catch {
            close(stdinPipe[0])
            close(stdinPipe[1])
            close(stdoutPipe[0])
            close(stdoutPipe[1])
            close(stderrPipe[0])
            close(stderrPipe[1])
            throw error
        }
        close(stdinPipe[0])
        close(stdoutPipe[1])
        close(stderrPipe[1])
        guard spawnStatus == 0, pid > 0 else {
            close(stdinPipe[1])
            close(stdoutPipe[0])
            close(stderrPipe[0])
            throw SetupCommandError.launchFailed
        }

        // Publish ownership before any post-spawn operation can fail. The
        // shared failure path then signals/reaps and closes this exact child.
        stdinWriteFD = stdinPipe[1]
        stdoutReadFD = stdoutPipe[0]
        stderrReadFD = stderrPipe[0]
        childPID = pid
        try setNonBlocking(stdinWriteFD)
        try setNonBlocking(stdoutReadFD)
        try setNonBlocking(stderrReadFD)
        // Scoped to this write fd; never a process-wide signal disposition.
        guard fcntl(stdinWriteFD, F_SETNOSIGPIPE, 1) == 0 else {
            throw SetupCommandError.launchFailed
        }
    }
}

private func closePipe(_ fds: inout [Int32]) {
    for fd in fds where fd >= 0 {
        close(fd)
    }
    fds = [-1, -1]
}

private func setNonBlocking(_ fd: Int32) throws {
    let flags = fcntl(fd, F_GETFL, 0)
    guard flags >= 0 else {
        throw SetupCommandError.launchFailed
    }
    guard fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
        throw SetupCommandError.launchFailed
    }
}

private func withCStrings<R>(
    _ strings: [String],
    _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) throws -> R
) throws -> R {
    var pointers: [UnsafeMutablePointer<CChar>?] = []
    pointers.reserveCapacity(strings.count + 1)
    for string in strings {
        guard let copy = strdup(string) else {
            for pointer in pointers {
                free(pointer)
            }
            throw SetupCommandError.launchFailed
        }
        pointers.append(copy)
    }
    pointers.append(nil)
    defer {
        for pointer in pointers {
            free(pointer)
        }
    }
    return try pointers.withUnsafeMutableBufferPointer { buffer in
        try body(buffer.baseAddress!)
    }
}

private func environmentStrings() -> [String] {
    ProcessInfo.processInfo.environment
        .sorted { $0.key < $1.key }
        .map { "\($0.key)=\($0.value)" }
}

private func decodedWaitStatus(_ rawStatus: Int32) -> Int32 {
    if (rawStatus & 0x7f) == 0 {
        return (rawStatus >> 8) & 0xff
    }
    return rawStatus & 0x7f
}
