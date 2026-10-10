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
        guard command.timeoutSeconds > 0, command.timeoutSeconds <= 120,
              command.outputLimit > 0, command.outputLimit <= 1_048_576,
              command.input.count <= 65_536 else {
            throw SetupCommandError.invalidBounds
        }
        let job = SetupProcessJob(command: command)
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

// Foundation invokes pipe and exit callbacks on different queues. All mutable
// state and continuation completion belong to this lock, including cancellation.
private final class SetupProcessJob: @unchecked Sendable {
    private let lock = NSLock()
    private let command: SetupCommand
    private let process = Process()
    private let stdout = Pipe()
    private let stderr = Pipe()
    private let stdin = Pipe()
    private var continuation: CheckedContinuation<SetupCommandResult, any Error>?
    private var timer: DispatchSourceTimer?
    private var output = Data()
    private var errorOutput = Data()
    private var outputClosed = false
    private var errorClosed = false
    private var exited = false
    private var status: Int32 = -1
    private var failure: SetupCommandError?
    private var started = false
    private var finished = false

    init(command: SetupCommand) { self.command = command }

    func start(_ continuation: CheckedContinuation<SetupCommandResult, any Error>) {
        lock.lock()
        self.continuation = continuation
        if failure != nil {
            exited = true
            outputClosed = true
            errorClosed = true
            completeLocked()
            lock.unlock()
            return
        }
        process.executableURL = URL(fileURLWithPath: command.executable)
        process.arguments = command.arguments
        process.standardOutput = stdout
        process.standardError = stderr
        process.standardInput = stdin
        stdout.fileHandleForReading.readabilityHandler = { [weak self] handle in
            self?.receive(handle.availableData, isError: false)
        }
        stderr.fileHandleForReading.readabilityHandler = { [weak self] handle in
            self?.receive(handle.availableData, isError: true)
        }
        process.terminationHandler = { [weak self] child in
            self?.didExit(child.terminationStatus)
        }
        do {
            try process.run()
            started = true
        } catch {
            failure = .launchFailed
            exited = true
            outputClosed = true
            errorClosed = true
            completeLocked()
            lock.unlock()
            return
        }
        let deadline = DispatchSource.makeTimerSource()
        deadline.schedule(deadline: .now() + command.timeoutSeconds)
        deadline.setEventHandler { [weak self] in self?.stop(.timedOut) }
        timer = deadline
        deadline.resume()
        lock.unlock()
        do {
            try stdin.fileHandleForWriting.write(contentsOf: command.input)
            try stdin.fileHandleForWriting.close()
        } catch {
            stop(.inputFailed)
        }
    }

    func stop(_ error: SetupCommandError) {
        lock.lock()
        defer { lock.unlock() }
        guard !finished else { return }
        abortLocked(error)
        completeLocked()
    }

    private func receive(_ bytes: Data, isError: Bool) {
        lock.lock()
        defer { lock.unlock() }
        guard !finished else { return }
        if bytes.isEmpty {
            if isError {
                errorClosed = true
                stderr.fileHandleForReading.readabilityHandler = nil
            } else {
                outputClosed = true
                stdout.fileHandleForReading.readabilityHandler = nil
            }
        } else if bytes.count > command.outputLimit - output.count - errorOutput.count {
            abortLocked(.outputExceeded)
        } else if failure == nil {
            if isError { errorOutput.append(bytes) } else { output.append(bytes) }
        }
        completeLocked()
    }

    private func didExit(_ status: Int32) {
        lock.lock()
        defer { lock.unlock() }
        self.status = status
        exited = true
        completeLocked()
    }

    private func abortLocked(_ error: SetupCommandError) {
        if failure == nil { failure = error }
        // A descendant may retain a pipe writer after the direct child exits.
        // Refused output is terminal; its EOF must not extend the deadline.
        stdout.fileHandleForReading.readabilityHandler = nil
        stderr.fileHandleForReading.readabilityHandler = nil
        outputClosed = true
        errorClosed = true
        if started, !exited, process.processIdentifier > 0 {
            _ = Darwin.kill(process.processIdentifier, SIGKILL)
        }
    }

    private func completeLocked() {
        guard !finished, exited, outputClosed, errorClosed, let continuation else { return }
        finished = true
        self.continuation = nil
        timer?.cancel()
        timer = nil
        stdout.fileHandleForReading.readabilityHandler = nil
        stderr.fileHandleForReading.readabilityHandler = nil
        process.terminationHandler = nil
        if let failure {
            continuation.resume(throwing: failure)
        } else {
            continuation.resume(returning: SetupCommandResult(
                exitStatus: status, output: output, errorOutput: errorOutput))
        }
    }
}
