import CoreGraphics
import CoreMedia
import CoreVideo
import Foundation
import HelicoidCore
import ScreenCaptureKit

/// A current primary-display frame. The pixel buffer remains owned by CoreVideo
/// and is delivered on the capture queue; consumers must not retain an
/// unbounded history of frames.
public struct ScreenObservationFrame: @unchecked Sendable {
    public let pixelBuffer: CVPixelBuffer
    public let presentationTime: CMTime
}

/// Starts ScreenCaptureKit only for a server-redeemed, current observation
/// lease and a confirmed unlocked physical-console state. It is a capture
/// adapter; callers still need an admitted peer/media path before forwarding
/// these frames to a Manager.
@MainActor
public final class AuthorizedScreenCapture {
    private let enrollmentClient: EndpointEnrollmentClient
    private let permissionProbe: any ComputerPermissionProbing
    private let unlockedConsoleProbe: @Sendable () -> Bool
    private let onFrame: @Sendable (ScreenObservationFrame) -> Void
    private let onStopped: @MainActor @Sendable (String) -> Void
    private let outputQueue = DispatchQueue(label: "systems.helicoid.computer.screen-capture", qos: .userInteractive)

    private var stream: SCStream?
    private var output: ScreenCaptureOutput?
    private var gate: ScreenCaptureGate?
    private var admission: EndpointObservationAdmission?
    private var monitorTask: Task<Void, Never>?

    /// The unlocked-console probe must return `false` for locked or unknown
    /// state. It defaults to `false` because the documented macOS session
    /// properties do not expose a lock-status key.
    public init(
        enrollmentClient: EndpointEnrollmentClient,
        permissionProbe: any ComputerPermissionProbing = NativeComputerPermissionProbe(),
        onFrame: @escaping @Sendable (ScreenObservationFrame) -> Void,
        onStopped: @escaping @MainActor @Sendable (String) -> Void = { _ in },
        unlockedConsoleProbe: @escaping @Sendable () -> Bool = { false }
    ) {
        self.enrollmentClient = enrollmentClient
        self.permissionProbe = permissionProbe
        self.unlockedConsoleProbe = unlockedConsoleProbe
        self.onFrame = onFrame
        self.onStopped = onStopped
    }

    public func start(admission: EndpointObservationAdmission) async throws {
        await stop()
        guard permissionProbe.currentStatus(for: .screenRecording).isAvailable else {
            await enrollmentClient.endObservationAdmission(admission)
            throw HelicoidError.permissionDenied(
                detail: "Screen Recording permission is not currently granted. No capture was started."
            )
        }
        guard unlockedConsoleProbe() else {
            await enrollmentClient.endObservationAdmission(admission)
            throw HelicoidError.permissionDenied(
                detail: "The unlocked physical-console state cannot be verified. No capture was started."
            )
        }
        guard await enrollmentClient.observationAdmissionIsCurrent(admission) else {
            await enrollmentClient.endObservationAdmission(admission)
            throw HelicoidError.sessionExpired(
                detail: "The observation lease is expired or no longer belongs to the signed-in console user."
            )
        }

        let remainingMilliseconds = Int64(
            min(10_000, (Double(admission.expiresAtUnix) - Date().timeIntervalSince1970) * 1_000)
        )
        guard remainingMilliseconds > 0 else {
            await enrollmentClient.endObservationAdmission(admission)
            throw HelicoidError.sessionExpired(detail: "The observation lease expired before capture could start.")
        }

        let shareableContent: SCShareableContent
        do {
            shareableContent = try await SCShareableContent.excludingDesktopWindows(
                false,
                onScreenWindowsOnly: true
            )
        } catch {
            await enrollmentClient.endObservationAdmission(admission)
            throw error
        }
        guard let display = shareableContent.displays.first(where: {
            $0.displayID == CGMainDisplayID()
        }) else {
            await enrollmentClient.endObservationAdmission(admission)
            throw HelicoidError.setupBlocked(reason: "The current primary display is unavailable for screen capture.")
        }

        let filter = SCContentFilter(display: display, excludingWindows: [])
        let configuration = SCStreamConfiguration()
        let outputSize = Self.outputSize(width: display.width, height: display.height)
        configuration.width = outputSize.width
        configuration.height = outputSize.height
        configuration.minimumFrameInterval = CMTime(value: 1, timescale: 15)
        configuration.queueDepth = 2
        configuration.pixelFormat = kCVPixelFormatType_32BGRA
        configuration.capturesAudio = false
        configuration.showsCursor = true

        let deadline = ContinuousClock().now.advanced(by: .milliseconds(remainingMilliseconds))
        let permissionProbe = self.permissionProbe
        let unlockedConsoleProbe = self.unlockedConsoleProbe
        let gate = ScreenCaptureGate(
            deadline: deadline,
            ownerMatches: {
                admission.belongsToCurrentConsoleUser() && unlockedConsoleProbe()
            },
            permissionAvailable: {
                permissionProbe.currentStatus(for: .screenRecording).isAvailable
            }
        )
        let output = ScreenCaptureOutput(
            gate: gate,
            onFrame: onFrame,
            onStop: { [weak self] in
                Task { @MainActor [weak self] in
                    await self?.finish(reason: "Screen capture stopped unexpectedly.", stopStream: false)
                }
            }
        )
        let candidate = SCStream(filter: filter, configuration: configuration, delegate: output)
        do {
            try candidate.addStreamOutput(output, type: .screen, sampleHandlerQueue: outputQueue)
        } catch {
            await enrollmentClient.endObservationAdmission(admission)
            throw error
        }
        self.stream = candidate
        self.output = output
        self.gate = gate
        self.admission = admission

        do {
            try await candidate.startCapture()
        } catch {
            await finish(reason: "Screen capture could not start.", stopStream: true)
            throw error
        }
        guard gate.allowsFrame else {
            await finish(reason: "The observation lease expired before the first frame.", stopStream: true)
            throw HelicoidError.sessionExpired(detail: "The observation lease expired before capture could start.")
        }

        monitorTask = Task { @MainActor [weak self, enrollmentClient, permissionProbe, unlockedConsoleProbe, admission, gate] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .milliseconds(250))
                } catch {
                    return
                }
                guard gate.allowsFrame else {
                    await self?.finish(reason: "The observation lease expired.", stopStream: true)
                    return
                }
                guard await enrollmentClient.observationAdmissionIsCurrent(admission) else {
                    await self?.finish(reason: "The signed-in console user or endpoint admission changed.", stopStream: true)
                    return
                }
                guard unlockedConsoleProbe() else {
                    await self?.finish(reason: "The unlocked physical-console state is no longer verified.", stopStream: true)
                    return
                }
                guard permissionProbe.currentStatus(for: .screenRecording).isAvailable else {
                    await self?.finish(reason: "Screen Recording permission is no longer available.", stopStream: true)
                    return
                }
            }
        }
    }

    public func stop() async {
        await finish(reason: nil, stopStream: true)
    }

    private func finish(reason: String?, stopStream: Bool) async {
        gate?.close()
        monitorTask?.cancel()
        monitorTask = nil

        let previousStream = stream
        let previousOutput = output
        stream = nil
        if stopStream, let previousStream {
            do {
                try await previousStream.stopCapture()
            } catch {
                if reason == nil {
                    onStopped("Screen capture did not stop cleanly.")
                }
            }
        }
        if let previousStream, let previousOutput {
            do {
                try previousStream.removeStreamOutput(previousOutput, type: .screen)
            } catch {
                if reason == nil {
                    onStopped("Screen capture output did not detach cleanly.")
                }
            }
        }
        output = nil

        if let admission {
            await enrollmentClient.endObservationAdmission(admission)
        }
        admission = nil
        gate = nil
        if let reason {
            onStopped(reason)
        }
    }

    private static func outputSize(width: Int, height: Int) -> (width: Int, height: Int) {
        let sourceWidth = max(2, width)
        let sourceHeight = max(2, height)
        let scale = min(1.0, 1_280.0 / Double(sourceWidth), 720.0 / Double(sourceHeight))
        let outputWidth = max(2, Int(Double(sourceWidth) * scale) & ~1)
        let outputHeight = max(2, Int(Double(sourceHeight) * scale) & ~1)
        return (outputWidth, outputHeight)
    }
}

final class ScreenCaptureGate: @unchecked Sendable {
    private let lock = NSLock()
    private let deadline: ContinuousClock.Instant
    private let ownerMatches: @Sendable () -> Bool
    private let permissionAvailable: @Sendable () -> Bool
    nonisolated(unsafe) private var isOpen = true

    nonisolated init(
        deadline: ContinuousClock.Instant,
        ownerMatches: @escaping @Sendable () -> Bool,
        permissionAvailable: @escaping @Sendable () -> Bool
    ) {
        self.deadline = deadline
        self.ownerMatches = ownerMatches
        self.permissionAvailable = permissionAvailable
    }

    nonisolated var allowsFrame: Bool {
        guard permissionFactsAreCurrent, ContinuousClock().now < deadline else {
            return false
        }
        lock.lock()
        let currentlyOpen = isOpen && ContinuousClock().now < deadline
        lock.unlock()
        return currentlyOpen
    }

    /// Serialize an admitted callback with close. Once close returns, no
    /// callback that passed the earlier permission probe can still deliver a
    /// frame, and no later callback can enter.
    @discardableResult
    nonisolated func deliverIfAuthorized(_ deliver: () -> Void) -> Bool {
        guard permissionFactsAreCurrent, ContinuousClock().now < deadline else {
            return false
        }
        lock.lock()
        defer { lock.unlock() }
        guard isOpen, ContinuousClock().now < deadline else { return false }
        deliver()
        return true
    }

    nonisolated func close() {
        lock.lock()
        isOpen = false
        lock.unlock()
    }

    private nonisolated var permissionFactsAreCurrent: Bool {
        ownerMatches() && permissionAvailable()
    }
}

private final class ScreenCaptureOutput: NSObject, SCStreamOutput, SCStreamDelegate, @unchecked Sendable {
    private let gate: ScreenCaptureGate
    private let onFrame: @Sendable (ScreenObservationFrame) -> Void
    private let onStop: @Sendable () -> Void

    init(
        gate: ScreenCaptureGate,
        onFrame: @escaping @Sendable (ScreenObservationFrame) -> Void,
        onStop: @escaping @Sendable () -> Void
    ) {
        self.gate = gate
        self.onFrame = onFrame
        self.onStop = onStop
    }

    func stream(
        _ stream: SCStream,
        didOutputSampleBuffer sampleBuffer: CMSampleBuffer,
        of outputType: SCStreamOutputType
    ) {
        guard outputType == .screen,
              CMSampleBufferIsValid(sampleBuffer),
              let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer),
              CVPixelBufferGetPixelFormatType(pixelBuffer) == kCVPixelFormatType_32BGRA,
              Self.hasSupportedLayout(pixelBuffer) else {
            return
        }
        _ = gate.deliverIfAuthorized {
            onFrame(ScreenObservationFrame(
                pixelBuffer: pixelBuffer,
                presentationTime: CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
            ))
        }
    }

    private static func hasSupportedLayout(_ pixelBuffer: CVPixelBuffer) -> Bool {
        let width = CVPixelBufferGetWidth(pixelBuffer)
        let height = CVPixelBufferGetHeight(pixelBuffer)
        let strideBytes = CVPixelBufferGetBytesPerRow(pixelBuffer)
        guard width >= 2, width <= 1_280, height >= 2, height <= 720 else {
            return false
        }

        let (minimumStrideBytes, strideOverflow) = width.multipliedReportingOverflow(by: 4)
        let (requiredBytes, sizeOverflow) = strideBytes.multipliedReportingOverflow(by: height)
        return !strideOverflow && !sizeOverflow &&
            strideBytes >= minimumStrideBytes &&
            requiredBytes <= 1_280 * 720 * 4 &&
            CVPixelBufferGetDataSize(pixelBuffer) >= requiredBytes
    }

    func stream(_ stream: SCStream, didStopWithError error: any Error) {
        gate.close()
        onStop()
    }
}
