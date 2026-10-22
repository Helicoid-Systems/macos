import Dispatch
import Foundation
import Testing
@testable import HelicoidComputer

private func waitForSemaphore(
    _ semaphore: DispatchSemaphore,
    timeout: TimeInterval
) -> DispatchTimeoutResult {
    semaphore.wait(timeout: .now() + timeout)
}

/// Injected probe seam. Never prompts and never reads live TCC.
/// Scripted statuses stand in for native results so lifecycle/policy cases stay deterministic.
final class ScriptedPermissionProbe: ComputerPermissionProbing, @unchecked Sendable {
    struct Calls: Sendable {
        var statusKinds: [ComputerPermissionKind] = []
        var requestKinds: [ComputerPermissionKind] = []
        var openSettingsKinds: [ComputerPermissionKind] = []
    }

    private let lock = NSLock()
    nonisolated(unsafe) private var _statuses: [ComputerPermissionKind: ComputerPermissionStatus]
    private var _postRequestStatuses: [ComputerPermissionKind: ComputerPermissionStatus]
    nonisolated(unsafe) private var _calls = Calls()

    init(
        statuses: [ComputerPermissionKind: ComputerPermissionStatus],
        postRequestStatuses: [ComputerPermissionKind: ComputerPermissionStatus] = [:]
    ) {
        _statuses = statuses
        _postRequestStatuses = postRequestStatuses
    }

    var calls: Calls {
        lock.lock()
        defer { lock.unlock() }
        return _calls
    }

    func setStatus(_ status: ComputerPermissionStatus, for kind: ComputerPermissionKind) {
        lock.lock()
        defer { lock.unlock() }
        _statuses[kind] = status
    }

    func currentStatus(for kind: ComputerPermissionKind) -> ComputerPermissionStatus {
        lock.lock()
        defer { lock.unlock() }
        _calls.statusKinds.append(kind)
        return _statuses[kind] ?? .unknown
    }

    func requestAccess(for kind: ComputerPermissionKind) {
        lock.lock()
        defer { lock.unlock() }
        _calls.requestKinds.append(kind)
        if let next = _postRequestStatuses[kind] {
            _statuses[kind] = next
        }
    }

    func openSystemSettings(for kind: ComputerPermissionKind) {
        lock.lock()
        defer { lock.unlock() }
        _calls.openSettingsKinds.append(kind)
    }
}

@Suite("Computer permission readiness policy")
@MainActor
struct ComputerPermissionPolicyTests {
    @Test("Ambiguous controller status never claims multiple controllers")
    func ambiguousControllerStatusIsUnavailable() {
        let state = ComputerStatusModel.ScreenAccess.controlled(operators: ["Morgan", "Alex"])
        #expect(state.headline == "Control Status Unavailable")
    }

    @Test("Granted is available; missing and unknown are unavailable")
    func statusAvailabilityDistinguishesGrantedMissingUnknown() {
        #expect(ComputerPermissionStatus.granted.isAvailable)
        #expect(!ComputerPermissionStatus.missing.isAvailable)
        #expect(!ComputerPermissionStatus.unknown.isAvailable)

        let probe = ScriptedPermissionProbe(statuses: [
            .screenRecording: .granted,
            .accessibility: .missing,
        ])
        let model = ComputerStatusModel(permissionProbe: probe)
        #expect(model.permissionStatus(for: .screenRecording) == .unknown)
        #expect(model.permissionStatus(for: .accessibility) == .unknown)

        model.refreshPermissions()
        #expect(model.permissionStatus(for: .screenRecording) == .granted)
        #expect(model.permissionStatus(for: .accessibility) == .missing)

        probe.setStatus(.unknown, for: .screenRecording)
        model.refreshPermissions()
        #expect(model.permissionStatus(for: .screenRecording) == .unknown)
        #expect(!model.permissionStatus(for: .screenRecording).isAvailable)
    }

    @Test("Permission grants alone never mark connected, observed, or controlled")
    func grantsAloneDoNotImplyAccess() {
        let probe = ScriptedPermissionProbe(statuses: [
            .screenRecording: .granted,
            .accessibility: .granted,
        ])
        let model = ComputerStatusModel(permissionProbe: probe)
        model.refreshPermissions()

        #expect(model.screenRecordingPermission == .granted)
        #expect(model.accessibilityPermission == .granted)
        #expect(model.connection == .notConfigured)
        #expect(model.screenAccess == .none)
        #expect(!model.isHelpAvailable)
        if case .observed = model.screenAccess {
            Issue.record("grants must not create observed access")
        }
        if case .controlled = model.screenAccess {
            Issue.record("grants must not create controlled access")
        }
        if case .connected = model.connection {
            Issue.record("grants must not create a connection")
        }
    }

    @Test("Fixtures use labeled synthetic probe and do not supply live permission facts")
    func fixturesDoNotSupplyLivePermissionFacts() {
        let model = ComputerDevelopmentFixtures.model()
        #expect(model.isFixturesMode)
        #expect(model.screenRecordingPermission == .missing)
        #expect(model.accessibilityPermission == .missing)
        #expect(!model.screenRecordingPermission.isAvailable)
        #expect(!ComputerFixturePermissionProbe.banner.isEmpty)
    }

    @Test("Help is unsupported in normal builds even when merely connected")
    func helpUnsupportedWhenMerelyConnected() {
        let probe = ScriptedPermissionProbe(statuses: [
            .screenRecording: .granted,
            .accessibility: .granted,
        ])
        let model = ComputerStatusModel(connection: .connected, permissionProbe: probe)
        #expect(!model.isHelpAvailable)
        model.requestHelp()
        #expect(model.helpRequestState == .idle)
        model.cancelHelpRequest()
        #expect(model.helpRequestState == .idle)
    }
}

@Suite("Computer permission lifecycle")
@MainActor
struct ComputerPermissionLifecycleTests {
    @Test("Startup refresh queries native probe without requesting")
    func startupRefreshDoesNotRequest() {
        let probe = ScriptedPermissionProbe(statuses: [
            .screenRecording: .missing,
            .accessibility: .granted,
        ])
        let model = ComputerStatusModel(permissionProbe: probe)
        model.refreshPermissions()

        #expect(probe.calls.statusKinds == [.screenRecording, .accessibility])
        #expect(probe.calls.requestKinds.isEmpty)
        #expect(probe.calls.openSettingsKinds.isEmpty)
    }

    @Test("Stale granted is replaced when a later query reports revoked")
    func staleGrantedReplacedOnRevoke() {
        let probe = ScriptedPermissionProbe(statuses: [
            .screenRecording: .granted,
            .accessibility: .granted,
        ])
        let model = ComputerStatusModel(permissionProbe: probe)
        model.refreshPermissions()
        #expect(model.screenRecordingPermission == .granted)

        probe.setStatus(.missing, for: .screenRecording)
        probe.setStatus(.unknown, for: .accessibility)
        model.refreshPermissions()

        #expect(model.screenRecordingPermission == .missing)
        #expect(model.accessibilityPermission == .unknown)
        #expect(!model.screenRecordingPermission.isAvailable)
        #expect(!model.accessibilityPermission.isAvailable)
    }

    @Test("Request is the only prompt path; status updates only after a fresh query")
    func requestThenFreshQueryRetainsUnavailableUntilConfirmed() {
        // Request does not flip status by itself; post-request query still missing.
        let staysMissing = ScriptedPermissionProbe(
            statuses: [.screenRecording: .missing, .accessibility: .missing],
            postRequestStatuses: [.screenRecording: .missing]
        )
        let model = ComputerStatusModel(permissionProbe: staysMissing)
        model.refreshPermissions()
        model.requestPermission(.screenRecording)

        #expect(staysMissing.calls.requestKinds == [.screenRecording])
        #expect(model.screenRecordingPermission == .missing)

        // Fresh query after grant confirms and replaces unavailable.
        let confirms = ScriptedPermissionProbe(
            statuses: [.screenRecording: .missing, .accessibility: .missing],
            postRequestStatuses: [.screenRecording: .granted]
        )
        let confirmedModel = ComputerStatusModel(permissionProbe: confirms)
        confirmedModel.refreshPermissions()
        #expect(confirmedModel.screenRecordingPermission == .missing)
        confirmedModel.requestPermission(.screenRecording)
        #expect(confirmedModel.screenRecordingPermission == .granted)
    }

    @Test("Open Settings is user-driven and does not change status")
    func openSettingsDoesNotMutateStatus() {
        let probe = ScriptedPermissionProbe(statuses: [
            .screenRecording: .missing,
            .accessibility: .missing,
        ])
        let model = ComputerStatusModel(permissionProbe: probe)
        model.refreshPermissions()
        model.openPermissionSettings(.accessibility)

        #expect(probe.calls.openSettingsKinds == [.accessibility])
        #expect(probe.calls.requestKinds.isEmpty)
        #expect(model.accessibilityPermission == .missing)
    }

    @Test("Reactivation-style refresh is non-prompting and re-reads both kinds")
    func reactivationRefreshIsNonPrompting() {
        let probe = ScriptedPermissionProbe(statuses: [
            .screenRecording: .granted,
            .accessibility: .missing,
        ])
        let model = ComputerStatusModel(permissionProbe: probe)
        model.refreshPermissions()
        probe.setStatus(.missing, for: .screenRecording)
        model.refreshPermissions()

        #expect(probe.calls.statusKinds == [
            .screenRecording, .accessibility,
            .screenRecording, .accessibility,
        ])
        #expect(probe.calls.requestKinds.isEmpty)
        #expect(model.screenRecordingPermission == .missing)
        #expect(model.accessibilityPermission == .missing)
    }
}

@Suite("Computer permission row action")
@MainActor
struct ComputerPermissionRowActionTests {
    @Test("First permission action prompts only once; later ungranted action opens Settings")
    func firstActionPromptsOnceThenOpensSettings() {
        let probe = ScriptedPermissionProbe(
            statuses: [.screenRecording: .missing, .accessibility: .missing],
            postRequestStatuses: [.screenRecording: .missing]
        )
        let model = ComputerStatusModel(permissionProbe: probe)
        model.refreshPermissions()

        #expect(model.permissionRowAction(for: .screenRecording) == .allow)
        model.performPermissionRowAction(.screenRecording)

        #expect(probe.calls.requestKinds == [.screenRecording])
        #expect(probe.calls.openSettingsKinds.isEmpty)
        #expect(model.permissionRowAction(for: .screenRecording) == .openSettings)

        model.performPermissionRowAction(.screenRecording)

        #expect(probe.calls.requestKinds == [.screenRecording])
        #expect(probe.calls.openSettingsKinds == [.screenRecording])
    }

    @Test("Open Settings path rechecks and reflects a later grant or revoke")
    func openSettingsPathRechecksActualStatus() {
        let probe = ScriptedPermissionProbe(
            statuses: [.screenRecording: .missing, .accessibility: .missing],
            postRequestStatuses: [.screenRecording: .missing]
        )
        let model = ComputerStatusModel(permissionProbe: probe)
        model.refreshPermissions()
        model.performPermissionRowAction(.screenRecording)

        probe.setStatus(.granted, for: .screenRecording)
        model.performPermissionRowAction(.screenRecording)
        #expect(probe.calls.openSettingsKinds == [.screenRecording])
        #expect(model.screenRecordingPermission == .granted)
        #expect(model.permissionRowAction(for: .screenRecording) == .none)

        probe.setStatus(.missing, for: .screenRecording)
        model.refreshPermissions()
        #expect(model.screenRecordingPermission == .missing)
        #expect(model.permissionRowAction(for: .screenRecording) == .openSettings)
    }

    @Test("Two permission kinds are independent")
    func permissionKindsAreIndependent() {
        let probe = ScriptedPermissionProbe(
            statuses: [.screenRecording: .missing, .accessibility: .missing],
            postRequestStatuses: [.screenRecording: .missing]
        )
        let model = ComputerStatusModel(permissionProbe: probe)
        model.refreshPermissions()

        model.performPermissionRowAction(.screenRecording)

        #expect(probe.calls.requestKinds == [.screenRecording])
        #expect(model.permissionRowAction(for: .accessibility) == .allow)
        #expect(model.permissionRowAction(for: .screenRecording) == .openSettings)

        model.performPermissionRowAction(.accessibility)
        #expect(probe.calls.requestKinds == [.screenRecording, .accessibility])
    }

    @Test("Native recheck confirms granted and revoked without implying access")
    func recheckConfirmsGrantedAndRevoked() {
        let probe = ScriptedPermissionProbe(
            statuses: [.screenRecording: .missing, .accessibility: .granted],
            postRequestStatuses: [.screenRecording: .granted]
        )
        let model = ComputerStatusModel(
            connection: .connected,
            screenAccess: .none,
            permissionProbe: probe
        )
        model.refreshPermissions()
        model.performPermissionRowAction(.screenRecording)

        #expect(model.screenRecordingPermission == .granted)
        #expect(model.accessibilityPermission == .granted)
        #expect(model.connection == .connected)
        #expect(model.screenAccess == .none)

        probe.setStatus(.missing, for: .screenRecording)
        model.refreshPermissions()
        #expect(model.screenRecordingPermission == .missing)
        #expect(model.screenAccess == .none)
        #expect(model.connection == .connected)
    }
}

@Suite("Screen capture teardown fence")
struct ScreenCaptureGateTests {
    @Test("Closing waits for an in-flight frame callback and blocks later delivery")
    func closeSerializesWithFrameDelivery() async {
        let gate = ScreenCaptureGate(
            deadline: ContinuousClock().now.advanced(by: .seconds(10)),
            ownerMatches: { true },
            permissionAvailable: { true }
        )
        let callbackEntered = DispatchSemaphore(value: 0)
        let finishCallback = DispatchSemaphore(value: 0)
        let delivery = Task.detached {
            gate.deliverIfAuthorized {
                callbackEntered.signal()
                _ = waitForSemaphore(finishCallback, timeout: 2)
            }
        }

        #expect(waitForSemaphore(callbackEntered, timeout: 1) == .success)

        let closeStarted = DispatchSemaphore(value: 0)
        let closeReturned = DispatchSemaphore(value: 0)
        let closing = Task.detached {
            closeStarted.signal()
            gate.close()
            closeReturned.signal()
        }
        #expect(waitForSemaphore(closeStarted, timeout: 1) == .success)
        #expect(waitForSemaphore(closeReturned, timeout: 0.05) == .timedOut)

        finishCallback.signal()
        #expect(await delivery.value)
        #expect(waitForSemaphore(closeReturned, timeout: 1) == .success)
        await closing.value

        var laterCallbackRan = false
        #expect(!gate.deliverIfAuthorized { laterCallbackRan = true })
        #expect(!laterCallbackRan)
    }
}
