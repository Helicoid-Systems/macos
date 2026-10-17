import Foundation
import Testing
@testable import HelicoidComputer

/// Injected probe seam. Never prompts and never reads live TCC.
/// Scripted statuses stand in for native results so lifecycle/policy cases stay deterministic.
final class ScriptedPermissionProbe: ComputerPermissionProbing, @unchecked Sendable {
    struct Calls: Sendable {
        var statusKinds: [ComputerPermissionKind] = []
        var requestKinds: [ComputerPermissionKind] = []
        var openSettingsKinds: [ComputerPermissionKind] = []
    }

    private let lock = NSLock()
    private var _statuses: [ComputerPermissionKind: ComputerPermissionStatus]
    private var _postRequestStatuses: [ComputerPermissionKind: ComputerPermissionStatus]
    private var _calls = Calls()

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
