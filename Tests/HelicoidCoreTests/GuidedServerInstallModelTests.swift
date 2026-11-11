import Foundation
import Testing
@testable import HelicoidCore

@Suite("Guided local server install")
struct GuidedServerInstallModelTests {
    @Test("A complete install reports installed, never ready without server evidence")
    @MainActor
    func completeInstallIsHonest() async throws {
        let applied = try ServerInstallTestSupport.operationStatus(
            state: "completed",
            serviceInstalled: true,
            bootstrapReady: false,
            readyForEnrollment: false)
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: applied,
            status: applied,
            cancel: try ServerInstallTestSupport.operationStatus(state: "cancelled", serviceInstalled: false))
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)

        #expect(model.phase == .install)
        #expect(model.installPackageAvailable)
        #expect(model.installAction == .start)

        await model.startInstallation()

        if case .installedUnverified(let summary) = model.installProgress {
            #expect(summary.contains("not verified"))
        } else {
            Issue.record("Expected an installed-but-unverified result, got \(model.installProgress)")
        }
        #expect(model.phase == .install)
        #expect(!model.isServerReadyForEnrollment)
        #expect(model.installStatusSummary?.contains("Service installed: yes") == true)
        #expect(model.installStatusSummary?.contains("Ready for enrollment: no") == true)
        #expect(model.installAction == .refreshStatus)
        model.advance()
        #expect(model.phase == .install)
        #expect(model.blocker?.contains("does not report server readiness") == true)
        #expect(!model.isServerReadyForEnrollment)

        let calls = await service.recordedCalls()
        #expect(calls.contains("availability"))
        #expect(calls.contains("capabilities"))
        #expect(calls.contains("preflight"))
        #expect(calls.contains("plan"))
        #expect(calls.contains("apply"))
    }

    @Test("Server-reported readiness is the only way to reach Ready")
    @MainActor
    func serverReadinessIsRequiredForReady() async throws {
        let applied = try ServerInstallTestSupport.operationStatus(
            state: "completed",
            serviceInstalled: true,
            bootstrapReady: true,
            readyForEnrollment: true)
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: applied,
            status: applied,
            cancel: applied)
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)
        await model.startInstallation()
        #expect(!model.isServerReadyForEnrollment)

        model.advance()
        #expect(model.phase == .ready)
        #expect(model.isServerReadyForEnrollment)
    }

    @Test("Development package provisions TLS before plan and remains clearly labeled")
    @MainActor
    func developmentPackageProvisionsTLS() async throws {
        let applied = try ServerInstallTestSupport.operationStatus(
            state: "completed",
            serviceInstalled: true,
            readyForEnrollment: false)
        let service = FakeInstallService(
            installPayloadKind: .development,
            package: .testFixture(provenance: .development),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: applied,
            status: applied,
            cancel: applied)
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)

        #expect(model.isDevelopmentInstall)
        #expect(model.installPayloadKind == .development)
        await model.startInstallation()

        let calls = await service.recordedCalls()
        guard let provisionIndex = calls.firstIndex(of: "provisionTLS"),
              let planIndex = calls.firstIndex(of: "plan"),
              let applyIndex = calls.firstIndex(of: "apply") else {
            Issue.record("Expected TLS provisioning, plan, and apply calls: \(calls)")
            return
        }
        #expect(provisionIndex < planIndex)
        #expect(provisionIndex < applyIndex)
        guard case .installedUnverified = model.installProgress else {
            Issue.record("Expected installed-unverified, got \(model.installProgress)")
            return
        }
        #expect(!model.isServerReadyForEnrollment)
    }

    @Test("Development TLS failure stops before plan and apply")
    @MainActor
    func developmentTLSFailureStopsInstall() async throws {
        let service = FakeInstallService(
            installPayloadKind: .development,
            package: .testFixture(provenance: .development),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: try ServerInstallTestSupport.operationStatus(),
            status: try ServerInstallTestSupport.operationStatus(),
            cancel: try ServerInstallTestSupport.operationStatus(),
            tlsProvisionError: .developmentTLSProvisioningFailed("test failure"))
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)
        await model.startInstallation()

        guard case .failed(let reason) = model.installProgress else {
            Issue.record("Expected failed TLS provisioning, got \(model.installProgress)")
            return
        }
        #expect(reason.contains("test failure"))
        let calls = await service.recordedCalls()
        #expect(calls.contains("provisionTLS"))
        #expect(!calls.contains("plan"))
        #expect(!calls.contains("apply"))
    }

    @Test("A helper build without the install capability is refused before any privileged call")
    @MainActor
    func capabilitiesGateStopsInstall() async throws {
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(
                actions: ["preflight", "plan"],
                reasons: ["macos_launchd": "macOS install capability is gated off: no independently trusted release root"]),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: try ServerInstallTestSupport.operationStatus(),
            status: try ServerInstallTestSupport.operationStatus(),
            cancel: try ServerInstallTestSupport.operationStatus())
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)

        await model.startInstallation()

        if case .refused(let reason) = model.installProgress {
            #expect(reason.contains("trusted release root"))
        } else {
            Issue.record("Expected a capability refusal, got \(model.installProgress)")
        }
        #expect(model.blocker?.contains("trusted release root") == true)
        let calls = await service.recordedCalls()
        #expect(!calls.contains("preflight"))
        #expect(!calls.contains("plan"))
        #expect(!calls.contains("apply"))
    }

    @Test("An unavailable package stops before capabilities")
    @MainActor
    func unavailablePackageStopsInstall() async throws {
        let service = FakeInstallService(
            package: .testFixture(),
            availability: .unavailable(reason: "No signed package is present."),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: try ServerInstallTestSupport.operationStatus(),
            status: try ServerInstallTestSupport.operationStatus(),
            cancel: try ServerInstallTestSupport.operationStatus())
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)

        await model.startInstallation()

        if case .refused(let reason) = model.installProgress {
            #expect(reason.contains("No signed package"))
        } else {
            Issue.record("Expected a package refusal, got \(model.installProgress)")
        }
        let calls = await service.recordedCalls()
        #expect(!calls.isEmpty)
        #expect(calls.allSatisfy { $0 == "availability" })
    }

    @Test("Failed preflight never reaches plan or apply")
    @MainActor
    func failedPreflightStopsInstall() async throws {
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(ok: false),
            plan: try ServerInstallTestSupport.planResult(),
            apply: try ServerInstallTestSupport.operationStatus(),
            status: try ServerInstallTestSupport.operationStatus(),
            cancel: try ServerInstallTestSupport.operationStatus())
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)

        await model.startInstallation()

        guard case .failed = model.installProgress else {
            Issue.record("Expected a failed preflight state, got \(model.installProgress)")
            return
        }
        let calls = await service.recordedCalls()
        #expect(!calls.contains("plan"))
        #expect(!calls.contains("apply"))
        #expect(!model.isServerReadyForEnrollment)
    }

    @Test("A refused plan never reaches apply")
    @MainActor
    func refusedPlanStopsInstall() async throws {
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(ok: false, error: "operator TLS material is missing"),
            apply: try ServerInstallTestSupport.operationStatus(),
            status: try ServerInstallTestSupport.operationStatus(),
            cancel: try ServerInstallTestSupport.operationStatus())
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)

        await model.startInstallation()

        guard case .failed(let reason) = model.installProgress else {
            Issue.record("Expected a failed plan state, got \(model.installProgress)")
            return
        }
        #expect(reason.contains("operator TLS material"))
        let calls = await service.recordedCalls()
        #expect(!calls.contains("apply"))
    }

    @Test("A dismissed authorization prompt is a cancellation, not an install")
    @MainActor
    func authorizationCancellationIsHonest() async throws {
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: try ServerInstallTestSupport.operationStatus(),
            status: try ServerInstallTestSupport.operationStatus(),
            cancel: try ServerInstallTestSupport.operationStatus(),
            applyError: .authorizationCancelled)
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)

        await model.startInstallation()

        guard case .cancelled(let reason) = model.installProgress else {
            Issue.record("Expected cancellation, got \(model.installProgress)")
            return
        }
        #expect(reason.contains("authorization was cancelled"))
        #expect(!model.isServerReadyForEnrollment)
        #expect(model.installStatusSummary == nil)
    }

    @Test("A lost helper response is an unknown outcome")
    @MainActor
    func postDispatchFailureIsUnknown() async throws {
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: try ServerInstallTestSupport.operationStatus(),
            status: try ServerInstallTestSupport.operationStatus(),
            cancel: try ServerInstallTestSupport.operationStatus(),
            applyError: .invalidResponse("helper response was lost"))
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)

        await model.startInstallation()

        guard case .outcomeUnknown(let reason) = model.installProgress else {
            Issue.record("Expected an unknown outcome, got \(model.installProgress)")
            return
        }
        #expect(reason.contains("Refresh status"))
        #expect(model.installAction == .refreshStatus)
        #expect(!model.isServerReadyForEnrollment)
        #expect(model.installStatusSummary == nil)
    }

    @Test("An apply timeout is an unknown outcome, never a success")
    @MainActor
    func applyTimeoutIsUnknown() async throws {
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: try ServerInstallTestSupport.operationStatus(),
            status: try ServerInstallTestSupport.operationStatus(),
            cancel: try ServerInstallTestSupport.operationStatus(),
            applyError: .timedOut)
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)

        await model.startInstallation()

        guard case .outcomeUnknown(let reason) = model.installProgress else {
            Issue.record("Expected an unknown outcome, got \(model.installProgress)")
            return
        }
        #expect(reason.contains("time limit"))
        #expect(!model.isServerReadyForEnrollment)
    }

    @Test("Cancellation rollback uses the recorded operation identity")
    @MainActor
    func rollbackUsesOperationIdentity() async throws {
        let attention = try ServerInstallTestSupport.operationStatus(
            state: "attention_required",
            serviceInstalled: false,
            cancellationAvailable: true,
            operationId: "operation-42")
        let cancelled = try ServerInstallTestSupport.operationStatus(
            state: "cancelled",
            serviceInstalled: false,
            cancellationAvailable: false,
            operationId: "operation-42")
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: attention,
            status: attention,
            cancel: cancelled)
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)
        await model.startInstallation()

        guard case .attentionRequired = model.installProgress else {
            Issue.record("Expected attention-required state, got \(model.installProgress)")
            return
        }
        #expect(model.canCancelInstallation)

        await model.cancelInstallation()

        guard case .cancelled = model.installProgress else {
            Issue.record("Expected rollback cancellation, got \(model.installProgress)")
            return
        }
        let cancellationOperationId = await service.recordedCancellationOperationId()
        #expect(cancellationOperationId == "operation-42")
        #expect(!model.isServerReadyForEnrollment)
    }

    @Test("Status and cancel reuse the exact reviewed apply configuration after UI edits")
    @MainActor
    func statusAndCancelReuseAppliedConfiguration() async throws {
        let attention = try ServerInstallTestSupport.operationStatus(
            state: "attention_required",
            serviceInstalled: false,
            cancellationAvailable: true,
            operationId: "operation-config")
        let cancelled = try ServerInstallTestSupport.operationStatus(
            state: "cancelled",
            serviceInstalled: false,
            operationId: "operation-config")
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: attention,
            status: attention,
            cancel: cancelled)
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)
        let reviewed = try #require(model.reviewedInstallConfiguration)
        await model.startInstallation()
        #expect(model.installOperationConfiguration == reviewed)

        // UI edits after apply must not alter the operation configuration used
        // for status/cancel.
        model.setProductPort("8999")
        model.setBackupDestination("/private/tmp/edited-backups")
        await model.refreshInstallStatus()
        let statusConfigurations = await service.recordedStatusConfigurations()
        #expect(statusConfigurations.last == reviewed)

        await model.cancelInstallation()
        let cancelConfigurations = await service.recordedCancelConfigurations()
        #expect(cancelConfigurations.last == reviewed)
        #expect(model.installOperationConfiguration == reviewed)
    }

    @Test("A failed status refresh keeps the operation identity and configuration")
    @MainActor
    func failedStatusRefreshKeepsOperation() async throws {
        let attention = try ServerInstallTestSupport.operationStatus(
            state: "attention_required",
            serviceInstalled: false,
            cancellationAvailable: true,
            operationId: "operation-retain")
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: attention,
            status: attention,
            cancel: try ServerInstallTestSupport.operationStatus(state: "cancelled", serviceInstalled: false),
            statusError: .timedOut)
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)
        let reviewed = try #require(model.reviewedInstallConfiguration)
        await model.startInstallation()
        #expect(model.installStatus != nil)
        #expect(model.canCancelInstallation)

        await model.refreshInstallStatus()

        #expect(model.installStatus != nil)
        #expect(model.installOperationConfiguration == reviewed)
        #expect(model.canCancelInstallation)
        guard case .attentionRequired = model.installProgress else {
            Issue.record("Expected attention-required after failed refresh, got \(model.installProgress)")
            return
        }
    }

    @Test("Returned helper refusal is a failure, not an unknown outcome")
    @MainActor
    func returnedHelperRefusalIsFailure() async throws {
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: try ServerInstallTestSupport.operationStatus(),
            status: try ServerInstallTestSupport.operationStatus(),
            cancel: try ServerInstallTestSupport.operationStatus(),
            applyError: .returnedRefusal("staged helper bytes changed"))
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)
        await model.startInstallation()
        guard case .failed(let reason) = model.installProgress else {
            Issue.record("Expected a returned refusal failure, got \(model.installProgress)")
            return
        }
        #expect(reason.contains("staged helper"))
    }

    @Test("A normal helper exit is a returned failure; a signal exit is unknown")
    @MainActor
    func helperExitClassification() async throws {
        for (status, expectedFailed) in [(Int32(2), true), (Int32(137), false)] {
            let service = FakeInstallService(
                package: .testFixture(),
                capabilities: try ServerInstallTestSupport.capabilities(),
                preflight: try ServerInstallTestSupport.preflight(),
                plan: try ServerInstallTestSupport.planResult(),
                apply: try ServerInstallTestSupport.operationStatus(),
                status: try ServerInstallTestSupport.operationStatus(),
                cancel: try ServerInstallTestSupport.operationStatus(),
                applyError: .helperFailed(status: status, detail: "test"))
            let model = makeGuidedInstallModel(service: service)
            advanceToInstall(model)
            await model.startInstallation()
            if expectedFailed {
                guard case .failed = model.installProgress else {
                    Issue.record("Expected failed for helper exit \(status), got \(model.installProgress)")
                    continue
                }
            } else {
                guard case .outcomeUnknown = model.installProgress else {
                    Issue.record("Expected unknown for helper exit \(status), got \(model.installProgress)")
                    continue
                }
            }
        }
    }

    @Test("Privileged TLS timeout after dispatch is an unknown outcome")
    @MainActor
    func privilegedTLSTimeoutIsUnknown() async throws {
        let service = FakeInstallService(
            installPayloadKind: .development,
            package: .testFixture(provenance: .development),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: try ServerInstallTestSupport.operationStatus(),
            status: try ServerInstallTestSupport.operationStatus(),
            cancel: try ServerInstallTestSupport.operationStatus(),
            tlsProvisionError: .privilegedOutcomeUnknown("TLS dispatch outcome unknown"))
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)
        await model.startInstallation()
        guard case .outcomeUnknown(let reason) = model.installProgress else {
            Issue.record("Expected unknown TLS outcome, got \(model.installProgress)")
            return
        }
        #expect(reason.contains("TLS dispatch"))
        let calls = await service.recordedCalls()
        #expect(!calls.contains("plan"))
        #expect(!calls.contains("apply"))
    }

    @Test("Existing unverified TLS is reported without claiming it was generated")
    @MainActor
    func existingTLSIsReported() async throws {
        let applied = try ServerInstallTestSupport.operationStatus(
            state: "completed",
            serviceInstalled: true,
            readyForEnrollment: false)
        let service = FakeInstallService(
            installPayloadKind: .development,
            package: .testFixture(provenance: .development),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: applied,
            status: applied,
            cancel: applied,
            tlsProvisionResult: .existingUnverifiedMaterial)
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)
        await model.startInstallation()
        #expect(model.developmentTLSNotice?.contains("not modified") == true)
        guard case .installedUnverified = model.installProgress else {
            Issue.record("Expected installed-unverified, got \(model.installProgress)")
            return
        }
    }

    @Test("Review shows the exact apply configuration and no installed-name claim")
    @MainActor
    func reviewUsesExactConfiguration() async throws {
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: try ServerInstallTestSupport.operationStatus(),
            status: try ServerInstallTestSupport.operationStatus(),
            cancel: try ServerInstallTestSupport.operationStatus())
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)
        model.back()
        #expect(model.phase == .review)

        let lines = model.reviewChanges().joined(separator: "\n")
        #expect(lines.contains("Deployment kind: macos_launchd"))
        #expect(lines.contains("Network: loopback_development, literal 127.0.0.1:8920"))
        #expect(lines.contains("Data directory: /Library/Application Support/Helicoid/Data"))
        #expect(lines.contains("Backup directory: /private/tmp/helicoid-test-backups"))
        #expect(lines.contains("Deployment display name: Test server (not created or installed"))
        #expect(lines.contains("First administrator: admin (not created by this local installer"))
        #expect(!lines.contains("Deployment name: Test server"))
    }

    @Test("Status refresh reports an installed service without inventing readiness")
    @MainActor
    func statusRefreshIsReadOnly() async throws {
        let installed = try ServerInstallTestSupport.operationStatus(
            state: "completed",
            serviceInstalled: true,
            readyForEnrollment: false,
            operationId: "operation-7")
        let service = FakeInstallService(
            package: .testFixture(),
            capabilities: try ServerInstallTestSupport.capabilities(),
            preflight: try ServerInstallTestSupport.preflight(),
            plan: try ServerInstallTestSupport.planResult(),
            apply: installed,
            status: installed,
            cancel: installed)
        let model = makeGuidedInstallModel(service: service)
        advanceToInstall(model)
        await model.startInstallation()

        await model.refreshInstallStatus()

        #expect(model.installStatusSummary?.contains("Service installed: yes") == true)
        #expect(!model.isServerReadyForEnrollment)
        #expect(model.phase == .install)
        let calls = await service.recordedCalls()
        #expect(calls.contains("status"))
    }
}
