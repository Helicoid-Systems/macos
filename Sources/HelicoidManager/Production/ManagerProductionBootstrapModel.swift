import Foundation
import HelicoidCore
import Observation

struct PreparedProductionTrust: Sendable {
    let tlsIdentity: DeploymentTLSIdentity
    let signingIdentity: ManagerSigningIdentity
    let checkpoint: DeploymentAuthorityCheckpoint
    let record: ManagerAuthorityTrustRecord
}

private struct BootstrapTrustSnapshot: Sendable {
    let modelDeploymentID: String?
    let formDeploymentID: String
    let modelRecord: ManagerAuthorityTrustRecord?
    let formRecord: ManagerAuthorityTrustRecord?
}

private struct BootstrapStateChanged: Error, Sendable {}

private struct BootstrapCommitResult: Sendable {
    let record: ManagerAuthorityTrustRecord
}

private enum BootstrapResetExpectation: Sendable {
    case record(ManagerAuthorityTrustRecord?)
    case unreadable(rawBytes: Data)
}

nonisolated private func bootstrapMessage(for error: any Error) -> String {
    if let error = error as? HelicoidError {
        return error.explanation
    }
    return error.localizedDescription
}

private func bootstrapConfiguration(
    from record: ManagerAuthorityTrustRecord
) throws -> ManagerProductionTrustConfiguration {
    try record.boundConfiguration()
}

/// Drives the production Manager trust bootstrap screen.
///
/// The operator supplies the CA DER, pin, host/port, deployment ID, key
/// fingerprint, and generation independently. The model observes the published
/// authority over the already-pinned TLS identity, requires the observed tuple
/// to match the operator values before committing, and persists the TLS
/// configuration and authority checkpoint as one atomic
/// `ManagerAuthorityTrustRecord` in `ManagerAuthorityTrustStore`.
@MainActor
@Observable
final class ManagerProductionBootstrapModel {
    typealias IdentityProvider = @Sendable () async throws -> ManagerSigningIdentity
    typealias AuthorityObserver = @Sendable (
        DeploymentTLSIdentity,
        ManagerSigningIdentity,
        ManagerAuthorityTrustStore
    ) async throws -> DeploymentAuthorityCheckpoint
    typealias ClientFactory = @Sendable (
        DeploymentTLSIdentity,
        ManagerSigningIdentity,
        ManagerAuthorityTrustStore
    ) async throws -> NativeV2AuthClient

    var host: String = ""
    var port: String = "8920"
    var caFileName: String?
    var caPin: String = ""
    var deploymentID: String = ""
    var keyFingerprint: String = ""
    var generation: String = ""
    private(set) var isReplacingTrust = false
    var isBusy = false
    var errorMessage: String?
    var statusMessage: String?
    private(set) var savedRecord: ManagerAuthorityTrustRecord?
    private(set) var didLoadSavedConfiguration = false
    private(set) var resetIncomplete = false
    private var caDER: Data?
    private var localStateGeneration: UInt64 = 0

    let authorityTrust: ManagerAuthorityTrustStore
    private let identityProvider: IdentityProvider
    private let authorityObserver: AuthorityObserver
    private let clientFactory: ClientFactory

    init(
        authorityTrust: ManagerAuthorityTrustStore = ManagerAuthorityTrustStore(),
        identityProvider: @escaping IdentityProvider = {
            try await ManagerIdentityStore().loadOrCreate()
        },
        authorityObserver: @escaping AuthorityObserver = { identity, signingIdentity, trust in
            try await ManagerProductionConnection(
                tlsIdentity: identity,
                authorityTrust: trust
            ).observeAuthority(signingIdentity: signingIdentity)
        },
        clientFactory: @escaping ClientFactory = { identity, signingIdentity, trust in
            try await ManagerProductionConnection(
                tlsIdentity: identity,
                authorityTrust: trust
            ).makeVerifiedClient(signingIdentity: signingIdentity)
        }
    ) {
        self.authorityTrust = authorityTrust
        self.identityProvider = identityProvider
        self.authorityObserver = authorityObserver
        self.clientFactory = clientFactory
    }

    /// The checkpoint half of the single saved trust record. The checkpoint and
    /// TLS configuration are never stored or cleared independently.
    var savedCheckpoint: DeploymentAuthorityCheckpoint? {
        savedRecord?.checkpoint
    }

    /// The TLS configuration decoded from the single saved trust record. `nil`
    /// for a legacy checkpoint-only record or when nothing is loaded.
    var savedConfiguration: ManagerProductionTrustConfiguration? {
        guard let savedRecord else { return nil }
        return try? bootstrapConfiguration(from: savedRecord)
    }

    /// SHA-256 of the selected CA DER bytes. Display-only; the operator must
    /// still type the independently supplied pin.
    var loadedCAFingerprint: String? {
        caDER.map(DeploymentTLSIdentity.sha256Hex)
    }

    var needsOperatorTrustValues: Bool {
        resetIncomplete || isReplacingTrust || savedConfiguration == nil
    }

    var canSubmit: Bool {
        guard !isBusy,
              !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let portValue, (1...65_535).contains(portValue),
              caDER != nil,
              isHex(caPin, length: 64),
              !deploymentID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return false
        }
        if needsOperatorTrustValues {
            return isHex(keyFingerprint, length: 64) && (generationValue ?? 0) > 0
        }
        return true
    }

    func loadSavedConfiguration() async {
        guard !didLoadSavedConfiguration else { return }
        didLoadSavedConfiguration = true
        let token = localStateGeneration
        do {
            let savedDeploymentIDs = try await authorityTrust.savedDeploymentIDs()
            guard token == localStateGeneration else { return }
            // Never guess which deployment the operator means when several
            // trust records exist. Nothing is loaded or overwritten.
            guard savedDeploymentIDs.count == 1, let savedDeploymentID = savedDeploymentIDs.first else {
                return
            }
            guard let record = try await authorityTrust.productionTrustRecord(
                deploymentID: savedDeploymentID
            ) else {
                return
            }
            guard token == localStateGeneration else { return }

            savedRecord = record
            let configuration: ManagerProductionTrustConfiguration
            do {
                configuration = try bootstrapConfiguration(from: record)
            } catch {
                // A legacy checkpoint-only or unreadable record is deliberately
                // not reused with a new or substituted origin. Keep it visible
                // so the operator can reset or explicitly replace it.
                resetIncomplete = true
                errorMessage = bootstrapMessage(for: error)
                return
            }

            resetIncomplete = false
            // Do not overwrite fields the operator already started editing while
            // the asynchronous Keychain read was in flight.
            let unedited = !isReplacingTrust
                && host.isEmpty
                && deploymentID.isEmpty
                && caDER == nil
                && caPin.isEmpty
                && keyFingerprint.isEmpty
                && generation.isEmpty
                && (port == "8920" || port.isEmpty)
            guard unedited else { return }
            host = configuration.host
            port = String(configuration.port)
            caDER = configuration.caDER
            caFileName = "Saved CA certificate"
            caPin = configuration.caFingerprintSHA256
            deploymentID = record.checkpoint.deploymentID
            keyFingerprint = record.checkpoint.grantSigningKeyFingerprintSHA256
            generation = String(record.checkpoint.authorityGeneration)
        } catch {
            guard token == localStateGeneration else { return }
            errorMessage = bootstrapMessage(for: error)
        }
    }

    /// Explicit local recovery: remove the one saved trust record for the
    /// relevant or operator-typed deployment. The delete is same-state checked
    /// under the shared authority lock, so a stale window cannot remove a record
    /// that another window has since replaced. Unrelated deployment records are
    /// never deleted.
    func clearSavedTrust() async {
        guard !isBusy else { return }
        isBusy = true
        localStateGeneration &+= 1
        defer { isBusy = false }

        let typedDeploymentID = deploymentID
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let modelRecord = savedRecord

        do {
            var targetID: String?
            var expectation: BootstrapResetExpectation?

            if let modelRecord {
                targetID = modelRecord.checkpoint.deploymentID
                expectation = .record(modelRecord)
            } else if !typedDeploymentID.isEmpty {
                targetID = typedDeploymentID
                expectation = try await resetExpectation(
                    deploymentID: typedDeploymentID
                )
            } else {
                let saved = try await authorityTrust.savedDeploymentIDs()
                if saved.isEmpty {
                    targetID = nil
                } else if saved.count == 1, let only = saved.first {
                    targetID = only
                    expectation = try await resetExpectation(deploymentID: only)
                } else {
                    resetIncomplete = true
                    statusMessage = nil
                    errorMessage = "Production trust reset was incomplete. authority checkpoint: multiple saved deployments exist and none were deleted; enter a deployment ID or load the matching saved configuration before resetting."
                    return
                }
            }

            if let targetID {
                if case .some(.unreadable(let rawBytes)) = expectation {
                    // Never delete a record that another window replaced after
                    // the unreadable state was observed. The raw-byte CAS is
                    // evaluated under the same authority lock as the delete.
                    let deleted = try await authorityTrust.deleteProductionTrustRecord(
                        deploymentID: targetID,
                        expectedRawBytes: rawBytes
                    )
                    guard deleted else {
                        throw BootstrapStateChanged()
                    }
                } else {
                    var expected: ManagerAuthorityTrustRecord?
                    if case .some(.record(let record)) = expectation {
                        expected = record
                    }
                    let deleted = try await authorityTrust.deleteProductionTrustRecord(
                        deploymentID: targetID,
                        expected: expected
                    )
                    guard deleted else {
                        throw BootstrapStateChanged()
                    }
                }
            }

            savedRecord = nil
            isReplacingTrust = false
            resetIncomplete = false
            clearPrefilledTrustInputs()
            statusMessage = "Saved production trust was cleared from the selected deployment. Enter independently verified values to set it up again."
            errorMessage = nil
        } catch is BootstrapStateChanged {
            // Keep the form and operator fields visible; a retry will keep
            // failing closed until the current record is reloaded.
            resetIncomplete = true
            statusMessage = nil
            errorMessage = "Saved production trust changed in another window; reset was not performed. Reopen production trust to load the current state before resetting."
        } catch {
            // Keep the form and operator fields visible so the failed reset can
            // be inspected and retried.
            resetIncomplete = true
            statusMessage = nil
            errorMessage = "Production trust reset was incomplete. \(bootstrapMessage(for: error)) The remaining trust record is still in place."
        }
    }

    private func resetExpectation(
        deploymentID: String
    ) async throws -> BootstrapResetExpectation {
        switch try await authorityTrust.productionTrustRecordState(
            deploymentID: deploymentID
        ) {
        case .absent:
            return .record(nil)
        case .present(let record):
            return .record(record)
        case .unreadable(let rawBytes):
            return .unreadable(rawBytes: rawBytes)
        }
    }

    func openGuidedSetup(in session: ManagerSession) {
        session.screen = .guidedSetup
    }

    func setReplacingTrust(_ replacing: Bool) {
        isReplacingTrust = replacing
        if replacing {
            // Force independent re-entry instead of reusing values loaded from
            // the very checkpoint being replaced.
            keyFingerprint = ""
            generation = ""
        }
    }

    private func clearPrefilledTrustInputs() {
        host = ""
        port = "8920"
        caDER = nil
        caFileName = nil
        caPin = ""
        deploymentID = ""
        keyFingerprint = ""
        generation = ""
        isReplacingTrust = false
    }

    private func requireSnapshotMatchesModel(
        _ snapshot: BootstrapTrustSnapshot
    ) throws {
        guard savedRecord == snapshot.modelRecord else {
            savedRecord = nil
            resetIncomplete = true
            localStateGeneration &+= 1
            clearPrefilledTrustInputs()
            throw HelicoidError.authenticationFailed(
                detail: "Saved production trust changed in another window or was reset. Reset production trust if the stored state is inconsistent, then re-enter independently verified values."
            )
        }
    }

    func setCADER(_ data: Data, fileName: String?) {
        guard !data.isEmpty else {
            errorMessage = "The selected CA certificate is empty."
            return
        }
        guard data.count <= DeploymentTLSIdentity.maxCADerBytes else {
            errorMessage = "The selected CA certificate is too large."
            return
        }
        caDER = data
        caFileName = fileName
        errorMessage = nil
    }

    /// Verify and persist trust, then install a production client into `session`.
    @discardableResult
    func connect(into session: ManagerSession) async -> Bool {
        guard !isBusy else { return false }
        isBusy = true
        errorMessage = nil
        statusMessage = nil
        defer { isBusy = false }

        do {
            // Detach any previously installed client after a trust mismatch so
            // a successful replacement can install the new verified client.
            session.uninstallProductionConnection()
            let prepared = try await prepareTrust()
            let client = try await clientFactory(
                prepared.tlsIdentity,
                prepared.signingIdentity,
                authorityTrust
            )
            let installed = await session.installProductionConnection(
                client: client,
                authorityTrust: authorityTrust,
                serverAddress: prepared.tlsIdentity.originURL.absoluteString,
                expectedRecord: prepared.record
            )
            guard installed else {
                throw HelicoidError.authenticationFailed(
                    detail: "The saved production trust could not be installed or changed during setup. Review production trust, reset if needed, and try again."
                )
            }
            statusMessage = "Production trust verified. Connecting…"
            await session.connect()
            if session.phase == .needsSignIn || session.phase == .signedIn {
                return true
            }
            // Leave the bootstrap screen available for review/recovery instead
            // of stranding the operator in a failed production connection.
            session.uninstallProductionConnection()
            statusMessage = nil
            errorMessage = session.connectError?.explanation
                ?? "The production server did not answer. Check the address and try again."
            return false
        } catch {
            errorMessage = bootstrapMessage(for: error)
            return false
        }
    }

    /// Perform the network observation and local atomic record commit.
    /// Internal so tests can exercise the trust boundary without a live server.
    func prepareTrust() async throws -> PreparedProductionTrust {
        localStateGeneration &+= 1
        let token = localStateGeneration
        guard let caDER else {
            throw HelicoidError.invalidInput(
                field: "CA certificate",
                detail: "Choose the independently supplied deployment CA certificate."
            )
        }
        guard let portValue, (1...65_535).contains(portValue) else {
            throw HelicoidError.invalidInput(
                field: "port",
                detail: "Port must be between 1 and 65535."
            )
        }
        let tlsIdentity = try DeploymentTLSIdentity(
            deploymentID: deploymentID,
            host: host,
            port: portValue,
            caDER: caDER,
            caFingerprintSHA256: caPin
        )
        let snapshot = try await readSnapshot(formDeploymentID: tlsIdentity.deploymentID)
        guard token == localStateGeneration else {
            throw HelicoidError.cancelled
        }
        try requireSnapshotMatchesModel(snapshot)

        if let modelDeploymentID = snapshot.modelDeploymentID,
           modelDeploymentID != tlsIdentity.deploymentID,
           !isReplacingTrust {
            throw HelicoidError.authenticationFailed(
                detail: "A different deployment's trust is already saved. Reset production trust or explicitly enable Replace saved trust checkpoint before switching deployments."
            )
        }

        let existingRecord = snapshot.formRecord
        if let existingRecord,
           existingRecord.configurationData == nil,
           !isReplacingTrust {
            throw HelicoidError.authenticationFailed(
                detail: "A saved authority checkpoint exists without an atomically bound TLS configuration. Enable Replace saved trust checkpoint after independent verification or reset production trust."
            )
        }
        let useSavedTrust = existingRecord != nil && !isReplacingTrust
        var confirmation: ManagerAuthorityConfirmation?

        if useSavedTrust, let existingRecord {
            let persistedConfiguration = try bootstrapConfiguration(from: existingRecord)
            let savedIdentity = try DeploymentTLSIdentity(
                deploymentID: persistedConfiguration.deploymentID,
                host: persistedConfiguration.host,
                port: persistedConfiguration.port,
                caDER: persistedConfiguration.caDER,
                caFingerprintSHA256: persistedConfiguration.caFingerprintSHA256
            )
            guard tlsIdentity == savedIdentity else {
                throw HelicoidError.authenticationFailed(
                    detail: "The host, port, CA certificate, or CA pin differs from the saved trust configuration. Enable Replace saved trust checkpoint and re-verify the authority through an independent channel."
                )
            }
        } else {
            guard let generationValue, generationValue > 0 else {
                throw HelicoidError.invalidInput(
                    field: "authority generation",
                    detail: "Enter the non-zero generation supplied through your trusted channel."
                )
            }
            let fingerprint = keyFingerprint
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
            guard isHex(fingerprint, length: 64) else {
                throw HelicoidError.invalidInput(
                    field: "key fingerprint",
                    detail: "Enter the 64-character SHA-256 fingerprint supplied through your trusted channel."
                )
            }
            keyFingerprint = fingerprint
            confirmation = try ManagerAuthorityConfirmation(
                operatorEnteredDeploymentID: tlsIdentity.deploymentID,
                operatorEnteredKeyFingerprintSHA256: fingerprint,
                operatorEnteredAuthorityGeneration: generationValue
            )
        }

        let signingIdentity = try await identityProvider()
        let observed = try await authorityObserver(
            tlsIdentity,
            signingIdentity,
            authorityTrust
        )
        guard token == localStateGeneration else {
            throw HelicoidError.authenticationFailed(
                detail: "Production trust changed while the server was being verified. Nothing was saved; review the current trust state and try again."
            )
        }

        if let confirmation {
            guard observed.deploymentID == confirmation.deploymentID,
                  observed.grantSigningKeyFingerprintSHA256 == confirmation.grantSigningKeyFingerprintSHA256,
                  observed.authorityGeneration == confirmation.authorityGeneration else {
                throw HelicoidError.authenticationFailed(
                    detail: "The live authority does not match the deployment ID, key fingerprint, or generation you entered. Nothing was saved."
                )
            }
        }

        let committed: BootstrapCommitResult
        do {
            committed = try await commitTrust(
                snapshot: snapshot,
                tlsIdentity: tlsIdentity,
                observed: observed,
                useSavedTrust: useSavedTrust,
                confirmation: confirmation
            )
        } catch is BootstrapStateChanged {
            savedRecord = nil
            resetIncomplete = true
            clearPrefilledTrustInputs()
            throw HelicoidError.authenticationFailed(
                detail: "Saved production trust changed while verifying the server. Nothing was saved; reset production trust and re-enter independently verified values."
            )
        }

        savedRecord = committed.record
        resetIncomplete = false
        return PreparedProductionTrust(
            tlsIdentity: tlsIdentity,
            signingIdentity: signingIdentity,
            checkpoint: committed.record.checkpoint,
            record: committed.record
        )
    }

    private func readSnapshot(
        formDeploymentID: String
    ) async throws -> BootstrapTrustSnapshot {
        let modelDeploymentID = savedRecord?.checkpoint.deploymentID
        let formRecord = try await authorityTrust.productionTrustRecord(
            deploymentID: formDeploymentID
        )
        let modelRecord: ManagerAuthorityTrustRecord?
        if let modelDeploymentID, modelDeploymentID == formDeploymentID {
            modelRecord = formRecord
        } else if let modelDeploymentID {
            modelRecord = try await authorityTrust.productionTrustRecord(
                deploymentID: modelDeploymentID
            )
        } else {
            modelRecord = nil
        }
        return BootstrapTrustSnapshot(
            modelDeploymentID: modelDeploymentID,
            formDeploymentID: formDeploymentID,
            modelRecord: modelRecord,
            formRecord: formRecord
        )
    }

    private func commitTrust(
        snapshot: BootstrapTrustSnapshot,
        tlsIdentity: DeploymentTLSIdentity,
        observed: DeploymentAuthorityCheckpoint,
        useSavedTrust: Bool,
        confirmation: ManagerAuthorityConfirmation?
    ) async throws -> BootstrapCommitResult {
        let configurationData: Data
        let proposedCheckpoint: DeploymentAuthorityCheckpoint

        if useSavedTrust {
            guard let record = snapshot.formRecord,
                  let data = record.configurationData else {
                throw HelicoidError.authenticationFailed(
                    detail: "A saved authority checkpoint exists without an atomically bound TLS configuration. Reset production trust and set it up again."
                )
            }
            guard observed == record.checkpoint else {
                throw HelicoidError.authenticationFailed(
                    detail: "The live authority differs from the saved checkpoint. Review the server authority and enable Replace saved trust checkpoint only after independent verification."
                )
            }
            configurationData = data
            proposedCheckpoint = record.checkpoint
        } else {
            let configuration = try ManagerProductionTrustConfiguration(
                deploymentID: tlsIdentity.deploymentID,
                host: tlsIdentity.host,
                port: tlsIdentity.port,
                caDER: tlsIdentity.caDER,
                caFingerprintSHA256: tlsIdentity.caFingerprintSHA256
            )
            configurationData = try configuration.encodedForTrustRecord()
            proposedCheckpoint = observed
        }

        let proposed = try ManagerAuthorityTrustRecord(
            checkpoint: proposedCheckpoint,
            configurationData: configurationData
        )
        var expectations: [ManagerAuthorityTrustExpectation] = []
        if let modelDeploymentID = snapshot.modelDeploymentID,
           modelDeploymentID != snapshot.formDeploymentID {
            expectations.append(
                try ManagerAuthorityTrustExpectation(
                    deploymentID: modelDeploymentID,
                    record: snapshot.modelRecord
                )
            )
        }

        let result = try await authorityTrust.commitProductionTrustRecord(
            proposed,
            expected: snapshot.formRecord,
            alsoRequiring: expectations,
            confirmation: useSavedTrust ? nil : confirmation
        )

        switch result {
        case .committed:
            // Decode what is actually stored so a corrupt configuration can
            // never be presented as verified trust.
            _ = try bootstrapConfiguration(from: proposed)
            return BootstrapCommitResult(record: proposed)
        case .recordChanged:
            throw BootstrapStateChanged()
        case .confirmationMismatch:
            throw HelicoidError.authenticationFailed(
                detail: "The live authority does not match the deployment ID, key fingerprint, or generation you entered. Nothing was saved."
            )
        case .transitionRefused:
            throw HelicoidError.authenticationFailed(
                detail: "The authority checkpoint could not advance. A rollback or same-generation key change requires approved recovery and an explicit local trust reset."
            )
        }
    }

    private var portValue: Int? {
        Int(port.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private var generationValue: UInt64? {
        UInt64(generation.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private func isHex(_ value: String, length: Int) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count == length else { return false }
        return trimmed.allSatisfy(\.isHexDigit)
    }

}
