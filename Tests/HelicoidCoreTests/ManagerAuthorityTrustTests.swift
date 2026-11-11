import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

private let authorityDeploymentID = "dep_00000000000000000000000000000001"
private let secondAuthorityDeploymentID = "dep_00000000000000000000000000000002"
private let authorityKeyAHex = String(repeating: "a", count: 64)
private let authorityKeyBHex = String(repeating: "b", count: 64)
// Independently recorded operator values, not derived from an observed tuple.
private let authorityFingerprintA = "e0e77a507412b120f6ede61f62295b1a7b2ff19d3dcc8f7253e51663470c888e"
private let authorityFingerprintB = "4ca14526b2751b640d549ce7caf8ac39438592211a0ec370064d57666a682ad6"

private struct NoopAuthorityLock: ManagerAuthorityLocking {
    func acquire() async throws -> any ManagerAuthorityLockReleasing {
        NoopAuthorityLockHandle()
    }
}

private struct NoopAuthorityLockHandle: ManagerAuthorityLockReleasing {
    func release() {}
}

private actor AuthorityTestFlag {
    private(set) var value = false
    func set() { value = true }
}

private func makePrivateTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("hs-authority-lock-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: url,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    return url
}

private func waitForAuthorityCondition(
    _ condition: @Sendable () async -> Bool
) async throws {
    for _ in 0..<200 {
        if await condition() { return }
        try await Task.sleep(for: .milliseconds(10))
    }
    Issue.record("Timed out waiting for authority test condition.")
}

private actor AuthorityKeyFixtureStore: ManagerAuthorityKeyStoring {
    private var values: [String: Data] = [:]
    private var failReads = false
    private var failWrites = false
    private(set) var insertions = 0
    private(set) var updates = 0
    private(set) var deletions = 0

    func read(account: String) throws -> Data? {
        if failReads { throw HelicoidError.offline }
        return values[account]
    }

    func insertIfAbsent(_ bytes: Data, account: String) throws -> Bool {
        if failWrites { throw HelicoidError.offline }
        guard values[account] == nil else { return false }
        values[account] = bytes
        insertions += 1
        return true
    }

    func update(_ bytes: Data, account: String) throws {
        if failWrites { throw HelicoidError.offline }
        guard values[account] != nil else { throw HelicoidError.offline }
        values[account] = bytes
        updates += 1
    }

    func delete(account: String) throws {
        if failWrites { throw HelicoidError.offline }
        values.removeValue(forKey: account)
        deletions += 1
    }

    func allAccounts() -> [String] { Array(values.keys) }

    func setFailReads(_ value: Bool) { failReads = value }
    func setFailWrites(_ value: Bool) { failWrites = value }
    func seed(_ bytes: Data, account: String) { values[account] = bytes }
    func storedBytes(account: String) -> Data? { values[account] }
}

/// Key store that can pause one read after capturing its value. This forces the
/// old read→check→write interleaving while the authority lock is supposed to
/// keep a second writer out.
private actor GatedAuthorityKeyStore: ManagerAuthorityKeyStoring {
    private var values: [String: Data] = [:]
    private var pauseNextRead = false
    private var pausedRead: CheckedContinuation<Void, Never>?
    private(set) var readCount = 0
    private(set) var insertions = 0
    private(set) var isReadPaused = false

    func enablePauseOnNextRead() {
        pauseNextRead = true
    }

    func releasePausedRead() {
        pausedRead?.resume()
        pausedRead = nil
        isReadPaused = false
    }

    func read(account: String) async throws -> Data? {
        readCount += 1
        let value = values[account]
        if pauseNextRead {
            pauseNextRead = false
            isReadPaused = true
            await withCheckedContinuation { pausedRead = $0 }
        }
        return value
    }

    func insertIfAbsent(_ bytes: Data, account: String) throws -> Bool {
        guard values[account] == nil else { return false }
        values[account] = bytes
        insertions += 1
        return true
    }

    func update(_ bytes: Data, account: String) throws {
        guard values[account] != nil else { throw HelicoidError.offline }
        values[account] = bytes
    }

    func delete(account: String) throws {
        values.removeValue(forKey: account)
    }

    func allAccounts() -> [String] { Array(values.keys) }
}

private func makeCheckpoint(
    deploymentID: String = authorityDeploymentID,
    keyCharacter: Character = "a",
    generation: UInt64 = 7
) throws -> DeploymentAuthorityCheckpoint {
    let keyHex = keyCharacter == "b" ? authorityKeyBHex : authorityKeyAHex
    return try DeploymentAuthorityCheckpoint(
        deploymentID: deploymentID,
        grantSigningPublicKeyHex: keyHex,
        authorityGeneration: generation
    )
}

/// Operator-supplied confirmation. The fingerprint and generation are explicit
/// independent test inputs, never copied from the checkpoint under test.
private func operatorConfirmation(
    deploymentID: String = authorityDeploymentID,
    keyCharacter: Character = "a",
    generation: UInt64 = 7
) throws -> ManagerAuthorityConfirmation {
    let fingerprint = keyCharacter == "b" ? authorityFingerprintB : authorityFingerprintA
    return try ManagerAuthorityConfirmation(
        operatorEnteredDeploymentID: deploymentID,
        operatorEnteredKeyFingerprintSHA256: fingerprint,
        operatorEnteredAuthorityGeneration: generation
    )
}

@Suite("Manager deployment authority trust")
struct ManagerAuthorityTrustTests {
    @Test("Checkpoint validation refuses noncanonical or zero-generation tuples")
    func checkpointValidationRefusesNoncanonicalTuples() throws {
        let badDeploymentIDs = [
            "",
            "dep_",
            "dep_short",
            "dep_" + String(repeating: "a", count: 33),
            "dep_" + String(repeating: "A", count: 32),
            "dep_" + String(repeating: "g", count: 32),
            "dep_" + String(repeating: "a", count: 31) + "\u{0000}",
            "de p_" + String(repeating: "a", count: 31),
        ]
        for deploymentID in badDeploymentIDs {
            #expect(throws: HelicoidError.self) {
                try DeploymentAuthorityCheckpoint(
                    deploymentID: deploymentID,
                    grantSigningPublicKeyHex: String(repeating: "a", count: 64),
                    authorityGeneration: 1
                )
            }
        }

        let badKeys = [
            "",
            String(repeating: "a", count: 63),
            String(repeating: "a", count: 65),
            String(repeating: "A", count: 64),
            String(repeating: "g", count: 64),
            " " + String(repeating: "a", count: 63),
        ]
        for key in badKeys {
            #expect(throws: HelicoidError.self) {
                try DeploymentAuthorityCheckpoint(
                    deploymentID: authorityDeploymentID,
                    grantSigningPublicKeyHex: key,
                    authorityGeneration: 1
                )
            }
        }

        for generation in [UInt64(0), DeploymentAuthorityCheckpoint.maxAuthorityGeneration + 1, UInt64.max] {
            #expect(throws: HelicoidError.self) {
                try DeploymentAuthorityCheckpoint(
                    deploymentID: authorityDeploymentID,
                    grantSigningPublicKeyHex: String(repeating: "a", count: 64),
                    authorityGeneration: generation
                )
            }
        }

        let checkpoint = try makeCheckpoint()
        let decodedKey = Data(repeating: 0xaa, count: 32)
        let expected = SHA256.hash(data: decodedKey)
            .map { String(format: "%02x", $0) }
            .joined()
        #expect(checkpoint.grantSigningKeyFingerprintSHA256 == expected)
        #expect(checkpoint.grantSigningKeyFingerprintSHA256.count == 64)
    }

    @Test("Confirmation validation refuses malformed out-of-band values")
    func confirmationValidationRefusesMalformedValues() throws {
        #expect(throws: HelicoidError.self) {
            try ManagerAuthorityConfirmation(
                operatorEnteredDeploymentID: authorityDeploymentID,
                operatorEnteredKeyFingerprintSHA256: String(repeating: "A", count: 64),
                operatorEnteredAuthorityGeneration: 1
            )
        }
        #expect(throws: HelicoidError.self) {
            try ManagerAuthorityConfirmation(
                operatorEnteredDeploymentID: authorityDeploymentID,
                operatorEnteredKeyFingerprintSHA256: String(repeating: "a", count: 63),
                operatorEnteredAuthorityGeneration: 1
            )
        }
        #expect(throws: HelicoidError.self) {
            try ManagerAuthorityConfirmation(
                operatorEnteredDeploymentID: secondAuthorityDeploymentID,
                operatorEnteredKeyFingerprintSHA256: String(repeating: "a", count: 64),
                operatorEnteredAuthorityGeneration: 0
            )
        }
    }

    @Test("Initial adoption needs a separate matching out-of-band confirmation")
    func initialAdoptionNeedsMatchingConfirmation() async throws {
        let fixture = AuthorityKeyFixtureStore()
        let store = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: NoopAuthorityLock())
        let observed = try makeCheckpoint(generation: 7)
        let wrong = try ManagerAuthorityConfirmation(
            operatorEnteredDeploymentID: authorityDeploymentID,
            operatorEnteredKeyFingerprintSHA256: authorityFingerprintB,
            operatorEnteredAuthorityGeneration: 7
        )

        await #expect(throws: HelicoidError.self) {
            try await store.adopt(observed, confirmation: wrong)
        }
        let saved = try await store.savedCheckpoint(deploymentID: observed.deploymentID)
        #expect(saved == nil)
        #expect(await fixture.insertions == 0)
        #expect(await fixture.updates == 0)
    }

    @Test("Adoption persists and reloads the exact tuple")
    func adoptionPersistsAndReloads() async throws {
        let fixture = AuthorityKeyFixtureStore()
        let store = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: NoopAuthorityLock())
        let observed = try makeCheckpoint(generation: 7)
        let confirmation = try operatorConfirmation(generation: 7)

        let adopted = try await store.adopt(observed, confirmation: confirmation)
        #expect(adopted == observed)

        let reloadedStore = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: NoopAuthorityLock())
        let reloaded = try await reloadedStore.savedCheckpoint(deploymentID: observed.deploymentID)
        #expect(reloaded == observed)
        let current = try await reloadedStore.requireCurrent(observed)
        #expect(current == observed)
        #expect(await fixture.insertions == 1)
    }

    @Test("A network observation alone never becomes local trust")
    func observationAloneIsNotTrust() async throws {
        let fixture = AuthorityKeyFixtureStore()
        let store = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: NoopAuthorityLock())
        let observed = try makeCheckpoint(generation: 7)

        await #expect(throws: HelicoidError.self) {
            try await store.requireCurrent(observed)
        }
        let saved = try await store.savedCheckpoint(deploymentID: observed.deploymentID)
        #expect(saved == nil)
        #expect(await fixture.insertions == 0)
    }

    @Test("Rollback and same-generation key changes are refused")
    func rollbackAndSameGenerationKeyChangeAreRefused() async throws {
        let fixture = AuthorityKeyFixtureStore()
        let store = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: NoopAuthorityLock())
        let trusted = try makeCheckpoint(keyCharacter: "a", generation: 7)
        _ = try await store.adopt(trusted, confirmation: try operatorConfirmation(generation: 7))

        let rollback = try makeCheckpoint(keyCharacter: "a", generation: 6)
        await #expect(throws: HelicoidError.self) {
            try await store.adopt(
                rollback,
                confirmation: try operatorConfirmation(keyCharacter: "a", generation: 6)
            )
        }
        let afterRollback = try await store.savedCheckpoint(deploymentID: trusted.deploymentID)
        #expect(afterRollback == trusted)

        let keyChange = try makeCheckpoint(keyCharacter: "b", generation: 7)
        await #expect(throws: HelicoidError.self) {
            try await store.adopt(
                keyChange,
                confirmation: try operatorConfirmation(keyCharacter: "b", generation: 7)
            )
        }
        let afterKeyChange = try await store.savedCheckpoint(deploymentID: trusted.deploymentID)
        #expect(afterKeyChange == trusted)

        let advanced = try makeCheckpoint(keyCharacter: "b", generation: 8)
        let adopted = try await store.adopt(
            advanced,
            confirmation: try operatorConfirmation(keyCharacter: "b", generation: 8)
        )
        #expect(adopted == advanced)
        let afterAdvance = try await store.savedCheckpoint(deploymentID: trusted.deploymentID)
        #expect(afterAdvance == advanced)
    }

    @Test("Existing trust stays intact when current authority differs")
    func existingTrustStaysIntactOnMismatch() async throws {
        let fixture = AuthorityKeyFixtureStore()
        let store = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: NoopAuthorityLock())
        let trusted = try makeCheckpoint(keyCharacter: "a", generation: 7)
        _ = try await store.adopt(trusted, confirmation: try operatorConfirmation(generation: 7))

        for observed in [
            try makeCheckpoint(keyCharacter: "a", generation: 8),
            try makeCheckpoint(keyCharacter: "b", generation: 7),
            try makeCheckpoint(deploymentID: secondAuthorityDeploymentID, keyCharacter: "a", generation: 7),
        ] {
            await #expect(throws: HelicoidError.self) {
                try await store.requireCurrent(observed)
            }
        }

        let after = try await store.savedCheckpoint(deploymentID: trusted.deploymentID)
        #expect(after == trusted)
        let other = try await store.savedCheckpoint(deploymentID: secondAuthorityDeploymentID)
        #expect(other == nil)
    }

    @Test("Corrupt persisted state fails closed and is not overwritten")
    func corruptPersistedStateFailsClosed() async throws {
        let fixture = AuthorityKeyFixtureStore()
        let corrupt = Data("not-a-checkpoint".utf8)
        await fixture.seed(corrupt, account: authorityDeploymentID)
        let store = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: NoopAuthorityLock())
        let observed = try makeCheckpoint(generation: 7)

        await #expect(throws: HelicoidError.self) {
            try await store.savedCheckpoint(deploymentID: authorityDeploymentID)
        }
        await #expect(throws: HelicoidError.self) {
            try await store.adopt(observed, confirmation: try operatorConfirmation(generation: 7))
        }

        let raw = await fixture.storedBytes(account: authorityDeploymentID)
        #expect(raw == corrupt)
        #expect(await fixture.updates == 0)
    }

    @Test("Persisted checkpoint cannot be replayed under another deployment account")
    func persistedCheckpointCannotCrossDeploymentAccounts() async throws {
        let fixture = AuthorityKeyFixtureStore()
        let payload = """
        {"version":1,"deploymentID":"\(secondAuthorityDeploymentID)","grantSigningPublicKeyHex":"\(authorityKeyAHex)","authorityGeneration":1}
        """
        await fixture.seed(Data(payload.utf8), account: authorityDeploymentID)
        let store = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: NoopAuthorityLock())

        await #expect(throws: HelicoidError.self) {
            try await store.savedCheckpoint(deploymentID: authorityDeploymentID)
        }
        await #expect(throws: HelicoidError.self) {
            try await store.requireCurrent(
                try makeCheckpoint(deploymentID: authorityDeploymentID, generation: 1)
            )
        }
        #expect(await fixture.updates == 0)
    }

    @Test("Persistence failure never reports adoption")
    func persistenceFailureNeverReportsAdoption() async throws {
        let fixture = AuthorityKeyFixtureStore()
        let store = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: NoopAuthorityLock())
        let trusted = try makeCheckpoint(generation: 7)

        await fixture.setFailWrites(true)
        await #expect(throws: HelicoidError.self) {
            try await store.adopt(trusted, confirmation: try operatorConfirmation(generation: 7))
        }
        let afterFailure = try await store.savedCheckpoint(deploymentID: trusted.deploymentID)
        #expect(afterFailure == nil)

        await fixture.setFailWrites(false)
        _ = try await store.adopt(trusted, confirmation: try operatorConfirmation(generation: 7))
        await fixture.setFailWrites(true)
        let advanced = try makeCheckpoint(generation: 8)
        await #expect(throws: HelicoidError.self) {
            try await store.adopt(advanced, confirmation: try operatorConfirmation(generation: 8))
        }
        let afterAdvancedFailure = try await store.savedCheckpoint(deploymentID: trusted.deploymentID)
        #expect(afterAdvancedFailure == trusted)
    }

    @Test("Read failure fails closed")
    func readFailureFailsClosed() async throws {
        let fixture = AuthorityKeyFixtureStore()
        let store = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: NoopAuthorityLock())
        let observed = try makeCheckpoint(generation: 7)
        await fixture.setFailReads(true)

        await #expect(throws: HelicoidError.self) {
            try await store.savedCheckpoint(deploymentID: observed.deploymentID)
        }
        await #expect(throws: HelicoidError.self) {
            try await store.requireCurrent(observed)
        }
        await #expect(throws: HelicoidError.self) {
            try await store.adopt(observed, confirmation: try operatorConfirmation(generation: 7))
        }
        #expect(await fixture.insertions == 0)
    }

    @Test("Deployments have independent checkpoint slots")
    func deploymentsHaveIndependentCheckpointSlots() async throws {
        let fixture = AuthorityKeyFixtureStore()
        let store = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: NoopAuthorityLock())
        let first = try makeCheckpoint(deploymentID: authorityDeploymentID, generation: 7)
        let second = try makeCheckpoint(deploymentID: secondAuthorityDeploymentID, generation: 3)

        _ = try await store.adopt(
            first,
            confirmation: try operatorConfirmation(deploymentID: authorityDeploymentID, generation: 7)
        )
        _ = try await store.adopt(
            second,
            confirmation: try operatorConfirmation(deploymentID: secondAuthorityDeploymentID, generation: 3)
        )

        #expect(try await store.savedCheckpoint(deploymentID: first.deploymentID) == first)
        #expect(try await store.savedCheckpoint(deploymentID: second.deploymentID) == second)

        try await store.clear(deploymentID: first.deploymentID)
        #expect(try await store.savedCheckpoint(deploymentID: first.deploymentID) == nil)
        #expect(try await store.savedCheckpoint(deploymentID: second.deploymentID) == second)
    }

    /// `flock` locks exclude independent open descriptions on Darwin and are
    /// released by the kernel on process exit.
    @Test("POSIX authority lock excludes an independent second holder")
    func posixLockExcludesSecondHolder() async throws {
        let directory = try makePrivateTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = POSIXManagerAuthorityLock(trustedRootURL: directory, relativeComponents: ["AuthorityTrust"])
        let second = POSIXManagerAuthorityLock(trustedRootURL: directory, relativeComponents: ["AuthorityTrust"])
        let started = AuthorityTestFlag()
        let acquired = AuthorityTestFlag()

        let firstHandle = try await first.acquire()
        let secondTask = Task {
            await started.set()
            let secondHandle = try await second.acquire()
            await acquired.set()
            secondHandle.release()
        }

        try await waitForAuthorityCondition { await started.value }
        try await Task.sleep(for: .milliseconds(100))
        #expect(await acquired.value == false, "second holder must wait while the first lock is held")

        firstHandle.release()
        try await secondTask.value
        #expect(await acquired.value == true)
    }

    @Test("Symlinked ancestor is refused by the lock chain walk")
    func symlinkAncestorIsRefused() async throws {
        let root = try makePrivateTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("target", isDirectory: true)
        try FileManager.default.createDirectory(
            at: target,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let link = root.appendingPathComponent("ancestor", isDirectory: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        let lock = POSIXManagerAuthorityLock(
            trustedRootURL: root,
            relativeComponents: ["ancestor", "AuthorityTrust"]
        )
        await #expect(throws: HelicoidError.self) {
            try await lock.acquire()
        }
        #expect(
            !FileManager.default.fileExists(
                atPath: target.appendingPathComponent("AuthorityTrust").path
            ),
            "a symlinked ancestor must not be followed or populated"
        )
    }

    @Test("Group-writable ancestor is refused by the lock chain walk")
    func groupWritableAncestorIsRefused() async throws {
        let root = try makePrivateTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let ancestor = root.appendingPathComponent("ancestor", isDirectory: true)
        try FileManager.default.createDirectory(
            at: ancestor,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o777]
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o777],
            ofItemAtPath: ancestor.path
        )

        let lock = POSIXManagerAuthorityLock(
            trustedRootURL: root,
            relativeComponents: ["ancestor", "AuthorityTrust"]
        )
        await #expect(throws: HelicoidError.self) {
            try await lock.acquire()
        }
    }

    @Test("Forced interleaving cannot roll back an authority checkpoint")
    func forcedInterleavingCannotRollBack() async throws {
        let fixture = GatedAuthorityKeyStore()
        let directory = try makePrivateTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let lock = POSIXManagerAuthorityLock(trustedRootURL: directory, relativeComponents: ["AuthorityTrust"])
        let firstStore = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: lock)
        let secondStore = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: lock)

        let trusted = try makeCheckpoint(keyCharacter: "a", generation: 7)
        _ = try await firstStore.adopt(
            trusted,
            confirmation: try operatorConfirmation(generation: 7)
        )

        await fixture.enablePauseOnNextRead()
        let advanced = try makeCheckpoint(keyCharacter: "b", generation: 8)
        let advanceTask = Task {
            try await firstStore.adopt(
                advanced,
                confirmation: try operatorConfirmation(keyCharacter: "b", generation: 8)
            )
        }
        try await waitForAuthorityCondition { await fixture.isReadPaused }

        let rolledBack = try makeCheckpoint(keyCharacter: "a", generation: 6)
        let rollbackStarted = AuthorityTestFlag()
        let rollbackTask = Task {
            await rollbackStarted.set()
            return try await secondStore.adopt(
                rolledBack,
                confirmation: try operatorConfirmation(keyCharacter: "a", generation: 6)
            )
        }
        try await waitForAuthorityCondition { await rollbackStarted.value }
        try await Task.sleep(for: .milliseconds(100))
        #expect(await fixture.readCount == 2, "the second writer must not read while the first holds the lock")

        await fixture.releasePausedRead()
        let advancedResult = try await advanceTask.value
        #expect(advancedResult == advanced)
        await #expect(throws: HelicoidError.self) {
            try await rollbackTask.value
        }

        let final = try await firstStore.savedCheckpoint(deploymentID: authorityDeploymentID)
        #expect(final == advanced)
    }

    @Test("Forced interleaving preserves two permitted higher generations")
    func forcedInterleavingPreservesHigherGeneration() async throws {
        let fixture = GatedAuthorityKeyStore()
        let directory = try makePrivateTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let lock = POSIXManagerAuthorityLock(
            trustedRootURL: directory,
            relativeComponents: ["AuthorityTrust"]
        )
        let firstStore = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: lock)
        let secondStore = ManagerAuthorityTrustStore(keyStore: fixture, authorityLock: lock)

        let trusted = try makeCheckpoint(keyCharacter: "a", generation: 7)
        _ = try await firstStore.adopt(
            trusted,
            confirmation: try operatorConfirmation(generation: 7)
        )

        await fixture.enablePauseOnNextRead()
        let eighth = try makeCheckpoint(keyCharacter: "b", generation: 8)
        let firstAdvance = Task {
            try await firstStore.adopt(
                eighth,
                confirmation: try operatorConfirmation(keyCharacter: "b", generation: 8)
            )
        }
        try await waitForAuthorityCondition { await fixture.isReadPaused }

        let ninth = try makeCheckpoint(keyCharacter: "b", generation: 9)
        let secondStarted = AuthorityTestFlag()
        let secondAdvance = Task {
            await secondStarted.set()
            return try await secondStore.adopt(
                ninth,
                confirmation: try operatorConfirmation(keyCharacter: "b", generation: 9)
            )
        }
        try await waitForAuthorityCondition { await secondStarted.value }
        try await Task.sleep(for: .milliseconds(100))
        #expect(await fixture.readCount == 2, "the second writer must not read while the first holds the lock")

        await fixture.releasePausedRead()
        #expect(try await firstAdvance.value == eighth)
        #expect(try await secondAdvance.value == ninth)
        let final = try await firstStore.savedCheckpoint(deploymentID: authorityDeploymentID)
        #expect(final == ninth, "the later generation must not be lost")
    }

    @Test("Cancellation before mutation leaves no checkpoint")
    func cancellationBeforeMutationLeavesNoCheckpoint() async throws {
        let fixture = GatedAuthorityKeyStore()
        let store = ManagerAuthorityTrustStore(
            keyStore: fixture,
            authorityLock: NoopAuthorityLock()
        )
        let observed = try makeCheckpoint(generation: 7)

        await fixture.enablePauseOnNextRead()
        let task = Task {
            try await store.adopt(
                observed,
                confirmation: try operatorConfirmation(generation: 7)
            )
        }
        try await waitForAuthorityCondition { await fixture.isReadPaused }
        task.cancel()
        await fixture.releasePausedRead()

        await #expect(throws: HelicoidError.self) {
            try await task.value
        }
        #expect(await fixture.insertions == 0)
        let saved = try await store.savedCheckpoint(deploymentID: authorityDeploymentID)
        #expect(saved == nil)
    }
}

// MARK: - Pinned observation

private actor AuthorityTransport: HTTPTransport {
    private var status: Int
    private var body: Data
    private(set) var requests: [URLRequest] = []

    init(status: Int = 200, body: Data = Data()) {
        self.status = status
        self.body = body
    }

    func setResponse(status: Int, body: Data) {
        self.status = status
        self.body = body
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        requests.append(request)
        guard let url = request.url else {
            throw HelicoidError.invalidInput(field: "request", detail: "Missing URL.")
        }
        let response = HTTPURLResponse(
            url: url,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        return (body, response)
    }

    var lastRequest: URLRequest? { requests.last }
}

private func makePinnedIdentity(deploymentID: String) async throws -> DeploymentTLSIdentity {
    let material = try await TLSTestHarness.sharedMaterial()
    return try DeploymentTLSIdentity(
        deploymentID: deploymentID,
        host: "server.test",
        port: 8443,
        caDER: material.caDER,
        caFingerprintSHA256: material.caFingerprint
    )
}

private func makeManagerSigningIdentity() throws -> ManagerSigningIdentity {
    try ManagerSigningIdentity(
        storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation
    )
}

private func authorityJSON(
    deploymentID: String = authorityDeploymentID,
    key: String = String(repeating: "a", count: 64),
    generation: Int64 = 1
) -> Data {
    let object: [String: Any] = [
        "deployment_id": deploymentID,
        "grant_signing_public_key": key,
        "authority_generation": generation,
    ]
    // swiftlint:disable:next force_try
    return try! JSONSerialization.data(withJSONObject: object)
}

@Suite("Deployment authority observation over pinned transport")
struct DeploymentAuthorityObservationTests {
    @Test("Fetch validates and returns the canonical tuple without adopting it")
    func fetchReturnsCanonicalTuple() async throws {
        let identity = try await makePinnedIdentity(deploymentID: authorityDeploymentID)
        let transport = AuthorityTransport(body: authorityJSON(generation: 7))
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: identity,
            signingIdentity: try makeManagerSigningIdentity()
        )

        let observed = try await client.fetchDeploymentAuthority()
        #expect(observed.deploymentID == authorityDeploymentID)
        #expect(observed.grantSigningPublicKeyHex == String(repeating: "a", count: 64))
        #expect(observed.authorityGeneration == 7)
        #expect(await transport.lastRequest?.url?.path == "/v2/deployment/authority")
        #expect(await transport.lastRequest?.value(forHTTPHeaderField: "Authorization") == nil)
    }

    @Test("Fetch refuses a different deployment identity")
    func fetchRefusesDifferentDeployment() async throws {
        let identity = try await makePinnedIdentity(deploymentID: authorityDeploymentID)
        let transport = AuthorityTransport(body: authorityJSON(deploymentID: secondAuthorityDeploymentID))
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: identity,
            signingIdentity: try makeManagerSigningIdentity()
        )

        await #expect(throws: HelicoidError.self) {
            try await client.fetchDeploymentAuthority()
        }
    }

    @Test("Fetch refuses noncanonical keys and nonpositive generations")
    func fetchRefusesMalformedAuthority() async throws {
        let identity = try await makePinnedIdentity(deploymentID: authorityDeploymentID)
        let transport = AuthorityTransport()
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: identity,
            signingIdentity: try makeManagerSigningIdentity()
        )
        let badBodies = [
            authorityJSON(key: String(repeating: "A", count: 64)),
            authorityJSON(key: String(repeating: "g", count: 64)),
            authorityJSON(key: String(repeating: "a", count: 63)),
            authorityJSON(generation: 0),
            authorityJSON(generation: -1),
        ]
        for body in badBodies {
            await transport.setResponse(status: 200, body: body)
            await #expect(throws: HelicoidError.self) {
                try await client.fetchDeploymentAuthority()
            }
        }
    }

    @Test("Fetch refuses a non-200 authority reply")
    func fetchRefusesNon200() async throws {
        let identity = try await makePinnedIdentity(deploymentID: authorityDeploymentID)
        let transport = AuthorityTransport(
            status: 503,
            body: Data(#"{"error":{"code":"unavailable","message":"paused","detail":""}}"#.utf8)
        )
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: identity,
            signingIdentity: try makeManagerSigningIdentity()
        )

        await #expect(throws: HelicoidError.self) {
            try await client.fetchDeploymentAuthority()
        }
    }
}

@Suite("Production Core TLS binding gates")
struct ManagerProductionTLSBindingTests {
    private func makeStore() -> ManagerAuthorityTrustStore {
        ManagerAuthorityTrustStore(
            keyStore: AuthorityKeyFixtureStore(),
            authorityLock: NoopAuthorityLock()
        )
    }

    private func seedAtomicRecord(
        _ store: ManagerAuthorityTrustStore,
        identity: DeploymentTLSIdentity,
        checkpoint: DeploymentAuthorityCheckpoint
    ) async throws -> ManagerAuthorityTrustRecord {
        let configuration = ManagerProductionTrustConfiguration(tlsIdentity: identity)
        let record = try ManagerAuthorityTrustRecord(
            checkpoint: checkpoint,
            configurationData: try configuration.encodedForTrustRecord()
        )
        let result = try await store.commitProductionTrustRecord(
            record,
            expected: nil,
            confirmation: try operatorConfirmation(
                generation: checkpoint.authorityGeneration
            )
        )
        #expect(result == .committed)
        return record
    }

    @Test("makeVerifiedClient refuses a substituted TLS origin")
    func makeVerifiedClientRefusesSubstitutedOrigin() async throws {
        let store = makeStore()
        let checkpoint = try makeCheckpoint(generation: 7)
        let identity = try await makePinnedIdentity(deploymentID: authorityDeploymentID)
        _ = try await seedAtomicRecord(store, identity: identity, checkpoint: checkpoint)
        let substituted = try DeploymentTLSIdentity(
            deploymentID: identity.deploymentID,
            host: "other.example",
            port: identity.port,
            caDER: identity.caDER,
            caFingerprintSHA256: identity.caFingerprintSHA256
        )
        let connection = ManagerProductionConnection(
            tlsIdentity: substituted,
            authorityTrust: store
        )

        await #expect(throws: HelicoidError.self) {
            _ = try await connection.makeVerifiedClient(
                signingIdentity: try makeManagerSigningIdentity()
            )
        }
    }

    @Test("makeVerifiedClient refuses a substituted deployment CA")
    func makeVerifiedClientRefusesSubstitutedCA() async throws {
        let store = makeStore()
        let checkpoint = try makeCheckpoint(generation: 7)
        let identity = try await makePinnedIdentity(deploymentID: authorityDeploymentID)
        _ = try await seedAtomicRecord(store, identity: identity, checkpoint: checkpoint)
        let material = try await TLSTestHarness.sharedMaterial()
        let substituted = try DeploymentTLSIdentity(
            deploymentID: identity.deploymentID,
            host: identity.host,
            port: identity.port,
            caDER: material.foreignCADER,
            caFingerprintSHA256: DeploymentTLSIdentity.sha256Hex(material.foreignCADER)
        )
        let connection = ManagerProductionConnection(
            tlsIdentity: substituted,
            authorityTrust: store
        )

        await #expect(throws: HelicoidError.self) {
            _ = try await connection.makeVerifiedClient(
                signingIdentity: try makeManagerSigningIdentity()
            )
        }
    }

    @Test("Observation factory refuses a genuine pinned transport for another identity")
    func observationFactoryRefusesPinnedTransportIdentityMismatch() async throws {
        let store = makeStore()
        let checkpoint = try makeCheckpoint(generation: 7)
        let pinned = try await makePinnedIdentity(deploymentID: authorityDeploymentID)
        let claimed = try DeploymentTLSIdentity(
            deploymentID: pinned.deploymentID,
            host: "claimed.example",
            port: pinned.port,
            caDER: pinned.caDER,
            caFingerprintSHA256: pinned.caFingerprintSHA256
        )
        _ = try await seedAtomicRecord(
            store,
            identity: claimed,
            checkpoint: checkpoint
        )
        let configuration = try PinnedHTTPSConfiguration(identity: pinned)
        let transport = try PinnedHTTPSTransport(configuration: configuration)
        let signingIdentity = try makeManagerSigningIdentity()
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: claimed,
            signingIdentity: signingIdentity
        )
        #expect(!client.isProductionPinned)

        await #expect(throws: HelicoidError.self) {
            _ = try await ManagerObservationLeaseClient.make(
                authClient: client,
                tlsIdentity: claimed,
                authorityTrust: store,
                signingIdentity: signingIdentity
            )
        }
        #expect(transport.activeOperationCount == 0)
    }

    @Test("makeVerifiedClient refuses a checkpoint-only record")
    func makeVerifiedClientRefusesCheckpointOnly() async throws {
        let store = makeStore()
        let checkpoint = try makeCheckpoint(generation: 7)
        _ = try await store.adopt(
            checkpoint,
            confirmation: try operatorConfirmation(generation: 7)
        )
        let identity = try await makePinnedIdentity(deploymentID: authorityDeploymentID)
        let connection = ManagerProductionConnection(
            tlsIdentity: identity,
            authorityTrust: store
        )

        await #expect(throws: HelicoidError.self) {
            _ = try await connection.makeVerifiedClient(
                signingIdentity: try makeManagerSigningIdentity()
            )
        }
    }
}
