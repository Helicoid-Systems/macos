import CryptoKit
import Darwin
import Foundation
import Security

/// One validated deployment authority tuple.
///
/// The tuple is the server-owned deployment ID, the Ed25519 grant-verification
/// public key, and the durable authority generation.
///
/// This type validates wire/persistence shape. It never fetches, adopts, or
/// vouches for values by itself, and it does not create trust from a health
/// response or any other unauthenticated network reply. Provenance is not
/// mechanically enforced by this type: a caller can construct it from any
/// source. Trust admission requires a separately supplied operator
/// confirmation plus the checkpoint store's monotonic rules.
public struct DeploymentAuthorityCheckpoint: Sendable, Hashable {
    /// The server's canonical deployment ID shape: `dep_` + 32 lowercase hex.
    public static let deploymentIDLength = 36
    /// Ed25519 public keys are 32 bytes, encoded as 64 lowercase hex chars.
    public static let grantSigningPublicKeyHexLength = 64
    /// The server stores the generation as a positive signed 64-bit integer.
    public static let maxAuthorityGeneration = UInt64(Int64.max)

    public let deploymentID: String
    public let grantSigningPublicKeyHex: String
    public let authorityGeneration: UInt64
    /// SHA-256 of the decoded 32-byte public key, lowercase hex.
    public let grantSigningKeyFingerprintSHA256: String

    public init(
        deploymentID: String,
        grantSigningPublicKeyHex: String,
        authorityGeneration: UInt64
    ) throws {
        let canonicalID = try Self.canonicalDeploymentID(deploymentID)
        guard let keyBytes = Self.decodeCanonicalPublicKeyHex(grantSigningPublicKeyHex) else {
            throw HelicoidError.invalidInput(
                field: "grant_signing_public_key",
                detail: "The authority key must be 64 lowercase hexadecimal characters."
            )
        }
        guard authorityGeneration > 0,
              authorityGeneration <= Self.maxAuthorityGeneration else {
            throw HelicoidError.invalidInput(
                field: "authority_generation",
                detail: "The authority generation must be between 1 and \(Self.maxAuthorityGeneration)."
            )
        }

        self.deploymentID = canonicalID
        self.grantSigningPublicKeyHex = grantSigningPublicKeyHex
        self.authorityGeneration = authorityGeneration
        self.grantSigningKeyFingerprintSHA256 = DeploymentTLSIdentity.sha256Hex(keyBytes)
    }

    /// Canonicalize and validate the deployment identity used for both the
    /// Keychain account and the trust comparison. Surrounding whitespace is
    /// removed; any other deviation is refused rather than repaired.
    static func canonicalDeploymentID(_ raw: String) throws -> String {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.hasPrefix("dep_"), value.count == deploymentIDLength else {
            throw HelicoidError.invalidInput(
                field: "deployment_id",
                detail: "Deployment id must be 'dep_' followed by 32 lowercase hexadecimal characters."
            )
        }
        let suffix = value.dropFirst(4)
        guard suffix.count == 32, suffix.allSatisfy({ $0.isLowercaseHexDigit }) else {
            throw HelicoidError.invalidInput(
                field: "deployment_id",
                detail: "Deployment id must be 'dep_' followed by 32 lowercase hexadecimal characters."
            )
        }
        return value
    }

    /// Lowercase-only canonical key encoding. Uppercase hex is refused so the
    /// persisted tuple has exactly one representation.
    static func decodeCanonicalPublicKeyHex(_ value: String) -> Data? {
        guard value.count == grantSigningPublicKeyHexLength,
              value.allSatisfy({ $0.isLowercaseHexDigit }) else {
            return nil
        }
        var bytes = Data(capacity: grantSigningPublicKeyHexLength / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }
}

/// One atomic production trust record: authority checkpoint plus the typed
/// TLS configuration that was independently verified for that authority.
///
/// Both fields live in one Keychain item and are written together under the
/// deployment authority lock. A checkpoint-only legacy record has
/// `configurationData == nil` and must be reset rather than reused with a new
/// or substituted origin.
public struct ManagerAuthorityTrustRecord: Sendable, Equatable {
    /// The encoded configuration is JSON containing a base64 CA DER, so leave
    /// room for the 65,536-byte CA limit plus encoding overhead.
    public static let maxConfigurationBytes = 131_072

    public let checkpoint: DeploymentAuthorityCheckpoint
    public let configurationData: Data?

    public init(
        checkpoint: DeploymentAuthorityCheckpoint,
        configurationData: Data?
    ) throws {
        if let configurationData, configurationData.count > Self.maxConfigurationBytes {
            throw HelicoidError.invalidInput(
                field: "configuration_data",
                detail: "The production trust configuration exceeded its size limit."
            )
        }
        self.checkpoint = checkpoint
        self.configurationData = configurationData
    }
}

public enum ManagerTrustCommitResult: Sendable, Equatable {
    case committed
    case recordChanged
    case confirmationMismatch
    case transitionRefused
}

/// Raw state of one persisted production trust record. Used by explicit reset
/// so an unreadable record can be deleted with a raw-byte compare-and-swap
/// rather than an unconditional delete.
public enum ManagerProductionTrustRecordState: Sendable, Equatable {
    case absent
    case present(ManagerAuthorityTrustRecord)
    case unreadable(Data)
}

extension ManagerAuthorityTrustRecord {
    /// Decode and validate the complete typed TLS binding stored in this record.
    ///
    /// A checkpoint-only record, a corrupt configuration, or a configuration
    /// whose deployment does not match the checkpoint fails closed.
    public func boundConfiguration() throws -> ManagerProductionTrustConfiguration {
        guard let data = configurationData else {
            throw HelicoidError.authenticationFailed(
                detail: "The production trust record has no atomically bound TLS configuration. Reset production trust or explicitly replace it."
            )
        }
        let configuration: ManagerProductionTrustConfiguration
        do {
            configuration = try ManagerProductionTrustConfiguration.decodeFromTrustRecord(data)
        } catch {
            throw HelicoidError.authenticationFailed(
                detail: "The production trust record's TLS configuration could not be read. Reset production trust or explicitly replace it."
            )
        }
        guard configuration.deploymentID == checkpoint.deploymentID else {
            throw HelicoidError.authenticationFailed(
                detail: "The saved production TLS configuration is not bound to the same deployment as its authority checkpoint. Reset production trust or explicitly replace it."
            )
        }
        return configuration
    }

    /// Require this record to bind exactly the supplied pinned TLS identity,
    /// including deployment ID, host, port, CA DER, and CA pin.
    public func requireBoundTLSIdentity(_ identity: DeploymentTLSIdentity) throws {
        guard try boundConfiguration().tlsIdentity == identity else {
            throw HelicoidError.identityMismatch
        }
    }
}

/// An exact record expectation that a production trust commit must revalidate
/// under the same lock as the proposed write. Callers use this to make a
/// pre-network snapshot of several deployments coherent without gaining any
/// general-purpose lock or write capability.
public struct ManagerAuthorityTrustExpectation: Sendable, Equatable {
    public let deploymentID: String
    public let record: ManagerAuthorityTrustRecord?

    public init(
        deploymentID: String,
        record: ManagerAuthorityTrustRecord?
    ) throws {
        self.deploymentID = try DeploymentAuthorityCheckpoint.canonicalDeploymentID(
            deploymentID
        )
        if let record, record.checkpoint.deploymentID != self.deploymentID {
            throw HelicoidError.identityMismatch
        }
        self.record = record
    }
}

/// A separate, explicit operator confirmation of one authority tuple.
///
/// Construct this only from values the operator entered or read through a
/// trusted organization channel, for example a server administrator reading the
/// authority locally and the operator comparing the deployment ID, key
/// fingerprint, and numeric generation.
///
/// There is intentionally no initializer that accepts a checkpoint or observed
/// network response. Swift cannot mechanically prove that the three values came
/// from an independent channel; this type is a policy boundary, not a
/// cryptographic attestation. UI and callers must not prefill these fields from
/// the same network reply they are supposed to verify.
public struct ManagerAuthorityConfirmation: Sendable, Hashable {
    public let deploymentID: String
    public let grantSigningKeyFingerprintSHA256: String
    public let authorityGeneration: UInt64

    public init(
        operatorEnteredDeploymentID: String,
        operatorEnteredKeyFingerprintSHA256: String,
        operatorEnteredAuthorityGeneration: UInt64
    ) throws {
        self.deploymentID = try DeploymentAuthorityCheckpoint.canonicalDeploymentID(
            operatorEnteredDeploymentID
        )
        guard operatorEnteredKeyFingerprintSHA256.count == 64,
              operatorEnteredKeyFingerprintSHA256.allSatisfy({ $0.isLowercaseHexDigit }) else {
            throw HelicoidError.invalidInput(
                field: "grant_signing_key_fingerprint",
                detail: "The confirmed key fingerprint must be a 64-character lowercase SHA-256 hex string."
            )
        }
        guard operatorEnteredAuthorityGeneration > 0,
              operatorEnteredAuthorityGeneration <= DeploymentAuthorityCheckpoint.maxAuthorityGeneration else {
            throw HelicoidError.invalidInput(
                field: "authority_generation",
                detail: "The confirmed authority generation must be between 1 and \(DeploymentAuthorityCheckpoint.maxAuthorityGeneration)."
            )
        }
        self.grantSigningKeyFingerprintSHA256 = operatorEnteredKeyFingerprintSHA256
        self.authorityGeneration = operatorEnteredAuthorityGeneration
    }
}

/// Durable, per-deployment Manager production trust record.
///
/// The checkpoint and its typed TLS configuration are stored together in one
/// Keychain item. The item is stored in the unlocked login Keychain with
/// `WhenUnlockedThisDeviceOnly` and is not synchronized. Every read, check, and
/// write that participates in trust runs while holding one exclusive
/// cross-process file lock. The lock file is in a private owner-only Manager
/// directory and uses kernel `flock`, which is released automatically when its
/// process exits. This makes the read-check-write sequence atomic among all
/// processes that use this store.
///
/// The lock cannot protect against a process that writes the Keychain item
/// without using this store. That is why the threat model treats this source as
/// the only Manager authority writer. Malformed or unreadable stored state
/// fails closed and is never silently replaced. Adoption requires a separate
/// `ManagerAuthorityConfirmation`; monotonic generation rules refuse rollback
/// or a same-generation signing-key change.
public actor ManagerAuthorityTrustStore {
    private let keyStore: any ManagerAuthorityKeyStoring
    private let authorityLock: any ManagerAuthorityLocking

    /// Production store backed by the macOS Keychain and the default
    /// cross-process authority lock.
    public init() {
        self.keyStore = KeychainManagerAuthorityKeyStore()
        self.authorityLock = POSIXManagerAuthorityLock()
    }

    /// Internal test seam. Production callers use the public initializer.
    init(
        keyStore: any ManagerAuthorityKeyStoring,
        authorityLock: any ManagerAuthorityLocking
    ) {
        self.keyStore = keyStore
        self.authorityLock = authorityLock
    }

    /// Read and validate the saved checkpoint for one deployment.
    ///
    /// - Returns: `nil` only when no checkpoint has ever been adopted.
    /// - Throws: `HelicoidError` when protected bytes are unreadable or invalid.
    ///   In that case the caller must not infer trust from the network.
    public func savedCheckpoint(deploymentID: String) async throws -> DeploymentAuthorityCheckpoint? {
        try await productionTrustRecord(deploymentID: deploymentID)?.checkpoint
    }

    /// Read the single atomic production trust record for one deployment.
    /// `configurationData == nil` denotes a legacy checkpoint-only record that
    /// must not be reused with a substituted TLS configuration.
    public func productionTrustRecord(
        deploymentID: String
    ) async throws -> ManagerAuthorityTrustRecord? {
        let account = try DeploymentAuthorityCheckpoint.canonicalDeploymentID(deploymentID)
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        return try await loadRecord(account: account)
    }

    /// Read one record together with its raw bytes so an unreadable record can
    /// later be deleted with an exact raw-byte compare-and-swap.
    public func productionTrustRecordState(
        deploymentID: String
    ) async throws -> ManagerProductionTrustRecordState {
        let account = try DeploymentAuthorityCheckpoint.canonicalDeploymentID(deploymentID)
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        guard let data = try await keyStore.read(account: account) else {
            return .absent
        }
        do {
            return .present(try Self.decodeRecord(data, expectedDeploymentID: account))
        } catch {
            return .unreadable(data)
        }
    }

    /// Adopt one checkpoint-only tuple after a separate operator confirmation.
    ///
    /// This compatibility API refuses config-bound production trust records;
    /// those must be changed through `commitProductionTrustRecord` so the TLS
    /// configuration cannot be separated from the checkpoint.
    @discardableResult
    public func adopt(
        _ observed: DeploymentAuthorityCheckpoint,
        confirmation: ManagerAuthorityConfirmation
    ) async throws -> DeploymentAuthorityCheckpoint {
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        return try await adoptLocked(observed, confirmation: confirmation)
    }

    /// Require the server's current authority to exactly match the saved
    /// checkpoint. Missing, rolled-back, or key-changed state fails closed.
    @discardableResult
    public func requireCurrent(
        _ observed: DeploymentAuthorityCheckpoint
    ) async throws -> DeploymentAuthorityCheckpoint {
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        return try await requireCurrentLocked(observed)
    }

    /// Remove local trust for one deployment. Internal recovery only; production
    /// reset goes through the same-state-checked delete APIs.
    func clear(deploymentID: String) async throws {
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        try await clearLocked(deploymentID: deploymentID)
    }

    /// Return every locally saved deployment checkpoint account. The caller can
    /// use this to target recovery without deleting unrelated deployments.
    public func savedDeploymentIDs() async throws -> [String] {
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        // Ignore unrelated accounts that may have been placed under this
        // Keychain service by an external writer or an older format.
        return try await keyStore.allAccounts()
            .filter {
                (try? DeploymentAuthorityCheckpoint.canonicalDeploymentID($0)) != nil
            }
            .sorted()
    }

    /// Compare-and-swap one complete production trust record under the authority
    /// lock. The checkpoint and typed TLS configuration are written as one
    /// Keychain item; the store never persists them as two separately written
    /// values.
    ///
    /// `alsoRequiring` lets a caller revalidate additional deployment records
    /// that were part of the same pre-network snapshot. All checks and the write
    /// happen under one lock; no lock object or unrestricted write capability is
    /// exposed to the caller.
    public func commitProductionTrustRecord(
        _ proposed: ManagerAuthorityTrustRecord,
        expected: ManagerAuthorityTrustRecord?,
        alsoRequiring expectations: [ManagerAuthorityTrustExpectation] = [],
        confirmation: ManagerAuthorityConfirmation?
    ) async throws -> ManagerTrustCommitResult {
        let account = try DeploymentAuthorityCheckpoint.canonicalDeploymentID(
            proposed.checkpoint.deploymentID
        )
        guard account == proposed.checkpoint.deploymentID else {
            return .recordChanged
        }
        // This is the atomic production trust writer. The typed TLS binding is
        // validated in Core before anything is written: a checkpoint-only,
        // corrupt, or mismatched configuration must never be persisted here.
        do {
            _ = try proposed.boundConfiguration()
        } catch {
            return .transitionRefused
        }
        if let expected,
           expected.checkpoint.deploymentID != proposed.checkpoint.deploymentID {
            return .recordChanged
        }
        for expectation in expectations
        where expectation.deploymentID != account {
            if let record = expectation.record,
               record.checkpoint.deploymentID != expectation.deploymentID {
                return .recordChanged
            }
        }

        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()

        let current = try await loadRecord(account: account)
        guard current == expected else { return .recordChanged }

        for expectation in expectations
        where expectation.deploymentID != account {
            let other = try await loadRecord(account: expectation.deploymentID)
            guard other == expectation.record else { return .recordChanged }
        }

        if let confirmation {
            do {
                try Self.requireConfirmation(
                    confirmation,
                    matches: proposed.checkpoint
                )
            } catch {
                return .confirmationMismatch
            }
            if let currentCheckpoint = current?.checkpoint {
                do {
                    try Self.requireAllowedTransition(
                        from: currentCheckpoint,
                        to: proposed.checkpoint
                    )
                } catch {
                    return .transitionRefused
                }
            }
        } else {
            // Without a fresh confirmation the whole record, including the
            // typed TLS configuration, must be unchanged. A caller may
            // re-assert an already verified record but can never silently
            // change the origin that is bound to an unchanged authority tuple.
            guard current == proposed else {
                return .transitionRefused
            }
        }

        if current == proposed {
            // A verified record can be re-asserted without an unnecessary
            // Keychain write.
            return .committed
        }
        try await writeRecord(proposed)
        return .committed
    }

    /// Verify that the exact record still matches under the lock. No write.
    public func verifyProductionTrustRecord(
        _ expected: ManagerAuthorityTrustRecord?,
        deploymentID: String
    ) async throws -> Bool {
        let account = try DeploymentAuthorityCheckpoint.canonicalDeploymentID(deploymentID)
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        return try await loadRecord(account: account) == expected
    }

    /// Same-state-checked delete of one production trust record. Returns false
    /// without deleting when the current record differs from `expected`.
    public func deleteProductionTrustRecord(
        deploymentID: String,
        expected: ManagerAuthorityTrustRecord?
    ) async throws -> Bool {
        let account = try DeploymentAuthorityCheckpoint.canonicalDeploymentID(deploymentID)
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        let current = try await loadRecord(account: account)
        guard current == expected else { return false }
        if current == nil { return true }
        try await keyStore.delete(account: account)
        return true
    }

    /// Delete one record only if its raw stored bytes still equal `expected`.
    /// This is the recovery path for an unreadable record: it never deletes a
    /// record that another process replaced after the state was observed.
    public func deleteProductionTrustRecord(
        deploymentID: String,
        expectedRawBytes: Data?
    ) async throws -> Bool {
        let account = try DeploymentAuthorityCheckpoint.canonicalDeploymentID(deploymentID)
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        let current = try await keyStore.read(account: account)
        guard current == expectedRawBytes else { return false }
        if current == nil { return true }
        try await keyStore.delete(account: account)
        return true
    }

    // MARK: - Locked helpers

    private func adoptLocked(
        _ observed: DeploymentAuthorityCheckpoint,
        confirmation: ManagerAuthorityConfirmation
    ) async throws -> DeploymentAuthorityCheckpoint {
        try Self.requireConfirmation(confirmation, matches: observed)
        if let current = try await loadRecord(account: observed.deploymentID) {
            guard current.configurationData == nil else {
                throw HelicoidError.authenticationFailed(
                    detail: "This deployment has an atomic TLS-bound trust record. Use the atomic production trust record API to change it."
                )
            }
            try Self.requireAllowedTransition(from: current.checkpoint, to: observed)
            if current.checkpoint == observed {
                return current.checkpoint
            }
        }
        try Self.throwIfCancelled()
        let record = try ManagerAuthorityTrustRecord(
            checkpoint: observed,
            configurationData: nil
        )
        try await writeRecord(record)
        return observed
    }

    private func requireCurrentLocked(
        _ observed: DeploymentAuthorityCheckpoint
    ) async throws -> DeploymentAuthorityCheckpoint {
        guard let saved = try await loadRecord(account: observed.deploymentID) else {
            throw HelicoidError.identityMismatch
        }
        guard saved.checkpoint == observed else {
            throw HelicoidError.identityMismatch
        }
        return saved.checkpoint
    }

    private func clearLocked(deploymentID: String) async throws {
        let account = try DeploymentAuthorityCheckpoint.canonicalDeploymentID(deploymentID)
        try await keyStore.delete(account: account)
    }

    private func loadRecord(account: String) async throws -> ManagerAuthorityTrustRecord? {
        guard let data = try await keyStore.read(account: account) else {
            return nil
        }
        return try Self.decodeRecord(data, expectedDeploymentID: account)
    }

    private func writeRecord(_ record: ManagerAuthorityTrustRecord) async throws {
        let stored = StoredManagerAuthorityCheckpoint(
            version: 2,
            deploymentID: record.checkpoint.deploymentID,
            grantSigningPublicKeyHex: record.checkpoint.grantSigningPublicKeyHex,
            authorityGeneration: record.checkpoint.authorityGeneration,
            configurationData: record.configurationData
        )
        let data: Data
        do {
            data = try JSONEncoder().encode(stored)
        } catch {
            throw HelicoidError.authenticationFailed(
                detail: "The production trust record could not be encoded. It was not saved."
            )
        }

        let account = record.checkpoint.deploymentID
        if try await keyStore.insertIfAbsent(data, account: account) {
            return
        }
        try await keyStore.update(data, account: account)
    }

    private static func decodeRecord(
        _ data: Data,
        expectedDeploymentID: String
    ) throws -> ManagerAuthorityTrustRecord {
        guard let stored = try? JSONDecoder().decode(
            StoredManagerAuthorityCheckpoint.self,
            from: data
        ),
        (stored.version == 1 || stored.version == 2),
        stored.deploymentID == expectedDeploymentID else {
            throw HelicoidError.identityMismatch
        }
        do {
            let checkpoint = try DeploymentAuthorityCheckpoint(
                deploymentID: stored.deploymentID,
                grantSigningPublicKeyHex: stored.grantSigningPublicKeyHex,
                authorityGeneration: stored.authorityGeneration
            )
            guard checkpoint.deploymentID == expectedDeploymentID else {
                throw HelicoidError.identityMismatch
            }
            return try ManagerAuthorityTrustRecord(
                checkpoint: checkpoint,
                configurationData: stored.configurationData
            )
        } catch {
            throw HelicoidError.identityMismatch
        }
    }

    private static func throwIfCancelled() throws {
        if Task.isCancelled {
            throw HelicoidError.cancelled
        }
    }

    private static func requireConfirmation(
        _ confirmation: ManagerAuthorityConfirmation,
        matches observed: DeploymentAuthorityCheckpoint
    ) throws {
        guard confirmation.deploymentID == observed.deploymentID,
              confirmation.grantSigningKeyFingerprintSHA256 == observed.grantSigningKeyFingerprintSHA256,
              confirmation.authorityGeneration == observed.authorityGeneration else {
            throw HelicoidError.identityMismatch
        }
    }

    private static func requireAllowedTransition(
        from current: DeploymentAuthorityCheckpoint,
        to next: DeploymentAuthorityCheckpoint
    ) throws {
        guard current.deploymentID == next.deploymentID else {
            throw HelicoidError.identityMismatch
        }
        guard next.authorityGeneration >= current.authorityGeneration else {
            // Rollback is refused even with a fresh confirmation. Local recovery
            // must clear and explicitly re-adopt instead.
            throw HelicoidError.identityMismatch
        }
        guard next.authorityGeneration > current.authorityGeneration ||
                next.grantSigningPublicKeyHex == current.grantSigningPublicKeyHex else {
            // The signing key must not change without a generation increase.
            throw HelicoidError.identityMismatch
        }
    }
}

// MARK: - Cross-process lock

protocol ManagerAuthorityLockReleasing: Sendable {
    func release()
}

protocol ManagerAuthorityLocking: Sendable {
    func acquire() async throws -> any ManagerAuthorityLockReleasing
}

/// Exclusive advisory lock backed by `flock`.
///
/// The trusted ancestor chain is walked with `openat` + `O_NOFOLLOW`; every
/// directory must be a real directory owned by root or the effective user and
/// not writable by group or other. The leaf `AuthorityTrust` directory must be
/// owned by the effective user with no group/other permissions. Its descriptor
/// stays open for the lock's lifetime and the lock file is opened with
/// `openat` so an ancestor cannot be replaced between validation and use.
///
/// The production home directory comes from the password database, not `HOME`
/// or another process environment variable.
///
/// `flock` is held for the complete read-check-write sequence and is released
/// by the kernel if the process exits.
struct POSIXManagerAuthorityLock: ManagerAuthorityLocking {
    private static let lockFileName = "authority-trust.lock"
    private static let acquisitionTimeout: Duration = .seconds(2)
    private static let retryInterval: Duration = .milliseconds(20)
    private static let managerComponents = [
        "Library", "Application Support", "Helicoid", "Manager", "AuthorityTrust",
    ]

    private let rootURL: URL?
    private let relativeComponents: [String]
    private let configurationFailure: String?

    /// Production lock rooted at `/`, with the password-database home path
    /// followed by `Library/Application Support/Helicoid/Manager/AuthorityTrust`.
    init() {
        guard let home = Self.stableHomeDirectory() else {
            self.rootURL = nil
            self.relativeComponents = []
            self.configurationFailure = "The Manager authority lock cannot locate the signed-in user's home directory."
            return
        }
        let homeComponents = home
            .split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)
        self.rootURL = URL(fileURLWithPath: "/", isDirectory: true)
        self.relativeComponents = homeComponents + Self.managerComponents
        self.configurationFailure = nil
    }

    /// Internal test seam. `trustedRootURL` is the already-trusted starting
    /// directory; `relativeComponents` are walked beneath it with `openat`.
    init(trustedRootURL: URL, relativeComponents: [String]) {
        self.rootURL = trustedRootURL
        self.relativeComponents = relativeComponents
        self.configurationFailure = nil
    }

    func acquire() async throws -> any ManagerAuthorityLockReleasing {
        let directoryDescriptor = try openTrustedLeafDirectory()
        let lockDescriptor: Int32
        do {
            lockDescriptor = try openLockFile(in: directoryDescriptor)
        } catch {
            close(directoryDescriptor)
            throw error
        }
        do {
            try await Self.acquireExclusive(lockDescriptor)
        } catch {
            close(lockDescriptor)
            close(directoryDescriptor)
            throw error
        }
        return POSIXManagerAuthorityLockHandle(
            lockDescriptor: lockDescriptor,
            directoryDescriptor: directoryDescriptor
        )
    }

    /// Walk from the trusted root to the leaf with `openat`/`O_NOFOLLOW`,
    /// creating missing directories with mode 0700. The returned descriptor is
    /// the held leaf directory; the caller owns and must close it.
    private func openTrustedLeafDirectory() throws -> Int32 {
        guard let rootURL, configurationFailure == nil else {
            throw HelicoidError.authenticationFailed(
                detail: configurationFailure ?? "The Manager authority lock is not configured."
            )
        }
        var current = rootURL.path.withCString {
            open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard current >= 0 else {
            throw HelicoidError.authenticationFailed(
                detail: "The Manager authority lock root could not be opened safely."
            )
        }

        for (index, component) in relativeComponents.enumerated() {
            guard Self.isSafePathComponent(component) else {
                close(current)
                throw HelicoidError.authenticationFailed(
                    detail: "The Manager authority lock path contains an unsafe component."
                )
            }
            var next = component.withCString {
                openat(current, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            if next < 0 && errno == ENOENT {
                let mkdirResult = component.withCString {
                    mkdirat(current, $0, 0o700)
                }
                if mkdirResult != 0 && errno != EEXIST {
                    close(current)
                    throw HelicoidError.authenticationFailed(
                        detail: "The Manager authority lock directory could not be created."
                    )
                }
                next = component.withCString {
                    openat(current, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                }
            }
            close(current)
            guard next >= 0 else {
                throw HelicoidError.authenticationFailed(
                    detail: "The Manager authority lock directory chain is not safe."
                )
            }

            var info = stat()
            let isLeaf = index == relativeComponents.count - 1
            guard fstat(next, &info) == 0,
                  (info.st_mode & S_IFMT) == S_IFDIR,
                  Self.trustedDirectoryOwner(info.st_uid),
                  (info.st_mode & (S_IWGRP | S_IWOTH)) == 0,
                  !isLeaf || (info.st_uid == geteuid() && (info.st_mode & 0o077) == 0) else {
                close(next)
                throw HelicoidError.authenticationFailed(
                    detail: "The Manager authority lock directory chain is not private to this user."
                )
            }
            current = next
        }
        return current
    }

    private func openLockFile(in directoryDescriptor: Int32) throws -> Int32 {
        let descriptor = Self.lockFileName.withCString {
            // O_NONBLOCK keeps a malicious FIFO from blocking open(); the
            // regular-file check below rejects it immediately.
            openat(
                directoryDescriptor,
                $0,
                O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                0o600
            )
        }
        guard descriptor >= 0 else {
            throw HelicoidError.authenticationFailed(
                detail: "The Manager authority lock file could not be opened safely."
            )
        }

        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_nlink == 1,
              info.st_uid == geteuid(),
              (info.st_mode & 0o077) == 0 else {
            close(descriptor)
            throw HelicoidError.authenticationFailed(
                detail: "The Manager authority lock file is not private to this user."
            )
        }
        return descriptor
    }

    private static func acquireExclusive(_ descriptor: Int32) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now + Self.acquisitionTimeout
        while true {
            if flock(descriptor, LOCK_EX | LOCK_NB) == 0 {
                return
            }
            let code = errno
            if code == EINTR {
                continue
            }
            guard code == EWOULDBLOCK || code == EAGAIN else {
                throw HelicoidError.authenticationFailed(
                    detail: "The Manager authority lock could not be acquired."
                )
            }
            guard clock.now < deadline else {
                throw HelicoidError.authenticationFailed(
                    detail: "Another Manager authority update is still in progress. Try again."
                )
            }
            do {
                try await Task.sleep(for: Self.retryInterval)
            } catch {
                throw HelicoidError.cancelled
            }
        }
    }

    private static func stableHomeDirectory() -> String? {
        // `getpwuid_r` reads the password database; it does not trust HOME or
        // any other ambient process environment.
        var entry = passwd()
        var result: UnsafeMutablePointer<passwd>?
        let requested = Int(sysconf(_SC_GETPW_R_SIZE_MAX))
        var buffer = [CChar](repeating: 0, count: max(requested, 4_096))
        let status = buffer.withUnsafeMutableBufferPointer { pointer in
            getpwuid_r(geteuid(), &entry, pointer.baseAddress, pointer.count, &result)
        }
        guard status == 0, let result, let directory = result.pointee.pw_dir else {
            return nil
        }
        return String(cString: directory)
    }

    private static func trustedDirectoryOwner(_ uid: uid_t) -> Bool {
        uid == 0 || uid == geteuid()
    }

    private static func isSafePathComponent(_ component: String) -> Bool {
        !component.isEmpty &&
            component != "." &&
            component != ".." &&
            !component.contains("/") &&
            !component.contains("\0")
    }
}

// Justified @unchecked Sendable: both descriptors are guarded by `lock`, and
// release is idempotent across `defer` and `deinit`.
private final class POSIXManagerAuthorityLockHandle: ManagerAuthorityLockReleasing, @unchecked Sendable {
    private let lock = NSLock()
    private var lockDescriptor: Int32
    private var directoryDescriptor: Int32

    init(lockDescriptor: Int32, directoryDescriptor: Int32) {
        self.lockDescriptor = lockDescriptor
        self.directoryDescriptor = directoryDescriptor
    }

    func release() {
        lock.lock()
        defer { lock.unlock() }
        if lockDescriptor >= 0 {
            _ = flock(lockDescriptor, LOCK_UN)
            close(lockDescriptor)
            lockDescriptor = -1
        }
        if directoryDescriptor >= 0 {
            close(directoryDescriptor)
            directoryDescriptor = -1
        }
    }

    deinit {
        release()
    }
}

// MARK: - Persistence seam

protocol ManagerAuthorityKeyStoring: Sendable {
    func read(account: String) async throws -> Data?
    func insertIfAbsent(_ bytes: Data, account: String) async throws -> Bool
    func update(_ bytes: Data, account: String) async throws
    func delete(account: String) async throws
    func allAccounts() async throws -> [String]
}

private struct StoredManagerAuthorityCheckpoint: Codable {
    let version: Int
    let deploymentID: String
    let grantSigningPublicKeyHex: String
    let authorityGeneration: UInt64
    let configurationData: Data?
}

private actor KeychainManagerAuthorityKeyStore: ManagerAuthorityKeyStoring {
    private static let service = "systems.helicoid.manager.deployment-authority.v1"

    private func query(account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: Self.service,
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }

    func read(account: String) throws -> Data? {
        var request = query(account: account)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let bytes = item as? Data else { throw failure() }
        return bytes
    }

    func insertIfAbsent(_ bytes: Data, account: String) throws -> Bool {
        var request = query(account: account)
        request[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        request[kSecAttrLabel as String] = "Helicoid Manager deployment authority checkpoint"
        request[kSecValueData as String] = bytes
        let status = SecItemAdd(request as CFDictionary, nil)
        if status == errSecDuplicateItem { return false }
        guard status == errSecSuccess else { throw failure() }
        return true
    }

    func update(_ bytes: Data, account: String) throws {
        let status = SecItemUpdate(
            query(account: account) as CFDictionary,
            [kSecValueData as String: bytes] as CFDictionary
        )
        guard status == errSecSuccess else { throw failure() }
    }

    func delete(account: String) throws {
        let status = SecItemDelete(query(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw failure() }
    }

    func allAccounts() throws -> [String] {
        let request: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrSynchronizable as String: false,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &item)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let item else { throw failure() }
        if let rows = item as? [Any] {
            return rows.compactMap { row in
                (row as? [String: Any])?[kSecAttrAccount as String] as? String
            }
        }
        if let row = item as? [String: Any],
           let account = row[kSecAttrAccount as String] as? String {
            return [account]
        }
        throw failure()
    }

    private func failure() -> HelicoidError {
        .authenticationFailed(
            detail: "The deployment authority checkpoint could not be read or saved in the unlocked macOS Keychain."
        )
    }
}

private extension Character {
    var isLowercaseHexDigit: Bool {
        guard let ascii = asciiValue else { return false }
        return (0x30...0x39).contains(ascii) || (0x61...0x66).contains(ascii)
    }
}
