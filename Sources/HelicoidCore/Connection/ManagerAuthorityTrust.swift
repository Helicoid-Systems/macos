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

/// Durable, per-deployment Manager authority checkpoint.
///
/// The checkpoint is stored in the unlocked login Keychain with
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
        let account = try DeploymentAuthorityCheckpoint.canonicalDeploymentID(deploymentID)
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        return try await load(account: account)
    }

    /// Adopt one observed tuple after a separate operator confirmation.
    ///
    /// The observed tuple must already have been read over the pinned deployment
    /// origin. This method never fetches it, so an unauthenticated network reply
    /// cannot create trust by itself.
    ///
    /// The whole read-check-write sequence is protected by the cross-process
    /// lock. Additional writers that bypass this store are outside the threat
    /// model; they are not made safe by a best-effort re-read.
    ///
    /// - Initial adoption: saves the tuple only when the confirmation matches all
    ///   three fields.
    /// - Existing checkpoint: a lower generation is refused, a same-generation
    ///   key change is refused, and a higher generation replaces the tuple only
    ///   with a fresh matching confirmation. An identical tuple is idempotent.
    @discardableResult
    public func adopt(
        _ observed: DeploymentAuthorityCheckpoint,
        confirmation: ManagerAuthorityConfirmation
    ) async throws -> DeploymentAuthorityCheckpoint {
        try Self.requireConfirmation(confirmation, matches: observed)

        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()

        if let current = try await load(account: observed.deploymentID) {
            try Self.requireAllowedTransition(from: current, to: observed)
            if current == observed {
                return current
            }
        }
        // Cancellation before the write must leave the old checkpoint intact.
        try Self.throwIfCancelled()
        try await write(observed)
        return observed
    }

    /// Require the server's current authority to exactly match the saved
    /// checkpoint. Missing, rolled-back, or key-changed state fails closed.
    ///
    /// This is a point-in-time check. Callers should run it again before each
    /// later protected operation rather than caching admission indefinitely.
    @discardableResult
    public func requireCurrent(
        _ observed: DeploymentAuthorityCheckpoint
    ) async throws -> DeploymentAuthorityCheckpoint {
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        guard let saved = try await load(account: observed.deploymentID) else {
            throw HelicoidError.identityMismatch
        }
        guard saved == observed else {
            throw HelicoidError.identityMismatch
        }
        return saved
    }

    /// Remove local trust for one deployment. This is an explicit local recovery
    /// action; it never substitutes network observation for a checkpoint.
    public func clear(deploymentID: String) async throws {
        let account = try DeploymentAuthorityCheckpoint.canonicalDeploymentID(deploymentID)
        let lock = try await authorityLock.acquire()
        defer { lock.release() }
        try Self.throwIfCancelled()
        try await keyStore.delete(account: account)
    }

    // MARK: - Internal validation and persistence

    private func load(account: String) async throws -> DeploymentAuthorityCheckpoint? {
        guard let data = try await keyStore.read(account: account) else {
            return nil
        }
        return try Self.decode(data, expectedDeploymentID: account)
    }

    /// Write only while the caller holds the authority lock. The caller has
    /// already validated the transition against the current checkpoint.
    private func write(_ checkpoint: DeploymentAuthorityCheckpoint) async throws {
        let stored = StoredManagerAuthorityCheckpoint(
            version: 1,
            deploymentID: checkpoint.deploymentID,
            grantSigningPublicKeyHex: checkpoint.grantSigningPublicKeyHex,
            authorityGeneration: checkpoint.authorityGeneration
        )
        let data: Data
        do {
            data = try JSONEncoder().encode(stored)
        } catch {
            throw HelicoidError.authenticationFailed(
                detail: "The deployment authority checkpoint could not be encoded. It was not saved."
            )
        }

        let account = checkpoint.deploymentID
        if try await keyStore.insertIfAbsent(data, account: account) {
            return
        }
        try await keyStore.update(data, account: account)
    }

    private static func decode(
        _ data: Data,
        expectedDeploymentID: String
    ) throws -> DeploymentAuthorityCheckpoint {
        guard let stored = try? JSONDecoder().decode(StoredManagerAuthorityCheckpoint.self, from: data),
              stored.version == 1,
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
            return checkpoint
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
}

private struct StoredManagerAuthorityCheckpoint: Codable {
    let version: Int
    let deploymentID: String
    let grantSigningPublicKeyHex: String
    let authorityGeneration: UInt64
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
