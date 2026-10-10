import CryptoKit
import Foundation
import Security

/// Signing identity survives launches. Private bytes never leave the key store API.
public struct ManagerSigningIdentity: Sendable {
    private let key: Curve25519.Signing.PrivateKey

    init(storedBytes: Data) throws {
        guard storedBytes.count == 33, storedBytes.first == 1 else {
            throw HelicoidError.authenticationFailed(detail: "The stored Manager identity is invalid. It was not replaced.")
        }
        key = try Curve25519.Signing.PrivateKey(rawRepresentation: storedBytes.dropFirst())
    }

    public var publicKey: Data { key.publicKey.rawRepresentation }

    /// Signs the shared contract's canonical message, including its domain tag.
    public func sign(canonicalMessage: Data) throws -> Data {
        guard !canonicalMessage.isEmpty, canonicalMessage.count <= 65_536 else {
            throw HelicoidError.invalidInput(field: "Identity proof", detail: "The signing message is empty or exceeds its size limit.")
        }
        return try key.signature(for: canonicalMessage)
    }
}

protocol ManagerIdentityKeyStoring: Sendable {
    func read() async throws -> Data?
    /// Atomic insert. False means another Manager already inserted its identity.
    func insertIfAbsent(_ bytes: Data) async throws -> Bool
}

public actor ManagerIdentityStore {
    private let keyStore: any ManagerIdentityKeyStoring

    public init() { keyStore = KeychainManagerIdentityKeyStore() }
    init(keyStore: any ManagerIdentityKeyStoring) { self.keyStore = keyStore }

    public func loadOrCreate() async throws -> ManagerSigningIdentity {
        if let stored = try await keyStore.read() { return try ManagerSigningIdentity(storedBytes: stored) }
        let generated = Curve25519.Signing.PrivateKey()
        let bytes = Data([1]) + generated.rawRepresentation
        if try await keyStore.insertIfAbsent(bytes) { return try ManagerSigningIdentity(storedBytes: bytes) }
        guard let winner = try await keyStore.read() else {
            throw HelicoidError.authenticationFailed(detail: "The Manager identity could not be saved. Setup is stopped.")
        }
        return try ManagerSigningIdentity(storedBytes: winner)
    }
}

private actor KeychainManagerIdentityKeyStore: ManagerIdentityKeyStoring {
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "systems.helicoid.manager.signing-identity.v1",
         kSecAttrAccount as String: "manager-ed25519",
         kSecAttrSynchronizable as String: false]
    }

    func read() throws -> Data? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let bytes = item as? Data else { throw failure() }
        return bytes
    }

    func insertIfAbsent(_ bytes: Data) throws -> Bool {
        var request = query
        request[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        request[kSecAttrLabel as String] = "Helicoid Manager signing identity"
        request[kSecValueData as String] = bytes
        let status = SecItemAdd(request as CFDictionary, nil)
        if status == errSecDuplicateItem { return false }
        guard status == errSecSuccess else { throw failure() }
        return true
    }

    private func failure() -> HelicoidError {
        .authenticationFailed(detail: "Keychain could not read or save the Manager identity. Unlock your login Keychain and retry.")
    }
}
