import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

private actor IdentityFixtureStore: ManagerIdentityKeyStoring {
    var bytes: Data?
    var failing = false
    private(set) var insertions = 0
    init(bytes: Data? = nil, failing: Bool = false) { self.bytes = bytes; self.failing = failing }
    func read() throws -> Data? {
        if failing { throw HelicoidError.offline }
        return bytes
    }
    func insertIfAbsent(_ new: Data) throws -> Bool {
        if failing { throw HelicoidError.offline }
        guard bytes == nil else { return false }
        bytes = new
        insertions += 1
        return true
    }
}

@Suite("Persistent Manager signing identity")
struct ManagerSigningIdentityTests {
    @Test func savedIdentitySignsAndReopens() async throws {
        let store = IdentityFixtureStore()
        let first = try await ManagerIdentityStore(keyStore: store).loadOrCreate()
        let second = try await ManagerIdentityStore(keyStore: store).loadOrCreate()
        #expect(first.publicKey == second.publicKey)
        #expect(await store.insertions == 1)
        let message = Data("HS-MANAGER-PROOF-V2\0actual-challenge".utf8)
        let signature = try first.sign(canonicalMessage: message)
        let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: second.publicKey)
        #expect(verifier.isValidSignature(signature, for: message))
        #expect(!verifier.isValidSignature(signature, for: message + Data([0])))
    }

    @Test func corruptOrUnsupportedStoredIdentityNeverRotates() async {
        for value in [Data(), Data([2]) + Data(repeating: 1, count: 32), Data(repeating: 1, count: 34)] {
            let store = IdentityFixtureStore(bytes: value)
            await #expect(throws: (any Error).self) { try await ManagerIdentityStore(keyStore: store).loadOrCreate() }
            #expect(await store.insertions == 0)
        }
    }

    @Test func persistenceFaultReturnsNoIdentity() async {
        let store = IdentityFixtureStore(failing: true)
        await #expect(throws: HelicoidError.offline) { try await ManagerIdentityStore(keyStore: store).loadOrCreate() }
        #expect(await store.insertions == 0)
    }

    @Test func competingCreatorsUsePersistedWinner() async throws {
        let store = IdentityFixtureStore()
        async let a = ManagerIdentityStore(keyStore: store).loadOrCreate()
        async let b = ManagerIdentityStore(keyStore: store).loadOrCreate()
        let keys = try await [a.publicKey, b.publicKey]
        #expect(keys[0] == keys[1])
        #expect(await store.insertions == 1)
    }

    @Test func signingIsBounded() throws {
        let identity = try ManagerSigningIdentity(storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation)
        for message in [Data(), Data(repeating: 0, count: 65_537)] {
            #expect(throws: (any Error).self) { try identity.sign(canonicalMessage: message) }
        }
    }
}
