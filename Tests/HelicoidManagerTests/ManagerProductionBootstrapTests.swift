import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore
@testable import HelicoidManager

private let bootstrapDeploymentID = "dep_00000000000000000000000000000005"
private let secondBootstrapDeploymentID = "dep_00000000000000000000000000000006"
private let bootstrapAuthorityKeyA = String(repeating: "a", count: 64)
private let bootstrapAuthorityKeyB = String(repeating: "b", count: 64)
private let bootstrapAuthorityFingerprintA =
    "e0e77a507412b120f6ede61f62295b1a7b2ff19d3dcc8f7253e51663470c888e"
private let bootstrapAuthorityFingerprintB =
    "4ca14526b2751b640d549ce7caf8ac39438592211a0ec370064d57666a682ad6"

private actor BootstrapAuthorityKeyStore: ManagerAuthorityKeyStoring {
    private var values: [String: Data] = [:]
    private(set) var insertions = 0
    private(set) var deleteAttempts = 0
    private var failDelete = false
    private var failRead = false
    private var failInsert = false
    private var failUpdate = false

    func read(account: String) throws -> Data? {
        if failRead {
            throw HelicoidError.authenticationFailed(detail: "fixture read failure")
        }
        return values[account]
    }

    func insertIfAbsent(_ bytes: Data, account: String) throws -> Bool {
        if failInsert {
            throw HelicoidError.authenticationFailed(detail: "fixture insert failure")
        }
        guard values[account] == nil else { return false }
        values[account] = bytes
        insertions += 1
        return true
    }

    func update(_ bytes: Data, account: String) throws {
        if failUpdate {
            throw HelicoidError.authenticationFailed(detail: "fixture update failure")
        }
        guard values[account] != nil else { throw HelicoidError.offline }
        values[account] = bytes
    }

    func delete(account: String) throws {
        deleteAttempts += 1
        if failDelete { throw HelicoidError.offline }
        values.removeValue(forKey: account)
    }

    func allAccounts() -> [String] { Array(values.keys) }

    func seed(_ bytes: Data, account: String) { values[account] = bytes }
    func rawValue(account: String) -> Data? { values[account] }
    func setFailDelete(_ value: Bool) { failDelete = value }
    func setFailRead(_ value: Bool) { failRead = value }
    func setFailInsert(_ value: Bool) { failInsert = value }
    func setFailUpdate(_ value: Bool) { failUpdate = value }
}

private actor BootstrapCallCounter {
    private(set) var count = 0
    func increment() { count += 1 }
}

private actor BootstrapGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private(set) var entered = false

    func pause() async {
        entered = true
        await withCheckedContinuation { continuation = $0 }
    }

    func release() {
        continuation?.resume()
        continuation = nil
    }
}

private func waitForBootstrapCondition(
    _ condition: @Sendable () async -> Bool
) async throws {
    for _ in 0..<300 {
        if await condition() { return }
        try await Task.sleep(for: .milliseconds(10))
    }
    Issue.record("Timed out waiting for bootstrap test condition.")
}

private actor BootstrapTransport: HTTPTransport {
    private let authorityBody: Data
    private let healthStatus: Int
    private(set) var authorityRequests = 0
    private(set) var healthRequests = 0

    init(authorityBody: Data, healthStatus: Int = 200) {
        self.authorityBody = authorityBody
        self.healthStatus = healthStatus
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        guard let url = request.url else {
            throw HelicoidError.invalidInput(field: "request", detail: "Missing URL.")
        }
        switch url.path {
        case "/v2/deployment/authority":
            authorityRequests += 1
            return try response(url: url, status: 200, body: authorityBody)
        case "/health":
            healthRequests += 1
            return try response(
                url: url,
                status: healthStatus,
                body: Data(#"{"status":"ok"}"#.utf8)
            )
        default:
            throw HelicoidError.unreachable
        }
    }

    private func response(url: URL, status: Int, body: Data) throws -> (Data, URLResponse) {
        let response = HTTPURLResponse(
            url: url,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        return (body, response)
    }
}

/// Test-only CA fixture (allowed in tests, never normal operation).
private let bootstrapCADERHex = "3082019030820135a00302010202142f2d30f1e37fdf3db4f30d8fdf8728741175b71b300a06082a8648ce3d04030230153113301106035504030c0a48532d546573742d4341301e170d3236313031363135333434365a170d3336313031333135333434365a30153113301106035504030c0a48532d546573742d43413059301306072a8648ce3d020106082a8648ce3d030107034200045dda8b60404df01b54df24ff5be48548d57ee450d0d34016a3f917e964d4258ea20c94821c4d8fde270f7370d403b1b6d4a00d8be30ddd2c9c4ff7f96e108830a3633061301d0603551d0e04160414110d92f6818de0787dcf793d09154c449fcd5a33301f0603551d23041830168014110d92f6818de0787dcf793d09154c449fcd5a33300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020204300a06082a8648ce3d040302034900304602210090e960a7cbc20680e19c9af2859397890b074166c6da5d571f5f71577f80e60f022100f60d9460317df7434ac3f97ff9d9ebff66e8024063b6d6ead5ed477383301443"

private func bootstrapBytes(hex: String) -> Data {
    var bytes = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        bytes.append(UInt8(hex[index..<next], radix: 16)!)
        index = next
    }
    return bytes
}

private func bootstrapCAPin() -> String {
    DeploymentTLSIdentity.sha256Hex(bootstrapCA())
}

private func bootstrapCA() -> Data {
    bootstrapBytes(hex: bootstrapCADERHex)
}

private func makeBootstrapIdentity() throws -> ManagerSigningIdentity {
    try ManagerSigningIdentity(
        storedBytes: Data([1]) + Curve25519.Signing.PrivateKey().rawRepresentation
    )
}

private func makeBootstrapTLSIdentity(
    deploymentID: String = bootstrapDeploymentID,
    host: String = "server.test",
    port: Int = 8443
) throws -> DeploymentTLSIdentity {
    try DeploymentTLSIdentity(
        deploymentID: deploymentID,
        host: host,
        port: port,
        caDER: bootstrapCA(),
        caFingerprintSHA256: bootstrapCAPin()
    )
}

private func makeBootstrapAuthorityCheckpoint(
    deploymentID: String = bootstrapDeploymentID,
    keyHex: String = bootstrapAuthorityKeyA,
    generation: UInt64 = 7
) throws -> DeploymentAuthorityCheckpoint {
    try DeploymentAuthorityCheckpoint(
        deploymentID: deploymentID,
        grantSigningPublicKeyHex: keyHex,
        authorityGeneration: generation
    )
}

private func bootstrapAuthorityJSON(
    keyHex: String = bootstrapAuthorityKeyA,
    generation: Int = 7
) -> Data {
    let object: [String: Any] = [
        "deployment_id": bootstrapDeploymentID,
        "grant_signing_public_key": keyHex,
        "authority_generation": generation,
    ]
    // swiftlint:disable:next force_try
    return try! JSONSerialization.data(withJSONObject: object)
}

private func makeBootstrapStore(
    keyStore: BootstrapAuthorityKeyStore = BootstrapAuthorityKeyStore()
) -> ManagerAuthorityTrustStore {
    ManagerAuthorityTrustStore(
        keyStore: keyStore,
        authorityLock: POSIXManagerAuthorityLock(
            trustedRootURL: FileManager.default.temporaryDirectory,
            relativeComponents: ["HelicoidBootstrapLock-\(UUID().uuidString)"]
        )
    )
}

private func makeTrustConfiguration(
    deploymentID: String = bootstrapDeploymentID,
    host: String = "server.test",
    port: Int = 8443
) throws -> ManagerProductionTrustConfiguration {
    try ManagerProductionTrustConfiguration(
        deploymentID: deploymentID,
        host: host,
        port: port,
        caDER: bootstrapCA(),
        caFingerprintSHA256: bootstrapCAPin()
    )
}

private func makeTrustRecord(
    checkpoint: DeploymentAuthorityCheckpoint,
    configuration: ManagerProductionTrustConfiguration?
) throws -> ManagerAuthorityTrustRecord {
    try ManagerAuthorityTrustRecord(
        checkpoint: checkpoint,
        configurationData: try configuration.map { try $0.encodedForTrustRecord() }
    )
}

private func confirmation(
    for checkpoint: DeploymentAuthorityCheckpoint
) throws -> ManagerAuthorityConfirmation {
    try ManagerAuthorityConfirmation(
        operatorEnteredDeploymentID: checkpoint.deploymentID,
        operatorEnteredKeyFingerprintSHA256: checkpoint.grantSigningKeyFingerprintSHA256,
        operatorEnteredAuthorityGeneration: checkpoint.authorityGeneration
    )
}

@discardableResult
private func seedTrustRecord(
    _ store: ManagerAuthorityTrustStore,
    checkpoint: DeploymentAuthorityCheckpoint,
    configuration: ManagerProductionTrustConfiguration?
) async throws -> ManagerAuthorityTrustRecord {
    let record = try makeTrustRecord(
        checkpoint: checkpoint,
        configuration: configuration
    )
    let result = try await store.commitProductionTrustRecord(
        record,
        expected: nil,
        confirmation: try confirmation(for: checkpoint)
    )
    #expect(result == .committed)
    return record
}

@discardableResult
private func seedLegacyCheckpoint(
    _ store: ManagerAuthorityTrustStore,
    checkpoint: DeploymentAuthorityCheckpoint
) async throws -> DeploymentAuthorityCheckpoint {
    try await store.adopt(
        checkpoint,
        confirmation: try confirmation(for: checkpoint)
    )
}

@Suite("Production Manager bootstrap")
@MainActor
struct ManagerProductionBootstrapTests {
    // MARK: - Configuration and record shape

    @Test("Configuration validation refuses a CA pin mismatch")
    func configurationRefusesPinMismatch() throws {
        #expect(throws: HelicoidError.self) {
            try ManagerProductionTrustConfiguration(
                deploymentID: bootstrapDeploymentID,
                host: "server.test",
                port: 8443,
                caDER: bootstrapCA(),
                caFingerprintSHA256: String(repeating: "f", count: 64)
            )
        }
    }

    @Test("Configuration JSON round-trips and revalidates the CA pin")
    func configurationJSONRevalidatesPin() throws {
        let configuration = try makeTrustConfiguration()
        let data = try configuration.encodedForTrustRecord()
        let decoded = try ManagerProductionTrustConfiguration.decodeFromTrustRecord(data)
        #expect(decoded == configuration)

        var object = try #require(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        object["caFingerprintSHA256"] = String(repeating: "f", count: 64)
        let tampered = try JSONSerialization.data(withJSONObject: object)
        #expect(throws: (any Error).self) {
            try ManagerProductionTrustConfiguration.decodeFromTrustRecord(tampered)
        }
    }

    @Test("Trust records cap the opaque configuration size")
    func trustRecordCapsConfigurationSize() throws {
        let checkpoint = try makeBootstrapAuthorityCheckpoint()
        #expect(throws: HelicoidError.self) {
            try ManagerAuthorityTrustRecord(
                checkpoint: checkpoint,
                configurationData: Data(
                    repeating: 0,
                    count: ManagerAuthorityTrustRecord.maxConfigurationBytes + 1
                )
            )
        }
    }

    // MARK: - Atomic record store

    @Test("A commit stores checkpoint and TLS configuration in one record")
    func commitStoresOneAtomicRecord() async throws {
        let keyStore = BootstrapAuthorityKeyStore()
        let store = makeBootstrapStore(keyStore: keyStore)
        let checkpoint = try makeBootstrapAuthorityCheckpoint()
        let configuration = try makeTrustConfiguration()
        let record = try await seedTrustRecord(
            store,
            checkpoint: checkpoint,
            configuration: configuration
        )

        let loaded = try await store.productionTrustRecord(
            deploymentID: checkpoint.deploymentID
        )
        #expect(loaded == record)
        #expect(loaded?.checkpoint == checkpoint)
        let loadedConfiguration = try #require(loaded?.configurationData)
        #expect(
            try ManagerProductionTrustConfiguration.decodeFromTrustRecord(loadedConfiguration)
                == configuration
        )
        #expect(try await store.savedCheckpoint(deploymentID: checkpoint.deploymentID) == checkpoint)
    }

    @Test("Commit requires the exact expected record")
    func commitRequiresExactExpectedRecord() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint(generation: 7)
        _ = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let advanced = try makeBootstrapAuthorityCheckpoint(generation: 8)
        let proposed = try makeTrustRecord(
            checkpoint: advanced,
            configuration: try makeTrustConfiguration()
        )

        let stale = try await store.commitProductionTrustRecord(
            proposed,
            expected: nil,
            confirmation: try confirmation(for: advanced)
        )
        #expect(stale == .recordChanged)
        #expect(try await store.savedCheckpoint(
            deploymentID: trusted.deploymentID
        ) == trusted)

        let current = try await store.productionTrustRecord(
            deploymentID: trusted.deploymentID
        )
        let committed = try await store.commitProductionTrustRecord(
            proposed,
            expected: current,
            confirmation: try confirmation(for: advanced)
        )
        #expect(committed == .committed)
        #expect(try await store.savedCheckpoint(
            deploymentID: trusted.deploymentID
        ) == advanced)
    }

    @Test("Commit revalidates additional snapshot deployments under one lock")
    func commitRevalidatesAdditionalSnapshotExpectations() async throws {
        let store = makeBootstrapStore()
        let first = try makeBootstrapAuthorityCheckpoint()
        let second = try makeBootstrapAuthorityCheckpoint(
            deploymentID: secondBootstrapDeploymentID,
            generation: 3
        )
        _ = try await seedTrustRecord(
            store,
            checkpoint: first,
            configuration: try makeTrustConfiguration()
        )
        _ = try await seedTrustRecord(
            store,
            checkpoint: second,
            configuration: try makeTrustConfiguration(
                deploymentID: secondBootstrapDeploymentID
            )
        )

        let secondConfiguration = try makeTrustConfiguration(
            deploymentID: secondBootstrapDeploymentID,
            host: "second.test"
        )
        let proposedSecond = try makeTrustRecord(
            checkpoint: second,
            configuration: secondConfiguration
        )
        let currentSecond = try await store.productionTrustRecord(
            deploymentID: secondBootstrapDeploymentID
        )

        let missingFirst = try ManagerAuthorityTrustExpectation(
            deploymentID: first.deploymentID,
            record: nil
        )
        let mismatched = try await store.commitProductionTrustRecord(
            proposedSecond,
            expected: currentSecond,
            alsoRequiring: [missingFirst],
            confirmation: nil
        )
        #expect(mismatched == .recordChanged)
        #expect(try await store.productionTrustRecord(
            deploymentID: secondBootstrapDeploymentID
        ) == currentSecond)

        let currentFirst = try await store.productionTrustRecord(
            deploymentID: first.deploymentID
        )
        let expectedFirst = try ManagerAuthorityTrustExpectation(
            deploymentID: first.deploymentID,
            record: currentFirst
        )
        let committed = try await store.commitProductionTrustRecord(
            proposedSecond,
            expected: currentSecond,
            alsoRequiring: [expectedFirst],
            confirmation: try confirmation(for: second)
        )
        #expect(committed == .committed)
        #expect(try await store.productionTrustRecord(
            deploymentID: secondBootstrapDeploymentID
        ) == proposedSecond)
    }

    @Test("Commit refuses a mismatched confirmation without writing")
    func commitConfirmationMismatchWritesNothing() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint(generation: 7)
        _ = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let current = try await store.productionTrustRecord(
            deploymentID: trusted.deploymentID
        )
        let advanced = try makeBootstrapAuthorityCheckpoint(generation: 8)
        let proposed = try makeTrustRecord(
            checkpoint: advanced,
            configuration: try makeTrustConfiguration()
        )
        let wrong = try ManagerAuthorityConfirmation(
            operatorEnteredDeploymentID: advanced.deploymentID,
            operatorEnteredKeyFingerprintSHA256: bootstrapAuthorityFingerprintB,
            operatorEnteredAuthorityGeneration: 8
        )

        let result = try await store.commitProductionTrustRecord(
            proposed,
            expected: current,
            confirmation: wrong
        )
        #expect(result == .confirmationMismatch)
        #expect(try await store.productionTrustRecord(
            deploymentID: trusted.deploymentID
        ) == current)
    }

    @Test("The atomic commit refuses a checkpoint-only record")
    func commitRefusesCheckpointOnlyRecord() async throws {
        let store = makeBootstrapStore()
        let checkpoint = try makeBootstrapAuthorityCheckpoint()
        let record = try ManagerAuthorityTrustRecord(
            checkpoint: checkpoint,
            configurationData: nil
        )

        let result = try await store.commitProductionTrustRecord(
            record,
            expected: nil,
            confirmation: try confirmation(for: checkpoint)
        )
        #expect(result == .transitionRefused)
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == nil)
    }

    @Test("A commit without confirmation cannot change the bound TLS configuration")
    func commitWithoutConfirmationCannotChangeConfiguration() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint()
        let record = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let replacement = try makeTrustRecord(
            checkpoint: trusted,
            configuration: try makeTrustConfiguration(host: "other.test")
        )

        let result = try await store.commitProductionTrustRecord(
            replacement,
            expected: record,
            confirmation: nil
        )
        #expect(result == .transitionRefused)
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == record)
    }

    @Test("Commit refuses rollback and same-generation key changes")
    func commitRefusesForbiddenTransitions() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint(generation: 7)
        _ = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let current = try await store.productionTrustRecord(
            deploymentID: trusted.deploymentID
        )

        let rollback = try makeBootstrapAuthorityCheckpoint(generation: 6)
        let rollbackProposal = try makeTrustRecord(
            checkpoint: rollback,
            configuration: try makeTrustConfiguration()
        )
        let rollbackResult = try await store.commitProductionTrustRecord(
            rollbackProposal,
            expected: current,
            confirmation: try confirmation(for: rollback)
        )
        #expect(rollbackResult == .transitionRefused)
        #expect(try await store.productionTrustRecord(
            deploymentID: trusted.deploymentID
        ) == current)

        let keyChange = try makeBootstrapAuthorityCheckpoint(
            keyHex: bootstrapAuthorityKeyB,
            generation: 7
        )
        let keyChangeProposal = try makeTrustRecord(
            checkpoint: keyChange,
            configuration: try makeTrustConfiguration()
        )
        let keyChangeResult = try await store.commitProductionTrustRecord(
            keyChangeProposal,
            expected: current,
            confirmation: try confirmation(for: keyChange)
        )
        #expect(keyChangeResult == .transitionRefused)
        #expect(try await store.productionTrustRecord(
            deploymentID: trusted.deploymentID
        ) == current)
    }

    @Test("Delete and verify require the exact record")
    func deleteAndVerifyRequireExactRecord() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint()
        _ = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let current = try #require(
            try await store.productionTrustRecord(deploymentID: trusted.deploymentID)
        )
        #expect(try await store.verifyProductionTrustRecord(
            current,
            deploymentID: trusted.deploymentID
        ))
        #expect(try await store.verifyProductionTrustRecord(
            nil,
            deploymentID: trusted.deploymentID
        ) == false)

        let replacement = try makeTrustRecord(
            checkpoint: trusted,
            configuration: try makeTrustConfiguration(host: "replacement.test")
        )
        let replaced = try await store.commitProductionTrustRecord(
            replacement,
            expected: current,
            confirmation: try confirmation(for: trusted)
        )
        #expect(replaced == .committed)
        #expect(try await store.verifyProductionTrustRecord(
            current,
            deploymentID: trusted.deploymentID
        ) == false)

        let staleDelete = try await store.deleteProductionTrustRecord(
            deploymentID: trusted.deploymentID,
            expected: current
        )
        #expect(staleDelete == false)
        #expect(try await store.productionTrustRecord(
            deploymentID: trusted.deploymentID
        ) == replacement)

        let deleted = try await store.deleteProductionTrustRecord(
            deploymentID: trusted.deploymentID,
            expected: replacement
        )
        #expect(deleted)
        #expect(try await store.productionTrustRecord(
            deploymentID: trusted.deploymentID
        ) == nil)
    }

    @Test("Checkpoint adoption refuses an atomic config-bound record")
    func adoptRefusesConfigBoundRecord() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint(generation: 7)
        let record = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let advanced = try makeBootstrapAuthorityCheckpoint(generation: 8)

        await #expect(throws: HelicoidError.self) {
            _ = try await store.adopt(
                advanced,
                confirmation: try confirmation(for: advanced)
            )
        }
        // The checkpoint-only adoption path must never strip the TLS binding.
        #expect(try await store.productionTrustRecord(
            deploymentID: trusted.deploymentID
        ) == record)
    }

    @Test("Legacy version 1 records decode as checkpoint-only")
    func legacyVersionOneRecordDecodes() async throws {
        let keyStore = BootstrapAuthorityKeyStore()
        let payload = """
        {"version":1,"deploymentID":"\(bootstrapDeploymentID)","grantSigningPublicKeyHex":"\(bootstrapAuthorityKeyA)","authorityGeneration":7}
        """
        await keyStore.seed(Data(payload.utf8), account: bootstrapDeploymentID)
        let store = makeBootstrapStore(keyStore: keyStore)

        let record = try #require(
            try await store.productionTrustRecord(deploymentID: bootstrapDeploymentID)
        )
        #expect(record.checkpoint.grantSigningPublicKeyHex == bootstrapAuthorityKeyA)
        #expect(record.configurationData == nil)
    }

    // MARK: - Bootstrap model: fresh adoption

    @Test("Mismatched operator authority values save nothing")
    func mismatchedOperatorValuesSaveNothing() async throws {
        let store = makeBootstrapStore()
        let observed = try makeBootstrapAuthorityCheckpoint()
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in observed },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        configure(model, keyFingerprint: bootstrapAuthorityFingerprintB, generation: "7")

        await #expect(throws: HelicoidError.self) {
            _ = try await model.prepareTrust()
        }
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == nil)
    }

    @Test("Matching operator values adopt one checkpoint and configuration record")
    func matchingValuesAdoptAndPersist() async throws {
        let keyStore = BootstrapAuthorityKeyStore()
        let store = makeBootstrapStore(keyStore: keyStore)
        let observed = try makeBootstrapAuthorityCheckpoint()
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in observed },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        configure(model, keyFingerprint: bootstrapAuthorityFingerprintA, generation: "7")

        let prepared = try await model.prepareTrust()
        #expect(prepared.checkpoint == observed)
        let record = try #require(
            try await store.productionTrustRecord(deploymentID: bootstrapDeploymentID)
        )
        #expect(record.checkpoint == observed)
        let configurationData = try #require(record.configurationData)
        let configuration = try ManagerProductionTrustConfiguration.decodeFromTrustRecord(
            configurationData
        )
        #expect(configuration.deploymentID == bootstrapDeploymentID)
        #expect(configuration.host == "server.test")
        #expect(configuration.port == 8443)
        #expect(configuration.caFingerprintSHA256 == bootstrapCAPin())
        #expect(await keyStore.insertions == 1)
        #expect(model.savedRecord == record)

        let reloaded = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in observed },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await reloaded.loadSavedConfiguration()
        #expect(reloaded.host == "server.test")
        #expect(reloaded.port == "8443")
        #expect(reloaded.deploymentID == bootstrapDeploymentID)
        #expect(reloaded.caPin == bootstrapCAPin())
        #expect(reloaded.savedCheckpoint == observed)
        #expect(reloaded.savedRecord == record)
    }

    @Test("Saved trust refuses a server generation advance")
    func savedCheckpointRejectsAdvance() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint(generation: 7)
        let record = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let advanced = try makeBootstrapAuthorityCheckpoint(generation: 8)
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in advanced },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()
        #expect(model.savedCheckpoint == trusted)

        await #expect(throws: HelicoidError.self) {
            _ = try await model.prepareTrust()
        }
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == record)
    }

    @Test("Saved trust matching the server needs no new confirmation")
    func savedCheckpointMatchingServerUsesSavedTrust() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint(generation: 7)
        let record = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in trusted },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()
        #expect(!model.needsOperatorTrustValues)
        model.keyFingerprint = ""
        model.generation = ""

        let prepared = try await model.prepareTrust()
        #expect(prepared.checkpoint == trusted)
        #expect(model.savedRecord == record)
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == record)
    }

    @Test("Saved trust refuses changed host, pin, or CA before the network")
    func savedTrustRefusesChangedOrigin() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint(generation: 7)
        let record = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let network = BootstrapCallCounter()
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                await network.increment()
                return trusted
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()

        model.host = "other.example"
        await #expect(throws: HelicoidError.self) {
            _ = try await model.prepareTrust()
        }
        #expect(await network.count == 0)
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == record)

        model.host = "server.test"
        model.caPin = String(repeating: "f", count: 64)
        await #expect(throws: HelicoidError.self) {
            _ = try await model.prepareTrust()
        }
        #expect(await network.count == 0)
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == record)

        model.caPin = bootstrapCAPin()
        model.setCADER(Data(repeating: 0x30, count: 16), fileName: "other.der")
        await #expect(throws: HelicoidError.self) {
            _ = try await model.prepareTrust()
        }
        #expect(await network.count == 0)
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == record)
    }

    @Test("Stale model fails closed after another window replaces the record")
    func staleModelAfterRecordReplacementFailsClosed() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint(generation: 7)
        let original = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let network = BootstrapCallCounter()
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                await network.increment()
                return trusted
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()
        #expect(model.savedRecord == original)

        let replacement = try makeTrustRecord(
            checkpoint: trusted,
            configuration: try makeTrustConfiguration(host: "replacement.test")
        )
        let committed = try await store.commitProductionTrustRecord(
            replacement,
            expected: original,
            confirmation: try confirmation(for: trusted)
        )
        #expect(committed == .committed)

        await #expect(throws: HelicoidError.self) {
            _ = try await model.prepareTrust()
        }
        #expect(await network.count == 0)
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == replacement)
        #expect(model.savedRecord == nil)
        #expect(model.host.isEmpty)
    }

    @Test("Stale model fails closed after another window clears the record")
    func staleModelAfterRecordClearFailsClosed() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint(generation: 7)
        _ = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let network = BootstrapCallCounter()
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                await network.increment()
                return trusted
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()
        try await store.clear(deploymentID: bootstrapDeploymentID)

        await #expect(throws: HelicoidError.self) {
            _ = try await model.prepareTrust()
        }
        #expect(await network.count == 0)
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == nil)
        #expect(model.savedRecord == nil)
    }

    // MARK: - Legacy and mixed records

    @Test("A checkpoint-only record fails closed instead of borrowing a TLS origin")
    func legacyCheckpointOnlyFailsClosed() async throws {
        let keyStore = BootstrapAuthorityKeyStore()
        let store = makeBootstrapStore(keyStore: keyStore)
        let trusted = try makeBootstrapAuthorityCheckpoint(generation: 7)
        _ = try await seedLegacyCheckpoint(store, checkpoint: trusted)
        let network = BootstrapCallCounter()
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                await network.increment()
                return trusted
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()
        #expect(model.savedRecord?.configurationData == nil)
        #expect(model.resetIncomplete)
        #expect(model.errorMessage != nil)
        #expect(model.host.isEmpty)
        #expect(model.needsOperatorTrustValues)

        configure(model, keyFingerprint: bootstrapAuthorityFingerprintA, generation: "7")
        await #expect(throws: HelicoidError.self) {
            _ = try await model.prepareTrust()
        }
        #expect(await network.count == 0)
        #expect(try await store.savedCheckpoint(
            deploymentID: bootstrapDeploymentID
        ) == trusted)
        let legacyRecord = try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        )
        #expect(legacyRecord?.configurationData == nil)
    }

    @Test("Explicit replacement upgrades a checkpoint-only record atomically")
    func explicitReplacementUpgradesLegacyRecord() async throws {
        let keyStore = BootstrapAuthorityKeyStore()
        let store = makeBootstrapStore(keyStore: keyStore)
        let trusted = try makeBootstrapAuthorityCheckpoint(generation: 7)
        _ = try await seedLegacyCheckpoint(store, checkpoint: trusted)
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in trusted },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        model.setReplacingTrust(true)
        configure(model, keyFingerprint: bootstrapAuthorityFingerprintA, generation: "7")

        _ = try await model.prepareTrust()
        let record = try #require(
            try await store.productionTrustRecord(deploymentID: bootstrapDeploymentID)
        )
        #expect(record.checkpoint == trusted)
        let configurationData = try #require(record.configurationData)
        let configuration = try ManagerProductionTrustConfiguration.decodeFromTrustRecord(
            configurationData
        )
        #expect(configuration.host == "server.test")
        #expect(configuration.deploymentID == bootstrapDeploymentID)
    }

    @Test("A mixed record with another deployment's TLS data fails closed")
    func mixedRecordFailsClosed() async throws {
        let keyStore = BootstrapAuthorityKeyStore()
        let store = makeBootstrapStore(keyStore: keyStore)
        let trusted = try makeBootstrapAuthorityCheckpoint()
        let otherConfiguration = try makeTrustConfiguration(
            deploymentID: secondBootstrapDeploymentID
        )
        let otherData = try otherConfiguration.encodedForTrustRecord()
        let payload: [String: Any] = [
            "version": 2,
            "deploymentID": bootstrapDeploymentID,
            "grantSigningPublicKeyHex": bootstrapAuthorityKeyA,
            "authorityGeneration": 7,
            "configurationData": otherData.base64EncodedString(),
        ]
        await keyStore.seed(
            try JSONSerialization.data(withJSONObject: payload),
            account: bootstrapDeploymentID
        )
        let network = BootstrapCallCounter()
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                await network.increment()
                return trusted
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()
        #expect(model.resetIncomplete)
        #expect(model.errorMessage?.contains("not bound to the same deployment") == true)
        #expect(model.host.isEmpty)

        configure(model, keyFingerprint: bootstrapAuthorityFingerprintA, generation: "7")
        await #expect(throws: HelicoidError.self) {
            _ = try await model.prepareTrust()
        }
        #expect(await network.count == 0)
    }

    // MARK: - Reset

    @Test("Reset removes only the selected deployment record")
    func resetRemovesOnlySelectedRecord() async throws {
        let store = makeBootstrapStore()
        let first = try makeBootstrapAuthorityCheckpoint()
        _ = try await seedTrustRecord(
            store,
            checkpoint: first,
            configuration: try makeTrustConfiguration()
        )
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in first },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()
        #expect(model.savedCheckpoint == first)

        let second = try makeBootstrapAuthorityCheckpoint(
            deploymentID: secondBootstrapDeploymentID,
            generation: 3
        )
        let secondRecord = try await seedTrustRecord(
            store,
            checkpoint: second,
            configuration: try makeTrustConfiguration(
                deploymentID: secondBootstrapDeploymentID
            )
        )

        await model.clearSavedTrust()
        #expect(model.savedRecord == nil)
        #expect(model.host.isEmpty)
        #expect(model.port == "8920")
        #expect(model.deploymentID.isEmpty)
        #expect(model.caPin.isEmpty)
        #expect(model.caFileName == nil)
        #expect(model.loadedCAFingerprint == nil)
        #expect(model.keyFingerprint.isEmpty)
        #expect(model.generation.isEmpty)
        #expect(!model.isReplacingTrust)
        #expect(try await store.productionTrustRecord(
            deploymentID: first.deploymentID
        ) == nil)
        #expect(try await store.productionTrustRecord(
            deploymentID: secondBootstrapDeploymentID
        ) == secondRecord)
    }

    @Test("Reset refuses to guess between multiple saved deployments")
    func resetRefusesAmbiguousDeployments() async throws {
        let store = makeBootstrapStore()
        let first = try makeBootstrapAuthorityCheckpoint()
        let second = try makeBootstrapAuthorityCheckpoint(
            deploymentID: secondBootstrapDeploymentID,
            generation: 3
        )
        let firstRecord = try await seedTrustRecord(
            store,
            checkpoint: first,
            configuration: try makeTrustConfiguration()
        )
        let secondRecord = try await seedTrustRecord(
            store,
            checkpoint: second,
            configuration: try makeTrustConfiguration(
                deploymentID: secondBootstrapDeploymentID
            )
        )
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in first },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()
        #expect(model.savedRecord == nil)

        await model.clearSavedTrust()
        #expect(model.resetIncomplete)
        #expect(model.errorMessage?.contains("multiple saved deployments") == true)
        #expect(try await store.productionTrustRecord(
            deploymentID: first.deploymentID
        ) == firstRecord)
        #expect(try await store.productionTrustRecord(
            deploymentID: secondBootstrapDeploymentID
        ) == secondRecord)
    }

    @Test("Typed reset removes only the typed deployment")
    func typedResetRemovesOnlyTypedDeployment() async throws {
        let store = makeBootstrapStore()
        let first = try makeBootstrapAuthorityCheckpoint()
        let second = try makeBootstrapAuthorityCheckpoint(
            deploymentID: secondBootstrapDeploymentID,
            generation: 3
        )
        let firstRecord = try await seedTrustRecord(
            store,
            checkpoint: first,
            configuration: try makeTrustConfiguration()
        )
        _ = try await seedTrustRecord(
            store,
            checkpoint: second,
            configuration: try makeTrustConfiguration(
                deploymentID: secondBootstrapDeploymentID
            )
        )
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in first },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        model.deploymentID = secondBootstrapDeploymentID

        await model.clearSavedTrust()
        #expect(!model.resetIncomplete)
        #expect(model.deploymentID.isEmpty)
        #expect(try await store.productionTrustRecord(
            deploymentID: first.deploymentID
        ) == firstRecord)
        #expect(try await store.productionTrustRecord(
            deploymentID: secondBootstrapDeploymentID
        ) == nil)
    }

    @Test("Stale reset does not delete a record replaced by another window")
    func staleResetDoesNotDeleteReplacedRecord() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint()
        let original = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in trusted },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()
        #expect(model.savedRecord == original)

        let other = try makeBootstrapAuthorityCheckpoint(
            deploymentID: secondBootstrapDeploymentID,
            generation: 3
        )
        let otherRecord = try await seedTrustRecord(
            store,
            checkpoint: other,
            configuration: try makeTrustConfiguration(
                deploymentID: secondBootstrapDeploymentID
            )
        )

        let replacement = try makeTrustRecord(
            checkpoint: trusted,
            configuration: try makeTrustConfiguration(host: "replacement.test")
        )
        let committed = try await store.commitProductionTrustRecord(
            replacement,
            expected: original,
            confirmation: try confirmation(for: trusted)
        )
        #expect(committed == .committed)

        await model.clearSavedTrust()
        #expect(model.resetIncomplete)
        #expect(model.errorMessage?.contains("changed in another window") == true)
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == replacement)
        #expect(try await store.productionTrustRecord(
            deploymentID: secondBootstrapDeploymentID
        ) == otherRecord)
    }

    @Test("A failed reset keeps the form visible and can be retried")
    func failedResetIsRetryable() async throws {
        let keyStore = BootstrapAuthorityKeyStore()
        let store = makeBootstrapStore(keyStore: keyStore)
        let trusted = try makeBootstrapAuthorityCheckpoint()
        let record = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in trusted },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()
        #expect(model.host == "server.test")
        await keyStore.setFailDelete(true)

        await model.clearSavedTrust()
        #expect(model.resetIncomplete)
        #expect(model.needsOperatorTrustValues)
        #expect(model.host == "server.test")
        #expect(model.deploymentID == bootstrapDeploymentID)
        #expect(model.caPin == bootstrapCAPin())
        #expect(model.keyFingerprint == bootstrapAuthorityFingerprintA)
        #expect(model.savedRecord == record)

        await keyStore.setFailDelete(false)
        await model.clearSavedTrust()
        #expect(!model.resetIncomplete)
        #expect(model.savedRecord == nil)
        #expect(model.host.isEmpty)
        #expect(model.deploymentID.isEmpty)
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == nil)
    }

    @Test("Explicit reset removes an unreadable targeted record")
    func resetRemovesUnreadableTargetedRecord() async throws {
        let keyStore = BootstrapAuthorityKeyStore()
        let store = makeBootstrapStore(keyStore: keyStore)
        let corrupt = Data("not-a-trust-record".utf8)
        await keyStore.seed(corrupt, account: bootstrapDeploymentID)
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                try makeBootstrapAuthorityCheckpoint()
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        model.deploymentID = bootstrapDeploymentID

        await model.clearSavedTrust()
        #expect(!model.resetIncomplete)
        #expect(model.deploymentID.isEmpty)
        #expect(await keyStore.rawValue(account: bootstrapDeploymentID) == nil)
    }

    @Test("Unreadable reset cannot delete a record replaced after observation")
    func unreadableResetCannotDeleteReplacedRecord() async throws {
        let keyStore = BootstrapAuthorityKeyStore()
        let store = makeBootstrapStore(keyStore: keyStore)
        let first = Data("unreadable-a".utf8)
        let second = Data("unreadable-b".utf8)
        await keyStore.seed(first, account: bootstrapDeploymentID)

        let state = try await store.productionTrustRecordState(
            deploymentID: bootstrapDeploymentID
        )
        #expect(state == .unreadable(first))

        // Another process replaces the raw item after the state was observed.
        await keyStore.seed(second, account: bootstrapDeploymentID)
        let deleted = try await store.deleteProductionTrustRecord(
            deploymentID: bootstrapDeploymentID,
            expectedRawBytes: first
        )
        #expect(!deleted)
        #expect(await keyStore.rawValue(account: bootstrapDeploymentID) == second)
    }

    @Test("Reset fails closed on a Keychain read failure")
    func resetFailsClosedOnReadFailure() async throws {
        let keyStore = BootstrapAuthorityKeyStore()
        let store = makeBootstrapStore(keyStore: keyStore)
        let corrupt = Data("still-present".utf8)
        await keyStore.seed(corrupt, account: bootstrapDeploymentID)
        await keyStore.setFailRead(true)
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                try makeBootstrapAuthorityCheckpoint()
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        model.deploymentID = bootstrapDeploymentID

        await model.clearSavedTrust()
        #expect(model.resetIncomplete)
        #expect(await keyStore.rawValue(account: bootstrapDeploymentID) == corrupt)
    }

    // MARK: - Concurrency barriers

    @Test("A concurrent reset cannot be undone by an in-flight submit")
    func concurrentResetFencesInFlightSubmit() async throws {
        let store = makeBootstrapStore()
        let trusted = try makeBootstrapAuthorityCheckpoint()
        _ = try await seedTrustRecord(
            store,
            checkpoint: trusted,
            configuration: try makeTrustConfiguration()
        )
        let gate = BootstrapGate()
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                await gate.pause()
                return trusted
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        await model.loadSavedConfiguration()

        let submit = Task { try await model.prepareTrust() }
        try await waitForBootstrapCondition { await gate.entered }
        await model.clearSavedTrust()
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == nil)
        await gate.release()

        await #expect(throws: HelicoidError.self) {
            _ = try await submit.value
        }
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == nil)
        #expect(model.savedRecord == nil)
        #expect(model.host.isEmpty)
    }

    @Test("Concurrent submissions for one deployment cannot overwrite the winner")
    func concurrentSameDeploymentSubmissionsDoNotOverwrite() async throws {
        let store = makeBootstrapStore()
        let checkpoint = try makeBootstrapAuthorityCheckpoint()
        let firstGate = BootstrapGate()
        let secondGate = BootstrapGate()
        let firstModel = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                await firstGate.pause()
                return checkpoint
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        let secondModel = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                await secondGate.pause()
                return checkpoint
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        configure(
            firstModel,
            host: "server.test",
            keyFingerprint: bootstrapAuthorityFingerprintA,
            generation: "7"
        )
        configure(
            secondModel,
            host: "second.test",
            keyFingerprint: bootstrapAuthorityFingerprintA,
            generation: "7"
        )

        let firstSubmit = Task { try await firstModel.prepareTrust() }
        let secondSubmit = Task { try await secondModel.prepareTrust() }
        try await waitForBootstrapCondition {
            let firstEntered = await firstGate.entered
            let secondEntered = await secondGate.entered
            return firstEntered && secondEntered
        }

        await firstGate.release()
        _ = try await firstSubmit.value
        let winner = try #require(
            try await store.productionTrustRecord(deploymentID: bootstrapDeploymentID)
        )
        let winnerConfigurationData = try #require(winner.configurationData)
        let winnerConfiguration = try ManagerProductionTrustConfiguration.decodeFromTrustRecord(
            winnerConfigurationData
        )
        #expect(winnerConfiguration.host == "server.test")

        await secondGate.release()
        await #expect(throws: HelicoidError.self) {
            _ = try await secondSubmit.value
        }
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == winner)
        #expect(secondModel.savedRecord == nil)
        #expect(secondModel.host.isEmpty)
    }

    @Test("Concurrent submissions for different deployments stay independent")
    func concurrentDifferentDeploymentSubmissionsStayIndependent() async throws {
        let store = makeBootstrapStore()
        let first = try makeBootstrapAuthorityCheckpoint()
        let second = try makeBootstrapAuthorityCheckpoint(
            deploymentID: secondBootstrapDeploymentID,
            generation: 3
        )
        let firstGate = BootstrapGate()
        let secondGate = BootstrapGate()
        let firstModel = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                await firstGate.pause()
                return first
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        let secondModel = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { try makeBootstrapIdentity() },
            authorityObserver: { _, _, _ in
                await secondGate.pause()
                return second
            },
            clientFactory: { _, _, _ in throw HelicoidError.cancelled }
        )
        configure(
            firstModel,
            deploymentID: bootstrapDeploymentID,
            host: "server.test",
            keyFingerprint: first.grantSigningKeyFingerprintSHA256,
            generation: "7"
        )
        configure(
            secondModel,
            deploymentID: secondBootstrapDeploymentID,
            host: "second.test",
            keyFingerprint: second.grantSigningKeyFingerprintSHA256,
            generation: "3"
        )

        let firstSubmit = Task { try await firstModel.prepareTrust() }
        let secondSubmit = Task { try await secondModel.prepareTrust() }
        try await waitForBootstrapCondition {
            let firstEntered = await firstGate.entered
            let secondEntered = await secondGate.entered
            return firstEntered && secondEntered
        }
        await firstGate.release()
        await secondGate.release()
        _ = try await firstSubmit.value
        _ = try await secondSubmit.value

        let firstRecord = try #require(
            try await store.productionTrustRecord(deploymentID: bootstrapDeploymentID)
        )
        let secondRecord = try #require(
            try await store.productionTrustRecord(
                deploymentID: secondBootstrapDeploymentID
            )
        )
        #expect(firstRecord.checkpoint == first)
        #expect(secondRecord.checkpoint == second)
        let firstConfigurationData = try #require(firstRecord.configurationData)
        let firstConfiguration = try ManagerProductionTrustConfiguration.decodeFromTrustRecord(
            firstConfigurationData
        )
        let secondConfigurationData = try #require(secondRecord.configurationData)
        let secondConfiguration = try ManagerProductionTrustConfiguration.decodeFromTrustRecord(
            secondConfigurationData
        )
        #expect(firstConfiguration.deploymentID == bootstrapDeploymentID)
        #expect(firstConfiguration.host == "server.test")
        #expect(secondConfiguration.deploymentID == secondBootstrapDeploymentID)
        #expect(secondConfiguration.host == "second.test")
    }

    // MARK: - Session integration

    @Test("Install refuses a record replaced after verification")
    func installRefusesStaleRecord() async throws {
        let store = makeBootstrapStore()
        let observed = try makeBootstrapAuthorityCheckpoint()
        let original = try await seedTrustRecord(
            store,
            checkpoint: observed,
            configuration: try makeTrustConfiguration()
        )
        let transport = BootstrapTransport(authorityBody: bootstrapAuthorityJSON())
        let tlsIdentity = try makeBootstrapTLSIdentity()
        let signingIdentity = try makeBootstrapIdentity()
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: tlsIdentity,
            signingIdentity: signingIdentity,
            timeSource: LiveSessionTimeSource(),
            productionPinnedForTesting: true
        )
        let replacement = try makeTrustRecord(
            checkpoint: observed,
            configuration: try makeTrustConfiguration(host: "replacement.test")
        )
        let committed = try await store.commitProductionTrustRecord(
            replacement,
            expected: original,
            confirmation: try confirmation(for: observed)
        )
        #expect(committed == .committed)
        let session = ManagerSession(configuration: ManagerLaunchConfiguration())

        let installed = await session.installProductionConnection(
            client: client,
            authorityTrust: store,
            serverAddress: tlsIdentity.originURL.absoluteString,
            expectedRecord: original
        )
        #expect(!installed)
        #expect(!session.allowsConnect)
        #expect(session.requiresProductionBootstrap)
    }

    @Test("A genuine pinned transport for another identity is refused before credentials")
    func pinnedTransportIdentityMismatchRefusesBeforeCredentials() async throws {
        let store = makeBootstrapStore()
        let checkpoint = try makeBootstrapAuthorityCheckpoint()
        let pinned = try makeBootstrapTLSIdentity(host: "server.test")
        let claimed = try makeBootstrapTLSIdentity(host: "claimed.example")
        let configuration = try PinnedHTTPSConfiguration(identity: pinned)
        let transport = try PinnedHTTPSTransport(configuration: configuration)
        let signingIdentity = try makeBootstrapIdentity()
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: claimed,
            signingIdentity: signingIdentity
        )
        #expect(!client.isProductionPinned)
        let record = try await seedTrustRecord(
            store,
            checkpoint: checkpoint,
            configuration: try makeTrustConfiguration(host: "claimed.example")
        )
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) == record)

        let installer = ManagerSession(configuration: ManagerLaunchConfiguration())
        let installed = await installer.installProductionConnection(
            client: client,
            authorityTrust: store,
            serverAddress: claimed.originURL.absoluteString,
            expectedRecord: record
        )
        #expect(!installed)
        #expect(!installer.allowsConnect)
        #expect(transport.activeOperationCount == 0)

        let injected = ManagerSession(
            configuration: ManagerLaunchConfiguration(),
            productionAuthClient: client,
            authorityTrust: store
        )
        #expect(!injected.allowsConnect)
        injected.username = "operator"
        injected.password = "pw"
        await injected.connect()
        await injected.signIn()
        #expect(injected.phase == .failed(.identityUnverified))
        #expect(injected.password.isEmpty)
        #expect(transport.activeOperationCount == 0)
    }

    @Test("Install refuses a client bound to a different origin")
    func installRefusesSubstitutedOrigin() async throws {
        let store = makeBootstrapStore()
        let observed = try makeBootstrapAuthorityCheckpoint()
        let record = try await seedTrustRecord(
            store,
            checkpoint: observed,
            configuration: try makeTrustConfiguration()
        )
        let original = try makeBootstrapTLSIdentity()
        let substituted = try DeploymentTLSIdentity(
            deploymentID: original.deploymentID,
            host: "other.example",
            port: original.port,
            caDER: original.caDER,
            caFingerprintSHA256: original.caFingerprintSHA256
        )
        let transport = BootstrapTransport(authorityBody: bootstrapAuthorityJSON())
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: substituted,
            signingIdentity: try makeBootstrapIdentity(),
            timeSource: LiveSessionTimeSource(),
            productionPinnedForTesting: true
        )
        let session = ManagerSession(configuration: ManagerLaunchConfiguration())

        let installed = await session.installProductionConnection(
            client: client,
            authorityTrust: store,
            serverAddress: substituted.originURL.absoluteString,
            expectedRecord: record
        )
        #expect(!installed)
        #expect(!session.allowsConnect)
        #expect(session.requiresProductionBootstrap)
    }

    @Test("Install refuses a checkpoint-only trust record")
    func installRefusesCheckpointOnlyRecord() async throws {
        let store = makeBootstrapStore()
        let observed = try makeBootstrapAuthorityCheckpoint()
        _ = try await seedLegacyCheckpoint(store, checkpoint: observed)
        let identity = try makeBootstrapTLSIdentity()
        let transport = BootstrapTransport(authorityBody: bootstrapAuthorityJSON())
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: identity,
            signingIdentity: try makeBootstrapIdentity(),
            timeSource: LiveSessionTimeSource(),
            productionPinnedForTesting: true
        )
        let session = ManagerSession(configuration: ManagerLaunchConfiguration())

        let installed = await session.installProductionConnection(
            client: client,
            authorityTrust: store,
            serverAddress: identity.originURL.absoluteString
        )
        #expect(!installed)
        #expect(!session.allowsConnect)
        #expect(session.requiresProductionBootstrap)
    }

    @Test("Install refuses a production client without a saved checkpoint")
    func installRefusesMissingCheckpoint() async throws {
        let store = makeBootstrapStore()
        let transport = BootstrapTransport(authorityBody: bootstrapAuthorityJSON())
        let tlsIdentity = try makeBootstrapTLSIdentity()
        let signingIdentity = try makeBootstrapIdentity()
        let client = NativeV2AuthClient(
            transport: transport,
            trustedAuthority: tlsIdentity,
            signingIdentity: signingIdentity,
            timeSource: LiveSessionTimeSource(),
            productionPinnedForTesting: true
        )
        let session = ManagerSession(configuration: ManagerLaunchConfiguration())

        let installed = await session.installProductionConnection(
            client: client,
            authorityTrust: store,
            serverAddress: tlsIdentity.originURL.absoluteString
        )
        #expect(!installed)
        #expect(!session.allowsConnect)
        #expect(session.requiresProductionBootstrap)
    }

    @Test("Verified client installs and connects the production session")
    func verifiedClientInstallsAndConnects() async throws {
        let store = makeBootstrapStore()
        let observed = try makeBootstrapAuthorityCheckpoint()
        let transport = BootstrapTransport(authorityBody: bootstrapAuthorityJSON())
        let tlsIdentity = try makeBootstrapTLSIdentity()
        let signingIdentity = try makeBootstrapIdentity()
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { signingIdentity },
            authorityObserver: { _, _, _ in observed },
            clientFactory: { _, _, _ in
                NativeV2AuthClient(
                    transport: transport,
                    trustedAuthority: tlsIdentity,
                    signingIdentity: signingIdentity,
                    timeSource: LiveSessionTimeSource(),
                    productionPinnedForTesting: true
                )
            }
        )
        configure(model, keyFingerprint: bootstrapAuthorityFingerprintA, generation: "7")
        let session = ManagerSession(configuration: ManagerLaunchConfiguration())

        let connected = await model.connect(into: session)
        #expect(connected)
        #expect(session.allowsConnect)
        #expect(session.phase == .needsSignIn)
        #expect(session.screen == .signIn)
        #expect(await transport.authorityRequests == 1)
        #expect(await transport.healthRequests == 1)
        #expect(try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        ) != nil)
    }

    @Test("Failed server connect returns to production bootstrap")
    func failedConnectReturnsToBootstrap() async throws {
        let store = makeBootstrapStore()
        let observed = try makeBootstrapAuthorityCheckpoint()
        let transport = BootstrapTransport(
            authorityBody: bootstrapAuthorityJSON(),
            healthStatus: 503
        )
        let tlsIdentity = try makeBootstrapTLSIdentity()
        let signingIdentity = try makeBootstrapIdentity()
        let model = ManagerProductionBootstrapModel(
            authorityTrust: store,
            identityProvider: { signingIdentity },
            authorityObserver: { _, _, _ in observed },
            clientFactory: { _, _, _ in
                NativeV2AuthClient(
                    transport: transport,
                    trustedAuthority: tlsIdentity,
                    signingIdentity: signingIdentity,
                    timeSource: LiveSessionTimeSource(),
                    productionPinnedForTesting: true
                )
            }
        )
        configure(model, keyFingerprint: bootstrapAuthorityFingerprintA, generation: "7")
        let session = ManagerSession(configuration: ManagerLaunchConfiguration())

        let connected = await model.connect(into: session)
        #expect(!connected)
        #expect(!session.allowsConnect)
        #expect(session.requiresProductionBootstrap)
        #expect(try await store.savedCheckpoint(
            deploymentID: bootstrapDeploymentID
        ) == observed)
        let savedRecord = try await store.productionTrustRecord(
            deploymentID: bootstrapDeploymentID
        )
        #expect(savedRecord?.configurationData != nil)
    }

    @Test("Bootstrap model exposes guided setup navigation")
    func guidedSetupNavigation() {
        let session = ManagerSession(configuration: ManagerLaunchConfiguration())
        let model = ManagerProductionBootstrapModel()
        model.openGuidedSetup(in: session)
        #expect(session.screen == .guidedSetup)
    }

    // MARK: - Fixtures

    private func configure(
        _ model: ManagerProductionBootstrapModel,
        deploymentID: String = bootstrapDeploymentID,
        host: String = "server.test",
        keyFingerprint: String,
        generation: String
    ) {
        model.host = host
        model.port = "8443"
        model.setCADER(bootstrapCA(), fileName: "ca.der")
        model.caPin = bootstrapCAPin()
        model.deploymentID = deploymentID
        model.keyFingerprint = keyFingerprint
        model.generation = generation
    }
}
