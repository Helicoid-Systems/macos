import CryptoKit
import Foundation
import Testing
@testable import HelicoidCore

private actor EndpointKeyFixtureStore: EndpointEnrollmentKeyStoring {
    var values: [String: Data] = [:]
    private(set) var insertions = 0

    func read(account: String) -> Data? { values[account] }

    func insertIfAbsent(_ bytes: Data, account: String) -> Bool {
        guard values[account] == nil else { return false }
        values[account] = bytes
        insertions += 1
        return true
    }

    func update(_ bytes: Data, account: String) throws {
        guard values[account] != nil else { throw HelicoidError.offline }
        values[account] = bytes
    }

    func delete(account: String) { values.removeValue(forKey: account) }
}

private actor EndpointEnrollmentTransportFixture: HTTPTransport {
    private let responseBody: Data
    private let responseURL: URL
    private(set) var receivedRequests: [URLRequest] = []

    init(responseBody: Data, responseURL: URL) {
        self.responseBody = responseBody
        self.responseURL = responseURL
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        receivedRequests.append(request)
        let isAuthority = request.url?.path == "/v2/deployment/authority"
        let authorityURL = URL(string: "https://helicoid.school.example:8920/v2/deployment/authority")!
        let body = isAuthority
            ? try JSONSerialization.data(withJSONObject: [
                "deployment_id": "deployment-fixture-42",
                "grant_signing_public_key": String(repeating: "a", count: 64),
                "authority_generation": 1,
            ])
            : responseBody
        let response = HTTPURLResponse(url: isAuthority ? authorityURL : responseURL,
                                       statusCode: isAuthority ? 200 : 201,
                                       httpVersion: "HTTP/1.1", headerFields: nil)!
        return (body, response)
    }
}

private struct StoredEndpointFixture: Decodable {
    let version: Int
    let deploymentID: String
    let privateKey: Data
    let result: EndpointEnrollmentResult?
    let serverAddress: String?
    let grantVerificationPublicKeyHex: String?
    let authorityGeneration: Int64?
}

private actor EndpointFileDeliveryTransportFixture: HTTPTransport {
    let origin: URL
    let computerID = "e475b9ca-801a-4f71-b5d5-b87daaaae731"
    let jobID = "8df8cc80-7c11-47cc-958e-47b7557d6e8a"
    let payload = Data("hello".utf8)
    let deploymentID: String
    let grantVerificationKeyHex: String
    let fileJobsEnabled: Bool
    private var authorityGeneration: Int64 = 1
    private(set) var requests: [(String, String?, String?)] = []

    init(
        origin: URL,
        fileJobsEnabled: Bool = true,
        deploymentID: String = "deployment-fixture-42",
        grantVerificationKeyHex: String = String(repeating: "a", count: 64)
    ) {
        self.origin = origin
        self.fileJobsEnabled = fileJobsEnabled
        self.deploymentID = deploymentID
        self.grantVerificationKeyHex = grantVerificationKeyHex
    }

    func setAuthorityGeneration(_ generation: Int64) {
        authorityGeneration = generation
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        let path = request.url!.path
        requests.append((path, request.httpMethod, request.value(forHTTPHeaderField: "Authorization")))
        let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        let status: Int
        let headers: [String: String]?
        let body: Data
        switch path {
        case "/health":
            status = 200
            headers = nil
            body = Data("""
            {"status":"ok","accepting_authorized_operations":true,"schema_version":1,"bootstrap_completed":true,"features":{"file_jobs":\(fileJobsEnabled)}}
            """.utf8)
        case "/v2/endpoints/enroll":
            status = 201
            headers = nil
            body = Data(#"{"computer":{"id":"e475b9ca-801a-4f71-b5d5-b87daaaae731","friendly_name":"Science Mac","platform":"macos","enrollment_state":"pending","enrollment_epoch":1},"state":"pending_approval"}"#.utf8)
        case "/v2/deployment/authority":
            status = 200
            headers = nil
            body = try JSONSerialization.data(withJSONObject: [
                "deployment_id": deploymentID,
                "grant_signing_public_key": grantVerificationKeyHex,
                "authority_generation": authorityGeneration,
            ])
        case "/v2/endpoints/session/challenge":
            let requestJSON = try JSONSerialization.jsonObject(with: request.httpBody!) as! [String: Any]
            let issuedAt = (requestJSON["issued_at_unix"] as! NSNumber).int64Value
            status = 201
            headers = nil
            body = Data("""
            {"challenge_id":"6b3a79c0-a00e-477e-a596-b814e1c82e0f","challenge_token":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","deployment_id":"\(deploymentID)","computer_id":"\(computerID)","enrollment_epoch":1,"expires_at_unix":\(issuedAt + 60)}
            """.utf8)
        case "/v2/endpoints/session/complete":
            let now = Int64(Date().timeIntervalSince1970)
            status = 200
            headers = nil
            body = Data("""
            {"token":"endpoint-session-fixture-token-0123456789","session_id":"b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1","deployment_id":"\(deploymentID)","computer_id":"\(computerID)","enrollment_epoch":1,"expires_at_unix":\(now + 600)}
            """.utf8)
        case "/v2/endpoints/self":
            status = 200
            headers = nil
            body = Data("""
            {"computer_id":"\(computerID)","friendly_name":"Science Mac","platform":"macos","enrollment_epoch":1}
            """.utf8)
        case "/v2/endpoints/admissions/observation/redeem":
            let requestJSON = try JSONSerialization.jsonObject(with: request.httpBody!) as! [String: String]
            let tokenPayload = String(requestJSON["grant_token"]!.split(separator: ".")[0])
                .replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            let paddedPayload = tokenPayload + String(repeating: "=", count: (4 - tokenPayload.count % 4) % 4)
            let claimsData = Data(base64Encoded: paddedPayload)!
            let claims = try JSONSerialization.jsonObject(with: claimsData) as! [String: Any]
            status = 200
            headers = nil
            body = try JSONSerialization.data(withJSONObject: [
                "grant_id": claims["grant_id"]!,
                "computer_id": computerID,
                "endpoint_session_id": claims["endpoint_session_id"]!,
                "expires_at_unix": claims["expires_at_unix"]!,
            ])
        case "/v2/endpoints/jobs":
            status = 200
            headers = nil
            body = Data("""
            {"jobs":[{"id":"\(jobID)","file_name":"hello.txt","file_size_bytes":5,"sha256":"\(digest)","chunk_size_bytes":262144,"chunk_count":1,"state":"in_progress"}],"max_page_size":50}
            """.utf8)
        case "/v2/endpoints/file-requests":
            status = 200
            headers = nil
            body = Data(#"{"requests":[],"max_page_size":100}"#.utf8)
        case "/v2/endpoints/jobs/\(jobID)/chunks/0":
            status = 200
            headers = ["x-helicoid-chunk-sha256": digest]
            body = payload
        case "/v2/endpoints/jobs/\(jobID)/result":
            status = 200
            headers = nil
            body = Data("{\"job_id\":\"\(jobID)\",\"target\":{}}".utf8)
        default:
            status = 404
            headers = nil
            body = Data()
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: status,
                                       httpVersion: "HTTP/1.1", headerFields: headers)!
        return (body, response)
    }
}

@Suite("Endpoint one-time enrollment")
struct EndpointEnrollmentClientTests {
    private let server = "https://helicoid.school.example:8920"
    private let endpointURL = URL(string: "https://helicoid.school.example:8920/v2/endpoints/enroll")!
    private let deploymentID = "deployment-fixture-42"
    private let invitationID = "60df2e9e-6d52-46f7-8a32-86789a29cb63"
    private let code = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUv"

    @Test func signsTheContractMessageAndPersistsOnlyPendingIdentity() async throws {
        let body = Data(#"{"computer":{"id":"e475b9ca-801a-4f71-b5d5-b87daaaae731","friendly_name":"Science Mac","platform":"macos","enrollment_state":"pending","enrollment_epoch":1,"groups":[]},"state":"pending_approval"}"#.utf8)
        let store = EndpointKeyFixtureStore()
        let transport = EndpointEnrollmentTransportFixture(responseBody: body, responseURL: endpointURL)
        let client = EndpointEnrollmentClient(keyStore: store, transport: transport)

        let result = try await client.enroll(serverAddress: server, deploymentID: deploymentID,
                                             invitationID: invitationID, enrollmentCode: code)

        #expect(result.computerID == "e475b9ca-801a-4f71-b5d5-b87daaaae731")
        #expect(result.enrollmentState == "pending")
        #expect(result.enrollmentEpoch == 1)
        #expect(await store.insertions == 1)

        guard let request = await transport.receivedRequests.first,
              let requestData = request.httpBody,
              let json = try JSONSerialization.jsonObject(with: requestData) as? [String: String],
              let publicKeyHex = json["public_key"],
              let signatureHex = json["proof"] else {
            Issue.record("The endpoint did not send a complete enrollment proof request")
            return
        }
        #expect(request.url == endpointURL)
        #expect(request.httpMethod == "POST")
        #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
        #expect(json["invitation_id"] == invitationID)
        #expect(json["enrollment_code"] == code)

        let codeDigest = SHA256.hash(data: Data(code.utf8))
        let codeHash = codeDigest.map { String(format: "%02x", $0) }.joined()
        let message = Data("hs-endpoint-enroll-v2|deployment:\(deploymentID)|invitation:\(invitationID)|code_hash:\(codeHash)|endpoint:\(publicKeyHex)".utf8)
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: Self.decodeHex(publicKeyHex))
        #expect(publicKey.isValidSignature(Self.decodeHex(signatureHex), for: message))

        let account = SHA256.hash(data: Data(deploymentID.utf8)).map { String(format: "%02x", $0) }.joined()
        let recordData = try #require(await store.read(account: account))
        let record = try JSONDecoder().decode(StoredEndpointFixture.self, from: recordData)
        #expect(record.deploymentID == deploymentID)
        #expect(record.version == 4)
        #expect(record.serverAddress == server)
        #expect(record.grantVerificationPublicKeyHex == String(repeating: "a", count: 64))
        #expect(record.authorityGeneration == 1)
        #expect(record.privateKey.count == 32)
        #expect(record.result == result)
        #expect(try await client.savedGrantVerificationPublicKey(deploymentID: deploymentID) ==
                String(repeating: "a", count: 64))
    }

    @Test func forgettingIdentityRemovesTheKeyAndAllowsFreshEnrollment() async throws {
        let body = Data(#"{"computer":{"id":"e475b9ca-801a-4f71-b5d5-b87daaaae731","friendly_name":"Science Mac","platform":"macos","enrollment_state":"pending","enrollment_epoch":1,"groups":[]},"state":"pending_approval"}"#.utf8)
        let store = EndpointKeyFixtureStore()
        let transport = EndpointEnrollmentTransportFixture(responseBody: body, responseURL: endpointURL)
        let client = EndpointEnrollmentClient(keyStore: store, transport: transport)

        _ = try await client.enroll(serverAddress: server, deploymentID: deploymentID,
                                    invitationID: invitationID, enrollmentCode: code)
        let account = SHA256.hash(data: Data(deploymentID.utf8)).map { String(format: "%02x", $0) }.joined()
        let firstIdentity = try #require(await store.read(account: account))

        try await client.forgetIdentity(deploymentID: deploymentID)

        #expect(await store.read(account: account) == nil)
        _ = try await client.enroll(serverAddress: server, deploymentID: deploymentID,
                                    invitationID: invitationID, enrollmentCode: code)
        let replacementIdentity = try #require(await store.read(account: account))
        let first = try JSONDecoder().decode(StoredEndpointFixture.self, from: firstIdentity)
        let replacement = try JSONDecoder().decode(StoredEndpointFixture.self, from: replacementIdentity)
        #expect(first.privateKey != replacement.privateKey)
    }

    @Test func admitsEndpointAndAtomicallyReceivesVerifiedFile() async throws {
        let store = EndpointKeyFixtureStore()
        let transport = EndpointFileDeliveryTransportFixture(origin: URL(string: server)!)
        let directory = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent(".endpoint-file-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let client = EndpointEnrollmentClient(
            keyStore: store,
            transport: transport,
            receivedFilesDirectory: { directory },
            localUserIdentity: { "macos:uid:501" }
        )

        _ = try await client.enroll(serverAddress: server, deploymentID: deploymentID,
                                    invitationID: invitationID, enrollmentCode: code)
        let files = try await client.receiveAvailableFiles(deploymentID: deploymentID)

        #expect(files.count == 1)
        #expect(files[0].fileName == "hello.txt")
        #expect(try Data(contentsOf: URL(fileURLWithPath: files[0].path)) == Data("hello".utf8))
        let requests = await transport.requests
        let paths = requests.map(\.0)
        #expect(paths == [
            "/v2/endpoints/enroll",
            "/v2/deployment/authority",
            "/v2/deployment/authority",
            "/health",
            "/v2/endpoints/session/challenge",
            "/v2/endpoints/session/complete",
            "/v2/endpoints/self",
            "/v2/endpoints/jobs",
            "/v2/endpoints/jobs/8df8cc80-7c11-47cc-958e-47b7557d6e8a/chunks/0",
            "/v2/endpoints/jobs/8df8cc80-7c11-47cc-958e-47b7557d6e8a/result",
        ])
        let resultRequest = requests.last
        #expect(resultRequest?.2 == "Bearer endpoint-session-fixture-token-0123456789")
    }

    @Test func refusesToStartEndpointSessionWhenFileJobsAreDisabled() async throws {
        let store = EndpointKeyFixtureStore()
        let transport = EndpointFileDeliveryTransportFixture(origin: URL(string: server)!, fileJobsEnabled: false)
        let client = EndpointEnrollmentClient(keyStore: store, transport: transport)
        _ = try await client.enroll(serverAddress: server, deploymentID: deploymentID,
                                   invitationID: invitationID, enrollmentCode: code)

        await #expect(throws: HelicoidError.setupBlocked(
            reason: "File delivery is not enabled by this deployment."
        )) {
            try await client.receiveAvailableFiles(deploymentID: deploymentID)
        }
        let paths = await transport.requests.map(\.0)
        #expect(paths == [
            "/v2/endpoints/enroll",
            "/v2/deployment/authority",
            "/v2/deployment/authority",
            "/health",
        ])
    }

    @Test func refusesProtectedOperationsWhenAuthorityGenerationChanges() async throws {
        let store = EndpointKeyFixtureStore()
        let transport = EndpointFileDeliveryTransportFixture(origin: URL(string: server)!)
        let client = EndpointEnrollmentClient(
            keyStore: store,
            transport: transport,
            localUserIdentity: { "macos:uid:501" }
        )
        _ = try await client.enroll(
            serverAddress: server,
            deploymentID: deploymentID,
            invitationID: invitationID,
            enrollmentCode: code
        )
        await transport.setAuthorityGeneration(2)

        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The server authority differs from this endpoint's saved generation. Keep this endpoint quarantined and re-enroll it through the Manager after recovery review."
        )) {
            try await client.listAvailableFileRequests(deploymentID: deploymentID)
        }

        let paths = await transport.requests.map(\.0)
        #expect(paths == [
            "/v2/endpoints/enroll",
            "/v2/deployment/authority",
            "/v2/deployment/authority",
        ])
    }

    @Test func verifiesManagerProofAndRedeemsOneObservationAdmission() async throws {
        let deploymentID = "dep_" + String(repeating: "a", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let serverPublicKeyHex = Self.lowerHex(serverKey.publicKey.rawRepresentation)
        let managerPublicKeyHex = Self.lowerHex(managerKey.publicKey.rawRepresentation)
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            deploymentID: deploymentID,
            grantVerificationKeyHex: serverPublicKeyHex
        )
        let store = EndpointKeyFixtureStore()
        let client = EndpointEnrollmentClient(
            keyStore: store,
            transport: transport,
            localUserIdentity: { "macos:uid:501" }
        )
        _ = try await client.enroll(
            serverAddress: server,
            deploymentID: deploymentID,
            invitationID: invitationID,
            enrollmentCode: code
        )

        let account = SHA256.hash(data: Data(deploymentID.utf8)).map { String(format: "%02x", $0) }.joined()
        let storedData = try #require(await store.read(account: account))
        let stored = try JSONDecoder().decode(StoredEndpointFixture.self, from: storedData)
        let endpointKey = try Curve25519.Signing.PrivateKey(rawRepresentation: stored.privateKey)
        let endpointPublicKeyHex = Self.lowerHex(endpointKey.publicKey.rawRepresentation)
        let grantID = "b8eeedb7-1d8d-4c29-9e13-05ec6045a173"
        let accountID = "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d"
        let managerID = "7a01cf88-6fdb-4cc1-a72f-d155f5309355"
        let endpointSessionID = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1"
        let issuedAt = Int64(Date().timeIntervalSince1970) - 1
        let expiresAt = issuedAt + 10
        let payload = Data([
            "{\"version\":1,\"grant_id\":\"", grantID,
            "\",\"deployment_id\":\"", deploymentID,
            "\",\"account_id\":\"", accountID,
            "\",\"manager_id\":\"", managerID,
            "\",\"manager_public_key\":\"", managerPublicKeyHex,
            "\",\"computer_id\":\"", transport.computerID,
            "\",\"endpoint_public_key\":\"", endpointPublicKeyHex,
            "\",\"endpoint_session_id\":\"", endpointSessionID,
            "\",\"enrollment_epoch\":1,\"issued_at_unix\":", String(issuedAt),
            ",\"expires_at_unix\":", String(expiresAt),
            ",\"capability\":\"observe\"}",
        ].joined().utf8)
        let signedPayload = Data("hs-observation-grant-v1\0".utf8) + payload
        let signature = try serverKey.signature(for: signedPayload)
        let token = payload.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            + "." + Self.lowerHex(signature)

        let challengeResults = await withTaskGroup(of: ObservationAdmissionChallenge?.self) { group in
            for _ in 0..<2 {
                group.addTask {
                    try? await client.prepareObservationAdmission(
                        grantToken: token,
                        deploymentID: deploymentID
                    )
                }
            }
            var results: [ObservationAdmissionChallenge] = []
            for await result in group {
                if let result { results.append(result) }
            }
            return results
        }
        #expect(challengeResults.count == 1)
        let challenge = try #require(challengeResults.first)
        #expect(challenge.grantID == grantID)
        #expect(challenge.computerID == transport.computerID)
        #expect(challenge.endpointSessionID == endpointSessionID)
        #expect(challenge.endpointNonceHex.count == 64)
        let channelBinding = Self.webRTCChannelBinding()
        let channelBindingHex = try #require(
            ObservationAdmissionGrantVerifier.canonicalChannelBindingHex(channelBinding)
        )
        let proofMessage = Data(
            "hs-observation-peer-proof-v2|deployment:\(deploymentID)|grant:\(grantID)|computer:\(transport.computerID)|endpoint_session:\(endpointSessionID)|epoch:1|nonce:\(challenge.endpointNonceHex)|channel_binding:\(channelBindingHex)".utf8
        )
        let managerProof = Self.lowerHex(try managerKey.signature(for: proofMessage))
        let accepted = try await client.redeemObservationAdmission(
            challengeID: challenge.id,
            managerProofHex: managerProof,
            currentVerifiedChannelBinding: { channelBinding }
        )
        #expect(accepted.grantID == grantID)
        #expect(accepted.computerID == transport.computerID)
        #expect(accepted.endpointSessionID == endpointSessionID)
        #expect(try await client.listAvailableFileRequests(deploymentID: deploymentID).isEmpty)
        await #expect(throws: HelicoidError.self) {
            try await client.redeemObservationAdmission(
                challengeID: challenge.id,
                managerProofHex: managerProof,
                currentVerifiedChannelBinding: { channelBinding }
            )
        }

        let requests = await transport.requests
        let paths = requests.map(\.0)
        let challengePath = "/v2/endpoints/session/challenge"
        let redemptionPath = "/v2/endpoints/admissions/observation/redeem"
        let fileRequestsPath = "/v2/endpoints/file-requests"
        let challengeIndex = try #require(paths.firstIndex(of: challengePath))
        let redemptionIndex = try #require(paths.firstIndex(of: redemptionPath))
        let fileRequestsIndex = try #require(paths.firstIndex(of: fileRequestsPath))
        let selfRequestIndices = paths.enumerated().compactMap { index, path in
            path == "/v2/endpoints/self" ? index : nil
        }
        let allowedPaths: Set<String> = [
            "/v2/endpoints/enroll",
            "/v2/deployment/authority",
            challengePath,
            "/v2/endpoints/session/complete",
            "/v2/endpoints/self",
            redemptionPath,
            fileRequestsPath,
        ]
        #expect(paths.first == "/v2/endpoints/enroll")
        #expect(paths.last == fileRequestsPath)
        #expect(paths.allSatisfy(allowedPaths.contains))
        #expect(paths.filter { $0 == challengePath }.count == 1)
        #expect(paths.filter { $0 == "/v2/endpoints/session/complete" }.count == 1)
        #expect(paths.filter { $0 == redemptionPath }.count == 1)
        #expect(challengeIndex < redemptionIndex)
        #expect(redemptionIndex < fileRequestsIndex)
        #expect(selfRequestIndices.contains { $0 < redemptionIndex })
        #expect(selfRequestIndices.contains { $0 > redemptionIndex && $0 < fileRequestsIndex })
        let fileRequestList = requests.first { $0.0 == fileRequestsPath }
        #expect(fileRequestList?.2 == "Bearer endpoint-session-fixture-token-0123456789")
    }

    @Test func refusesPlainHTTPBeforeGeneratingOrPersistingAKey() async {
        let store = EndpointKeyFixtureStore()
        let transport = EndpointEnrollmentTransportFixture(responseBody: Data(), responseURL: endpointURL)
        let client = EndpointEnrollmentClient(keyStore: store, transport: transport)

        await #expect(throws: HelicoidError.self) {
            try await client.enroll(serverAddress: "http://helicoid.school.example:8920",
                                    deploymentID: deploymentID, invitationID: invitationID,
                                    enrollmentCode: code)
        }
        #expect(await store.insertions == 0)
        #expect(await transport.receivedRequests.isEmpty)
    }

    @Test func refusesAResponseFromAnotherOrigin() async {
        let body = Data(#"{"computer":{"id":"e475b9ca-801a-4f71-b5d5-b87daaaae731","friendly_name":"Science Mac","platform":"macos","enrollment_state":"pending","enrollment_epoch":1,"groups":[]},"state":"pending_approval"}"#.utf8)
        let store = EndpointKeyFixtureStore()
        let wrongURL = URL(string: "https://attacker.example/v2/endpoints/enroll")!
        let transport = EndpointEnrollmentTransportFixture(responseBody: body, responseURL: wrongURL)
        let client = EndpointEnrollmentClient(keyStore: store, transport: transport)

        await #expect(throws: HelicoidError.self) {
            try await client.enroll(serverAddress: server, deploymentID: deploymentID,
                                    invitationID: invitationID, enrollmentCode: code)
        }
        #expect(await store.insertions == 1)
    }

    private static func decodeHex(_ value: String) -> Data {
        var data = Data()
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else { return Data() }
            data.append(byte)
            index = next
        }
        return data
    }

    private static func lowerHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func webRTCChannelBinding() -> Data {
        var bytes = Data("HS-WEBRTC-DTLS-SCTP-V1\0".utf8)
        bytes.append(contentsOf: [0, 10])
        bytes.append(Data("hs-product".utf8))
        bytes.append(contentsOf: [0, 7])
        bytes.append(Data(repeating: 0x11, count: 32))
        bytes.append(Data(repeating: 0x22, count: 32))
        return bytes
    }
}
