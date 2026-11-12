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

private struct StoredEndpointFixture: Codable {
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
    let screenObservationEnabled: Bool
    private var authorityGeneration: Int64 = 1
    private var pendingObservationGrantResponses: [Data] = []
    private var signalsResponseStatusOverride: Int?
    private(set) var requests: [(String, String?, String?)] = []
    private(set) var requestBodies: [(String, Data?)] = []
    private(set) var requestTimeoutIntervals: [String: TimeInterval] = [:]
    private(set) var requestMaxBytes: [String: Int] = [:]

    init(
        origin: URL,
        fileJobsEnabled: Bool = true,
        screenObservationEnabled: Bool = false,
        deploymentID: String = "deployment-fixture-42",
        grantVerificationKeyHex: String = String(repeating: "a", count: 64)
    ) {
        self.origin = origin
        self.fileJobsEnabled = fileJobsEnabled
        self.screenObservationEnabled = screenObservationEnabled
        self.deploymentID = deploymentID
        self.grantVerificationKeyHex = grantVerificationKeyHex
    }

    func setAuthorityGeneration(_ generation: Int64) {
        authorityGeneration = generation
    }

    func setPendingObservationGrantResponse(_ body: Data) {
        pendingObservationGrantResponses = [body]
    }

    func setSignalsResponseStatus(_ status: Int?) {
        signalsResponseStatusOverride = status
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        let path = request.url!.path
        requests.append((path, request.httpMethod, request.value(forHTTPHeaderField: "Authorization")))
        requestBodies.append((path, request.httpBody))
        requestTimeoutIntervals[path] = request.timeoutInterval
        requestMaxBytes[path] = maxBytes
        let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        let status: Int
        let headers: [String: String]?
        let body: Data
        switch path {
        case "/health":
            status = 200
            headers = nil
            body = Data("""
            {"status":"ok","accepting_authorized_operations":true,"schema_version":1,"bootstrap_completed":true,"features":{"file_jobs":\(fileJobsEnabled),"screen_observation":\(screenObservationEnabled)}}
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
        case "/v2/endpoints/admissions/observation/pending":
            status = 200
            headers = nil
            body = pendingObservationGrantResponses.isEmpty
                ? Data(#"{"grants":[]}"#.utf8)
                : pendingObservationGrantResponses.removeFirst()
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
        case _ where path.hasPrefix("/v2/endpoints/admissions/observation/")
            && path.hasSuffix("/signals"):
            headers = nil
            if request.httpMethod == "POST" {
                status = signalsResponseStatusOverride ?? 204
                body = Data()
            } else {
                status = signalsResponseStatusOverride ?? 200
                body = Data(#"{"cursor":0,"messages":[]}"#.utf8)
            }
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

/// Pauses the pending-grant response so a test can change local identity
/// generation while the request is in flight.
private actor PendingGrantGateTransport: HTTPTransport {
    private let inner: EndpointFileDeliveryTransportFixture
    private var pendingRequestSeen = false
    private var blockedFirstPendingRequest = false
    private var pendingRequestStarted: CheckedContinuation<Void, Never>?
    private var pendingRequestRelease: CheckedContinuation<Void, Never>?
    private var released = false

    init(inner: EndpointFileDeliveryTransportFixture) {
        self.inner = inner
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        if request.url?.path == "/v2/endpoints/admissions/observation/pending",
           !blockedFirstPendingRequest {
            blockedFirstPendingRequest = true
            pendingRequestSeen = true
            pendingRequestStarted?.resume()
            pendingRequestStarted = nil
            if !released {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    pendingRequestRelease = continuation
                }
            }
        }
        return try await inner.bytes(for: request, maxBytes: maxBytes)
    }

    func waitForPendingRequest() async {
        if pendingRequestSeen { return }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            pendingRequestStarted = continuation
        }
    }

    func releasePendingRequest() {
        released = true
        pendingRequestRelease?.resume()
        pendingRequestRelease = nil
    }
}

/// Blocks one exact request path so tests can reset identity or cancel while a
/// server-consumed operation is in flight.
private actor BlockingPathTransport: HTTPTransport {
    private let inner: EndpointFileDeliveryTransportFixture
    private var path: String
    private var requestSeen = false
    private var requestStarted: CheckedContinuation<Void, Never>?
    private var requestRelease: CheckedContinuation<Void, Never>?
    private var released = false

    init(inner: EndpointFileDeliveryTransportFixture, path: String) {
        self.inner = inner
        self.path = path
    }

    func setPath(_ value: String) {
        path = value
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        if request.url?.path == path {
            requestSeen = true
            requestStarted?.resume()
            requestStarted = nil
            if !released {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    requestRelease = continuation
                }
            }
        }
        return try await inner.bytes(for: request, maxBytes: maxBytes)
    }

    func waitForRequest() async {
        if requestSeen { return }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            requestStarted = continuation
        }
    }

    func releaseRequest() {
        released = true
        requestRelease?.resume()
        requestRelease = nil
    }
}

/// Routes test requests by origin so one client can exercise more than one
/// deployment without sharing a fixture.
private actor RoutingHTTPTransport: HTTPTransport {
    private let routes: [String: any HTTPTransport]

    init(routes: [String: any HTTPTransport]) {
        self.routes = routes
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        guard let host = request.url?.host, let route = routes[host] else {
            throw HelicoidError.unreachable
        }
        return try await route.bytes(for: request, maxBytes: maxBytes)
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

    @Test func identityResetDuringInFlightRedeemDoesNotInstallActiveLease() async throws {
        let deploymentID = "dep_" + String(repeating: "d", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let innerTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let gate = BlockingPathTransport(
            inner: innerTransport,
            path: "/v2/endpoints/admissions/observation/redeem"
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: gate
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let grant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: managerKey,
            deploymentID: deploymentID,
            computerID: innerTransport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        let challenge = try await client.prepareObservationAdmission(
            grantToken: grant.token,
            deploymentID: deploymentID
        )
        let binding = Self.webRTCChannelBinding()
        let proof = try Self.managerProof(
            challenge: challenge,
            deploymentID: deploymentID,
            managerKey: managerKey,
            channelBinding: binding
        )
        let redemption = Task {
            try await client.redeemObservationAdmission(
                challengeID: challenge.id,
                managerProofHex: proof,
                currentVerifiedChannelBinding: { binding }
            )
        }
        await gate.waitForRequest()
        try await client.forgetIdentity(deploymentID: deploymentID)
        await gate.releaseRequest()

        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The saved endpoint identity changed while this request was in progress."
        )) {
            _ = try await redemption.value
        }
    }

    @Test func cancellationDuringInFlightRedeemDoesNotInstallActiveLease() async throws {
        let deploymentID = "dep_" + String(repeating: "e", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let innerTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let gate = BlockingPathTransport(
            inner: innerTransport,
            path: "/v2/endpoints/admissions/observation/redeem"
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: gate
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let grant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: managerKey,
            deploymentID: deploymentID,
            computerID: innerTransport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "d2e3f4a5-b6c7-4d8e-9f0a-1b2c3d4e5f60",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        let challenge = try await client.prepareObservationAdmission(
            grantToken: grant.token,
            deploymentID: deploymentID
        )
        let binding = Self.webRTCChannelBinding()
        let proof = try Self.managerProof(
            challenge: challenge,
            deploymentID: deploymentID,
            managerKey: managerKey,
            channelBinding: binding
        )
        let redemption = Task {
            try await client.redeemObservationAdmission(
                challengeID: challenge.id,
                managerProofHex: proof,
                currentVerifiedChannelBinding: { binding }
            )
        }
        await gate.waitForRequest()
        redemption.cancel()
        await gate.releaseRequest()

        do {
            _ = try await redemption.value
            Issue.record("A cancelled redemption installed an active lease")
        } catch {
            #expect(error is CancellationError)
        }
    }

    @Test func activeLeaseCapacityIsPerDeploymentAndReservationsRelease() async throws {
        let originA = URL(string: "https://a.helicoid.example:8920")!
        let originB = URL(string: "https://b.helicoid.example:8920")!
        let deploymentA = "dep_" + String(repeating: "a", count: 32)
        let deploymentB = "dep_" + String(repeating: "b", count: 32)
        let serverKeyA = Curve25519.Signing.PrivateKey()
        let serverKeyB = Curve25519.Signing.PrivateKey()
        let managerKeyA = Curve25519.Signing.PrivateKey()
        let managerKeyB = Curve25519.Signing.PrivateKey()
        let fixtureA = EndpointFileDeliveryTransportFixture(
            origin: originA,
            screenObservationEnabled: true,
            deploymentID: deploymentA,
            grantVerificationKeyHex: Self.lowerHex(serverKeyA.publicKey.rawRepresentation)
        )
        let fixtureB = EndpointFileDeliveryTransportFixture(
            origin: originB,
            screenObservationEnabled: true,
            deploymentID: deploymentB,
            grantVerificationKeyHex: Self.lowerHex(serverKeyB.publicKey.rawRepresentation)
        )
        let gateA = BlockingPathTransport(inner: fixtureA, path: "")
        let routing = RoutingHTTPTransport(routes: [
            originA.host!: gateA,
            originB.host!: fixtureB,
        ])
        let store = EndpointKeyFixtureStore()
        let client = EndpointEnrollmentClient(
            keyStore: store,
            transport: routing,
            localUserIdentity: { "macos:uid:501" }
        )
        _ = try await client.enroll(
            serverAddress: originA.absoluteString,
            deploymentID: deploymentA,
            invitationID: invitationID,
            enrollmentCode: code
        )
        _ = try await client.enroll(
            serverAddress: originB.absoluteString,
            deploymentID: deploymentB,
            invitationID: invitationID,
            enrollmentCode: code
        )
        let endpointPublicKeyA = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentA
        )
        let endpointPublicKeyB = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentB
        )

        var lastA: EndpointObservationAdmission?
        for _ in 0..<7 {
            let prepared = try await preparedObservationChallenge(
                client: client,
                deploymentID: deploymentA,
                serverKey: serverKeyA,
                managerKey: managerKeyA,
                computerID: fixtureA.computerID,
                endpointPublicKeyHex: endpointPublicKeyA
            )
            lastA = try await client.redeemObservationAdmission(
                challengeID: prepared.challenge.id,
                managerProofHex: prepared.proof,
                currentVerifiedChannelBinding: { prepared.binding }
            )
        }

        await gateA.setPath("/v2/endpoints/admissions/observation/redeem")
        let cancelledPreparation = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentA,
            serverKey: serverKeyA,
            managerKey: managerKeyA,
            computerID: fixtureA.computerID,
            endpointPublicKeyHex: endpointPublicKeyA
        )
        let cancelled = Task {
            try await client.redeemObservationAdmission(
                challengeID: cancelledPreparation.challenge.id,
                managerProofHex: cancelledPreparation.proof,
                currentVerifiedChannelBinding: { cancelledPreparation.binding }
            )
        }
        await gateA.waitForRequest()
        cancelled.cancel()
        await gateA.releaseRequest()
        do {
            _ = try await cancelled.value
            Issue.record("A cancelled redemption installed an active lease")
        } catch {
            #expect(error is CancellationError)
        }

        let failedPreparation = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentA,
            serverKey: serverKeyA,
            managerKey: managerKeyA,
            computerID: fixtureA.computerID,
            endpointPublicKeyHex: endpointPublicKeyA
        )
        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The endpoint observation grant is invalid or expired."
        )) {
            _ = try await client.redeemObservationAdmission(
                challengeID: failedPreparation.challenge.id,
                managerProofHex: String(repeating: "0", count: 128),
                currentVerifiedChannelBinding: { failedPreparation.binding }
            )
        }

        let eighthPreparation = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentA,
            serverKey: serverKeyA,
            managerKey: managerKeyA,
            computerID: fixtureA.computerID,
            endpointPublicKeyHex: endpointPublicKeyA
        )
        let eighth = try await client.redeemObservationAdmission(
            challengeID: eighthPreparation.challenge.id,
            managerProofHex: eighthPreparation.proof,
            currentVerifiedChannelBinding: { eighthPreparation.binding }
        )
        #expect(await client.observationAdmissionIsCurrent(eighth))
        if let lastA { #expect(await client.observationAdmissionIsCurrent(lastA)) }

        let ninthPreparation = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentA,
            serverKey: serverKeyA,
            managerKey: managerKeyA,
            computerID: fixtureA.computerID,
            endpointPublicKeyHex: endpointPublicKeyA
        )
        await #expect(throws: HelicoidError.setupBlocked(
            reason: "Too many admitted observation leases are already active."
        )) {
            _ = try await client.redeemObservationAdmission(
                challengeID: ninthPreparation.challenge.id,
                managerProofHex: ninthPreparation.proof,
                currentVerifiedChannelBinding: { ninthPreparation.binding }
            )
        }

        let preparedB = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentB,
            serverKey: serverKeyB,
            managerKey: managerKeyB,
            computerID: fixtureB.computerID,
            endpointPublicKeyHex: endpointPublicKeyB
        )
        let admittedB = try await client.redeemObservationAdmission(
            challengeID: preparedB.challenge.id,
            managerProofHex: preparedB.proof,
            currentVerifiedChannelBinding: { preparedB.binding }
        )
        #expect(await client.observationAdmissionIsCurrent(admittedB))
    }

    @Test func publishSignalRejectsIdentityResetDuringRequest() async throws {
        let deploymentID = "dep_" + String(repeating: "f", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let innerTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let gate = BlockingPathTransport(inner: innerTransport, path: "")
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: gate
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let prepared = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentID,
            serverKey: serverKey,
            managerKey: managerKey,
            computerID: innerTransport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex
        )
        await gate.setPath(
            "/v2/endpoints/admissions/observation/\(prepared.challenge.grantID)/signals"
        )
        let publish = Task {
            try await client.publishObservationSignal(
                challengeID: prepared.challenge.id,
                kind: .ice,
                payload: "candidate:1"
            )
        }
        await gate.waitForRequest()
        try await client.forgetIdentity(deploymentID: deploymentID)
        await gate.releaseRequest()

        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The saved endpoint identity changed while this request was in progress."
        )) {
            try await publish.value
        }
    }

    @Test func pollSignalsRejectsIdentityResetDuringRequest() async throws {
        let deploymentID = "dep_" + String(repeating: "9", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let innerTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let gate = BlockingPathTransport(inner: innerTransport, path: "")
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: gate
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let prepared = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentID,
            serverKey: serverKey,
            managerKey: managerKey,
            computerID: innerTransport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex
        )
        await gate.setPath(
            "/v2/endpoints/admissions/observation/\(prepared.challenge.grantID)/signals"
        )
        let poll = Task {
            try await client.pollObservationSignals(
                challengeID: prepared.challenge.id,
                after: 0
            )
        }
        await gate.waitForRequest()
        try await client.forgetIdentity(deploymentID: deploymentID)
        await gate.releaseRequest()

        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The saved endpoint identity changed while this request was in progress."
        )) {
            _ = try await poll.value
        }
    }

    @Test func publishesSignedEndpointChallengeWithFixedSixFieldWire() async throws {
        let deploymentID = "dep_" + String(repeating: "c", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let prepared = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentID,
            serverKey: serverKey,
            managerKey: managerKey,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex
        )
        let signalsPath =
            "/v2/endpoints/admissions/observation/\(prepared.challenge.grantID)/signals"

        let payload = try await client.publishObservationChallenge(
            challengeID: prepared.challenge.id,
            endpointCertificatePEM: Self.endpointCertificatePEM
        )

        let rawObject = try JSONSerialization.jsonObject(with: Data(payload.utf8))
        let object = try #require(rawObject as? [String: Any])
        #expect(object.count == 6)
        #expect(Set(object.keys) == Set([
            "computer_id",
            "endpoint_session_id",
            "endpoint_nonce",
            "expires_at_unix",
            "endpoint_certificate_pem",
            "endpoint_certificate_signature",
        ]))
        #expect(object["computer_id"] as? String == prepared.challenge.computerID)
        #expect(object["endpoint_session_id"] as? String == prepared.challenge.endpointSessionID)
        #expect(object["endpoint_nonce"] as? String == prepared.challenge.endpointNonceHex)
        #expect((object["expires_at_unix"] as? NSNumber)?.int64Value == prepared.challenge.expiresAtUnix)
        #expect(object["endpoint_certificate_pem"] as? String == Self.endpointCertificatePEM)
        let signatureHex = try #require(object["endpoint_certificate_signature"] as? String)
        #expect(signatureHex.count == 128)
        #expect(signatureHex.utf8.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66)
        })

        let certificateDigest = SHA256.hash(data: Data(Self.endpointCertificatePEM.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        let message = Data(
            "hs-observation-peer-certificate-v1|deployment:\(deploymentID)|grant:\(prepared.challenge.grantID)|computer:\(prepared.challenge.computerID)|endpoint_session:\(prepared.challenge.endpointSessionID)|epoch:1|nonce:\(prepared.challenge.endpointNonceHex)|role:endpoint|certificate_sha256:\(certificateDigest)".utf8
        )
        let endpointKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: Self.decodeHex(endpointPublicKeyHex)
        )
        #expect(endpointKey.isValidSignature(Self.decodeHex(signatureHex), for: message))

        let verified = try ObservationEndpointChallengeVerifier.verify(
            payload: payload,
            grant: prepared.grant,
            nowUnixSeconds: Int64(Date().timeIntervalSince1970)
        )
        #expect(verified.computerID == prepared.challenge.computerID)
        #expect(verified.endpointSessionID == prepared.challenge.endpointSessionID)
        #expect(verified.endpointNonceHex == prepared.challenge.endpointNonceHex)
        #expect(verified.expiresAtUnix == prepared.challenge.expiresAtUnix)
        #expect(verified.endpointCertificatePEM == Data(Self.endpointCertificatePEM.utf8))

        let bodies = await transport.requestBodies
        let body = try #require(bodies.last(where: { $0.0 == signalsPath })?.1)
        let rawOuter = try JSONSerialization.jsonObject(with: body)
        let outer = try #require(rawOuter as? [String: String])
        #expect(outer.count == 2)
        #expect(outer["kind"] == "challenge")
        #expect(outer["payload"] == payload)
    }

    @Test func rejectsNonCanonicalEndpointCertificatePEMBeforePublishing() async throws {
        let transport = EndpointFileDeliveryTransportFixture(origin: URL(string: server)!)
        let store = EndpointKeyFixtureStore()
        let client = EndpointEnrollmentClient(keyStore: store, transport: transport)
        let invalidCertificates = [
            "-----BEGIN CERTIFICATE-----\r\nAQIDBA==\r\n-----END CERTIFICATE-----\r\n",
            "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\nAQ ID BA==\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\nextra",
            "-----BEGIN CERTIFICATE-----\nAQIDB\u{00E9}==\n-----END CERTIFICATE-----\n",
        ]
        for certificate in invalidCertificates {
            await #expect(throws: HelicoidError.invalidInput(
                field: "endpoint certificate",
                detail: "The endpoint certificate must be canonical ASCII PEM with exact BEGIN and END lines."
            )) {
                _ = try await client.publishObservationChallenge(
                    challengeID: UUID(),
                    endpointCertificatePEM: certificate
                )
            }
        }
        #expect(await transport.requests.isEmpty)
    }

    @Test func endpointChallengePublishRejectsIdentityResetDuringRequest() async throws {
        let deploymentID = "dep_" + String(repeating: "b", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let innerTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let gate = BlockingPathTransport(inner: innerTransport, path: "")
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: gate
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let prepared = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentID,
            serverKey: serverKey,
            managerKey: managerKey,
            computerID: innerTransport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex
        )
        await gate.setPath(
            "/v2/endpoints/admissions/observation/\(prepared.challenge.grantID)/signals"
        )
        let publish = Task {
            try await client.publishObservationChallenge(
                challengeID: prepared.challenge.id,
                endpointCertificatePEM: Self.endpointCertificatePEM
            )
        }
        await gate.waitForRequest()
        try await client.forgetIdentity(deploymentID: deploymentID)
        await gate.releaseRequest()

        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The saved endpoint identity changed while this request was in progress."
        )) {
            _ = try await publish.value
        }
    }

    @Test func endpointChallengePublishCancellationDoesNotReportSuccess() async throws {
        let deploymentID = "dep_" + String(repeating: "1", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let innerTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let gate = BlockingPathTransport(inner: innerTransport, path: "")
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: gate
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let prepared = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentID,
            serverKey: serverKey,
            managerKey: managerKey,
            computerID: innerTransport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex
        )
        await gate.setPath(
            "/v2/endpoints/admissions/observation/\(prepared.challenge.grantID)/signals"
        )
        let publish = Task {
            try await client.publishObservationChallenge(
                challengeID: prepared.challenge.id,
                endpointCertificatePEM: Self.endpointCertificatePEM
            )
        }
        await gate.waitForRequest()
        publish.cancel()
        await gate.releaseRequest()

        do {
            _ = try await publish.value
            Issue.record("A cancelled endpoint challenge attestation reported success")
        } catch {
            #expect(error is CancellationError)
        }
    }

    @Test func genericSignalPublisherCannotConstructUnsignedChallenge() async {
        #expect(ObservationSignalKind(rawValue: "challenge") == nil)
        #expect(ObservationSignalKind(rawValue: "ice") == ObservationSignalKind.ice)
    }

    @Test func endpointChallengePublishIsSingleShotAcrossCertificates() async throws {
        let deploymentID = "dep_" + String(repeating: "d", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let innerTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let gate = BlockingPathTransport(inner: innerTransport, path: "")
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: gate
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let prepared = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentID,
            serverKey: serverKey,
            managerKey: managerKey,
            computerID: innerTransport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex
        )
        let signalsPath =
            "/v2/endpoints/admissions/observation/\(prepared.challenge.grantID)/signals"
        await gate.setPath(signalsPath)

        let first = Task {
            try await client.publishObservationChallenge(
                challengeID: prepared.challenge.id,
                endpointCertificatePEM: Self.endpointCertificatePEM
            )
        }
        await gate.waitForRequest()
        await #expect(throws: HelicoidError.setupBlocked(
            reason: "The observation challenge publish has already been attempted."
        )) {
            _ = try await client.publishObservationChallenge(
                challengeID: prepared.challenge.id,
                endpointCertificatePEM: Self.otherEndpointCertificatePEM
            )
        }
        await gate.releaseRequest()
        let payload = try await first.value
        let rawObject = try JSONSerialization.jsonObject(with: Data(payload.utf8))
        let object = try #require(rawObject as? [String: Any])
        #expect(object["endpoint_certificate_pem"] as? String == Self.endpointCertificatePEM)

        await #expect(throws: HelicoidError.setupBlocked(
            reason: "The observation challenge publish has already been attempted."
        )) {
            _ = try await client.publishObservationChallenge(
                challengeID: prepared.challenge.id,
                endpointCertificatePEM: Self.endpointCertificatePEM
            )
        }
        let bodies = await innerTransport.requestBodies
        #expect(bodies.filter { $0.0 == signalsPath }.count == 1)
    }

    @Test func endpointChallengePublishRejectsExpiredChallenge() async throws {
        let deploymentID = "dep_" + String(repeating: "e", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        // Give fixture setup the full allowed lifetime under CI contention.
        let prepared = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentID,
            serverKey: serverKey,
            managerKey: managerKey,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            lifetimeSeconds: 10
        )
        let remaining = prepared.grant.expiresAtUnix - Int64(Date().timeIntervalSince1970)
        try await Task.sleep(nanoseconds: UInt64(max(0, remaining) + 1) * 1_000_000_000)

        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The endpoint observation grant is invalid or expired."
        )) {
            _ = try await client.publishObservationChallenge(
                challengeID: prepared.challenge.id,
                endpointCertificatePEM: Self.endpointCertificatePEM
            )
        }
        let bodies = await transport.requestBodies
        #expect(bodies.filter { $0.0.contains("/signals") }.isEmpty)
    }

    @Test func endpointChallengePublishRejectsMismatchedSigningIdentity() async throws {
        let deploymentID = "dep_" + String(repeating: "f", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let prepared = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentID,
            serverKey: serverKey,
            managerKey: managerKey,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex
        )
        let replacement = Curve25519.Signing.PrivateKey()
        let originalKey = try await replaceStoredEndpointPrivateKey(
            store: store,
            deploymentID: deploymentID,
            privateKey: replacement.rawRepresentation
        )

        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The saved endpoint identity does not match the verified observation grant."
        )) {
            _ = try await client.publishObservationChallenge(
                challengeID: prepared.challenge.id,
                endpointCertificatePEM: Self.endpointCertificatePEM
            )
        }

        try await replaceStoredEndpointPrivateKey(
            store: store,
            deploymentID: deploymentID,
            privateKey: originalKey
        )
        await #expect(throws: HelicoidError.setupBlocked(
            reason: "The observation challenge publish has already been attempted."
        )) {
            _ = try await client.publishObservationChallenge(
                challengeID: prepared.challenge.id,
                endpointCertificatePEM: Self.endpointCertificatePEM
            )
        }
    }

    @Test func endpointChallengePublishMapsServerConflict() async throws {
        let deploymentID = "dep_" + String(repeating: "0", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let managerKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let prepared = try await preparedObservationChallenge(
            client: client,
            deploymentID: deploymentID,
            serverKey: serverKey,
            managerKey: managerKey,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex
        )
        await transport.setSignalsResponseStatus(409)

        await #expect(throws: HelicoidError.setupBlocked(
            reason: "The observation challenge was already published."
        )) {
            _ = try await client.publishObservationChallenge(
                challengeID: prepared.challenge.id,
                endpointCertificatePEM: Self.endpointCertificatePEM
            )
        }
        await #expect(throws: HelicoidError.setupBlocked(
            reason: "The observation challenge publish has already been attempted."
        )) {
            _ = try await client.publishObservationChallenge(
                challengeID: prepared.challenge.id,
                endpointCertificatePEM: Self.endpointCertificatePEM
            )
        }
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

    @Test func fetchesAndVerifiesPendingObservationGrant() async throws {
        let deploymentID = "dep_" + String(repeating: "a", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let pollTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport,
            observationPollTransport: pollTransport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let grant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "b8eeedb7-1d8d-4c29-9e13-05ec6045a173",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        await pollTransport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (grant.grantID, transport.computerID, grant.expiresAtUnix, grant.token),
        ]))

        let challenges = try await client.fetchPendingObservationGrants(deploymentID: deploymentID)

        #expect(challenges.count == 1)
        let challenge = try #require(challenges.first)
        #expect(challenge.grantID == grant.grantID)
        #expect(challenge.computerID == transport.computerID)
        #expect(challenge.endpointSessionID == Self.endpointSessionID)
        #expect(challenge.endpointNonceHex.count == 64)
        #expect(challenge.endpointNonceHex.utf8.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66)
        })
        #expect(challenge.expiresAtUnix == grant.expiresAtUnix)

        let mainRequests = await transport.requests
        let pollRequests = await pollTransport.requests
        let pending = try #require(pollRequests.first {
            $0.0 == "/v2/endpoints/admissions/observation/pending"
        })
        #expect(pending.1 == "GET")
        #expect(pending.2 == "Bearer endpoint-session-fixture-token-0123456789")
        let mainPending = mainRequests.filter {
            $0.0 == "/v2/endpoints/admissions/observation/pending"
        }
        #expect(mainPending.isEmpty)
        let timeouts = await pollTransport.requestTimeoutIntervals
        let pollTimeout = timeouts["/v2/endpoints/admissions/observation/pending"]
        #expect(pollTimeout == 15)
        let caps = await pollTransport.requestMaxBytes
        #expect(caps["/v2/endpoints/admissions/observation/pending"] == 8 * 8 * 1024 + 8 * 1024)

        let paths = mainRequests.map(\.0)
        #expect(paths.filter { $0 == "/v2/endpoints/session/challenge" }.count == 1)
        #expect(paths.filter { $0 == "/v2/endpoints/session/complete" }.count == 1)
        #expect(!paths.contains("/v2/endpoints/admissions/observation/redeem"))
        #expect(paths.filter { $0.contains("/signals") }.isEmpty)
    }

    @Test func fetchesFullEightGrantBatchAtCapacity() async throws {
        let deploymentID = "dep_" + String(repeating: "5", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let grants = try (0..<8).map { _ in
            try Self.observationGrant(
                serverKey: serverKey,
                managerKey: Curve25519.Signing.PrivateKey(),
                deploymentID: deploymentID,
                computerID: transport.computerID,
                endpointPublicKeyHex: endpointPublicKeyHex,
                endpointSessionID: Self.endpointSessionID,
                grantID: UUID().uuidString.lowercased(),
                issuedAtUnix: now - 1,
                expiresAtUnix: now + 9
            )
        }
        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody(
            grants.map { ($0.grantID, transport.computerID, $0.expiresAtUnix, $0.token) }
        ))

        let challenges = try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        #expect(challenges.count == 8)
        #expect(Set(challenges.map(\.grantID)).count == 8)

        let requestCount = await transport.requests.count
        await #expect(throws: HelicoidError.setupBlocked(
            reason: "Observation grant polling is waiting for pending observation requests to finish."
        )) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }
        #expect(await transport.requests.count == requestCount)
    }

    @Test func acceptsExpiredEntriesWithoutDiscardingValidSiblings() async throws {
        let deploymentID = "dep_" + String(repeating: "4", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let expiredGrant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "6e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b",
            issuedAtUnix: now - 6,
            expiresAtUnix: now - 5
        )
        let activeGrant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "7f2a3b4c-5d6e-4f7a-9b0c-1d2e3f4a5b6c",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (expiredGrant.grantID, transport.computerID,
             expiredGrant.expiresAtUnix, expiredGrant.token),
            (activeGrant.grantID, transport.computerID,
             activeGrant.expiresAtUnix, activeGrant.token),
        ]))

        let challenges = try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        #expect(challenges.count == 1)
        #expect(challenges.first?.grantID == activeGrant.grantID)
    }

    @Test func rejectsTamperedExpiredEntryWithoutPartialAdmission() async throws {
        let deploymentID = "dep_" + String(repeating: "3", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let tamperedExpiredGrant = try Self.observationGrant(
            serverKey: Curve25519.Signing.PrivateKey(),
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "8a3b4c5d-6e7f-4a8b-9c0d-2e3f4a5b6c7d",
            issuedAtUnix: now - 6,
            expiresAtUnix: now - 5
        )
        let activeGrant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "9b4c5d6e-7f8a-4b9c-0d1e-3f4a5b6c7d8e",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (activeGrant.grantID, transport.computerID,
             activeGrant.expiresAtUnix, activeGrant.token),
            (tamperedExpiredGrant.grantID, transport.computerID,
             tamperedExpiredGrant.expiresAtUnix, tamperedExpiredGrant.token),
        ]))
        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The endpoint observation grant is invalid or expired."
        )) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }

        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (activeGrant.grantID, transport.computerID,
             activeGrant.expiresAtUnix, activeGrant.token),
        ]))
        #expect(try await client.fetchPendingObservationGrants(deploymentID: deploymentID).count == 1)
    }

    @Test func longPollOnDedicatedTransportDoesNotStarveMainRequests() async throws {
        let deploymentID = "dep_" + String(repeating: "6", count: 32)
        let mainTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID
        )
        let pollInner = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID
        )
        let pollTransport = PendingGrantGateTransport(inner: pollInner)
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: mainTransport,
            observationPollTransport: pollTransport
        )

        let fetchTask = Task {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }
        await pollTransport.waitForPendingRequest()

        let requests = try await client.listAvailableFileRequests(deploymentID: deploymentID)
        #expect(requests.isEmpty)

        await pollTransport.releasePendingRequest()
        #expect(try await fetchTask.value.isEmpty)
        let mainPaths = await mainTransport.requests.map(\.0)
        #expect(mainPaths.contains("/v2/endpoints/file-requests"))
        #expect(!mainPaths.contains("/v2/endpoints/admissions/observation/pending"))
        let pollPaths = await pollInner.requests.map(\.0)
        #expect(pollPaths == ["/v2/endpoints/admissions/observation/pending"])
    }

    @Test func multipleDeploymentsPollAndPrepareIndependently() async throws {
        let originA = URL(string: "https://a.helicoid.example:8920")!
        let originB = URL(string: "https://b.helicoid.example:8920")!
        let deploymentA = "dep_" + String(repeating: "a", count: 32)
        let deploymentB = "dep_" + String(repeating: "b", count: 32)
        let serverKeyA = Curve25519.Signing.PrivateKey()
        let serverKeyB = Curve25519.Signing.PrivateKey()
        let fixtureA = EndpointFileDeliveryTransportFixture(
            origin: originA,
            screenObservationEnabled: true,
            deploymentID: deploymentA,
            grantVerificationKeyHex: Self.lowerHex(serverKeyA.publicKey.rawRepresentation)
        )
        let fixtureB = EndpointFileDeliveryTransportFixture(
            origin: originB,
            screenObservationEnabled: true,
            deploymentID: deploymentB,
            grantVerificationKeyHex: Self.lowerHex(serverKeyB.publicKey.rawRepresentation)
        )
        let pollFixtureA = EndpointFileDeliveryTransportFixture(
            origin: originA,
            screenObservationEnabled: true,
            deploymentID: deploymentA,
            grantVerificationKeyHex: Self.lowerHex(serverKeyA.publicKey.rawRepresentation)
        )
        let pollFixtureB = EndpointFileDeliveryTransportFixture(
            origin: originB,
            screenObservationEnabled: true,
            deploymentID: deploymentB,
            grantVerificationKeyHex: Self.lowerHex(serverKeyB.publicKey.rawRepresentation)
        )
        let gateA = PendingGrantGateTransport(inner: pollFixtureA)
        let mainTransport = RoutingHTTPTransport(routes: [
            originA.host!: fixtureA,
            originB.host!: fixtureB,
        ])
        let pollTransport = RoutingHTTPTransport(routes: [
            originA.host!: gateA,
            originB.host!: pollFixtureB,
        ])
        let store = EndpointKeyFixtureStore()
        let client = EndpointEnrollmentClient(
            keyStore: store,
            transport: mainTransport,
            observationPollTransport: pollTransport,
            localUserIdentity: { "macos:uid:501" }
        )
        _ = try await client.enroll(
            serverAddress: originA.absoluteString,
            deploymentID: deploymentA,
            invitationID: invitationID,
            enrollmentCode: code
        )
        _ = try await client.enroll(
            serverAddress: originB.absoluteString,
            deploymentID: deploymentB,
            invitationID: invitationID,
            enrollmentCode: code
        )
        let endpointPublicKeyB = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentB
        )
        let now = Int64(Date().timeIntervalSince1970)
        let grantB = try Self.observationGrant(
            serverKey: serverKeyB,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentB,
            computerID: fixtureB.computerID,
            endpointPublicKeyHex: endpointPublicKeyB,
            endpointSessionID: Self.endpointSessionID,
            grantID: "5c6d7e8f-9a0b-4c5d-8e9f-0a1b2c3d4e5f",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )

        let fetchA = Task {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentA)
        }
        await gateA.waitForPendingRequest()

        // Deployment B is not blocked by A's in-flight long poll.
        #expect(try await client.fetchPendingObservationGrants(deploymentID: deploymentB).isEmpty)
        let preparedB = try await client.prepareObservationAdmission(
            grantToken: grantB.token,
            deploymentID: deploymentB
        )
        #expect(preparedB.grantID == grantB.grantID)
        #expect(preparedB.computerID == fixtureB.computerID)

        await gateA.releasePendingRequest()
        #expect(try await fetchA.value.isEmpty)
        let pollAPaths = await pollFixtureA.requests.map(\.0)
        let pollBPaths = await pollFixtureB.requests.map(\.0)
        #expect(pollAPaths == ["/v2/endpoints/admissions/observation/pending"])
        #expect(pollBPaths == ["/v2/endpoints/admissions/observation/pending"])
    }

    @Test func sameDeploymentRejectsConcurrentPollAndDirectPrepare() async throws {
        let deploymentID = "dep_" + String(repeating: "2", count: 32)
        let mainTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID
        )
        let pollInner = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID
        )
        let pollTransport = PendingGrantGateTransport(inner: pollInner)
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: mainTransport,
            observationPollTransport: pollTransport
        )
        let fetchTask = Task {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }
        await pollTransport.waitForPendingRequest()

        await #expect(throws: HelicoidError.setupBlocked(
            reason: "Another observation admission operation is in progress for this deployment."
        )) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }
        await #expect(throws: HelicoidError.setupBlocked(
            reason: "Another observation admission operation is in progress for this deployment."
        )) {
            try await client.prepareObservationAdmission(
                grantToken: "invalid",
                deploymentID: deploymentID
            )
        }

        await pollTransport.releasePendingRequest()
        #expect(try await fetchTask.value.isEmpty)
        let pollPaths = await pollInner.requests.map(\.0)
        #expect(pollPaths == ["/v2/endpoints/admissions/observation/pending"])
    }

    @Test func cancelledPollReleasesTheDeploymentOperation() async throws {
        let deploymentID = "dep_" + String(repeating: "0", count: 32)
        let mainTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID
        )
        let pollInner = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID
        )
        let pollTransport = PendingGrantGateTransport(inner: pollInner)
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: mainTransport,
            observationPollTransport: pollTransport
        )
        let fetchTask = Task {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }
        await pollTransport.waitForPendingRequest()
        fetchTask.cancel()

        // The cancellation handler must release the busy owner even though the
        // first transport request is still blocked.
        var replacementPollSucceeded = false
        for _ in 0..<64 {
            do {
                _ = try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
                replacementPollSucceeded = true
                break
            } catch let error as HelicoidError {
                if case .setupBlocked(let reason) = error,
                   reason == "Another observation admission operation is in progress for this deployment." {
                    await Task.yield()
                } else {
                    throw error
                }
            }
        }
        #expect(replacementPollSucceeded)

        await pollTransport.releasePendingRequest()
        do {
            _ = try await fetchTask.value
            Issue.record("A cancelled observation poll returned a value")
        } catch {
            #expect(error is CancellationError)
        }
    }

    @Test func publicGrantVerifierRejectsExpiredToken() async throws {
        let deploymentID = "dep_" + String(repeating: "2", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let endpointKey = Curve25519.Signing.PrivateKey()
        let endorsement = "f0e1d2c3-b4a5-4968-8776-655443322110"
        let now = Int64(Date().timeIntervalSince1970)
        let grant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: "e475b9ca-801a-4f71-b5d5-b87daaaae731",
            endpointPublicKeyHex: Self.lowerHex(endpointKey.publicKey.rawRepresentation),
            endpointSessionID: Self.endpointSessionID,
            grantID: endorsement,
            issuedAtUnix: now - 6,
            expiresAtUnix: now - 5
        )
        let expected = ObservationAdmissionEndpoint(
            deploymentID: deploymentID,
            computerID: "e475b9ca-801a-4f71-b5d5-b87daaaae731",
            endpointPublicKeyHex: Self.lowerHex(endpointKey.publicKey.rawRepresentation),
            endpointSessionID: Self.endpointSessionID,
            enrollmentEpoch: 1
        )

        #expect(throws: HelicoidError.authenticationFailed(
            detail: "The endpoint observation grant is invalid or expired."
        )) {
            _ = try ObservationAdmissionGrantVerifier.verify(
                token: grant.token,
                serverPublicKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation),
                expected: expected,
                nowUnixSeconds: now
            )
        }
    }

    @Test func refusesPendingPollWithoutFullBatchCapacityBeforeNetwork() async throws {
        let deploymentID = "dep_" + String(repeating: "8", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let grant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "8a0d1f42-5b8f-4d4d-b06f-58a3f1e6c2a9",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (grant.grantID, transport.computerID, grant.expiresAtUnix, grant.token),
        ]))
        #expect(try await client.fetchPendingObservationGrants(deploymentID: deploymentID).count == 1)

        let requestCountBeforeRefusal = await transport.requests.count
        await #expect(throws: HelicoidError.setupBlocked(
            reason: "Observation grant polling is waiting for pending observation requests to finish."
        )) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }
        let requestCountAfterRefusal = await transport.requests.count
        #expect(requestCountAfterRefusal == requestCountBeforeRefusal)
    }

    @Test func refusesPendingFetchWhenScreenObservationIsDisabled() async throws {
        let deploymentID = "dep_" + String(repeating: "9", count: 32)
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: false,
            deploymentID: deploymentID
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )

        await #expect(throws: HelicoidError.setupBlocked(
            reason: "Screen observation is not enabled by this deployment."
        )) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }
        let paths = await transport.requests.map(\.0)
        #expect(paths.contains("/health"))
        #expect(!paths.contains("/v2/endpoints/admissions/observation/pending"))
        #expect(!paths.contains("/v2/endpoints/session/challenge"))
        #expect(!paths.contains("/v2/endpoints/session/complete"))
        #expect(!paths.contains("/v2/endpoints/self"))
    }

    @Test func rejectsPendingGrantForAnotherComputer() async throws {
        let deploymentID = "dep_" + String(repeating: "b", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let grant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "4b9ba3e6-7e42-4c88-95a8-6e9c70cf9f19",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        let otherComputerID = "f4b0c9e2-6a7f-4a9f-8f6d-9f8f6b2c1d3e"
        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (grant.grantID, otherComputerID, grant.expiresAtUnix, grant.token),
        ]))

        await #expect(throws: HelicoidError.serverContractUnavailable) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }

        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (grant.grantID, transport.computerID, grant.expiresAtUnix, grant.token),
        ]))
        #expect(try await client.fetchPendingObservationGrants(deploymentID: deploymentID).count == 1)
    }

    @Test func rejectsStaleEndpointSessionEpochAndKeyBindings() async throws {
        let deploymentID = "dep_" + String(repeating: "7", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let staleSessionGrant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: "0b8d2d3f-0c4a-4f4a-9d3e-7f3b6f1c2a90",
            grantID: "7c1e7e2a-1f4c-4f1e-9f0a-6f4b2d9c8e71",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (staleSessionGrant.grantID, transport.computerID,
             staleSessionGrant.expiresAtUnix, staleSessionGrant.token),
        ]))
        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The endpoint observation grant is invalid or expired."
        )) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }

        let staleEpochGrant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "2d4b8d1a-6c3e-4f6b-8b2d-1f0e9c7a5d43",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9,
            enrollmentEpoch: 2
        )
        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (staleEpochGrant.grantID, transport.computerID,
             staleEpochGrant.expiresAtUnix, staleEpochGrant.token),
        ]))
        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The endpoint observation grant is invalid or expired."
        )) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }

        let staleEndpointKey = Curve25519.Signing.PrivateKey()
        let staleKeyGrant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: Self.lowerHex(staleEndpointKey.publicKey.rawRepresentation),
            endpointSessionID: Self.endpointSessionID,
            grantID: "9e6c3a2b-5d1f-4c7e-8a0b-3d2f1e4c6b85",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (staleKeyGrant.grantID, transport.computerID,
             staleKeyGrant.expiresAtUnix, staleKeyGrant.token),
        ]))
        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The endpoint observation grant is invalid or expired."
        )) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }
    }

    @Test func rejectsDuplicatePendingObservationGrants() async throws {
        let deploymentID = "dep_" + String(repeating: "c", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let grant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "ff4d5d5b-ccb5-4f4d-91f1-a6d8c9a3ae08",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (grant.grantID, transport.computerID, grant.expiresAtUnix, grant.token),
            (grant.grantID, transport.computerID, grant.expiresAtUnix, grant.token),
        ]))

        await #expect(throws: HelicoidError.serverContractUnavailable) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }

        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (grant.grantID, transport.computerID, grant.expiresAtUnix, grant.token),
        ]))
        #expect(try await client.fetchPendingObservationGrants(deploymentID: deploymentID).count == 1)
    }

    @Test func rejectsExpiredOrMismatchedPendingObservationGrant() async throws {
        let deploymentID = "dep_" + String(repeating: "d", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let grant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "1d1872b1-42e5-4a2d-96e0-ac66b0fc51e0",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )

        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (grant.grantID, transport.computerID, now - 1, grant.token),
        ]))
        // The unsigned envelope says expired while the signed grant is still
        // active. This is an inconsistent delivery, not a safely stale grant,
        // so the credential check must reject it.
        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The endpoint observation grant is invalid or expired."
        )) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }

        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (grant.grantID, transport.computerID, now + 10, grant.token),
        ]))
        await #expect(throws: HelicoidError.serverContractUnavailable) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }

        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            ("c0d3c0de-4b01-4e6c-8f2a-7c9f1d2e3a4b", transport.computerID,
             grant.expiresAtUnix, grant.token),
        ]))
        await #expect(throws: HelicoidError.serverContractUnavailable) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }
    }

    @Test func rejectsOversizedAndMalformedPendingObservationGrantPayloads() async throws {
        let deploymentID = "dep_" + String(repeating: "e", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let now = Int64(Date().timeIntervalSince1970)
        let repeated = (0..<9).map { index in
            [
                "grant_id": "00000000-0000-4000-8000-\(String(format: "%012d", index))",
                "computer_id": transport.computerID,
                "expires_at_unix": now + 9,
                "grant_token": "token",
            ] as [String: Any]
        }
        await transport.setPendingObservationGrantResponse(
            try JSONSerialization.data(withJSONObject: ["grants": repeated])
        )
        await #expect(throws: HelicoidError.serverContractUnavailable) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }

        let extraField = try JSONSerialization.data(withJSONObject: [
            "grants": [[
                "grant_id": "b8eeedb7-1d8d-4c29-9e13-05ec6045a173",
                "computer_id": transport.computerID,
                "expires_at_unix": now + 9,
                "grant_token": "token",
                "unexpected": true,
            ]],
        ])
        await transport.setPendingObservationGrantResponse(extraField)
        await #expect(throws: HelicoidError.serverContractUnavailable) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }

        let unknownEnvelopeField = try JSONSerialization.data(withJSONObject: [
            "grants": [],
            "unexpected": true,
        ])
        await transport.setPendingObservationGrantResponse(unknownEnvelopeField)
        await #expect(throws: HelicoidError.serverContractUnavailable) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }
    }

    @Test func rejectsTamperedPendingGrantWithoutPartialAdmission() async throws {
        let deploymentID = "dep_" + String(repeating: "f", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let transport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let validGrant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "a1f27d40-0c3f-4b91-95bf-6f0f0b9ec6cf",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        let tamperedGrant = try Self.observationGrant(
            serverKey: Curve25519.Signing.PrivateKey(),
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: transport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "b5e7c5f1-6a2d-4e8c-8f3a-2d1b0c9e7a64",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (validGrant.grantID, transport.computerID, validGrant.expiresAtUnix, validGrant.token),
            (tamperedGrant.grantID, transport.computerID, tamperedGrant.expiresAtUnix, tamperedGrant.token),
        ]))

        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The endpoint observation grant is invalid or expired."
        )) {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }

        await transport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (validGrant.grantID, transport.computerID, validGrant.expiresAtUnix, validGrant.token),
        ]))
        #expect(try await client.fetchPendingObservationGrants(deploymentID: deploymentID).count == 1)
    }

    @Test func forgettingIdentityDuringPendingFetchDiscardsDeliveredGrant() async throws {
        let deploymentID = "dep_" + String(repeating: "1", count: 32)
        let serverKey = Curve25519.Signing.PrivateKey()
        let innerTransport = EndpointFileDeliveryTransportFixture(
            origin: URL(string: server)!,
            screenObservationEnabled: true,
            deploymentID: deploymentID,
            grantVerificationKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation)
        )
        let transport = PendingGrantGateTransport(inner: innerTransport)
        let store = EndpointKeyFixtureStore()
        let client = try await makeObservationClient(
            deploymentID: deploymentID,
            store: store,
            transport: transport
        )
        let endpointPublicKeyHex = try await enrolledEndpointPublicKeyHex(
            store: store,
            deploymentID: deploymentID
        )
        let now = Int64(Date().timeIntervalSince1970)
        let grant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: Curve25519.Signing.PrivateKey(),
            deploymentID: deploymentID,
            computerID: innerTransport.computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: "7ce0c16f-4a63-4e5f-92dd-8f87c8a3b6b4",
            issuedAtUnix: now - 1,
            expiresAtUnix: now + 9
        )
        await innerTransport.setPendingObservationGrantResponse(try Self.pendingObservationGrantBody([
            (grant.grantID, innerTransport.computerID, grant.expiresAtUnix, grant.token),
        ]))

        let fetchTask = Task {
            try await client.fetchPendingObservationGrants(deploymentID: deploymentID)
        }
        await transport.waitForPendingRequest()
        try await client.forgetIdentity(deploymentID: deploymentID)
        await transport.releasePendingRequest()

        await #expect(throws: HelicoidError.authenticationFailed(
            detail: "The saved endpoint identity changed while this request was in progress."
        )) {
            _ = try await fetchTask.value
        }

        // The invalidated poll must not leave the deployment busy or poison a
        // replacement identity.
        _ = try await client.enroll(
            serverAddress: server,
            deploymentID: deploymentID,
            invitationID: invitationID,
            enrollmentCode: code
        )
        #expect(try await client.fetchPendingObservationGrants(deploymentID: deploymentID).isEmpty)
    }

    private static let endpointSessionID = "b4a3f66d-4ac1-4ac6-8847-e50d0c6f55a1"
    private static let endpointCertificatePEM =
        "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n"
    private static let otherEndpointCertificatePEM =
        "-----BEGIN CERTIFICATE-----\nBQYHCA==\n-----END CERTIFICATE-----\n"

    private struct ObservationGrantMaterial {
        let token: String
        let grantID: String
        let expiresAtUnix: Int64
    }

    private func makeObservationClient(
        deploymentID: String,
        store: EndpointKeyFixtureStore,
        transport: any HTTPTransport,
        observationPollTransport: (any HTTPTransport)? = nil
    ) async throws -> EndpointEnrollmentClient {
        let client = EndpointEnrollmentClient(
            keyStore: store,
            transport: transport,
            observationPollTransport: observationPollTransport,
            localUserIdentity: { "macos:uid:501" }
        )
        _ = try await client.enroll(
            serverAddress: server,
            deploymentID: deploymentID,
            invitationID: invitationID,
            enrollmentCode: code
        )
        return client
    }

    private func enrolledEndpointPublicKeyHex(
        store: EndpointKeyFixtureStore,
        deploymentID: String
    ) async throws -> String {
        let account = SHA256.hash(data: Data(deploymentID.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        let storedData = try #require(await store.read(account: account))
        let stored = try JSONDecoder().decode(StoredEndpointFixture.self, from: storedData)
        let endpointKey = try Curve25519.Signing.PrivateKey(rawRepresentation: stored.privateKey)
        return Self.lowerHex(endpointKey.publicKey.rawRepresentation)
    }

    @discardableResult
    private func replaceStoredEndpointPrivateKey(
        store: EndpointKeyFixtureStore,
        deploymentID: String,
        privateKey: Data
    ) async throws -> Data {
        let account = SHA256.hash(data: Data(deploymentID.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
        let storedData = try #require(await store.read(account: account))
        let stored = try JSONDecoder().decode(StoredEndpointFixture.self, from: storedData)
        let replacement = StoredEndpointFixture(
            version: stored.version,
            deploymentID: stored.deploymentID,
            privateKey: privateKey,
            result: stored.result,
            serverAddress: stored.serverAddress,
            grantVerificationPublicKeyHex: stored.grantVerificationPublicKeyHex,
            authorityGeneration: stored.authorityGeneration
        )
        let encoded = try JSONEncoder().encode(replacement)
        try await store.update(encoded, account: account)
        return stored.privateKey
    }

    private func preparedObservationChallenge(
        client: EndpointEnrollmentClient,
        deploymentID: String,
        serverKey: Curve25519.Signing.PrivateKey,
        managerKey: Curve25519.Signing.PrivateKey,
        computerID: String,
        endpointPublicKeyHex: String,
        lifetimeSeconds: Int64 = 10
    ) async throws -> (
        challenge: ObservationAdmissionChallenge,
        binding: Data,
        proof: String,
        grant: VerifiedObservationAdmissionGrant
    ) {
        let now = Int64(Date().timeIntervalSince1970)
        let expiresAt = now + lifetimeSeconds
        let grant = try Self.observationGrant(
            serverKey: serverKey,
            managerKey: managerKey,
            deploymentID: deploymentID,
            computerID: computerID,
            endpointPublicKeyHex: endpointPublicKeyHex,
            endpointSessionID: Self.endpointSessionID,
            grantID: UUID().uuidString.lowercased(),
            issuedAtUnix: now,
            expiresAtUnix: expiresAt
        )
        let verifiedGrant = try ObservationAdmissionGrantVerifier.verify(
            token: grant.token,
            serverPublicKeyHex: Self.lowerHex(serverKey.publicKey.rawRepresentation),
            expected: ObservationAdmissionEndpoint(
                deploymentID: deploymentID,
                computerID: computerID,
                endpointPublicKeyHex: endpointPublicKeyHex,
                endpointSessionID: Self.endpointSessionID,
                enrollmentEpoch: 1
            ),
            nowUnixSeconds: now
        )
        let challenge = try await client.prepareObservationAdmission(
            grantToken: grant.token,
            deploymentID: deploymentID
        )
        let binding = Self.webRTCChannelBinding()
        let proof = try Self.managerProof(
            challenge: challenge,
            deploymentID: deploymentID,
            managerKey: managerKey,
            channelBinding: binding
        )
        return (challenge, binding, proof, verifiedGrant)
    }

    private static func managerProof(
        challenge: ObservationAdmissionChallenge,
        deploymentID: String,
        managerKey: Curve25519.Signing.PrivateKey,
        channelBinding: Data
    ) throws -> String {
        guard let channelBindingHex = ObservationAdmissionGrantVerifier.canonicalChannelBindingHex(
            channelBinding
        ) else {
            throw HelicoidError.authenticationFailed(detail: "Invalid test channel binding")
        }
        let message = Data(
            "hs-observation-peer-proof-v2|deployment:\(deploymentID)|grant:\(challenge.grantID)|computer:\(challenge.computerID)|endpoint_session:\(challenge.endpointSessionID)|epoch:1|nonce:\(challenge.endpointNonceHex)|channel_binding:\(channelBindingHex)".utf8
        )
        return Self.lowerHex(try managerKey.signature(for: message))
    }

    private static func observationGrant(
        serverKey: Curve25519.Signing.PrivateKey,
        managerKey: Curve25519.Signing.PrivateKey,
        deploymentID: String,
        computerID: String,
        endpointPublicKeyHex: String,
        endpointSessionID: String,
        grantID: String,
        issuedAtUnix: Int64,
        expiresAtUnix: Int64,
        enrollmentEpoch: Int64 = 1
    ) throws -> ObservationGrantMaterial {
        let accountID = "ef255e0d-4f8c-4c08-bff2-4e11cbd23f9d"
        let managerID = "7a01cf88-6fdb-4cc1-a72f-d155f5309355"
        let managerPublicKeyHex = Self.lowerHex(managerKey.publicKey.rawRepresentation)
        let payload = Data([
            "{\"version\":1,\"grant_id\":\"", grantID,
            "\",\"deployment_id\":\"", deploymentID,
            "\",\"account_id\":\"", accountID,
            "\",\"manager_id\":\"", managerID,
            "\",\"manager_public_key\":\"", managerPublicKeyHex,
            "\",\"computer_id\":\"", computerID,
            "\",\"endpoint_public_key\":\"", endpointPublicKeyHex,
            "\",\"endpoint_session_id\":\"", endpointSessionID,
            "\",\"enrollment_epoch\":", String(enrollmentEpoch),
            ",\"issued_at_unix\":", String(issuedAtUnix),
            ",\"expires_at_unix\":", String(expiresAtUnix),
            ",\"capability\":\"observe\"}",
        ].joined().utf8)
        let signature = try serverKey.signature(
            for: Data("hs-observation-grant-v1\0".utf8) + payload
        )
        let token = payload.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            + "." + Self.lowerHex(signature)
        return ObservationGrantMaterial(
            token: token,
            grantID: grantID,
            expiresAtUnix: expiresAtUnix
        )
    }

    private static func pendingObservationGrantBody(
        _ grants: [(grantID: String, computerID: String, expiresAtUnix: Int64, grantToken: String)]
    ) throws -> Data {
        let values = grants.map { grant -> [String: Any] in
            [
                "grant_id": grant.grantID,
                "computer_id": grant.computerID,
                "expires_at_unix": grant.expiresAtUnix,
                "grant_token": grant.grantToken,
            ]
        }
        return try JSONSerialization.data(withJSONObject: ["grants": values])
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
