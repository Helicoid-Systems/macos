import CryptoKit
import Darwin
import Foundation
import Security
import SystemConfiguration

/// The endpoint identity created by redeeming a one-time Manager invitation.
/// This establishes a pending enrollment only; it does not authorize capture,
/// observation, input, or a live connection.
public struct EndpointEnrollmentResult: Codable, Sendable, Equatable {
    public let computerID: String
    public let friendlyName: String
    public let platform: String
    public let enrollmentState: String
    public let enrollmentEpoch: Int

    enum CodingKeys: String, CodingKey {
        case computerID = "id"
        case friendlyName = "friendly_name"
        case platform
        case enrollmentState = "enrollment_state"
        case enrollmentEpoch = "enrollment_epoch"
    }
}

public struct EndpointFileReceivedFile: Sendable, Equatable {
    public let jobID: String
    public let fileName: String
    public let path: String
}

public struct EndpointFileRequest: Identifiable, Sendable, Equatable {
    public let id: String
    public let revision: Int64
    public let title: String
    public let instructions: String
    public let allowedExtensions: [String]
    public let maxFileCount: UInt32
    public let maxTotalSizeBytes: UInt64
    public let closesAtUnix: Int64
    public let replacementAllowed: Bool

    public var allowedExtensionSummary: String {
        allowedExtensions.contains("*") ? "Any file type" : allowedExtensions.map { ".\($0)" }.joined(separator: ", ")
    }
}

public struct EndpointFileRequestSubmissionFile: Identifiable, Sendable, Equatable {
    public let id: String
    public let fileName: String
    public let fileSizeBytes: UInt64
    public let sha256: String
    public let state: String
}

public struct EndpointFileRequestSubmission: Identifiable, Sendable, Equatable {
    public let id: String
    public let requestID: String
    public let requestRevision: Int64
    public let computerID: String
    public let localUserDisplayName: String
    public let state: String
    public let createdAtUnix: Int64
    public let files: [EndpointFileRequestSubmissionFile]
}

/// Endpoint-generated nonce for the Manager's peer proof. The grant token is
/// intentionally kept inside the enrollment actor between these two calls.
public struct ObservationAdmissionChallenge: Sendable, Equatable {
    public let id: UUID
    public let grantID: String
    public let computerID: String
    public let endpointSessionID: String
    public let endpointNonceHex: String
    public let expiresAtUnix: Int64
}

public enum ObservationSignalKind: String, Sendable, Encodable {
    case offer
    case answer
    case ice
    case close
}

public struct ObservationSignalMessage: Sendable, Decodable, Equatable {
    public let sequence: UInt64
    public let sender: String
    public let kind: String
    public let payload: String

    enum CodingKeys: String, CodingKey {
        case sequence
        case sender
        case kind
        case payload
    }
}

public struct ObservationSignalBatch: Sendable, Decodable, Equatable {
    public let cursor: UInt64
    public let messages: [ObservationSignalMessage]

    enum CodingKeys: String, CodingKey {
        case cursor
        case messages
    }
}

public struct EndpointObservationAdmission: Sendable {
    public let grantID: String
    public let computerID: String
    public let endpointSessionID: String
    public let expiresAtUnix: Int64

    fileprivate let deploymentID: String
    private let localUserID: String
    private let localUserIdentity: @Sendable () throws -> String?
    private let channelBindingHex: String
    private let currentChannelBinding: @Sendable () throws -> Data

    fileprivate init(
        deploymentID: String,
        grantID: String,
        computerID: String,
        endpointSessionID: String,
        expiresAtUnix: Int64,
        localUserID: String,
        channelBindingHex: String,
        currentChannelBinding: @escaping @Sendable () throws -> Data,
        localUserIdentity: @escaping @Sendable () throws -> String?
    ) {
        self.deploymentID = deploymentID
        self.grantID = grantID
        self.computerID = computerID
        self.endpointSessionID = endpointSessionID
        self.expiresAtUnix = expiresAtUnix
        self.localUserID = localUserID
        self.channelBindingHex = channelBindingHex
        self.currentChannelBinding = currentChannelBinding
        self.localUserIdentity = localUserIdentity
    }

    /// Synchronous frame-path guard. The lease cannot be constructed by
    /// callers; only the enrollment client returns one after server redemption.
    public func belongsToCurrentConsoleUser() -> Bool {
        do {
            guard try localUserIdentity() == localUserID,
                  let currentHex = ObservationAdmissionGrantVerifier.canonicalChannelBindingHex(
                    try currentChannelBinding()
                  ) else {
                return false
            }
            return currentHex == channelBindingHex
        } catch {
            return false
        }
    }
}

/// Redeems an endpoint invitation over system-trusted HTTPS and keeps the
/// endpoint signing key in the macOS Keychain. The one-time code is never
/// persisted by this client.
public actor EndpointEnrollmentClient {
    private let keyStore: any EndpointEnrollmentKeyStoring
    private let transport: any HTTPTransport
    private let receivedFilesDirectory: @Sendable () throws -> URL
    private let localUserIdentity: @Sendable () throws -> String?
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private var pendingObservationAdmissions: [UUID: PendingObservationAdmission] = [:]
    private var observationGrantExpirations: [ObservationGrantKey: Int64] = [:]
    private var activeObservationAdmissions: [ObservationGrantKey: ActiveObservationAdmission] = [:]
    private var cachedEndpointSessions: [String: CachedEndpointSession] = [:]
    private var endpointSessionFlights: [String: EndpointSessionFlight] = [:]
    private var endpointIdentityGenerations: [String: UInt64] = [:]

    public init(transport: (any HTTPTransport)? = nil) {
        self.keyStore = KeychainEndpointEnrollmentKeyStore()
        self.transport = transport ?? Self.makeTransport()
        self.receivedFilesDirectory = { try Self.receivedFilesDirectoryURL() }
        self.localUserIdentity = { Self.verifiedConsoleUserIdentity() }
    }

    init(
        keyStore: any EndpointEnrollmentKeyStoring,
        transport: any HTTPTransport,
        receivedFilesDirectory: @escaping @Sendable () throws -> URL = { try EndpointEnrollmentClient.receivedFilesDirectoryURL() },
        localUserIdentity: @escaping @Sendable () throws -> String? = { EndpointEnrollmentClient.verifiedConsoleUserIdentity() }
    ) {
        self.keyStore = keyStore
        self.transport = transport
        self.receivedFilesDirectory = receivedFilesDirectory
        self.localUserIdentity = localUserIdentity
    }

    /// Remove this deployment's locally saved endpoint identity. This does not
    /// change the server-side computer record or move its queued work. A fresh
    /// invitation after recovery creates a separate computer identity.
    public func forgetIdentity(deploymentID: String) async throws {
        let deployment = deploymentID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !deployment.isEmpty, deployment.count <= 128,
              deployment.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw HelicoidError.invalidInput(field: "Deployment ID", detail: "The saved deployment ID is invalid.")
        }

        let generation = endpointIdentityGenerations[deployment, default: 0]
        guard generation < UInt64.max else {
            throw HelicoidError.authenticationFailed(detail: "The endpoint identity cannot be safely reset right now.")
        }
        endpointIdentityGenerations[deployment] = generation + 1
        if let flight = endpointSessionFlights.removeValue(forKey: deployment) {
            flight.task.cancel()
        }
        cachedEndpointSessions.removeValue(forKey: deployment)
        pendingObservationAdmissions = pendingObservationAdmissions.filter {
            $0.value.context.deploymentID != deployment
        }
        observationGrantExpirations = observationGrantExpirations.filter {
            $0.key.deploymentID != deployment
        }
        activeObservationAdmissions = activeObservationAdmissions.filter {
            $0.key.deploymentID != deployment
        }

        try await keyStore.delete(account: Self.keychainAccount(for: deployment))
    }

    /// Redeem invitation details copied from the Manager's one-time display.
    public func enroll(
        serverAddress: String,
        deploymentID: String,
        invitationID: String,
        enrollmentCode: String
    ) async throws -> EndpointEnrollmentResult {
        let baseURL = try Self.validateServerAddress(serverAddress)
        let deployment = deploymentID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !deployment.isEmpty, deployment.count <= 128,
              deployment.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw HelicoidError.invalidInput(field: "Deployment ID", detail: "Enter the deployment ID shown with the invitation.")
        }
        guard Self.isCanonicalUUID(invitationID) else {
            throw HelicoidError.invalidInput(field: "Invitation ID", detail: "Enter the complete invitation UUID shown by the Manager.")
        }
        guard enrollmentCode.utf8.count == 43,
              enrollmentCode.utf8.allSatisfy({
                  ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95
              }) else {
            throw HelicoidError.invalidInput(field: "Enrollment code", detail: "The one-time code must be 43 letters, digits, underscores, or hyphens.")
        }

        let account = Self.keychainAccount(for: deployment)
        var stored = try await loadOrCreateIdentity(account: account, deploymentID: deployment)
        defer { stored.privateKey.resetBytes(in: stored.privateKey.startIndex..<stored.privateKey.endIndex) }
        guard stored.result == nil else {
            throw HelicoidError.authenticationFailed(detail: "This Mac already has an endpoint identity for that deployment. Ask the Manager to inspect its enrollment before trying another invitation.")
        }
        guard stored.privateKey.count == 32 else {
            throw HelicoidError.authenticationFailed(detail: "The protected endpoint identity is invalid. It was not replaced.")
        }

        let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: stored.privateKey).publicKey.rawRepresentation
        let publicKeyHex = AuthV2Canonical.lowercaseHex(publicKey)
        let codeHash = AuthV2Canonical.lowercaseHex(Data(SHA256.hash(data: Data(enrollmentCode.utf8))))
        let message = Data(
            "hs-endpoint-enroll-v2|deployment:\(deployment)|invitation:\(invitationID)|code_hash:\(codeHash)|endpoint:\(publicKeyHex)".utf8
        )
        let proof = try Curve25519.Signing.PrivateKey(rawRepresentation: stored.privateKey).signature(for: message)

        let payload = EndpointEnrollmentRequest(
            invitationID: invitationID,
            enrollmentCode: enrollmentCode,
            publicKey: publicKeyHex,
            proof: AuthV2Canonical.lowercaseHex(proof)
        )
        var body = try encoder.encode(payload)
        defer { body.resetBytes(in: body.startIndex..<body.endIndex) }

        let endpointURL = baseURL.appending(path: "/v2/endpoints/enroll")
        var request = URLRequest(url: endpointURL)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = body
        defer { request.httpBody = nil }

        let (responseData, response) = try await transport.bytes(for: request, maxBytes: 16_384)
        guard let http = response as? HTTPURLResponse, http.url == endpointURL else {
            throw HelicoidError.serverContractUnavailable
        }
        guard http.statusCode == 201 else {
            throw http.statusCode == 401
                ? HelicoidError.authenticationFailed(detail: "The invitation was rejected, expired, revoked, or already used. Ask the Manager for a new invitation.")
                : HelicoidError.serverContractUnavailable
        }

        let envelope: EndpointEnrollmentEnvelope
        do {
            envelope = try decoder.decode(EndpointEnrollmentEnvelope.self, from: responseData)
        } catch {
            throw HelicoidError.authenticationFailed(detail: "The server accepted the one-time invitation but returned invalid enrollment details. Ask the Manager to inspect the pending endpoint before retrying.")
        }
        let result = envelope.computer
        guard envelope.state == "pending_approval",
              Self.isCanonicalUUID(result.computerID),
              result.platform == "macos",
              result.enrollmentState == "pending",
              result.enrollmentEpoch == 1 else {
            throw HelicoidError.authenticationFailed(detail: "The server accepted the one-time invitation but returned mismatched enrollment details. Ask the Manager to inspect the pending endpoint before retrying.")
        }

        let authority: DeploymentAuthorityResponse
        do {
            authority = try await fetchDeploymentAuthority(
                baseURL: baseURL,
                expectedDeploymentID: deployment
            )
        } catch {
            throw HelicoidError.authenticationFailed(detail: "The server accepted the invitation, but its authority checkpoint could not be pinned. Ask the Manager to inspect this endpoint before retrying.")
        }
        stored.version = 4
        stored.serverAddress = baseURL.absoluteString
        stored.grantVerificationPublicKeyHex = authority.grantSigningPublicKey
        stored.authorityGeneration = authority.authorityGeneration
        stored.result = result
        var saved = try encoder.encode(stored)
        defer { saved.resetBytes(in: saved.startIndex..<saved.endIndex) }
        do {
            try await keyStore.update(saved, account: account)
        } catch {
            throw HelicoidError.authenticationFailed(detail: "The server accepted the one-time invitation, but the endpoint result could not be saved in the Keychain. Ask the Manager to inspect the pending endpoint before retrying.")
        }
        return result
    }

    /// Return the public grant-verification key and checkpoint saved at enrollment.
    /// A changed server authority requires reviewed recovery and re-enrollment.
    public func savedGrantVerificationPublicKey(deploymentID: String) async throws -> String {
        let deployment = deploymentID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !deployment.isEmpty, deployment.count <= 128,
              deployment.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw HelicoidError.invalidInput(field: "Deployment ID", detail: "The configured deployment identity is invalid.")
        }
        let account = Self.keychainAccount(for: deployment)
        guard var storedBytes = try await keyStore.read(account: account) else {
            throw HelicoidError.authenticationFailed(detail: "This Mac has no saved endpoint identity for the selected deployment.")
        }
        defer { storedBytes.resetBytes(in: storedBytes.startIndex..<storedBytes.endIndex) }
        let stored: StoredEndpointIdentity
        do {
            stored = try decoder.decode(StoredEndpointIdentity.self, from: storedBytes)
        } catch {
            throw HelicoidError.authenticationFailed(detail: "The saved endpoint identity is invalid.")
        }
        guard stored.version == 4 else {
            throw HelicoidError.authenticationFailed(
                detail: "This endpoint has no saved authority-generation checkpoint. Re-enroll it through the Manager after recovery review."
            )
        }
        guard stored.deploymentID == deployment,
              let generation = stored.authorityGeneration, generation > 0,
              let key = stored.grantVerificationPublicKeyHex,
              Self.isCanonicalLowerHex(key, byteCount: 32) else {
            throw HelicoidError.authenticationFailed(detail: "The saved deployment authority checkpoint is invalid. Re-enroll this endpoint through the Manager after recovery review.")
        }
        return key
    }

    /// Validate a Manager-delivered grant against the deployment key pinned at
    /// enrollment and bind it to a newly authenticated endpoint session.
    /// The caller sends `endpointNonceHex` to the Manager over its peer channel.
    public func prepareObservationAdmission(
        grantToken: String,
        deploymentID: String
    ) async throws -> ObservationAdmissionChallenge {
        let context = try await makeFileRequestSession(deploymentID: deploymentID)
        guard let verificationKey = context.grantVerificationPublicKeyHex else {
            throw HelicoidError.authenticationFailed(
                detail: "This endpoint has no pinned observation-grant key. A trusted enrollment is required."
            )
        }
        let expected = ObservationAdmissionEndpoint(
            deploymentID: context.deploymentID,
            computerID: context.computerID,
            endpointPublicKeyHex: context.endpointPublicKeyHex,
            endpointSessionID: context.session.sessionID,
            enrollmentEpoch: context.session.enrollmentEpoch
        )
        let grant = try ObservationAdmissionGrantVerifier.verify(
            token: grantToken,
            serverPublicKeyHex: verificationKey,
            expected: expected
        )
        let now = Int64(Date().timeIntervalSince1970)
        pendingObservationAdmissions = pendingObservationAdmissions.filter {
            $0.value.grant.expiresAtUnix > now
        }
        observationGrantExpirations = observationGrantExpirations.filter {
            $0.value > now
        }
        let grantKey = ObservationGrantKey(
            deploymentID: context.deploymentID,
            grantID: grant.grantID
        )
        guard observationGrantExpirations[grantKey] == nil else {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        guard pendingObservationAdmissions.count < 8 else {
            throw HelicoidError.setupBlocked(reason: "Too many observation requests are already waiting for Manager proof.")
        }
        let challenge = ObservationAdmissionChallenge(
            id: UUID(),
            grantID: grant.grantID,
            computerID: grant.computerID,
            endpointSessionID: grant.endpointSessionID,
            endpointNonceHex: ObservationAdmissionGrantVerifier.makeEndpointNonce(),
            expiresAtUnix: grant.expiresAtUnix
        )
        pendingObservationAdmissions[challenge.id] = PendingObservationAdmission(
            grantToken: grantToken,
            grant: grant,
            challenge: challenge,
            context: context
        )
        observationGrantExpirations[grantKey] = grant.expiresAtUnix
        return challenge
    }

    /// Send one bounded signaling value for the pending grant. This carries
    /// SDP/ICE only; a native peer must still verify its DTLS channel binding.
    public func publishObservationSignal(
        challengeID: UUID,
        kind: ObservationSignalKind,
        payload: String
    ) async throws {
        guard let pending = pendingObservationAdmissions[challengeID],
              pending.challenge.id == challengeID,
              pending.grant.expiresAtUnix > Int64(Date().timeIntervalSince1970) else {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        try requireSameLocalUser(pending.context.localUserID)
        try await verifyEndpointSession(
            pending.context.session,
            baseURL: pending.context.baseURL,
            deploymentID: pending.context.deploymentID,
            enrollment: pending.context.enrollment
        )
        guard Self.validObservationSignal(kind: kind, payload: payload) else {
            throw HelicoidError.invalidInput(
                field: "observation signaling",
                detail: "The signaling value is invalid or exceeds its size limit."
            )
        }
        let endpointURL = pending.context.baseURL.appending(
            path: "/v2/endpoints/admissions/observation/\(pending.grant.grantID)/signals"
        )
        var body = try encoder.encode(ObservationSignalRequest(kind: kind, payload: payload))
        defer { body.resetBytes(in: body.startIndex..<body.endIndex) }
        var request = URLRequest(url: endpointURL)
        request.httpMethod = "POST"
        request.timeoutInterval = 10
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(pending.context.session.token)", forHTTPHeaderField: "Authorization")
        request.httpBody = body
        defer { request.httpBody = nil }
        let (responseData, response) = try await transport.bytes(for: request, maxBytes: 1024)
        var responseBody = responseData
        defer { responseBody.resetBytes(in: responseBody.startIndex..<responseBody.endIndex) }
        guard let http = response as? HTTPURLResponse, http.url == endpointURL else {
            throw HelicoidError.serverContractUnavailable
        }
        guard http.statusCode == 204, responseBody.isEmpty else {
            if http.statusCode == 401 || http.statusCode == 403 {
                throw HelicoidError.authenticationFailed(
                    detail: "The endpoint observation session or grant is no longer current."
                )
            }
            throw HelicoidError.serverContractUnavailable
        }
    }

    /// Poll a bounded batch of Manager signaling values. The cursor belongs to
    /// the caller's exact pending grant and should be retained only in memory.
    public func pollObservationSignals(
        challengeID: UUID,
        after cursor: UInt64
    ) async throws -> ObservationSignalBatch {
        guard let pending = pendingObservationAdmissions[challengeID],
              pending.challenge.id == challengeID,
              pending.grant.expiresAtUnix > Int64(Date().timeIntervalSince1970) else {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        try requireSameLocalUser(pending.context.localUserID)
        try await verifyEndpointSession(
            pending.context.session,
            baseURL: pending.context.baseURL,
            deploymentID: pending.context.deploymentID,
            enrollment: pending.context.enrollment
        )
        var components = URLComponents(
            url: pending.context.baseURL.appending(
                path: "/v2/endpoints/admissions/observation/\(pending.grant.grantID)/signals"
            ),
            resolvingAgainstBaseURL: false
        )
        components?.queryItems = [URLQueryItem(name: "after", value: String(cursor))]
        guard let endpointURL = components?.url else {
            throw HelicoidError.serverContractUnavailable
        }
        var request = URLRequest(url: endpointURL)
        request.httpMethod = "GET"
        request.timeoutInterval = 10
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(pending.context.session.token)", forHTTPHeaderField: "Authorization")
        let (responseData, response) = try await transport.bytes(for: request, maxBytes: 1024 * 1024)
        var responseBody = responseData
        defer { responseBody.resetBytes(in: responseBody.startIndex..<responseBody.endIndex) }
        guard let http = response as? HTTPURLResponse, http.url == endpointURL else {
            throw HelicoidError.serverContractUnavailable
        }
        guard http.statusCode == 200 else {
            if http.statusCode == 401 || http.statusCode == 403 {
                throw HelicoidError.authenticationFailed(
                    detail: "The endpoint observation session or grant is no longer current."
                )
            }
            throw HelicoidError.serverContractUnavailable
        }
        do {
            return try decoder.decode(ObservationSignalBatch.self, from: responseBody)
        } catch {
            throw HelicoidError.serverContractUnavailable
        }
    }

    /// Verify the Manager's proof locally and redeem this exact one-use
    /// challenge with the server under the current endpoint bearer session.
    /// The exporter must read the live native verified-channel handle; the
    /// returned admission keeps using it to reject stale channel bindings.
    public func redeemObservationAdmission(
        challengeID: UUID,
        managerProofHex: String,
        currentVerifiedChannelBinding: @escaping @Sendable () throws -> Data
    ) async throws -> EndpointObservationAdmission {
        guard let pending = pendingObservationAdmissions.removeValue(forKey: challengeID) else {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        let context = pending.context
        let verifiedChannelBinding: Data
        do {
            verifiedChannelBinding = try currentVerifiedChannelBinding()
        } catch {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        guard let channelBindingHex = ObservationAdmissionGrantVerifier.canonicalChannelBindingHex(
            verifiedChannelBinding
        ) else {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        guard pending.challenge.id == challengeID,
              pending.grant.expiresAtUnix > Int64(Date().timeIntervalSince1970),
              let proof = Self.lowercaseHexData(managerProofHex, byteCount: 64),
              pending.grant.verifiesManagerProof(
                endpointNonceHex: pending.challenge.endpointNonceHex,
                channelBindingHex: channelBindingHex,
                signature: proof
              ) else {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        do {
            try requireSameLocalUser(context.localUserID)
        } catch {
            throw HelicoidError.setupBlocked(reason: "Observation stopped because the signed-in console user changed.")
        }
        try await verifyEndpointSession(
            context.session,
            baseURL: context.baseURL,
            deploymentID: context.deploymentID,
            enrollment: context.enrollment
        )
        guard pending.grant.expiresAtUnix > Int64(Date().timeIntervalSince1970),
              Self.currentChannelBindingMatches(
                currentVerifiedChannelBinding,
                expectedHex: channelBindingHex
              ) else {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        let request = RedeemObservationGrantRequest(
            grantToken: pending.grantToken,
            endpointNonce: pending.challenge.endpointNonceHex,
            channelBinding: channelBindingHex,
            managerProof: managerProofHex
        )
        var body = try encoder.encode(request)
        defer { body.resetBytes(in: body.startIndex..<body.endIndex) }
        let accepted: ObservationAdmissionAccepted = try await postJSON(
            body,
            to: context.baseURL.appending(path: "/v2/endpoints/admissions/observation/redeem"),
            bearerToken: context.session.token,
            expectedStatus: 200
        )
        guard accepted.grantID == pending.grant.grantID,
              accepted.computerID == context.computerID,
              accepted.endpointSessionID == context.session.sessionID,
              accepted.expiresAtUnix == pending.grant.expiresAtUnix else {
            throw HelicoidError.serverContractUnavailable
        }
        do {
            try requireSameLocalUser(context.localUserID)
        } catch {
            throw HelicoidError.setupBlocked(reason: "Observation stopped because the signed-in console user changed.")
        }
        guard Self.currentChannelBindingMatches(
            currentVerifiedChannelBinding,
            expectedHex: channelBindingHex
        ) else {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        let now = Int64(Date().timeIntervalSince1970)
        activeObservationAdmissions = activeObservationAdmissions.filter {
            $0.value.expiresAtUnix > now
        }
        guard activeObservationAdmissions.count < 8 else {
            throw HelicoidError.setupBlocked(reason: "Too many admitted observation leases are already active.")
        }
        activeObservationAdmissions[ObservationGrantKey(
            deploymentID: context.deploymentID,
            grantID: accepted.grantID
        )] = ActiveObservationAdmission(
            computerID: accepted.computerID,
            endpointSessionID: accepted.endpointSessionID,
            expiresAtUnix: accepted.expiresAtUnix
        )
        return EndpointObservationAdmission(
            deploymentID: context.deploymentID,
            grantID: accepted.grantID,
            computerID: accepted.computerID,
            endpointSessionID: accepted.endpointSessionID,
            expiresAtUnix: accepted.expiresAtUnix,
            localUserID: context.localUserID,
            channelBindingHex: channelBindingHex,
            currentChannelBinding: currentVerifiedChannelBinding,
            localUserIdentity: localUserIdentity
        )
    }

    /// Recheck the local owner and lease before continuing screen capture.
    /// Server redemption remains the admission decision; this short local
    /// lease prevents capture from surviving user changes or expiry.
    public func observationAdmissionIsCurrent(
        _ admission: EndpointObservationAdmission
    ) -> Bool {
        let grantKey = ObservationGrantKey(
            deploymentID: admission.deploymentID,
            grantID: admission.grantID
        )
        guard let active = activeObservationAdmissions[grantKey],
              active.computerID == admission.computerID,
              active.endpointSessionID == admission.endpointSessionID,
              active.expiresAtUnix == admission.expiresAtUnix,
              active.expiresAtUnix > Int64(Date().timeIntervalSince1970) else {
            return false
        }
        return admission.belongsToCurrentConsoleUser()
    }

    /// Release the in-memory owner binding when capture or its peer ends.
    public func endObservationAdmission(_ admission: EndpointObservationAdmission) {
        let grantKey = ObservationGrantKey(
            deploymentID: admission.deploymentID,
            grantID: admission.grantID
        )
        guard let active = activeObservationAdmissions[grantKey],
              active.computerID == admission.computerID,
              active.endpointSessionID == admission.endpointSessionID else {
            return
        }
        activeObservationAdmissions.removeValue(forKey: grantKey)
    }

    private func fetchDeploymentAuthority(
        baseURL: URL,
        expectedDeploymentID: String
    ) async throws -> DeploymentAuthorityResponse {
        let endpointURL = baseURL.appending(path: "/v2/deployment/authority")
        var request = URLRequest(url: endpointURL)
        request.httpMethod = "GET"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (body, response) = try await transport.bytes(for: request, maxBytes: 16_384)
        guard let http = response as? HTTPURLResponse, http.url == endpointURL,
              http.statusCode == 200 else {
            throw HelicoidError.authenticationFailed(detail: "The deployment authority could not be confirmed over the pinned server connection.")
        }
        let authority: DeploymentAuthorityResponse
        do {
            authority = try decoder.decode(DeploymentAuthorityResponse.self, from: body)
        } catch {
            throw HelicoidError.authenticationFailed(detail: "The deployment returned invalid authority details.")
        }
        guard authority.deploymentID == expectedDeploymentID,
              Self.isCanonicalLowerHex(authority.grantSigningPublicKey, byteCount: 32),
              authority.authorityGeneration > 0 else {
            throw HelicoidError.authenticationFailed(detail: "The deployment returned a mismatched authority identity or checkpoint.")
        }
        return authority
    }

    private func verifyAuthorityCheckpoint(
        baseURL: URL,
        deploymentID: String,
        grantVerificationPublicKeyHex: String?,
        authorityGeneration: Int64?
    ) async throws {
        guard let grantVerificationPublicKeyHex,
              Self.isCanonicalLowerHex(grantVerificationPublicKeyHex, byteCount: 32),
              let authorityGeneration, authorityGeneration > 0 else {
            throw HelicoidError.authenticationFailed(
                detail: "This endpoint has no saved authority-generation checkpoint. Re-enroll it through the Manager before using protected operations."
            )
        }
        let authority = try await fetchDeploymentAuthority(
            baseURL: baseURL,
            expectedDeploymentID: deploymentID
        )
        guard authority.grantSigningPublicKey == grantVerificationPublicKeyHex,
              authority.authorityGeneration == authorityGeneration else {
            invalidateEndpointAuthorityState(deploymentID: deploymentID)
            throw HelicoidError.authenticationFailed(
                detail: "The server authority differs from this endpoint's saved generation. Keep this endpoint quarantined and re-enroll it through the Manager after recovery review."
            )
        }
    }

    private func invalidateEndpointAuthorityState(deploymentID: String) {
        let generation = endpointIdentityGenerations[deploymentID, default: 0]
        if generation < UInt64.max {
            endpointIdentityGenerations[deploymentID] = generation + 1
        }
        if let flight = endpointSessionFlights.removeValue(forKey: deploymentID) {
            flight.task.cancel()
        }
        cachedEndpointSessions.removeValue(forKey: deploymentID)
        pendingObservationAdmissions = pendingObservationAdmissions.filter {
            $0.value.context.deploymentID != deploymentID
        }
        observationGrantExpirations = observationGrantExpirations.filter {
            $0.key.deploymentID != deploymentID
        }
        activeObservationAdmissions = activeObservationAdmissions.filter {
            $0.key.deploymentID != deploymentID
        }
    }

    /// Authenticate this enrolled endpoint, receive only its leased file jobs,
    /// verify every chunk and whole-file digest, and publish files atomically
    /// into a private per-user directory. The short-lived bearer is memory-only.
    public func receiveAvailableFiles(
        deploymentID: String
    ) async throws -> [EndpointFileReceivedFile] {
        let deployment = deploymentID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !deployment.isEmpty, deployment.count <= 128,
              deployment.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw HelicoidError.invalidInput(field: "Deployment ID", detail: "The configured deployment identity is invalid.")
        }
        let account = Self.keychainAccount(for: deployment)
        guard var storedBytes = try await keyStore.read(account: account) else {
            throw HelicoidError.authenticationFailed(detail: "This Mac has no saved endpoint identity for the selected deployment.")
        }
        defer { storedBytes.resetBytes(in: storedBytes.startIndex..<storedBytes.endIndex) }
        var stored: StoredEndpointIdentity
        do {
            stored = try decoder.decode(StoredEndpointIdentity.self, from: storedBytes)
        } catch {
            throw HelicoidError.authenticationFailed(detail: "The saved endpoint identity is invalid or has not completed enrollment.")
        }
        guard stored.version == 4 else {
            throw HelicoidError.authenticationFailed(
                detail: "This endpoint has no saved authority-generation checkpoint. Keep it quarantined and re-enroll it through the Manager after recovery review."
            )
        }
        guard stored.deploymentID == deployment,
              stored.privateKey.count == 32, let enrolled = stored.result,
              Self.isCanonicalUUID(enrolled.computerID), enrolled.platform == "macos",
              let serverAddress = stored.serverAddress else {
            throw HelicoidError.authenticationFailed(detail: "The saved endpoint identity is invalid or has not completed enrollment.")
        }
        defer { stored.privateKey.resetBytes(in: stored.privateKey.startIndex..<stored.privateKey.endIndex) }
        let baseURL = try Self.validateServerAddress(serverAddress)
        try await verifyAuthorityCheckpoint(
            baseURL: baseURL,
            deploymentID: deployment,
            grantVerificationPublicKeyHex: stored.grantVerificationPublicKeyHex,
            authorityGeneration: stored.authorityGeneration
        )
        try await requireFileJobsEnabled(baseURL: baseURL)
        let localUserID = try localUserIdentity()

        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: stored.privateKey)
        let publicKeyHex = AuthV2Canonical.lowercaseHex(privateKey.publicKey.rawRepresentation)
        let session = try await currentEndpointSession(
            baseURL: baseURL,
            deploymentID: deployment,
            enrollment: enrolled,
            localUserID: localUserID,
            publicKeyHex: publicKeyHex,
            privateKey: privateKey
        )
        guard let localUserID else {
            throw HelicoidError.setupBlocked(reason: "Waiting for an eligible signed-in console user.")
        }
        do {
            try requireSameLocalUser(localUserID)
        } catch is EndpointFileDeliveryPaused {
            let currentLocalUserID = try await refreshEndpointSessionForCurrentConsole(
                baseURL: baseURL,
                deploymentID: deployment,
                enrollment: enrolled,
                publicKeyHex: publicKeyHex,
                privateKey: privateKey
            )
            throw HelicoidError.setupBlocked(reason: currentLocalUserID == nil
                ? "Waiting for an eligible signed-in console user."
                : "File delivery paused after a console-user change. It will check again shortly.")
        }

        let jobsURL = baseURL.appending(path: "/v2/endpoints/jobs")
        var jobsRequest = URLRequest(url: jobsURL)
        jobsRequest.httpMethod = "GET"
        jobsRequest.timeoutInterval = 20
        jobsRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        jobsRequest.setValue("Bearer \(session.token)", forHTTPHeaderField: "Authorization")
        let (jobsData, jobsResponse) = try await transport.bytes(for: jobsRequest, maxBytes: 256 * 1024)
        guard let jobsHTTP = jobsResponse as? HTTPURLResponse, jobsHTTP.url == jobsURL,
              jobsHTTP.statusCode == 200 else {
            if let http = jobsResponse as? HTTPURLResponse, http.statusCode == 401 || http.statusCode == 403 {
                throw HelicoidError.authenticationFailed(detail: "The endpoint is waiting for administrator approval or its session is no longer valid.")
            }
            throw HelicoidError.serverContractUnavailable
        }
        let response = try decoder.decode(EndpointFileJobList.self, from: jobsData)
        guard response.jobs.count <= 50 else {
            throw HelicoidError.serverContractUnavailable
        }
        do {
            try requireSameLocalUser(localUserID)
        } catch is EndpointFileDeliveryPaused {
            let currentLocalUserID = try await refreshEndpointSessionForCurrentConsole(
                baseURL: baseURL,
                deploymentID: deployment,
                enrollment: enrolled,
                publicKeyHex: publicKeyHex,
                privateKey: privateKey
            )
            throw HelicoidError.setupBlocked(reason: currentLocalUserID == nil
                ? "Waiting for an eligible signed-in console user."
                : "File delivery paused after a console-user change. It will check again shortly.")
        }

        var received: [EndpointFileReceivedFile] = []
        received.reserveCapacity(response.jobs.count)
        for job in response.jobs {
            try Task.checkCancellation()
            do {
                let file = try await receive(
                    job,
                    baseURL: baseURL,
                    localUserID: localUserID,
                    bearerToken: session.token
                )
                received.append(file)
            } catch is EndpointFileDeliveryPaused {
                let currentLocalUserID = try await refreshEndpointSessionForCurrentConsole(
                    baseURL: baseURL,
                    deploymentID: deployment,
                    enrollment: enrolled,
                    publicKeyHex: publicKeyHex,
                    privateKey: privateKey
                )
                throw HelicoidError.setupBlocked(reason: currentLocalUserID == nil
                    ? "Waiting for an eligible signed-in console user."
                    : "File delivery paused after a console-user change. It will check again shortly.")
            } catch let failure as EndpointFileDeliveryFailure {
                try await reportFailure(jobID: job.id, detail: failure.detail,
                                        baseURL: baseURL, bearerToken: session.token)
            }
        }
        return received
    }

    /// Return only requests currently open for this enrolled computer and
    /// signed-in console user. The server still rechecks request revision and
    /// eligibility when the selected files are submitted.
    public func listAvailableFileRequests(deploymentID: String) async throws -> [EndpointFileRequest] {
        let context = try await makeFileRequestSession(deploymentID: deploymentID)
        return try await fetchAvailableFileRequests(using: context)
    }

    private func fetchAvailableFileRequests(
        using context: FileRequestSession
    ) async throws -> [EndpointFileRequest] {
        let endpoint = context.baseURL.appending(path: "/v2/endpoints/file-requests")
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.timeoutInterval = 20
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(context.session.token)", forHTTPHeaderField: "Authorization")
        let (body, response) = try await transport.bytes(for: request, maxBytes: 256 * 1024)
        guard let http = response as? HTTPURLResponse, http.url == endpoint else {
            throw HelicoidError.serverContractUnavailable
        }
        if http.statusCode == 401 || http.statusCode == 403 {
            throw HelicoidError.authenticationFailed(detail: "The endpoint is waiting for administrator approval or its session is no longer valid.")
        }
        guard http.statusCode == 200 else {
            throw HelicoidError.serverContractUnavailable
        }
        let result = try decoder.decode(EndpointFileRequestList.self, from: body)
        guard result.maxPageSize > 0, result.maxPageSize <= 100,
              result.requests.count <= result.maxPageSize else {
            throw HelicoidError.serverContractUnavailable
        }
        var seenIDs = Set<String>()
        let requests = try result.requests.map { request -> EndpointFileRequest in
            let extensions = request.allowedExtensions
            let validExtensions = !extensions.isEmpty && extensions.count <= 64 &&
                extensions.allSatisfy(Self.validRequestExtension) &&
                Set(extensions).count == extensions.count &&
                (!extensions.contains("*") || extensions.count == 1)
            guard Self.isCanonicalUUID(request.id), seenIDs.insert(request.id).inserted,
                  request.revision > 0, !request.title.isEmpty, request.title.count <= 120,
                  request.title.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
                  request.instructions.count <= 2000,
                  request.instructions.unicodeScalars.allSatisfy({
                      !CharacterSet.controlCharacters.contains($0) || "\n\r\t".unicodeScalars.contains($0)
                  }),
                  validExtensions, request.maxFileCount > 0, request.maxFileCount <= 50,
                  request.maxTotalSizeBytes > 0, request.maxTotalSizeBytes <= 128 * 1024 * 1024,
                  request.closesAtUnix > Int64(Date().timeIntervalSince1970),
                  request.closesAtUnix <= Int64(Date().timeIntervalSince1970) + 30 * 24 * 60 * 60 else {
                throw HelicoidError.serverContractUnavailable
            }
            return EndpointFileRequest(
                id: request.id,
                revision: request.revision,
                title: request.title,
                instructions: request.instructions,
                allowedExtensions: extensions,
                maxFileCount: request.maxFileCount,
                maxTotalSizeBytes: request.maxTotalSizeBytes,
                closesAtUnix: request.closesAtUnix,
                replacementAllowed: request.replacementAllowed
            )
        }
        try requireSameLocalUser(context.localUserID)
        return requests
    }

    /// Read submission history only for this enrolled computer and the exact
    /// local OS user represented by the newly authenticated endpoint session.
    public func listMyFileRequestSubmissions(
        deploymentID: String,
        requestID: String
    ) async throws -> [EndpointFileRequestSubmission] {
        guard Self.isCanonicalUUID(requestID) else {
            throw HelicoidError.invalidInput(field: "File request", detail: "The selected request identity is invalid.")
        }
        let context = try await makeFileRequestSession(deploymentID: deploymentID)
        return try await fetchMyFileRequestSubmissions(using: context, requestID: requestID)
    }

    private func fetchMyFileRequestSubmissions(
        using context: FileRequestSession,
        requestID: String
    ) async throws -> [EndpointFileRequestSubmission] {
        let endpoint = context.baseURL.appending(
            path: "/v2/endpoints/file-requests/\(requestID)/submissions"
        )
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.timeoutInterval = 20
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(context.session.token)", forHTTPHeaderField: "Authorization")
        let (body, response) = try await transport.bytes(for: request, maxBytes: 2 * 1024 * 1024)
        guard let http = response as? HTTPURLResponse, http.url == endpoint else {
            throw HelicoidError.serverContractUnavailable
        }
        if http.statusCode == 401 || http.statusCode == 403 {
            throw HelicoidError.authenticationFailed(detail: "The endpoint is waiting for administrator approval or its session is no longer valid.")
        }
        guard http.statusCode == 200 else {
            throw HelicoidError.serverContractUnavailable
        }
        let records = try decoder.decode([EndpointFileRequestSubmissionDTO].self, from: body)
        guard records.count <= 100 else { throw HelicoidError.serverContractUnavailable }
        var seenIDs = Set<String>()
        let submissions = try records.map { record -> EndpointFileRequestSubmission in
            guard Self.isCanonicalUUID(record.id), seenIDs.insert(record.id).inserted,
                  record.requestID == requestID, record.computerID == context.computerID,
                  record.requestRevision > 0, record.localUserDisplayName == context.displayName,
                  ["uploading", "received", "failed", "expired", "superseded"].contains(record.state),
                  record.createdAtUnix > 0, record.files.count > 0, record.files.count <= 50 else {
                throw HelicoidError.serverContractUnavailable
            }
            var seenNames = Set<String>()
            let files = try record.files.map { file -> EndpointFileRequestSubmissionFile in
                guard Self.isCanonicalUUID(file.id), Self.safeFileName(file.fileName),
                      seenNames.insert(file.fileName.lowercased()).inserted,
                      file.fileSizeBytes <= 128 * 1024 * 1024,
                      file.sha256.utf8.count == 64,
                      file.sha256.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }),
                      file.chunkSizeBytes == 256 * 1024,
                      file.chunkCount == (file.fileSizeBytes == 0 ? 0 : (file.fileSizeBytes + 262_143) / 262_144),
                      file.state == "uploading" || file.state == "received" ||
                      file.state == "deleted" else {
                    throw HelicoidError.serverContractUnavailable
                }
                return EndpointFileRequestSubmissionFile(
                    id: file.id,
                    fileName: file.fileName,
                    fileSizeBytes: file.fileSizeBytes,
                    sha256: file.sha256,
                    state: file.state
                )
            }
            return EndpointFileRequestSubmission(
                id: record.id,
                requestID: record.requestID,
                requestRevision: record.requestRevision,
                computerID: record.computerID,
                localUserDisplayName: record.localUserDisplayName,
                state: record.state,
                createdAtUnix: record.createdAtUnix,
                files: files
            )
        }
        try requireSameLocalUser(context.localUserID)
        return submissions
    }

    /// Upload files selected by the signed-in local user to one open request.
    /// Existing partial uploads with an identical manifest are resumed by
    /// re-sending their idempotent chunks. Replacing a completed submission
    /// requires its exact ID and an explicit confirmation from the UI.
    public func submitFilesToRequest(
        deploymentID: String,
        requestID: String,
        requestRevision: Int64,
        fileURLs: [URL],
        replaceSubmissionID: String? = nil,
        confirmReplacement: Bool = false
    ) async throws -> EndpointFileRequestSubmission {
        guard Self.isCanonicalUUID(requestID), requestRevision > 0,
              !fileURLs.isEmpty, fileURLs.count <= 50 else {
            throw HelicoidError.invalidInput(field: "File request", detail: "Choose a current request and between 1 and 50 files.")
        }
        if let replaceSubmissionID {
            guard Self.isCanonicalUUID(replaceSubmissionID), confirmReplacement else {
                throw HelicoidError.invalidInput(field: "Replacement", detail: "Replacing a submission requires its exact ID and explicit confirmation.")
            }
        } else if confirmReplacement {
            throw HelicoidError.invalidInput(field: "Replacement", detail: "A submission ID is required for replacement.")
        }

        let context = try await makeFileRequestSession(deploymentID: deploymentID)
        let requests = try await fetchAvailableFileRequests(using: context)
        guard let fileRequest = requests.first(where: { $0.id == requestID }),
              fileRequest.revision == requestRevision else {
            throw HelicoidError.setupBlocked(reason: "This file request changed or closed. Refresh the request list before submitting.")
        }
        var sources = try prepareUploadSources(fileURLs, for: fileRequest)
        defer { Self.closeUploadSources(sources) }

        let history = try await fetchMyFileRequestSubmissions(using: context, requestID: requestID)
        if let replaceSubmissionID {
            guard fileRequest.replacementAllowed,
                  history.contains(where: { $0.id == replaceSubmissionID && $0.state == "received" }) else {
                throw HelicoidError.permissionDenied(detail: "The selected submission cannot be replaced by this request or signed-in user.")
            }
        }

        let existingUpload = replaceSubmissionID == nil ? history.first(where: { submission in
            submission.state == "uploading" && submission.requestRevision == requestRevision &&
                Self.matchesManifest(submission.files, sources: sources)
        }) : nil
        let submission: EndpointFileRequestSubmission
        if let existingUpload {
            submission = existingUpload
        } else {
            try requireUploadUser(context.localUserID)
            let manifest = sources.map {
                FileRequestSubmissionFileManifest(
                    fileName: $0.fileName,
                    fileSizeBytes: $0.fileSizeBytes,
                    sha256: $0.sha256
                )
            }
            let payload = try encoder.encode(CreateFileRequestSubmissionBody(
                requestRevision: requestRevision,
                files: manifest,
                replaceSubmissionID: replaceSubmissionID,
                confirmReplacement: confirmReplacement
            ))
            let created: EndpointFileRequestSubmissionDTO = try await postJSON(
                payload,
                to: context.baseURL.appending(path: "/v2/endpoints/file-requests/\(requestID)/submissions"),
                bearerToken: context.session.token,
                expectedStatus: 201
            )
            submission = try validatedSubmission(created, context: context, requestID: requestID)
        }

        guard submission.state == "uploading", submission.requestRevision == requestRevision,
              submission.requestID == requestID,
              let enrolledFileIDs = Self.fileIDs(in: submission.files, matching: sources) else {
            throw HelicoidError.serverContractUnavailable
        }
        var updatedSources: [FileRequestUploadSource] = []
        for source in sources {
            guard let fileID = enrolledFileIDs[source.fileName] else {
                throw HelicoidError.serverContractUnavailable
            }
            updatedSources.append(source.withServerFileID(fileID))
        }
        sources = updatedSources

        for source in sources {
            guard let fileID = source.serverFileID else { throw HelicoidError.serverContractUnavailable }
            let chunkCount = source.fileSizeBytes == 0 ? 0 :
                (source.fileSizeBytes + 262_143) / 262_144
            guard lseek(source.descriptor, 0, SEEK_SET) == 0 else {
                throw HelicoidError.invalidInput(field: "Selected file", detail: "A selected file could not be read from the beginning.")
            }
            var uploadHasher = SHA256()
            var uploadedBytes: UInt64 = 0
            for index in 0..<chunkCount {
                try Task.checkCancellation()
                try requireUploadUser(context.localUserID)
                guard context.session.expiresAtUnix > Int64(Date().timeIntervalSince1970) else {
                    throw HelicoidError.authenticationFailed(detail: "The file request session expired. Refresh the request and resume the upload.")
                }
                let offset = UInt64(index) * 262_144
                let expectedCount = Int(min(UInt64(262_144), source.fileSizeBytes - offset))
                let chunk = try Self.readFileBytes(source.descriptor, upTo: expectedCount)
                guard chunk.count == expectedCount else {
                    throw HelicoidError.invalidInput(field: "Selected file", detail: "A selected file changed during upload preparation.")
                }
                uploadHasher.update(data: chunk)
                uploadedBytes += UInt64(chunk.count)

                let endpoint = context.baseURL.appending(
                    path: "/v2/endpoints/file-requests/\(requestID)/submissions/\(submission.id)/files/\(fileID)/chunks/\(index)"
                )
                var request = URLRequest(url: endpoint)
                request.httpMethod = "PUT"
                request.timeoutInterval = 30
                request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
                request.setValue("application/json", forHTTPHeaderField: "Accept")
                request.setValue("Bearer \(context.session.token)", forHTTPHeaderField: "Authorization")
                request.httpBody = chunk
                let (receiptBody, response) = try await transport.bytes(for: request, maxBytes: 16 * 1024)
                request.httpBody = nil
                guard let http = response as? HTTPURLResponse, http.url == endpoint else {
                    throw HelicoidError.serverContractUnavailable
                }
                if http.statusCode == 401 || http.statusCode == 403 {
                    throw HelicoidError.authenticationFailed(detail: "The endpoint session is no longer valid.")
                }
                guard http.statusCode == 200 else { throw HelicoidError.serverContractUnavailable }
                let receipt: FileRequestChunkReceipt
                do {
                    receipt = try decoder.decode(FileRequestChunkReceipt.self, from: receiptBody)
                } catch {
                    throw HelicoidError.serverContractUnavailable
                }
                guard
                      receipt.submissionID == submission.id, receipt.fileID == fileID,
                      receipt.chunkIndex == index,
                      receipt.sha256 == AuthV2Canonical.lowercaseHex(Data(SHA256.hash(data: chunk))) else {
                    throw HelicoidError.serverContractUnavailable
                }
            }
            let trailing = try Self.readFileBytes(source.descriptor, upTo: 1)
            let finalDigest = AuthV2Canonical.lowercaseHex(Data(uploadHasher.finalize()))
            guard trailing.isEmpty, uploadedBytes == source.fileSizeBytes, finalDigest == source.sha256,
                  Self.sourceFileIsUnchanged(source) else {
                throw HelicoidError.invalidInput(field: "Selected file", detail: "A selected file changed before the request could be committed.")
            }
        }

            try requireUploadUser(context.localUserID)
        guard context.session.expiresAtUnix > Int64(Date().timeIntervalSince1970) else {
            throw HelicoidError.authenticationFailed(detail: "The file request session expired before submission could be completed.")
        }
        let completion = try encoder.encode(CompleteFileRequestSubmissionBody(
            requestRevision: requestRevision,
            confirmSubmissionID: submission.id
        ))
        let completed: EndpointFileRequestSubmissionDTO = try await postJSON(
            completion,
            to: context.baseURL.appending(
                path: "/v2/endpoints/file-requests/\(requestID)/submissions/\(submission.id)/complete"
            ),
            bearerToken: context.session.token,
            expectedStatus: 200
        )
        let result = try validatedSubmission(completed, context: context, requestID: requestID)
        guard result.id == submission.id, result.state == "received",
              result.files.allSatisfy({ $0.state == "received" }) else {
            throw HelicoidError.serverContractUnavailable
        }
        try requireUploadUser(context.localUserID)
        return result
    }

    private func makeFileRequestSession(deploymentID: String) async throws -> FileRequestSession {
        let deployment = deploymentID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !deployment.isEmpty, deployment.count <= 128,
              deployment.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw HelicoidError.invalidInput(field: "Deployment ID", detail: "The configured deployment identity is invalid.")
        }
        let account = Self.keychainAccount(for: deployment)
        guard var storedBytes = try await keyStore.read(account: account) else {
            throw HelicoidError.authenticationFailed(detail: "This Mac has no saved endpoint identity for the selected deployment.")
        }
        defer { storedBytes.resetBytes(in: storedBytes.startIndex..<storedBytes.endIndex) }
        var stored: StoredEndpointIdentity
        do {
            stored = try decoder.decode(StoredEndpointIdentity.self, from: storedBytes)
        } catch {
            throw HelicoidError.authenticationFailed(detail: "The saved endpoint identity is invalid or has not completed enrollment.")
        }
        guard stored.version == 4 else {
            throw HelicoidError.authenticationFailed(
                detail: "This endpoint has no saved authority-generation checkpoint. Keep it quarantined and re-enroll it through the Manager after recovery review."
            )
        }
        guard stored.deploymentID == deployment,
              stored.privateKey.count == 32, let enrolled = stored.result,
              Self.isCanonicalUUID(enrolled.computerID), enrolled.platform == "macos",
              let serverAddress = stored.serverAddress else {
            throw HelicoidError.authenticationFailed(detail: "The saved endpoint identity is invalid or has not completed enrollment.")
        }
        defer { stored.privateKey.resetBytes(in: stored.privateKey.startIndex..<stored.privateKey.endIndex) }
        let baseURL = try Self.validateServerAddress(serverAddress)
        try await verifyAuthorityCheckpoint(
            baseURL: baseURL,
            deploymentID: deployment,
            grantVerificationPublicKeyHex: stored.grantVerificationPublicKeyHex,
            authorityGeneration: stored.authorityGeneration
        )
        guard let localUserID = try localUserIdentity() else {
            throw HelicoidError.setupBlocked(reason: "Waiting for an eligible signed-in console user.")
        }
        let displayName = NSUserName()
        guard !displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              displayName.utf8.count <= 128,
              displayName.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw HelicoidError.setupBlocked(reason: "The signed-in console user label is unavailable.")
        }
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: stored.privateKey)
        let publicKeyHex = AuthV2Canonical.lowercaseHex(privateKey.publicKey.rawRepresentation)
        let session = try await currentEndpointSession(
            baseURL: baseURL,
            deploymentID: deployment,
            enrollment: enrolled,
            localUserID: localUserID,
            publicKeyHex: publicKeyHex,
            privateKey: privateKey
        )
        try requireSameLocalUser(localUserID)
        return FileRequestSession(
            baseURL: baseURL,
            deploymentID: deployment,
            localUserID: localUserID,
            displayName: displayName,
            computerID: enrolled.computerID,
            enrollment: enrolled,
            endpointPublicKeyHex: publicKeyHex,
            grantVerificationPublicKeyHex: stored.grantVerificationPublicKeyHex,
            session: session
        )
    }

    private func refreshEndpointSessionForCurrentConsole(
        baseURL: URL,
        deploymentID: String,
        enrollment: EndpointEnrollmentResult,
        publicKeyHex: String,
        privateKey: Curve25519.Signing.PrivateKey
    ) async throws -> String? {
        let identityGeneration = endpointIdentityGenerations[deploymentID, default: 0]
        let currentLocalUserID = (try? localUserIdentity()) ?? nil
        let refreshedSession = try await authenticateEndpoint(
            baseURL: baseURL,
            deploymentID: deploymentID,
            computerID: enrollment.computerID,
            localUserID: currentLocalUserID,
            publicKeyHex: publicKeyHex,
            privateKey: privateKey
        )
        try await verifyEndpointSession(
            refreshedSession,
            baseURL: baseURL,
            deploymentID: deploymentID,
            enrollment: enrollment
        )
        try requireCurrentIdentityGeneration(identityGeneration, deploymentID: deploymentID)
        cachedEndpointSessions[deploymentID] = CachedEndpointSession(
            session: refreshedSession,
            localUserID: currentLocalUserID
        )
        return currentLocalUserID
    }

    private func currentEndpointSession(
        baseURL: URL,
        deploymentID: String,
        enrollment: EndpointEnrollmentResult,
        localUserID: String?,
        publicKeyHex: String,
        privateKey: Curve25519.Signing.PrivateKey
    ) async throws -> EndpointSession {
        let identityGeneration = endpointIdentityGenerations[deploymentID, default: 0]
        if let cached = cachedEndpointSessions[deploymentID],
           cached.localUserID == localUserID,
           cached.session.expiresAtUnix > Int64(Date().timeIntervalSince1970) + 30 {
            do {
                try await verifyEndpointSession(
                    cached.session,
                    baseURL: baseURL,
                    deploymentID: deploymentID,
                    enrollment: enrollment
                )
                try requireCurrentIdentityGeneration(identityGeneration, deploymentID: deploymentID)
                return cached.session
            } catch HelicoidError.authenticationFailed(_) {
                try requireCurrentIdentityGeneration(identityGeneration, deploymentID: deploymentID)
                cachedEndpointSessions.removeValue(forKey: deploymentID)
            }
        }

        if let flight = endpointSessionFlights[deploymentID] {
            if flight.localUserID == localUserID {
                do {
                    let session = try await flight.task.value
                    removeEndpointSessionFlight(flight, deploymentID: deploymentID)
                    try requireCurrentIdentityGeneration(identityGeneration, deploymentID: deploymentID)
                    return session
                } catch {
                    removeEndpointSessionFlight(flight, deploymentID: deploymentID)
                    throw error
                }
            }

            // A physical-console user change can overlap an earlier handshake.
            // Let it finish before issuing the replacement session, since the
            // server revokes older sessions for this endpoint on completion.
            _ = try? await flight.task.value
            removeEndpointSessionFlight(flight, deploymentID: deploymentID)
            try requireCurrentIdentityGeneration(identityGeneration, deploymentID: deploymentID)
            return try await currentEndpointSession(
                baseURL: baseURL,
                deploymentID: deploymentID,
                enrollment: enrollment,
                localUserID: localUserID,
                publicKeyHex: publicKeyHex,
                privateKey: privateKey
            )
        }

        let flight = EndpointSessionFlight(
            id: UUID(),
            localUserID: localUserID,
            task: Task { [self] in
                let session = try await authenticateEndpoint(
                    baseURL: baseURL,
                    deploymentID: deploymentID,
                    computerID: enrollment.computerID,
                    localUserID: localUserID,
                    publicKeyHex: publicKeyHex,
                    privateKey: privateKey
                )
                try await verifyEndpointSession(
                    session,
                    baseURL: baseURL,
                    deploymentID: deploymentID,
                    enrollment: enrollment
                )
                try requireCurrentIdentityGeneration(identityGeneration, deploymentID: deploymentID)
                cachedEndpointSessions[deploymentID] = CachedEndpointSession(
                    session: session,
                    localUserID: localUserID
                )
                return session
            }
        )
        endpointSessionFlights[deploymentID] = flight
        do {
            let session = try await flight.task.value
            removeEndpointSessionFlight(flight, deploymentID: deploymentID)
            try requireCurrentIdentityGeneration(identityGeneration, deploymentID: deploymentID)
            return session
        } catch {
            removeEndpointSessionFlight(flight, deploymentID: deploymentID)
            throw error
        }
    }

    private func removeEndpointSessionFlight(
        _ flight: EndpointSessionFlight,
        deploymentID: String
    ) {
        guard endpointSessionFlights[deploymentID]?.id == flight.id else { return }
        endpointSessionFlights.removeValue(forKey: deploymentID)
    }

    private func requireCurrentIdentityGeneration(_ generation: UInt64, deploymentID: String) throws {
        guard endpointIdentityGenerations[deploymentID, default: 0] == generation else {
            throw HelicoidError.authenticationFailed(detail: "The saved endpoint identity changed while this request was in progress.")
        }
    }

    private func requireFileJobsEnabled(baseURL: URL) async throws {
        let healthURL = baseURL.appending(path: "/health")
        var request = URLRequest(url: healthURL)
        request.httpMethod = "GET"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let (data, response) = try await transport.bytes(for: request, maxBytes: 16_384)
        guard let http = response as? HTTPURLResponse, http.url == healthURL, http.statusCode == 200,
              let health = try? decoder.decode(HealthDTO.self, from: data),
              health.status == "ok", health.schemaVersion == 1 else {
            throw HelicoidError.serverContractUnavailable
        }
        guard health.features["file_jobs"] == true else {
            throw HelicoidError.setupBlocked(reason: "File delivery is not enabled by this deployment.")
        }
    }

    private func authenticateEndpoint(
        baseURL: URL,
        deploymentID: String,
        computerID: String,
        localUserID: String?,
        publicKeyHex: String,
        privateKey: Curve25519.Signing.PrivateKey
    ) async throws -> EndpointSession {
        var nonceBytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, nonceBytes.count, &nonceBytes) == errSecSuccess else {
            throw HelicoidError.authenticationFailed(detail: "A fresh endpoint proof could not be created.")
        }
        defer { _ = nonceBytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        let nonce = nonceBytes.map { String(format: "%02x", $0) }.joined()
        let issuedAt = Int64(Date().timeIntervalSince1970)
        let localUserDisplayName = localUserID == nil ? nil : NSUserName()
        let beginMessage: Data
        if let localUserID, let localUserDisplayName {
            let displayNameHex = Data(localUserDisplayName.utf8).map { String(format: "%02x", $0) }.joined()
            beginMessage = Data(
                "hs-endpoint-session-begin-v3|deployment:\(deploymentID)|computer:\(computerID)|local_user:\(localUserID)|local_user_display_name:\(displayNameHex)|issued_at:\(issuedAt)|nonce:\(nonce)".utf8
            )
        } else if let localUserID {
            beginMessage = Data(
                "hs-endpoint-session-begin-v2|deployment:\(deploymentID)|computer:\(computerID)|local_user:\(localUserID)|issued_at:\(issuedAt)|nonce:\(nonce)".utf8
            )
        } else {
            beginMessage = Data(
                "hs-endpoint-session-begin-v1|deployment:\(deploymentID)|computer:\(computerID)|issued_at:\(issuedAt)|nonce:\(nonce)".utf8
            )
        }
        let beginSignature = try privateKey.signature(for: beginMessage)
        let challengeBody = try encoder.encode(EndpointSessionChallengeRequest(
            computerID: computerID,
            localUserID: localUserID,
            localUserDisplayName: localUserDisplayName,
            clientNonce: nonce,
            issuedAtUnix: issuedAt,
            proof: AuthV2Canonical.lowercaseHex(beginSignature)
        ))
        let challenge: EndpointSessionChallenge = try await postJSON(
            challengeBody,
            to: baseURL.appending(path: "/v2/endpoints/session/challenge"),
            bearerToken: nil,
            expectedStatus: 201
        )
        guard Self.isCanonicalUUID(challenge.challengeID),
              challenge.deploymentID == deploymentID,
              challenge.computerID == computerID,
              challenge.enrollmentEpoch > 0,
              challenge.expiresAtUnix > issuedAt,
              challenge.expiresAtUnix <= issuedAt + 120,
              challenge.challengeToken.utf8.count == 43,
              challenge.challengeToken.utf8.allSatisfy({
                  ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95
              }) else {
            throw HelicoidError.serverContractUnavailable
        }
        let tokenHash = AuthV2Canonical.lowercaseHex(
            Data(SHA256.hash(data: Data(challenge.challengeToken.utf8)))
        )
        let completionMessage: Data
        if let localUserID, let localUserDisplayName {
            let displayNameHex = Data(localUserDisplayName.utf8).map { String(format: "%02x", $0) }.joined()
            completionMessage = Data(
                "hs-endpoint-session-v3|deployment:\(deploymentID)|challenge:\(challenge.challengeID)|token_hash:\(tokenHash)|computer:\(computerID)|epoch:\(challenge.enrollmentEpoch)|endpoint:\(publicKeyHex)|local_user:\(localUserID)|local_user_display_name:\(displayNameHex)".utf8
            )
        } else if let localUserID {
            completionMessage = Data(
                "hs-endpoint-session-v2|deployment:\(deploymentID)|challenge:\(challenge.challengeID)|token_hash:\(tokenHash)|computer:\(computerID)|epoch:\(challenge.enrollmentEpoch)|endpoint:\(publicKeyHex)|local_user:\(localUserID)".utf8
            )
        } else {
            completionMessage = Data(
                "hs-endpoint-session-v1|deployment:\(deploymentID)|challenge:\(challenge.challengeID)|token_hash:\(tokenHash)|computer:\(computerID)|epoch:\(challenge.enrollmentEpoch)|endpoint:\(publicKeyHex)".utf8
            )
        }
        let completionSignature = try privateKey.signature(for: completionMessage)
        let completionBody = try encoder.encode(EndpointSessionCompleteRequest(
            challengeID: challenge.challengeID,
            challengeToken: challenge.challengeToken,
            signature: AuthV2Canonical.lowercaseHex(completionSignature)
        ))
        let issued: EndpointSession = try await postJSON(
            completionBody,
            to: baseURL.appending(path: "/v2/endpoints/session/complete"),
            bearerToken: nil,
            expectedStatus: 200
        )
        let now = Int64(Date().timeIntervalSince1970)
        guard issued.deploymentID == deploymentID,
              Self.isCanonicalUUID(issued.sessionID),
              issued.computerID == computerID,
              issued.enrollmentEpoch == challenge.enrollmentEpoch,
              issued.token.utf8.count >= 32, issued.token.utf8.count <= 128,
              issued.token.utf8.allSatisfy({
                  ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95
              }),
              issued.expiresAtUnix > now, issued.expiresAtUnix <= now + 15 * 60 else {
            throw HelicoidError.serverContractUnavailable
        }
        return issued
    }

    private func verifyEndpointSession(
        _ session: EndpointSession,
        baseURL: URL,
        deploymentID: String,
        enrollment: EndpointEnrollmentResult
    ) async throws {
        let endpoint = baseURL.appending(path: "/v2/endpoints/self")
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(session.token)", forHTTPHeaderField: "Authorization")
        let (body, response) = try await transport.bytes(for: request, maxBytes: 16_384)
        guard let http = response as? HTTPURLResponse, http.url == endpoint,
              http.statusCode == 200 else {
            throw HelicoidError.authenticationFailed(detail: "The endpoint session was not accepted by its deployment.")
        }
        let identity = try decoder.decode(EndpointSelfResponse.self, from: body)
        guard identity.computerID == enrollment.computerID,
              identity.platform == "macos",
              identity.enrollmentEpoch == session.enrollmentEpoch,
              !deploymentID.isEmpty else {
            throw HelicoidError.authenticationFailed(detail: "The deployment returned a different endpoint identity.")
        }
    }

    private func receive(
        _ job: EndpointFileJob,
        baseURL: URL,
        localUserID: String,
        bearerToken: String
    ) async throws -> EndpointFileReceivedFile {
        try requireSameLocalUser(localUserID)
        guard Self.isCanonicalUUID(job.id) else {
            throw HelicoidError.serverContractUnavailable
        }
        guard Self.safeFileName(job.fileName),
              job.fileSizeBytes <= 128 * 1024 * 1024,
              job.chunkSizeBytes == 256 * 1024,
              job.chunkCount == (job.fileSizeBytes == 0 ? 0 : (job.fileSizeBytes + 262_143) / 262_144),
              job.state == "in_progress",
              job.sha256.utf8.count == 64,
              job.sha256.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }) else {
            throw EndpointFileDeliveryFailure(detail: "The server returned invalid file-job metadata.")
        }

        let directory = try receivedFilesDirectory().standardizedFileURL
        let directoryDescriptor = try Self.pinReceivedFilesDirectory(at: directory)
        defer { close(directoryDescriptor) }
        let outputName = Self.outputFileName(jobID: job.id, name: job.fileName)
        let finalURL = directory.appendingPathComponent(outputName, isDirectory: false)
        if Self.isRegularFile(in: directoryDescriptor, name: outputName),
           try Self.fileDigest(in: directoryDescriptor, name: outputName) == job.sha256,
           (try Self.fileSize(in: directoryDescriptor, name: outputName)) == job.fileSizeBytes {
            try Self.requireDirectoryStillPinned(directory, descriptor: directoryDescriptor)
            try requireSameLocalUser(localUserID)
            try await reportSuccess(job, baseURL: baseURL, bearerToken: bearerToken)
            return EndpointFileReceivedFile(jobID: job.id, fileName: job.fileName, path: finalURL.path)
        }
        if Self.itemExists(in: directoryDescriptor, name: outputName) {
            throw EndpointFileDeliveryFailure(detail: "A different local file already occupies this job's destination.")
        }

        let temporaryName = ".\(job.id).part"
        var temporaryCreated = false
        defer {
            if temporaryCreated {
                _ = temporaryName.withCString { unlinkat(directoryDescriptor, $0, 0) }
            }
        }
        let descriptor = temporaryName.withCString {
            openat(directoryDescriptor, $0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                   mode_t(S_IRUSR | S_IWUSR))
        }
        guard descriptor >= 0 else {
            throw EndpointFileDeliveryFailure(detail: "The private received-files directory is not writable.")
        }
        temporaryCreated = true
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var hasher = SHA256()
        var receivedSize: UInt64 = 0
        do {
            for index in 0..<job.chunkCount {
                try Task.checkCancellation()
                try requireSameLocalUser(localUserID)
                let path = "/v2/endpoints/jobs/\(job.id)/chunks/\(index)"
                let url = baseURL.appending(path: path)
                var request = URLRequest(url: url)
                request.httpMethod = "GET"
                request.timeoutInterval = 20
                request.setValue("application/octet-stream", forHTTPHeaderField: "Accept")
                request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
                let (chunk, response) = try await transport.bytes(for: request, maxBytes: Int(job.chunkSizeBytes))
                guard let http = response as? HTTPURLResponse, http.url == url else {
                    throw HelicoidError.serverContractUnavailable
                }
                if http.statusCode == 401 || http.statusCode == 403 {
                    throw HelicoidError.authenticationFailed(detail: "The endpoint session is no longer valid.")
                }
                guard http.statusCode == 200,
                      http.value(forHTTPHeaderField: "x-helicoid-chunk-sha256") == AuthV2Canonical.lowercaseHex(Data(SHA256.hash(data: chunk))) else {
                    throw HelicoidError.serverContractUnavailable
                }
                let offset = UInt64(index) * UInt64(job.chunkSizeBytes)
                let expectedLength = min(UInt64(job.chunkSizeBytes), job.fileSizeBytes - offset)
                guard UInt64(chunk.count) == expectedLength else {
                    throw HelicoidError.serverContractUnavailable
                }
                try handle.write(contentsOf: chunk)
                hasher.update(data: chunk)
                receivedSize += UInt64(chunk.count)
            }
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }
        let digest = AuthV2Canonical.lowercaseHex(Data(hasher.finalize()))
        guard receivedSize == job.fileSizeBytes, digest == job.sha256 else {
            throw EndpointFileDeliveryFailure(detail: "The received file failed its full-file integrity check.")
        }

        try Self.requireDirectoryStillPinned(directory, descriptor: directoryDescriptor)
        try requireSameLocalUser(localUserID)
        let renameResult = temporaryName.withCString { source in
            outputName.withCString { destination in
                renameatx_np(directoryDescriptor, source, directoryDescriptor, destination, UInt32(RENAME_EXCL))
            }
        }
        guard renameResult == 0 else {
            if Self.isRegularFile(in: directoryDescriptor, name: outputName),
               try Self.fileDigest(in: directoryDescriptor, name: outputName) == job.sha256,
               (try Self.fileSize(in: directoryDescriptor, name: outputName)) == job.fileSizeBytes {
                try Self.requireDirectoryStillPinned(directory, descriptor: directoryDescriptor)
                try requireSameLocalUser(localUserID)
                _ = temporaryName.withCString { unlinkat(directoryDescriptor, $0, 0) }
                temporaryCreated = false
                try await reportSuccess(job, baseURL: baseURL, bearerToken: bearerToken)
                return EndpointFileReceivedFile(jobID: job.id, fileName: job.fileName, path: finalURL.path)
            }
            throw EndpointFileDeliveryFailure(detail: "The verified file could not be published without replacing another file.")
        }
        temporaryCreated = false
        try Self.requireDirectoryStillPinned(directory, descriptor: directoryDescriptor)
        try requireSameLocalUser(localUserID)
        try await reportSuccess(job, baseURL: baseURL, bearerToken: bearerToken)
        return EndpointFileReceivedFile(jobID: job.id, fileName: job.fileName, path: finalURL.path)
    }

    private func reportSuccess(_ job: EndpointFileJob, baseURL: URL, bearerToken: String) async throws {
        let body = try encoder.encode(EndpointFileJobResult(
            succeeded: true,
            receivedSizeBytes: job.fileSizeBytes,
            receivedSHA256: job.sha256
        ))
        _ = try await postJSON(
            body,
            to: baseURL.appending(path: "/v2/endpoints/jobs/\(job.id)/result"),
            bearerToken: bearerToken,
            expectedStatus: 200
        ) as EndpointFileJobResultResponse
    }

    private func reportFailure(jobID: String, detail: String, baseURL: URL, bearerToken: String) async throws {
        let safeDetail = String(detail.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.prefix(512))
        let body = try encoder.encode(EndpointFileJobResult(succeeded: false, detail: safeDetail))
        _ = try await postJSON(
            body,
            to: baseURL.appending(path: "/v2/endpoints/jobs/\(jobID)/result"),
            bearerToken: bearerToken,
            expectedStatus: 200
        ) as EndpointFileJobResultResponse
    }

    private func validatedSubmission(
        _ record: EndpointFileRequestSubmissionDTO,
        context: FileRequestSession,
        requestID: String
    ) throws -> EndpointFileRequestSubmission {
        guard Self.isCanonicalUUID(record.id), record.requestID == requestID,
              record.computerID == context.computerID, record.requestRevision > 0,
              record.localUserDisplayName == context.displayName,
              ["uploading", "received", "failed", "expired", "superseded"].contains(record.state),
              record.createdAtUnix > 0, !record.files.isEmpty, record.files.count <= 50 else {
            throw HelicoidError.serverContractUnavailable
        }
        var seenIDs = Set<String>()
        var seenNames = Set<String>()
        let files = try record.files.map { file -> EndpointFileRequestSubmissionFile in
            guard Self.isCanonicalUUID(file.id), seenIDs.insert(file.id).inserted,
                  Self.safeFileName(file.fileName), seenNames.insert(file.fileName.lowercased()).inserted,
                  file.fileSizeBytes <= 128 * 1024 * 1024,
                  file.sha256.utf8.count == 64,
                  file.sha256.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }),
                  file.chunkSizeBytes == 256 * 1024,
                  file.chunkCount == (file.fileSizeBytes == 0 ? 0 : (file.fileSizeBytes + 262_143) / 262_144),
                  file.state == "uploading" || file.state == "received" ||
                  file.state == "deleted" else {
                throw HelicoidError.serverContractUnavailable
            }
            return EndpointFileRequestSubmissionFile(
                id: file.id,
                fileName: file.fileName,
                fileSizeBytes: file.fileSizeBytes,
                sha256: file.sha256,
                state: file.state
            )
        }
        return EndpointFileRequestSubmission(
            id: record.id,
            requestID: record.requestID,
            requestRevision: record.requestRevision,
            computerID: record.computerID,
            localUserDisplayName: record.localUserDisplayName,
            state: record.state,
            createdAtUnix: record.createdAtUnix,
            files: files
        )
    }

    private func prepareUploadSources(
        _ urls: [URL],
        for request: EndpointFileRequest
    ) throws -> [FileRequestUploadSource] {
        guard urls.count <= Int(request.maxFileCount) else {
            throw HelicoidError.invalidInput(field: "Selected files", detail: "The request allows fewer files than you selected.")
        }
        var sources: [FileRequestUploadSource] = []
        var keepOpen = false
        defer {
            if !keepOpen { Self.closeUploadSources(sources) }
        }
        var seenNames = Set<String>()
        var totalSize: UInt64 = 0
        for url in urls {
            let source = try Self.openAndHashUploadSource(url)
            sources.append(source)
            let normalizedName = source.fileName.lowercased()
            guard seenNames.insert(normalizedName).inserted else {
                throw HelicoidError.invalidInput(field: "Selected files", detail: "File names must be unique without case sensitivity.")
            }
            let extensionName = URL(fileURLWithPath: source.fileName).pathExtension.lowercased()
            guard request.allowedExtensions.contains("*") ||
                    (!extensionName.isEmpty && request.allowedExtensions.contains(extensionName)) else {
                throw HelicoidError.invalidInput(field: "Selected files", detail: "A selected file does not match the request's allowed types.")
            }
            let (nextTotal, overflow) = totalSize.addingReportingOverflow(source.fileSizeBytes)
            guard !overflow, nextTotal <= request.maxTotalSizeBytes,
                  nextTotal <= 128 * 1024 * 1024 else {
                throw HelicoidError.invalidInput(field: "Selected files", detail: "The selected files exceed the request's total size limit.")
            }
            totalSize = nextTotal
        }
        keepOpen = true
        return sources
    }

    private static func openAndHashUploadSource(_ url: URL) throws -> FileRequestUploadSource {
        guard url.isFileURL else {
            throw HelicoidError.invalidInput(field: "Selected file", detail: "Choose a local file.")
        }
        let scoped = url.startAccessingSecurityScopedResource()
        var descriptor: Int32 = -1
        do {
            var pathInfo = stat()
            let pathStatus = url.path.withCString { Darwin.lstat($0, &pathInfo) }
            guard pathStatus == 0, (pathInfo.st_mode & S_IFMT) == S_IFREG else {
                throw HelicoidError.invalidInput(field: "Selected file", detail: "Choose a regular file, not a folder or symbolic link.")
            }
            descriptor = url.path.withCString {
                Darwin.open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            }
            guard descriptor >= 0 else {
                throw HelicoidError.invalidInput(field: "Selected file", detail: "The selected file could not be opened safely.")
            }
            var openInfo = stat()
            guard fstat(descriptor, &openInfo) == 0,
                  (openInfo.st_mode & S_IFMT) == S_IFREG,
                  openInfo.st_dev == pathInfo.st_dev, openInfo.st_ino == pathInfo.st_ino,
                  openInfo.st_size >= 0, openInfo.st_size <= 128 * 1024 * 1024 else {
                throw HelicoidError.invalidInput(field: "Selected file", detail: "The selected file changed or exceeds the 128 MiB limit.")
            }
            let fileName = url.lastPathComponent
            guard safeFileName(fileName) else {
                throw HelicoidError.invalidInput(field: "Selected file", detail: "The selected file name is not safe for this request.")
            }
            let expectedSize = UInt64(openInfo.st_size)
            var hasher = SHA256()
            var offset: UInt64 = 0
            while offset < expectedSize {
                let count = Int(min(UInt64(256 * 1024), expectedSize - offset))
                let chunk = try readFileBytes(descriptor, upTo: count)
                guard chunk.count == count else {
                    throw HelicoidError.invalidInput(field: "Selected file", detail: "The selected file changed while it was being prepared.")
                }
                hasher.update(data: chunk)
                offset += UInt64(chunk.count)
            }
            guard try readFileBytes(descriptor, upTo: 1).isEmpty,
                  lseek(descriptor, 0, SEEK_SET) == 0,
                  sourceIdentityMatches(descriptor: descriptor, url: url,
                                        device: openInfo.st_dev, inode: openInfo.st_ino,
                                        size: openInfo.st_size) else {
                throw HelicoidError.invalidInput(field: "Selected file", detail: "The selected file changed while it was being prepared.")
            }
            return FileRequestUploadSource(
                url: url,
                descriptor: descriptor,
                securityScopeStarted: scoped,
                fileName: fileName,
                fileSizeBytes: expectedSize,
                sha256: AuthV2Canonical.lowercaseHex(Data(hasher.finalize())),
                device: openInfo.st_dev,
                inode: openInfo.st_ino,
                serverFileID: nil
            )
        } catch {
            if descriptor >= 0 { _ = Darwin.close(descriptor) }
            if scoped { url.stopAccessingSecurityScopedResource() }
            throw error
        }
    }

    private static func sourceIdentityMatches(
        descriptor: Int32,
        url: URL,
        device: dev_t,
        inode: ino_t,
        size: off_t
    ) -> Bool {
        var openInfo = stat()
        var pathInfo = stat()
        let pathStatus = url.path.withCString { Darwin.lstat($0, &pathInfo) }
        return fstat(descriptor, &openInfo) == 0 && pathStatus == 0 &&
            (openInfo.st_mode & S_IFMT) == S_IFREG && (pathInfo.st_mode & S_IFMT) == S_IFREG &&
            openInfo.st_dev == device && openInfo.st_ino == inode &&
            pathInfo.st_dev == device && pathInfo.st_ino == inode && openInfo.st_size == size
    }

    private static func sourceFileIsUnchanged(_ source: FileRequestUploadSource) -> Bool {
        sourceIdentityMatches(descriptor: source.descriptor, url: source.url,
                              device: source.device, inode: source.inode,
                              size: off_t(source.fileSizeBytes))
    }

    private static func readFileBytes(_ descriptor: Int32, upTo count: Int) throws -> Data {
        guard count >= 0 else {
            throw HelicoidError.invalidInput(field: "Selected file", detail: "The requested read size is invalid.")
        }
        var data = Data()
        data.reserveCapacity(count)
        while data.count < count {
            var buffer = [UInt8](repeating: 0, count: count - data.count)
            let bytesRead = buffer.withUnsafeMutableBytes { bytes -> Int in
                guard let baseAddress = bytes.baseAddress else { return 0 }
                return Darwin.read(descriptor, baseAddress, bytes.count)
            }
            if bytesRead < 0 {
                if errno == EINTR { continue }
                throw HelicoidError.invalidInput(field: "Selected file", detail: "The selected file could not be read.")
            }
            if bytesRead == 0 { break }
            data.append(contentsOf: buffer.prefix(bytesRead))
        }
        return data
    }

    private static func closeUploadSources(_ sources: [FileRequestUploadSource]) {
        for source in sources {
            _ = Darwin.close(source.descriptor)
            if source.securityScopeStarted { source.url.stopAccessingSecurityScopedResource() }
        }
    }

    private static func matchesManifest(
        _ files: [EndpointFileRequestSubmissionFile],
        sources: [FileRequestUploadSource]
    ) -> Bool {
        guard files.count == sources.count else { return false }
        return sources.allSatisfy { source in
            files.contains {
                $0.fileName == source.fileName && $0.fileSizeBytes == source.fileSizeBytes &&
                    $0.sha256 == source.sha256 && $0.state == "uploading"
            }
        }
    }

    private static func fileIDs(
        in files: [EndpointFileRequestSubmissionFile],
        matching sources: [FileRequestUploadSource]
    ) -> [String: String]? {
        guard files.count == sources.count else { return nil }
        var ids: [String: String] = [:]
        for source in sources {
            guard let file = files.first(where: {
                $0.fileName == source.fileName && $0.fileSizeBytes == source.fileSizeBytes &&
                    $0.sha256 == source.sha256 && $0.state == "uploading"
            }), ids[source.fileName] == nil else { return nil }
            ids[source.fileName] = file.id
        }
        return ids
    }

    private func requireUploadUser(_ userID: String) throws {
        do {
            try requireSameLocalUser(userID)
        } catch {
            throw HelicoidError.setupBlocked(reason: "File submission paused after the signed-in user changed. Sign in as the same user to resume it.")
        }
    }

    private static func lowercaseHexData(_ value: String, byteCount: Int) -> Data? {
        let bytes = Array(value.utf8)
        guard bytes.count == byteCount * 2,
              bytes.allSatisfy({
                  ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66)
              }) else { return nil }
        var result = Data()
        result.reserveCapacity(byteCount)
        for index in stride(from: 0, to: bytes.count, by: 2) {
            let high: UInt8 = bytes[index] <= 0x39 ? bytes[index] - 0x30 : bytes[index] - 0x61 + 10
            let low: UInt8 = bytes[index + 1] <= 0x39 ? bytes[index + 1] - 0x30 : bytes[index + 1] - 0x61 + 10
            result.append((high << 4) | low)
        }
        return result
    }

    private static func validObservationSignal(kind: ObservationSignalKind, payload: String) -> Bool {
        let bytes = Array(payload.utf8)
        let maxBytes: Int
        switch kind {
        case .offer, .answer:
            maxBytes = 65_536
            guard payload.hasPrefix("v=0"), !bytes.isEmpty else { return false }
        case .ice:
            maxBytes = 4_096
        case .close:
            maxBytes = 0
        }
        return bytes.count <= maxBytes && bytes.allSatisfy {
            $0 != 0 && (!($0 < 0x20 || $0 == 0x7f) || $0 == 9 || $0 == 10 || $0 == 13)
        }
    }

    private static func currentChannelBindingMatches(
        _ provider: @Sendable () throws -> Data,
        expectedHex: String
    ) -> Bool {
        do {
            return ObservationAdmissionGrantVerifier.canonicalChannelBindingHex(try provider()) == expectedHex
        } catch {
            return false
        }
    }

    private func postJSON<Response: Decodable>(
        _ body: Data,
        to url: URL,
        bearerToken: String?,
        expectedStatus: Int
    ) async throws -> Response {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let bearerToken {
            request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        }
        request.httpBody = body
        defer { request.httpBody = nil }
        let (responseBody, response) = try await transport.bytes(for: request, maxBytes: 32 * 1024)
        guard let http = response as? HTTPURLResponse, http.url == url else {
            throw HelicoidError.serverContractUnavailable
        }
        guard http.statusCode == expectedStatus else {
            if http.statusCode == 401 || http.statusCode == 403 {
                throw HelicoidError.authenticationFailed(detail: "The endpoint is waiting for administrator approval or its session is no longer valid.")
            }
            throw HelicoidError.serverContractUnavailable
        }
        do {
            return try decoder.decode(Response.self, from: responseBody)
        } catch {
            throw HelicoidError.serverContractUnavailable
        }
    }

    private static func safeFileName(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 255, value == value.trimmingCharacters(in: .whitespacesAndNewlines),
              value != ".", value != "..", !value.hasSuffix("."), !value.hasSuffix(" "),
              !value.contains("/"), !value.contains("\\"), !value.contains(":"),
              value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return false
        }
        let firstComponent = String(value.split(separator: ".", omittingEmptySubsequences: false).first ?? "")
        let deviceStem = firstComponent.trimmingCharacters(in: CharacterSet(charactersIn: " .")).uppercased()
        let reserved = ["CON", "PRN", "AUX", "NUL"].contains(deviceStem) ||
            (deviceStem.count == 4 &&
             (deviceStem.hasPrefix("COM") || deviceStem.hasPrefix("LPT")) &&
             deviceStem.last.map { ("1"..."9").contains($0) } == true)
        return !reserved
    }

    private static func validRequestExtension(_ value: String) -> Bool {
        if value == "*" { return true }
        let bytes = Array(value.utf8)
        return !bytes.isEmpty && bytes.count <= 32 && value == value.lowercased() &&
            !value.hasPrefix(".") && !value.hasSuffix(".") && !value.contains("..") &&
            bytes.allSatisfy {
                ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) ||
                    ($0 >= 97 && $0 <= 122) || [UInt8(46), 43, 95, 45].contains($0)
            }
    }

    public static func receivedFilesDirectoryURL() throws -> URL {
        guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw HelicoidError.invalidInput(field: "received files", detail: "The per-user application support directory is unavailable.")
        }
        let parent = support.appendingPathComponent("Helicoid/Computer", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let directory = parent.appendingPathComponent("Received Files", isDirectory: true)
        if mkdir(directory.path, mode_t(S_IRWXU)) != 0 && errno != EEXIST {
            throw HelicoidError.invalidInput(field: "received files", detail: "The private received-files directory could not be created.")
        }
        let descriptor = try Self.openDirectoryChain(at: directory.standardizedFileURL.path, allowWritableLeaf: true)
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_uid == geteuid(),
              fchmod(descriptor, mode_t(S_IRWXU)) == 0,
              fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              (info.st_mode & 0o077) == 0 else {
            throw HelicoidError.invalidInput(field: "received files", detail: "The received-files directory is not private to this user.")
        }
        return directory
    }

    private static func verifiedConsoleUserIdentity() -> String? {
        let processUID = getuid()
        guard processUID > 0, geteuid() == processUID else {
            return nil
        }
        var consoleUID: uid_t = 0
        var consoleGID: gid_t = 0
        guard let consoleUser = SCDynamicStoreCopyConsoleUser(nil, &consoleUID, &consoleGID),
              !String(consoleUser).isEmpty,
              consoleUID == processUID else {
            return nil
        }
        return "macos:uid:\(consoleUID)"
    }

    private func requireSameLocalUser(_ expectedLocalUserID: String) throws {
        let current: String?
        do {
            current = try localUserIdentity()
        } catch {
            throw EndpointFileDeliveryPaused()
        }
        guard current == expectedLocalUserID else { throw EndpointFileDeliveryPaused() }
    }

    private static func outputFileName(jobID: String, name: String) -> String {
        let prefix = String(jobID.prefix(16)) + "_"
        var result = prefix
        let budget = 255 - prefix.utf8.count
        var used = 0
        for scalar in name.unicodeScalars {
            let bytes = String(scalar).utf8.count
            if used + bytes > budget { break }
            result.unicodeScalars.append(scalar)
            used += bytes
        }
        return result
    }

    private static func openDirectoryChain(at path: String, allowWritableLeaf: Bool = false) throws -> Int32 {
        guard path.hasPrefix("/"), !path.utf8.contains(0) else {
            throw HelicoidError.invalidInput(field: "received files", detail: "The received-files path is invalid.")
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: true)
        var descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw HelicoidError.invalidInput(field: "received files", detail: "The received-files path could not be opened safely.")
        }
        for (index, component) in components.enumerated() {
            let next = component.withCString {
                openat(descriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            close(descriptor)
            guard next >= 0 else {
                throw HelicoidError.invalidInput(field: "received files", detail: "The received-files path contains an unsafe directory.")
            }
            descriptor = next
            var info = stat()
            let isLeaf = index == components.count - 1
            guard fstat(descriptor, &info) == 0,
                  (info.st_mode & S_IFMT) == S_IFDIR,
                  info.st_uid == 0 || info.st_uid == geteuid() else {
                close(descriptor)
                throw HelicoidError.invalidInput(field: "received files", detail: "The received-files path is writable by another user or has an unsafe owner.")
            }
            let hasUnsafeWritePermissions = (info.st_mode & (S_IWGRP | S_IWOTH)) != 0
            guard (allowWritableLeaf && isLeaf) || !hasUnsafeWritePermissions else {
                close(descriptor)
                throw HelicoidError.invalidInput(field: "received files", detail: "The received-files path is writable by another user or has an unsafe owner.")
            }
        }
        return descriptor
    }

    private static func pinReceivedFilesDirectory(at directory: URL) throws -> Int32 {
        let descriptor = try openDirectoryChain(at: directory.standardizedFileURL.path)
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(),
              (info.st_mode & 0o077) == 0 else {
            close(descriptor)
            throw HelicoidError.invalidInput(field: "received files", detail: "The received-files directory is not private to this user.")
        }
        return descriptor
    }

    private static func requireDirectoryStillPinned(_ directory: URL, descriptor: Int32) throws {
        let current: Int32
        do {
            current = try pinReceivedFilesDirectory(at: directory)
        } catch {
            throw EndpointFileDeliveryPaused()
        }
        defer { close(current) }
        var originalInfo = stat()
        var currentInfo = stat()
        guard fstat(descriptor, &originalInfo) == 0,
              fstat(current, &currentInfo) == 0,
              originalInfo.st_dev == currentInfo.st_dev,
              originalInfo.st_ino == currentInfo.st_ino else {
            throw EndpointFileDeliveryPaused()
        }
    }

    private static func itemExists(in directory: Int32, name: String) -> Bool {
        var info = stat()
        return name.withCString { fstatat(directory, $0, &info, AT_SYMLINK_NOFOLLOW) == 0 }
    }

    private static func isRegularFile(in directory: Int32, name: String) -> Bool {
        var info = stat()
        return name.withCString { fileName in
            fstatat(directory, fileName, &info, AT_SYMLINK_NOFOLLOW) == 0 &&
                (info.st_mode & S_IFMT) == S_IFREG && info.st_uid == geteuid()
        }
    }

    private static func fileSize(in directory: Int32, name: String) throws -> UInt64 {
        var info = stat()
        guard name.withCString({ fstatat(directory, $0, &info, AT_SYMLINK_NOFOLLOW) }) == 0,
              (info.st_mode & S_IFMT) == S_IFREG, info.st_uid == geteuid(), info.st_size >= 0 else {
            throw HelicoidError.invalidInput(field: "received file", detail: "The existing received file could not be verified.")
        }
        return UInt64(info.st_size)
    }

    private static func fileDigest(in directory: Int32, name: String) throws -> String {
        let descriptor = name.withCString {
            openat(directory, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard descriptor >= 0 else {
            throw HelicoidError.invalidInput(field: "received file", detail: "The existing received file is not a regular per-user file.")
        }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == geteuid() else {
            close(descriptor)
            throw HelicoidError.invalidInput(field: "received file", detail: "The existing received file is not a regular per-user file.")
        }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? file.close() }
        var hasher = SHA256()
        while true {
            let bytes = try file.read(upToCount: 256 * 1024) ?? Data()
            if bytes.isEmpty { break }
            hasher.update(data: bytes)
        }
        return AuthV2Canonical.lowercaseHex(Data(hasher.finalize()))
    }

    private func loadOrCreateIdentity(account: String, deploymentID: String) async throws -> StoredEndpointIdentity {
        if var data = try await keyStore.read(account: account) {
            defer { data.resetBytes(in: data.startIndex..<data.endIndex) }
            guard let value = try? decoder.decode(StoredEndpointIdentity.self, from: data),
                  (value.version == 1 || value.version == 2 || value.version == 3 || value.version == 4),
                  value.deploymentID == deploymentID, value.privateKey.count == 32 else {
                throw HelicoidError.authenticationFailed(detail: "The protected endpoint identity could not be read. It was not replaced.")
            }
            return value
        }

        let generated = Curve25519.Signing.PrivateKey()
        let candidate = StoredEndpointIdentity(version: 2, deploymentID: deploymentID,
                                                privateKey: generated.rawRepresentation, result: nil,
                                                serverAddress: nil)
        var bytes = try encoder.encode(candidate)
        defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
        if try await keyStore.insertIfAbsent(bytes, account: account) { return candidate }
        guard var winner = try await keyStore.read(account: account) else {
            throw HelicoidError.authenticationFailed(detail: "The protected endpoint identity could not be saved. Enrollment stopped.")
        }
        defer { winner.resetBytes(in: winner.startIndex..<winner.endIndex) }
        guard let value = try? decoder.decode(StoredEndpointIdentity.self, from: winner),
              (value.version == 1 || value.version == 2 || value.version == 3 || value.version == 4),
              value.deploymentID == deploymentID, value.privateKey.count == 32 else {
            throw HelicoidError.authenticationFailed(detail: "The protected endpoint identity could not be saved. Enrollment stopped.")
        }
        return value
    }

    private static func validateServerAddress(_ raw: String) throws -> URL {
        guard raw == raw.trimmingCharacters(in: .whitespacesAndNewlines),
              let components = URLComponents(string: raw),
              components.scheme?.lowercased() == "https",
              let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.path.isEmpty || components.path == "/",
              let url = components.url else {
            throw HelicoidError.invalidInput(field: "Server address", detail: "Enter an HTTPS origin such as https://helicoid.school.example:8920. Install the deployment CA in macOS trust settings first if it uses a private CA.")
        }
        return url
    }

    private static func isCanonicalUUID(_ value: String) -> Bool {
        guard let uuid = UUID(uuidString: value) else { return false }
        return uuid.uuidString.lowercased() == value
    }

    private static func isCanonicalLowerHex(_ value: String, byteCount: Int) -> Bool {
        value.utf8.count == byteCount * 2 && value.utf8.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66)
        }
    }

    private static func keychainAccount(for deploymentID: String) -> String {
        let digest = SHA256.hash(data: Data(deploymentID.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func makeTransport() -> any HTTPTransport {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        configuration.httpMaximumConnectionsPerHost = 1
        let session = URLSession(configuration: configuration,
                                 delegate: EndpointEnrollmentRedirectRefuser(),
                                 delegateQueue: nil)
        return URLSessionTransport(session: session)
    }
}

private struct EndpointEnrollmentRequest: Encodable {
    let invitationID: String
    let enrollmentCode: String
    let publicKey: String
    let proof: String

    enum CodingKeys: String, CodingKey {
        case invitationID = "invitation_id"
        case enrollmentCode = "enrollment_code"
        case publicKey = "public_key"
        case proof
    }
}

private struct EndpointSessionChallengeRequest: Encodable {
    let computerID: String
    let localUserID: String?
    let localUserDisplayName: String?
    let clientNonce: String
    let issuedAtUnix: Int64
    let proof: String

    enum CodingKeys: String, CodingKey {
        case computerID = "computer_id"
        case localUserID = "local_user_id"
        case localUserDisplayName = "local_user_display_name"
        case clientNonce = "client_nonce"
        case issuedAtUnix = "issued_at_unix"
        case proof
    }
}

private struct EndpointSessionChallenge: Decodable {
    let challengeID: String
    let challengeToken: String
    let deploymentID: String
    let computerID: String
    let enrollmentEpoch: Int64
    let expiresAtUnix: Int64

    enum CodingKeys: String, CodingKey {
        case challengeID = "challenge_id"
        case challengeToken = "challenge_token"
        case deploymentID = "deployment_id"
        case computerID = "computer_id"
        case enrollmentEpoch = "enrollment_epoch"
        case expiresAtUnix = "expires_at_unix"
    }
}

private struct EndpointSessionCompleteRequest: Encodable {
    let challengeID: String
    let challengeToken: String
    let signature: String

    enum CodingKeys: String, CodingKey {
        case challengeID = "challenge_id"
        case challengeToken = "challenge_token"
        case signature
    }
}

private struct EndpointSession: Decodable, Sendable {
    let token: String
    let sessionID: String
    let deploymentID: String
    let computerID: String
    let enrollmentEpoch: Int64
    let expiresAtUnix: Int64

    enum CodingKeys: String, CodingKey {
        case token
        case sessionID = "session_id"
        case deploymentID = "deployment_id"
        case computerID = "computer_id"
        case enrollmentEpoch = "enrollment_epoch"
        case expiresAtUnix = "expires_at_unix"
    }
}

private struct RedeemObservationGrantRequest: Encodable {
    let grantToken: String
    let endpointNonce: String
    let channelBinding: String
    let managerProof: String

    enum CodingKeys: String, CodingKey {
        case grantToken = "grant_token"
        case endpointNonce = "endpoint_nonce"
        case channelBinding = "channel_binding"
        case managerProof = "manager_proof"
    }
}

private struct ObservationSignalRequest: Encodable {
    let kind: ObservationSignalKind
    let payload: String
}

private struct ObservationAdmissionAccepted: Decodable {
    let grantID: String
    let computerID: String
    let endpointSessionID: String
    let expiresAtUnix: Int64

    enum CodingKeys: String, CodingKey {
        case grantID = "grant_id"
        case computerID = "computer_id"
        case endpointSessionID = "endpoint_session_id"
        case expiresAtUnix = "expires_at_unix"
    }
}

private struct EndpointSelfResponse: Decodable {
    let computerID: String
    let friendlyName: String
    let platform: String
    let enrollmentEpoch: Int64

    enum CodingKeys: String, CodingKey {
        case computerID = "computer_id"
        case friendlyName = "friendly_name"
        case platform
        case enrollmentEpoch = "enrollment_epoch"
    }
}

private struct EndpointFileJobList: Decodable {
    let jobs: [EndpointFileJob]
}

private struct EndpointFileRequestList: Decodable {
    let requests: [EndpointFileRequestDTO]
    let maxPageSize: Int

    enum CodingKeys: String, CodingKey {
        case requests
        case maxPageSize = "max_page_size"
    }
}

private struct EndpointFileRequestDTO: Decodable {
    let id: String
    let revision: Int64
    let title: String
    let instructions: String
    let allowedExtensions: [String]
    let maxFileCount: UInt32
    let maxTotalSizeBytes: UInt64
    let closesAtUnix: Int64
    let replacementAllowed: Bool

    enum CodingKeys: String, CodingKey {
        case id
        case revision
        case title
        case instructions
        case allowedExtensions = "allowed_extensions"
        case maxFileCount = "max_file_count"
        case maxTotalSizeBytes = "max_total_size_bytes"
        case closesAtUnix = "closes_at_unix"
        case replacementAllowed = "replacement_allowed"
    }
}

private struct EndpointFileRequestSubmissionDTO: Decodable {
    let id: String
    let requestID: String
    let requestRevision: Int64
    let computerID: String
    let localUserDisplayName: String
    let state: String
    let createdAtUnix: Int64
    let files: [EndpointFileRequestSubmissionFileDTO]

    enum CodingKeys: String, CodingKey {
        case id
        case requestID = "request_id"
        case requestRevision = "request_revision"
        case computerID = "computer_id"
        case localUserDisplayName = "local_user_display_name"
        case state
        case createdAtUnix = "created_at_unix"
        case files
    }
}

private struct EndpointFileRequestSubmissionFileDTO: Decodable {
    let id: String
    let fileName: String
    let fileSizeBytes: UInt64
    let sha256: String
    let chunkSizeBytes: UInt32
    let chunkCount: UInt32
    let state: String

    enum CodingKeys: String, CodingKey {
        case id
        case fileName = "file_name"
        case fileSizeBytes = "file_size_bytes"
        case sha256
        case chunkSizeBytes = "chunk_size_bytes"
        case chunkCount = "chunk_count"
        case state
    }
}

private struct FileRequestSubmissionFileManifest: Encodable {
    let fileName: String
    let fileSizeBytes: UInt64
    let sha256: String

    enum CodingKeys: String, CodingKey {
        case fileName = "file_name"
        case fileSizeBytes = "file_size_bytes"
        case sha256
    }
}

private struct CreateFileRequestSubmissionBody: Encodable {
    let requestRevision: Int64
    let files: [FileRequestSubmissionFileManifest]
    let replaceSubmissionID: String?
    let confirmReplacement: Bool

    enum CodingKeys: String, CodingKey {
        case requestRevision = "request_revision"
        case files
        case replaceSubmissionID = "replace_submission_id"
        case confirmReplacement = "confirm_replacement"
    }
}

private struct CompleteFileRequestSubmissionBody: Encodable {
    let requestRevision: Int64
    let confirmSubmissionID: String

    enum CodingKeys: String, CodingKey {
        case requestRevision = "request_revision"
        case confirmSubmissionID = "confirm_submission_id"
    }
}

private struct FileRequestChunkReceipt: Decodable {
    let submissionID: String
    let fileID: String
    let chunkIndex: UInt32
    let sha256: String
    let alreadyPresent: Bool

    enum CodingKeys: String, CodingKey {
        case submissionID = "submission_id"
        case fileID = "file_id"
        case chunkIndex = "chunk_index"
        case sha256
        case alreadyPresent = "already_present"
    }
}

private struct FileRequestUploadSource {
    let url: URL
    let descriptor: Int32
    let securityScopeStarted: Bool
    let fileName: String
    let fileSizeBytes: UInt64
    let sha256: String
    let device: dev_t
    let inode: ino_t
    let serverFileID: String?

    func withServerFileID(_ value: String) -> FileRequestUploadSource {
        FileRequestUploadSource(
            url: url,
            descriptor: descriptor,
            securityScopeStarted: securityScopeStarted,
            fileName: fileName,
            fileSizeBytes: fileSizeBytes,
            sha256: sha256,
            device: device,
            inode: inode,
            serverFileID: value
        )
    }
}

private struct FileRequestSession {
    let baseURL: URL
    let deploymentID: String
    let localUserID: String
    let displayName: String
    let computerID: String
    let enrollment: EndpointEnrollmentResult
    let endpointPublicKeyHex: String
    let grantVerificationPublicKeyHex: String?
    let session: EndpointSession
}

private struct PendingObservationAdmission {
    let grantToken: String
    let grant: VerifiedObservationAdmissionGrant
    let challenge: ObservationAdmissionChallenge
    let context: FileRequestSession
}

private struct ActiveObservationAdmission {
    let computerID: String
    let endpointSessionID: String
    let expiresAtUnix: Int64
}

private struct ObservationGrantKey: Hashable {
    let deploymentID: String
    let grantID: String
}

private struct CachedEndpointSession {
    let session: EndpointSession
    let localUserID: String?
}

private struct EndpointSessionFlight: Sendable {
    let id: UUID
    let localUserID: String?
    let task: Task<EndpointSession, Error>
}

private struct EndpointFileJob: Decodable {
    let id: String
    let fileName: String
    let fileSizeBytes: UInt64
    let sha256: String
    let chunkSizeBytes: UInt32
    let chunkCount: UInt32
    let state: String

    enum CodingKeys: String, CodingKey {
        case id
        case fileName = "file_name"
        case fileSizeBytes = "file_size_bytes"
        case sha256
        case chunkSizeBytes = "chunk_size_bytes"
        case chunkCount = "chunk_count"
        case state
    }
}

private struct EndpointFileJobResult: Encodable {
    let succeeded: Bool
    var detail: String? = nil
    var receivedSizeBytes: UInt64? = nil
    var receivedSHA256: String? = nil

    enum CodingKeys: String, CodingKey {
        case succeeded
        case detail
        case receivedSizeBytes = "received_size_bytes"
        case receivedSHA256 = "received_sha256"
    }
}

private struct EndpointFileJobResultResponse: Decodable {
    let jobID: String

    enum CodingKeys: String, CodingKey {
        case jobID = "job_id"
    }
}

private struct EndpointEnrollmentEnvelope: Decodable {
    let computer: EndpointEnrollmentResult
    let state: String
}

private struct DeploymentAuthorityResponse: Decodable {
    let deploymentID: String
    let grantSigningPublicKey: String
    let authorityGeneration: Int64

    enum CodingKeys: String, CodingKey {
        case deploymentID = "deployment_id"
        case grantSigningPublicKey = "grant_signing_public_key"
        case authorityGeneration = "authority_generation"
    }
}

private struct StoredEndpointIdentity: Codable, Sendable {
    var version: Int
    let deploymentID: String
    var privateKey: Data
    var result: EndpointEnrollmentResult?
    var serverAddress: String?
    var grantVerificationPublicKeyHex: String? = nil
    var authorityGeneration: Int64? = nil
}

private struct EndpointFileDeliveryFailure: Error {
    let detail: String
}

private struct EndpointFileDeliveryPaused: Error {}

protocol EndpointEnrollmentKeyStoring: Sendable {
    func read(account: String) async throws -> Data?
    func insertIfAbsent(_ bytes: Data, account: String) async throws -> Bool
    func update(_ bytes: Data, account: String) async throws
    func delete(account: String) async throws
}

private actor KeychainEndpointEnrollmentKeyStore: EndpointEnrollmentKeyStoring {
    private func query(account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "systems.helicoid.computer.endpoint-identity.v1",
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
        guard status == errSecSuccess, let data = item as? Data else { throw keychainFailure() }
        return data
    }

    func insertIfAbsent(_ bytes: Data, account: String) throws -> Bool {
        var request = query(account: account)
        request[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        request[kSecAttrLabel as String] = "Helicoid Computer endpoint identity"
        request[kSecValueData as String] = bytes
        let status = SecItemAdd(request as CFDictionary, nil)
        if status == errSecDuplicateItem { return false }
        guard status == errSecSuccess else { throw keychainFailure() }
        return true
    }

    func update(_ bytes: Data, account: String) throws {
        let status = SecItemUpdate(query(account: account) as CFDictionary,
                                   [kSecValueData as String: bytes] as CFDictionary)
        guard status == errSecSuccess else { throw keychainFailure() }
    }

    func delete(account: String) throws {
        let status = SecItemDelete(query(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw keychainFailure() }
    }

    private func keychainFailure() -> HelicoidError {
        .authenticationFailed(detail: "The endpoint identity could not be read or saved in the unlocked macOS Keychain.")
    }
}

private final class EndpointEnrollmentRedirectRefuser: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
