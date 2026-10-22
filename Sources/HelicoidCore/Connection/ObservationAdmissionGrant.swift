import CryptoKit
import Foundation

/// Expected endpoint incarnation for local observation-grant validation.
/// The server verification key must come from the deployment's pinned HTTPS
/// connection; this type does not establish trust in that key.
public struct ObservationAdmissionEndpoint: Sendable {
    public let deploymentID: String
    public let computerID: String
    public let endpointPublicKeyHex: String
    public let endpointSessionID: String
    public let enrollmentEpoch: Int64

    public init(
        deploymentID: String,
        computerID: String,
        endpointPublicKeyHex: String,
        endpointSessionID: String,
        enrollmentEpoch: Int64
    ) {
        self.deploymentID = deploymentID
        self.computerID = computerID
        self.endpointPublicKeyHex = endpointPublicKeyHex
        self.endpointSessionID = endpointSessionID
        self.enrollmentEpoch = enrollmentEpoch
    }
}

/// A deployment-signed observation grant whose target and lifetime were
/// checked against the current local endpoint session.
public struct VerifiedObservationAdmissionGrant: Sendable, Equatable {
    public let grantID: String
    public let deploymentID: String
    public let accountID: String
    public let managerID: String
    public let managerPublicKeyHex: String
    public let computerID: String
    public let endpointPublicKeyHex: String
    public let endpointSessionID: String
    public let enrollmentEpoch: Int64
    public let issuedAtUnix: Int64
    public let expiresAtUnix: Int64

    fileprivate init(claims: ObservationAdmissionGrantVerifier.Claims) {
        grantID = claims.grantID
        deploymentID = claims.deploymentID
        accountID = claims.accountID
        managerID = claims.managerID
        managerPublicKeyHex = claims.managerPublicKey
        computerID = claims.computerID
        endpointPublicKeyHex = claims.endpointPublicKey
        endpointSessionID = claims.endpointSessionID
        enrollmentEpoch = claims.enrollmentEpoch
        issuedAtUnix = claims.issuedAtUnix
        expiresAtUnix = claims.expiresAtUnix
    }

    /// Bytes the Manager signs after receiving this endpoint's fresh nonce and
    /// the canonical binding exported by its currently verified native peer.
    public func managerProofMessage(
        endpointNonceHex: String,
        channelBindingHex: String
    ) throws -> Data {
        guard ObservationAdmissionGrantVerifier.isLowerHex(endpointNonceHex, byteCount: 32) else {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        guard ObservationAdmissionGrantVerifier.isCanonicalChannelBindingHex(channelBindingHex) else {
            throw ObservationAdmissionGrantVerifier.invalidGrant()
        }
        let message = "hs-observation-peer-proof-v2|deployment:\(deploymentID)|grant:\(grantID)|computer:\(computerID)|endpoint_session:\(endpointSessionID)|epoch:\(enrollmentEpoch)|nonce:\(endpointNonceHex)|channel_binding:\(channelBindingHex)"
        return Data(message.utf8)
    }

    /// Verify the Manager's proof locally before asking the server to consume
    /// the grant. The current native channel binding is part of the signature.
    public func verifiesManagerProof(
        endpointNonceHex: String,
        channelBindingHex: String,
        signature: Data
    ) -> Bool {
        guard signature.count == 64,
              let keyBytes = ObservationAdmissionGrantVerifier.lowerHexBytes(managerPublicKeyHex)
        else {
            return false
        }
        do {
            let message = try managerProofMessage(
                endpointNonceHex: endpointNonceHex,
                channelBindingHex: channelBindingHex
            )
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: keyBytes)
            return key.isValidSignature(signature, for: message)
        } catch {
            return false
        }
    }
}

/// Strict verifier for the server's version-1 observation admission token.
public enum ObservationAdmissionGrantVerifier {
    private static let domain = Data("hs-observation-grant-v1\0".utf8)
    private static let maximumTokenBytes = 8 * 1024
    private static let maximumPayloadBytes = 4 * 1024
    private static let lifetimeSeconds: Int64 = 10

    fileprivate struct Claims: Decodable {
        let version: UInt8
        let grantID: String
        let deploymentID: String
        let accountID: String
        let managerID: String
        let managerPublicKey: String
        let computerID: String
        let endpointPublicKey: String
        let endpointSessionID: String
        let enrollmentEpoch: Int64
        let issuedAtUnix: Int64
        let expiresAtUnix: Int64
        let capability: String

        enum CodingKeys: String, CodingKey {
            case version
            case grantID = "grant_id"
            case deploymentID = "deployment_id"
            case accountID = "account_id"
            case managerID = "manager_id"
            case managerPublicKey = "manager_public_key"
            case computerID = "computer_id"
            case endpointPublicKey = "endpoint_public_key"
            case endpointSessionID = "endpoint_session_id"
            case enrollmentEpoch = "enrollment_epoch"
            case issuedAtUnix = "issued_at_unix"
            case expiresAtUnix = "expires_at_unix"
            case capability
        }
    }

    /// Verify the exact signed bytes, canonical token encoding, claims, and
    /// endpoint binding. `serverPublicKeyHex` must already be trusted through
    /// the deployment's pinned HTTPS connection.
    public static func verify(
        token: String,
        serverPublicKeyHex: String,
        expected: ObservationAdmissionEndpoint,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> VerifiedObservationAdmissionGrant {
        guard token.utf8.count <= maximumTokenBytes,
              token.utf8.allSatisfy({ $0 < 0x80 })
        else { throw invalidGrant() }

        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2,
              !parts[0].isEmpty,
              isLowerHex(String(parts[1]), byteCount: 64),
              let payload = decodeCanonicalBase64URL(String(parts[0])),
              payload.count <= maximumPayloadBytes,
              let serverKeyBytes = lowerHexBytes(serverPublicKeyHex),
              let signature = lowerHexBytes(String(parts[1])),
              signature.count == 64
        else { throw invalidGrant() }

        let serverKey: Curve25519.Signing.PublicKey
        do {
            serverKey = try Curve25519.Signing.PublicKey(rawRepresentation: serverKeyBytes)
        } catch {
            throw invalidGrant()
        }
        guard serverKey.isValidSignature(signature, for: domain + payload) else {
            throw invalidGrant()
        }

        let decoder = JSONDecoder()
        let claims: Claims
        do {
            claims = try decoder.decode(Claims.self, from: payload)
        } catch {
            throw invalidGrant()
        }

        guard claims.version == 1,
              claims.capability == "observe",
              canonicalUUID(claims.grantID),
              canonicalUUID(claims.accountID),
              canonicalUUID(claims.managerID),
              canonicalUUID(claims.computerID),
              canonicalUUID(claims.endpointSessionID),
              canonicalDeploymentID(claims.deploymentID),
              isLowerHex(claims.managerPublicKey, byteCount: 32),
              isLowerHex(claims.endpointPublicKey, byteCount: 32),
              claims.enrollmentEpoch > 0,
              claims.issuedAtUnix <= nowUnixSeconds + 5,
              claims.expiresAtUnix > nowUnixSeconds,
              claims.expiresAtUnix > claims.issuedAtUnix,
              claims.expiresAtUnix >= Int64.min + lifetimeSeconds,
              claims.issuedAtUnix >= claims.expiresAtUnix - lifetimeSeconds,
              claims.deploymentID == expected.deploymentID,
              claims.computerID == expected.computerID,
              claims.endpointPublicKey == expected.endpointPublicKeyHex,
              claims.endpointSessionID == expected.endpointSessionID,
              claims.enrollmentEpoch == expected.enrollmentEpoch,
              canonicalPayload(claims) == payload
        else { throw invalidGrant() }

        return VerifiedObservationAdmissionGrant(claims: claims)
    }

    /// Produce a cryptographically random 32-byte lowercase-hex endpoint nonce.
    public static func makeEndpointNonce() -> String {
        var generator = SystemRandomNumberGenerator()
        var bytes = [UInt8]()
        bytes.reserveCapacity(32)
        for _ in 0..<32 {
            bytes.append(UInt8.random(in: 0...UInt8.max, using: &generator))
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    fileprivate static func isLowerHex(_ value: String, byteCount: Int) -> Bool {
        value.utf8.count == byteCount * 2 && value.utf8.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66)
        }
    }

    fileprivate static func lowerHexBytes(_ value: String) -> Data? {
        guard isLowerHex(value, byteCount: value.utf8.count / 2) else { return nil }
        var bytes = Data()
        bytes.reserveCapacity(value.utf8.count / 2)
        let input = Array(value.utf8)
        for index in stride(from: 0, to: input.count, by: 2) {
            guard let high = hexNibble(input[index]), let low = hexNibble(input[index + 1]) else {
                return nil
            }
            bytes.append((high << 4) | low)
        }
        return bytes
    }

    /// Return lowercase hex only for the exact canonical tuple exported by
    /// the native WebRTC verified-channel handle.
    public static func canonicalChannelBindingHex(_ binding: Data) -> String? {
        let bytes = Array(binding)
        let domain = Array("HS-WEBRTC-DTLS-SCTP-V1\0".utf8)
        let label = Array("hs-product".utf8)
        let expectedCount = domain.count + 2 + label.count + 2 + 64
        guard bytes.count == expectedCount,
              Array(bytes.prefix(domain.count)) == domain else { return nil }
        var cursor = domain.count
        let labelLength = (UInt16(bytes[cursor]) << 8) | UInt16(bytes[cursor + 1])
        cursor += 2
        guard Int(labelLength) == label.count,
              Array(bytes[cursor..<(cursor + label.count)]) == label else { return nil }
        cursor += label.count
        let streamID = (UInt16(bytes[cursor]) << 8) | UInt16(bytes[cursor + 1])
        guard streamID != UInt16.max else { return nil }
        cursor += 2
        let first = Array(bytes[cursor..<(cursor + 32)])
        let second = Array(bytes[(cursor + 32)..<(cursor + 64)])
        guard first == second || first.lexicographicallyPrecedes(second) else { return nil }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    public static func isCanonicalChannelBindingHex(_ value: String) -> Bool {
        guard let bytes = lowerHexBytes(value),
              let canonical = canonicalChannelBindingHex(bytes) else { return false }
        return canonical == value
    }

    static func invalidGrant() -> HelicoidError {
        .authenticationFailed(detail: "The endpoint observation grant is invalid or expired.")
    }

    private static func canonicalUUID(_ value: String) -> Bool {
        UUID(uuidString: value)?.uuidString.lowercased() == value
    }

    private static func canonicalDeploymentID(_ value: String) -> Bool {
        value.hasPrefix("dep_") && isLowerHex(String(value.dropFirst(4)), byteCount: 16)
    }

    private static func canonicalPayload(_ claims: Claims) -> Data {
        let json = "{\"version\":\(claims.version),\"grant_id\":\"\(claims.grantID)\",\"deployment_id\":\"\(claims.deploymentID)\",\"account_id\":\"\(claims.accountID)\",\"manager_id\":\"\(claims.managerID)\",\"manager_public_key\":\"\(claims.managerPublicKey)\",\"computer_id\":\"\(claims.computerID)\",\"endpoint_public_key\":\"\(claims.endpointPublicKey)\",\"endpoint_session_id\":\"\(claims.endpointSessionID)\",\"enrollment_epoch\":\(claims.enrollmentEpoch),\"issued_at_unix\":\(claims.issuedAtUnix),\"expires_at_unix\":\(claims.expiresAtUnix),\"capability\":\"\(claims.capability)\"}"
        return Data(json.utf8)
    }

    private static func decodeCanonicalBase64URL(_ value: String) -> Data? {
        guard value.utf8.allSatisfy({
            ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) ||
                ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2d || $0 == 0x5f
        }) else { return nil }
        let standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4)
        guard let decoded = Data(base64Encoded: standard + padding),
              decoded.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "") == value
        else { return nil }
        return decoded
    }

    private static func hexNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: byte - 0x30
        case 0x61...0x66: byte - 0x61 + 10
        default: nil
        }
    }
}
