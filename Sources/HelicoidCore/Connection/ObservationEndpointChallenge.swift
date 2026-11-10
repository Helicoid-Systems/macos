import CryptoKit
import Foundation

/// Device whose ephemeral WebRTC certificate is named by a signed observation
/// peer statement.
public enum ObservationPeerRole: String, Sendable, Equatable {
    case manager
    case endpoint
}

/// An endpoint challenge whose unsigned identity claims and certificate
/// attestation both matched one verified observation grant. The certificate is
/// public data and may be pinned only after this value has been returned.
///
/// This value proves only the challenge payload. The signaling caller remains
/// responsible for accepting it solely from a relayed endpoint `challenge`
/// message in the expected order.
public struct VerifiedObservationEndpointChallenge: Sendable, Equatable {
    public let computerID: String
    public let endpointSessionID: String
    public let endpointNonceHex: String
    public let expiresAtUnix: Int64
    public let endpointCertificatePEM: Data

    fileprivate init(
        computerID: String,
        endpointSessionID: String,
        endpointNonceHex: String,
        expiresAtUnix: Int64,
        endpointCertificatePEM: Data
    ) {
        self.computerID = computerID
        self.endpointSessionID = endpointSessionID
        self.endpointNonceHex = endpointNonceHex
        self.expiresAtUnix = expiresAtUnix
        self.endpointCertificatePEM = endpointCertificatePEM
    }
}

/// Strict Manager-side verifier for the endpoint's first observation signal.
///
/// The challenge is unsigned JSON, so every identity claim must match the
/// server-signed grant and the endpoint certificate attestation must verify
/// under the endpoint key named by that grant. The attestation is required:
/// without it the Manager cannot pin the endpoint's DTLS identity. A four-field
/// challenge without the certificate and signature is rejected explicitly.
/// Expiry is checked against the supplied time so callers can test exact
/// boundaries.
///
/// This verifier checks only the challenge payload. The signaling caller must
/// still require the enclosing relayed message to have sender `endpoint` and
/// kind `challenge`, in order, before invoking this verifier.
public enum ObservationEndpointChallengeVerifier {
    private static let maximumPayloadBytes = 4 * 1024
    private static let baseFields: Set<String> = [
        "computer_id",
        "endpoint_session_id",
        "endpoint_nonce",
        "expires_at_unix",
    ]
    private static let expectedFields: Set<String> = [
        "computer_id",
        "endpoint_session_id",
        "endpoint_nonce",
        "expires_at_unix",
        "endpoint_certificate_pem",
        "endpoint_certificate_signature",
    ]

    /// Verify one endpoint challenge payload against a verified grant before
    /// the Manager creates an offer or trusts any endpoint certificate.
    public static func verify(
        payload: String,
        grant: VerifiedObservationAdmissionGrant,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> VerifiedObservationEndpointChallenge {
        let utf8Count = payload.utf8.count
        guard utf8Count > 0, utf8Count <= maximumPayloadBytes else {
            throw invalidChallenge()
        }
        let bytes = Array(payload.utf8)
        guard bytes.allSatisfy({ $0 < 0x80 && $0 != 0 }) else {
            throw invalidChallenge()
        }

        var parser = ChallengePayloadParser(bytes: bytes)
        let claims: [String: ChallengeValue]
        do {
            claims = try parser.parse()
        } catch {
            throw invalidChallenge()
        }

        let fields = Set(claims.keys)
        if fields == baseFields {
            throw missingAttestationChallenge()
        }
        guard claims.count == expectedFields.count,
              fields == expectedFields,
              let computerID = challengeString(claims["computer_id"]),
              let endpointSessionID = challengeString(claims["endpoint_session_id"]),
              let endpointNonceHex = challengeString(claims["endpoint_nonce"]),
              let expiresAtUnix = challengeInteger(claims["expires_at_unix"]),
              let certificatePEM = challengeString(claims["endpoint_certificate_pem"]),
              let signatureHex = challengeString(claims["endpoint_certificate_signature"]),
              computerID == grant.computerID,
              endpointSessionID == grant.endpointSessionID,
              ObservationAdmissionGrantVerifier.isLowerHex(endpointNonceHex, byteCount: 32),
              expiresAtUnix == grant.expiresAtUnix,
              expiresAtUnix > nowUnixSeconds,
              let certificateBytes = certificatePEM.data(using: .ascii),
              let signature = ObservationAdmissionGrantVerifier.lowerHexBytes(signatureHex),
              signature.count == 64,
              grant.verifiesPeerCertificateAttestation(
                certificatePEM: certificateBytes,
                endpointNonceHex: endpointNonceHex,
                role: .endpoint,
                signature: signature,
                nowUnixSeconds: nowUnixSeconds
              )
        else { throw invalidChallenge() }

        return VerifiedObservationEndpointChallenge(
            computerID: computerID,
            endpointSessionID: endpointSessionID,
            endpointNonceHex: endpointNonceHex,
            expiresAtUnix: expiresAtUnix,
            endpointCertificatePEM: certificateBytes
        )
    }

    static func isCanonicalCertificatePEM(_ value: Data) -> Bool {
        let begin = Array("-----BEGIN CERTIFICATE-----\n".utf8)
        let end = Array("-----END CERTIFICATE-----\n".utf8)
        let bytes = Array(value)
        guard bytes.count > begin.count + end.count,
              bytes.count <= 4 * 1024,
              !bytes.contains(0),
              Array(bytes.prefix(begin.count)) == begin,
              Array(bytes.suffix(end.count)) == end
        else { return false }
        let body = bytes[begin.count..<(bytes.count - end.count)]
        return !body.isEmpty && body.allSatisfy { byte in
            (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) ||
                (byte >= 0x30 && byte <= 0x39) || byte == 0x2B || byte == 0x2F ||
                byte == 0x3D || byte == 0x0A
        }
    }

    private static func invalidChallenge() -> HelicoidError {
        .authenticationFailed(
            detail: "The endpoint observation challenge is invalid or does not match the verified grant."
        )
    }

    private static func missingAttestationChallenge() -> HelicoidError {
        .authenticationFailed(
            detail: "The endpoint observation challenge has no certificate attestation, so the endpoint identity cannot be pinned."
        )
    }
}

extension VerifiedObservationAdmissionGrant {
    /// Build the canonical device-key statement for one exact ephemeral DTLS
    /// certificate. The nonce, role, and signed grant context prevent reuse
    /// across observations or peer directions. The grant must still be current.
    public func peerCertificateAttestationMessage(
        certificatePEM: Data,
        endpointNonceHex: String,
        role: ObservationPeerRole,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> Data {
        guard ObservationAdmissionGrantVerifier.isLowerHex(endpointNonceHex, byteCount: 32),
              expiresAtUnix > nowUnixSeconds,
              ObservationEndpointChallengeVerifier.isCanonicalCertificatePEM(certificatePEM)
        else { throw ObservationAdmissionGrantVerifier.invalidGrant() }

        let certificateSHA256 = SHA256.hash(data: certificatePEM)
            .map { String(format: "%02x", $0) }
            .joined()
        let message = "hs-observation-peer-certificate-v1|deployment:\(deploymentID)|grant:\(grantID)|computer:\(computerID)|endpoint_session:\(endpointSessionID)|epoch:\(enrollmentEpoch)|nonce:\(endpointNonceHex)|role:\(role.rawValue)|certificate_sha256:\(certificateSHA256)"
        return Data(message.utf8)
    }

    /// Verify the endpoint's certificate attestation before pinning its
    /// certificate. The endpoint role uses the endpoint key named by the
    /// verified grant; the manager role uses the active Manager key.
    public func verifiesPeerCertificateAttestation(
        certificatePEM: Data,
        endpointNonceHex: String,
        role: ObservationPeerRole,
        signature: Data,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) -> Bool {
        guard signature.count == 64 else { return false }
        let publicKeyHex: String
        switch role {
        case .manager: publicKeyHex = managerPublicKeyHex
        case .endpoint: publicKeyHex = endpointPublicKeyHex
        }
        guard let publicKeyBytes = ObservationAdmissionGrantVerifier.lowerHexBytes(publicKeyHex) else {
            return false
        }
        do {
            let message = try peerCertificateAttestationMessage(
                certificatePEM: certificatePEM,
                endpointNonceHex: endpointNonceHex,
                role: role,
                nowUnixSeconds: nowUnixSeconds
            )
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyBytes)
            return key.isValidSignature(signature, for: message)
        } catch {
            return false
        }
    }
}

private enum ChallengeValue {
    case string(String)
    case integer(Int64)
}

private func challengeString(_ value: ChallengeValue?) -> String? {
    guard let value = value else { return nil }
    if case .string(let string) = value { return string }
    return nil
}

private func challengeInteger(_ value: ChallengeValue?) -> Int64? {
    guard let value = value else { return nil }
    if case .integer(let integer) = value { return integer }
    return nil
}

private struct ChallengeParseError: Error {}

/// Strict parser for the challenge's flat JSON object. Values are limited to
/// strings and non-negative integers, duplicate or unknown keys are rejected,
/// and escaped non-ASCII scalars are refused so the payload stays bounded.
private struct ChallengePayloadParser {
    let bytes: [UInt8]
    var index = 0

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    mutating func parse() throws -> [String: ChallengeValue] {
        skipWhitespace()
        guard consume(0x7B) else { throw ChallengeParseError() }
        skipWhitespace()
        if consume(0x7D) { throw ChallengeParseError() }

        var values: [String: ChallengeValue] = [:]
        while true {
            skipWhitespace()
            let key = try parseString()
            guard values[key] == nil else { throw ChallengeParseError() }
            skipWhitespace()
            guard consume(0x3A) else { throw ChallengeParseError() }
            skipWhitespace()

            if index < bytes.count, bytes[index] == 0x22 {
                values[key] = .string(try parseString())
            } else {
                values[key] = .integer(try parseInteger())
            }

            skipWhitespace()
            if consume(0x2C) { continue }
            guard consume(0x7D) else { throw ChallengeParseError() }
            break
        }
        skipWhitespace()
        guard index == bytes.count else { throw ChallengeParseError() }
        return values
    }

    private mutating func skipWhitespace() {
        while index < bytes.count {
            switch bytes[index] {
            case 0x20, 0x09, 0x0A, 0x0D:
                index += 1
            default:
                return
            }
        }
    }

    private mutating func consume(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1
        return true
    }

    private mutating func parseString() throws -> String {
        guard consume(0x22) else { throw ChallengeParseError() }
        var result: [UInt8] = []
        while index < bytes.count {
            let byte = bytes[index]
            index += 1
            if byte == 0x22 {
                return String(decoding: result, as: UTF8.self)
            }
            if byte == 0x5C {
                guard index < bytes.count else { throw ChallengeParseError() }
                let escaped = bytes[index]
                index += 1
                switch escaped {
                case 0x22, 0x5C, 0x2F:
                    result.append(escaped)
                case 0x62:
                    result.append(0x08)
                case 0x66:
                    result.append(0x0C)
                case 0x6E:
                    result.append(0x0A)
                case 0x72:
                    result.append(0x0D)
                case 0x74:
                    result.append(0x09)
                case 0x75:
                    guard index + 4 <= bytes.count else { throw ChallengeParseError() }
                    var scalar: UInt32 = 0
                    for _ in 0..<4 {
                        guard let nibble = hexNibble(bytes[index]) else {
                            throw ChallengeParseError()
                        }
                        scalar = (scalar << 4) | UInt32(nibble)
                        index += 1
                    }
                    guard scalar <= 0x7F else { throw ChallengeParseError() }
                    result.append(UInt8(scalar))
                default:
                    throw ChallengeParseError()
                }
                continue
            }
            guard byte >= 0x20 else { throw ChallengeParseError() }
            result.append(byte)
        }
        throw ChallengeParseError()
    }

    private mutating func parseInteger() throws -> Int64 {
        guard index < bytes.count,
              bytes[index] >= 0x30,
              bytes[index] <= 0x39
        else { throw ChallengeParseError() }

        if bytes[index] == 0x30 {
            index += 1
            if index < bytes.count, bytes[index] >= 0x30, bytes[index] <= 0x39 {
                throw ChallengeParseError()
            }
            return 0
        }

        var value: Int64 = 0
        while index < bytes.count, bytes[index] >= 0x30, bytes[index] <= 0x39 {
            let digit = Int64(bytes[index] - 0x30)
            let (multiplied, multipliedOverflow) =
                value.multipliedReportingOverflow(by: 10)
            guard !multipliedOverflow else { throw ChallengeParseError() }
            let (added, addedOverflow) =
                multiplied.addingReportingOverflow(digit)
            guard !addedOverflow else { throw ChallengeParseError() }
            value = added
            index += 1
        }
        return value
    }

    private func hexNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: return byte - 0x30
        case 0x61...0x66: return byte - 0x61 + 10
        case 0x41...0x46: return byte - 0x41 + 10
        default: return nil
        }
    }
}
