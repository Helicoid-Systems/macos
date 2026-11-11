import Foundation

/// Independently supplied production TLS trust inputs bound atomically to the
/// deployment authority checkpoint in `ManagerAuthorityTrustRecord`.
///
/// This type validates the complete pinned TLS identity: deployment ID, host,
/// port, CA DER, and CA SHA-256 pin. It is persisted inside the same Keychain
/// record as the authority checkpoint, so a substituted origin or CA cannot be
/// paired with an unchanged checkpoint.
public struct ManagerProductionTrustConfiguration: Codable, Sendable, Hashable {
    public let tlsIdentity: DeploymentTLSIdentity

    public var deploymentID: String { tlsIdentity.deploymentID }
    public var host: String { tlsIdentity.host }
    public var port: Int { tlsIdentity.port }
    public var caDER: Data { tlsIdentity.caDER }
    public var caFingerprintSHA256: String { tlsIdentity.caFingerprintSHA256 }

    public init(
        deploymentID: String,
        host: String,
        port: Int,
        caDER: Data,
        caFingerprintSHA256: String
    ) throws {
        self.tlsIdentity = try DeploymentTLSIdentity(
            deploymentID: deploymentID,
            host: host,
            port: port,
            caDER: caDER,
            caFingerprintSHA256: caFingerprintSHA256
        )
    }

    public init(tlsIdentity: DeploymentTLSIdentity) {
        self.tlsIdentity = tlsIdentity
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            deploymentID: container.decode(String.self, forKey: .deploymentID),
            host: container.decode(String.self, forKey: .host),
            port: container.decode(Int.self, forKey: .port),
            caDER: container.decode(Data.self, forKey: .caDER),
            caFingerprintSHA256: container.decode(String.self, forKey: .caFingerprintSHA256)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(deploymentID, forKey: .deploymentID)
        try container.encode(host, forKey: .host)
        try container.encode(port, forKey: .port)
        try container.encode(caDER, forKey: .caDER)
        try container.encode(caFingerprintSHA256, forKey: .caFingerprintSHA256)
    }

    public func encodedForTrustRecord() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func decodeFromTrustRecord(_ data: Data) throws -> Self {
        try JSONDecoder().decode(Self.self, from: data)
    }

    private enum CodingKeys: String, CodingKey {
        case deploymentID
        case host
        case port
        case caDER
        case caFingerprintSHA256
    }
}
