import Foundation

/// Opaque identity of an enrolled computer. Display names and addresses never grant authority.
public struct ComputerID: Hashable, Sendable, Codable, RawRepresentable, CustomStringConvertible {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    public var description: String { rawValue }
}

/// Identity of an authorized operator account on a deployment.
public struct OperatorID: Hashable, Sendable, Codable, RawRepresentable, CustomStringConvertible {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    public var description: String { rawValue }
}

/// Stable display identity of an enrolled computer.
public struct Computer: Hashable, Sendable, Identifiable, Codable {
    public let id: ComputerID
    public var name: String
    public var trustedUserName: String?
    public var isOnline: Bool
    public var needsAttention: Bool
    public var groupIDs: [String]
    /// Contract enrollment_state when known: pending | enrolled | quarantined | revoked.
    public var enrollmentState: String?
    /// Honest display status derived from enrollment. Not a presence signal.
    public var statusLabel: String?
    public var publicIdentity: String?

    public init(
        id: ComputerID,
        name: String,
        trustedUserName: String? = nil,
        isOnline: Bool = false,
        needsAttention: Bool = false,
        groupIDs: [String] = [],
        enrollmentState: String? = nil,
        statusLabel: String? = nil,
        publicIdentity: String? = nil
    ) {
        self.id = id
        self.name = name
        self.trustedUserName = trustedUserName
        self.isOnline = isOnline
        self.needsAttention = needsAttention
        self.groupIDs = groupIDs
        self.enrollmentState = enrollmentState
        self.statusLabel = statusLabel
        self.publicIdentity = publicIdentity
    }
}

/// Optional flat named group. Membership never duplicates a tile and never grants access.
public struct ComputerGroup: Hashable, Sendable, Identifiable, Codable {
    public let id: String
    public var name: String
    public var computerIDs: [ComputerID]

    public init(id: String, name: String, computerIDs: [ComputerID] = []) {
        self.id = id
        self.name = name
        self.computerIDs = computerIDs
    }
}

/// Verified deployment identity presented during connect/verify.
public struct ServerIdentity: Hashable, Sendable, Codable {
    public var deploymentName: String
    public var verificationFingerprint: String
    public var trustedSourceNote: String

    public init(
        deploymentName: String,
        verificationFingerprint: String,
        trustedSourceNote: String = "Verify this fingerprint through a trusted Helicoid Systems channel before continuing."
    ) {
        self.deploymentName = deploymentName
        self.verificationFingerprint = verificationFingerprint
        self.trustedSourceNote = trustedSourceNote
    }
}

/// A remembered server address/profile the operator may connect to.
public struct ServerProfile: Hashable, Sendable, Identifiable, Codable {
    public let id: String
    public var displayName: String
    public var address: String
    public var lastVerifiedIdentity: ServerIdentity?

    public init(
        id: String = UUID().uuidString,
        displayName: String,
        address: String,
        lastVerifiedIdentity: ServerIdentity? = nil
    ) {
        self.id = id
        self.displayName = displayName
        self.address = address
        self.lastVerifiedIdentity = lastVerifiedIdentity
    }
}
