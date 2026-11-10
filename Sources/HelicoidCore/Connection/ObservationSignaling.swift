import CoreFoundation
import Foundation

/// One endpoint-to-Manager signaling value that has passed the enclosing
/// envelope, sender, kind, sequence, and size checks. SDP and ICE values are
/// still only negotiation data: this type does not prove a connected peer or
/// authorize media.
public struct VerifiedManagerObservationSignal: Sendable, Equatable {
    public enum Kind: String, Sendable, Equatable {
        case answer
        case ice
        case close
    }

    public let sequence: UInt64
    public let kind: Kind
    public let payload: String

    fileprivate init(sequence: UInt64, kind: Kind, payload: String) {
        self.sequence = sequence
        self.kind = kind
        self.payload = payload
    }
}

/// Strict Manager-side state for one observation grant's signaling mailbox.
///
/// The server relays unsigned values, so no value may be trusted before its
/// enclosing message is proven to come from `endpoint` with a kind the Manager
/// expects next. The first endpoint signal must be `challenge` or a terminal
/// `close`; a challenge payload is then verified against the server-signed
/// grant, including the endpoint's certificate attestation. Later values may
/// only be `answer`, `ice`, or `close`. There is deliberately no offer, media,
/// pixel, or control path here: a native verified WebRTC peer is still required
/// before the Manager can send an attested offer or display frames.
public struct ManagerObservationSignalingSession: Sendable {
    public enum Phase: Sendable, Equatable {
        /// Polling for the endpoint's first `challenge` signal.
        case awaitingChallenge
        /// Challenge and its DTLS certificate attestation were verified.
        case awaitingAnswer
        /// A valid endpoint answer arrived; ICE/close may still follow.
        case negotiating
        /// The endpoint sent `close`, or the caller ended the session.
        case closed
    }

    /// Bounds mirror the current server observation-signaling wire rules. The
    /// macOS app still vendors only `http-v1`; copying the v2 contract and
    /// recording its exact upstream provenance is a separate required step, not
    /// something this file claims to provide.
    public static let maximumSignalSequence: UInt64 = 128
    public static let maximumBatchMessages = 64
    public static let maximumAnswerBytes = 65_536
    public static let maximumICEBytes = 4_096
    public static let maximumChallengeBytes = 4_096

    /// The server bounds the mailbox's raw signal payload at 256 KiB of UTF-8.
    /// The wire batch is larger: JSON escaping of legal signal text expands at
    /// most 2x (quote, backslash, CR, LF, TAB), and the envelope adds keys,
    /// numbers, and separators for up to 64 messages. Use 4x as explicit
    /// headroom rather than a claim about arbitrary Unicode escaping, plus
    /// 512 bytes of envelope per message and 4 KiB of root/array overhead.
    /// This remains a fixed upper bound, not a claim that every accepted size is
    /// reachable for one signal kind.
    private static let maximumMailboxPayloadBytes = 256 * 1024
    private static let maximumJSONExpansionFactor = 4
    private static let maximumEnvelopeBytesPerMessage = 512
    private static let maximumRootEnvelopeBytes = 4 * 1024
    public static let maximumBatchBytes =
        maximumMailboxPayloadBytes * maximumJSONExpansionFactor
        + maximumBatchMessages * maximumEnvelopeBytesPerMessage
        + maximumRootEnvelopeBytes

    public let grant: VerifiedObservationAdmissionGrant
    public private(set) var phase: Phase
    public private(set) var cursor: UInt64
    public private(set) var challenge: VerifiedObservationEndpointChallenge?
    public private(set) var hasRemoteAnswer: Bool

    public init(grant: VerifiedObservationAdmissionGrant) {
        self.grant = grant
        self.phase = .awaitingChallenge
        self.cursor = 0
        self.challenge = nil
        self.hasRemoteAnswer = false
    }

    /// Decode one bounded Manager mailbox batch. Unknown or incorrectly typed
    /// envelope fields are rejected before semantic checks.
    public static func decodeBatch(_ data: Data) throws -> ObservationSignalBatch {
        guard !data.isEmpty, data.count <= maximumBatchBytes,
              let root = try? JSONSerialization.jsonObject(with: data),
              let object = root as? [String: Any],
              object.count == 2,
              let cursorNumber = object["cursor"] as? NSNumber,
              !isBooleanNumber(cursorNumber),
              let rawMessages = object["messages"] as? [Any],
              rawMessages.count <= maximumBatchMessages
        else { throw invalidSignal() }

        for rawMessage in rawMessages {
            guard let message = rawMessage as? [String: Any],
                  message.count == 4,
                  let sequence = message["sequence"] as? NSNumber,
                  !isBooleanNumber(sequence),
                  message["sender"] is String,
                  message["kind"] is String,
                  message["payload"] is String
            else { throw invalidSignal() }
        }

        let batch: ObservationSignalBatch
        do {
            batch = try JSONDecoder().decode(ObservationSignalBatch.self, from: data)
        } catch {
            throw invalidSignal()
        }
        guard batch.cursor <= maximumSignalSequence,
              batch.messages.count <= maximumBatchMessages
        else { throw invalidSignal() }
        return batch
    }

    /// Accept only endpoint `challenge` and `close` messages while waiting for
    /// admission. An empty poll advances the cursor without changing phase. A
    /// verified challenge is the sole point at which the endpoint certificate
    /// may be pinned; its claims must already match this server-signed grant.
    /// `close` is terminal even before a challenge and must be the last message
    /// in its batch. A close in the same batch makes any preceding challenge
    /// unusable: it is neither returned nor retained.
    @discardableResult
    public mutating func acceptChallengeBatch(
        _ data: Data,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> VerifiedObservationEndpointChallenge? {
        try acceptChallengeBatch(
            Self.decodeBatch(data),
            nowUnixSeconds: nowUnixSeconds
        )
    }

    /// Accept only endpoint `challenge` and `close` messages while waiting for
    /// admission.
    @discardableResult
    public mutating func acceptChallengeBatch(
        _ batch: ObservationSignalBatch,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> VerifiedObservationEndpointChallenge? {
        guard phase == .awaitingChallenge else { throw invalidSignal() }
        let messages = try validatedMessages(in: batch)

        guard !messages.isEmpty else {
            cursor = batch.cursor
            return nil
        }

        var nextPhase = Phase.awaitingChallenge
        var nextChallenge: VerifiedObservationEndpointChallenge?
        var challengeSeen = false
        var closeSeen = false

        for (index, message) in messages.enumerated() {
            guard message.sender == "endpoint" else { throw invalidChallengeSignal() }

            switch message.kind {
            case "challenge":
                guard !challengeSeen,
                      !message.payload.isEmpty,
                      message.payload.utf8.count <= Self.maximumChallengeBytes
                else { throw invalidChallengeSignal() }

                // The challenge payload is unsigned JSON. The verifier requires
                // every identity claim to match the signed grant and verifies
                // the endpoint's certificate attestation under the grant's
                // endpoint key. Translate its malformed-endpoint failures to a
                // non-auth protocol error so the operator is not signed out.
                do {
                    nextChallenge = try ObservationEndpointChallengeVerifier.verify(
                        payload: message.payload,
                        grant: grant,
                        nowUnixSeconds: nowUnixSeconds
                    )
                } catch {
                    throw invalidChallengeSignal()
                }
                challengeSeen = true
                nextPhase = .awaitingAnswer

            case "close":
                guard !closeSeen,
                      index == messages.count - 1,
                      message.payload.isEmpty
                else { throw invalidChallengeSignal() }
                closeSeen = true
                nextPhase = .closed

            default:
                // No offer, answer, or ICE may precede admission.
                throw invalidChallengeSignal()
            }
        }

        // A close in the same batch makes the whole exchange terminal. Even if
        // a valid challenge preceded it, no challenge is usable or retained.
        let usableChallenge = closeSeen ? nil : nextChallenge
        cursor = batch.cursor
        challenge = usableChallenge
        phase = nextPhase
        return usableChallenge
    }

    /// Accept endpoint `answer`, `ice`, and `close` messages after a verified
    /// challenge. The state change is atomic: a malformed later message rejects
    /// the whole batch and leaves the session unchanged.
    public mutating func acceptNegotiationBatch(
        _ data: Data,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> [VerifiedManagerObservationSignal] {
        try acceptNegotiationBatch(
            Self.decodeBatch(data),
            nowUnixSeconds: nowUnixSeconds
        )
    }

    /// Accept endpoint `answer`, `ice`, and `close` messages after a verified
    /// challenge.
    public mutating func acceptNegotiationBatch(
        _ batch: ObservationSignalBatch,
        nowUnixSeconds: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> [VerifiedManagerObservationSignal] {
        guard phase == .awaitingAnswer || phase == .negotiating,
              grant.expiresAtUnix > nowUnixSeconds
        else { throw invalidSignal() }

        let messages = try validatedMessages(in: batch)
        var nextPhase = phase
        var nextHasRemoteAnswer = hasRemoteAnswer
        var verified: [VerifiedManagerObservationSignal] = []

        for message in messages {
            guard message.sender == "endpoint" else { throw invalidSignal() }

            switch message.kind {
            case "answer":
                guard nextPhase == .awaitingAnswer, !nextHasRemoteAnswer else {
                    throw invalidSignal()
                }
                guard message.payload.hasPrefix("v=0"),
                      message.payload.utf8.count <= Self.maximumAnswerBytes
                else { throw invalidSignal() }
                nextHasRemoteAnswer = true
                nextPhase = .negotiating
                verified.append(VerifiedManagerObservationSignal(
                    sequence: message.sequence,
                    kind: .answer,
                    payload: message.payload
                ))

            case "ice":
                guard nextPhase == .awaitingAnswer || nextPhase == .negotiating,
                      !message.payload.isEmpty,
                      message.payload.utf8.count <= Self.maximumICEBytes
                else { throw invalidSignal() }
                verified.append(VerifiedManagerObservationSignal(
                    sequence: message.sequence,
                    kind: .ice,
                    payload: message.payload
                ))

            case "close":
                guard nextPhase != .closed, message.payload.isEmpty else {
                    throw invalidSignal()
                }
                nextPhase = .closed
                verified.append(VerifiedManagerObservationSignal(
                    sequence: message.sequence,
                    kind: .close,
                    payload: message.payload
                ))

            default:
                // In particular, never accept a relayed `offer` or a repeated
                // `challenge` as post-admission negotiation.
                throw invalidSignal()
            }
        }

        cursor = batch.cursor
        phase = nextPhase
        hasRemoteAnswer = nextHasRemoteAnswer
        return verified
    }

    /// Caller-ended terminal state. A closed session rejects further signals.
    public mutating func close() {
        phase = .closed
    }

    private struct ValidatedMessage {
        let sequence: UInt64
        let sender: String
        let kind: String
        let payload: String
    }

    /// Validate the unsigned envelope and its cursor before any payload is
    /// interpreted. Sequence values must increase across batches and may skip
    /// the Manager's own messages, as the server's per-grant sequence includes
    /// both senders.
    private func validatedMessages(
        in batch: ObservationSignalBatch
    ) throws -> [ValidatedMessage] {
        guard batch.cursor >= cursor,
              batch.cursor <= Self.maximumSignalSequence,
              batch.messages.count <= Self.maximumBatchMessages
        else { throw invalidSignal() }

        var lastSequence = cursor
        var result: [ValidatedMessage] = []
        result.reserveCapacity(batch.messages.count)

        for message in batch.messages {
            guard message.sequence > lastSequence,
                  message.sequence <= batch.cursor,
                  message.sequence <= Self.maximumSignalSequence,
                  isServerSignalPayload(message.payload),
                  message.payload.utf8.count <= Self.maximumAnswerBytes
            else { throw invalidSignal() }
            lastSequence = message.sequence
            result.append(ValidatedMessage(
                sequence: message.sequence,
                sender: message.sender,
                kind: message.kind,
                payload: message.payload
            ))
        }
        return result
    }

    private static func isBooleanNumber(_ number: NSNumber) -> Bool {
        CFGetTypeID(number as CFTypeRef) == CFBooleanGetTypeID()
    }

    /// Match the server's signal-payload rule: NUL and ASCII control bytes are
    /// rejected except CR, LF, and TAB. Non-ASCII UTF-8 is valid and is counted
    /// by its encoded byte length.
    private func isServerSignalPayload(_ value: String) -> Bool {
        value.utf8.allSatisfy { byte in
            if byte == 0x09 || byte == 0x0A || byte == 0x0D { return true }
            return !(byte < 0x20 || byte == 0x7F)
        }
    }

    private static func invalidSignal() -> HelicoidError {
        .observationProtocolViolation(
            detail: "The endpoint sent an invalid, stale, or out-of-order observation signal. The Manager session remains active."
        )
    }

    private static func invalidChallengeSignal() -> HelicoidError {
        .observationProtocolViolation(
            detail: "The endpoint observation challenge or close signal did not match the verified grant. The Manager session remains active."
        )
    }
}
