import Foundation

/// Pure validation used by the native peer. Kept free of native handles so the
/// fail-closed rules can be exercised without loading a dylib.
enum NativeWebRTCPeerValidation {
    /// The bridge compares the pinned PEM byte-for-byte against the negotiated
    /// leaf certificate. Reject anything that cannot be an exact canonical PEM
    /// leaf so a caller cannot pin a prefix, a chain, or a NUL-truncated value.
    static func isCanonicalCertificatePEM(_ value: Data) -> Bool {
        let begin = Array("-----BEGIN CERTIFICATE-----\n".utf8)
        let end = Array("-----END CERTIFICATE-----\n".utf8)
        let bytes = Array(value)
        guard bytes.count > begin.count + end.count,
              bytes.count <= NativeWebRTCContract.maximumCertificatePEMBytes,
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

    static func constantTimeEqual(_ first: Data, _ second: Data) -> Bool {
        guard first.count == second.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(first, second) {
            difference |= left ^ right
        }
        return difference == 0
    }

    static func isValidSDP(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard bytes.count >= 3,
              bytes.count <= NativeWebRTCContract.maximumSDPBytes,
              Array(bytes.prefix(3)) == Array("v=0".utf8)
        else { return false }
        return bytes.allSatisfy { $0 < 0x80 && $0 != 0 }
    }

    static func isValidICECandidate(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty,
              bytes.count <= NativeWebRTCContract.maximumICECandidateBytes,
              bytes.allSatisfy({ $0 < 0x80 && $0 != 0 })
        else { return false }
        return bytes.contains { $0 > 0x20 }
    }

    /// The bridge accepts a zero-length data message and queues it on receive;
    /// only the upper bound is enforced. Do not translate an empty message into
    /// a bounds failure.
    static func acceptsProductMessageLength(_ count: Int) -> Bool {
        count >= 0 && count <= NativeWebRTCContract.maximumMessageBytes
    }

    static func verifiedChannelValidityError(
        status: NativeWebRTCStatus,
        valid: UInt32
    ) -> NativeWebRTCError? {
        guard status == .ok else {
            return .nativeFailure(
                operation: "read verified channel validity", status: status)
        }
        return valid == 1 ? nil : .verifiedChannelInvalid
    }

    static func verifiedChannelGenerationError(
        channelStatus: NativeWebRTCStatus,
        channelGeneration: UInt32,
        peerStatus: NativeWebRTCStatus,
        peerGeneration: UInt32
    ) -> NativeWebRTCError? {
        guard channelStatus == .ok else {
            return .nativeFailure(
                operation: "read verified channel generation", status: channelStatus)
        }
        guard peerStatus == .ok else {
            return .nativeFailure(
                operation: "read peer generation", status: peerStatus)
        }
        guard peerGeneration != 0 else {
            return .invalidHandle("read peer generation")
        }
        guard channelGeneration == peerGeneration else {
            return .generationMismatch(
                channel: channelGeneration, peer: peerGeneration)
        }
        return nil
    }
}

/// Owns one initialized native engine and the loaded library for its lifetime.
///
/// `close` is explicit and idempotent. If the native drain cannot prove
/// quiescence the loaded code is retained until process exit rather than
/// `dlclose`d under possible callbacks.
public final class NativeWebRTCEngine: @unchecked Sendable {
    private enum PeerTokenState {
        case active
        case orphaned
    }

    let module: NativeWebRTCModule

    private let lock = NSLock()
    private var handle: OpaquePointer?
    private var peerTokens: [OpaquePointer: PeerTokenState] = [:]
    private var unprovenTeardownStatus: NativeWebRTCStatus?

    init(module: NativeWebRTCModule) throws {
        self.module = module

        var nativeHandle: OpaquePointer?
        let status = module.symbols.engineInit(&nativeHandle)
        guard status == NativeWebRTCStatus.ok.rawValue, let nativeHandle else {
            if let nativeHandle {
                let shutdown = NativeWebRTCStatus.from(
                    module.symbols.engineShutdown(nativeHandle))
                if !NativeWebRTCValidation.isProvenQuiescence(shutdown) {
                    module.retainLibraryUntilProcessExit()
                }
            }
            let mapped = status == NativeWebRTCStatus.ok.rawValue
                ? NativeWebRTCStatus.internalError
                : NativeWebRTCStatus.from(status)
            throw NativeWebRTCError.nativeFailure(
                operation: "initialize engine", status: mapped)
        }
        self.handle = nativeHandle
    }

    public var isOpen: Bool {
        lock.lock()
        defer { lock.unlock() }
        return handle != nil
    }

    /// Number of native peer tokens this engine still owns. A token remains
    /// tracked after a failed peer drain until an active peer retires it or
    /// engine close performs bounded orphan retirement.
    public var livePeerCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return peerTokens.count
    }

    public var hasLivePeers: Bool {
        livePeerCount != 0
    }

    public var activePeerCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return peerTokens.values.filter { $0 == .active }.count
    }

    public var orphanedPeerCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return peerTokens.values.filter { $0 == .orphaned }.count
    }

    /// True after `hs_engine_shutdown` returned an unproven barrier. The engine
    /// token is already retired, the loaded image is retained, and later
    /// `close` calls keep reporting the unproven status rather than OK.
    public var hasUnprovenTeardown: Bool {
        lock.lock()
        defer { lock.unlock() }
        return unprovenTeardownStatus != nil
    }

    public func createPeer() throws -> NativeObservationPeer {
        lock.lock()
        defer { lock.unlock() }

        guard let handle else { throw NativeWebRTCError.closed }

        var nativePeer: OpaquePointer?
        let status = module.symbols.peerCreate(handle, &nativePeer)
        guard status == NativeWebRTCStatus.ok.rawValue else {
            if let nativePeer {
                let drain = NativeWebRTCStatus.from(
                    module.symbols.peerDrain(nativePeer, 5_000))
                if !NativeWebRTCTeardown.peerRetired(drain) {
                    module.retainLibraryUntilProcessExit()
                }
            }
            throw NativeWebRTCError.nativeFailure(
                operation: "create peer", status: NativeWebRTCStatus.from(status))
        }
        guard let nativePeer else {
            throw NativeWebRTCError.invalidHandle("create peer")
        }
        peerTokens[nativePeer] = .active
        return NativeObservationPeer(engine: self, handle: nativePeer)
    }

    /// Called by a peer only after its drain barrier is proven. An unproven
    /// peer continues to count as live, so the engine refuses shutdown.
    func peerDidRetire(_ peer: OpaquePointer) {
        lock.lock()
        peerTokens.removeValue(forKey: peer)
        lock.unlock()
    }

    /// Called after a peer object has fully deinitialized with an unproven
    /// drain. No peer object can call the native token anymore, so engine close
    /// may safely retry and eventually retire this orphan without racing an
    /// active handle.
    func peerDidOrphan(_ peer: OpaquePointer) {
        lock.lock()
        if peerTokens[peer] == .active {
            peerTokens[peer] = .orphaned
        }
        lock.unlock()
    }

    /// Bounded orphan retirement. Every orphan gets at most
    /// `maximumOrphanDrainAttempts` retries inside one close, with the caller's
    /// timeout divided across all planned attempts. A token that remains
    /// unproven after the bound is released from engine tracking, but the image
    /// is retained and the unproven status is reported: quiescence is never
    /// inferred from exhaustion.
    private func retryOrphanedPeersLocked(
        timeoutMilliseconds: UInt32
    ) -> (lastUnproven: NativeWebRTCStatus?, releasedUnproven: Bool) {
        let orphans = peerTokens.compactMap { token, state in
            state == .orphaned ? token : nil
        }
        guard !orphans.isEmpty else { return (nil, false) }

        let maximumAttempts = max(
            1, NativeWebRTCTeardown.maximumOrphanDrainAttempts)
        let plannedAttempts = UInt32(orphans.count) * maximumAttempts
        let perAttemptTimeout = NativeWebRTCTeardown.orphanAttemptTimeout(
            totalMilliseconds: timeoutMilliseconds,
            attemptCount: Int(plannedAttempts)
        )

        var lastUnproven: NativeWebRTCStatus?
        var releasedUnproven = false

        for token in orphans {
            var retired = false
            for attempt in 1...maximumAttempts {
                let status = NativeWebRTCStatus.from(
                    module.symbols.peerDrain(token, perAttemptTimeout))
                switch NativeWebRTCTeardown.orphanAttemptOutcome(
                    status: status,
                    attempt: attempt,
                    maximumAttempts: maximumAttempts)
                {
                case .retired:
                    peerTokens.removeValue(forKey: token)
                    retired = true
                case .retry:
                    lastUnproven = status
                case .releaseUnproven:
                    peerTokens.removeValue(forKey: token)
                    lastUnproven = status
                    releasedUnproven = true
                    retired = true
                }
                if retired { break }
            }
        }
        return (lastUnproven, releasedUnproven)
    }

    /// Drain and shut down the engine. Refuses with `.state` while an active
    /// peer object still owns a token. Tokens orphaned by a peer deinit are
    /// retried a bounded number of times, then their ownership is relinquished
    /// without inventing quiescence: the loaded image is retained and the
    /// unproven status is reported. Once shutdown is attempted, the engine
    /// token is retired by the bridge, but an unproven drain or shutdown keeps
    /// the image mapped and is reported on every later close.
    @discardableResult
    public func close(timeoutMilliseconds: UInt32 = 5_000) -> NativeWebRTCStatus {
        lock.lock()
        defer { lock.unlock() }

        if let unprovenTeardownStatus {
            return unprovenTeardownStatus
        }
        guard let handle else { return .ok }

        // Never touch an active peer's native token; its owner must close it.
        if peerTokens.values.contains(where: { $0 == .active }) {
            return .state
        }

        let orphanResult = retryOrphanedPeersLocked(
            timeoutMilliseconds: timeoutMilliseconds)
        guard NativeWebRTCTeardown.engineMayShutDown(
            livePeers: peerTokens.count)
        else {
            // Defensive fallback: a token survived bounded retirement. Keep the
            // engine open for a later retry and never unload under it.
            module.retainLibraryUntilProcessExit()
            return orphanResult.lastUnproven ?? .timeout
        }
        self.handle = nil

        let drain = NativeWebRTCStatus.from(
            module.symbols.engineDrain(handle, timeoutMilliseconds))
        let shutdown = NativeWebRTCStatus.from(
            module.symbols.engineShutdown(handle))
        let result = NativeWebRTCTeardown.engineTeardown(
            drain: drain, shutdown: shutdown)

        var retired = result.retired
        var reported = result.reported
        if orphanResult.releasedUnproven {
            // An orphan was abandoned without proof. Even if shutdown later
            // reports OK, keep the code mapped and report the unproven state.
            retired = false
            reported = orphanResult.lastUnproven ?? .timeout
        }
        if !retired {
            unprovenTeardownStatus = reported
            module.retainLibraryUntilProcessExit()
        }
        return reported
    }

    deinit {
        let status = close()
        // A deinit cannot ask the caller to close live peers. Retain the image
        // and leave native ownership to the bridge rather than shutting down
        // under an active/unproven peer.
        if status == .state || isOpen {
            module.retainLibraryUntilProcessExit()
        }
    }
}

/// One owned native peer with a verified-channel pin and safe teardown.
///
/// The only public pin entry point accepts `VerifiedObservationEndpointChallenge`,
/// whose initializer is not available to app code. This type stores and
/// compares that exact PEM; it does not verify signatures, grants, or the SDP
/// fingerprint itself.
///
/// The verified `hs_verified_channel` handle is held for the connection's
/// lifetime because the native send/poll paths require the peer's current
/// verified binding. It is released by `close`.
///
/// SDP creation and remote-description calls may block for up to the bridge's
/// ten-second signaling wait. Do not call them on the main thread.
public final class NativeObservationPeer: @unchecked Sendable {
    private enum Lifecycle {
        case open
        case closing
        case closed
    }

    private let engine: NativeWebRTCEngine
    private let lock = NSLock()
    private var peer: OpaquePointer?
    private var verifiedChannel: OpaquePointer?
    private var pinnedCertificate: Data?
    private var evidence: NativeWebRTCConnectionEvidence?
    private var productChannelCreated = false
    private var offerCreated = false
    private var lifecycle = Lifecycle.open

    init(engine: NativeWebRTCEngine, handle: OpaquePointer) {
        self.engine = engine
        self.peer = handle
    }

    private var module: NativeWebRTCModule { engine.module }

    public var isOpen: Bool {
        lock.lock()
        defer { lock.unlock() }
        return lifecycle == .open && peer != nil
    }

    /// True while a failed `hs_peer_drain` still owns the native peer. All
    /// operations other than `close` are refused in this state; `close` retries
    /// the drain until `OK` or `NULL` proves retirement.
    public var requiresDrainRetry: Bool {
        lock.lock()
        defer { lock.unlock() }
        return lifecycle == .closing && peer != nil
    }

    /// Pin the exact endpoint DTLS leaf certificate from a verified challenge.
    public func pinRemoteCertificate(
        from challenge: VerifiedObservationEndpointChallenge
    ) throws {
        try pinRemoteCertificate(challenge.endpointCertificatePEM)
    }

    /// Pin the exact endpoint DTLS leaf certificate PEM.
    ///
    /// Internal because the only valid public source is a verified challenge;
    /// accepting arbitrary PEMs from app code would create an unverified pin.
    /// The bridge rejects a mismatch at verified-channel acquisition. This
    /// wrapper checks the exported certificate again before exposing evidence,
    /// so a stale or mismatched bridge result cannot bypass the pin.
    func pinRemoteCertificate(_ certificatePEM: Data) throws {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()
        guard NativeWebRTCPeerValidation.isCanonicalCertificatePEM(certificatePEM) else {
            throw NativeWebRTCError.certificatePinInvalid
        }

        let status = certificatePEM.withUnsafeBytes { raw -> UInt32 in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: CChar.self) else {
                return NativeWebRTCStatus.null.rawValue
            }
            return module.symbols.setExpectedCertificate(
                peer, base, certificatePEM.count)
        }
        guard status == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "pin endpoint certificate",
                status: NativeWebRTCStatus.from(status))
        }

        // A successful pin replacement invalidates the native verified handle.
        releaseVerifiedChannelLocked()
        pinnedCertificate = certificatePEM
    }

    /// Create the fixed `hs-product` channel that the offer advertises.
    /// Must happen before `createOffer`.
    public func createProductChannel() throws {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()
        guard pinnedCertificate != nil else {
            throw NativeWebRTCError.certificatePinRequired
        }
        guard !productChannelCreated else {
            throw NativeWebRTCError.invalidState("product channel already created")
        }
        guard !offerCreated else {
            throw NativeWebRTCError.invalidState("offer already created")
        }

        let label = NativeWebRTCContract.productChannelLabel
        let status = label.withCString { pointer in
            module.symbols.channelCreate(peer, pointer, label.utf8.count)
        }
        guard status == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "create product channel",
                status: NativeWebRTCStatus.from(status))
        }
        productChannelCreated = true
    }

    /// Create and set the local offer. A pin is mandatory: the Manager must not
    /// advertise a DTLS identity before it knows which endpoint certificate it
    /// will accept.
    public func createOffer() throws -> String {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()
        guard pinnedCertificate != nil else {
            throw NativeWebRTCError.certificatePinRequired
        }
        guard productChannelCreated else {
            throw NativeWebRTCError.invalidState("product channel not created")
        }
        guard !offerCreated else {
            throw NativeWebRTCError.invalidState("offer already created")
        }

        var buffer = [CChar](
            repeating: 0, count: NativeWebRTCContract.maximumSDPBytes + 1)
        var length = 0
        let status = buffer.withUnsafeMutableBufferPointer { pointer in
            withUnsafeMutablePointer(to: &length) { lengthPointer in
                module.symbols.createOffer(
                    peer, pointer.baseAddress, pointer.count, lengthPointer)
            }
        }
        guard status == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "create offer", status: NativeWebRTCStatus.from(status))
        }
        let sdp = try decodeText(
            buffer,
            length: length,
            maximumBytes: NativeWebRTCContract.maximumSDPBytes,
            operation: "offer"
        )
        guard NativeWebRTCPeerValidation.isValidSDP(sdp) else {
            throw NativeWebRTCError.bounds("offer")
        }
        offerCreated = true
        return sdp
    }

    /// Set the endpoint's answer SDP after the offer has been published.
    public func setRemoteAnswer(_ sdp: String) throws {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()
        guard pinnedCertificate != nil else {
            throw NativeWebRTCError.certificatePinRequired
        }
        guard offerCreated else {
            throw NativeWebRTCError.invalidState("offer not created")
        }
        guard NativeWebRTCPeerValidation.isValidSDP(sdp) else {
            throw NativeWebRTCError.bounds("remote answer")
        }

        let type = "answer"
        let status = type.withCString { typePointer in
            sdp.withCString { sdpPointer in
                module.symbols.setRemoteDescription(
                    peer,
                    typePointer,
                    type.utf8.count,
                    sdpPointer,
                    sdp.utf8.count
                )
            }
        }
        guard status == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "set remote answer",
                status: NativeWebRTCStatus.from(status))
        }
    }

    public func addRemoteICECandidate(_ candidate: String) throws {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()
        guard NativeWebRTCPeerValidation.isValidICECandidate(candidate) else {
            throw NativeWebRTCError.bounds("remote ICE candidate")
        }

        let status = candidate.withCString { pointer in
            module.symbols.addIceCandidate(
                peer, pointer, candidate.utf8.count)
        }
        guard status == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "add remote ICE candidate",
                status: NativeWebRTCStatus.from(status))
        }
    }

    /// Pop one locally gathered candidate. `nil` means the queue is empty and
    /// gathering is not complete (`timeout`) or gathering is complete
    /// (`exhausted`). A `bounds` result is a native overflow and is surfaced.
    public func pollLocalICECandidate() throws -> String? {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()

        var buffer = [CChar](
            repeating: 0,
            count: NativeWebRTCContract.maximumICECandidateBytes + 1)
        var length = 0
        let status = buffer.withUnsafeMutableBufferPointer { pointer in
            withUnsafeMutablePointer(to: &length) { lengthPointer in
                module.symbols.pollIceCandidate(
                    peer, pointer.baseAddress, pointer.count, lengthPointer)
            }
        }

        let mapped = NativeWebRTCStatus.from(status)
        if mapped == .timeout || mapped == .exhausted {
            return nil
        }
        guard mapped == .ok else {
            throw NativeWebRTCError.nativeFailure(
                operation: "poll local ICE candidate", status: mapped)
        }
        return try decodeText(
            buffer,
            length: length,
            maximumBytes: NativeWebRTCContract.maximumICECandidateBytes,
            operation: "ICE candidate"
        )
    }

    public func state() throws -> NativeWebRTCPeerState {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()
        var rawState: UInt32 = 0
        let status = module.symbols.peerState(peer, &rawState)
        guard status == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "read peer state", status: NativeWebRTCStatus.from(status))
        }
        guard let state = NativeWebRTCPeerState(rawValue: rawState) else {
            throw NativeWebRTCError.invalidPeerState(rawState)
        }
        return state
    }

    public func generation() throws -> UInt32 {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()
        var generation: UInt32 = 0
        let status = module.symbols.peerGeneration(peer, &generation)
        guard status == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "read peer generation",
                status: NativeWebRTCStatus.from(status))
        }
        guard generation != 0 else {
            throw NativeWebRTCError.invalidHandle("read peer generation")
        }
        return generation
    }

    public func exportLocalCertificatePEM() throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()
        var buffer = [UInt8](
            repeating: 0,
            count: NativeWebRTCContract.maximumCertificatePEMBytes)
        var length: UInt32 = 0
        let status = buffer.withUnsafeMutableBufferPointer { pointer in
            module.symbols.localCertificateExport(
                peer, pointer.baseAddress, UInt32(pointer.count), &length)
        }
        guard status == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "export local certificate",
                status: NativeWebRTCStatus.from(status))
        }
        guard length > 0,
              Int(length) <= buffer.count,
              !buffer[0..<Int(length)].contains(0)
        else {
            throw NativeWebRTCError.bounds("local certificate")
        }
        return Data(buffer[0..<Int(length)])
    }

    /// Acquire the native verified channel and prove the negotiated DTLS leaf
    /// equals the pinned endpoint certificate. Evidence is exposed only after
    /// the pin, generation, and canonical channel binding all check out.
    ///
    /// The acquired handle is retained for send/poll. Calling this again
    /// replaces and re-verifies it.
    @discardableResult
    public func verifyConnectedPeer() throws -> NativeWebRTCConnectionEvidence {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()
        guard let pinnedCertificate = self.pinnedCertificate else {
            throw NativeWebRTCError.certificatePinRequired
        }

        let state = try readPeerStateLocked(peer)
        guard state == .connected || state == .channelOpen else {
            throw NativeWebRTCError.peerNotConnected
        }

        var acquiredChannel: OpaquePointer?
        let acquireStatus = module.symbols.verifiedChannelAcquire(
            peer, &acquiredChannel)
        guard acquireStatus == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "acquire verified channel",
                status: NativeWebRTCStatus.from(acquireStatus))
        }
        guard let acquiredChannel else {
            throw NativeWebRTCError.invalidHandle("acquire verified channel")
        }

        do {
            let negotiatedCertificate = try exportVerifiedCertificate(
                acquiredChannel)
            guard NativeWebRTCPeerValidation.constantTimeEqual(
                negotiatedCertificate, pinnedCertificate)
            else {
                throw NativeWebRTCError.certificatePinMismatch
            }

            var valid: UInt32 = 0
            let validityStatus = module.symbols.verifiedChannelValid(
                acquiredChannel, &valid)
            if let error = NativeWebRTCPeerValidation.verifiedChannelValidityError(
                status: NativeWebRTCStatus.from(validityStatus), valid: valid)
            {
                throw error
            }

            var channelGeneration: UInt32 = 0
            let channelGenerationStatus = module.symbols.verifiedChannelGeneration(
                acquiredChannel, &channelGeneration)
            var peerGeneration: UInt32 = 0
            let peerGenerationStatus = module.symbols.peerGeneration(
                peer, &peerGeneration)
            if let error = NativeWebRTCPeerValidation.verifiedChannelGenerationError(
                channelStatus: NativeWebRTCStatus.from(channelGenerationStatus),
                channelGeneration: channelGeneration,
                peerStatus: NativeWebRTCStatus.from(peerGenerationStatus),
                peerGeneration: peerGeneration)
            {
                throw error
            }

            let binding = try exportVerifiedBinding(acquiredChannel)
            guard let bindingHex =
                ObservationAdmissionGrantVerifier.canonicalChannelBindingHex(binding)
            else {
                throw NativeWebRTCError.invalidChannelBinding
            }

            if let previous = verifiedChannel, previous != acquiredChannel {
                _ = module.symbols.verifiedChannelRelease(previous)
            }
            verifiedChannel = acquiredChannel

            let verified = NativeWebRTCConnectionEvidence(
                remoteCertificatePEM: negotiatedCertificate,
                channelBinding: binding,
                channelBindingHex: bindingHex,
                generation: peerGeneration
            )
            evidence = verified
            return verified
        } catch {
            _ = module.symbols.verifiedChannelRelease(acquiredChannel)
            releaseVerifiedChannelLocked()
            throw error
        }
    }

    /// Current evidence, rechecked against the live native channel. A replaced
    /// certificate, closed channel, or failed DTLS transport clears it.
    public func currentEvidence() -> NativeWebRTCConnectionEvidence? {
        lock.lock()
        defer { lock.unlock() }

        guard lifecycle == .open, let channel = verifiedChannel,
              let evidence = self.evidence
        else { return nil }

        var valid: UInt32 = 0
        let status = module.symbols.verifiedChannelValid(channel, &valid)
        guard status == NativeWebRTCStatus.ok.rawValue, valid == 1 else {
            releaseVerifiedChannelLocked()
            return nil
        }
        return evidence
    }

    public var isVerified: Bool {
        currentEvidence() != nil
    }

    public func sendProductMessage(_ message: Data) throws {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()
        guard evidence != nil, verifiedChannel != nil else {
            throw NativeWebRTCError.notVerified
        }
        guard NativeWebRTCPeerValidation.acceptsProductMessageLength(
            message.count)
        else {
            throw NativeWebRTCError.bounds("product message")
        }

        let status: UInt32
        if message.isEmpty {
            // hs_channel_send accepts a zero-length datagram but rejects a null
            // data pointer. Pass a valid sentinel, not an invented bounds error.
            var sentinel: UInt8 = 0
            status = withUnsafePointer(to: &sentinel) { pointer in
                module.symbols.channelSend(peer, pointer, 0)
            }
        } else {
            status = message.withUnsafeBytes { raw -> UInt32 in
                guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
                else {
                    return NativeWebRTCStatus.null.rawValue
                }
                return module.symbols.channelSend(
                    peer, base, UInt32(message.count))
            }
        }
        let mapped = NativeWebRTCStatus.from(status)
        guard mapped == .ok else {
            if mapped == .handshake || mapped == .state {
                releaseVerifiedChannelLocked()
            }
            throw NativeWebRTCError.nativeFailure(
                operation: "send product message", status: mapped)
        }
    }

    /// Pop one product message. `nil` means the queue is empty. Messages are
    /// accepted only while the verified channel is current.
    public func pollProductMessage() throws -> Data? {
        lock.lock()
        defer { lock.unlock() }

        let peer = try requirePeerLocked()
        guard evidence != nil, verifiedChannel != nil else {
            throw NativeWebRTCError.notVerified
        }

        var buffer = [UInt8](
            repeating: 0, count: NativeWebRTCContract.maximumMessageBytes)
        var length: UInt32 = 0
        let status = buffer.withUnsafeMutableBufferPointer { pointer in
            module.symbols.channelPoll(
                peer, pointer.baseAddress, UInt32(pointer.count), &length)
        }

        let mapped = NativeWebRTCStatus.from(status)
        if mapped == .timeout || mapped == .exhausted {
            return nil
        }
        guard mapped == .ok else {
            if mapped == .handshake || mapped == .state {
                releaseVerifiedChannelLocked()
            }
            throw NativeWebRTCError.nativeFailure(
                operation: "poll product message", status: mapped)
        }
        // The bridge queues and returns zero-length messages as OK with len 0.
        // Empty is a valid datagram, not a bounds failure.
        guard Int(length) <= buffer.count,
              NativeWebRTCPeerValidation.acceptsProductMessageLength(Int(length))
        else {
            throw NativeWebRTCError.bounds("product message")
        }
        return Data(buffer[0..<Int(length)])
    }

    /// Close and drain this peer. The engine remains owned by its caller and
    /// should be closed after all peers are retired.
    ///
    /// A drain timeout RETURNS `.timeout` and retains peer/observer ownership.
    /// The handle is not dropped and a later `close` retries `hs_peer_drain`.
    /// `requiresDrainRetry` reports that state; only `OK` or `NULL` retires it.
    @discardableResult
    public func close(timeoutMilliseconds: UInt32 = 5_000) -> NativeWebRTCStatus {
        lock.lock()
        defer { lock.unlock() }
        return tearDownLocked(timeoutMilliseconds: timeoutMilliseconds)
    }

    deinit {
        _ = close()
        // If the final drain was unproven, the peer object is about to vanish.
        // Hand the native token to the engine so a later engine close can
        // perform bounded drain retries instead of being blocked by an
        // unreachable active token.
        lock.lock()
        let orphanToken = lifecycle == .closing ? peer : nil
        lock.unlock()
        if let orphanToken {
            engine.peerDidOrphan(orphanToken)
        }
    }

    // MARK: - Locked helpers

    private func requirePeerLocked() throws -> OpaquePointer {
        guard lifecycle != .closed else {
            throw NativeWebRTCError.closed
        }
        guard lifecycle == .open, let peer else {
            throw NativeWebRTCError.teardownUnproven
        }
        return peer
    }

    private func readPeerStateLocked(
        _ peer: OpaquePointer
    ) throws -> NativeWebRTCPeerState {
        var rawState: UInt32 = 0
        let status = module.symbols.peerState(peer, &rawState)
        guard status == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "read peer state",
                status: NativeWebRTCStatus.from(status))
        }
        guard let state = NativeWebRTCPeerState(rawValue: rawState) else {
            throw NativeWebRTCError.invalidPeerState(rawState)
        }
        return state
    }

    private func exportVerifiedCertificate(
        _ channel: OpaquePointer
    ) throws -> Data {
        var buffer = [UInt8](
            repeating: 0,
            count: NativeWebRTCContract.maximumCertificatePEMBytes)
        var length: UInt32 = 0
        let status = buffer.withUnsafeMutableBufferPointer { pointer in
            module.symbols.verifiedChannelExport(
                channel, pointer.baseAddress, UInt32(pointer.count), &length)
        }
        guard status == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "export verified certificate",
                status: NativeWebRTCStatus.from(status))
        }
        guard length > 0,
              Int(length) <= buffer.count,
              !buffer[0..<Int(length)].contains(0)
        else {
            throw NativeWebRTCError.bounds("verified certificate")
        }
        return Data(buffer[0..<Int(length)])
    }

    private func exportVerifiedBinding(
        _ channel: OpaquePointer
    ) throws -> Data {
        var buffer = [UInt8](
            repeating: 0,
            count: NativeWebRTCContract.maximumChannelBindingBytes)
        var length: UInt32 = 0
        let status = buffer.withUnsafeMutableBufferPointer { pointer in
            module.symbols.verifiedChannelBindingExport(
                channel, pointer.baseAddress, UInt32(pointer.count), &length)
        }
        guard status == NativeWebRTCStatus.ok.rawValue else {
            throw NativeWebRTCError.nativeFailure(
                operation: "export verified channel binding",
                status: NativeWebRTCStatus.from(status))
        }
        guard length > 0, Int(length) <= buffer.count else {
            throw NativeWebRTCError.bounds("verified channel binding")
        }
        return Data(buffer[0..<Int(length)])
    }

    private func decodeText(
        _ buffer: [CChar],
        length: Int,
        maximumBytes: Int,
        operation: String
    ) throws -> String {
        guard length > 0,
              length <= maximumBytes,
              length < buffer.count,
              buffer[length] == 0,
              !buffer[0..<length].contains(0)
        else {
            throw NativeWebRTCError.bounds(operation)
        }
        let bytes = buffer[0..<length].map { UInt8(bitPattern: $0) }
        guard bytes.allSatisfy({ $0 < 0x80 }) else {
            throw NativeWebRTCError.bounds(operation)
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private func releaseVerifiedChannelLocked() {
        if let verifiedChannel {
            _ = module.symbols.verifiedChannelRelease(verifiedChannel)
        }
        verifiedChannel = nil
        evidence = nil
    }

    private func tearDownLocked(timeoutMilliseconds: UInt32) -> NativeWebRTCStatus {
        guard lifecycle != .closed else { return .ok }
        guard let peer = self.peer else {
            lifecycle = .closed
            return .ok
        }

        if lifecycle == .open {
            lifecycle = .closing
            releaseVerifiedChannelLocked()
            _ = module.symbols.channelClose(peer)
            _ = module.symbols.peerClose(peer)
        }

        // Retry is valid and required after a timeout: hs_peer_drain retains
        // peer/observer ownership until a later proven barrier.
        let drainStatus = NativeWebRTCStatus.from(
            module.symbols.peerDrain(peer, timeoutMilliseconds))
        if NativeWebRTCTeardown.peerRetired(drainStatus) {
            engine.peerDidRetire(peer)
            self.peer = nil
            lifecycle = .closed
        } else {
            // Keep the handle for retry and keep the engine's peer count live
            // so engine shutdown is refused. Never dlclose under observers.
            lifecycle = .closing
            module.retainLibraryUntilProcessExit()
        }
        return drainStatus
    }
}
