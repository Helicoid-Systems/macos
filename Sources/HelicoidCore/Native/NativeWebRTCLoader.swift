import Darwin
import Foundation

/// Native status codes from the E01 ABI-3 bridge (`native/hs_webrtc.h`).
///
/// The values are part of the load contract. They are declared here instead of
/// linking the C header so the macOS app has no compile-time dependency on the
/// bundled bridge and cannot accidentally bind to a host-provided library.
public enum NativeWebRTCStatus: UInt32, Sendable, Equatable {
    case ok = 0
    case invalid = 1
    case null = 2
    case state = 3
    case panic = 4
    case exhausted = 5
    case unavailable = 6
    case internalError = 7
    case bounds = 8
    case timeout = 9
    case handshake = 10

    static func from(_ raw: UInt32) -> NativeWebRTCStatus {
        NativeWebRTCStatus(rawValue: raw) ?? .internalError
    }
}

/// Public constants mirrored from the generated E01 ABI-3 header.
///
/// Only connection-level primitives are wrapped on macOS today. Capture,
/// admission, and media bits are reported exactly as the library reports them;
/// this code never synthesizes a capability or a preview.
public enum NativeWebRTCContract {
    public static let abiVersion: UInt32 = 3

    public static let initializationCapability: UInt32 = 0x1
    public static let negotiationCapability: UInt32 = 0x2
    public static let channelEvidenceCapability: UInt32 = 0x4
    public static let drainCapability: UInt32 = 0x8
    public static let captureCapability: UInt32 = 0x10
    public static let admissionCapability: UInt32 = 0x20
    public static let mediaCapability: UInt32 = 0x40

    public static let requiredConnectionCapabilities: UInt32 =
        initializationCapability | negotiationCapability |
        channelEvidenceCapability | drainCapability

    public static let requiredObservationCapabilities: UInt32 =
        requiredConnectionCapabilities | captureCapability |
        admissionCapability | mediaCapability

    public static let maximumSDPBytes = 65_536
    public static let maximumMessageBytes = 4_096
    public static let maximumCertificatePEMBytes = 8_192
    public static let maximumChannelBindingBytes = 128
    public static let maximumICECandidateBytes = 4_096
    public static let maximumLibraryBytes: Int64 = 1_073_741_824

    /// The only data-channel label the bridge accepts.
    public static let productChannelLabel = "hs-product"

    /// The only library location the macOS loader will consider.
    public static let bundledLibraryName = "libhs_webrtc_shared.dylib"
}

public enum NativeWebRTCError: Error, Equatable, Sendable, CustomStringConvertible {
    case bundleUnavailable
    case libraryMissing(String)
    case libraryNotRegularFile(String)
    case libraryOutsideBundle(String)
    case libraryOpenFailed(String)
    case missingSymbol(String)
    case abiMismatch(expected: UInt32, actual: UInt32)
    case capabilityQueryFailed(NativeWebRTCStatus)
    case requiredCapabilitiesMissing(missing: UInt32)
    case invalidHandle(String)
    case closed
    case teardownUnproven
    case certificatePinRequired
    case certificatePinInvalid
    case certificatePinMismatch
    case peerNotConnected
    case notVerified
    case invalidState(String)
    case invalidPeerState(UInt32)
    case verifiedChannelInvalid
    case generationMismatch(channel: UInt32, peer: UInt32)
    case invalidChannelBinding
    case bounds(String)
    case nativeFailure(operation: String, status: NativeWebRTCStatus)

    public var description: String {
        switch self {
        case .bundleUnavailable:
            "The WebRTC bridge can only be loaded from a macOS application bundle."
        case .libraryMissing(let path):
            "The bundled WebRTC library is missing at \(path)."
        case .libraryNotRegularFile(let path):
            "The bundled WebRTC path is not a regular file: \(path)."
        case .libraryOutsideBundle(let path):
            "The WebRTC library resolved outside Contents/Frameworks: \(path)."
        case .libraryOpenFailed(let detail):
            "The bundled WebRTC library could not be opened: \(detail)."
        case .missingSymbol(let name):
            "The bundled WebRTC library does not export \(name)."
        case .abiMismatch(let expected, let actual):
            "The bundled WebRTC bridge ABI is \(actual); this app requires \(expected)."
        case .capabilityQueryFailed(let status):
            "The bundled WebRTC bridge could not report capabilities (status \(status.rawValue))."
        case .requiredCapabilitiesMissing(let missing):
            "The bundled WebRTC bridge is missing required connection capabilities 0x\(String(missing, radix: 16))."
        case .invalidHandle(let operation):
            "The bundled WebRTC bridge returned no handle for \(operation)."
        case .closed:
            "The native WebRTC handle is closed."
        case .teardownUnproven:
            "The native WebRTC peer still owns observers after an unproven drain; close must retry."
        case .certificatePinRequired:
            "A verified endpoint certificate pin is required before this WebRTC operation."
        case .certificatePinInvalid:
            "The endpoint certificate pin is not a canonical bounded PEM value."
        case .certificatePinMismatch:
            "The negotiated DTLS certificate does not match the verified endpoint certificate pin."
        case .peerNotConnected:
            "The native WebRTC peer has not reached a connected transport state."
        case .notVerified:
            "The native WebRTC peer has no current verified-channel evidence."
        case .invalidState(let detail):
            "The native WebRTC peer is not in a state that permits this operation: \(detail)."
        case .invalidPeerState(let state):
            "The bundled WebRTC bridge returned unknown peer state \(state)."
        case .verifiedChannelInvalid:
            "The native verified channel is no longer valid for the connected peer."
        case .generationMismatch(let channel, let peer):
            "The native verified channel generation \(channel) does not match peer generation \(peer)."
        case .invalidChannelBinding:
            "The native channel binding is not the canonical hs-product binding."
        case .bounds(let operation):
            "The native WebRTC value for \(operation) exceeded its bounds."
        case .nativeFailure(let operation, let status):
            "Native WebRTC could not \(operation) (status \(status.rawValue))."
        }
    }
}

/// Peer lifecycle values from the E01 ABI.
public enum NativeWebRTCPeerState: UInt32, Sendable, Equatable {
    case new = 0
    case connected = 1
    case channelOpen = 2
    case closing = 3
    case closed = 4
    case failed = 5
}

/// Exact peer identity exported only after the native bridge has a connected
/// DTLS transport, an open `hs-product` channel, and a matching certificate pin.
///
/// `channelBindingHex` is the canonical ABI binding used by the observation
/// grant proof. This value is evidence from the native bridge, not a grant and
/// not admission authority.
public struct NativeWebRTCConnectionEvidence: Sendable, Equatable {
    public let remoteCertificatePEM: Data
    public let channelBinding: Data
    public let channelBindingHex: String
    public let generation: UInt32
}

// MARK: - Dynamic symbol table

typealias AbiVersionFunction = @convention(c) () -> UInt32
typealias EngineVersionFunction = @convention(c) () -> UnsafePointer<CChar>?
typealias CapabilitiesFunction =
    @convention(c) (UnsafeMutablePointer<UInt32>?) -> UInt32
typealias EngineInitFunction =
    @convention(c) (UnsafeMutablePointer<OpaquePointer?>?) -> UInt32
typealias EngineShutdownFunction = @convention(c) (OpaquePointer?) -> UInt32
typealias EngineDrainFunction = @convention(c) (OpaquePointer?, UInt32) -> UInt32
typealias PeerCreateFunction =
    @convention(c) (OpaquePointer?, UnsafeMutablePointer<OpaquePointer?>?) -> UInt32
typealias PeerStatusFunction = @convention(c) (OpaquePointer?) -> UInt32
typealias PeerDrainFunction = @convention(c) (OpaquePointer?, UInt32) -> UInt32
typealias PeerValueFunction =
    @convention(c) (OpaquePointer?, UnsafeMutablePointer<UInt32>?) -> UInt32
typealias CertificateExportFunction = @convention(c) (
    OpaquePointer?, UnsafeMutablePointer<UInt8>?, UInt32, UnsafeMutablePointer<UInt32>?
) -> UInt32
typealias ChannelCreateFunction =
    @convention(c) (OpaquePointer?, UnsafePointer<CChar>?, Int) -> UInt32
typealias CreateDescriptionFunction = @convention(c) (
    OpaquePointer?, UnsafeMutablePointer<CChar>?, Int, UnsafeMutablePointer<Int>?
) -> UInt32
typealias SetLocalFunction =
    @convention(c) (OpaquePointer?, UnsafePointer<CChar>?, Int) -> UInt32
typealias SetRemoteFunction = @convention(c) (
    OpaquePointer?, UnsafePointer<CChar>?, Int, UnsafePointer<CChar>?, Int
) -> UInt32
typealias AddIceFunction =
    @convention(c) (OpaquePointer?, UnsafePointer<CChar>?, Int) -> UInt32
typealias PollIceFunction = @convention(c) (
    OpaquePointer?, UnsafeMutablePointer<CChar>?, Int, UnsafeMutablePointer<Int>?
) -> UInt32
typealias ChannelSendFunction =
    @convention(c) (OpaquePointer?, UnsafePointer<UInt8>?, UInt32) -> UInt32
typealias ChannelPollFunction = @convention(c) (
    OpaquePointer?, UnsafeMutablePointer<UInt8>?, UInt32, UnsafeMutablePointer<UInt32>?
) -> UInt32
typealias SetExpectedCertificateFunction =
    @convention(c) (OpaquePointer?, UnsafePointer<CChar>?, Int) -> UInt32
typealias VerifiedChannelAcquireFunction =
    @convention(c) (OpaquePointer?, UnsafeMutablePointer<OpaquePointer?>?) -> UInt32
typealias VerifiedChannelReleaseFunction = @convention(c) (OpaquePointer?) -> UInt32

struct NativeWebRTCSymbols {
    let abiVersion: AbiVersionFunction
    let engineVersion: EngineVersionFunction
    let capabilities: CapabilitiesFunction
    let engineInit: EngineInitFunction
    let engineShutdown: EngineShutdownFunction
    let engineDrain: EngineDrainFunction
    let peerCreate: PeerCreateFunction
    let peerClose: PeerStatusFunction
    let peerFree: PeerStatusFunction
    let peerGeneration: PeerValueFunction
    let peerState: PeerValueFunction
    let localCertificateExport: CertificateExportFunction
    let channelCreate: ChannelCreateFunction
    let createOffer: CreateDescriptionFunction
    let createAnswer: CreateDescriptionFunction
    let setLocalDescription: SetLocalFunction
    let setRemoteDescription: SetRemoteFunction
    let addIceCandidate: AddIceFunction
    let pollIceCandidate: PollIceFunction
    let channelSend: ChannelSendFunction
    let channelPoll: ChannelPollFunction
    let channelClose: PeerStatusFunction
    let setExpectedCertificate: SetExpectedCertificateFunction
    let verifiedChannelAcquire: VerifiedChannelAcquireFunction
    let verifiedChannelExport: CertificateExportFunction
    let verifiedChannelBindingExport: CertificateExportFunction
    let verifiedChannelGeneration: PeerValueFunction
    let verifiedChannelValid: PeerValueFunction
    let verifiedChannelRelease: VerifiedChannelReleaseFunction
    let peerDrain: PeerDrainFunction

    static func load(from handle: UnsafeMutableRawPointer) throws -> NativeWebRTCSymbols {
        func required<T>(_ name: String, as type: T.Type) throws -> T {
            let symbol = name.withCString { dlsym(handle, $0) }
            guard let symbol else {
                throw NativeWebRTCError.missingSymbol(name)
            }
            return unsafeBitCast(symbol, to: type)
        }

        return NativeWebRTCSymbols(
            abiVersion: try required("hs_abi_version", as: AbiVersionFunction.self),
            engineVersion: try required(
                "hs_engine_version", as: EngineVersionFunction.self),
            capabilities: try required(
                "hs_engine_capabilities", as: CapabilitiesFunction.self),
            engineInit: try required("hs_engine_init", as: EngineInitFunction.self),
            engineShutdown: try required(
                "hs_engine_shutdown", as: EngineShutdownFunction.self),
            engineDrain: try required("hs_engine_drain", as: EngineDrainFunction.self),
            peerCreate: try required("hs_peer_create", as: PeerCreateFunction.self),
            peerClose: try required("hs_peer_close", as: PeerStatusFunction.self),
            peerFree: try required("hs_peer_free", as: PeerStatusFunction.self),
            peerGeneration: try required(
                "hs_peer_generation", as: PeerValueFunction.self),
            peerState: try required("hs_peer_state", as: PeerValueFunction.self),
            localCertificateExport: try required(
                "hs_peer_local_cert_export", as: CertificateExportFunction.self),
            channelCreate: try required(
                "hs_channel_create", as: ChannelCreateFunction.self),
            createOffer: try required(
                "hs_peer_create_offer", as: CreateDescriptionFunction.self),
            createAnswer: try required(
                "hs_peer_create_answer", as: CreateDescriptionFunction.self),
            setLocalDescription: try required(
                "hs_peer_set_local", as: SetLocalFunction.self),
            setRemoteDescription: try required(
                "hs_peer_set_remote", as: SetRemoteFunction.self),
            addIceCandidate: try required(
                "hs_peer_add_ice", as: AddIceFunction.self),
            pollIceCandidate: try required(
                "hs_peer_poll_ice", as: PollIceFunction.self),
            channelSend: try required("hs_channel_send", as: ChannelSendFunction.self),
            channelPoll: try required("hs_channel_poll", as: ChannelPollFunction.self),
            channelClose: try required("hs_channel_close", as: PeerStatusFunction.self),
            setExpectedCertificate: try required(
                "hs_peer_expected_cert_set", as: SetExpectedCertificateFunction.self),
            verifiedChannelAcquire: try required(
                "hs_verified_channel_acquire", as: VerifiedChannelAcquireFunction.self),
            verifiedChannelExport: try required(
                "hs_verified_channel_export", as: CertificateExportFunction.self),
            verifiedChannelBindingExport: try required(
                "hs_verified_channel_binding_export", as: CertificateExportFunction.self),
            verifiedChannelGeneration: try required(
                "hs_verified_channel_generation", as: PeerValueFunction.self),
            verifiedChannelValid: try required(
                "hs_verified_channel_valid", as: PeerValueFunction.self),
            verifiedChannelRelease: try required(
                "hs_verified_channel_release", as: VerifiedChannelReleaseFunction.self),
            peerDrain: try required("hs_peer_drain", as: PeerDrainFunction.self)
        )
    }
}

// MARK: - Library ownership

/// One `dlopen` reference. `dlclose` is skipped forever when a native teardown
/// barrier is unproven: the bridge may still own callbacks or peers, and
/// unloading its code would turn a late callback into a use-after-free.
final class NativeWebRTCLibrary: @unchecked Sendable {
    private let lock = NSLock()
    private var handle: UnsafeMutableRawPointer?
    private var retainUntilProcessExitFlag = false

    init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    func retainUntilProcessExit() {
        lock.lock()
        retainUntilProcessExitFlag = true
        lock.unlock()
    }

    deinit {
        lock.lock()
        let handle = self.handle
        let retain = retainUntilProcessExitFlag
        self.handle = nil
        lock.unlock()

        if let handle, !retain {
            _ = dlclose(handle)
        }
    }
}

// MARK: - Bundled path resolution

/// Resolves exactly one location: `Contents/Frameworks/libhs_webrtc_shared.dylib`
/// inside the running `.app`. There is no environment override, no `@rpath`
/// search, no system fallback, and no dev-directory escape hatch.
enum NativeWebRTCBundleResolver {
    static func resolve(bundle: Bundle) throws -> URL {
        try resolve(bundleURL: bundle.bundleURL, executableURL: bundle.executableURL)
    }

    static func resolve(bundleURL: URL, executableURL: URL?) throws -> URL {
        guard bundleURL.isFileURL else {
            throw NativeWebRTCError.bundleUnavailable
        }

        let canonicalBundle = bundleURL.resolvingSymlinksInPath().standardizedFileURL
        guard canonicalBundle.pathExtension.lowercased() == "app" else {
            throw NativeWebRTCError.bundleUnavailable
        }

        if let executableURL {
            let canonicalExecutable =
                executableURL.resolvingSymlinksInPath().standardizedFileURL
            guard isContained(canonicalExecutable, in: canonicalBundle) else {
                throw NativeWebRTCError.bundleUnavailable
            }
        }

        let frameworks = canonicalBundle.appendingPathComponent(
            "Contents/Frameworks", isDirectory: true)
        let candidate = frameworks.appendingPathComponent(
            NativeWebRTCContract.bundledLibraryName, isDirectory: false)

        var pathInfo = stat()
        let pathStatus = candidate.path.withCString { Darwin.lstat($0, &pathInfo) }
        guard pathStatus == 0 else {
            throw NativeWebRTCError.libraryMissing(candidate.path)
        }
        guard (pathInfo.st_mode & S_IFMT) == S_IFREG else {
            throw NativeWebRTCError.libraryNotRegularFile(candidate.path)
        }
        guard pathInfo.st_size > 0,
              pathInfo.st_size <= NativeWebRTCContract.maximumLibraryBytes
        else {
            throw NativeWebRTCError.libraryNotRegularFile(candidate.path)
        }

        let canonicalCandidate = candidate.resolvingSymlinksInPath().standardizedFileURL
        let canonicalFrameworks = frameworks.resolvingSymlinksInPath().standardizedFileURL
        guard isContained(canonicalCandidate, in: canonicalBundle),
              canonicalCandidate.lastPathComponent
                == NativeWebRTCContract.bundledLibraryName,
              canonicalCandidate.deletingLastPathComponent().standardizedFileURL
                == canonicalFrameworks
        else {
            throw NativeWebRTCError.libraryOutsideBundle(candidate.path)
        }
        return canonicalCandidate
    }

    private static func isContained(_ child: URL, in parent: URL) -> Bool {
        child.path == parent.path || child.path.hasPrefix(parent.path + "/")
    }
}

// MARK: - Contract validation

enum NativeWebRTCValidation {
    static func validateContract(
        abiVersion: UInt32,
        capabilityStatus: UInt32,
        capabilities: UInt32
    ) throws {
        guard abiVersion == NativeWebRTCContract.abiVersion else {
            throw NativeWebRTCError.abiMismatch(
                expected: NativeWebRTCContract.abiVersion, actual: abiVersion)
        }
        let status = NativeWebRTCStatus.from(capabilityStatus)
        guard status == .ok else {
            throw NativeWebRTCError.capabilityQueryFailed(status)
        }
        let missing = NativeWebRTCContract.requiredConnectionCapabilities & ~capabilities
        guard missing == 0 else {
            throw NativeWebRTCError.requiredCapabilitiesMissing(missing: missing)
        }
    }

    /// A native teardown is only safe to unload after an explicit OK or after
    /// the bridge reports the token already retired. Timeout and state failures
    /// retain the library and every observer it owns.
    static func isProvenQuiescence(_ status: NativeWebRTCStatus) -> Bool {
        status == .ok || status == .null
    }

    static func supportsObservation(_ capabilities: UInt32) -> Bool {
        (capabilities & NativeWebRTCContract.requiredObservationCapabilities)
            == NativeWebRTCContract.requiredObservationCapabilities
    }
}

/// Pure teardown decisions matching `hs_peer_drain` / `hs_engine_shutdown`
/// semantics. Engine shutdown is never started while an active peer object owns
/// a token; orphaned tokens get bounded drain attempts, and an unproven result
/// always retains the loaded image.
struct NativeWebRTCEngineTeardown: Equatable {
    let retired: Bool
    let reported: NativeWebRTCStatus
}

/// Outcome of one bounded attempt to drain an orphaned peer token.
enum NativeWebRTCOrphanAttemptOutcome: Equatable {
    case retired
    case retry
    case releaseUnproven
}

enum NativeWebRTCTeardown {
    /// Maximum `hs_peer_drain` attempts for one orphaned peer inside a single
    /// engine close. After this bound the engine stops treating the orphan as
    /// its own retryable peer, but the image is retained and the unproven
    /// status is reported; quiescence is never invented.
    static let maximumOrphanDrainAttempts: UInt32 = 3

    /// A peer is retired only after a proven barrier (`OK`) or when the bridge
    /// reports the token already retired (`NULL`). Every other result retains
    /// the peer and must be retried with another `hs_peer_drain`.
    static func peerRetired(_ status: NativeWebRTCStatus) -> Bool {
        NativeWebRTCValidation.isProvenQuiescence(status)
    }

    /// Give each bounded orphan attempt a slice of the caller's timeout. The
    /// total drain blocking stays bounded by close's timeout budget.
    static func orphanAttemptTimeout(
        totalMilliseconds: UInt32,
        attemptCount: Int
    ) -> UInt32 {
        guard attemptCount > 0 else { return 0 }
        return max(1, totalMilliseconds / UInt32(attemptCount))
    }

    /// Classify one orphan drain attempt. `attempt` is 1-based.
    static func orphanAttemptOutcome(
        status: NativeWebRTCStatus,
        attempt: UInt32,
        maximumAttempts: UInt32 = maximumOrphanDrainAttempts
    ) -> NativeWebRTCOrphanAttemptOutcome {
        if peerRetired(status) { return .retired }
        if attempt >= maximumAttempts { return .releaseUnproven }
        return .retry
    }

    /// The engine must not start shutdown while it still owns a peer token.
    static func engineMayShutDown(livePeers: Int) -> Bool {
        livePeers == 0
    }

    /// `hs_engine_shutdown` retires the engine token even when its internal
    /// drain fails, so an unproven engine teardown is terminal for the handle
    /// but must still retain the loaded image. The reported status is the
    /// first unproven barrier, never a misleading OK.
    static func engineTeardown(
        drain: NativeWebRTCStatus,
        shutdown: NativeWebRTCStatus
    ) -> NativeWebRTCEngineTeardown {
        let drainProven = NativeWebRTCValidation.isProvenQuiescence(drain)
        let shutdownProven = NativeWebRTCValidation.isProvenQuiescence(shutdown)
        if drainProven && shutdownProven {
            return NativeWebRTCEngineTeardown(retired: true, reported: .ok)
        }
        return NativeWebRTCEngineTeardown(
            retired: false,
            reported: drainProven ? shutdown : drain
        )
    }
}

// MARK: - Loaded module

/// One successfully validated bundled library. Keeping the `dlopen` reference
/// here makes every engine/peer hold the code it calls for as long as it lives.
public final class NativeWebRTCModule: @unchecked Sendable {
    let library: NativeWebRTCLibrary
    let symbols: NativeWebRTCSymbols
    public let abiVersion: UInt32
    public let capabilities: UInt32
    public let engineVersion: String

    init(
        library: NativeWebRTCLibrary,
        symbols: NativeWebRTCSymbols,
        abiVersion: UInt32,
        capabilities: UInt32,
        engineVersion: String
    ) {
        self.library = library
        self.symbols = symbols
        self.abiVersion = abiVersion
        self.capabilities = capabilities
        self.engineVersion = engineVersion
    }

    /// True when the library reports the four bits required to negotiate and
    /// prove a data channel. These bits are queried, never assumed.
    public var supportsConnection: Bool {
        (capabilities & NativeWebRTCContract.requiredConnectionCapabilities)
            == NativeWebRTCContract.requiredConnectionCapabilities
    }

    /// Honest capability report only. This macOS wrapper does not expose a
    /// preview path, and capture/admission/media are never enabled here.
    public var reportsObservationCapabilities: Bool {
        NativeWebRTCValidation.supportsObservation(capabilities)
    }

    public func makeEngine() throws -> NativeWebRTCEngine {
        guard supportsConnection else {
            throw NativeWebRTCError.requiredCapabilitiesMissing(
                missing: NativeWebRTCContract.requiredConnectionCapabilities & ~capabilities)
        }
        return try NativeWebRTCEngine(module: self)
    }

    func retainLibraryUntilProcessExit() {
        library.retainUntilProcessExit()
    }
}

/// Strict loader for the one library the running application bundle contains.
public enum NativeWebRTCLoader {
    /// The only production entry point. The bundle is always `Bundle.main`; a
    /// caller cannot point the loader at another app or an arbitrary dylib.
    public static func loadBundled() throws -> NativeWebRTCModule {
        let libraryURL = try NativeWebRTCBundleResolver.resolve(bundle: .main)
        return try loadLibrary(at: libraryURL)
    }

    private static func loadLibrary(at url: URL) throws -> NativeWebRTCModule {
        guard url.isFileURL, url.path.hasPrefix("/") else {
            throw NativeWebRTCError.bundleUnavailable
        }

        // RTLD_FIRST keeps dlsym lookups scoped to this image; a dependency
        // cannot impersonate a required ABI export.
        let opened = url.path.withCString {
            dlopen($0, RTLD_NOW | RTLD_LOCAL | RTLD_FIRST)
        }
        guard let opened else {
            throw NativeWebRTCError.libraryOpenFailed(lastDynamicLoaderError())
        }
        let library = NativeWebRTCLibrary(handle: opened)

        let symbols = try NativeWebRTCSymbols.load(from: opened)
        let abiVersion = symbols.abiVersion()
        var capabilities: UInt32 = 0
        let capabilityStatus = symbols.capabilities(&capabilities)
        try NativeWebRTCValidation.validateContract(
            abiVersion: abiVersion,
            capabilityStatus: capabilityStatus,
            capabilities: capabilities
        )

        let engineVersion = boundedString(
            symbols.engineVersion(), maximumBytes: 256) ?? ""
        return NativeWebRTCModule(
            library: library,
            symbols: symbols,
            abiVersion: abiVersion,
            capabilities: capabilities,
            engineVersion: engineVersion
        )
    }

    private static func lastDynamicLoaderError() -> String {
        guard let message = dlerror() else {
            return "unknown dynamic loader error"
        }
        return String(cString: message)
    }

    private static func boundedString(
        _ pointer: UnsafePointer<CChar>?,
        maximumBytes: Int
    ) -> String? {
        guard let pointer else { return nil }
        let length = strnlen(pointer, maximumBytes + 1)
        guard length > 0, length <= maximumBytes else { return nil }
        let bytes = UnsafeRawPointer(pointer).assumingMemoryBound(to: UInt8.self)
        return String(
            decoding: UnsafeBufferPointer(start: bytes, count: length),
            as: UTF8.self
        )
    }
}
