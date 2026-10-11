import CryptoKit
import Foundation
import Security

/// Bounded cancelable HTTPS transport for an operator-pinned deployment origin.
///
/// Native Foundation `URLSession` + Security `SecTrust` evaluation:
/// `SecPolicyCreateSSL` hostname policy, `SecTrustSetAnchorCertificates`,
/// `SecTrustSetAnchorCertificatesOnly(true)` (no OS/browser roots),
/// `SecTrustSetNetworkFetchAllowed(false)` (no online AIA/CA downloads),
/// then `SecTrustEvaluateWithError` on the real chain.
///
/// Pin matching alone does not replace certificate validation. Invalid
/// pin/chain/hostname/missing cert or any unknown auth challenge cancels.
/// Redirects are never followed (including same-origin). No cookies,
/// credential storage, proxy adoption, or URL cache. No bearer/token
/// source code or logging.
///
/// Production app mode and loopback development clients stay as currently
/// wired; this transport is a request seam for later v2 account integration.
public struct PinnedHTTPSConfiguration: Sendable {
    /// Default decoded-body cap (64 KiB).
    public static let defaultMaxResponseBytes = 65_536
    /// Absolute decoded-body hard cap (1 MiB).
    public static let absoluteMaxResponseBytes = 1_048_576
    /// Maximum accepted timeout (seconds). Keeps sleep/deadline safely representable.
    public static let maxTimeoutSeconds: TimeInterval = 7 * 24 * 60 * 60

    public let identity: DeploymentTLSIdentity
    /// Per-request timeout for connection + headers + body (seconds).
    public let requestTimeout: TimeInterval
    /// Per-operation deadline covering connection + headers + body (seconds).
    public let operationTimeout: TimeInterval
    /// Decoded body cap. Must be in `1...absoluteMaxResponseBytes` — never clamped.
    public let maxResponseBytes: Int

    /// Validate bounds. Throws `HelicoidError.invalidInput` on negative,
    /// non-finite, zero, or out-of-range values. Never silently clamps.
    public init(
        identity: DeploymentTLSIdentity,
        requestTimeout: TimeInterval = 15,
        operationTimeout: TimeInterval = 30,
        maxResponseBytes: Int = PinnedHTTPSConfiguration.defaultMaxResponseBytes
    ) throws {
        guard requestTimeout > 0, requestTimeout.isFinite, requestTimeout <= Self.maxTimeoutSeconds else {
            throw HelicoidError.invalidInput(
                field: "requestTimeout",
                detail: "Request timeout must be finite, positive, and at most \(Int(Self.maxTimeoutSeconds)) seconds."
            )
        }
        guard operationTimeout > 0, operationTimeout.isFinite, operationTimeout <= Self.maxTimeoutSeconds else {
            throw HelicoidError.invalidInput(
                field: "operationTimeout",
                detail: "Operation timeout must be finite, positive, and at most \(Int(Self.maxTimeoutSeconds)) seconds."
            )
        }
        guard maxResponseBytes > 0, maxResponseBytes <= Self.absoluteMaxResponseBytes else {
            throw HelicoidError.invalidInput(
                field: "maxResponseBytes",
                detail: "Body bound must be in 1...\(Self.absoluteMaxResponseBytes)."
            )
        }
        self.identity = identity
        self.requestTimeout = requestTimeout
        self.operationTimeout = operationTimeout
        self.maxResponseBytes = maxResponseBytes
    }

    /// Rejects negative, non-finite, or otherwise invalid bounds.
    public var hasFinitePositiveBounds: Bool {
        requestTimeout > 0 && requestTimeout.isFinite && requestTimeout <= Self.maxTimeoutSeconds
            && operationTimeout > 0 && operationTimeout.isFinite && operationTimeout <= Self.maxTimeoutSeconds
            && maxResponseBytes > 0 && maxResponseBytes <= Self.absoluteMaxResponseBytes
    }

    /// Convert a validated timeout to nanoseconds without trapping on huge values.
    static func nanoseconds(from seconds: TimeInterval) -> UInt64 {
        let capped = min(max(seconds, 0), maxTimeoutSeconds)
        // 7 days * 1e9 is well below UInt64.max; round down for safety.
        let scaled = (capped * 1_000_000_000).rounded(.down)
        return UInt64(min(scaled, TimeInterval(UInt64.max)))
    }
}

/// Result of one bounded pinned HTTPS request.
public struct PinnedHTTPSResponse: Sendable, Equatable {
    public let statusCode: Int
    public let body: Data

    public init(statusCode: Int, body: Data) {
        self.statusCode = statusCode
        self.body = body
    }
}

/// HTTPTransport seam for pinned HTTPS.
///
/// `bytes(for:maxBytes:)` and `request(...)` share one path that refuses
/// non-2xx **before** reading any body. Origin, bounds, and redirect
/// semantics are enforced inside this type.
public final class PinnedHTTPSTransport: HTTPTransport, @unchecked Sendable {
    // Justified @unchecked Sendable: immutable configuration, thread-safe
    // OperationRegistry, and a URLSession. The trust delegate holds immutable
    // pin/root material only (see PinnedTrustDelegate).

    private let configuration: PinnedHTTPSConfiguration
    private let session: URLSession
    private let sessionDelegate: PinnedTrustDelegate
    private let registry = OperationRegistry()

    /// Create a transport from validated trust inputs.
    public init(configuration: PinnedHTTPSConfiguration) throws {
        guard configuration.hasFinitePositiveBounds else {
            throw HelicoidError.invalidInput(field: "configuration", detail: "Configuration bounds must be finite and positive.")
        }
        self.configuration = configuration

        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.timeoutIntervalForRequest = configuration.requestTimeout
        sessionConfig.timeoutIntervalForResource = configuration.operationTimeout
        sessionConfig.httpShouldSetCookies = false
        sessionConfig.httpCookieAcceptPolicy = .never
        sessionConfig.urlCache = nil
        sessionConfig.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        sessionConfig.httpAdditionalHeaders = ["Connection": "close"]
        sessionConfig.urlCredentialStorage = nil
        sessionConfig.httpMaximumConnectionsPerHost = 2
        // TLS 1.2 minimum (1.3 preferred by the stack). Explicit, not implied.
        sessionConfig.tlsMinimumSupportedProtocolVersion = .TLSv12
        // Never adopt configured system proxy.
        sessionConfig.connectionProxyDictionary = [
            kCFNetworkProxiesHTTPEnable as String: false,
            kCFNetworkProxiesHTTPSEnable as String: false,
        ]

        let delegate = PinnedTrustDelegate(
            caDER: configuration.identity.caDER,
            caFingerprintSHA256: configuration.identity.caFingerprintSHA256,
            expectedHost: configuration.identity.host
        )
        self.sessionDelegate = delegate
        let session = URLSession(configuration: sessionConfig, delegate: delegate, delegateQueue: nil)
        self.session = session
        registry.attach(session: session)
    }

    /// Configured canonical origin. Only this origin may be addressed.
    public var originURL: URL { configuration.identity.originURL }

    /// Decoded body cap in force for this transport.
    public var maxResponseBytes: Int { configuration.maxResponseBytes }

    /// True after `dispose()`. Subsequent requests fail closed.
    public var isDisposed: Bool { registry.isDisposed }

    /// Number of registered in-flight operations (for tests/inspection).
    public var activeOperationCount: Int { registry.activeCount }

    /// Last pinned TLS trust decision (test/diagnostics seam).
    /// Bounded and non-secret: native codes and host names only.
    var lastTrustDiagnostic: TrustEvaluationDiagnostic? {
        sessionDelegate.lastTrustDiagnostic
    }

    // MARK: - HTTPTransport

    public func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        // Enforce both the caller cap and the configured cap.
        let configured = configuration.maxResponseBytes
        let cap = min(maxBytes, configured, PinnedHTTPSConfiguration.absoluteMaxResponseBytes)
        guard maxBytes > 0, cap > 0 else {
            throw HelicoidError.invalidInput(field: "maxBytes", detail: "Body bound must be positive.")
        }
        guard let url = request.url else {
            throw HelicoidError.invalidInput(field: "url", detail: "Request URL is missing.")
        }
        try Self.validateRequestURL(url, origin: originURL)

        return try await performRegistered(request: request, maxBytes: cap)
    }

    /// Bounded cancelable request seam. Throws `HelicoidError` on any refusal.
    public func request(
        method: String,
        path: String,
        headers: [String: String] = [:],
        body: Data? = nil
    ) async throws -> PinnedHTTPSResponse {
        let resolved: URL
        switch DeploymentOriginPolicy.resolve(path: path, origin: originURL) {
        case .allowed(let url):
            resolved = url
        case .refused(let reason):
            throw HelicoidError.invalidInput(field: "path", detail: reason.message)
        }

        var request = URLRequest(url: resolved)
        request.httpMethod = method.uppercased()
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }

        let (data, response) = try await bytes(for: request, maxBytes: configuration.maxResponseBytes)
        guard let http = response as? HTTPURLResponse else {
            throw HelicoidError.unreachable
        }
        // Status already refused inside performBounded; this is belt-and-braces.
        guard (200...299).contains(http.statusCode) else {
            throw HelicoidError.invalidInput(
                field: "response",
                detail: "Pinned HTTPS transport refused non-2xx status \(http.statusCode)."
            )
        }
        return PinnedHTTPSResponse(statusCode: http.statusCode, body: data)
    }

    /// Release session resources. Cancels tracked operations and defers
    /// `invalidateAndCancel` until no registered operation can still create
    /// URLSession tasks (prevents "task created in invalidated session").
    public func dispose() {
        registry.dispose()
    }

    deinit {
        registry.dispose()
    }

    // MARK: - Validation

    /// Refuse absolute foreign URIs, traversal, scheme escapes, and origin mismatch.
    public static func validateRequestURL(_ url: URL, origin: URL) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw HelicoidError.invalidInput(field: "url", detail: "Request URL is not parseable.")
        }
        if components.user != nil || components.password != nil {
            throw HelicoidError.invalidInput(field: "url", detail: DeploymentOriginPolicy.Reason.credentialsPresent.message)
        }
        if components.fragment != nil {
            throw HelicoidError.invalidInput(field: "url", detail: DeploymentOriginPolicy.Reason.fragmentPresent.message)
        }
        guard components.scheme?.lowercased() == "https" else {
            throw HelicoidError.invalidInput(field: "url", detail: "Only https is accepted.")
        }
        guard let host = components.host.map(DeploymentTLSIdentity.normalizeHostForCompare),
              host == DeploymentTLSIdentity.normalizeHostForCompare(origin.host ?? "") else {
            throw HelicoidError.invalidInput(field: "url", detail: DeploymentOriginPolicy.Reason.hostMismatch.message)
        }
        let requestPort = components.port ?? 443
        let originPort = origin.port ?? 443
        guard requestPort == originPort else {
            throw HelicoidError.invalidInput(field: "url", detail: DeploymentOriginPolicy.Reason.portMismatch.message)
        }
        if DeploymentOriginPolicy.hasTraversal(components.path) {
            throw HelicoidError.invalidInput(field: "url", detail: DeploymentOriginPolicy.Reason.traversal.message)
        }
    }

    // MARK: - Registered perform (atomic with disposal)

    private enum RaceResult: Sendable {
        case response(Data, URLResponse)
        case deadline
    }

    private func performRegistered(
        request: URLRequest,
        maxBytes: Int
    ) async throws -> (Data, URLResponse) {
        let holder = CancellableHolder()
        // Registration is atomic with disposal: begin() throws if disposed and
        // increments the live count before any URLSession task can be created.
        let lease = try registry.begin { holder.cancel() }

        let operationTimeout = configuration.operationTimeout

        // Owned operation task: disposal cancels this handle. Structured work
        // (work + deadline) lives entirely inside so cancellation propagates.
        // Registration is released only after this task fully drains.
        let op = Task { () async throws -> (Data, URLResponse) in
            try await self.raceWorkAndDeadline(
                request: request,
                maxBytes: maxBytes,
                operationTimeout: operationTimeout
            )
        }
        holder.bind(op)

        do {
            let result = try await withTaskCancellationHandler {
                try await op.value
            } onCancel: {
                holder.cancel()
            }
            // op.value returning means raceWorkAndDeadline finished and its
            // task group drained every child — safe to release the lease.
            registry.end(lease)
            return result
        } catch {
            registry.end(lease)
            throw error
        }
    }

    /// Fully structured race: first winner cancels the loser and both are
    /// drained before return. No unstructured Task values are awaited here.
    private func raceWorkAndDeadline(
        request: URLRequest,
        maxBytes: Int,
        operationTimeout: TimeInterval
    ) async throws -> (Data, URLResponse) {
        let session = self.session
        let delegate = self.sessionDelegate
        return try await withThrowingTaskGroup(of: RaceResult.self) { group in
            group.addTask {
                let (data, response) = try await self.performBounded(
                    request: request,
                    session: session,
                    delegate: delegate,
                    maxBytes: maxBytes
                )
                return .response(data, response)
            }
            group.addTask {
                try await Task.sleep(nanoseconds: PinnedHTTPSConfiguration.nanoseconds(from: operationTimeout))
                return .deadline
            }

            // First winner (success or error).
            let winner: RaceResult
            do {
                guard let first = try await group.next() else {
                    throw HelicoidError.unreachable
                }
                winner = first
            } catch {
                // Winner was an error — cancel and drain the sibling before rethrow.
                group.cancelAll()
                await Self.drainCancelledSiblings(&group)
                throw error
            }

            // Cancel the loser immediately so drain is prompt.
            group.cancelAll()
            await Self.drainCancelledSiblings(&group)

            switch winner {
            case .response(let data, let response):
                return (data, response)
            case .deadline:
                throw HelicoidError.unreachable
            }
        }
    }

    /// True when `error` is the named expected outcome of draining a sibling
    /// that lost the race after `cancelAll()`.
    private static func isExpectedCancellationDrain(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        if let helicoid = error as? HelicoidError { return helicoid == .cancelled }
        return false
    }

    /// Drain remaining children after `cancelAll()`.
    ///
    /// The race winner is already chosen and remains authoritative. Losing
    /// children are drained so the group can exit; a loser that fails
    /// independently (including non-cancellation network errors while a
    /// deadline or cancellation is also racing) cannot change the winner and
    /// is not process-fatal. Intentionally not `try?` and not `assertionFailure`:
    /// expected cancellation is named; other sibling outcomes are ignored for
    /// the race result only, without logging potentially sensitive external
    /// error text.
    private static func drainCancelledSiblings(
        _ group: inout ThrowingTaskGroup<RaceResult, Error>
    ) async {
        while true {
            do {
                guard (try await group.next()) != nil else { return }
            } catch let error where isExpectedCancellationDrain(error) {
                continue
            } catch {
                // Independently failing loser after cancelAll(). Winner stands.
                continue
            }
        }
    }

    // MARK: - Bounded perform (status before body, cancelable URLSessionTask)

    private func performBounded(
        request: URLRequest,
        session: URLSession,
        delegate: PinnedTrustDelegate,
        maxBytes: Int
    ) async throws -> (Data, URLResponse) {
        let sink = BodySink(maxBytes: maxBytes)
        let task = session.dataTask(with: request)
        // Sink can promptly cancel the actual URLSessionDataTask on overflow.
        sink.bindDataTask(task)
        delegate.registerSink(sink, taskID: task.taskIdentifier)
        defer { delegate.unregisterSink(taskID: task.taskIdentifier) }

        return try await withTaskCancellationHandler {
            task.resume()
            do {
                return try await sink.result()
            } catch {
                // EVERY exit path cancels the owned URLSessionDataTask so
                // overflow/error cannot leave the network download running.
                task.cancel()
                throw error
            }
        } onCancel: {
            // Prompt abort: cancel the URLSessionTask directly, not only the Task.
            task.cancel()
            sink.cancel()
        }
    }
}

// MARK: - Operation registry (disposal ownership)

/// Owns in-flight operation lifetime relative to session invalidation.
///
/// `begin` is atomic with `dispose`: once disposed, new operations are refused.
/// `dispose` cancels tracked work and **defers** `invalidateAndCancel` until
/// `activeCount == 0`, so no registered operation can observe an invalidated
/// session while creating a URLSession task.
private final class OperationRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var _disposed = false
    private var _active = 0
    private var _session: URLSession?
    private var cancels: [UUID: () -> Void] = [:]

    struct Lease {
        let id: UUID
    }

    var isDisposed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _disposed
    }

    var activeCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _active
    }

    func attach(session: URLSession) {
        lock.lock()
        _session = session
        lock.unlock()
    }

    /// Atomic with dispose. Throws when already disposed.
    func begin(_ cancel: @escaping () -> Void) throws -> Lease {
        lock.lock()
        defer { lock.unlock() }
        guard !_disposed else {
            throw HelicoidError.unreachable
        }
        let id = UUID()
        _active += 1
        cancels[id] = cancel
        return Lease(id: id)
    }

    /// Release registration. Invalidates the session only when dispose already
    /// happened and no registered operation remains.
    func end(_ lease: Lease) {
        lock.lock()
        cancels[lease.id] = nil
        _active -= 1
        let shouldInvalidate = _disposed && _active == 0
        let session = shouldInvalidate ? _session : nil
        if shouldInvalidate {
            _session = nil
        }
        lock.unlock()
        if let session {
            session.invalidateAndCancel()
        }
    }

    /// Cancel tracked operations and invalidate when safe.
    func dispose() {
        lock.lock()
        _disposed = true
        let pending = Array(cancels.values)
        cancels.removeAll()
        let shouldInvalidate = _active == 0
        let session = shouldInvalidate ? _session : nil
        if shouldInvalidate {
            _session = nil
        }
        lock.unlock()
        // Cancel outside the lock, then invalidate only if no operation can
        // still call session.bytes / create tasks.
        for cancel in pending {
            cancel()
        }
        if let session {
            session.invalidateAndCancel()
        }
    }
}

// MARK: - Cancellable holder

/// Late-bound cancel handle so disposal can abort a task created after begin().
private final class CancellableHolder: @unchecked Sendable {
    private let lock = NSLock()
    private var task: Task<(Data, URLResponse), Error>?
    private var cancelled = false

    func bind(_ task: Task<(Data, URLResponse), Error>) {
        lock.lock()
        self.task = task
        let already = cancelled
        lock.unlock()
        if already {
            task.cancel()
        }
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let task = self.task
        self.task = nil
        lock.unlock()
        task?.cancel()
    }
}

// MARK: - Body sink (bounded streaming with prompt task cancel)

/// Per-request streaming sink. Receives URLSessionDataDelegate callbacks and
/// resumes a single continuation. Bounded body, non-2xx refused before read.
///
/// Buffer never exceeds `maxBytes`: `append` prechecks the remaining bound
/// before writing. Overflow and early refusal cancel the owned
/// `URLSessionDataTask` so the network download does not continue.
final class BodySink: @unchecked Sendable {
    private let lock = NSLock()
    private let maxBytes: Int
    private var data = Data()
    private var response: URLResponse?
    private var continuation: CheckedContinuation<(Data, URLResponse), Error>?
    private var finished = false
    private var pendingResult: Result<(Data, URLResponse), Error>?
    private weak var dataTask: URLSessionDataTask?
    /// Recorded trust decision for this task. Lets a later auth-challenge
    /// cancellation surface as a structured trust failure instead of bare
    /// `HelicoidError.cancelled`. Bounded, non-secret.
    private var trustDiagnostic: TrustEvaluationDiagnostic?

    init(maxBytes: Int) {
        self.maxBytes = maxBytes
    }

    /// Bind the owned URLSessionTask so overflow/refusal can cancel it promptly.
    func bindDataTask(_ task: URLSessionDataTask) {
        lock.lock()
        dataTask = task
        lock.unlock()
    }

    /// Record the trust decision for this task (test/structured-error seam).
    /// A refusal replaces any earlier value so the first hard failure is kept.
    func recordTrustDiagnostic(_ diagnostic: TrustEvaluationDiagnostic) {
        lock.lock()
        if trustDiagnostic == nil || diagnostic.decision != .accepted {
            trustDiagnostic = diagnostic
        }
        lock.unlock()
    }

    /// Peak buffered body length (for tests). Never exceeds `maxBytes`.
    var bufferedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return data.count
    }

    func result() async throws -> (Data, URLResponse) {
        try await withCheckedThrowingContinuation { cont in
            lock.lock()
            if let pending = pendingResult {
                pendingResult = nil
                finished = true
                lock.unlock()
                cont.resume(with: pending)
                return
            }
            if finished {
                // complete() already ran without a continuation — treat as failure.
                lock.unlock()
                cont.resume(throwing: HelicoidError.unreachable)
                return
            }
            continuation = cont
            lock.unlock()
        }
    }

    func accept(response: URLResponse, dataTask: URLSessionDataTask, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock()
        if let error = earlyError(response: response) {
            finish(.failure(error))
            let task = self.dataTask ?? dataTask
            lock.unlock()
            completionHandler(.cancel)
            // Prompt abort of the actual URLSessionDataTask on early refusal.
            task.cancel()
            return
        }
        self.response = response
        lock.unlock()
        completionHandler(.allow)
    }

    func append(_ chunk: Data) {
        lock.lock()
        guard !finished, pendingResult == nil else {
            lock.unlock()
            return
        }
        // Precheck remaining bound BEFORE append so the buffer never exceeds
        // the configured limit, even transiently.
        let remaining = maxBytes - data.count
        if chunk.count > remaining {
            finish(.failure(HelicoidError.invalidInput(field: "response", detail: "Response body exceeded the bounded size limit.")))
            let task = dataTask
            lock.unlock()
            // Cancel the actual URLSessionDataTask promptly — do not leave the
            // network download running after the sink has failed.
            task?.cancel()
            return
        }
        data.append(chunk)
        lock.unlock()
    }

    func complete(error: Error?) {
        lock.lock()
        if let error {
            // Owner's own trust decision only — never another task's.
            finish(.failure(BodySink.mapNSURLError(error, trustDiagnostic: trustDiagnostic)))
        } else if let resp = response {
            finish(.success((data, resp)))
        } else {
            finish(.failure(HelicoidError.unreachable))
        }
        lock.unlock()
    }

    func cancel() {
        complete(error: CancellationError())
    }

    /// Call with lock held.
    private func finish(_ result: Result<(Data, URLResponse), Error>) {
        guard !finished, pendingResult == nil else { return }
        finished = true
        if let cont = continuation {
            continuation = nil
            cont.resume(with: result)
        } else {
            pendingResult = result
        }
    }

    private func earlyError(response: URLResponse) -> Error? {
        guard let http = response as? HTTPURLResponse else {
            return HelicoidError.unreachable
        }
        // Refuse non-2xx BEFORE reading any body.
        if !(200...299).contains(http.statusCode) {
            return HelicoidError.invalidInput(
                field: "response",
                detail: "Pinned HTTPS transport refused non-2xx status \(http.statusCode)."
            )
        }
        if let declared = http.value(forHTTPHeaderField: "Content-Length"),
           let length = Int(declared),
           length > maxBytes {
            return HelicoidError.invalidInput(field: "response", detail: "Response body exceeded the bounded size limit.")
        }
        return nil
    }

    /// Map transport completion errors to `HelicoidError`.
    ///
    /// URLSession reports an auth-challenge refusal as task cancellation
    /// (`NSURLErrorCancelled` / `userCancelledAuthentication`). When a trust
    /// refusal was recorded for this task, that cause is surfaced instead of
    /// bare `.cancelled` so native failures stay actionable. Genuine task
    /// cancellation (dispose / `Task.cancel`) still maps to `.cancelled`.
    private static func mapNSURLError(
        _ error: Error,
        trustDiagnostic: TrustEvaluationDiagnostic?
    ) -> HelicoidError {
        if let helicoid = error as? HelicoidError {
            return helicoid
        }
        if let trustDiagnostic, trustDiagnostic.decision != .accepted {
            if error is CancellationError {
                return .invalidInput(field: "server_trust", detail: trustDiagnostic.description)
            }
            let nsError = error as NSError
            if nsError.domain == NSURLErrorDomain {
                let code = URLError.Code(rawValue: nsError.code)
                switch code {
                case .cancelled, .userCancelledAuthentication,
                     .secureConnectionFailed, .serverCertificateUntrusted,
                     .serverCertificateHasBadDate, .serverCertificateHasUnknownRoot,
                     .serverCertificateNotYetValid, .clientCertificateRejected,
                     .clientCertificateRequired, .appTransportSecurityRequiresSecureConnection:
                    return .invalidInput(field: "server_trust", detail: trustDiagnostic.description)
                default:
                    break
                }
            }
        }
        if error is CancellationError {
            return .cancelled
        }
        let nsError = error as NSError
        if nsError.domain == NSURLErrorDomain {
            return mapURLError(URLError(URLError.Code(rawValue: nsError.code)))
        }
        return .unreachable
    }

    private static func mapURLError(_ error: URLError) -> HelicoidError {
        switch error.code {
        case .cancelled:
            return .cancelled
        case .secureConnectionFailed, .serverCertificateUntrusted, .serverCertificateHasBadDate,
             .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid, .clientCertificateRejected,
             .clientCertificateRequired, .appTransportSecurityRequiresSecureConnection:
            return .unreachable
        case .timedOut, .cannotConnectToHost, .networkConnectionLost, .dnsLookupFailed, .cannotFindHost:
            return .unreachable
        default:
            return .unreachable
        }
    }
}

// MARK: - Trust decision diagnostic

/// Bounded, non-secret record of one pinned TLS trust decision.
///
/// Exposes native Security evaluation codes (`OSStatus`, `CFError` domain/code)
/// so a native CI failure is actionable. Never carries certificate bytes, PEM,
/// private keys, credentials, or raw `CFError` prose (OS text may embed identity).
struct TrustEvaluationDiagnostic: Equatable, Sendable, CustomStringConvertible {
    enum Decision: String, Equatable, Sendable {
        case accepted
        case refusedAuthMethod
        case refusedHostMismatch
        case refusedPin
        case refusedCAParse
        case refusedSetup
        case refusedEvaluate
    }

    let decision: Decision
    /// Setup/evaluate step that produced the decision (e.g. "evaluate").
    let step: String
    let host: String
    let expectedHost: String
    /// Raw `URLAuthenticationChallenge.protectionSpace.authenticationMethod`.
    let authenticationMethod: String
    let serverTrustPresent: Bool
    /// Chain length recorded only after the configured evaluation result.
    /// Unknown-method / setup refusals report 0 and never probe `SecTrust`.
    let certificateCount: Int
    let osStatus: Int32?
    let cfErrorDomain: String?
    let cfErrorCode: Int?

    /// Fixed-width, code-only summary safe for structured error details.
    var description: String {
        var parts: [String] = [
            "decision=\(decision.rawValue)",
            "step=\(step)",
            "host=\(host)",
            "expectedHost=\(expectedHost)",
            "authMethod=\(authenticationMethod)",
            "serverTrust=\(serverTrustPresent)",
            "certs=\(certificateCount)",
        ]
        if let osStatus {
            parts.append("osStatus=\(osStatus)")
        }
        if let cfErrorDomain {
            parts.append("cfDomain=\(cfErrorDomain)")
        }
        if let cfErrorCode {
            parts.append("cfCode=\(cfErrorCode)")
        }
        return parts.joined(separator: " ")
    }
}

// MARK: - Trust + redirect + data delegate

/// URLSession delegate holding immutable pinned CA/root state and per-task body sinks.
///
/// @unchecked Sendable is justified: pin/root properties are immutable `let`
/// values written once at init. Sink map is lock-guarded. No process-global
/// network bypass is installed.
final class PinnedTrustDelegate: NSObject, URLSessionTaskDelegate, URLSessionDelegate, URLSessionDataDelegate, @unchecked Sendable {
    private let caDER: Data
    private let caFingerprintSHA256: String
    private let expectedHost: String
    private let sinkLock = NSLock()
    private var sinks: [Int: BodySink] = [:]
    private var _lastTrustDiagnostic: TrustEvaluationDiagnostic?

    init(caDER: Data, caFingerprintSHA256: String, expectedHost: String) {
        self.caDER = caDER
        self.caFingerprintSHA256 = caFingerprintSHA256
        self.expectedHost = expectedHost
        super.init()
    }

    /// Last trust decision (internal inspection seam). Bounded and non-secret.
    /// Never used as a cross-task completion fallback.
    var lastTrustDiagnostic: TrustEvaluationDiagnostic? {
        sinkLock.lock()
        defer { sinkLock.unlock() }
        return _lastTrustDiagnostic
    }

    func registerSink(_ sink: BodySink, taskID: Int) {
        sinkLock.lock()
        sinks[taskID] = sink
        sinkLock.unlock()
    }

    func unregisterSink(taskID: Int) {
        sinkLock.lock()
        sinks[taskID] = nil
        sinkLock.unlock()
    }

    private func sink(for taskID: Int) -> BodySink? {
        sinkLock.lock()
        defer { sinkLock.unlock() }
        return sinks[taskID]
    }

    /// Record the trust decision on the owning sink only.
    /// A missing/retired task id never writes another sink.
    private func recordTrustDiagnostic(_ diagnostic: TrustEvaluationDiagnostic, taskID: Int) {
        sinkLock.lock()
        _lastTrustDiagnostic = diagnostic
        let owner = sinks[taskID]
        sinkLock.unlock()
        owner?.recordTrustDiagnostic(diagnostic)
    }

    // MARK: Redirects

    /// Never follow redirects, including same-origin authentication redirects.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    // MARK: Auth challenges

    /// Task-level auth challenge. ServerTrust is delivered here **with the
    /// owning task** when the session-level handler is omitted (Apple:
    /// `urlSession(_:task:didReceive:completionHandler:)`). Unknown auth,
    /// host mismatch, and failed pinned evaluation cancel exactly once.
    ///
    /// There is intentionally no `urlSession(_:didReceive:completionHandler:)`
    /// session handler: that path has no task id and cannot own a sink.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleChallenge(challenge, taskID: task.taskIdentifier, completionHandler: completionHandler)
    }

    // MARK: Body streaming

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        guard let sink = sink(for: dataTask.taskIdentifier) else {
            completionHandler(.cancel)
            return
        }
        sink.accept(response: response, dataTask: dataTask, completionHandler: completionHandler)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        sink(for: dataTask.taskIdentifier)?.append(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        // Owner sink only. Never substitute another task's trust diagnostic.
        sink(for: task.taskIdentifier)?.complete(error: error)
        unregisterSink(taskID: task.taskIdentifier)
    }

    private func handleChallenge(
        _ challenge: URLAuthenticationChallenge,
        taskID: Int,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let method = challenge.protectionSpace.authenticationMethod
        let presentedHost = DeploymentTLSIdentity.normalizeHostForCompare(challenge.protectionSpace.host)
        let expected = DeploymentTLSIdentity.normalizeHostForCompare(expectedHost)
        let trust = challenge.protectionSpace.serverTrust

        func refuse(_ diagnostic: TrustEvaluationDiagnostic) {
            recordTrustDiagnostic(diagnostic, taskID: taskID)
            completionHandler(.cancelAuthenticationChallenge, nil)
        }

        // Unknown method / missing serverTrust: refuse without probing SecTrust.
        guard method == NSURLAuthenticationMethodServerTrust, let trust else {
            refuse(TrustEvaluationDiagnostic(
                decision: .refusedAuthMethod,
                step: "auth-method",
                host: presentedHost,
                expectedHost: expected,
                authenticationMethod: method,
                serverTrustPresent: trust != nil,
                certificateCount: 0,
                osStatus: nil,
                cfErrorDomain: nil,
                cfErrorCode: nil
            ))
            return
        }
        guard presentedHost == expected else {
            refuse(TrustEvaluationDiagnostic(
                decision: .refusedHostMismatch,
                step: "host-match",
                host: presentedHost,
                expectedHost: expected,
                authenticationMethod: method,
                serverTrustPresent: true,
                certificateCount: 0,
                osStatus: nil,
                cfErrorDomain: nil,
                cfErrorCode: nil
            ))
            return
        }

        let diagnostic = evaluateServerTrust(trust, host: presentedHost, method: method)
        recordTrustDiagnostic(diagnostic, taskID: taskID)
        if diagnostic.decision == .accepted {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// Full pinned evaluation. Pin match is necessary but not sufficient.
    ///
    /// Strictness is unchanged: single operator CA as sole anchor
    /// (`SecTrustSetAnchorCertificatesOnly(true)`), no OS/browser roots,
    /// network fetch disabled (no AIA/CA downloads), SSL host policy.
    /// Call order is preserved. Failures record native codes only.
    ///
    /// `SecTrustGetCertificateCount` is intentionally **not** called before
    /// evaluation: count access can implicitly evaluate trust under a stale
    /// policy/network state. Chain length is recorded only after the
    /// configured evaluate result. Setup/pin refusals report 0 and never probe.
    func evaluateServerTrust(
        _ trust: SecTrust,
        host: String,
        method: String = NSURLAuthenticationMethodServerTrust
    ) -> TrustEvaluationDiagnostic {
        let expected = DeploymentTLSIdentity.normalizeHostForCompare(expectedHost)
        let normalizedHost = DeploymentTLSIdentity.normalizeHostForCompare(host)

        func diagnostic(
            decision: TrustEvaluationDiagnostic.Decision,
            step: String,
            osStatus: Int32? = nil,
            cfError: CFError? = nil,
            certificateCount: Int = 0
        ) -> TrustEvaluationDiagnostic {
            // Code fields only. Never copy CFError prose (may embed identity).
            let domain = cfError.map { CFErrorGetDomain($0) as String }
            let code = cfError.map { CFErrorGetCode($0) }
            return TrustEvaluationDiagnostic(
                decision: decision,
                step: step,
                host: normalizedHost,
                expectedHost: expected,
                authenticationMethod: method,
                serverTrustPresent: true,
                certificateCount: certificateCount,
                osStatus: osStatus,
                cfErrorDomain: domain,
                cfErrorCode: code
            )
        }

        let digest = SHA256.hash(data: caDER).map { String(format: "%02x", $0) }.joined()
        guard digest == caFingerprintSHA256 else {
            return diagnostic(decision: .refusedPin, step: "pin-match")
        }

        guard let caCert = SecCertificateCreateWithData(nil, caDER as CFData) else {
            return diagnostic(decision: .refusedCAParse, step: "ca-parse")
        }
        let setAnchors = SecTrustSetAnchorCertificates(trust, [caCert] as CFArray)
        guard setAnchors == errSecSuccess else {
            return diagnostic(decision: .refusedSetup, step: "set-anchors", osStatus: setAnchors)
        }
        // No OS/browser root fallback (SecTrustSetAnchorCertificatesOnly(true)).
        let anchorsOnly = SecTrustSetAnchorCertificatesOnly(trust, true)
        guard anchorsOnly == errSecSuccess else {
            return diagnostic(decision: .refusedSetup, step: "anchors-only", osStatus: anchorsOnly)
        }
        // Online AIA/CA downloads disabled.
        let noFetch = SecTrustSetNetworkFetchAllowed(trust, false)
        guard noFetch == errSecSuccess else {
            return diagnostic(decision: .refusedSetup, step: "network-fetch-false", osStatus: noFetch)
        }

        let policy = SecPolicyCreateSSL(true, normalizedHost as CFString)
        let setPolicy = SecTrustSetPolicies(trust, policy)
        guard setPolicy == errSecSuccess else {
            return diagnostic(decision: .refusedSetup, step: "set-policies", osStatus: setPolicy)
        }

        // Evaluate exactly once under sole-anchor / no-AIA / SSL host policy.
        // Only after that result is the chain count recorded.
        var error: CFError?
        let evaluated = SecTrustEvaluateWithError(trust, &error)
        let certificateCount = SecTrustGetCertificateCount(trust)
        if evaluated {
            return diagnostic(decision: .accepted, step: "evaluate", certificateCount: certificateCount)
        }
        return diagnostic(
            decision: .refusedEvaluate,
            step: "evaluate",
            cfError: error,
            certificateCount: certificateCount
        )
    }
}
