import Foundation

/// Transport seam. Implementations must not follow redirects; the client rejects them.
public protocol HTTPTransport: Sendable {
    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse)
}

public struct URLSessionTransport: HTTPTransport {
    private let session: URLSession

    public init(session: URLSession) {
        self.session = session
    }

    public func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        let (asyncBytes, response) = try await session.bytes(for: request)
        var data = Data()
        if let http = response as? HTTPURLResponse,
           let declared = http.value(forHTTPHeaderField: "Content-Length"),
           let length = Int(declared),
           length > maxBytes {
            throw HelicoidError.invalidInput(field: "response", detail: "Response body exceeded the bounded size limit.")
        }
        for try await byte in asyncBytes {
            data.append(byte)
            if data.count > maxBytes {
                throw HelicoidError.invalidInput(field: "response", detail: "Response body exceeded the bounded size limit.")
            }
        }
        return (data, response)
    }
}

/// Bounded loopback DEVELOPMENT HTTP client for HS Server contract v1.
///
/// Enabled only with `--development-server`. Production mode stays closed.
/// This client never synthesizes a verified server key/fingerprint.
public struct LoopbackDevelopmentClient: ConnectionClient {
    public struct Configuration: Sendable {
        public var baseURL: URL
        public var managerPublicIdentity: String?
        public var requestTimeout: TimeInterval
        public var operationTimeout: TimeInterval
        public var maxResponseBytes: Int

        public init(
            baseURL: URL,
            managerPublicIdentity: String? = nil,
            requestTimeout: TimeInterval = 15,
            operationTimeout: TimeInterval = 30,
            maxResponseBytes: Int = 65_536
        ) {
            self.baseURL = baseURL
            self.managerPublicIdentity = managerPublicIdentity
            self.requestTimeout = requestTimeout
            self.operationTimeout = operationTimeout
            self.maxResponseBytes = maxResponseBytes
        }

        public var hasFinitePositiveBounds: Bool {
            requestTimeout > 0 && requestTimeout.isFinite
                && operationTimeout > 0 && operationTimeout.isFinite
                && maxResponseBytes > 0
        }
    }

    /// Result of connect. Development transport is explicit and never claims verified trust.
    public enum ConnectOutcome: Sendable, Equatable {
        case developmentReady(canonical: LoopbackAddressPolicy.CanonicalTarget, health: HealthDTO)
        case needsSetup(canonical: LoopbackAddressPolicy.CanonicalTarget, health: HealthDTO)
        case notAcceptingOperations(canonical: LoopbackAddressPolicy.CanonicalTarget, health: HealthDTO)
    }

    private let transport: any HTTPTransport
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder
    private let tokenBox: TokenBox
    private let configBox: ConfigBox

    public init(
        configuration: Configuration,
        transport: (any HTTPTransport)? = nil,
        tokenBox: TokenBox = TokenBox()
    ) {
        precondition(configuration.hasFinitePositiveBounds, "Configuration bounds must be finite and positive")
        self.tokenBox = tokenBox
        self.configBox = ConfigBox(configuration: configuration)
        self.decoder = JSONDecoder()
        self.encoder = JSONEncoder()

        if let transport {
            self.transport = transport
        } else {
            let sessionConfig = URLSessionConfiguration.ephemeral
            sessionConfig.timeoutIntervalForRequest = configuration.requestTimeout
            sessionConfig.timeoutIntervalForResource = configuration.operationTimeout
            sessionConfig.httpShouldSetCookies = false
            sessionConfig.httpCookieAcceptPolicy = .never
            sessionConfig.urlCache = nil
            sessionConfig.httpMaximumConnectionsPerHost = 2
            // Redirects are never followed (see LoopbackRedirectDelegate).
            let session = URLSession(
                configuration: sessionConfig,
                delegate: LoopbackRedirectDelegate(),
                delegateQueue: nil
            )
            self.transport = URLSessionTransport(session: session)
        }
    }

    // MARK: - Session binding

    /// Invalidate any previous session/token before a new connect.
    public func invalidatePreviousSession() {
        tokenBox.token = nil
        configBox.boundBaseURL = nil
        configBox.connectedIdentity = nil
    }

    /// Exact canonical base used for all calls after a successful connect.
    public var boundBaseURL: URL? {
        configBox.boundBaseURL
    }

    // MARK: - ConnectionClient

    public func validateAddress(_ address: String) async -> AddressValidation {
        switch LoopbackAddressPolicy.validate(address) {
        case .allowed:
            return AddressValidation(outcome: .ok)
        case .refused(let reason):
            return AddressValidation(outcome: .invalid(detail: reason.message))
        }
    }

    public func connect(address: String) async -> Result<ServerIdentity, HelicoidError> {
        invalidatePreviousSession()

        let canonical: LoopbackAddressPolicy.CanonicalTarget
        switch LoopbackAddressPolicy.validate(address) {
        case .allowed(let target):
            canonical = target
        case .refused(let reason):
            return .failure(.invalidInput(field: "Server address", detail: reason.message))
        }

        do {
            let health = try await get(
                HealthDTO.self,
                path: "/health",
                authorized: false,
                base: canonical.baseURL
            )

            guard Self.validateHealth(health) else {
                return .failure(.serverContractUnavailable)
            }

            if !health.acceptingAuthorizedOperations {
                // Degraded / not ready. Do not claim a ready development transport.
                configBox.boundBaseURL = canonical.baseURL
                return .failure(.setupBlocked(reason: "Server is not accepting authorized operations. It may need setup or recovery."))
            }

            // Development transport only. Never synthesize a verified fingerprint or key.
            let identity = ServerIdentity.developmentTransport(canonical: canonical)
            configBox.boundBaseURL = canonical.baseURL
            configBox.connectedIdentity = identity
            return .success(identity)
        } catch let error as HelicoidError {
            return .failure(error)
        } catch {
            return .failure(.unreachable)
        }
    }

    /// Development connect detail without fabricating trust.
    public func connectDevelopment(address: String) async -> Result<ConnectOutcome, HelicoidError> {
        invalidatePreviousSession()

        let canonical: LoopbackAddressPolicy.CanonicalTarget
        switch LoopbackAddressPolicy.validate(address) {
        case .allowed(let target):
            canonical = target
        case .refused(let reason):
            return .failure(.invalidInput(field: "Server address", detail: reason.message))
        }

        do {
            let health = try await get(
                HealthDTO.self,
                path: "/health",
                authorized: false,
                base: canonical.baseURL
            )
            guard Self.validateHealth(health) else {
                return .failure(.serverContractUnavailable)
            }
            configBox.boundBaseURL = canonical.baseURL
            configBox.connectedIdentity = ServerIdentity.developmentTransport(canonical: canonical)

            if !health.bootstrapCompleted {
                return .success(.needsSetup(canonical: canonical, health: health))
            }
            if !health.acceptingAuthorizedOperations {
                return .success(.notAcceptingOperations(canonical: canonical, health: health))
            }
            return .success(.developmentReady(canonical: canonical, health: health))
        } catch let error as HelicoidError {
            return .failure(error)
        } catch {
            return .failure(.unreachable)
        }
    }

    public static func validateHealth(_ health: HealthDTO) -> Bool {
        guard health.schemaVersion == 1 else { return false }
        switch health.status {
        case "ok": return health.acceptingAuthorizedOperations && health.bootstrapCompleted
        case "degraded": return !health.acceptingAuthorizedOperations
        default: return false
        }
    }

    public func trust(identity: ServerIdentity, address: String) async -> Result<Void, HelicoidError> {
        // Development transport never records a verified production identity.
        _ = identity
        _ = address
        return .success(())
    }

    public func signIn(username: String, password: String) async -> Result<OperatorID, HelicoidError> {
        // Clear any previous bearer before attempt and on every failure path.
        tokenBox.token = nil

        guard let base = configBox.boundBaseURL else {
            return .failure(.notConfigured)
        }

        struct LoginBody: Encodable {
            let username: String
            let password: String
            let manager_public_identity: String?
        }

        let body = LoginBody(
            username: username,
            password: password,
            manager_public_identity: configBox.configuration.managerPublicIdentity
        )

        do {
            let response = try await post(
                LoginResponseDTO.self,
                path: "/v1/auth/login",
                body: body,
                authorized: false,
                base: base
            )
            // Validate login payload before accepting.
            let validation = Self.validateLogin(response, requestedManagerIdentity: configBox.configuration.managerPublicIdentity)
            if let problem = validation {
                tokenBox.token = nil
                return .failure(problem)
            }
            tokenBox.token = response.token
            configBox.sessionAccountID = response.account.id
            return .success(OperatorID(response.account.id))
        } catch let error as HelicoidError {
            tokenBox.token = nil
            return .failure(error)
        } catch {
            tokenBox.token = nil
            return .failure(.authenticationFailed(detail: "Sign-in request failed."))
        }
    }

    /// Validate login response fields. Returns an error when the payload is not acceptable.
    public static func validateLogin(
        _ response: LoginResponseDTO,
        requestedManagerIdentity: String?
    ) -> HelicoidError? {
        if response.token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return .authenticationFailed(detail: "Server returned an empty session token.")
        }
        if response.account.id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return .authenticationFailed(detail: "Server returned an empty account id.")
        }
        if response.account.username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return .authenticationFailed(detail: "Server returned an empty account username.")
        }
        if response.account.state != "active" {
            return .permissionDenied(detail: "Account state is \(response.account.state).")
        }
        guard let revision = response.account.revision, revision > 0,
              response.account.capabilities != nil else {
            return .authenticationFailed(detail: "Server returned an invalid account revision.")
        }
        guard let expires = response.expiresAtUnix,
              expires > Int(Date().timeIntervalSince1970), expires <= 253_402_300_799 else {
            return .authenticationFailed(detail: "Session expiry is missing or invalid.")
        }
        guard response.mfa != nil else {
            return .authenticationFailed(detail: "Server returned no MFA state.")
        }
        // Manager fixture must match the approved response when a manager is present.
        if let requested = requestedManagerIdentity, !requested.isEmpty {
            guard let manager = response.manager else {
                return .permissionDenied(detail: "Manager identity was requested but the server returned no manager binding.")
            }
            if manager.publicIdentity != requested {
                return .permissionDenied(detail: "Manager identity mismatch.")
            }
            if !manager.isApproved {
                return .permissionDenied(detail: "Manager not approved: lifecycle \(manager.lifecycleState).")
            }
        }
        // MFA: this foundation reports unavailable; do not pretend a factor was satisfied.
        if let mfa = response.mfa, mfa.required {
            return .authenticationFailed(detail: "MFA is required but not implemented in this foundation.")
        }
        return nil
    }

    public func authorizedInventory() async -> Result<[Computer], HelicoidError> {
        guard let base = configBox.boundBaseURL else {
            return .failure(.notConfigured)
        }
        guard tokenBox.token != nil else {
            return .failure(.notConfigured)
        }

        do {
            let inventory = try await get(InventoryResponseDTO.self, path: "/v1/computers", authorized: true, base: base)
            if let problem = Self.validateInventory(inventory) {
                return .failure(problem)
            }
            let mapped = inventory.computers.map(mapComputer)
            return .success(mapped)
        } catch let error as HelicoidError {
            // Authentication failure must not retain previous inventory (caller clears).
            return .failure(error)
        } catch {
            return .failure(.offline)
        }
    }

    /// Validate inventory payload. IDs must be non-empty, bounded, unique; page cap 100.
    public static func validateInventory(_ inventory: InventoryResponseDTO) -> HelicoidError? {
        if inventory.computers.count > 100 {
            return .invalidInput(field: "inventory", detail: "Inventory exceeded max_page_size 100.")
        }
        var seen = Set<String>()
        for computer in inventory.computers {
            let id = computer.id.trimmingCharacters(in: .whitespacesAndNewlines)
            if id.isEmpty {
                return .invalidInput(field: "inventory", detail: "Computer id must not be empty.")
            }
            if id.count > 128 {
                return .invalidInput(field: "inventory", detail: "Computer id exceeded 128 characters.")
            }
            if seen.contains(id) {
                return .invalidInput(field: "inventory", detail: "Duplicate computer id in inventory.")
            }
            seen.insert(id)
        }
        return nil
    }

    public func managerApprovalState() async -> Result<ManagerApprovalState, HelicoidError> {
        guard let base = configBox.boundBaseURL else {
            return .failure(.notConfigured)
        }
        do {
            let session = try await get(SessionResponseDTO.self, path: "/v1/auth/session", authorized: true, base: base)
            guard let manager = session.manager else {
                return .success(.unknown)
            }
            if manager.isApproved { return .success(.approved) }
            if manager.isPending { return .success(.pending) }
            if manager.isRevoked { return .success(.denied) }
            return .success(.unknown)
        } catch let error as HelicoidError {
            return .failure(error)
        } catch {
            return .failure(.offline)
        }
    }

    public func signOut() async {
        _ = await signOutReportingRemoteFailure()
    }

    /// Clears local token/identity even when remote logout fails.
    public func signOutReportingRemoteFailure() async -> HelicoidError? {
        let token = tokenBox.token
        let base = configBox.boundBaseURL
        // Always clear local material first.
        tokenBox.token = nil
        configBox.sessionAccountID = nil
        configBox.boundBaseURL = nil
        configBox.connectedIdentity = nil

        guard token != nil, let base else { return nil }
        do {
            _ = try await post(
                EmptySuccessDTO.self,
                path: "/v1/auth/logout",
                body: EmptySuccessDTO(),
                authorized: true,
                base: base,
                preClearedToken: token
            )
            return nil
        } catch let error as HelicoidError {
            return error
        } catch {
            return .offline
        }
    }

    // MARK: - Mapping

    public static func mapEnrollmentState(_ raw: String) -> (isOnline: Bool, needsAttention: Bool, statusLabel: String) {
        switch raw {
        case "enrolled":
            return (false, false, "Enrolled")
        case "pending":
            return (false, true, "Pending")
        case "quarantined":
            return (false, true, "Quarantined")
        case "revoked":
            return (false, true, "Revoked")
        default:
            return (false, true, "Unavailable")
        }
    }

    private func mapComputer(_ dto: ComputerDTO) -> Computer {
        let status = Self.mapEnrollmentState(dto.enrollmentState)
        return Computer(
            id: ComputerID(dto.id),
            name: dto.friendlyName ?? dto.id,
            trustedUserName: nil,
            isOnline: status.isOnline,
            needsAttention: status.needsAttention,
            groupIDs: [],
            enrollmentState: dto.enrollmentState,
            statusLabel: status.statusLabel,
            publicIdentity: dto.publicIdentity
        )
    }

    // MARK: - HTTP plumbing

    private struct SessionIdentity {
        let identity: String?
    }

    private func requestURL(path: String, base: URL) throws -> URL {
        guard let url = URL(string: path, relativeTo: base)?.absoluteURL else {
            throw HelicoidError.invalidInput(field: "path", detail: "Invalid request path")
        }
        // Request URLs may have a path; host must remain allowed loopback.
        switch LoopbackAddressPolicy.validateRequestURL(url.absoluteString) {
        case .allowed:
            return url
        case .refused(let reason):
            throw HelicoidError.invalidInput(field: "url", detail: reason.message)
        }
    }

    private func get<T: Decodable & Sendable>(
        _ type: T.Type,
        path: String,
        authorized: Bool,
        base: URL
    ) async throws -> T {
        let url = try requestURL(path: path, base: base)
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if authorized {
            guard let token = tokenBox.token else {
                throw HelicoidError.notConfigured
            }
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        return try await perform(request, as: T.self)
    }

    private func post<T: Decodable & Sendable, B: Encodable>(
        _ type: T.Type,
        path: String,
        body: B,
        authorized: Bool,
        base: URL,
        preClearedToken: String? = nil
    ) async throws -> T {
        let data = try encoder.encode(body)
        let url = try requestURL(path: path, base: base)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = data
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if authorized {
            let token = preClearedToken ?? tokenBox.token
            if let token {
                request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            } else {
                throw HelicoidError.notConfigured
            }
        }
        return try await perform(request, as: T.self)
    }

    private func perform<T: Decodable & Sendable>(_ request: URLRequest, as type: T.Type) async throws -> T {
        let config = configBox.configuration
        let maxBytes = config.maxResponseBytes
        let operationTimeout = config.operationTimeout

        return try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask {
                let (data, response) = try await transport.bytes(for: request, maxBytes: maxBytes)
                return try Self.decodeResponse(T.self, data: data, response: response, maxBytes: maxBytes)
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(operationTimeout * 1_000_000_000))
                throw HelicoidError.offline
            }
            guard let first = try await group.next() else {
                throw HelicoidError.offline
            }
            group.cancelAll()
            return first
        }
    }

    /// 2xx check, bounded body, and error-envelope parsing.
    public static func decodeResponse<T: Decodable & Sendable>(
        _ type: T.Type,
        data: Data,
        response: URLResponse,
        maxBytes: Int
    ) throws -> T {
        guard let http = response as? HTTPURLResponse else {
            throw HelicoidError.offline
        }
        // Error and success bodies are both bounded.
        if data.count > maxBytes {
            throw HelicoidError.invalidInput(field: "response", detail: "Response body exceeded the bounded size limit.")
        }
        let decoder = JSONDecoder()

        if (200...299).contains(http.statusCode) {
            if T.self == EmptySuccessDTO.self {
                if let empty = EmptySuccessDTO() as? T {
                    return empty
                }
            }
            do {
                return try decoder.decode(T.self, from: data)
            } catch {
                throw HelicoidError.invalidInput(field: "response", detail: "Malformed success payload.")
            }
        }

        if let envelope = try? decoder.decode(ServerErrorEnvelope.self, from: data) {
            let code = envelope.error.code
            let message = envelope.error.message
            switch code {
            case "unauthorized":
                throw HelicoidError.permissionDenied(detail: message)
            case "forbidden":
                if message.lowercased().contains("manager") {
                    throw HelicoidError.permissionDenied(detail: "Manager not approved: \(message)")
                }
                throw HelicoidError.permissionDenied(detail: message)
            case "bad_request", "unprocessable":
                throw HelicoidError.invalidInput(field: "request", detail: message)
            case "rate_limited":
                throw HelicoidError.permissionDenied(detail: message)
            case "not_implemented":
                throw HelicoidError.serverContractUnavailable
            case "security_state_unavailable":
                throw HelicoidError.setupBlocked(reason: message)
            case "not_found":
                throw HelicoidError.invalidInput(field: "resource", detail: message)
            case "conflict":
                throw HelicoidError.setupBlocked(reason: message)
            case "internal":
                throw HelicoidError.offline
            default:
                throw HelicoidError.permissionDenied(detail: message)
            }
        }

        if http.statusCode == 401 {
            throw HelicoidError.permissionDenied(detail: "Authentication required or expired.")
        }
        if http.statusCode == 403 {
            throw HelicoidError.permissionDenied(detail: "Manager not approved or account not permitted.")
        }
        throw HelicoidError.offline
    }
}

/// Explicit development-transport identity. Never a verified production fingerprint.
public extension ServerIdentity {
    static func developmentTransport(canonical: LoopbackAddressPolicy.CanonicalTarget) -> ServerIdentity {
        ServerIdentity(
            deploymentName: "Local development server",
            verificationFingerprint: "",
            trustedSourceNote: "Local development loopback transport only. No production server identity is claimed or verified."
        )
    }

    /// True when this identity is development transport (not verified trust).
    var isDevelopmentTransport: Bool {
        verificationFingerprint.isEmpty && deploymentName == "Local development server"
    }
}

/// Memory-only token holder. Not persisted.
public final class TokenBox: @unchecked Sendable {
    private let lock = NSLock()
    private var _token: String?

    public init(token: String? = nil) {
        self._token = token
    }

    public var token: String? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _token
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _token = newValue
        }
    }
}

/// Mutable runtime binding after connect (canonical base + session account).
final class ConfigBox: @unchecked Sendable {
    private let lock = NSLock()
    private var _configuration: LoopbackDevelopmentClient.Configuration
    private var _boundBaseURL: URL?
    private var _connectedIdentity: ServerIdentity?
    private var _sessionAccountID: String?

    init(configuration: LoopbackDevelopmentClient.Configuration) {
        self._configuration = configuration
    }

    var configuration: LoopbackDevelopmentClient.Configuration {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _configuration
        }
    }

    var boundBaseURL: URL? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _boundBaseURL
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _boundBaseURL = newValue
        }
    }

    var connectedIdentity: ServerIdentity? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _connectedIdentity
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _connectedIdentity = newValue
        }
    }

    var sessionAccountID: String? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _sessionAccountID
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            _sessionAccountID = newValue
        }
    }
}

/// Never follows redirects — bearer must not leak to another service/port.
final class LoopbackRedirectDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @Sendable (URLRequest?) -> Void
    ) {
        // Reject all redirects, including other loopback ports.
        completionHandler(nil)
    }
}
