import Testing
import Foundation
@testable import HelicoidCore

/// Safe in-memory fixture transport. Never opens a socket.
final class FixtureTransport: HTTPTransport, @unchecked Sendable {
    struct Stub {
        var status: Int
        var body: Data
        var error: Error?
    }

    private let lock = NSLock()
    private var _stub = Stub(status: 200, body: Data("{}".utf8), error: nil)
    private var _lastRequest: URLRequest?
    private var _requestCount = 0

    var stub: Stub {
        get { sync { $0.stub } }
        set { sync { $0.stub = newValue } }
    }

    var lastRequest: URLRequest? {
        sync { $0.lastRequest }
    }

    var requestCount: Int {
        sync { $0.requestCount }
    }

    private struct Snapshot {
        var stub: Stub
        var lastRequest: URLRequest?
        var requestCount: Int
    }

    /// Synchronous critical section (NSLock is unavailable from async contexts).
    private func sync<T>(_ body: (inout Snapshot) -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        var snapshot = Snapshot(stub: _stub, lastRequest: _lastRequest, requestCount: _requestCount)
        let result = body(&snapshot)
        _stub = snapshot.stub
        _lastRequest = snapshot.lastRequest
        _requestCount = snapshot.requestCount
        return result
    }

    func bytes(for request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        let current: Stub = sync { snapshot in
            snapshot.requestCount += 1
            snapshot.lastRequest = request
            return snapshot.stub
        }

        if let error = current.error {
            throw error
        }
        if current.body.count > maxBytes {
            throw HelicoidError.invalidInput(field: "response", detail: "Response body exceeded the bounded size limit.")
        }
        let url = request.url ?? URL(string: "http://127.0.0.1:8787")!
        let response = HTTPURLResponse(
            url: url,
            statusCode: current.status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        return (current.body, response)
    }
}

@Suite("Loopback address policy")
struct LoopbackAddressPolicyTests {

    private func isAllowed(_ raw: String) -> Bool {
        if case .allowed = LoopbackAddressPolicy.validate(raw) { return true }
        return false
    }

    private func reason(_ raw: String) -> LoopbackAddressPolicy.Reason? {
        if case .refused(let r) = LoopbackAddressPolicy.validate(raw) { return r }
        return nil
    }

    @Test("Allows literal IPv4 loopback only")
    func literalIPv4() {
        #expect(isAllowed("http://127.0.0.1:8787"))
        #expect(isAllowed("http://127.0.0.1"))
        #expect(isAllowed("http://127.5.5.5:8787"))
        #expect(isAllowed("http://127.255.255.255:1"))
    }

    @Test("Allows exact IPv6 loopback")
    func literalIPv6() {
        #expect(isAllowed("http://[::1]:8787"))
        #expect(isAllowed("http://[::1]"))
    }

    @Test("Rewrites localhost to 127.0.0.1 without DNS")
    func localhostRewrite() {
        guard case .allowed(let target) = LoopbackAddressPolicy.validate("http://localhost:8787") else {
            Issue.record("localhost must be allowed after rewrite")
            return
        }
        #expect(target.host == "127.0.0.1")
        #expect(target.url.host == "127.0.0.1")
        #expect(!target.url.absoluteString.contains("localhost"))
    }

    @Test("Refuses malicious 127 hostname")
    func malicious127Hostname() {
        #expect(!isAllowed("http://127.attacker.example:8787"))
        #expect(reason("http://127.attacker.example:8787") == .hostnameNotAllowed)
        #expect(!isAllowed("http://127.0.0.1.attacker.example"))
        #expect(!isAllowed("http://localhost.attacker.example:8787"))
    }

    @Test("Refuses remote hosts and non-loopback literals")
    func remoteHosts() {
        #expect(reason("http://10.0.0.5:8787") == .remoteHost)
        #expect(reason("http://192.168.1.10:8787") == .remoteHost)
        #expect(reason("http://8.8.8.8") == .remoteHost)
        #expect(reason("http://example.com:8787") == .hostnameNotAllowed)
        #expect(reason("http://[2001:db8::1]") == .remoteHost || reason("http://[2001:db8::1]") == .hostnameNotAllowed)
    }

    @Test("Refuses embedded credentials")
    func embeddedCredentials() {
        #expect(reason("http://user:pass@127.0.0.1:8787") == .embeddedCredentials)
        #expect(reason("http://user@localhost:8787") == .embeddedCredentials)
    }

    @Test("Refuses fragments and queries")
    func fragmentsQueries() {
        #expect(reason("http://127.0.0.1:8787#admin") == .fragmentPresent)
        #expect(reason("http://127.0.0.1/#/setup") == .fragmentPresent)
        #expect(reason("http://127.0.0.1:8787?token=1") == .queryPresent)
    }

    @Test("Refuses path beyond root")
    func pathNotRoot() {
        #expect(reason("http://127.0.0.1:8787/api") == .pathNotRoot)
    }

    @Test("Refuses empty and invalid")
    func emptyInvalid() {
        #expect(reason("") == .empty)
        #expect(reason("   ") == .empty)
        #expect(reason("not a url at all") == .invalidURL)
        #expect(reason("127.0.0.1:8787") == .invalidURL)
    }

    @Test("Refuses non-http schemes")
    func schemes() {
        #expect(reason("https://127.0.0.1:8787") == .unsupportedScheme)
        #expect(reason("ftp://127.0.0.1") == .unsupportedScheme)
        #expect(reason("file:///etc/passwd") == .unsupportedScheme)
    }

    @Test("All redirects refused including other loopback ports")
    func redirectsNeverFollowed() {
        let same = URL(string: "http://127.0.0.1:8787/health")!
        let otherPort = URL(string: "http://127.0.0.1:9999/health")!
        let remote = URL(string: "http://evil.example/steal")!
        #expect(!LoopbackAddressPolicy.allowRedirect(from: same, to: same))
        #expect(!LoopbackAddressPolicy.allowRedirect(from: same, to: otherPort))
        #expect(!LoopbackAddressPolicy.allowRedirect(from: same, to: remote))
    }

    @Test("Strict IPv4 parse rejects octal and short forms")
    func strictIPv4Parse() {
        #expect(LoopbackAddressPolicy.parseIPv4Literal("127.0.0.1") == 0x7F000001)
        #expect(LoopbackAddressPolicy.parseIPv4Literal("127.attacker.example") == nil)
        #expect(LoopbackAddressPolicy.parseIPv4Literal("0177.0.0.1") == nil)
        #expect(LoopbackAddressPolicy.parseIPv4Literal("127.0.1") == nil)
        #expect(LoopbackAddressPolicy.parseIPv4Literal("256.0.0.1") == nil)
    }
}

@Suite("HTTP response decoding")
struct HTTPDecodeTests {

    private func httpResponse(status: Int, url: String = "http://127.0.0.1:8787/health") -> HTTPURLResponse {
        HTTPURLResponse(
            url: URL(string: url)!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
    }

    @Test("Parses health success")
    func healthSuccess() throws {
        let json = """
        {"status":"ok","accepting_authorized_operations":true,"schema_version":1,
         "bootstrap_completed":true,"features":{"local_accounts":true}}
        """.data(using: .utf8)!
        let value = try LoopbackDevelopmentClient.decodeResponse(
            HealthDTO.self,
            data: json,
            response: httpResponse(status: 200),
            maxBytes: 1_000_000
        )
        #expect(value.status == "ok")
        #expect(value.schemaVersion == 1)
        #expect(value.acceptingAuthorizedOperations)
    }

    @Test("Parses login DTO with manager")
    func loginSuccess() throws {
        let json = """
        {"token":"tok","expires_at_unix":1760086400,
         "account":{"id":"acc","username":"admin","state":"active","revision":1},
         "manager":{"id":"m1","public_identity":"dev-key","friendly_name":"Mac","lifecycle_state":"approved","approved_at_unix":1},
         "mfa":{"required":false,"available":false,"reason":"mfa_not_implemented_in_this_foundation"}}
        """.data(using: .utf8)!
        let value = try LoopbackDevelopmentClient.decodeResponse(
            LoginResponseDTO.self,
            data: json,
            response: httpResponse(status: 200, url: "http://127.0.0.1:8787/v1/auth/login"),
            maxBytes: 1_000_000
        )
        #expect(value.token == "tok")
        #expect(value.manager?.isApproved == true)
    }

    @Test("Parses inventory with enrollment states")
    func inventorySuccess() throws {
        let json = """
        {"computers":[
          {"id":"c1","public_identity":"e1","friendly_name":"Lab Mac","platform":"macos","enrollment_state":"enrolled","enrollment_epoch":1},
          {"id":"c2","public_identity":"e2","friendly_name":"Pending PC","platform":"windows","enrollment_state":"pending","enrollment_epoch":1}
        ],"scope_is_explicit":true,"max_page_size":100}
        """.data(using: .utf8)!
        let value = try LoopbackDevelopmentClient.decodeResponse(
            InventoryResponseDTO.self,
            data: json,
            response: httpResponse(status: 200, url: "http://127.0.0.1:8787/v1/computers"),
            maxBytes: 1_000_000
        )
        #expect(value.computers.count == 2)
        #expect(value.computers[0].enrollmentState == "enrolled")
        #expect(value.computers[1].enrollmentState == "pending")
    }

    @Test("403 manager approval maps to permission denied with manager detail")
    func forbiddenManager() {
        let json = """
        {"error":{"code":"forbidden","message":"manager is pending approval"}}
        """.data(using: .utf8)!
        #expect(throws: HelicoidError.self) {
            try LoopbackDevelopmentClient.decodeResponse(
                LoginResponseDTO.self,
                data: json,
                response: httpResponse(status: 403, url: "http://127.0.0.1:8787/v1/auth/login"),
                maxBytes: 1_000_000
            )
        }
        do {
            _ = try LoopbackDevelopmentClient.decodeResponse(
                LoginResponseDTO.self,
                data: json,
                response: httpResponse(status: 403),
                maxBytes: 1_000_000
            )
            Issue.record("Expected failure")
        } catch let error as HelicoidError {
            guard case .permissionDenied(let detail) = error else {
                Issue.record("Expected permissionDenied, got \(error)")
                return
            }
            #expect(detail.lowercased().contains("manager"))
        } catch {
            Issue.record("Unexpected error type \(error)")
        }
    }

    @Test("Error envelope codes map distinctly")
    func errorCodes() {
        func expectCode(_ code: String, status: Int, matches: (HelicoidError) -> Bool) {
            let json = "{\"error\":{\"code\":\"\(code)\",\"message\":\"msg\"}}".data(using: .utf8)!
            do {
                _ = try LoopbackDevelopmentClient.decodeResponse(
                    HealthDTO.self,
                    data: json,
                    response: httpResponse(status: status),
                    maxBytes: 1_000_000
                )
                Issue.record("Expected failure for \(code)")
            } catch let error as HelicoidError {
                if !matches(error) {
                    Issue.record("Code \(code) mapped to \(error), expected a different case")
                }
            } catch {
                Issue.record("Unexpected \(error)")
            }
        }

        expectCode("unauthorized", status: 401) { if case .permissionDenied = $0 { return true }; return false }
        expectCode("bad_request", status: 400) { if case .invalidInput = $0 { return true }; return false }
        expectCode("not_implemented", status: 501) { if case .serverContractUnavailable = $0 { return true }; return false }
        expectCode("security_state_unavailable", status: 503) { if case .setupBlocked = $0 { return true }; return false }
    }

    @Test("Bounded response size is enforced")
    func boundedBody() {
        let big = Data(repeating: 0x20, count: 2048)
        #expect(throws: HelicoidError.self) {
            try LoopbackDevelopmentClient.decodeResponse(
                HealthDTO.self,
                data: big,
                response: httpResponse(status: 200),
                maxBytes: 256
            )
        }
    }

    @Test("Malformed success payload is rejected")
    func malformedSuccess() {
        let junk = "not-json".data(using: .utf8)!
        #expect(throws: HelicoidError.self) {
            try LoopbackDevelopmentClient.decodeResponse(
                HealthDTO.self,
                data: junk,
                response: httpResponse(status: 200),
                maxBytes: 1_000_000
            )
        }
    }

    @Test("Bare 401 without envelope still maps")
    func bare401() {
        #expect(throws: HelicoidError.self) {
            try LoopbackDevelopmentClient.decodeResponse(
                HealthDTO.self,
                data: Data(),
                response: httpResponse(status: 401),
                maxBytes: 1_000_000
            )
        }
    }

    @Test("Empty success for logout type")
    func emptySuccess() throws {
        let value = try LoopbackDevelopmentClient.decodeResponse(
            EmptySuccessDTO.self,
            data: Data(),
            response: httpResponse(status: 204, url: "http://127.0.0.1:8787/v1/auth/logout"),
            maxBytes: 1_000_000
        )
        #expect(value == EmptySuccessDTO())
    }
}

@Suite("Enrollment status mapping")
struct EnrollmentMappingTests {
    @Test("Does not invent online presence")
    func honestStatuses() {
        let enrolled = LoopbackDevelopmentClient.mapEnrollmentState("enrolled")
        #expect(enrolled.isOnline == false)
        #expect(enrolled.statusLabel == "Enrolled")

        let pending = LoopbackDevelopmentClient.mapEnrollmentState("pending")
        #expect(pending.isOnline == false)
        #expect(pending.needsAttention)
        #expect(pending.statusLabel == "Pending")

        let quarantined = LoopbackDevelopmentClient.mapEnrollmentState("quarantined")
        #expect(quarantined.statusLabel == "Quarantined")

        let revoked = LoopbackDevelopmentClient.mapEnrollmentState("revoked")
        #expect(revoked.statusLabel == "Revoked")

        let unknown = LoopbackDevelopmentClient.mapEnrollmentState("something")
        #expect(unknown.statusLabel == "Unavailable")
    }
}

@Suite("Development client with fixture transport")
struct DevelopmentClientTransportTests {

    private func makeClient(
        address: String = "http://127.0.0.1:8787",
        managerIdentity: String? = "dev-manager-key"
    ) throws -> (LoopbackDevelopmentClient, TokenBox, FixtureTransport) {
        let transport = FixtureTransport()
        let box = TokenBox()
        guard let base = URL(string: address) else {
            struct E: Error {}
            throw E()
        }
        let client = LoopbackDevelopmentClient(
            configuration: LoopbackDevelopmentClient.Configuration(
                baseURL: base,
                managerPublicIdentity: managerIdentity
            ),
            transport: transport,
            tokenBox: box
        )
        return (client, box, transport)
    }

    /// Bind a session via successful development connect (health 200 / ready).
    private func connectReady(_ client: LoopbackDevelopmentClient, _ transport: FixtureTransport) async throws {
        transport.stub = FixtureTransport.Stub(
            status: 200,
            body: Data("""
            {"status":"ok","accepting_authorized_operations":true,"schema_version":1,
             "bootstrap_completed":true,"features":{"local_accounts":true}}
            """.utf8),
            error: nil
        )
        let result = await client.connectDevelopment(address: "http://127.0.0.1:8787")
        guard case .success = result else {
            Issue.record("connectDevelopment should succeed: \(result)")
            throw CancellationError()
        }
    }

    @Test("Login stores token in memory and sends manager identity")
    func loginFlow() async throws {
        let (client, box, transport) = try makeClient()
        try await connectReady(client, transport)
        transport.stub = FixtureTransport.Stub(
            status: 200,
            body: Data("""
            {"token":"secret-token","account":{"id":"a","username":"admin","state":"active","revision":1,"capabilities":{"operate":true,"manage_enrollment":true,"manage_access":true,"manage_accounts":true,"manage_security":true}},
             "manager":{"id":"m","public_identity":"dev-manager-key","lifecycle_state":"approved","approved_at_unix":9999999999},
             "mfa":{"required":false,"available":false},"expires_at_unix":9999999999}
            """.utf8),
            error: nil
        )
        let result = await client.signIn(username: "admin", password: "password12345")
        guard case .success(let op) = result else {
            Issue.record("Login should succeed: \(result)")
            return
        }
        #expect(op.rawValue == "a")
        #expect(box.token == "secret-token")
        if let body = transport.lastRequest?.httpBody {
            let text = String(data: body, encoding: .utf8) ?? ""
            #expect(text.contains("dev-manager-key"))
            #expect(text.contains("password12345"))
        }
    }

    @Test("403 manager approval failure is distinct")
    func approvalDenied() async throws {
        let (client, box, transport) = try makeClient()
        try await connectReady(client, transport)
        transport.stub = FixtureTransport.Stub(
            status: 403,
            body: Data("{\"error\":{\"code\":\"forbidden\",\"message\":\"manager is pending approval\"}}".utf8),
            error: nil
        )
        let result = await client.signIn(username: "admin", password: "password12345")
        guard case .failure(let error) = result else {
            Issue.record("Expected failure")
            return
        }
        guard case .permissionDenied(let detail) = error else {
            Issue.record("Expected permissionDenied, got \(error)")
            return
        }
        #expect(detail.lowercased().contains("manager"))
        #expect(box.token == nil)
    }

    @Test("Sign-out clears token even when remote logout fails")
    func signOutClearsOnFailure() async throws {
        let (client, box, transport) = try makeClient()
        try await connectReady(client, transport)
        box.token = "live-token"
        transport.stub = FixtureTransport.Stub(
            status: 500,
            body: Data("{\"error\":{\"code\":\"internal\",\"message\":\"boom\"}}".utf8),
            error: nil
        )
        let remoteError = await client.signOutReportingRemoteFailure()
        #expect(box.token == nil)
        #expect(remoteError != nil)
    }

    @Test("Sign-out with empty token does not call network")
    func signOutNoToken() async throws {
        // request count is per-transport
        let (client, box, transport) = try makeClient()
        box.token = nil
        await client.signOut()
        #expect(transport.requestCount == 0)
        #expect(box.token == nil)
    }

    @Test("Inventory maps enrollment without inventing online")
    func inventoryMapping() async throws {
        let (client, box, transport) = try makeClient()
        try await connectReady(client, transport)
        box.token = "tok"
        transport.stub = FixtureTransport.Stub(
            status: 200,
            body: Data("""
            {"computers":[
              {"id":"c1","public_identity":"e1","friendly_name":"Lab","platform":"macos","enrollment_state":"enrolled"}
            ],"scope_is_explicit":true}
            """.utf8),
            error: nil
        )
        let result = await client.authorizedInventory()
        guard case .success(let computers) = result else {
            Issue.record("Inventory failed: \(result)")
            return
        }
        #expect(computers.count == 1)
        #expect(computers[0].isOnline == false)
        #expect(computers[0].statusLabel == "Enrolled")
        #expect(computers[0].name == "Lab")
    }

    @Test("Unauthorized inventory does not invent data")
    func inventoryUnauthorized() async throws {
        let (client, box, transport) = try makeClient()
        try await connectReady(client, transport)
        box.token = "expired"
        transport.stub = FixtureTransport.Stub(
            status: 401,
            body: Data("{\"error\":{\"code\":\"unauthorized\",\"message\":\"expired\"}}".utf8),
            error: nil
        )
        let result = await client.authorizedInventory()
        guard case .failure = result else {
            Issue.record("Must not succeed without authority")
            return
        }
    }

    @Test("Validation refuses non-loopback before any request")
    func validateRefusesRemote() async throws {
        // request count is per-transport
        let (client, _, transport) = try makeClient()
        let result = await client.validateAddress("http://10.0.0.1:8787")
        if case .ok = result.outcome {
            Issue.record("Remote address must not validate")
        }
        #expect(transport.requestCount == 0)
    }

    @Test("Connect against health never fabricates a production fingerprint")
    func connectIdentityIsDevelopmentOnly() async throws {
        let (client, _, transport) = try makeClient()
        transport.stub = FixtureTransport.Stub(
            status: 200,
            body: Data("""
            {"status":"ok","accepting_authorized_operations":true,"schema_version":1,"bootstrap_completed":true,"features":{}}
            """.utf8),
            error: nil
        )
        let result = await client.connect(address: "http://127.0.0.1:8787")
        guard case .success(let identity) = result else {
            Issue.record("Connect failed: \(result)")
            return
        }
        #expect(identity.isDevelopmentTransport)
        #expect(identity.verificationFingerprint.isEmpty)
        #expect(identity.deploymentName.contains("development"))
    }

    @Test("Network failure maps to offline, not success")
    func networkFailure() async throws {
        let (client, box, transport) = try makeClient()
        try await connectReady(client, transport)
        box.token = "tok"
        transport.stub = FixtureTransport.Stub(
            status: 0,
            body: Data(),
            error: URLError(.timedOut)
        )
        let result = await client.authorizedInventory()
        guard case .failure(let error) = result else {
            Issue.record("Timeout must fail")
            return
        }
        #expect(error == .offline || error == .cancelled)
    }
}

@Suite("Launch configuration")
struct LaunchConfigurationTests {
    @Test("Modes are independent")
    func independentModes() {
        let none = ManagerLaunchConfiguration.parse(arguments: ["HelicoidManager"])
        #expect(!none.useSourceFixtures)
        #expect(!none.useDevelopmentServer)

        let fixtures = ManagerLaunchConfiguration.parse(arguments: ["HelicoidManager", "--development-fixtures"])
        #expect(fixtures.useSourceFixtures)
        #expect(!fixtures.useDevelopmentServer)

        let server = ManagerLaunchConfiguration.parse(arguments: ["HelicoidManager", "--development-server"])
        #expect(!server.useSourceFixtures)
        #expect(server.useDevelopmentServer)

        let both = ManagerLaunchConfiguration.parse(arguments: [
            "HelicoidManager", "--development-fixtures", "--development-server",
        ])
        #expect(both.useSourceFixtures)
        #expect(both.useDevelopmentServer)
    }

    @Test("Manager identity and address flags")
    func identityFlags() {
        let config = ManagerLaunchConfiguration.parse(arguments: [
            "HelicoidManager",
            "--development-server",
            "--development-server-address", "http://127.0.0.1:9999",
            "--manager-public-identity", "lab-mac-1",
        ])
        #expect(config.developmentServerAddress == "http://127.0.0.1:9999")
        #expect(config.managerPublicIdentity == "lab-mac-1")
        #expect(config.useDevelopmentServer)
    }
}

@Suite("Login and inventory payload validation")
struct PayloadValidationTests {
    @Test("Rejects empty token")
    func emptyToken() {
        let dto = LoginResponseDTO(
            token: "  ",
            account: AccountDTO(id: "a", username: "u", state: "active")
        )
        #expect(LoopbackDevelopmentClient.validateLogin(dto, requestedManagerIdentity: nil) != nil)
    }

    @Test("Rejects inactive account")
    func inactiveAccount() {
        let dto = LoginResponseDTO(
            token: "tok",
            account: AccountDTO(id: "a", username: "u", state: "disabled")
        )
        #expect(LoopbackDevelopmentClient.validateLogin(dto, requestedManagerIdentity: nil) != nil)
    }

    @Test("Rejects past expiry")
    func pastExpiry() {
        let dto = LoginResponseDTO(
            token: "tok",
            expiresAtUnix: 1,
            account: AccountDTO(id: "a", username: "u", state: "active")
        )
        #expect(LoopbackDevelopmentClient.validateLogin(dto, requestedManagerIdentity: nil) != nil)
    }

    @Test("Rejects manager identity mismatch")
    func managerMismatch() {
        let dto = LoginResponseDTO(
            token: "tok",
            account: AccountDTO(id: "a", username: "u", state: "active"),
            manager: ManagerDTO(id: "m", publicIdentity: "other", lifecycleState: "approved", approvedAtUnix: 9_999_999_999)
        )
        #expect(LoopbackDevelopmentClient.validateLogin(dto, requestedManagerIdentity: "lab-1") != nil)
    }

    @Test("Rejects pending manager")
    func pendingManager() {
        let dto = LoginResponseDTO(
            token: "tok",
            account: AccountDTO(id: "a", username: "u", state: "active"),
            manager: ManagerDTO(id: "m", publicIdentity: "lab-1", lifecycleState: "pending")
        )
        #expect(LoopbackDevelopmentClient.validateLogin(dto, requestedManagerIdentity: "lab-1") != nil)
    }

    @Test("Accepts matching approved manager")
    func approvedManager() {
        let dto = LoginResponseDTO(
            token: "tok",
            expiresAtUnix: 9_999_999_999,
            account: AccountDTO(id: "a", username: "u", state: "active", capabilities: AccountCapabilitiesDTO(operate: true, manageEnrollment: true, manageAccess: true, manageAccounts: true, manageSecurity: true), revision: 1),
            manager: ManagerDTO(id: "m", publicIdentity: "lab-1", lifecycleState: "approved", approvedAtUnix: 9_999_999_999),
            mfa: MFADTO(required: false, available: false)
        )
        #expect(LoopbackDevelopmentClient.validateLogin(dto, requestedManagerIdentity: "lab-1") == nil)
    }

    @Test("Inventory rejects empty, oversized, duplicate IDs and page overflow")
    func inventoryValidation() {
        let ok = InventoryResponseDTO(computers: [
            ComputerDTO(id: "c1", publicIdentity: "p", enrollmentState: "enrolled")
        ])
        #expect(LoopbackDevelopmentClient.validateInventory(ok) == nil)

        let empty = InventoryResponseDTO(computers: [
            ComputerDTO(id: "  ", publicIdentity: "p", enrollmentState: "enrolled")
        ])
        #expect(LoopbackDevelopmentClient.validateInventory(empty) != nil)

        let longID = String(repeating: "x", count: 129)
        let oversized = InventoryResponseDTO(computers: [
            ComputerDTO(id: longID, publicIdentity: "p", enrollmentState: "enrolled")
        ])
        #expect(LoopbackDevelopmentClient.validateInventory(oversized) != nil)

        let dup = InventoryResponseDTO(computers: [
            ComputerDTO(id: "c1", publicIdentity: "p", enrollmentState: "enrolled"),
            ComputerDTO(id: "c1", publicIdentity: "q", enrollmentState: "enrolled")
        ])
        #expect(LoopbackDevelopmentClient.validateInventory(dup) != nil)

        let many = InventoryResponseDTO(computers: (0..<101).map {
            ComputerDTO(id: "c\($0)", publicIdentity: "p\($0)", enrollmentState: "enrolled")
        })
        #expect(LoopbackDevelopmentClient.validateInventory(many) != nil)
    }

    @Test("Configuration requires finite positive bounds")
    func configBounds() {
        let good = LoopbackDevelopmentClient.Configuration(baseURL: URL(string: "http://127.0.0.1:8787")!)
        #expect(good.hasFinitePositiveBounds)
        let bad = LoopbackDevelopmentClient.Configuration(
            baseURL: URL(string: "http://127.0.0.1:8787")!,
            requestTimeout: -1
        )
        #expect(!bad.hasFinitePositiveBounds)
    }

    @Test("Transport enforces maxBytes before returning body")
    func byteCap() async throws {
        let transport = FixtureTransport()
        transport.stub = FixtureTransport.Stub(
            status: 200,
            body: Data(repeating: 0x41, count: 2048),
            error: nil
        )
        do {
            _ = try await transport.bytes(
                for: URLRequest(url: URL(string: "http://127.0.0.1:8787/")!),
                maxBytes: 128
            )
            Issue.record("Expected size failure")
        } catch let error as HelicoidError {
            guard case .invalidInput = error else {
                Issue.record("Expected invalidInput, got \(error)")
                return
            }
        }
    }
}

@Suite("Setup model regression")
struct SetupModelRegressionTests {
    @Test("Advance moves phase when ready")
    @MainActor
    func advanceWorks() {
        let model = GuidedServerSetupModel()
        model.setRoute(.existingLinuxSSH)
        #expect(model.phase == .chooseHosting)
        model.advance()
        #expect(model.phase == .connect)
        model.setSSHAddress("server.lan")
        model.advance()
        #expect(model.phase == .hostIdentity)
        model.setHostIdentity(.verified(fingerprint: "SHA256:x"))
        model.advance()
        #expect(model.phase == .checkHost)
        model.setHostCheck("SSH reachability", status: .passed)
        model.setHostCheck("Disk space", status: .passed)
        model.setHostCheck("Operating system", status: .passed)
        for name in GuidedServerSetupModel.requiredHostChecks(for: .existingLinuxSSH) { model.setHostCheck(name, status: .passed) }
        model.advance()
        #expect(model.phase == .network)
    }

    @Test("Cannot continue from host identity without verification")
    @MainActor
    func identityGateBlocks() {
        let model = GuidedServerSetupModel()
        model.setRoute(.existingLinuxSSH)
        model.setSSHAddress("server.lan")
        model.advance()
        model.advance()
        #expect(model.phase == .hostIdentity)
        #expect(!model.canContinueFromCurrentPhase)
        let before = model.phase
        model.advance()
        #expect(model.phase == before)
    }
}
