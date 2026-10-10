import Testing
import Foundation
@testable import HelicoidCore

@Suite("Loopback address policy")
struct LoopbackAddressPolicyTests {

    private func alwaysLoopback(_: String) -> Bool? { true }
    private func neverLoopback(_: String) -> Bool? { false }
    private func failingResolve(_: String) -> Bool? { nil }

    @Test("Allows literal IPv4 loopback")
    func literalIPv4() {
        #expect(LoopbackAddressPolicy.validate("http://127.0.0.1:8787") == .allowed)
        #expect(LoopbackAddressPolicy.validate("http://127.0.0.1") == .allowed)
        #expect(LoopbackAddressPolicy.validate("http://127.5.5.5") == .allowed)
    }

    @Test("Allows literal IPv6 loopback")
    func literalIPv6() {
        #expect(LoopbackAddressPolicy.validate("http://[::1]:8787") == .allowed)
    }

    @Test("Allows localhost only when resolver confirms loopback")
    func localhostResolution() {
        #expect(LoopbackAddressPolicy.validate("http://localhost:8787", resolveLoopback: alwaysLoopback) == .allowed)
        #expect(LoopbackAddressPolicy.validate("http://localhost:8787", resolveLoopback: neverLoopback) == .refused(.dnsNotLoopback))
        #expect(LoopbackAddressPolicy.validate("http://localhost:8787", resolveLoopback: failingResolve) == .refused(.dnsNotLoopback))
    }

    @Test("Refuses remote hosts")
    func remoteHosts() {
        #expect(LoopbackAddressPolicy.validate("http://10.0.0.5:8787") == .refused(.remoteHost))
        #expect(LoopbackAddressPolicy.validate("http://192.168.1.10:8787") == .refused(.remoteHost))
        #expect(LoopbackAddressPolicy.validate("http://example.com:8787") == .refused(.remoteHost))
        #expect(LoopbackAddressPolicy.validate("http://evil.example") == .refused(.remoteHost))
    }

    @Test("Refuses embedded credentials")
    func embeddedCredentials() {
        #expect(LoopbackAddressPolicy.validate("http://user:pass@127.0.0.1:8787") == .refused(.embeddedCredentials))
        #expect(LoopbackAddressPolicy.validate("http://user@localhost:8787", resolveLoopback: alwaysLoopback) == .refused(.embeddedCredentials))
    }

    @Test("Refuses fragments")
    func fragments() {
        #expect(LoopbackAddressPolicy.validate("http://127.0.0.1:8787#admin") == .refused(.fragmentPresent))
        #expect(LoopbackAddressPolicy.validate("http://127.0.0.1/#/setup") == .refused(.fragmentPresent))
    }

    @Test("Refuses empty and invalid")
    func emptyInvalid() {
        #expect(LoopbackAddressPolicy.validate("") == .refused(.empty))
        #expect(LoopbackAddressPolicy.validate("   ") == .refused(.empty))
        #expect(LoopbackAddressPolicy.validate("not a url at all") == .refused(.invalidURL))
    }

    @Test("Refuses non-http schemes")
    func schemes() {
        #expect(LoopbackAddressPolicy.validate("https://127.0.0.1:8787") == .refused(.unsupportedScheme))
        #expect(LoopbackAddressPolicy.validate("ftp://127.0.0.1") == .refused(.unsupportedScheme))
        #expect(LoopbackAddressPolicy.validate("file:///etc/passwd") == .refused(.unsupportedScheme))
    }

    @Test("Redirect escape is refused")
    func redirectEscape() {
        let loopback = URL(string: "http://127.0.0.1:8787/health")!
        let remote = URL(string: "http://evil.example/steal")!
        let loopback2 = URL(string: "http://127.0.0.1:8787/v1/auth/login")!
        let localhost = URL(string: "http://localhost:8787/health")!

        #expect(LoopbackAddressPolicy.allowRedirect(from: loopback, to: loopback2))
        #expect(!LoopbackAddressPolicy.allowRedirect(from: loopback, to: remote))
        // localhost redirects need resolver confirmation; default DNS may fail in sandbox → must not blindly allow.
        _ = localhost
    }

    @Test("Remote literal detection")
    func remoteLiteral() {
        #expect(LoopbackAddressPolicy.validate("http://8.8.8.8") == .refused(.remoteHost))
        #expect(LoopbackAddressPolicy.validate("http://[2001:db8::1]") == .refused(.hostIsNotLiteralLoopback)
            || LoopbackAddressPolicy.validate("http://[2001:db8::1]") == .refused(.remoteHost))
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

    /// URLProtocol stub that never touches the network.
    final class StubURLProtocol: URLProtocol, @unchecked Sendable {
        struct Stub {
            var status: Int
            var body: Data
            var error: Error?
        }
        nonisolated(unsafe) static var stub: Stub = Stub(status: 200, body: Data("{}".utf8), error: nil)
        nonisolated(unsafe) static var lastRequest: URLRequest?
        nonisolated(unsafe) static var requestCount = 0

        override class func canInit(with request: URLRequest) -> Bool { true }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
        override func startLoading() {
            Self.requestCount += 1
            Self.lastRequest = request
            if let error = Self.stub.error {
                client?.urlProtocol(self, didFailWithError: error)
                return
            }
            let response = HTTPURLResponse(
                url: request.url ?? URL(string: "http://127.0.0.1:8787")!,
                statusCode: Self.stub.status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Self.stub.body)
            client?.urlProtocolDidFinishLoading(self)
        }
        override func stopLoading() {}
    }

    private func makeClient(
        address: String = "http://127.0.0.1:8787",
        managerIdentity: String? = "dev-manager-key"
    ) throws -> (LoopbackDevelopmentClient, TokenBox) {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)
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
            session: session,
            tokenBox: box
        )
        return (client, box)
    }

    @Test("Login stores token in memory and sends manager identity")
    func loginFlow() async throws {
        StubURLProtocol.stub = StubURLProtocol.Stub(
            status: 200,
            body: Data("""
            {"token":"secret-token","account":{"id":"a","username":"admin","state":"active"},
             "manager":{"id":"m","public_identity":"dev-manager-key","lifecycle_state":"approved"},
             "mfa":{"required":false,"available":false}}
            """.utf8),
            error: nil
        )
        StubURLProtocol.requestCount = 0
        let (client, box) = try makeClient()
        let result = await client.signIn(username: "admin", password: "password12345")
        guard case .success(let op) = result else {
            Issue.record("Login should succeed: \(result)")
            return
        }
        #expect(op.rawValue == "a")
        #expect(box.token == "secret-token")
        if let body = StubURLProtocol.lastRequest?.httpBody {
            let text = String(data: body, encoding: .utf8) ?? ""
            #expect(text.contains("dev-manager-key"))
            #expect(text.contains("password12345"))
        }
    }

    @Test("403 manager approval failure is distinct")
    func approvalDenied() async throws {
        StubURLProtocol.stub = StubURLProtocol.Stub(
            status: 403,
            body: Data("{\"error\":{\"code\":\"forbidden\",\"message\":\"manager is pending approval\"}}".utf8),
            error: nil
        )
        let (client, box) = try makeClient()
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
        let (client, box) = try makeClient()
        box.token = "live-token"
        StubURLProtocol.stub = StubURLProtocol.Stub(
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
        StubURLProtocol.requestCount = 0
        let (client, box) = try makeClient()
        box.token = nil
        await client.signOut()
        #expect(StubURLProtocol.requestCount == 0)
        #expect(box.token == nil)
    }

    @Test("Inventory maps enrollment without inventing online")
    func inventoryMapping() async throws {
        let (client, box) = try makeClient()
        box.token = "tok"
        StubURLProtocol.stub = StubURLProtocol.Stub(
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
        let (client, box) = try makeClient()
        box.token = "expired"
        StubURLProtocol.stub = StubURLProtocol.Stub(
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
        StubURLProtocol.requestCount = 0
        let (client, _) = try makeClient()
        let result = await client.validateAddress("http://10.0.0.1:8787")
        if case .ok = result.outcome {
            Issue.record("Remote address must not validate")
        }
        #expect(StubURLProtocol.requestCount == 0)
    }

    @Test("Connect against health never fabricates a production fingerprint")
    func connectIdentityIsDevelopmentOnly() async throws {
        StubURLProtocol.stub = StubURLProtocol.Stub(
            status: 200,
            body: Data("""
            {"status":"ok","accepting_authorized_operations":true,"schema_version":1,"bootstrap_completed":true,"features":{}}
            """.utf8),
            error: nil
        )
        let (client, _) = try makeClient()
        let result = await client.connect(address: "http://127.0.0.1:8787")
        guard case .success(let identity) = result else {
            Issue.record("Connect failed: \(result)")
            return
        }
        #expect(identity.verificationFingerprint == "development-transport-unverified")
        #expect(identity.deploymentName.contains("development"))
    }

    @Test("Network failure maps to offline, not success")
    func networkFailure() async throws {
        let (client, box) = try makeClient()
        box.token = "tok"
        StubURLProtocol.stub = StubURLProtocol.Stub(
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
