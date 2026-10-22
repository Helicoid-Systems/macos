import AppKit
import Combine
import Foundation
import HelicoidCore

/// Status model for the managed computer (Helicoid Computer).
/// Menu-bar status prioritizes operator identity and current access.
@MainActor
public final class ComputerStatusModel: ObservableObject {
    public enum ConnectionState: Hashable, Sendable {
        case notConfigured
        case connecting
        case connected
        case disconnected(reason: String)

        public var label: String {
            switch self {
            case .notConfigured: "Not Configured"
            case .connecting: "Connecting"
            case .connected: "Connected"
            case .disconnected: "Disconnected"
            }
        }
    }

    public enum ScreenAccess: Hashable, Sendable {
        case none
        case observed(operators: [String])
        case controlled(operators: [String])

        public var headline: String {
            switch self {
            case .none:
                "No Active Screen Access"
            case .observed(let names):
                switch names.count {
                case 0:
                    "Your Screen Is Being Viewed"
                case 1:
                    "\(names[0]) Is Viewing Your Screen"
                default:
                    "\(names.count) People Are Viewing Your Screen"
                }
            case .controlled(let names):
                switch names.count {
                case 0:
                    "This Computer Is Being Controlled"
                case 1:
                    "\(names[0]) Is Controlling This Computer"
                default:
                    "Control Status Unavailable"
                }
            }
        }
    }

    /// Single permission-row action for the current status.
    public enum PermissionRowAction: Hashable, Sendable {
        /// First explicit request path. May present the system prompt.
        case allow
        /// After a prior unsuccessful request. Opens Settings; never prompts.
        case openSettings
        /// Confirmed grant. No button.
        case none
    }

    @Published public var connection: ConnectionState
    @Published public var screenAccess: ScreenAccess
    @Published public var helpRequestText: String
    @Published public var helpRequestState: HelpRequestState
    @Published public var isFixturesMode: Bool

    @Published public var enrollmentServerAddress = ""
    @Published public var enrollmentDeploymentID = ""
    @Published public var enrollmentInvitationID = ""
    @Published public var enrollmentCode = ""
    @Published public private(set) var enrollmentStatus = "Not enrolled"
    @Published public private(set) var isEnrolling = false
    @Published public private(set) var isForgettingEndpointIdentity = false
    @Published public private(set) var fileDeliveryStatus = "Enroll this Mac to receive files."
    @Published public private(set) var receivedFiles: [EndpointFileReceivedFile] = []
    @Published public private(set) var availableFileRequests: [EndpointFileRequest] = []
    @Published public private(set) var fileRequestStatus = "Refresh to check for open file requests."
    @Published public private(set) var isRefreshingFileRequests = false
    @Published public private(set) var fileRequestSubmissions: [EndpointFileRequestSubmission] = []
    @Published public private(set) var fileRequestSubmissionStatus = ""
    @Published public private(set) var isRefreshingFileRequestSubmissions = false
    @Published public private(set) var isSubmittingFileRequest = false
    @Published public private(set) var hasSavedEndpointConfiguration = false

    // MARK: - Permission readiness
    // Independent of connection, admission, and actual screen access.
    // Grants alone never mark connected/observed/controlled or enable capture/media/input.
    @Published public private(set) var screenRecordingPermission: ComputerPermissionStatus = .unknown
    @Published public private(set) var accessibilityPermission: ComputerPermissionStatus = .unknown

    /// Kinds the user already drove through the explicit request path.
    /// Later ungranted actions open Settings instead of prompting again.
    private var requestedPermissionKinds: Set<ComputerPermissionKind> = []

    private let permissionProbe: any ComputerPermissionProbing
    private let endpointEnrollmentClient: EndpointEnrollmentClient
    private var fileDeliveryTask: Task<Void, Never>?
    private var fileRequestSubmissionGeneration: UInt64 = 0

    public init(
        connection: ConnectionState = .notConfigured,
        screenAccess: ScreenAccess = .none,
        helpRequestText: String = "",
        helpRequestState: HelpRequestState = .idle,
        isFixturesMode: Bool = false,
        permissionProbe: any ComputerPermissionProbing = NativeComputerPermissionProbe(),
        endpointEnrollmentClient: EndpointEnrollmentClient = EndpointEnrollmentClient()
    ) {
        self.connection = connection
        self.screenAccess = screenAccess
        self.helpRequestText = helpRequestText
        self.helpRequestState = helpRequestState
        self.isFixturesMode = isFixturesMode
        self.permissionProbe = permissionProbe
        self.endpointEnrollmentClient = endpointEnrollmentClient
        self.enrollmentServerAddress = UserDefaults.standard.string(forKey: "endpoint.serverAddress") ?? ""
        self.enrollmentDeploymentID = UserDefaults.standard.string(forKey: "endpoint.deploymentID") ?? ""
        self.hasSavedEndpointConfiguration = !self.enrollmentServerAddress.isEmpty && !self.enrollmentDeploymentID.isEmpty
        if self.hasSavedEndpointConfiguration {
            self.enrollmentStatus = "Endpoint identity saved · \(self.enrollmentDeploymentID)"
            self.fileDeliveryStatus = "Checking for approved file jobs…"
        }
    }

    public func permissionStatus(for kind: ComputerPermissionKind) -> ComputerPermissionStatus {
        switch kind {
        case .screenRecording: screenRecordingPermission
        case .accessibility: accessibilityPermission
        }
    }

    /// Non-prompting refresh. Startup, status refresh, and app reactivation only.
    /// A fresh native query replaces stale granted state after revoke.
    public func refreshPermissions() {
        screenRecordingPermission = permissionProbe.currentStatus(for: .screenRecording)
        accessibilityPermission = permissionProbe.currentStatus(for: .accessibility)
    }

    /// Button shown for the row right now. Granted rows hide the action.
    public func permissionRowAction(for kind: ComputerPermissionKind) -> PermissionRowAction {
        if permissionStatus(for: kind).isAvailable {
            return .none
        }
        return requestedPermissionKinds.contains(kind) ? .openSettings : .allow
    }

    /// Single row action. First ungranted action may prompt once per kind;
    /// later ungranted actions open the exact Settings pane and never prompt.
    /// Always ends with a non-prompting probe recheck. Never infers a grant
    /// from requesting.
    public func performPermissionRowAction(_ kind: ComputerPermissionKind) {
        switch permissionRowAction(for: kind) {
        case .none:
            return
        case .allow:
            requestPermission(kind)
        case .openSettings:
            openPermissionSettings(kind)
        }
    }

    /// Explicit user button only. May prompt. Marks the kind as already requested.
    /// Status stays unavailable until a fresh native query confirms.
    public func requestPermission(_ kind: ComputerPermissionKind) {
        permissionProbe.requestAccess(for: kind)
        requestedPermissionKinds.insert(kind)
        recheckPermission(kind)
    }

    /// Opens the exact System Settings privacy pane. Never prompts.
    /// Rechecks so a grant completed in Settings is reflected.
    public func openPermissionSettings(_ kind: ComputerPermissionKind) {
        permissionProbe.openSystemSettings(for: kind)
        recheckPermission(kind)
    }

    private func recheckPermission(_ kind: ComputerPermissionKind) {
        let status = permissionProbe.currentStatus(for: kind)
        switch kind {
        case .screenRecording:
            screenRecordingPermission = status
        case .accessibility:
            accessibilityPermission = status
        }
    }

    /// Register this Mac with a one-time invitation. This creates pending
    /// enrollment only; it does not enable a server connection or screen access.
    public func enrollEndpoint() async {
        guard !isEnrolling, !isForgettingEndpointIdentity else { return }
        isEnrolling = true
        enrollmentStatus = "Redeeming invitation…"
        defer { isEnrolling = false }

        do {
            let result = try await endpointEnrollmentClient.enroll(
                serverAddress: enrollmentServerAddress,
                deploymentID: enrollmentDeploymentID,
                invitationID: enrollmentInvitationID,
                enrollmentCode: enrollmentCode
            )
            enrollmentCode = ""
            enrollmentInvitationID = ""
            UserDefaults.standard.set(enrollmentServerAddress, forKey: "endpoint.serverAddress")
            UserDefaults.standard.set(enrollmentDeploymentID, forKey: "endpoint.deploymentID")
            hasSavedEndpointConfiguration = true
            enrollmentStatus = "Waiting for administrator approval · \(result.computerID)"
            fileDeliveryStatus = "Waiting for endpoint approval before checking for files."
            startEndpointFileDeliveryPolling()
        } catch let error as HelicoidError {
            enrollmentStatus = error.explanation
        } catch {
            enrollmentStatus = "Enrollment could not be completed. Check the HTTPS address and try again."
        }
    }

    /// Stop local endpoint work, remove the saved Keychain identity and reset
    /// enrollment hints. Received Files are user data and are left in place.
    public func forgetSavedEndpointIdentity() async {
        guard hasSavedEndpointConfiguration, !isEnrolling, !isForgettingEndpointIdentity else { return }
        guard !isRefreshingFileRequests, !isRefreshingFileRequestSubmissions, !isSubmittingFileRequest else {
            enrollmentStatus = "Finish the current file request action before forgetting this endpoint identity."
            return
        }

        isForgettingEndpointIdentity = true
        enrollmentStatus = "Stopping endpoint activity…"
        defer { isForgettingEndpointIdentity = false }

        let pollingTask = fileDeliveryTask
        fileDeliveryTask = nil
        pollingTask?.cancel()
        await pollingTask?.value

        do {
            try await endpointEnrollmentClient.forgetIdentity(deploymentID: enrollmentDeploymentID)
            UserDefaults.standard.removeObject(forKey: "endpoint.serverAddress")
            UserDefaults.standard.removeObject(forKey: "endpoint.deploymentID")
            enrollmentServerAddress = ""
            enrollmentDeploymentID = ""
            enrollmentInvitationID = ""
            enrollmentCode = ""
            hasSavedEndpointConfiguration = false
            connection = .notConfigured
            screenAccess = .none
            availableFileRequests = []
            fileRequestSubmissions = []
            fileRequestStatus = "Enroll this Mac before checking for file requests."
            fileRequestSubmissionStatus = ""
            fileDeliveryStatus = "Saved endpoint identity forgotten. Received Files are still on this Mac."
            enrollmentStatus = "Identity forgotten. Ask the Manager for a fresh invitation to enroll this Mac again."
        } catch let error as HelicoidError {
            enrollmentStatus = "The saved identity could not be forgotten: \(error.explanation)"
        } catch {
            enrollmentStatus = "The saved identity could not be forgotten. Retry after checking Keychain access."
        }
    }

    /// Poll only the deployment saved by the successful enrollment flow. The
    /// endpoint key and origin remain in the protected identity store; this
    /// preference is only the deployment lookup hint.
    public func startEndpointFileDeliveryPolling() {
        guard !isFixturesMode, fileDeliveryTask == nil,
              !enrollmentDeploymentID.isEmpty else { return }
        let deploymentID = enrollmentDeploymentID
        fileDeliveryTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                await self?.pollEndpointFileJobs(deploymentID: deploymentID)
                do {
                    try await Task.sleep(for: .seconds(120))
                } catch {
                    return
                }
            }
        }
    }

    private func pollEndpointFileJobs(deploymentID: String) async {
        do {
            let files = try await endpointEnrollmentClient.receiveAvailableFiles(deploymentID: deploymentID)
            if !files.isEmpty {
                var byJobID = Dictionary(uniqueKeysWithValues: receivedFiles.map { ($0.jobID, $0) })
                for file in files { byJobID[file.jobID] = file }
                receivedFiles = Array(byJobID.values).sorted { $0.fileName.localizedStandardCompare($1.fileName) == .orderedAscending }
                fileDeliveryStatus = "Received \(files.count) file\(files.count == 1 ? "" : "s"); saved in Received Files."
            } else {
                fileDeliveryStatus = "No file jobs are waiting. Checks run every two minutes."
            }
        } catch let error as HelicoidError {
            switch error {
            case .authenticationFailed:
                fileDeliveryStatus = "Waiting for administrator approval or valid endpoint access."
            case .setupBlocked(let reason) where reason == "Waiting for an eligible signed-in console user."
                || reason == "File delivery paused after a console-user change. It will check again shortly.":
                fileDeliveryStatus = reason
            default:
                fileDeliveryStatus = "File delivery check failed: \(error.explanation)"
            }
        } catch {
            fileDeliveryStatus = "File delivery check failed. Check the server connection."
        }
    }

    /// Request listings are user initiated. The server returns only open
    /// requests for this approved computer and the current signed-in user.
    public func refreshFileRequests() async {
        guard !isRefreshingFileRequests else { return }
        guard hasSavedEndpointConfiguration, !enrollmentDeploymentID.isEmpty else {
            availableFileRequests = []
            fileRequestStatus = "Enroll this Mac before checking for file requests."
            return
        }
        isRefreshingFileRequests = true
        fileRequestStatus = "Checking for open file requests…"
        defer { isRefreshingFileRequests = false }
        do {
            let requests = try await endpointEnrollmentClient.listAvailableFileRequests(
                deploymentID: enrollmentDeploymentID
            )
            availableFileRequests = requests
            fileRequestStatus = requests.isEmpty
                ? "No open file requests are available for this computer."
                : "Choose a request to review its instructions and file limits."
        } catch let error as HelicoidError {
            availableFileRequests = []
            fileRequestStatus = error.explanation
        } catch {
            availableFileRequests = []
            fileRequestStatus = "File requests could not be loaded. Check the server connection."
        }
    }

    public func refreshFileRequestSubmissions(requestID: String) async {
        guard fileRequestSubmissionGeneration < UInt64.max else {
            fileRequestSubmissionStatus = "Submission refresh could not be started. Restart the app before retrying."
            return
        }
        guard hasSavedEndpointConfiguration else {
            fileRequestSubmissions = []
            fileRequestSubmissionStatus = "Enroll this Mac before checking submissions."
            return
        }
        fileRequestSubmissionGeneration += 1
        let generation = fileRequestSubmissionGeneration
        isRefreshingFileRequestSubmissions = true
        fileRequestSubmissions = []
        fileRequestSubmissionStatus = "Checking submissions for this signed-in user…"
        defer {
            if generation == fileRequestSubmissionGeneration {
                isRefreshingFileRequestSubmissions = false
            }
        }
        do {
            let submissions = try await endpointEnrollmentClient.listMyFileRequestSubmissions(
                deploymentID: enrollmentDeploymentID,
                requestID: requestID
            )
            guard generation == fileRequestSubmissionGeneration else { return }
            fileRequestSubmissions = submissions
            fileRequestSubmissionStatus = fileRequestSubmissions.isEmpty
                ? "No earlier submissions for this user."
                : "Only this computer and signed-in user can resume or replace these submissions."
        } catch let error as HelicoidError {
            guard generation == fileRequestSubmissionGeneration else { return }
            fileRequestSubmissions = []
            fileRequestSubmissionStatus = error.explanation
        } catch {
            guard generation == fileRequestSubmissionGeneration else { return }
            fileRequestSubmissions = []
            fileRequestSubmissionStatus = "Submission history could not be loaded."
        }
    }

    public func submitFilesToRequest(
        _ request: EndpointFileRequest,
        fileURLs: [URL],
        replaceSubmissionID: String? = nil,
        confirmReplacement: Bool = false
    ) async -> Bool {
        guard !isSubmittingFileRequest else { return false }
        guard hasSavedEndpointConfiguration,
              availableFileRequests.contains(where: { $0.id == request.id && $0.revision == request.revision }) else {
            fileRequestSubmissionStatus = "Refresh this request before submitting files."
            return false
        }
        isSubmittingFileRequest = true
        fileRequestSubmissionStatus = "Preparing the selected files for this request…"
        defer { isSubmittingFileRequest = false }
        do {
            let submission = try await endpointEnrollmentClient.submitFilesToRequest(
                deploymentID: enrollmentDeploymentID,
                requestID: request.id,
                requestRevision: request.revision,
                fileURLs: fileURLs,
                replaceSubmissionID: replaceSubmissionID,
                confirmReplacement: confirmReplacement
            )
            fileRequestSubmissions.removeAll(where: { $0.id == submission.id })
            fileRequestSubmissions.insert(submission, at: 0)
            fileRequestSubmissionStatus = "Files submitted and verified for this request."
            return true
        } catch let error as HelicoidError {
            fileRequestSubmissionStatus = error.explanation
        } catch {
            fileRequestSubmissionStatus = "Files could not be submitted. The same signed-in user can retry or resume."
        }
        return false
    }

    public func openReceivedFilesFolder() {
        guard let directory = try? EndpointEnrollmentClient.receivedFilesDirectoryURL() else { return }
        NSWorkspace.shared.open(directory)
    }

    /// Help transport does not exist in production. Normal builds hide help
    /// entirely even when connected. Fixture-only synthetic help stays labeled.
    public var isHelpAvailable: Bool {
        isFixturesMode
    }

    public var helpUnavailableReason: String {
        "Help is not available in this build."
    }

    public func requestHelp() {
        guard isHelpAvailable else { return }
        // Deduplicate repeated taps.
        if helpRequestState == .pending { return }
        helpRequestState = .pending
    }

    public func cancelHelpRequest() {
        guard isHelpAvailable else { return }
        helpRequestState = .idle
    }
}

public enum HelpRequestState: String, Hashable, Sendable {
    case idle
    case pending
    case sent
    case cancelled
}

/// Development fixtures for the managed computer status UI.
/// Permission facts here are synthetic and clearly labeled — never live TCC.
public enum ComputerDevelopmentFixtures {
    public static func model() -> ComputerStatusModel {
        let model = ComputerStatusModel(
            connection: .connected,
            screenAccess: .observed(operators: ["Morgan"]),
            helpRequestText: "",
            helpRequestState: .idle,
            isFixturesMode: true,
            permissionProbe: ComputerFixturePermissionProbe()
        )
        model.refreshPermissions()
        return model
    }
}
