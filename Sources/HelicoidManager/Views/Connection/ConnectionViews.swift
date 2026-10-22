import SwiftUI
import HelicoidCore

/// Shared compact width for connect/verify/sign-in forms.
private enum ConnectionLayout {
    static let formWidth: CGFloat = 472
}

/// C01 Connect to Server. Address field, trusted profile rows, Set Up Server.
struct ConnectView: View {
    @Environment(ManagerSession.self) private var session
    @State private var isConnecting = false
    @FocusState private var addressFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    ConnectionHeading(title: "Connect to Server")

                    VStack(alignment: .leading, spacing: 8) {
                        Text("Server address")
                            .font(.callout)
                        TextField("server.example.com", text: Binding(
                            get: { session.serverAddress },
                            set: { session.serverAddress = $0 }
                        ))
                        .textFieldStyle(.roundedBorder)
                        .textContentType(.URL)
                        .accessibilityLabel("Server address")
                        .focused($addressFocused)

                        if !session.allowsConnect {
                            Text("A verified connection profile is required.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }

                    if session.isDevelopmentServerMode {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Manager identity (optional)").font(.callout)
                            TextField("Manager identity", text: Binding(
                                get: { session.managerPublicIdentity ?? "" },
                                set: { session.managerPublicIdentity = $0.isEmpty ? nil : $0 }
                            ))
                            .textFieldStyle(.roundedBorder)
                            .accessibilityLabel("Manager public identity")
                        }
                    }
                    if let failure = session.connectError {
                        InlineErrorView(failure: failure)
                    }
                    if !session.trustedProfiles.isEmpty {
                        TrustedProfilesList(profiles: session.trustedProfiles) { profile in
                            session.serverAddress = profile.address
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(24)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()
            HStack(spacing: 12) {
                Button("Set Up Server") { session.screen = .guidedSetup }
                Spacer()
                if isConnecting { ProgressView().controlSize(.small) }
                Button("Connect") {
                    isConnecting = true
                    Task {
                        await session.connect()
                        isConnecting = false
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(isConnecting || !session.allowsConnect
                    || session.serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .help("Connect to the server")
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 16)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { addressFocused = true }
    }
}

/// C02 Verify Server. Full selectable identities and trusted source.
struct VerifyServerView: View {
    @Environment(ManagerSession.self) private var session
    @State private var isTrusting = false

    private var identityChanged: Bool {
        session.connectError == .identityChanged
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 0) {
                    ConnectionHeading(title: "Verify Server")
                        .padding(.bottom, 20)

                    if identityChanged {
                        Form {
                            Section {
                                Label("Server identity changed", systemImage: "exclamationmark.triangle.fill")
                                    .foregroundStyle(.orange)
                                Text("The identity no longer matches the stored trust. Access is stopped. Trust is not offered for a changed identity.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                                if let failure = session.connectError {
                                    InlineErrorView(failure: failure)
                                }
                            }
                        }
                        .formStyle(.grouped)
                        .frame(maxWidth: ConnectionLayout.formWidth)
                    } else if let identity = session.pendingIdentity {
                        Form {
                            Section {
                                LabeledContent("Deployment", value: identity.deploymentName)
                                    .textSelection(.enabled)
                                LabeledContent("Address", value: session.serverAddress)
                                    .textSelection(.enabled)
                                LabeledContent("Identity fingerprint", value: identity.verificationFingerprint)
                                    .textSelection(.enabled)
                                Text(identity.trustedSourceNote)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }
                        }
                        .formStyle(.grouped)
                        .frame(maxWidth: ConnectionLayout.formWidth)

                        if let failure = session.connectError {
                            InlineErrorView(failure: failure)
                        }

                        Text("A changed identity later stops access. Discovery does not establish trust.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                            .frame(maxWidth: ConnectionLayout.formWidth)
                    } else {
                        Text("No identity is waiting for verification.")
                            .foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding(.horizontal, 24)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()
            HStack {
                Button("Back") {
                    withAnimation(.easeOut(duration: 0.22)) {
                        session.screen = .connect
                    }
                }
                Spacer()
                if !identityChanged {
                    Button {
                        isTrusting = true
                        Task {
                            await session.trustPendingIdentity()
                            isTrusting = false
                        }
                    } label: {
                        if isTrusting {
                            ProgressView("Trusting")
                                .controlSize(.small)
                        } else {
                            Text("Verify and Continue")
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(session.pendingIdentity == nil || isTrusting)
                }
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 16)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// C03 Sign In. Conditional MFA, cancellation, real errors.
struct SignInView: View {
    @Environment(ManagerSession.self) private var session
    @State private var isSigningIn = false
    @FocusState private var focusedField: Field?

    private enum Field: Hashable {
        case username
        case password
        case authCode
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 0) {
                    ConnectionHeading(title: session.authCodeState == .required ? "Verification Code" : "Sign In")
                        .padding(.bottom, 20)

                    if let identity = session.verifiedIdentity {
                        Text(identity.deploymentName)
                            .foregroundStyle(.secondary)
                    }

                    VStack(alignment: .leading, spacing: 16) {
                        if session.authCodeState != .required {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Username").font(.callout)
                                TextField("Username", text: Binding(
                                    get: { session.username },
                                    set: { session.username = $0 }
                                ))
                                .textContentType(.username)
                                .focused($focusedField, equals: .username)
                                Text("Password").font(.callout).padding(.top, 8)
                                SecureField("Password", text: Binding(
                                    get: { session.password },
                                    set: { session.password = $0 }
                                ))
                                .textContentType(.password)
                                .focused($focusedField, equals: .password)
                            }
                        }

                        if session.authCodeState == .required {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Verification code").font(.callout)
                                SecureField("Verification code", text: Binding(
                                    get: { session.authCode },
                                    set: { session.authCode = $0 }
                                ))
                                .textContentType(.oneTimeCode)
                                .accessibilityLabel("Six-digit verification code")
                                .focused($focusedField, equals: .authCode)
                                Text("Enter the six-digit code from your authenticator.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }

                        if let error = session.authCodeError {
                            VStack(alignment: .leading, spacing: 8) {
                                InlineErrorView(error: error)
                            }
                        }

                        if let error = session.signInError {
                            VStack(alignment: .leading, spacing: 8) {
                                InlineErrorView(error: error)
                                if session.phase == .pendingManagerApproval {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text("Manager pending approval")
                                            .font(.caption.weight(.semibold))
                                        Text("Ask an administrator to approve this manager, then try again.")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                    .accessibilityElement(children: .combine)
                                }
                            }
                        }
                    }
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: ConnectionLayout.formWidth)
                }
                .frame(maxWidth: .infinity)
                .padding(.horizontal, 24)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()
            HStack {
                if session.authCodeState == .required {
                    Button("Cancel") {
                        Task { await session.cancelAuthCode() }
                    }
                } else {
                    Button("Back") {
                        withAnimation(.easeOut(duration: 0.22)) {
                            session.screen = .verify
                        }
                    }
                }
                Spacer()
                if session.authCodeState == .required {
                    Button {
                        isSigningIn = true
                        Task {
                            await session.submitAuthCode()
                            isSigningIn = false
                        }
                    } label: {
                        if isSigningIn {
                            ProgressView("Verifying")
                                .controlSize(.small)
                        } else {
                            Text("Verify")
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(
                        isSigningIn
                            || !NativeV2AuthClient.isValidTOTPCode(session.authCode)
                    )
                } else {
                    Button {
                        isSigningIn = true
                        Task {
                            await session.signIn()
                            isSigningIn = false
                        }
                    } label: {
                        if isSigningIn {
                            ProgressView("Signing In")
                                .controlSize(.small)
                        } else {
                            Text("Sign In")
                        }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(
                        isSigningIn
                            || session.username.trimmingCharacters(in: .whitespaces).isEmpty
                            || session.password.isEmpty
                    )
                }
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 16)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear {
            focusedField = session.authCodeState == .required ? .authCode : .username
        }
    }
}

struct ConnectionHeading: View {
    let title: String

    var body: some View {
        HStack(spacing: 12) {
            BrandMark()
            Text(title).font(.headline)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct BrandMark: View {
    var body: some View {
        Image(nsImage: NSApp.applicationIconImage)
            .resizable()
            .frame(width: 32, height: 32)
            .accessibilityHidden(true)
    }
}

struct InlineErrorView: View {
    let failure: ConnectionFailure?

    var body: some View {
        if let failure {
            VStack(alignment: .leading, spacing: 4) {
                Text(failure.title)
                    .font(.caption.weight(.semibold))
                Text(failure.explanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            .accessibilityElement(children: .combine)
        }
    }

    init(failure: ConnectionFailure?) {
        self.failure = failure
    }

    init(error: HelicoidError) {
        self.failure = ConnectionFailure.authenticationFailed(detail: error.explanation)
    }
}

/// Selectable trusted profile rows. Selecting fills the address only — never signs in.
struct TrustedProfilesList: View {
    let profiles: [ServerProfile]
    let onSelect: (ServerProfile) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Trusted Connections")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            ForEach(profiles) { profile in
                Button {
                    onSelect(profile)
                } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(profile.displayName)
                                .font(.callout)
                            Text(profile.address)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                        Spacer()
                        Image(systemName: "arrow.down.circle")
                            .foregroundStyle(.secondary)
                            .accessibilityHidden(true)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Use \(profile.displayName) address \(profile.address)")
                .help("Fill the server address with \(profile.address)")
            }
        }
        .frame(maxWidth: ConnectionLayout.formWidth, alignment: .leading)
        .padding(.top, 12)
    }
}
