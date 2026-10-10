import SwiftUI
import HelicoidCore

/// C01 Connect to Server. One address/profile field; trusted connections as a short list.
struct ConnectView: View {
    @Environment(ManagerSession.self) private var session
    @State private var isConnecting = false

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 0) {
                BrandMark()

                Text("Connect to Server")
                    .font(.title2.weight(.semibold))
                    .padding(.top, 12)

                Form {
                    Section {
                        TextField("Server address", text: Binding(
                            get: { session.serverAddress },
                            set: { session.serverAddress = $0 }
                        ))
                        .textContentType(.URL)
                        .accessibilityLabel("Server address")

                        if session.isDevelopmentServerMode {
                            TextField("Manager identity (optional)", text: Binding(
                                get: { session.managerPublicIdentity ?? "" },
                                set: { session.managerPublicIdentity = $0.isEmpty ? nil : $0 }
                            ))
                            .accessibilityLabel("Manager public identity")
                            .help("Development manager identity fixture used for approval checks.")
                        }

                        if !session.allowsConnect {
                            Text("Connect is unavailable. \(session.transportDescription)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }

                        if let failure = session.connectError {
                            InlineErrorView(failure: failure)
                        }
                    }
                }
                .formStyle(.grouped)
                .frame(maxWidth: 440)

                if !session.trustedProfiles.isEmpty {
                    TrustedProfilesList(profiles: session.trustedProfiles)
                }
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            HStack {
                Button("Guided Server Setup") {
                    withAnimation(.easeOut(duration: 0.22)) {
                        session.screen = .guidedSetup
                    }
                }
                .buttonStyle(.link)

                Spacer()

                Button {
                    isConnecting = true
                    Task {
                        await session.connect()
                        isConnecting = false
                    }
                } label: {
                    if isConnecting {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Text("Connect")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(
                    isConnecting
                        || !session.allowsConnect
                        || session.serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                )
                .help(session.allowsConnect ? "Connect to the development loopback server" : session.transportDescription)
            }
            .padding(.horizontal, 28)
            .padding(.bottom, 28)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// C02 Verify Server.
struct VerifyServerView: View {
    @Environment(ManagerSession.self) private var session
    @State private var isTrusting = false

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 0) {
                BrandMark()

                Text("Verify Server")
                    .font(.title2.weight(.semibold))
                    .padding(.top, 12)

                if let identity = session.pendingIdentity {
                    Form {
                        LabeledContent("Deployment", value: identity.deploymentName)
                        LabeledContent("Address", value: session.serverAddress)
                        LabeledContent("Identity fingerprint", value: identity.verificationFingerprint)
                        Text(identity.trustedSourceNote)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .formStyle(.grouped)
                    .frame(maxWidth: 480)

                    if let failure = session.connectError {
                        InlineErrorView(failure: failure)
                    }

                    Text("A changed identity later stops access. Discovery does not establish trust.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                } else {
                    Text("No identity is waiting for verification.")
                        .foregroundStyle(.secondary)
                }
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            HStack {
                Button("Back") {
                    withAnimation(.easeOut(duration: 0.22)) {
                        session.screen = .connect
                    }
                }
                Spacer()
                Button {
                    isTrusting = true
                    Task {
                        await session.trustPendingIdentity()
                        isTrusting = false
                    }
                } label: {
                    if isTrusting {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("Trust Server")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(session.pendingIdentity == nil || isTrusting)
            }
            .padding(.horizontal, 28)
            .padding(.bottom, 28)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// C03 Sign In. Native local-account fields.
struct SignInView: View {
    @Environment(ManagerSession.self) private var session
    @State private var isSigningIn = false

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 0) {
                BrandMark()

                Text("Sign In")
                    .font(.title2.weight(.semibold))
                    .padding(.top, 12)

                if let identity = session.verifiedIdentity {
                    Text("Connected to \(identity.deploymentName)")
                        .foregroundStyle(.secondary)
                }

                Form {
                    Section {
                        TextField("Username", text: Binding(
                            get: { session.username },
                            set: { session.username = $0 }
                        ))
                        .textContentType(.username)
                        SecureField("Password", text: Binding(
                            get: { session.password },
                            set: { session.password = $0 }
                        ))
                        .textContentType(.password)
                    } footer: {
                        Text("Organization-managed local accounts. No external identity provider is required.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    if let error = session.signInError {
                        Section {
                            InlineErrorView(error: error)
                            if session.phase == .pendingManagerApproval {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Manager pending approval")
                                        .font(.caption.weight(.semibold))
                                    Text("This management computer is waiting for administrator approval. Ask an administrator to approve the manager identity, then try again. No computer screens are available yet.")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                .accessibilityElement(children: .combine)
                            }
                        }
                    }
                }
                .formStyle(.grouped)
                .frame(maxWidth: 440)
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            HStack {
                Button("Back") {
                    withAnimation(.easeOut(duration: 0.22)) {
                        session.screen = .verify
                    }
                }
                Spacer()
                Button {
                    isSigningIn = true
                    Task {
                        await session.signIn()
                        isSigningIn = false
                    }
                } label: {
                    if isSigningIn {
                        ProgressView().controlSize(.small)
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
            .padding(.horizontal, 28)
            .padding(.bottom, 28)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct BrandMark: View {
    var body: some View {
        Image(systemName: "server.rack")
            .font(.system(size: 36, weight: .light))
            .foregroundStyle(.tint)
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

struct TrustedProfilesList: View {
    let profiles: [ServerProfile]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Trusted Connections")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            ForEach(profiles) { profile in
                LabeledContent(profile.displayName, value: profile.address)
                    .font(.callout)
            }
        }
        .padding(.horizontal, 28)
        .padding(.bottom, 20)
    }
}
