import SwiftUI
import HelicoidCore

/// M01–M04 Computers main view.
struct ComputersView: View {
    @Environment(ManagerSession.self) private var session
    @State private var layout: LayoutKind = .grid
    @State private var previewSize: PreviewSize = .medium
    @State private var selectionAnchor: ComputerID?

    enum LayoutKind: String, CaseIterable, Identifiable {
        case grid
        case list
        var id: String { rawValue }
        var label: String { rawValue == "grid" ? "Grid" : "List" }
    }

    enum PreviewSize: String, CaseIterable, Identifiable {
        case small
        case medium
        case large
        var id: String { rawValue }
        var label: String { rawValue.capitalized }
    }

    var body: some View {
        @Bindable var session = session
        NavigationSplitView {
            if session.showInclusionPanel {
                InclusionPanel()
                    .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            }
        } detail: {
            VStack(spacing: 0) {
                if session.showDevelopmentBanner {
                    DevelopmentBanner()
                }

                scopeLine
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)

                if session.overview.scope.displayedIDs.isEmpty {
                    emptyState
                } else {
                    switch layout {
                    case .grid:
                        computerGrid
                    case .list:
                        computerList
                    }
                }
            }
        }
        .navigationTitle("Computers")
        .searchable(
            text: Binding(
                get: { session.overview.filter.searchText },
                set: { session.overview.setSearchText($0) }
            ),
            placement: .toolbar,
            prompt: "Search computers"
        )
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Picker("Layout", selection: Binding(
                    get: { layout },
                    set: { layout = $0 }
                )) {
                    ForEach(LayoutKind.allCases) { kind in
                        Image(systemName: kind == .grid ? "square.grid.2x2" : "list.bullet")
                            .tag(kind)
                            .accessibilityLabel(kind.label)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 88)

                Picker("Preview size", selection: Binding(
                    get: { previewSize },
                    set: { previewSize = $0 }
                )) {
                    ForEach(PreviewSize.allCases) { size in
                        Text(size.label).tag(size)
                    }
                }

                Picker("Status", selection: Binding(
                    get: { session.overview.filter.status },
                    set: { session.overview.setStatusFilter($0) }
                )) {
                    ForEach(StatusFilter.allCases, id: \.self) { status in
                        Text(status.label).tag(status)
                    }
                }
                .frame(width: 140)

                Toggle("Inclusion", isOn: Binding(
                    get: { session.showInclusionPanel },
                    set: { session.showInclusionPanel = $0 }
                ))
                .toggleStyle(.button)

                Menu("Actions") {
                    Button("Share Screen") { openComposer("Share Screen") }
                    Button("Message") { openComposer("Message") }
                    Button("Actions") { openComposer("Actions") }
                    Divider()
                    Button("Pause Monitoring") {
                        session.overview.pauseMonitoring()
                    }
                    .disabled(session.overview.isMonitoringPaused)
                    Button("Resume Monitoring") {
                        session.overview.resumeMonitoring()
                    }
                    .disabled(!session.overview.isMonitoringPaused)
                }
            }
        }
        .sheet(isPresented: Binding(
            get: { !session.overview.openSnapshots.isEmpty },
            set: { presented in
                if !presented, let snap = session.overview.openSnapshots.first {
                    session.overview.closeSnapshot(snap.id)
                }
            }
        )) {
            if let snapshot = session.overview.openSnapshots.first {
                ActionComposerView(snapshot: snapshot)
            }
        }
    }

    private func openComposer(_ kind: String) {
        _ = session.overview.openSnapshot(actionKind: kind)
    }

    private var scopeLine: some View {
        let line = session.overview.scope.scopeLine(selection: session.overview.selection)
        return HStack {
            Text(line.text)
                .font(.callout.weight(.medium))
                .accessibilityLabel(line.text)
            if line.showsClearSelection {
                Button("Clear Selection") {
                    session.overview.clearSelection()
                }
                .buttonStyle(.link)
            }
            Spacer()
            if session.overview.isMonitoringPaused {
                Label("Monitoring Paused", systemImage: "pause.circle")
                    .foregroundStyle(.secondary)
                    .font(.callout)
            }
        }
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No Computers", systemImage: "desktopcomputer")
        } description: {
            Text(emptyDescription)
        } actions: {
            if session.overview.inclusion.includedIDs(from: session.overview.authorizedInventory.map(\.id)).isEmpty
                && !session.overview.authorizedInventory.isEmpty {
                Button("Choose Computers") {
                    session.showInclusionPanel = true
                    session.overview.selectAllComputersMode()
                }
            }
            if session.overview.authorizedInventory.isEmpty {
                Button("Guided Server Setup") {
                    session.screen = .guidedSetup
                }
            }
        }
    }

    private var emptyDescription: String {
        if session.overview.authorizedInventory.isEmpty {
            return "No enrolled computers are authorized for this account yet. Connect to a Helicoid server, then enroll computers from administration. Nothing is invented here."
        }
        if session.overview.filter.isActive {
            return "No computers match the current search or status filter. Clear Search to see the underlying inventory."
        }
        return "No computers are included. Use the inclusion panel to choose All Computers or individual computers."
    }

    private var computerGrid: some View {
        ScrollView {
            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: previewSize.minTile), spacing: 12)],
                spacing: 12
            ) {
                ForEach(session.overview.scope.computers) { computer in
                    ComputerTile(
                        computer: computer,
                        admission: session.overview.admittedStreams[computer.id] ?? .idle,
                        isSelected: session.overview.selection.selectedIDs.contains(computer.id)
                    )
                    .gesture(
                        TapGesture()
                            .onEnded {
                                if NSEvent.modifierFlags.contains(.shift) {
                                    session.overview.selectRange(from: selectionAnchor, to: computer.id)
                                } else if NSEvent.modifierFlags.contains(.command) {
                                    session.overview.toggleSelection(computer.id)
                                } else {
                                    session.overview.selectOnly(computer.id)
                                    selectionAnchor = computer.id
                                }
                            }
                    )
                    .simultaneousGesture(
                        TapGesture(count: 2)
                            .onEnded {
                                session.openRemoteView(for: computer.id)
                            }
                    )
                    .contextMenu {
                        Button("Open View Screen") {
                            session.openRemoteView(for: computer.id)
                        }
                        Button("Select") {
                            session.overview.selectOnly(computer.id)
                        }
                    }
                }
            }
            .padding(12)
        }
        .sheet(isPresented: Binding(
            get: { !session.openRemoteWindows.isEmpty },
            set: { presented in
                if !presented {
                    session.openRemoteWindows.removeAll()
                }
            }
        )) {
            if let id = session.openRemoteWindows.first {
                RemoteViewWindow(computerID: id)
            }
        }
    }

    private var computerList: some View {
        List(selection: Binding(
            get: { session.overview.selection.selectedIDs },
            set: { session.overview.replaceSelection(with: $0) }
        )) {
            ForEach(session.overview.scope.computers) { computer in
                ComputerRow(
                    computer: computer,
                    admission: session.overview.admittedStreams[computer.id] ?? .idle
                )
                .tag(computer.id)
                .contextMenu {
                    Button("Open View Screen") {
                        session.openRemoteView(for: computer.id)
                    }
                }
            }
        }
        .listStyle(.inset)
    }
}

private extension ComputersView.PreviewSize {
    var minTile: CGFloat {
        switch self {
        case .small: 140
        case .medium: 200
        case .large: 280
        }
    }
}

struct DevelopmentBanner: View {
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill")
            Text(DevelopmentFixtures.banner)
                .font(.callout.weight(.medium))
            Spacer()
        }
        .padding(8)
        .background(.yellow.opacity(0.25))
        .accessibilityElement(children: .combine)
    }
}

struct ComputerTile: View {
    let computer: Computer
    let admission: ObservationAdmission
    let isSelected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(.quaternary.opacity(0.4))
                    .aspectRatio(16.0 / 9.0, contentMode: .fit)
                placeholderContent
            }
            Text(computer.name)
                .font(.callout.weight(.medium))
                .lineLimit(1)
            HStack(spacing: 4) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 7, height: 7)
                Text(statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if computer.needsAttention {
                    Label(computer.statusLabel ?? "Needs Attention", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            if let user = computer.trustedUserName {
                Text(user)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(8)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(isSelected ? Color.accentColor.opacity(0.18) : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(isSelected ? Color.accentColor : Color.clear, lineWidth: 2)
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityLabel)
    }

    private var placeholderContent: some View {
        switch admission {
        case .idle:
            return AnyView(
                Text("Ready")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            )
        case .requesting:
            return AnyView(
                VStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Admitting…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            )
        case .admitted:
            return AnyView(
                VStack(spacing: 6) {
                    Image(systemName: "desktopcomputer")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                    Text("Preview requires engine")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            )
        case .denied(let reason):
            return AnyView(
                Text(reason)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(4)
            )
        case .expired:
            return AnyView(
                Text("Admission expired")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            )
        }
    }

    private var statusText: String {
        if let label = computer.statusLabel {
            return label
        }
        return computer.isOnline ? "Online" : "Offline"
    }

    private var statusColor: Color {
        if computer.needsAttention { return .orange }
        return computer.isOnline ? Color.green : Color.secondary.opacity(0.4)
    }

    private var accessibilityLabel: String {
        var parts = [computer.name]
        parts.append(statusText)
        if let user = computer.trustedUserName { parts.append("User \(user)") }
        if isSelected { parts.append("Selected") }
        return parts.joined(separator: ", ")
    }
}

struct ComputerRow: View {
    let computer: Computer
    let admission: ObservationAdmission

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(computer.name)
                    .font(.body.weight(.medium))
                if let user = computer.trustedUserName {
                    Text(user)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if computer.needsAttention {
                Label("Needs Attention", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.caption)
            }
            Text(computer.isOnline ? "Online" : "Offline")
                .foregroundStyle(.secondary)
                .font(.caption)
        }
        .accessibilityElement(children: .combine)
    }
}

struct InclusionPanel: View {
    @Environment(ManagerSession.self) private var session

    var body: some View {
        @Bindable var session = session
        List {
            Section("Monitoring Inclusion") {
                Toggle("All Computers", isOn: Binding(
                    get: {
                        session.overview.inclusion.allComputersCheckState(
                            authorized: session.overview.authorizedInventory.map(\.id)
                        ) != .off
                    },
                    set: { on in
                        if on {
                            session.overview.selectAllComputersMode()
                        } else {
                            session.overview.clearAllComputersMode()
                        }
                    }
                ))
                .accessibilityLabel("All Computers inclusion")

                ForEach(session.overview.groups.groups) { group in
                    DisclosureGroup(group.name) {
                        ForEach(group.computerIDs, id: \.self) { id in
                            if let computer = session.computer(with: id) {
                                Toggle(computer.name, isOn: Binding(
                                    get: { session.overview.inclusion.includes(id) },
                                    set: { on in
                                        if on {
                                            session.overview.includeComputer(id)
                                        } else {
                                            session.overview.excludeComputer(id)
                                        }
                                    }
                                ))
                            }
                        }
                    }
                }

                let ungrouped = session.overview.authorizedInventory.filter { $0.groupIDs.isEmpty }
                if !ungrouped.isEmpty {
                    DisclosureGroup("Ungrouped Computers") {
                        ForEach(ungrouped) { computer in
                            Toggle(computer.name, isOn: Binding(
                                get: { session.overview.inclusion.includes(computer.id) },
                                set: { on in
                                    if on {
                                        session.overview.includeComputer(computer.id)
                                    } else {
                                        session.overview.excludeComputer(computer.id)
                                    }
                                }
                            ))
                        }
                    }
                }
            }

            Section {
                Text("Inclusion is separate from temporary selection and from authorization. Explicit inclusion never expands silently.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .listStyle(.sidebar)
    }
}

/// Frozen-scope action composer. Shows exact target names and count before dispatch.
struct ActionComposerView: View {
    @Environment(ManagerSession.self) private var session
    let snapshot: ActionSnapshot
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(snapshot.actionKind)
                .font(.title3.weight(.semibold))
            Text(snapshot.targetCount == 1
                 ? "1 Computer Selected"
                 : "\(snapshot.targetCount) Computers Selected")
                .font(.callout)
                .foregroundStyle(.secondary)

            List(snapshot.computerIDs, id: \.self) { id in
                Text(session.computer(with: id)?.name ?? id.rawValue)
            }
            .frame(minHeight: 160)

            Text("Targets are frozen when this action opened. Inventory changes cannot expand this snapshot.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Dispatch") {
                    // Dispatch is not integrated with a server route; do not pretend success.
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(snapshot.targetCount == 0)
            }
        }
        .padding(20)
        .frame(minWidth: 420, minHeight: 320)
    }
}


