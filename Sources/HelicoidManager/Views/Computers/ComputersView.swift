import SwiftUI
import HelicoidCore

/// M01–M04 Computers main view.
/// Layout, preview size, and panel visibility live on ManagerSession.
struct ComputersView: View {
    @Environment(ManagerSession.self) private var session
    @State private var selectionAnchor: ComputerID?
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        NavigationSplitView {
            if session.presentation.isComputersPanelShown {
                ComputersPanel()
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
                    switch session.presentation.layout {
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
                    get: { session.presentation.layout },
                    set: { session.setPresentationLayout($0) }
                )) {
                    ForEach(ManagerLayoutKind.allCases) { kind in
                        Image(systemName: kind == .grid ? "square.grid.2x2" : "list.bullet")
                            .tag(kind)
                            .accessibilityLabel(kind.label)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 88)

                previewSizeControl

                Picker("Status", selection: Binding(
                    get: { session.overview.filter.status },
                    set: { session.overview.setStatusFilter($0) }
                )) {
                    ForEach(StatusFilter.allCases, id: \.self) { status in
                        Text(status.label).tag(status)
                    }
                }
                .frame(width: 140)

                Toggle("Computers Panel", isOn: Binding(
                    get: { session.presentation.isComputersPanelShown },
                    set: { session.setComputersPanelShown($0) }
                ))
                .toggleStyle(.button)

                Menu("Monitoring") {
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
    }

    private var previewSizeControl: some View {
        Menu {
            Picker("Preview Size", selection: Binding(
                get: { session.presentation.previewSize },
                set: { session.setPresentationPreviewSize($0) }
            )) {
                ForEach(ManagerPreviewSize.allCases) { size in
                    Text("\(size.label) (\(Int(size.tileWidth)))").tag(size)
                }
            }
        } label: {
            Label(session.presentation.previewSize.label, systemImage: "rectangle.resize")
        }
        .accessibilityLabel("Preview size")
    }

    private func openComputerWindow(_ id: ComputerID) {
        guard let key = session.openRemoteView(for: id) else { return }
        openWindow(id: ManagerWindowID.computerView, value: key)
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
            if session.overview.filter.isActive {
                Button("Clear Filters") {
                    session.clearInventoryFilters()
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
        let reason = session.inventoryEmptyReason
        return ContentUnavailableView {
            Label(reason.title, systemImage: "desktopcomputer")
        } description: {
            Text(reason.message)
        } actions: {
            switch reason {
            case .noAuthorizedInventory:
                EmptyView()
            case .noneIncluded:
                Button("Choose Computers") {
                    session.setComputersPanelShown(true)
                }
            case .noResults:
                Button("Clear Filters") {
                    session.clearInventoryFilters()
                }
            }
        }
    }

    private var computerGrid: some View {
        ScrollView {
            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: session.presentation.previewSize.tileWidth), spacing: 12)],
                spacing: 12
            ) {
                ForEach(session.overview.scope.computers) { computer in
                    ComputerTile(
                        computer: computer,
                        admission: session.overview.admittedStreams[computer.id] ?? .idle,
                        isSelected: session.overview.selection.selectedIDs.contains(computer.id)
                    )
                    .focusable()
                    .onKeyPress(.return) {
                        openComputerWindow(computer.id)
                        return .handled
                    }
                    .onKeyPress(.space) {
                        session.overview.toggleSelection(computer.id)
                        selectionAnchor = computer.id
                        return .handled
                    }
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
                                openComputerWindow(computer.id)
                            }
                    )
                    .contextMenu {
                        Button("View Screen") {
                            openComputerWindow(computer.id)
                        }
                        Button("Select") {
                            session.overview.selectOnly(computer.id)
                        }
                        if session.overview.filter.isActive {
                            Button("Clear Filters") {
                                session.clearInventoryFilters()
                            }
                        }
                    }
                }
            }
            .padding(12)
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
                .contentShape(Rectangle())
                .onTapGesture(count: 2) {
                    openComputerWindow(computer.id)
                }
                .contextMenu {
                    Button("View Screen") {
                        openComputerWindow(computer.id)
                    }
                }
            }
        }
        .listStyle(.inset)
        .onKeyPress(.return) {
            if let id = session.overview.selection.selectedIDs.first {
                openComputerWindow(id)
                return .handled
            }
            return .ignored
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

/// Quiet tile: name, trusted user, and relevant exceptions only. No presence dots.
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
            if let user = computer.trustedUserName {
                Text(user)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            if computer.needsAttention {
                Label(computer.statusLabel ?? "Needs Attention", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
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
                Text("Screen Unavailable")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            )
        case .requesting:
            return AnyView(
                VStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Connecting")
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
                    Text("Screen Unavailable")
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

    private var accessibilityLabel: String {
        var parts = [computer.name]
        if let user = computer.trustedUserName { parts.append("User \(user)") }
        if computer.needsAttention { parts.append(computer.statusLabel ?? "Needs Attention") }
        if isSelected { parts.append("Selected") }
        return parts.joined(separator: ", ")
    }
}

/// Compact list row. Activation opens the same view window as the grid.
struct ComputerRow: View {
    let computer: Computer
    let admission: ObservationAdmission

    var body: some View {
        HStack(spacing: 8) {
            Text(computer.name)
                .font(.body)
                .lineLimit(1)
            if let user = computer.trustedUserName {
                Text(user)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            if computer.needsAttention {
                Label(computer.statusLabel ?? "Needs Attention", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.caption)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityLabel)
    }

    private var accessibilityLabel: String {
        var parts = [computer.name]
        if let user = computer.trustedUserName { parts.append("User \(user)") }
        if computer.needsAttention { parts.append(computer.statusLabel ?? "Needs Attention") }
        return parts.joined(separator: ", ")
    }
}

/// Optional Computers panel. Tri-state All/group checkboxes from real inclusion state.
struct ComputersPanel: View {
    @Environment(ManagerSession.self) private var session

    var body: some View {
        List {
            Section("Computers") {
                InclusionCheckbox(title: "All Computers", state: session.allComputersCheckState) {
                    session.applyAllComputersCheckState(session.allComputersCheckState == .on ? .off : .on)
                }

                ForEach(session.overview.groups.groups) { group in
                    InclusionCheckbox(title: group.name, state: session.groupCheckState(groupID: group.id)) {
                        let state = session.groupCheckState(groupID: group.id)
                        session.applyGroupCheckState(groupID: group.id, state: state == .on ? .off : .on)
                    }

                    ForEach(ungroupedMembers(of: group), id: \.id) { computer in
                        computerToggle(computer)
                            .padding(.leading, 12)
                    }
                }

                let ungrouped = ungroupedComputers()
                if !ungrouped.isEmpty {
                    DisclosureGroup("Ungrouped") {
                        ForEach(ungrouped) { computer in
                            computerToggle(computer)
                        }
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }

    private func computerToggle(_ computer: Computer) -> some View {
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
        .toggleStyle(.checkbox)
    }

    /// First group wins so a computer never appears twice in the panel.
    private func ungroupedMembers(of group: ComputerGroup) -> [Computer] {
        let seenEarlier = Set(
            session.overview.groups.groups
                .prefix(while: { $0.id != group.id })
                .flatMap(\.computerIDs)
        )
        return group.computerIDs.compactMap { id in
            guard !seenEarlier.contains(id), let computer = session.computer(with: id) else { return nil }
            return computer
        }
    }

    private func ungroupedComputers() -> [Computer] {
        let claimed = Set(session.overview.groups.groups.flatMap(\.computerIDs))
        return session.overview.authorizedInventory.filter { computer in
            !claimed.contains(computer.id) && computer.groupIDs.isEmpty
        }
    }

 }

/// AppKit supplies the actual mixed checkbox state and native keyboard semantics.
struct InclusionCheckbox: NSViewRepresentable {
    let title: String
    let state: CheckState
    let action: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(action: action) }

    func makeNSView(context: Context) -> NSButton {
        let button = NSButton(checkboxWithTitle: title, target: context.coordinator, action: #selector(Coordinator.toggle))
        button.allowsMixedState = true
        return button
    }

    func updateNSView(_ button: NSButton, context: Context) {
        context.coordinator.action = action
        button.title = title
        button.state = switch state {
        case .on: .on
        case .off: .off
        case .mixed: .mixed
        }
    }

    @MainActor
    final class Coordinator: NSObject {
        var action: () -> Void
        init(action: @escaping () -> Void) { self.action = action }
        @objc func toggle() { action() }
    }
}
