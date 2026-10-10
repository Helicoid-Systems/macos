import Foundation

/// Explicit development fixtures. Never loaded unless the process is launched
/// with `--development-fixtures`. Not production pixels or mock production inventory.
public enum DevelopmentFixtures {
    public static let launchFlag = "--development-fixtures"

    public static func isRequested(arguments: [String] = CommandLine.arguments) -> Bool {
        arguments.contains(launchFlag)
    }

    /// Labeled fixture inventory for exercising selection, filter, inclusion, and view-only UI.
    public static func computers() -> [Computer] {
        [
            Computer(
                id: ComputerID("fixture-lab-01"),
                name: "Lab Mac A",
                trustedUserName: "Alex",
                isOnline: true,
                needsAttention: false,
                groupIDs: ["group-lab"]
            ),
            Computer(
                id: ComputerID("fixture-lab-02"),
                name: "Lab Mac B",
                trustedUserName: "Sam",
                isOnline: true,
                needsAttention: true,
                groupIDs: ["group-lab"]
            ),
            Computer(
                id: ComputerID("fixture-office-01"),
                name: "Office PC 01",
                trustedUserName: nil,
                isOnline: false,
                needsAttention: false,
                groupIDs: ["group-office"]
            ),
            Computer(
                id: ComputerID("fixture-office-02"),
                name: "Office PC 02",
                trustedUserName: "Jordan",
                isOnline: true,
                needsAttention: false,
                groupIDs: ["group-office"]
            ),
            Computer(
                id: ComputerID("fixture-ungrouped-01"),
                name: "Spare Laptop",
                trustedUserName: nil,
                isOnline: true,
                needsAttention: false,
                groupIDs: []
            ),
        ]
    }

    public static func groups() -> [ComputerGroup] {
        [
            ComputerGroup(
                id: "group-lab",
                name: "Lab",
                computerIDs: [ComputerID("fixture-lab-01"), ComputerID("fixture-lab-02")]
            ),
            ComputerGroup(
                id: "group-office",
                name: "Office",
                computerIDs: [ComputerID("fixture-office-01"), ComputerID("fixture-office-02")]
            ),
        ]
    }

    @MainActor
    public static func overviewModel() -> OverviewModel {
        OverviewModel(
            authorizedInventory: computers(),
            groups: GroupMembership(groups: groups()),
            inclusion: .all
        )
    }

    public static let banner = "Development fixtures — not production inventory"
}
