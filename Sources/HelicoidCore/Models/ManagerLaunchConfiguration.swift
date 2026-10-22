import Foundation

/// Launch configuration for Helicoid Manager.
/// Source fixtures and development server modes are independent flags.
public struct ManagerLaunchConfiguration: Sendable, Equatable {
    public var useSourceFixtures: Bool
    public var useDevelopmentServer: Bool
    public var developmentServerAddress: String
    public var managerPublicIdentity: String?

    public static let developmentServerFlag = "--development-server"
    public static let developmentServerAddressFlag = "--development-server-address"
    public static let managerIdentityFlag = "--manager-public-identity"

    public init(
        useSourceFixtures: Bool = false,
        useDevelopmentServer: Bool = false,
        developmentServerAddress: String = "http://127.0.0.1:8787",
        managerPublicIdentity: String? = nil
    ) {
        self.useSourceFixtures = useSourceFixtures
        self.useDevelopmentServer = useDevelopmentServer
        self.developmentServerAddress = developmentServerAddress
        self.managerPublicIdentity = managerPublicIdentity
    }

    /// Parse argv. Development server is enabled only with the explicit flag.
    public static func parse(arguments: [String]) -> ManagerLaunchConfiguration {
        var config = ManagerLaunchConfiguration()
        config.useSourceFixtures = arguments.contains("--development-fixtures")

        var index = 0
        while index < arguments.count {
            let arg = arguments[index]
            if arg == developmentServerFlag {
                config.useDevelopmentServer = true
            } else if arg == developmentServerAddressFlag, index + 1 < arguments.count {
                config.developmentServerAddress = arguments[index + 1]
                config.useDevelopmentServer = true
                index += 1
            } else if arg.hasPrefix(developmentServerAddressFlag + "=") {
                config.developmentServerAddress = String(arg.dropFirst(developmentServerAddressFlag.count + 1))
                config.useDevelopmentServer = true
            } else if arg == managerIdentityFlag, index + 1 < arguments.count {
                config.managerPublicIdentity = arguments[index + 1]
                index += 1
            } else if arg.hasPrefix(managerIdentityFlag + "=") {
                let value = String(arg.dropFirst(managerIdentityFlag.count + 1))
                config.managerPublicIdentity = value.isEmpty ? nil : value
            }
            index += 1
        }
        return config
    }
}
