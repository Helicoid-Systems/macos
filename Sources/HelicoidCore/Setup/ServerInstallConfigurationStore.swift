import Foundation

/// Persists the exact reviewed deployment configuration so a restarted Manager
/// can ask `status-v2`/`cancel-v2` with the same configuration instead of
/// abandoning the durable operation identity. The server operation record
/// remains authoritative; a stale or tampered local copy is rejected by
/// `status-v2` rather than promoting a false success.
protocol ServerInstallConfigurationStoring: Sendable {
    func load() -> InstallerDeploymentConfiguration?
    func save(_ configuration: InstallerDeploymentConfiguration) throws
}

struct FileServerInstallConfigurationStore: ServerInstallConfigurationStoring {
    let fileURL: URL

    init(fileURL: URL = FileServerInstallConfigurationStore.defaultURL()) {
        self.fileURL = fileURL
    }

    static func defaultURL() -> URL {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base
            .appendingPathComponent("Helicoid", isDirectory: true)
            .appendingPathComponent("installer-operation-v2.json")
    }

    func load() -> InstallerDeploymentConfiguration? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        return try? JSONDecoder().decode(InstallerDeploymentConfiguration.self, from: data)
    }

    func save(_ configuration: InstallerDeploymentConfiguration) throws {
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: 0o700)])
        let data = try JSONEncoder().encode(configuration)
        try data.write(to: fileURL, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o600)],
            ofItemAtPath: fileURL.path)
    }
}
