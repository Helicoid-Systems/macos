import Darwin
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
    private static let maximumBytes = 64 * 1024
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

    /// Bounded, non-blocking, no-symlink read. A symlink, FIFO, device, or
    /// oversized/regular-shape mismatch is treated as no record rather than
    /// blocking the UI or following attacker-controlled paths.
    func load() -> InstallerDeploymentConfiguration? {
        let descriptor = open(
            fileURL.path,
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }

        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size >= 0,
              info.st_size <= off_t(Self.maximumBytes) else {
            return nil
        }

        let total = Int(info.st_size)
        var data = Data()
        data.reserveCapacity(total)
        var buffer = [UInt8](repeating: 0, count: 8 * 1024)
        var remaining = total
        while remaining > 0 {
            let chunk = min(buffer.count, remaining)
            let count = read(descriptor, &buffer, chunk)
            guard count > 0 else { return nil }
            data.append(contentsOf: buffer[0..<count])
            remaining -= count
        }
        // Reject data appended after fstat's size observation.
        var extra: UInt8 = 0
        guard read(descriptor, &extra, 1) == 0 else { return nil }
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
