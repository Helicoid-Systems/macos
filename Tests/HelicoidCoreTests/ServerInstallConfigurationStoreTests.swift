import Darwin
import Dispatch
import Foundation
import Testing
@testable import HelicoidCore

private final class StoreLoadSignal: @unchecked Sendable {
    let semaphore = DispatchSemaphore(value: 0)
}

@Suite("Server install configuration store")
struct ServerInstallConfigurationStoreTests {
    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("helicoid-config-store-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test("Round-trips the exact configuration")
    func roundTrip() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = FileServerInstallConfigurationStore(
            fileURL: directory.appendingPathComponent("operation.json"))
        let configuration = ServerInstallTestSupport.configuration()

        try store.save(configuration)

        #expect(store.load() == configuration)
    }

    @Test("A symlinked store file is not followed")
    func symlinkIsNotFollowed() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("target.json")
        let data = try JSONEncoder().encode(ServerInstallTestSupport.configuration())
        try data.write(to: target)
        let link = directory.appendingPathComponent("operation.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        let store = FileServerInstallConfigurationStore(fileURL: link)

        #expect(store.load() == nil)
        let after = try Data(contentsOf: target)
        #expect(after == data)
    }

    @Test("A FIFO is rejected without blocking")
    func fifoIsRejected() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fifo = directory.appendingPathComponent("operation.json")
        guard mkfifo(fifo.path, 0o600) == 0 else {
            Issue.record("Could not create the test FIFO")
            return
        }
        let store = FileServerInstallConfigurationStore(fileURL: fifo)

        let finished = StoreLoadSignal()
        let reader = Thread {
            if store.load() == nil {
                finished.semaphore.signal()
            }
        }
        reader.start()
        let result = finished.semaphore.wait(timeout: .now() + 10)

        switch result {
        case .success:
            break
        case .timedOut:
            Issue.record("The configuration store did not promptly reject the FIFO")
        }
    }

    @Test("An oversized store file is rejected")
    func oversizedIsRejected() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("operation.json")
        try Data(repeating: 0x20, count: 64 * 1024 + 1).write(to: file)
        let store = FileServerInstallConfigurationStore(fileURL: file)

        #expect(store.load() == nil)
    }

    @Test("A corrupt store file is rejected")
    func corruptIsRejected() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("operation.json")
        try Data("not-a-configuration".utf8).write(to: file)
        let store = FileServerInstallConfigurationStore(fileURL: file)

        #expect(store.load() == nil)
    }
}
