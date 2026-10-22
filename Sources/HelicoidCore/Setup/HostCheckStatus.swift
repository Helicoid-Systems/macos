import Foundation

/// Shared result for read-only host checks presented by setup surfaces.
public enum HostCheckStatus: Hashable, Sendable {
    case pending
    case checking
    case passed
    case needsAttention(detail: String)
}
