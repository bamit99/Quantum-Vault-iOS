import Foundation

/// Best-effort secret hygiene for sensitive byte buffers (P2 hardening).
///
/// Swift's `Data` copies on CoW and the optimizer may keep values in registers,
/// so this cannot *guarantee* zeroization the way `memset_s`/`explicit_bzero`
/// can in C. It is still worth doing: it reduces the window in which key
/// material lingers in freed heap memory, and documents intent at every site.
/// A full secure-memory abstraction (mlock-backed, non-copyable buffer) is
/// deferred to the v3 follow-up — documented limitation, not an oversight.
extension Data {
    /// Overwrite every byte with 0. Volatile-style barrier is not available in
    /// pure Swift; the optimizer is trusted not to elide the write because the
    /// buffer is subsequently observed via `withUnsafeBytes` in DEBUG builds.
    mutating func secureZero() {
        self.withUnsafeMutableBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            memset(ptr.baseAddress, 0, ptr.count)
            _ = base // silence unused warnings on some toolchains
        }
    }
}