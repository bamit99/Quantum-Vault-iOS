import Foundation

/// Bounds-safe sequential reader for untrusted blobs.
/// Every read either succeeds fully or throws `QVaultError.truncatedBlob` —
/// no trapping subscripts, no partial parses. (P0 hardening: Foundation's
/// `Data.subdata(in:)` traps (SIGTRAP) on out-of-bounds ranges, which turned
/// malformed containers into crashes; this reader makes that impossible.)
struct ByteReader {
    private let data: [UInt8]
    private(set) var offset = 0

    init(_ data: Data) {
        self.data = [UInt8](data)
    }

    var remaining: Int { data.count - offset }

    /// Read exactly `count` bytes or throw `.truncatedBlob`.
    mutating func read(_ count: Int) throws -> Data {
        guard count >= 0, offset <= data.count, count <= data.count - offset else {
            throw QVaultError.truncatedBlob
        }
        let out = Data(data[offset..<(offset + count)])
        offset += count
        return out
    }

    /// Read a single byte or throw `.truncatedBlob`.
    mutating func readByte() throws -> UInt8 {
        guard offset < data.count else { throw QVaultError.truncatedBlob }
        let b = data[offset]
        offset += 1
        return b
    }

    /// Read all remaining bytes.
    mutating func readRemaining() throws -> Data {
        try read(remaining)
    }
}