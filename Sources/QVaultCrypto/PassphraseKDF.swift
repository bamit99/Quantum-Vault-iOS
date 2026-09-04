import Foundation
import Security
import CArgon2

/// Argon2id passphrase KDF — byte-compatible with Android PassphraseKDF:
/// t=3, m=64 MiB, parallelism=1, 32-byte salt → 32-byte key.
public enum PassphraseKDF {
    public static let saltLen = 32
    public static let keyLen = 32
    static let iterations: UInt32 = 3
    static let memoryKiB: UInt32 = 64 * 1024
    static let parallelism: UInt32 = 1

    /// Cryptographically secure 32-byte salt. Throws on entropy-source failure —
    /// never silently ignored (P1 hardening).
    public static func newSalt() throws -> Data {
        var bytes = Data(count: saltLen)
        let rc = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, saltLen, $0.baseAddress!)
        }
        guard rc == errSecSuccess else { throw QVaultError.randomGenerationFailed }
        return bytes
    }

    /// Derive a 32-byte key from passphrase (UTF-8) and salt. ~0.5–1.5s on phone.
    public static func derive(passphrase: String, salt: Data) throws -> Data {
        guard salt.count == saltLen else { throw QVaultError.badSalt }
        guard !passphrase.isEmpty else { throw QVaultError.emptyPassphrase }

        let passBytes = Array(passphrase.utf8)
        let saltBytes = [UInt8](salt)
        var out = [UInt8](repeating: 0, count: keyLen)

        // Swift imports uint32_t as UInt32 and size_t as Int on arm64.
        let rc = try passBytes.withUnsafeBufferPointer { pwdBuf in
            try saltBytes.withUnsafeBufferPointer { saltBuf in
                try out.withUnsafeMutableBufferPointer { outBuf in
                    argon2id_hash_raw(
                        iterations, memoryKiB, parallelism,
                        pwdBuf.baseAddress!, Int(passBytes.count),
                        saltBuf.baseAddress!, Int(saltBytes.count),
                        outBuf.baseAddress!, Int(keyLen)
                    )
                }
            }
        }
        // ARGON2_OK == 0
        guard rc == 0 else { throw QVaultError.argon2(Int32(rc)) }
        return Data(out)
    }
}

public enum QVaultError: Error, Equatable {
    case badSalt
    case emptyPassphrase
    case argon2(Int32)
    case badMagic
    case badVersion(Int)
    case truncatedBlob
    case wrongPassphrase
    case notQVaultBlob
    case badEncapsulation
    case cryptoUnderlying(String)
    case vaultKeysMissing
    case randomGenerationFailed
    /// Authenticated decryption failed (GCM tag mismatch) — tampered or
    /// truncated data. Normalized from CryptoKitError so callers only ever
    /// see QVaultError (P1 hardening: precise error taxonomy).
    case authenticationFailure
}