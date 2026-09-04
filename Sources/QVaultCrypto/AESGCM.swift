import Foundation
import CryptoKit

/// Single-shot AES-256-GCM helper — byte-compatible with Android HybridPQCrypto.aesGcm():
/// encrypt → iv(12) ‖ ciphertext ‖ tag(16); decrypt expects the same layout.
enum AESGCM {
    static let ivLen = 12
    static let tagLen = 16

    /// Cryptographically secure random bytes; throws on entropy-source failure (never ignored).
    static func randomBytes(_ count: Int) throws -> Data {
        var bytes = Data(count: count)
        let rc = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard rc == errSecSuccess else { throw QVaultError.randomGenerationFailed }
        return bytes
    }

    static func randomIV() throws -> Data {
        try randomBytes(ivLen)
    }

    static func encrypt(key: Data, data: Data) throws -> Data {
        let iv = try randomIV()
        let sealed = try AES.GCM.seal(data, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: iv))
        guard let combined = sealed.combined else { throw QVaultError.cryptoUnderlying("AES-GCM seal failed") }
        // combined = iv ‖ ct ‖ tag — exactly the Android layout
        return combined
    }

    static func decrypt(key: Data, data: Data) throws -> Data {
        // NOTE: `>=` (not `>`) — AES-GCM legitimately encrypts empty plaintext,
        // producing exactly iv(12) + tag(16) = 28 bytes.
        guard data.count >= ivLen + tagLen else { throw QVaultError.truncatedBlob }
        let iv = data.prefix(ivLen)
        let ct = data.dropFirst(ivLen).prefix(data.count - ivLen - tagLen)
        let tag = data.suffix(tagLen)
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ct, tag: tag)
            return try AES.GCM.open(box, using: SymmetricKey(data: key))
        } catch let e as CryptoKitError {
            // Normalize: callers only ever see QVaultError (precise taxonomy, P1).
            switch e {
            case .authenticationFailure:
                throw QVaultError.authenticationFailure
            default:
                throw QVaultError.cryptoUnderlying("AES-GCM: \(e)")
            }
        }
    }
}