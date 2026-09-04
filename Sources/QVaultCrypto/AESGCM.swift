import Foundation
import CryptoKit

/// Single-shot AES-256-GCM helper — byte-compatible with Android HybridPQCrypto.aesGcm():
/// encrypt → iv(12) ‖ ciphertext ‖ tag(16); decrypt expects the same layout.
enum AESGCM {
    static let ivLen = 12
    static let tagLen = 16

    static func randomIV() -> Data {
        var iv = Data(count: ivLen)
        iv.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, ivLen, $0.baseAddress!) }
        return iv
    }

    static func encrypt(key: Data, data: Data) throws -> Data {
        let iv = randomIV()
        let sealed = try AES.GCM.seal(data, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: iv))
        guard let combined = sealed.combined else { throw QVaultError.cryptoUnderlying("AES-GCM seal failed") }
        // combined = iv ‖ ct ‖ tag — exactly the Android layout
        return combined
    }

    static func decrypt(key: Data, data: Data) throws -> Data {
        guard data.count > ivLen + tagLen else { throw QVaultError.truncatedBlob }
        let iv = data.prefix(ivLen)
        let ct = data.dropFirst(ivLen).prefix(data.count - ivLen - tagLen)
        let tag = data.suffix(tagLen)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ct, tag: tag)
        return try AES.GCM.open(box, using: SymmetricKey(data: key))
    }
}