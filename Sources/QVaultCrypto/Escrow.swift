import Foundation
import CryptoKit

/// Passphrase-encrypted key escrow — byte-compatible layout with Android VaultEscrow,
/// with one interop note: the ML-KEM-768 private slot carries the 64-byte SEED
/// (FIPS 203 deterministic expansion) instead of BouncyCastle's 2400-byte expanded form.
/// Android restores via BC's seed-format constructor; iOS restores via
/// MLKEM768.PrivateKey(seedRepresentation:). Same positions, length-derived parsing.
///
/// .vaultkey wire format:
///   magic "VKEY1\0" (6B)
///   argonSalt        (32B)
///   AES-GCM(passKek, payload)  [iv(12B) || ct || tag]
///     payload := xPriv(32B) || seed(64B) || pubMlkem(1184B) || pubX25519(32B)
public enum VaultEscrow {
    public static let magic: [UInt8] = [0x56, 0x4B, 0x45, 0x59, 0x31, 0x00] // "VKEY1\0"
    public static let fileName = ".vaultkey"
    static let ivLen = 12
    static let x25519PrivLen = 32
    static let x25519PubLen = 32
    static let mlkem768PubLen = 1184
    static let mlkem768SeedLen = 64

    public struct RestoredKeys {
        public let vault: HybridPQCrypto
        public let fingerprint: String
    }

    /// SHA-256 fingerprint (base64) of the vault public halves — matches Android
    /// VaultEscrow.fingerprint(pubMlkem, pubX25519) which hashes pubX25519 ‖ pubMlkem.
    public static func fingerprint(pubMlkem: Data, pubX25519: Data) -> String {
        let all = pubX25519 + pubMlkem
        return Data(SHA256.hash(data: all)).base64EncodedString()
    }

    /// Build the escrow blob from the current vault keys under `passphrase`.
    /// Save as ".vaultkey" in the vault folder.
    public static func export(from vault: HybridPQCrypto, passphrase: String) throws -> Data {
        guard !passphrase.isEmpty else { throw QVaultError.emptyPassphrase }
        let payload = try vault.exportForEscrow() // xPriv(32) ‖ seed(64) ‖ pubMlkem(1184) ‖ pubX25519(32)
        let argonSalt = PassphraseKDF.newSalt()
        let kek = try PassphraseKDF.derive(passphrase: passphrase, salt: argonSalt)
        let ct = try AESGCM.encrypt(key: kek, data: payload)
        return Data(magic) + argonSalt + ct
    }

    /// Restore vault keys from an escrow blob using `passphrase`.
    /// Wrong passphrase → AES-GCM auth failure → clean error, no partial state.
    public static func restore(blob: Data, passphrase: String) throws -> RestoredKeys {
        guard blob.count > magic.count + PassphraseKDF.saltLen + ivLen + x25519PrivLen else {
            throw QVaultError.truncatedBlob
        }
        guard blob.prefix(magic.count).elementsEqual(magic) else { throw QVaultError.badMagic }

        var off = magic.count
        let escrowSalt = blob.subdata(in: off..<off + PassphraseKDF.saltLen); off += PassphraseKDF.saltLen
        let ivAndCt = blob.subdata(in: off..<blob.count)

        let kek = try PassphraseKDF.derive(passphrase: passphrase, salt: escrowSalt)
        let payload: Data
        do {
            payload = try AESGCM.decrypt(key: kek, data: ivAndCt)
        } catch {
            throw QVaultError.wrongPassphrase
        }

        let expected = x25519PrivLen + mlkem768SeedLen + mlkem768PubLen + x25519PubLen
        guard payload.count == expected else { throw QVaultError.truncatedBlob }

        var p = 0
        let xPrivData = payload.subdata(in: p..<p + x25519PrivLen); p += x25519PrivLen
        let seed = payload.subdata(in: p..<p + mlkem768SeedLen); p += mlkem768SeedLen
        let pubMlkem = payload.subdata(in: p..<p + mlkem768PubLen); p += mlkem768PubLen
        let pubX25519 = payload.subdata(in: p..<p + x25519PubLen)

        let xPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: xPrivData)
        let mlkemPriv = try MLKEM768.PrivateKey(
            seedRepresentation: seed,
            publicKey: try MLKEM768.PublicKey(rawRepresentation: pubMlkem)
        )
        let vault = HybridPQCrypto(mlkemPriv: mlkemPriv, xPriv: xPriv)

        // Verify restored identity matches the public halves in the escrow
        let fp = fingerprint(pubMlkem: pubMlkem, pubX25519: pubX25519)
        guard fp == fingerprint(pubMlkem: vault.mlkemPub.rawRepresentation, pubX25519: vault.xPub.rawRepresentation) else {
            throw QVaultError.cryptoUnderlying("escrow identity mismatch")
        }
        return RestoredKeys(vault: vault, fingerprint: fp)
    }

    public static func isEscrowBlob(_ blob: Data) -> Bool {
        blob.count > magic.count && blob.prefix(magic.count).elementsEqual(magic)
    }
}

// MARK: - Escrow export support on the vault

extension HybridPQCrypto {
    /// payload := xPriv(32) ‖ seed(64) ‖ pubMlkem(1184) ‖ pubX25519(32)
    public func exportForEscrow() throws -> Data {
        let seed = mlkemPriv.seedRepresentation
        guard seed.count == 64 else { throw QVaultError.cryptoUnderlying("unexpected ML-KEM seed length \(seed.count)") }
        return xPriv.rawRepresentation + seed + mlkemPub.rawRepresentation + xPub.rawRepresentation
    }

    /// Public accessors for app-layer persistence (Keychain) and display.
    public var mlkemSeed: Data { mlkemPriv.seedRepresentation }
    public var xPrivRaw: Data { xPriv.rawRepresentation }
    public var mlkemPubRaw: Data { mlkemPub.rawRepresentation }
    public var xPubRaw: Data { xPub.rawRepresentation }

    /// Identity fingerprint (base64 of SHA-256 over pubX25519 ‖ pubMlkem) — matches Android.
    public var fingerprint: String {
        VaultEscrow.fingerprint(pubMlkem: mlkemPubRaw, pubX25519: xPubRaw)
    }
}