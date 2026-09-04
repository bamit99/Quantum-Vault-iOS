import Foundation
import CryptoKit

/// QVAULT container format — byte-compatible with Android HybridPQCrypto.
///
/// v1 layout:  magic(6) | version(1) | ephPub(32) | encapsulation(1088) | salt(32) | wrappedDevice(60) | payload
/// v2 layout:  magic(6) | version(1) | ephPub(32) | encapsulation(1088) | salt(32) | argonSalt(32) | wrappedDevice(60) | wrappedPass(60) | payload
///
/// KEK = HKDF-SHA256(X25519_secret || MLKEM768_secret, salt, info="aiguru-pq-hybrid-v1")
/// FileKey = AES-256-GCM(KEK, wrappedDevice) — or from wrappedPass via Argon2id(passphrase)
public struct HybridPQCrypto {
    // MARK: - Constants (byte-compatible with Android)
    public static let magic: [UInt8] = [0x51, 0x56, 0x41, 0x55, 0x4C, 0x54] // "QVAULT"
    public static let formatV1: UInt8 = 1
    public static let formatV2: UInt8 = 2
    public static let x25519PubLen = 32
    public static let mlkem768EncapLen = 1088
    public static let saltLen = 32
    public static let ivLen = 12
    public static let gcmTagBits = 128
    public static let fileKeyLen = 32
    public static let kekLen = 32
    public static let hkdfInfo = "aiguru-pq-hybrid-v1"
    public static let wrappedKeyLen = ivLen + fileKeyLen + gcmTagBits / 8 // 60 bytes

    // MARK: - Vault keys
    public private(set) var mlkemPriv: MLKEM768.PrivateKey
    public private(set) var xPriv: Curve25519.KeyAgreement.PrivateKey

    public var mlkemPub: MLKEM768.PublicKey { mlkemPriv.publicKey }
    public var xPub: Curve25519.KeyAgreement.PublicKey { xPriv.publicKey }

    public init(mlkemPriv: MLKEM768.PrivateKey, xPriv: Curve25519.KeyAgreement.PrivateKey) {
        self.mlkemPriv = mlkemPriv
        self.xPriv = xPriv
    }

    /// Generate a fresh vault keypair.
    public static func generate() throws -> Self {
        try Self(mlkemPriv: MLKEM768.PrivateKey(), xPriv: Curve25519.KeyAgreement.PrivateKey())
    }

    // MARK: - Encrypt (QVAULT v1 — device-wrap only)

    public func encrypt(_ data: Data) throws -> Data {
        try encryptInternal(data, passphrase: nil)
    }

    /// QVAULT v2: dual-wrapped FileKey — device-key wrap AND passphrase wrap.
    /// Either factor alone can unwrap the payload (matches Android hybridEncrypt(data, passphrase)).
    public func encrypt(_ data: Data, passphrase: String) throws -> Data {
        guard !passphrase.isEmpty else { throw QVaultError.emptyPassphrase }
        return try encryptInternal(data, passphrase: passphrase)
    }

    private func encryptInternal(_ data: Data, passphrase: String?) throws -> Data {
        let fileKey = SymmetricKey(size: .bits256)
        let payloadIv = AESGCM.randomIV()
        let sealed = try AES.GCM.seal(data, using: fileKey, nonce: AES.GCM.Nonce(data: payloadIv))
        guard let payloadCombined = sealed.combined else {
            throw QVaultError.cryptoUnderlying("payload seal failed")
        }
        // payloadCombined = iv || ct || tag — exactly the Android layout

        // 3. Classical leg: ephemeral X25519 ECDH
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.rawRepresentation
        let sharedClassical = try eph.sharedSecretFromKeyAgreement(with: xPub).withUnsafeBytes { Data($0) }

        // 4. PQ leg: ML-KEM-768 encapsulate
        let encResult = try mlkemPub.encapsulate()
        let sharedPQ = encResult.sharedSecret.withUnsafeBytes { Data($0) }
        let encapsulation = encResult.encapsulated

        // 5. KEK = HKDF(classical || PQ, salt)
        var salt = Data(count: Self.saltLen)
        salt.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, Self.saltLen, $0.baseAddress!) }
        let combinedSecret = sharedClassical + sharedPQ
        let kek = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: combinedSecret),
            salt: salt,
            info: Data(Self.hkdfInfo.utf8),
            outputByteCount: Self.kekLen
        )
        let kekData = kek.withUnsafeBytes { Data($0) }

        // 6. Wrap fileKey under KEK
        let fileKeyData = fileKey.withUnsafeBytes { Data($0) }
        let wrappedDevice = try AESGCM.encrypt(key: kekData, data: fileKeyData)

        // 7. Assemble
        var out = Data(Self.magic)
        if let pass = passphrase {
            // v2: argonSalt(32) | wrappedDevice(60) | wrappedPass(60) | payload
            let argonSalt = PassphraseKDF.newSalt()
            let passKek = try PassphraseKDF.derive(passphrase: pass, salt: argonSalt)
            let wrappedPass = try AESGCM.encrypt(key: passKek, data: fileKeyData)
            out.append(Self.formatV2)
            out.append(ephPub)
            out.append(encapsulation)
            out.append(salt)
            out.append(argonSalt)
            out.append(wrappedDevice)
            out.append(wrappedPass)
            out.append(payloadCombined)
        } else {
            out.append(Self.formatV1)
            out.append(ephPub)
            out.append(encapsulation)
            out.append(salt)
            out.append(wrappedDevice)
            out.append(payloadCombined)
        }
        return out
    }

    // MARK: - Decrypt

    public func decrypt(_ blob: Data) throws -> Data {
        try decryptInternal(blob, passphrase: nil)
    }

    public func decrypt(_ blob: Data, passphrase: String) throws -> Data {
        try decryptInternal(blob, passphrase: passphrase)
    }

    private func decryptInternal(_ blob: Data, passphrase: String?) throws -> Data {
        guard blob.count >= Self.magic.count + 1, blob.prefix(Self.magic.count).elementsEqual(Self.magic) else {
            throw QVaultError.notQVaultBlob
        }
        var off = Self.magic.count
        let version = blob[off]; off += 1
        guard version == Self.formatV1 || version == Self.formatV2 else { throw QVaultError.badVersion(Int(version)) }

        let ephPub = blob.subdata(in: off..<off + Self.x25519PubLen); off += Self.x25519PubLen
        let encapsulation = blob.subdata(in: off..<off + Self.mlkem768EncapLen); off += Self.mlkem768EncapLen
        let salt = blob.subdata(in: off..<off + Self.saltLen); off += Self.saltLen

        // v2 adds argonSalt + passphrase-wrapped FileKey before the payload
        // Parse order matches ENCRYPT order (Android encrypt writes:
        //   argonSalt, wrappedDevice, wrappedPass, payload).
        // NOTE: BouncyCastle-side Android v1.0 decrypt parsed wrappedPass BEFORE
        // wrappedDevice — swapped vs encrypt — a field-order bug (found 2026-09-04
        // during iOS cross-verification; GCM auth fails on both legs for v2 blobs).
        let argonSalt: Data?
        if version == Self.formatV2 {
            argonSalt = blob.subdata(in: off..<off + Self.saltLen); off += Self.saltLen
        } else {
            argonSalt = nil
        }
        let wrappedDevice = blob.subdata(in: off..<off + Self.wrappedKeyLen); off += Self.wrappedKeyLen
        let wrappedPass: Data?
        if version == Self.formatV2 {
            wrappedPass = blob.subdata(in: off..<off + Self.wrappedKeyLen); off += Self.wrappedKeyLen
        } else {
            wrappedPass = nil
        }
        let payload = blob.subdata(in: off..<blob.count)

        // ── Leg 1: device keys ──
        do {
            // Classical leg: X25519 ECDH with the ephemeral public key
            let sharedClassical = try xPriv.sharedSecretFromKeyAgreement(
                with: try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephPub)
            )
            // PQ leg: ML-KEM-768 decapsulate
            let sharedPQ = try mlkemPriv.decapsulate(encapsulation)
            let combinedSecret = sharedClassical.withUnsafeBytes { Data($0) }
                + sharedPQ.withUnsafeBytes { Data($0) }
            let kek = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: combinedSecret),
                salt: salt,
                info: Data(Self.hkdfInfo.utf8),
                outputByteCount: Self.kekLen
            )
            let kekData = kek.withUnsafeBytes { Data($0) }
            let fileKeyData = try AESGCM.decrypt(key: kekData, data: wrappedDevice)
            let plaintext = try AESGCM.decrypt(key: fileKeyData, data: payload)
            return plaintext
        } catch {
            // ── Leg 2: passphrase (v2 only) — fully independent of device keys ──
            guard version == Self.formatV2, let pass = passphrase, let aSalt = argonSalt, let wPass = wrappedPass else {
                throw error
            }
            let passKek = try PassphraseKDF.derive(passphrase: pass, salt: aSalt)
            let fileKeyData = try AESGCM.decrypt(key: passKek, data: wPass)
            let plaintext = try AESGCM.decrypt(key: fileKeyData, data: payload)
            return plaintext
        }
    }

    // MARK: - Introspection

    public static func hasMagic(_ blob: Data) -> Bool {
        blob.count > magic.count && blob.prefix(magic.count).elementsEqual(magic)
    }

    public static func isPassphraseCapable(_ blob: Data) -> Bool {
        hasMagic(blob) && blob.count > magic.count && blob[magic.count] == formatV2
    }
}