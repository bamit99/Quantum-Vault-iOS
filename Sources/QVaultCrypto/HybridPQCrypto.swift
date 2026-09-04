import Foundation
import CryptoKit

/// QVAULT container format — byte-compatible with Android HybridPQCrypto.
///
/// v1 layout:  magic(6) | version(1) | ephPub(32) | encapsulation(1088) | salt(32) | wrappedDevice(60) | payload
/// v2 layout:  magic(6) | version(1) | ephPub(32) | encapsulation(1088) | salt(32) | argonSalt(32) | wrappedDevice(60) | wrappedPass(60) | payload
///
/// KEK = HKDF-SHA256(X25519_secret || MLKEM768_secret, salt, info="aiguru-pq-hybrid-v1")
/// FileKey = AES-256-GCM(KEK, wrappedDevice) — or from wrappedPass via Argon2id(passphrase)
///
/// P0 hardening: all parsing goes through `ByteReader` (bounds-safe — Foundation's
/// Data.subdata traps on out-of-bounds ranges, which turned malformed containers
/// into crashes). The container is fully parsed and structurally validated before
/// any cryptographic primitive runs. Parse errors NEVER trigger passphrase
/// fallback — only key-unwrap/payload authentication failures do.
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

    /// Fully validated container — produced by the strict parser before any crypto runs.
    struct Container {
        let version: UInt8
        let ephPub: Data
        let encapsulation: Data
        let salt: Data
        let argonSalt: Data?      // v2 only
        let wrappedDevice: Data
        let wrappedPass: Data?    // v2 only
        let payload: Data         // non-empty
    }

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

    // MARK: - Strict parser (no crypto here — structure only)

    /// Parse and validate the complete container structure.
    /// Throws .truncatedBlob / .badVersion / .notQVaultBlob / .cryptoUnderlying on any violation.
    static func parse(_ blob: Data) throws -> Container {
        guard blob.count >= magic.count else { throw QVaultError.notQVaultBlob }
        guard blob.prefix(magic.count).elementsEqual(magic) else { throw QVaultError.notQVaultBlob }

        var reader = ByteReader(blob)
        _ = try reader.read(magic.count) // magic already verified
        let version = try reader.readByte()
        guard version == formatV1 || version == formatV2 else { throw QVaultError.badVersion(Int(version)) }

        let ephPub = try reader.read(x25519PubLen)
        let encapsulation = try reader.read(mlkem768EncapLen)
        let salt = try reader.read(saltLen)

        let argonSalt: Data?
        let wrappedPass: Data?
        if version == formatV2 {
            argonSalt = try reader.read(saltLen)
        } else {
            argonSalt = nil
        }
        let wrappedDevice = try reader.read(wrappedKeyLen)
        if version == formatV2 {
            wrappedPass = try reader.read(wrappedKeyLen)
        } else {
            wrappedPass = nil
        }

        // Non-empty payload required, and it must at least hold iv(12) ‖ tag(16) —
        // the representation of an empty plaintext. Anything smaller can never
        // decrypt, so it's rejected structurally, before any crypto runs (#3).
        let payload = try reader.readRemaining()
        guard payload.count >= ivLen + gcmTagBits / 8 else { throw QVaultError.truncatedBlob }

        return Container(version: version, ephPub: ephPub, encapsulation: encapsulation,
                         salt: salt, argonSalt: argonSalt, wrappedDevice: wrappedDevice,
                         wrappedPass: wrappedPass, payload: payload)
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
        let payloadIv = try AESGCM.randomIV()
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
        let salt = try AESGCM.randomBytes(Self.saltLen)
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
            let argonSalt = try PassphraseKDF.newSalt()
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

    /// Error taxonomy:
    ///  - parse errors (.notQVaultBlob/.badVersion/.truncatedBlob/.badMagic) — structural; never fall back
    ///  - key unwrap / payload auth failures — MAY fall back to the passphrase leg (v2)
    private func decryptInternal(_ blob: Data, passphrase: String?) throws -> Data {
        // ── Strict parse first: no crypto runs on an unvalidated container ──
        let c = try Self.parse(blob)

        // ── Leg 1: device keys ──
        do {
            let sharedClassical = try xPriv.sharedSecretFromKeyAgreement(
                with: try Curve25519.KeyAgreement.PublicKey(rawRepresentation: c.ephPub)
            )
            let sharedPQ = try mlkemPriv.decapsulate(c.encapsulation)
            let combinedSecret = sharedClassical.withUnsafeBytes { Data($0) }
                + sharedPQ.withUnsafeBytes { Data($0) }
            let kek = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: combinedSecret),
                salt: c.salt,
                info: Data(Self.hkdfInfo.utf8),
                outputByteCount: Self.kekLen
            )
            let kekData = kek.withUnsafeBytes { Data($0) }
            let fileKeyData = try AESGCM.decrypt(key: kekData, data: c.wrappedDevice)
            return try AESGCM.decrypt(key: fileKeyData, data: c.payload)
        } catch let err as QVaultError {
            // Structural problems are container defects — never fall back.
            switch err {
            case .truncatedBlob, .badEncapsulation:
                throw err
            default:
                break // auth-style failure → passphrase leg may apply
            }
            // ── Leg 2: passphrase (v2 only) — fully independent of device keys ──
            guard c.version == Self.formatV2, let pass = passphrase,
                  let aSalt = c.argonSalt, let wPass = c.wrappedPass else {
                throw err
            }
            let passKek = try PassphraseKDF.derive(passphrase: pass, salt: aSalt)
            let fileKeyData = try AESGCM.decrypt(key: passKek, data: wPass)
            return try AESGCM.decrypt(key: fileKeyData, data: c.payload)
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