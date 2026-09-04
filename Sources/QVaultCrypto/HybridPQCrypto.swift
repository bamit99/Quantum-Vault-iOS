import Foundation
import CryptoKit

/// QVAULT container format — byte-compatible with Android HybridPQCrypto (v1/v2)
/// plus the v3 authenticated-header format (see QVAULT_V3_SPEC.md).
///
/// v1 layout:  magic(6) | version(1) | ephPub(32) | encapsulation(1088) | salt(32) | wrappedDevice(60) | payload
/// v2 layout:  magic(6) | version(1) | ephPub(32) | encapsulation(1088) | salt(32) | argonSalt(32) | wrappedDevice(60) | wrappedPass(60) | payload
/// v3 layout:  identical field order to v2, version=3, and the header prefix
///             (magic ‖ version ‖ ephPub ‖ encapsulation ‖ salt ‖ argonSalt = 1191 B)
///             is authenticated as AES-GCM AAD on both file-key wraps.
///
/// KEK = HKDF-SHA256(X25519_secret || MLKEM768_secret, salt, info="aiguru-pq-hybrid-v1")
/// FileKey = AES-256-GCM(KEK, wrappedDevice) — or from wrappedPass via Argon2id(passphrase)
///
/// Hardening invariants:
///  - All parsing goes through `ByteReader` (Foundation's Data.subdata traps on
///    out-of-bounds ranges — malformed containers must throw, never crash).
///  - The container is fully parsed and structurally validated (incl. minimum
///    payload ≥ iv+tag) before any cryptographic primitive runs.
///  - Passphrase fallback fires ONLY on `.authenticationFailure` from the device
///    leg. Structural and implementation errors propagate (fail closed).
public struct HybridPQCrypto {
    // MARK: - Constants (byte-compatible with Android)
    public static let magic: [UInt8] = [0x51, 0x56, 0x41, 0x55, 0x4C, 0x54] // "QVAULT"
    public static let formatV1: UInt8 = 1
    public static let formatV2: UInt8 = 2
    public static let formatV3: UInt8 = 3
    public static let x25519PubLen = 32
    public static let mlkem768EncapLen = 1088
    public static let saltLen = 32
    public static let ivLen = 12
    public static let gcmTagBits = 128
    public static let fileKeyLen = 32
    public static let kekLen = 32
    public static let hkdfInfo = "aiguru-pq-hybrid-v1"
    public static let wrappedKeyLen = ivLen + fileKeyLen + gcmTagBits / 8 // 60 bytes

    /// v3 AAD length: magic(6) ‖ version(1) ‖ ephPub(32) ‖ encapsulation(1088) ‖ salt(32) ‖ argonSalt(32)
    public static let v3AADLen = magic.count + 1 + x25519PubLen + mlkem768EncapLen + saltLen + saltLen // 1191

    /// Fully validated container — produced by the strict parser before any crypto runs.
    struct Container {
        let version: UInt8
        let ephPub: Data
        let encapsulation: Data
        let salt: Data
        let argonSalt: Data?      // v2/v3
        let wrappedDevice: Data
        let wrappedPass: Data?    // v2/v3
        let payload: Data
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
    /// Throws .notQVaultBlob / .badVersion / .truncatedBlob on any violation.
    static func parse(_ blob: Data) throws -> Container {
        guard blob.count >= magic.count else { throw QVaultError.notQVaultBlob }
        guard blob.prefix(magic.count).elementsEqual(magic) else { throw QVaultError.notQVaultBlob }

        var reader = ByteReader(blob)
        _ = try reader.read(magic.count) // magic already verified
        let version = try reader.readByte()
        guard version == formatV1 || version == formatV2 || version == formatV3
        else { throw QVaultError.badVersion(Int(version)) }

        let ephPub = try reader.read(x25519PubLen)
        let encapsulation = try reader.read(mlkem768EncapLen)
        let salt = try reader.read(saltLen)

        // v2/v3: argonSalt + wrappedPass follow (fixed layout — see QVAULT_V3_SPEC.md)
        let argonSalt: Data?
        let wrappedPass: Data?
        if version == formatV2 || version == formatV3 {
            argonSalt = try reader.read(saltLen)
        } else {
            argonSalt = nil
        }
        let wrappedDevice = try reader.read(wrappedKeyLen)
        if version == formatV2 || version == formatV3 {
            wrappedPass = try reader.read(wrappedKeyLen)
        } else {
            wrappedPass = nil
        }

        // Payload must hold at least iv(12) ‖ tag(16) — the encoding of an empty
        // plaintext. Anything smaller can never decrypt: rejected structurally.
        let payload = try reader.readRemaining()
        guard payload.count >= ivLen + gcmTagBits / 8 else { throw QVaultError.truncatedBlob }

        return Container(version: version, ephPub: ephPub, encapsulation: encapsulation,
                         salt: salt, argonSalt: argonSalt, wrappedDevice: wrappedDevice,
                         wrappedPass: wrappedPass, payload: payload)
    }

    /// AAD slice for a v3 blob: everything from magic through argonSalt.
    /// Zero-copy — the canonical header bytes in wire order.
    static func v3AAD(_ blob: Data) throws -> Data {
        guard blob.count >= v3AADLen else { throw QVaultError.truncatedBlob }
        return blob.prefix(v3AADLen)
    }

    // MARK: - Encrypt (QVAULT v1 — device-wrap only)

    public func encrypt(_ data: Data) throws -> Data {
        try encryptInternal(data, passphrase: nil, mode: .v1)
    }

    /// QVAULT v2: dual-wrapped FileKey — device-key wrap AND passphrase wrap.
    /// Either factor alone can unwrap the payload (matches Android hybridEncrypt(data, passphrase)).
    public func encrypt(_ data: Data, passphrase: String) throws -> Data {
        guard !passphrase.isEmpty else { throw QVaultError.emptyPassphrase }
        return try encryptInternal(data, passphrase: passphrase, mode: .v2)
    }

    /// QVAULT v3: authenticated header (AAD) + always-dual layout.
    /// With a passphrase both legs are live; without one the passphrase wrap is
    /// inert filler encrypted under a discarded key (layout stays fixed).
    public func encryptV3(_ data: Data, passphrase: String? = nil) throws -> Data {
        try encryptInternal(data, passphrase: passphrase, mode: .v3)
    }

    private enum EncryptMode { case v1, v2, v3 }

    private func encryptInternal(_ data: Data, passphrase: String?, mode: EncryptMode) throws -> Data {
        let fileKey = SymmetricKey(size: .bits256)
        let payloadIv = try AESGCM.randomIV()
        let sealed = try AES.GCM.seal(data, using: fileKey, nonce: AES.GCM.Nonce(data: payloadIv))
        guard let payloadCombined = sealed.combined else {
            throw QVaultError.cryptoUnderlying("payload seal failed")
        }
        // payloadCombined = iv ‖ ct ‖ tag — exactly the Android layout

        // Classical leg: ephemeral X25519 ECDH
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.rawRepresentation
        let sharedClassical = try eph.sharedSecretFromKeyAgreement(with: xPub).withUnsafeBytes { Data($0) }

        // PQ leg: ML-KEM-768 encapsulate
        let encResult = try mlkemPub.encapsulate()
        let sharedPQ = encResult.sharedSecret.withUnsafeBytes { Data($0) }
        let encapsulation = encResult.encapsulated

        // KEK = HKDF(classical ‖ PQ, salt)
        let salt = try AESGCM.randomBytes(Self.saltLen)
        let combinedSecret = sharedClassical + sharedPQ
        var combinedSecretMut = combinedSecret
        combinedSecretMut.secureZero()
        let kek = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: combinedSecret),
            salt: salt,
            info: Data(Self.hkdfInfo.utf8),
            outputByteCount: Self.kekLen
        )
        var kekData = kek.withUnsafeBytes { Data($0) }
        defer { kekData.secureZero() }

        let fileKeyData = fileKey.withUnsafeBytes { Data($0) }
        var fileKeyMutable = fileKeyData
        defer { fileKeyMutable.secureZero() }

        switch mode {
        case .v1:
            let wrappedDevice = try AESGCM.encrypt(key: kekData, data: fileKeyData)
            var out = Data(Self.magic)
            out.append(Self.formatV1)
            out.append(ephPub)
            out.append(encapsulation)
            out.append(salt)
            out.append(wrappedDevice)
            out.append(payloadCombined)
            return out

        case .v2:
            guard let pass = passphrase else { throw QVaultError.emptyPassphrase }
            let argonSalt = try PassphraseKDF.newSalt()
            let passKek = try PassphraseKDF.derive(passphrase: pass, salt: argonSalt)
            var passKekMut = passKek
            defer { passKekMut.secureZero() }
            let wrappedDevice = try AESGCM.encrypt(key: kekData, data: fileKeyData)
            let wrappedPass = try AESGCM.encrypt(key: passKek, data: fileKeyData)
            var out = Data(Self.magic)
            out.append(Self.formatV2)
            out.append(ephPub)
            out.append(encapsulation)
            out.append(salt)
            out.append(argonSalt)
            out.append(wrappedDevice)
            out.append(wrappedPass)
            out.append(payloadCombined)
            return out

        case .v3:
            let argonSalt = try AESGCM.randomBytes(Self.saltLen) // always present in v3
            // AAD = magic ‖ version(3) ‖ ephPub ‖ encapsulation ‖ salt ‖ argonSalt
            var aad = Data(Self.magic)
            aad.append(Self.formatV3)
            aad.append(ephPub)
            aad.append(encapsulation)
            aad.append(salt)
            aad.append(argonSalt)
            precondition(aad.count == Self.v3AADLen, "v3 AAD length drift")

            let wrappedDevice = try AESGCM.encrypt(key: kekData, data: fileKeyData, aad: aad)
            let wrappedPass: Data
            if let pass = passphrase, !pass.isEmpty {
                let passKek = try PassphraseKDF.derive(passphrase: pass, salt: argonSalt)
                var passKekMut = passKek
                defer { passKekMut.secureZero() }
                wrappedPass = try AESGCM.encrypt(key: passKek, data: fileKeyData, aad: aad)
            } else {
                // Inert filler: no passphrase leg — encrypted under a discarded key.
                let throwaway = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
                var throwawayMut = throwaway
                defer { throwawayMut.secureZero() }
                wrappedPass = try AESGCM.encrypt(key: throwaway, data: fileKeyData, aad: aad)
            }

            var out = Data(Self.magic)
            out.append(Self.formatV3)
            out.append(ephPub)
            out.append(encapsulation)
            out.append(salt)
            out.append(argonSalt)
            out.append(wrappedDevice)
            out.append(wrappedPass)
            out.append(payloadCombined)
            return out
        }
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
    ///  - `.authenticationFailure` on the device leg — the ONLY error that may
    ///    trigger the v2/v3 passphrase fallback (P1 tightening)
    ///  - everything else propagates immediately (fail closed)
    private func decryptInternal(_ blob: Data, passphrase: String?) throws -> Data {
        // ── Strict parse first: no crypto runs on an unvalidated container ──
        let c = try Self.parse(blob)
        let aad: Data? = c.version == Self.formatV3 ? try Self.v3AAD(blob) : nil

        // ── Leg 1: device keys ──
        do {
            let sharedClassical = try xPriv.sharedSecretFromKeyAgreement(
                with: try Curve25519.KeyAgreement.PublicKey(rawRepresentation: c.ephPub)
            )
            let sharedPQ = try mlkemPriv.decapsulate(c.encapsulation)
            var combinedSecret = sharedClassical.withUnsafeBytes { Data($0) }
                + sharedPQ.withUnsafeBytes { Data($0) }
            defer { combinedSecret.secureZero() }
            let kek = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: combinedSecret),
                salt: c.salt,
                info: Data(Self.hkdfInfo.utf8),
                outputByteCount: Self.kekLen
            )
            var kekData = kek.withUnsafeBytes { Data($0) }
            defer { kekData.secureZero() }
            let fileKeyData = try AESGCM.decrypt(key: kekData, data: c.wrappedDevice, aad: aad)
            defer { var fk = fileKeyData; fk.secureZero() }
            return try AESGCM.decrypt(key: fileKeyData, data: c.payload)
        } catch {
            // ── Fail closed (P1): ONLY an authentication failure on the device
            // leg justifies trying the passphrase leg. Implementation errors,
            // RNG failures, and unexpected crypto errors propagate. ──
            guard case QVaultError.authenticationFailure = error,
                  (c.version == Self.formatV2 || c.version == Self.formatV3),
                  let pass = passphrase,
                  let aSalt = c.argonSalt,
                  let wPass = c.wrappedPass else {
                throw error
            }
            // ── Leg 2: passphrase — fully independent of device keys ──
            let passKek = try PassphraseKDF.derive(passphrase: pass, salt: aSalt)
            var passKekMut = passKek
            defer { passKekMut.secureZero() }
            let fileKeyData = try AESGCM.decrypt(key: passKek, data: wPass, aad: aad)
            defer { var fk = fileKeyData; fk.secureZero() }
            return try AESGCM.decrypt(key: fileKeyData, data: c.payload)
        }
    }

    // MARK: - Introspection

    public static func hasMagic(_ blob: Data) -> Bool {
        blob.count > magic.count && blob.prefix(magic.count).elementsEqual(magic)
    }

    /// v2 and v3 both carry a passphrase-wrap slot (v3's may be inert filler).
    public static func isPassphraseCapable(_ blob: Data) -> Bool {
        hasMagic(blob) && blob.count > magic.count
            && (blob[magic.count] == formatV2 || blob[magic.count] == formatV3)
    }
}