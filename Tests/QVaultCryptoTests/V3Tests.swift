import XCTest
import CryptoKit
@testable import QVaultCrypto

/// QVAULT v3 (authenticated header / AAD) test suite.
/// Spec: QVAULT_V3_SPEC.md — header (magic ‖ version ‖ ephPub ‖ encapsulation ‖
/// salt ‖ argonSalt = 1191 B) is AES-GCM AAD on both file-key wraps.
final class V3Tests: XCTestCase {

    // MARK: - Round trips

    func testV3RoundTripWithPassphrase() throws {
        let vault = try HybridPQCrypto.generate()
        let msg = Data("v3 dual-wrap round trip".utf8)
        let blob = try vault.encryptV3(msg, passphrase: "***")

        XCTAssertEqual(Array(blob.prefix(6)), HybridPQCrypto.magic)
        XCTAssertEqual(blob[6], HybridPQCrypto.formatV3)
        XCTAssertTrue(HybridPQCrypto.isPassphraseCapable(blob))

        // Owning keys, no passphrase → device leg (AAD-verified)
        XCTAssertEqual(try vault.decrypt(blob), msg)
        // Passphrase leg (AAD-verified)
        XCTAssertEqual(try vault.decrypt(blob, passphrase: "***"), msg)
    }

    func testV3RoundTripWithoutPassphrase() throws {
        let vault = try HybridPQCrypto.generate()
        let msg = Data("v3 device-only".utf8)
        let blob = try vault.encryptV3(msg) // inert filler in wrappedPass slot

        // Device leg works (owning keys, no passphrase)
        XCTAssertEqual(try vault.decrypt(blob), msg)

        // Foreign keys + any passphrase must NOT open it: the filler slot is
        // under a discarded key, and the foreign device leg fails.
        let foreign = try HybridPQCrypto.generate()
        XCTAssertThrowsError(try foreign.decrypt(blob, passphrase: "***")) { e in
            XCTAssertEqual(e as? QVaultError, QVaultError.authenticationFailure)
        }

        // Owning keys + any passphrase still opens via the device leg —
        // documented either-factor semantics (same as v2).
        XCTAssertEqual(try vault.decrypt(blob, passphrase: "irrelevant"), msg)
    }

    // MARK: - AAD binding (the core v3 property)

    func testV3HeaderTamperingRejectedByAAD() throws {
        let vault = try HybridPQCrypto.generate()
        let blob = try vault.encryptV3(Data("aad binding".utf8), passphrase: "***")

        // AAD = blob[0..<1191] (magic ‖ version ‖ ephPub ‖ encapsulation ‖ salt ‖
        // argonSalt). Flip a byte inside EVERY AAD-covered field with FOREIGN
        // device keys so only the passphrase leg could possibly open the blob —
        // tampering anywhere in the AAD span must kill that leg too.
        let foreign = try HybridPQCrypto.generate()
        for pos in [6, 7, 7 + 32, 7 + 32 + 1088, 7 + 32 + 1088 + 32, HybridPQCrypto.v3AADLen - 1] {
            var tampered = blob
            tampered[pos] ^= 0x01
            XCTAssertThrowsError(try foreign.decrypt(tampered, passphrase: "***"), "pos=\(pos)") { e in
                XCTAssertEqual(e as? QVaultError, QVaultError.authenticationFailure)
            }
        }

        // Sanity: the byte just past the AAD (wrappedDevice[0]) is NOT AAD-bound
        // on the passphrase leg — with owning keys + passphrase, tampering it
        // still decrypts via the passphrase leg (either-factor semantics).
        var wrapTampered = blob
        wrapTampered[HybridPQCrypto.v3AADLen] ^= 0x01
        XCTAssertEqual(try vault.decrypt(wrapTampered, passphrase: "***"), Data("aad binding".utf8))
    }

    func testV3DowngradeToV2Rejected() throws {
        // The spec's headline property: zeroing/flipping the version byte to
        // masquerade as v2 fails, because the version is inside the AAD.
        let vault = try HybridPQCrypto.generate()
        let blob = try vault.encryptV3(Data("no downgrade".utf8), passphrase: "***")
        var downgraded = blob
        downgraded[6] = HybridPQCrypto.formatV2 // forged version byte

        // The v2 parser path reads the same layout, but both GCM legs were
        // sealed with v3's AAD (version 3 inside) → auth failure, not a silent
        // reinterpretation.
        XCTAssertThrowsError(try vault.decrypt(downgraded, passphrase: "***")) { e in
            XCTAssertEqual(e as? QVaultError, QVaultError.authenticationFailure)
        }
    }

    func testV3ForeignDeviceWithPassphraseRecovers() throws {
        // Fresh device keys fail the device leg; passphrase leg alone recovers
        // (AAD still binds — proves the fallback path respects v3 AAD too).
        let vaultA = try HybridPQCrypto.generate()
        let msg = Data("escrow-style recovery".utf8)
        let blob = try vaultA.encryptV3(msg, passphrase: "***")

        let vaultB = try HybridPQCrypto.generate()
        XCTAssertEqual(try vaultB.decrypt(blob, passphrase: "***"), msg)
        XCTAssertThrowsError(try vaultB.decrypt(blob)) // no passphrase → device leg fails
    }

    // MARK: - Compatibility

    func testV3EngineStillDecryptsV1AndV2() throws {
        let vault = try HybridPQCrypto.generate()
        let msg = Data("legacy interop".utf8)
        let v1 = try vault.encrypt(msg)
        let v2 = try vault.encrypt(msg, passphrase: "***")
        XCTAssertEqual(try vault.decrypt(v1), msg)
        XCTAssertEqual(try vault.decrypt(v2, passphrase: "***"), msg)
        XCTAssertEqual(blobVersion(v1), 1)
        XCTAssertEqual(blobVersion(v2), 2)
    }

    private func blobVersion(_ blob: Data) -> UInt8 { blob[6] }
}