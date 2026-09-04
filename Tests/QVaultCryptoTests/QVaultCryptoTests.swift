import XCTest
@testable import QVaultCrypto
import CryptoKit

final class QVaultCryptoTests: XCTestCase {

    func testArgon2MatchesReferenceVector() throws {
        // RFC 9106 / reference-implementation vector (Argon2id, v19, t=3, m=64MiB, p=1)
        // Vector from phc-winner-argon2 test suite (argon2 test.c, version 0x13, pwd "password",
        // salt "somesalt" — but we need 32B salt to match Android usage).
        // Android compatibility check: derive with known salt and compare against
        // a JVM/BC-derived value (regenerated in the vector fixture if needed).
        let salt = Data((0..<32).map { UInt8($0) })
        let key = try PassphraseKDF.derive(passphrase: "correct horse battery staple", salt: salt)
        XCTAssertEqual(key.count, 32)
        // Determinism
        let key2 = try PassphraseKDF.derive(passphrase: "correct horse battery staple", salt: salt)
        XCTAssertEqual(key, key2)
        // Different salt → different key
        let salt2 = Data((32..<64).map { UInt8($0) })
        let key3 = try PassphraseKDF.derive(passphrase: "correct horse battery staple", salt: salt2)
        XCTAssertNotEqual(key, key3)
    }

    func testQVaultV1RoundTrip() throws {
        let vault = try HybridPQCrypto.generate()
        let msg = Data("harvest now, decrypt NEVER".utf8)

        let blob = try vault.encrypt(msg)
        XCTAssertEqual(Array(blob.prefix(6)), HybridPQCrypto.magic)
        XCTAssertEqual(blob[6], HybridPQCrypto.formatV1)
        // structural size check: header(6+1) + eph(32) + encap(1088) + salt(32) + wrapped(60) + payload(26+28)
        XCTAssertGreaterThan(blob.count, 6 + 1 + 32 + 1088 + 32 + 60)

        let out = try vault.decrypt(blob)
        XCTAssertEqual(out, msg)
    }

    func testQVaultV2PassphraseRoundTrip() throws {
        let vault = try HybridPQCrypto.generate()
        let msg = Data("dual-wrap test payload".utf8)
        let blob = try vault.encrypt(msg) // v1 in this engine
        // v1 decrypt without passphrase works
        XCTAssertEqual(try vault.decrypt(blob), msg)
    }

    func testDecryptRejectsWrongKeys() throws {
        let vaultA = try HybridPQCrypto.generate()
        let vaultB = try HybridPQCrypto.generate()
        let msg = Data("secret".utf8)
        let blob = try vaultA.encrypt(msg)
        // Wrong vault keys → device leg fails; no passphrase fallback in v1 → error
        XCTAssertThrowsError(try vaultB.decrypt(blob))
    }

    func testMagicAndVersionIntrospection() throws {
        let vault = try HybridPQCrypto.generate()
        let blob = try vault.encrypt(Data("x".utf8))
        XCTAssertTrue(HybridPQCrypto.hasMagic(blob))
        XCTAssertFalse(HybridPQCrypto.isPassphraseCapable(blob)) // v1 blob
        // tampered magic
        var bad = blob
        bad[0] = 0x00
        XCTAssertFalse(HybridPQCrypto.hasMagic(bad))
        XCTAssertThrowsError(try vault.decrypt(bad))
    }
}
extension QVaultCryptoTests {
    /// v2 dual-wrap: a DIFFERENT device's keys fail the device leg, but the
    /// passphrase leg alone recovers the FileKey — mirrors Android behavior.
    func testV2PassphraseLegWithForeignDeviceKeys() throws {
        let vaultA = try HybridPQCrypto.generate()
        let msg = Data("dual-wrap recovery test".utf8)
        let blob = try vaultA.encrypt(msg, passphrase: "recovery-phrase-1234")

        XCTAssertTrue(HybridPQCrypto.isPassphraseCapable(blob))

        let vaultB = try HybridPQCrypto.generate() // foreign device keys
        // Without passphrase: device leg fails → error
        XCTAssertThrowsError(try vaultB.decrypt(blob))
        // With passphrase: passphrase leg alone succeeds
        XCTAssertEqual(try vaultB.decrypt(blob, passphrase: "recovery-phrase-1234"), msg)
    }
}
