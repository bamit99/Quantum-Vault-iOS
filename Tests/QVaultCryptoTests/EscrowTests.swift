import XCTest
import CryptoKit
@testable import QVaultCrypto

/// Escrow (.vaultkey) round-trip tests — iOS-native format.
/// Wire layout matches Android VaultEscrow; the ML-KEM private slot carries
/// the 64-byte seed (interop note documented in Escrow.swift).
final class EscrowTests: XCTestCase {

    func testEscrowRoundTrip() throws {
        let vault = try HybridPQCrypto.generate()
        let passphrase = "correct horse battery staple"

        let blob = try VaultEscrow.export(from: vault, passphrase: passphrase)
        XCTAssertTrue(VaultEscrow.isEscrowBlob(blob))
        XCTAssertEqual(Array(blob.prefix(6)), VaultEscrow.magic)

        // Restore with correct passphrase
        let restored = try VaultEscrow.restore(blob: blob, passphrase: passphrase)
        XCTAssertEqual(restored.fingerprint, VaultEscrow.fingerprint(
            pubMlkem: vault.mlkemPub.rawRepresentation,
            pubX25519: vault.xPub.rawRepresentation
        ))

        // Restored vault decrypts what the original encrypted
        let msg = Data("escrow round-trip".utf8)
        let blob2 = try vault.encrypt(msg)
        XCTAssertEqual(try restored.vault.decrypt(blob2), msg)

        // And vice versa: restored vault encrypts, original decrypts
        let blob3 = try restored.vault.encrypt(msg)
        XCTAssertEqual(try vault.decrypt(blob3), msg)
    }

    func testEscrowWrongPassphraseFailsCleanly() throws {
        let vault = try HybridPQCrypto.generate()
        let blob = try VaultEscrow.export(from: vault, passphrase: "correct passphrase here")
        XCTAssertThrowsError(try VaultEscrow.restore(blob: blob, passphrase: "wrong passphrase!!")) { err in
            XCTAssertEqual(err as? QVaultError, QVaultError.wrongPassphrase)
        }
    }

    func testEscrowRejectsGarbage() {
        XCTAssertFalse(VaultEscrow.isEscrowBlob(Data([0x00, 0x01])))
        XCTAssertThrowsError(try VaultEscrow.restore(blob: Data(repeating: 0, count: 12), passphrase: "x"))
    }
}