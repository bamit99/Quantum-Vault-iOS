import XCTest
import CryptoKit
@testable import QVaultCrypto

/// P0 hardening suite: malformed-input safety + negative tests.
/// Every externally supplied byte sequence is hostile — the parser must throw
/// clean errors, never trap (Foundation's Data.subdata SIGTRAPs on OOB ranges —
/// the original bug class these tests pin).
final class HardeningTests: XCTestCase {

    // MARK: - Fixtures

    private func makeVault() throws -> HybridPQCrypto {
        try HybridPQCrypto.generate()
    }

    private func makeBlob(_ vault: HybridPQCrypto) throws -> Data {
        try vault.encrypt(Data("hardening fixture".utf8))
    }

    // MARK: - Structural garbage (must throw, never trap)

    func testTruncatedV1AtEveryLengthThrowsNotCrashes() throws {
        let vault = try makeVault()
        let blob = try makeBlob(vault)
        // v1 header = magic(6)+version(1)+eph(32)+encap(1088)+salt(32)+wrapped(60) = 1219
        let headerLen = HybridPQCrypto.magic.count + 1 + HybridPQCrypto.x25519PubLen
            + HybridPQCrypto.mlkem768EncapLen + HybridPQCrypto.saltLen + HybridPQCrypto.wrappedKeyLen
        // Truncate the valid blob at EVERY length — must always throw a typed
        // QVaultError, never trap. Cuts inside the header are structural;
        // cuts inside the (authenticated) payload legitimately surface as
        // authenticationFailure — indistinguishable from tampering by design.
        for cut in 0..<blob.count {
            let truncated = blob.prefix(cut)
            XCTAssertThrowsError(try vault.decrypt(truncated), "cut=\(cut) must throw") { e in
                guard let qe = e as? QVaultError else { return XCTFail("unexpected error type") }
                switch qe {
                case .truncatedBlob, .badVersion, .notQVaultBlob:
                    // Structural zone includes the parse-time minimum-payload
                    // check: payload must hold iv(12)+tag(16), so cuts within
                    // 28 bytes past the header are also structural rejections.
                    XCTAssertTrue(cut < headerLen + 28, "structural error at cut=\(cut) beyond header+28")
                case .authenticationFailure:
                    XCTAssertGreaterThanOrEqual(cut, headerLen + 28, "auth failure in header/min-payload zone at cut=\(cut)")
                default:
                    XCTFail("unexpected error \(qe) at cut=\(cut)")
                }
            }
        }
    }

    func testTruncatedV2AtEveryLengthThrowsNotCrashes() throws {
        let vault = try makeVault()
        let v2 = try vault.encrypt(Data("dual".utf8), passphrase: "test-passphrase")
        for cut in 0..<v2.count {
            XCTAssertThrowsError(try vault.decrypt(v2.prefix(cut)), "cut=\(cut) must throw") { e in
                XCTAssertNotNil(e as? QVaultError)
            }
        }
    }

    func testRandomGarbageNeverTraps() throws {
        let vault = try makeVault()
        // Deterministic pseudo-random garbage sweep across interesting lengths
        var seed: UInt64 = 0xC0FFEE
        func nextByte() -> UInt8 {
            seed &*= 6364136223846793005
            seed = (seed >> 7) &+ 0x9E3779B97F4A7C15
            return UInt8(truncatingIfNeeded: seed >> 33)
        }
        for len in [0, 1, 5, 6, 7, 8, 20, 100, 1200, 1500, 3000] {
            let garbage = Data((0..<len).map { _ in nextByte() })
            XCTAssertThrowsError(try vault.decrypt(garbage), "len=\(len)") { e in
                XCTAssertNotNil(e as? QVaultError)
            }
        }
    }

    func testValidMagicWithGarbageBodyThrows() throws {
        let vault = try makeVault()
        // Valid magic + version but garbage/short body — parser must not trap
        for bodyLen in [0, 1, 5, 31, 32, 100] {
            var blob = Data(HybridPQCrypto.magic)
            blob.append(HybridPQCrypto.formatV1)
            blob.append(Data(repeating: 0xAB, count: bodyLen))
            XCTAssertThrowsError(try vault.decrypt(blob), "bodyLen=\(bodyLen)") { e in
                XCTAssertNotNil(e as? QVaultError)
            }
        }
    }

    // MARK: - Field-level tampering (auth failures, not traps)

    func testMagicCorruptionThrowsNotQVault() throws {
        let vault = try makeVault()
        let blob = try makeBlob(vault)
        for pos in 0..<6 {
            var bad = blob
            bad[pos] ^= 0xFF
            XCTAssertEqual(try classify(bad), QVaultError.notQVaultBlob)
        }
    }

    func testVersionByteInvalid() throws {
        let vault = try makeVault()
        var bad = try makeBlob(vault)
        bad[6] = 0x07 // neither v1 nor v2
        XCTAssertEqual(try classify(bad), QVaultError.badVersion(7))
    }

    func testEncapsulationByteFlipFailsCleanly() throws {
        let vault = try makeVault()
        var tampered = try makeBlob(vault)
        tampered[7 + 32] ^= 0xFF // inside the encapsulation field
        // device leg GCM auth fails; v1 has no passphrase leg → error (not trap)
        XCTAssertThrowsError(try vault.decrypt(tampered))
    }

    func testSaltCorruptionFailsCleanly() throws {
        let vault = try makeVault()
        var tampered = try makeBlob(vault)
        tampered[7 + 32 + 1088] ^= 0x01 // HKDF salt
        XCTAssertThrowsError(try vault.decrypt(tampered))
    }

    func testPayloadTamperingFailsCleanly() throws {
        let vault = try makeVault()
        var tampered = try makeBlob(vault)
        tampered[tampered.count - 1] ^= 0xFF
        XCTAssertThrowsError(try vault.decrypt(tampered))
    }

    func testParseErrorsNeverTriggerPassphraseFallback() throws {
        // A truncated v2 blob must surface a STRUCTURAL error even when a
        // passphrase is available — parse failures are container defects,
        // not key failures. (Reviewer issue #6)
        // Exception: cuts inside the authenticated payload are indistinguishable
        // from tampering → authenticationFailure is the correct outcome there.
        let vault = try makeVault()
        let v2 = try vault.encrypt(Data("dual".utf8), passphrase: "test-passphrase")
        let headerLen = HybridPQCrypto.magic.count + 1 + HybridPQCrypto.x25519PubLen
            + HybridPQCrypto.mlkem768EncapLen + HybridPQCrypto.saltLen
            + HybridPQCrypto.wrappedKeyLen + HybridPQCrypto.saltLen + HybridPQCrypto.wrappedKeyLen
        for cut in [8, 40, 1200, v2.count - 61, v2.count - 1] {
            XCTAssertThrowsError(try vault.decrypt(v2.prefix(cut), passphrase: "test-passphrase"), "cut=\(cut)") { e in
                guard let qe = e as? QVaultError else { return XCTFail("unexpected error type") }
                switch qe {
                case .truncatedBlob, .badVersion, .notQVaultBlob:
                    XCTAssertTrue(cut < headerLen + 28, "structural error at cut=\(cut) beyond header+28")
                case .authenticationFailure:
                    XCTAssertGreaterThanOrEqual(cut, headerLen + 28, "auth failure in header/min-payload zone at cut=\(cut)")
                default:
                    XCTFail("unexpected error \(qe) at cut=\(cut)")
                }
            }
        }
    }

    // MARK: - Empty plaintext (reviewer issue #4)

    func testEmptyPlaintextRoundTrip() throws {
        // AES-GCM legitimately produces iv‖tag (28B) for empty plaintext
        let vault = try makeVault()
        let blob = try vault.encrypt(Data())
        XCTAssertEqual(try vault.decrypt(blob), Data())
    }

    // MARK: - helpers

    /// Classify a parse-level error without crypto side effects.
    private func classify(_ blob: Data) throws -> QVaultError {
        do {
            _ = try HybridPQCrypto.parse(blob)
            return QVaultError.cryptoUnderlying("no-error") // parsed fine — shouldn't happen for corrupted
        } catch let e as QVaultError {
            return e
        }
    }
}
// MARK: - Wrapped-key tampering + tiny-file edges (P2 fuzz expansion)

extension HardeningTests {

    func testV2WrappedDeviceTamperingFallbackBehavior() throws {
        // Either-factor semantics, tampering edition:
        // tampered wrappedDevice kills Leg 1; Leg 2 (passphrase) recovers when
        // the passphrase is correct — on the owning device.
        let vault = try makeVault()
        var blob = try vault.encrypt(Data("wrapped-key tamper".utf8), passphrase: "***")
        blob[HybridPQCrypto.magic.count + 1 + HybridPQCrypto.x25519PubLen
             + HybridPQCrypto.mlkem768EncapLen + HybridPQCrypto.saltLen] ^= 0x01 // wrappedDevice[0]
        XCTAssertEqual(try vault.decrypt(blob, passphrase: "***"), Data("wrapped-key tamper".utf8))
    }

    func testV2WrappedPassTamperingWithForeignKeysFails() throws {
        // Foreign device keys + tampered wrappedPass + correct passphrase →
        // Leg 1 fails (foreign keys), Leg 2 fails (tampered) → clean auth failure.
        let vault = try makeVault()
        var blob = try vault.encrypt(Data("pass-slot tamper".utf8), passphrase: "***")
        let argonSaltOff = HybridPQCrypto.magic.count + 1 + HybridPQCrypto.x25519PubLen
            + HybridPQCrypto.mlkem768EncapLen + HybridPQCrypto.saltLen
        blob[argonSaltOff + 32 + HybridPQCrypto.wrappedKeyLen] ^= 0x01 // wrappedPass[0]
        let foreign = try makeVault()
        XCTAssertThrowsError(try foreign.decrypt(blob, passphrase: "***")) { e in
            XCTAssertEqual(e as? QVaultError, QVaultError.authenticationFailure)
        }
    }

    func testOneBytePlaintextRoundTrip() throws {
        let vault = try makeVault()
        let blob = try vault.encrypt(Data("!".utf8))
        XCTAssertEqual(try vault.decrypt(blob), Data("!".utf8))
        let v2 = try vault.encrypt(Data("!".utf8), passphrase: "***")
        XCTAssertEqual(try vault.decrypt(v2, passphrase: "***"), Data("!".utf8))
    }
}
