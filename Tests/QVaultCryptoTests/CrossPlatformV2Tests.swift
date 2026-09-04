import XCTest
import CryptoKit
@testable import QVaultCrypto

/// Cross-platform v2 test: decrypt a QVAULT v2 (dual-wrap) blob produced by the
/// FIXED Android code path (post-6bc42dc wire order) using the iOS engine.
/// Vector: Tests/QVaultVectorGenV2.java output (/tmp/qv-vector-v2.txt).
final class CrossPlatformV2Tests: XCTestCase {

    // Values from /tmp/qv-vector-v2.txt (regenerate: Tests/QVaultVectorGenV2.java)
    static let kemSeedB64 = "U9s6N5GigX24qz5mDItm2DPqmD49HVwYX3Z84IW9C/swxzLx0uDew9TU3GjtOePBCpkpcSusghUsAdQ8gKZstw=="
    static let kexPrivB64 = "GFN7+z3zCwEo/O6eou5MicMdhmzRBRL6O2/CYTykTlI="
    static let passphrase = "quantum-vault-cross-test"
    static let expectedPlaintext = "QVAULT v2 dual-wrap: Android fixed code, iOS decrypt"
    static let blobB64 = "UVZBVUxUAg19+8aZGVU9STKMvtzjEb25yx36jw8qemVsekARR8EqVZ0BsoNhTmJwG+2KL8BgDw0DRhqKw4oNPZiJf/S9VSuYxkI1pFsCkpbDJObCkJWDYYYcrwi+32RR8unRHp0CfxeEZOpDgvHkFlTfOB7i6g9KgBWIUzkJjjuDWclVVf2pUQSCHOxzpaIkEZMA0Ns17WU2pHBOW5AnvdQDe76kx8jlsxdX6gCU4aWUvFmMT0T/1R2wJCtyo3D7t+7qmLHORIeBfL0INe4Be/AtpT6BMV7Lx9mi38NjwlF0oMidEPnb4VnV9Eb98bcGu7SvZvgi/btd1sLW2mYY4uhM92C6/i5TiG0NuYItSKF3CjM3G40dT9YLR2J1Oc9RMqb0RRMEp7MJ/niHJlcUwURMDK1CDBI2SUoxfsXmN8siCR/G2DW6fTFRug8bJTV/+zECzB0qMKDY+42TlXmo00RiGW7aeHqXSCpt+jTeZ8RImsgO9hjabOXFWn8YvhJCyrkqPIsFzWF7uPIKAHEnmLZjvr0DRELZnA2MngbhsfTimIQ84KIoFn83wxJrNg2cxtUXr0iZGxxPctwzxpHvSDq3R+jTWGmpmVFQpI5yMWrSRHamNvZEVB1tBUKDo+P+uhFiUrxjL3M4bH/mBOMH/NyK4Srxw77NCeD1vT/oTuT+CCYM5S6FXVMWFs7+aV+4bCv46l4b9ETRSIlZYu1gwgKtyuhHTQA7ArJA59wKW1SjGrM09Gwn7oyd6VGIUSxHuiLE1Tb9BGOXJeADWVN2HpYC4Wq+cO6kFtWNvu0eYDOhXQ2jv5j5+jdxD1alpKEeHu6XRIHc277wYdYoygbBaHAc2uu5RBTu4s3B8cdnLCIb/7YoswK79SlfVVI4aOry76wLmaMHXZsqdgkTiS+UCoExskXA7RhZNcNxInNSG2QS3NpRUt73c/B+0LAojN2mLbqI6mqlWr/Rn67h3c0AqJcrgUZwdVKOHItMPDXfXj0yawH4AVANPJRPKW8JbNbEFcsS40kMnzrhHbi0oQsbkwSLrLLGCtuXOBoO8FlSWCVh2XvlKZ08/Cg7tdX27bDKUrOfRqE7ON4H7bKZHWyBjUCLpD73RrSucPM65Mp6GNJn9T9V1r42lcMVauJMbpWbO4ZjBtfnrv/Ud1pqvy6zZ7xfSoMs6Y3VrEyRq+4I81bs+rn2vYJDhEWvyemfZxsHiQlWzijwwrY8d/XQH1aQWi5CimlCQT3O8cjHDi9BXtmoUYpQZopZBoiOkPqeZKwiac/z64XRY4AZclsC1iZeREV/tD5t1IaXoZw6vmOWf92Tj4wPFkS4oJcu4L9WuFJrcBhwKW4DYqJqEP+3STIPgpsLdUGmj1ddGaT0afQpJHCFYAdYD4gV/KD1kSkFSpEAwgUFPrUC6tn061ooQjQ44BiuF/vj6Krytd+PBcskrKagUXnXcheoU1tEPUJCPixQFr36sjhGqpo9Kbls5p1mwKqNBUm1u21kppADS4ExbnSW+QGe7oOCCLEXNABqmCvs3aKIhwYOuSWH7ncvbbNKyonlNFMHf+XPF/e6/v2IQRBSum8digqywZcB0a8eQA7W2Rj2GI5eo5igxcnIUh2l5fub1dcH7F+175VrWEoReXNvJu1tFXxm5uufCypCO8Tvajz+TsPPmp8tdW5IbZoDi8NAbQpMtTUSoQu7zCuojKGY4VgRd79WGaG5mkEw2Xc4O+az2OoVCdyxTDMf6IhA7bHzdFiWEP/nOvE4QxYG1bPirDk0oe/yGRyAKq7PtktIq9Wmf4f/uOcGaPG/yALqqIaH8bEUuiRr5sEXErGV+Xdu5met3OT7ccwd+bMQdT0="

    func testDecryptAndroidV2BlobPassphraseLeg() throws {
        let vault = try makeVault()
        let blob = Data(base64Encoded: Self.blobB64)!
        XCTAssertTrue(HybridPQCrypto.hasMagic(blob))
        XCTAssertTrue(HybridPQCrypto.isPassphraseCapable(blob))

        // Passphrase leg recovers the FileKey (argonSalt/wrappedPass slices correct).
        let out = try vault.decrypt(blob, passphrase: Self.passphrase)
        XCTAssertEqual(String(data: out, encoding: .utf8), Self.expectedPlaintext)
    }

    func testDecryptAndroidV2BlobDeviceLeg() throws {
        let vault = try makeVault()
        let blob = Data(base64Encoded: Self.blobB64)!

        // Device leg (no passphrase) — proves the wrappedDevice slice is correct too.
        let out = try vault.decrypt(blob)
        XCTAssertEqual(String(data: out, encoding: .utf8), Self.expectedPlaintext)
    }

    func testWrongPassphraseWithForeignKeysFailsCleanly() throws {
        // The Android-bug scenario: a fresh device's keys fail Leg 1, and a wrong
        // passphrase fails Leg 2 → both legs fail → clean error, no partial decrypt.
        let foreign = try HybridPQCrypto.generate()
        let blob = Data(base64Encoded: Self.blobB64)!
        XCTAssertThrowsError(try foreign.decrypt(blob, passphrase: "totally-wrong-passphrase")) {
            XCTAssertFalse(String(describing: $0).isEmpty)
        }
    }

    func testWrongPassphraseWithOwningKeysStillOpensViaDeviceLeg() throws {
        // Documented semantics (same as Android): EITHER factor alone unwraps.
        // Owning device keys + wrong passphrase → device leg succeeds regardless
        // of the passphrase content. This is intentional, not a bug.
        let vault = try makeVault()
        let blob = Data(base64Encoded: Self.blobB64)!
        let out = try vault.decrypt(blob, passphrase: "totally-wrong-passphrase")
        XCTAssertEqual(String(data: out, encoding: .utf8), Self.expectedPlaintext)
    }

    // MARK: - Helpers

    /// The vector's owning vault keys (the device that encrypted the blob).
    private func makeVault() throws -> HybridPQCrypto {
        let kemPriv = try MLKEM768.PrivateKey(
            seedRepresentation: Data(base64Encoded: Self.kemSeedB64)!,
            publicKey: nil
        )
        let xPriv = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(base64Encoded: Self.kexPrivB64)!
        )
        return HybridPQCrypto(mlkemPriv: kemPriv, xPriv: xPriv)
    }
}