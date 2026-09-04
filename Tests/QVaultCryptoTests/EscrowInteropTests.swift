import XCTest
import CryptoKit
@testable import QVaultCrypto

/// Escrow cross-platform interop tests.
///
/// Vectors from Tests/QVaultEscrowVectorGen.java (Android-identical code path):
///  - SEED escrow:  payload = xPriv(32) ‖ mlkemSeed(64) ‖ pubMlkem(1184) ‖ pubX25519(32)  → 1340 B wire
///  - EXPANDED escrow: payload = xPriv(32) ‖ expanded(2400) ‖ pubMlkem(1184) ‖ pubX25519(32) → 3676 B wire
///
/// Interop matrix (verified):
///  - Android→Android: both formats work (BC ctor auto-detects)
///  - iOS escrow → Android restore: works (BC ctor accepts 64-byte seed form, proven in BCSeedInterop.java)
///  - Android escrow (expanded) → iOS restore: NOT possible natively — CryptoKit has no
///    expanded-key import; iOS parses and rejects with a clear error. Android should switch
///    escrow export to the seed format (getSeed() instead of getEncoded()) for full interop.
final class EscrowInteropTests: XCTestCase {

    static let passphrase = "escrow-recovery-passphrase"

    // From /tmp/qv-escrow-vector.txt (QVaultEscrowVectorGen.java)
    static let escrowSeedB64 = "VktFWTEAhoi0P7Vi4bUHW0XjiqQJcVLuMAYxX1ENCoo6g3C3HoymJzvBhrLyH1SzGMGShZPLWKBa1NkxdgZNRWHeu69Lad10Y+qcpYXEzUNtriPEAmKGaNv3JWvIjimcQlWAKpzR/ibxehKbWdk5EM9ocsY2GgF22r4V4+Gw2vSYd6+XSuxx5OG5jzivgoEnV2JFjtJZYHjJD+Fl5WQdOOOXvwn+gl1KJJyqv68UmqI7tYsNR1YcLWU8Klc+TJWvtvUPwrypURQdRuAjdF+4AS6J7DaO4v0wJgvMYBmmCNr6UMdLq51QyLgvDwh+9akqHAwpdI8NhZtWpIItbGwnFVN0I5F54qMPa1tZ+fYS5S0TsikuT/76mMsMEp0TdhiLGUyj3Ya5kALvzJYgsSv/GqH3EkAAuIY7EO553pvBWmm0v5fUvhVSShQiGi1H1Jm+V5BGSuU5+bJj1bC0OSk7pTAD4R1Ydtxy1So9b/GNy++z1sOizQ90bNdvGZxjc7OELSVkjxqAEXw/qRdVDTvpr8OFA8WifzbHxzxjQlG+WCiDtSZzbvlA+QS0PfADraFvB4zR3uTZpvMs/mL3CxqhnkFHXa5Tk15Viv332zU6h5MOd5f6QNQMnudguH7vBELmqRh0GHH1heyC75H2av/sN6yT6RHH4PPdmuKWuq4I1JV40RJemVLAgg1Je0i75UDEpU9YYYjox8Nt2yqRaw/yQMOJMgmTVfLR+WqvgSZ84v7bALs6t50yk3fNPfI42dibPMQjcod73laj1unJGmQkh6GKQ+lgVg0hroolz4E83AQ7sYi7eC2AVJf822OE+GZwDxOSnzWTmStSYwp/dWzEYZRQGfqmWUtzspfhvAcQXnyyEmEedJbGNoyGGDf3I/exRFQb4o79xLV8v2buMIIUeE+/meTn3R7Qs+VcTYs9aeuyCt8LUyDHr5DRXT0ZLzUpyRBVruOZ+gEjTjguxTxzCJ5gL6jOF3UfS4WnxvmJcTP57JQtxH5DdhqriK9i1tR/iW/RFIm3jtDBMPL2Za8wJX2TeKCeuOTqBceD8u+w+BGBoLtG9NVP9RtbCyjfx9gi1kEOmVE4/b20R05InfvlCT38FHXc2zaueGGoLm5KSKelyXBvqrbcaAXewUWOGOrSzLjEwgHQbGtgun4peQJAeIX8uicjyVFxPkgeixhbvziLjDqr5+VUyIbd/afTXCBi90FjLt48jGvK3OgVFW04DMmaJ31MDdgH8MXYCntcR5MCCFjF9lgAK+akdxIj2hkxGPi2viET/SZHX2U6HI5QYEINXPO+s5CeWdrLDI66k+Llh58xwGqE+Azy62aPOUsBwnKFG/yRqDIGqpLdN09rorGm8hKAddIA4xfLY4zZQwyPmHv2J/StiO+qIjki5udK/V98Zn6M8Gmh2mdwcgQCOn33xeZNEDP61qmLf4Hu4LeEG0tNdtEqZDkvuKA4tlrM8cF+m4z5pclmePQxcjlxmP3qH2NTYipdulwCzIECQjhP0T1AEQbZX27g2ZA1FZU/cZMSA14gGcoQBNDGvhvKWZISxHZRYOBSb3YM0H1T4ynjzPPFCvuLLOOGdf+8HqijE056IXc+czA3EeQs72IJONHiEgJSPx2MhHx5Z3+6MzYh9SUk16TrmP8vfAtEhgyyeJf19s8uviayPSwby0pBeNRKTCYNhFXm40ffImofE4N6BtNPkPQHupI6I1bAh4V0vL2xEWKe5Zwx65Kcif7iKUjRdv5iQN1hUGV9ESVRxyGHmUuhVrPquDnKN63n+bUmTgt+RJqKbcdrP2cz6LQbDPlvnB/+btrOKNRjStLlInKsLQ=="
    static let escrowExpandedB64 = "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"
    static let v2BlobB64 = "UVZBVUxUAg19+8aZGVU9STKMvtzjEb25yx36jw8qemVsekARR8EqVZ0BsoNhTmJwG+2KL8BgDw0DRhqKw4oNPZiJf/S9VSuYxkI1pFsCkpbDJObCkJWDYYYcrwi+32RR8unRHp0CfxeEZOpDgvHkFlTfOB7i6g9KgBWIUzkJjjuDWclVVf2pUQSCHOxzpaIkEZMA0Ns17WU2pHBOW5AnvdQDe76kx8jlsxdX6gCU4aWUvFmMT0T/1R2wJCtyo3D7t+7qmLHORIeBfL0INe4Be/AtpT6BMV7Lx9mi38NjwlF0oMidEPnb4VnV9Eb98bcGu7SvZvgi/btd1sLW2mYY4uhM92C6/i5TiG0NuYItSKF3CjM3G40dT9YLR2J1Oc9RMqb0RRMEp7MJ/niHJlcUwURMDK1CDBI2SUoxfsXmN8siCR/G2DW6fTFRug8bJTV/+zECzB0qMKDY+42TlXmo00RiGW7aeHqXSCpt+jTeZ8RImsgO9hjabOXFWn8YvhJCyrkqPIsFzWF7uPIKAHEnmLZjvr0DRELZnA2MngbhsfTimIQ84KIoFn83wxJrNg2cxtUXr0iZGxxPctwzxpHvSDq3R+jTWGmpmVFQpI5yMWrSRHamNvZEVB1tBUKDo+P+uhFiUrxjL3M4bH/mBOMH/NyK4Srxw77NCeD1vT/oTuT+CCYM5S6FXVMWFs7+aV+4bCv46l4b9ETRSIlZYu1gwgKtyuhHTQA7ArJA59wKW1SjGrM09Gwn7oyd6VGIUSxHuiLE1Tb9BGOXJeADWVN2HpYC4Wq+cO6kFtWNvu0eYDOhXQ2jv5j5+jdxD1alpKEeHu6XRIHc277wYdYoygbBaHAc2uu5RBTu4s3B8cdnLCIb/7YoswK79SlfVVI4aOry76wLmaMHXZsqdgkTiS+UCoExskXA7RhZNcNxInNSG2QS3NpRUt73c/B+0LAojN2mLbqI6mqlWr/Rn67h3c0AqJcrgUZwdVKOHItMPDXfXj0yawH4AVANPJRPKW8JbNbEFcsS40kMnzrhHbi0oQsbkwSLrLLGCtuXOBoO8FlSWCVh2XvlKZ08/Cg7tdX27bDKUrOfRqE7ON4H7bKZHWyBjUCLpD73RrSucPM65Mp6GNJn9T9V1r42lcMVauJMbpWbO4ZjBtfnrv/Ud1pqvy6zZ7xfSoMs6Y3VrEyRq+4I81bs+rn2vYJDhEWvyemfZxsHiQlWzijwwrY8d/XQH1aQWi5CimlCQT3O8cjHDi9BXtmoUYpQZopZBoiOkPqeZKwiac/z64XRY4AZclsC1iZeREV/tD5t1IaXoZw6vmOWf92Tj4wPFkS4oJcu4L9WuFJrcBhwKW4DYqJqEP+3STIPgpsLdUGmj1ddGaT0afQpJHCFYAdYD4gV/KD1kSkFSpEAwgUFPrUC6tn061ooQjQ44BiuF/vj6Krytd+PBcskrKagUXnXcheoU1tEPUJCPixQFr36sjhGqpo9Kbls5p1mwKqNBUm1u21kppADS4ExbnSW+QGe7oOCCLEXNABqmCvs3aKIhwYOuSWH7ncvbbNKyonlNFMHf+XPF/e6/v2IQRBSum8digqywZcB0a8eQA7W2Rj2GI5eo5igxcnIUh2l5fub1dcH7F+175VrWEoReXNvJu1tFXxm5uufCypCO8Tvajz+TsPPmp8tdW5IbZoDmdbYTV7uo642ZmVd4yEVZ45tv9g9xXBDWbEZp7pVNyx7hznuFOrWrvXX6AT0YDRs7bHzdFiWEP/nOvE4VzMk8pDBoT1j8v/oChWNPq7BtQJFmtejeY75rqpaIci0yFDmrobCtvQEhltr6+snQKyA7mQuyFVEUYuptKHt9LhtMbvvpdz1"
    static let expectedPlaintext = "Escrow-restore cross-platform: Android keys, iOS decrypt"

    func testRestoreAndroidSeedEscrowAndDecrypt() throws {
        // 1. Restore the vault identity from the Android-written seed escrow
        let escrow = Data(base64Encoded: Self.escrowSeedB64)!
        XCTAssertTrue(VaultEscrow.isEscrowBlob(escrow))
        let restored = try VaultEscrow.restore(blob: escrow, passphrase: "escrow-recovery-passphrase")

        // 2. The restored identity decrypts the Android-encrypted v2 file
        let blob = Data(base64Encoded: Self.v2BlobB64)!
        let out = try restored.vault.decrypt(blob)
        XCTAssertEqual(String(data: out, encoding: .utf8), Self.expectedPlaintext)
    }

    func testSeedEscrowRoundTripIosSide() throws {
        // iOS escrow → iOS restore (sanity, uses same wire layout as Android)
        let vault = try HybridPQCrypto.generate()
        let blob = try VaultEscrow.export(from: vault, passphrase: "escrow-recovery-passphrase")
        let restored = try VaultEscrow.restore(blob: blob, passphrase: "escrow-recovery-passphrase")
        XCTAssertEqual(restored.fingerprint, vault.fingerprint)

        let msg = Data("post-escrow round trip".utf8)
        XCTAssertEqual(try restored.vault.decrypt(try vault.encrypt(msg)), msg)
    }

    func testExpandedEscrowRejectedWithClearError() throws {
        // Android's CURRENT expanded-format escrow cannot be imported into CryptoKit.
        // It must parse as far as payload-length validation, then fail cleanly —
        // never partially import or crash.
        let escrow = Data(base64Encoded: Self.escrowExpandedB64)!
        XCTAssertTrue(VaultEscrow.isEscrowBlob(escrow))
        XCTAssertThrowsError(try VaultEscrow.restore(blob: escrow, passphrase: "escrow-recovery-passphrase")) { err in
            // wrongPassphrase would be a MISLEADING error here; we expect a length/parse error
            XCTAssertNotEqual(err as? QVaultError, QVaultError.wrongPassphrase)
        }
    }
}