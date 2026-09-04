# QVAULT v3 — Authenticated Container Format (Specification)

**Status:** Draft · **Last updated:** 2026-09-04  
**Target:** Quantum Vault iOS (v3 in `HybridPQCrypto.swift`) · Android parity later

---

## 1. Motivation

The current QVAULT v1 and v2 formats authenticate the encrypted payload and wrapped file keys via AES-GCM, but the **container header itself is not authenticated as Associated Data (AAD)**. This means an attacker can manipulate header fields (version byte, ephemeral public key, ML-KEM encapsulation, salt) without triggering an immediate cryptographic failure at the point where that metadata is interpreted.

The fix is to supply the canonical header as AAD to the payload's AES-GCM operation. This cryptographically binds the header to the ciphertext without changing the underlying key schedule, KEM primitives, or KDF parameters.

**v3 does not replace v1/v2.** Android devices continue to produce and consume v1 and v2 blobs. The iOS engine detects v3 by its version byte and applies the AAD-verified path; v1/v2 paths remain unchanged.

---

## 2. Wire Format

### v3 Layout (AAD-aware)

```
magic         "QVAULT"          6 B         (untouched)
version       = 3                1 B
header        = ephPub(32)      32 B         ← AAD scope
               ‖ encapsulation  1088 B
               ‖ salt           32 B
               ‖ argonSalt      32 B         (v3 only — always present for dual-wrap)
               ‖ wrappedDevice  60 B
               ‖ wrappedPass    60 B
───────────────────────────────────────────────
payload       = iv(12) ‖ ct ‖ tag(16)
```

**AAD scope** = `version + header` (everything before the payload). The AAD is supplied to the outer AES-GCM decryption of the wrapped file key, **not** to the inner payload decryption — that way the header is bound to the key that protects the file, and any tampering with header fields causes the key unwrap to fail.

### Fields

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 6 | `magic` | `0x51 0x56 0x41 0x55 0x4C 0x54` = "QVAULT" |
| 6 | 1 | `version` | `3` |
| 7 | 32 | `ephPub` | Ephemeral X25519 public key (raw) |
| 39 | 1088 | `encapsulation` | ML-KEM-768 encapsulation (FIPS 203) |
| 1127 | 32 | `salt` | HKDF salt for device-leg KEK |
| 1159 | 32 | `argonSalt` | Argon2id salt for passphrase-leg KEK |
| 1191 | 60 | `wrappedDevice` | AES-256-GCM(KEK, fileKey) — iv‖ct‖tag |
| 1251 | 60 | `wrappedPass` | AES-256-GCM(passKek, fileKey) — iv‖ct‖tag |
| 1311 | — | `payload` | AES-256-GCM(fileKey, data, AAD: version ‖ header) |

**Total header length:** 1311 bytes (v3 vs v2: same `argonSalt` field — v3 always includes it, even when the passphrase is empty, to keep the layout fixed. The passphrase-wrap leg is simply skipped if the passphrase field is absent.)

---

## 3. AAD Scheme

### What is authenticated

The AAD is the **canonical encoding of header fields** — exactly the bytes that precede the payload in the container:

```
AAD = [version(1)] ‖ ephPub(32) ‖ encapsulation(1088) ‖ salt(32)
      ‖ argonSalt(32) ‖ wrappedDevice(60) ‖ wrappedPass(60)
```

**Zero-copy invariant:** the AAD is a byte-exact slice of the container from `offset 6` to `offset 1311`. This means the parser can supply the AAD without re-serializing — it's already in the right order on disk.

### GCM integration

The AAD is supplied to the **outer AES-GCM decryption that unwraps the file key**, not to the inner payload decryption:

```
decrypt_flow(blob):
    header = blob[6..1311]   ← AAD slice
    payload = blob[1311..]
    
    # Device leg
    kek = HKDF(sharedClassical ‖ sharedPQ, salt)
    fileKey = AES-GCM.decrypt(kek, wrappedDevice, AAD: header)  ← AAD here
    plaintext = AES.GCM.decrypt(fileKey, payload)                ← no AAD
    
    # Passphrase leg (if device leg fails)
    passKek = Argon2id(passphrase, argonSalt)
    fileKey = AES-GCM.decrypt(passKek, wrappedPass, AAD: header) ← AAD here
    plaintext = AES.GCM.decrypt(fileKey, payload)                ← no AAD
```

**Why not AAD on the inner payload too?** The inner payload is already bound to the file key, which is bound to the header via the outer AAD. Adding AAD to the inner payload would be redundant and would break the clean separation between key management and data encryption.

---

## 4. Key Schedule (unchanged from v2)

| Layer | Primitive | Role |
|-------|-----------|------|
| Key encapsulation | ML-KEM-768 (FIPS 203, CryptoKit) | Post-quantum wrap of the file key |
| Key encapsulation | X25519 | Classical wrap of the file key |
| Key derivation | HKDF-SHA256 (info: `"aiguru-pq-hybrid-v1"`) | Combines both shared secrets → KEK |
| KDF (passphrase) | Argon2id (t=3, 64 MiB, p=1) | Passphrase → wrapping key |
| Payload | AES-256-GCM (128-bit tag) | File content encryption |
| Device binding | iOS Keychain (`WhenUnlockedThisDeviceOnly`) | Vault private keys stay on-device |

**No changes.** The key schedule, KEM selection, KDF parameters, and AES mode are identical to v2. The only new element is the AAD parameter to the file-key unwrap operation.

---

## 5. Backward Compatibility

### v3 usage rules

- **v3 encrypt → v3 decrypt:** Always works (no migration needed).
- **v3 encrypt → Android v2 decrypt:** The Android app will see `version = 3` and reject it as unsupported (`Unsupported QVAULT version 3`). This is **correct behavior** — the Android app should be updated to handle v3 (or treat v3 blobs as "this device needs the iOS app to decrypt").
- **v2 encrypt → v3 decrypt:** The iOS v3 engine sees `version = 2` and falls back to the existing v2 code path (no AAD check). **Full backward compatibility.**
- **v1 encrypt → v3 decrypt:** Same as v2 — falls back to v1 path.

### Migration strategy

1. **iOS ships v3 decrypt first.** The v3 engine recognizes all three versions (1, 2, 3) and handles each correctly.
2. **iOS v3 encrypt is opt-in.** A future UI toggle or automatic upgrade path (per-file or per-vault) chooses between v2 (max compat) and v3 (AAD integrity).
3. **Android v3 parity later.** The Android app's `HybridPQCrypto.kt` would gain a v3 code path with the same AAD scheme. The wrapped-key layout is identical — only the AES-GCM init changes to include the AAD.
4. **No silent format upgrade.** The app never rewrites a v2 blob into v3 without the user's explicit action. This avoids the "v3 blobs mysteriously unreadable on Android" trap.

### Wire-format summary

| Version | Compat | AAD | argonSalt | Android | iOS |
|---------|--------|-----|-----------|---------|-----|
| v1 | Base | No | No | ✅ | ✅ |
| v2 | Current | No | Yes | ✅ | ✅ |
| v3 | Forward | Yes | Yes | ⬜ (planned) | ✅ (this spec) |

---

## 6. Implementation Notes

### 6.1 Encrypt (v3)

```swift
func encryptV3(_ data: Data) throws -> Data {
    let (header, wrappedDevice, wrappedPass, payload) = try encryptShared(data)
    // header is the canonical AAD (version + ephPub + encapsulation + salt + argonSalt + wrappedDevice + wrappedPass)
    // Re-wrap the outer GCM with AAD:
    let aad = header
    let fileKey = ... // recover from the outer wrap (or use a fresh one)
    // This is the key change:
    let sealed = try AES.GCM.seal(data, using: fileKey, nonce: payloadIv, authenticating: aad)
    // ...
}
```

### 6.2 Decrypt (v3)

```swift
func decryptV3(_ blob: Data) throws -> Data {
    let container = try parse(blob)  // ByteReader, same as v1/v2
    let aad = blob.subdata(in: 6..<1311)  // zero-copy slice
    // Device leg with AAD:
    let kek = hkdf(...)
    let fileKey = try AES.GCM.open(sealedBox, using: SymmetricKey(data: kek), authenticating: aad)
    let plaintext = try AES.GCM.open(payload, using: fileKey)  // no AAD — already bound via fileKey
    return plaintext
}
```

### 6.3 Parser changes

The `ByteReader`-based parser needs one new field: `isV3: Bool`. If `version == 3`, the payload is decrypted with AAD; otherwise, the existing non-AAD path is used. The `Container` struct gains an optional `aad: Data?` field.

---

## 7. Open Questions

1. **Empty passphrase → v3?** v3 always includes `argonSalt` (32 bytes) and `wrappedPass` (60 bytes) to keep the layout fixed. The passphrase wrap is simply skipped if the user didn't provide one. This keeps the AAD slice at a constant offset 1311 bytes from the start.

2. **Android-side AAD verification** — the Android app uses `javax.crypto.Cipher` with `GCMParameterSpec`. The AAD is supplied via `cipher.updateAAD(aad)` before `doFinal()`. The concrete implementation should be verified against the iOS test vectors.

3. **v3 enum in the code** — should `Container.version` carry an explicit `.v3` case, or just `Int(3)`? I'd prefer the enum for exhaustiveness, but the `ByteReader` should still accept `3` as a valid integer for forward compatibility.

4. **Should the v3 encryption be passphrase-required?** v3 always carries both wraps, but the passphrase wrap is optional (if no passphrase, `wrappedPass` is a GCM-encrypted zero-length placeholder). This keeps the layout fixed. Accepting this simplifies the implementation but wastes 60 bytes per file. An alternative is to make the passphrase presence implicit from the AAD length — but that complicates the parser.

---

## 8. Security Analysis

The AAD binding provides:

- **Header integrity:** Modifying `ephPub`, `encapsulation`, `salt`, `argonSalt`, `wrappedDevice`, or `wrappedPass` causes the file-key unwrap to fail (GCM tag mismatch). An attacker cannot substitute a different header without the new key.
- **Version pinning:** A v3 blob cannot be downgraded to v2 by zeroing the version byte — the AAD covers the version, so the GCM tag would fail.
- **No key-schedule changes:** The KEM, KDF, and AES parameters are unchanged from v2. The security properties of the hybrid construction (both legs must be broken) are preserved.

What AAD does **not** provide:

- **Metadata hiding:** The header fields are still in cleartext. An observer can see the version byte, ephemeral public key, encapsulation, and salts. This is by design — these fields are public by nature (they're needed for the KEM/KDF to work). If metadata hiding is desired, a future version could encrypt the entire container under a static key, but that's a different use case.
- **Replay protection:** The AAD does not include a nonce or counter. An attacker could replay a v3 blob (same header, same ciphertext) and the decryption would succeed. For a file vault, this is acceptable — the attacker already has the ciphertext.
- **Side-channel resistance:** The AAD slice is read from the container at a fixed offset. The implementation must ensure that the AAD slice is never leaked through timing or memory-access patterns.

---

## 9. Specification Status

This document is a **draft specification** for the QVAULT v3 format. It is not yet implemented in the Quantum Vault iOS codebase. The specification is published alongside the code to invite review and discussion before implementation.

**Next steps after review:**

1. Implement `encryptV3` / `decryptV3` in `HybridPQCrypto.swift`
2. Add v3 test vectors (JVM + Swift side)
3. Add v3 round-trip + AAD-tampering-rejection tests
4. Update README with v3 format description
5. Android-side specification review (separate document)