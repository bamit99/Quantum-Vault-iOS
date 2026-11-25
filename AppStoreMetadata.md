# Quantum Vault — App Store Description

## App name
Quantum Vault

## Subtitle
Post-quantum encrypted file vault. Your files, sealed before they ever leave your hands.

## Description (up to 4,000 characters)

Quantum Vault encrypts every file on-device with NIST‑standardized post‑quantum cryptography — ML‑KEM‑768 (FIPS 203) — and stores it via the system Files picker into any folder you choose: Google Drive, OneDrive, local storage. No OAuth. No cloud SDK. No account. Just a vault that travels with your files.

**Why "Quantum"?**
Every encrypted file you store in the cloud today can be harvested now and decrypted later: a future quantum computer running Shor's algorithm will break today's RSA/ECDH key exchange retroactively. Quantum Vault defends against that today by wrapping every file key with ML‑KEM‑768 combined with X25519 in a hybrid construction. An attacker must break both legs.

**How it works**
• Create your ML‑KEM‑768 + X25519 vault keypair — generated once on‑device, sealed in the iOS Keychain (hardware-backed, device‑only).
• Choose a vault location via the Files picker — any folder, any provider, no permissions required.
• Pick any file to encrypt → a `.qvault` container lands in your vault folder.
• Decrypt by tapping the file — the device key unwraps it instantly. For dual‑wrap (v2) or authenticated‑header (v3) files, a passphrase can recover the file even without the original device.
• Save a `.vaultkey` escrow in your vault folder — passphrase‑protected, survives phone loss. Restore it on a fresh install to regain access.

**Key features**
• Hybrid post‑quantum encryption: ML‑KEM‑768 (FIPS 203) + X25519 → HKDF‑SHA256 → AES‑256‑GCM.
• Argon2id passphrase KDF (t=3, 64 MiB, p=1) — GPU‑hostile, interactive‑phone practical.
• Dual‑wrap: device key OR passphrase alone can decrypt — your choice, your risk model.
• QVAULT v3 with authenticated headers: AAD‑bound container metadata prevents tampering.
• Files‑app integration with security‑scoped bookmarks — the iOS analogue of Android's SAF-based vault.
• Face ID / Touch ID session gate.
• Zero‑permission manifest: no internet access, no location, no contacts. Your data never leaves your device.
• QVAULT containers are byte‑compatible with the Android version of Quantum Vault — the same vault folder works on both platforms.

**Cross‑platform compatibility**
The iOS engine is tested against Android‑generated containers (v1, v2, and v3) using deterministic test vectors. The `.qvault` and `.vaultkey` formats are shared between both platforms — encrypt on Android, decrypt on iPhone, and vice versa.

**Requires iOS 26+** (CryptoKit's native ML‑KEM‑768 support).

**Privacy**
Quantum Vault collects no data. It makes no network requests. The vault keys, encrypted files, and escrow blobs never leave your control. Full privacy policy available at [URL].

## Keywords
post-quantum, encryption, ML-KEM, Kyber, FIPS 203, file vault, security, AES, Argon2, privacy, encrypt, decrypt, zero trust, NIST

## Promotional text (170 characters)
Post‑quantum file encryption for iOS. ML‑KEM‑768 + X25519 hybrid. Files picker, Face ID, escrow recovery. No data collected. iOS 26+.

## Support URL
https://github.com/bamit99/Quantum-Vault-iOS/issues

## Marketing URL
https://github.com/bamit99/Quantum-Vault-iOS