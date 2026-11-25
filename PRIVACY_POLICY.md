# Quantum Vault — Privacy Policy

**Effective date: 2026-09-04**

Quantum Vault (the "App") is designed so that **no personal data ever leaves your device**. This policy explains exactly what the App does and does not collect, store, or transmit.

## 1. Data Collection

**The App collects no data. None.**

- We do not collect, transmit, sell, or share any personal information.
- The App makes **no network requests** of any kind. It has no internet permission and communicates with no servers.
- We do not use analytics, telemetry, crash reporting, advertising, or tracking of any kind.
- We do not access your contacts, location, photos, microphone, or camera.

## 2. Data Storage

All data the App touches stays **on your device and in storage locations you explicitly choose**:

- **Vault keys** — generated on-device, stored in the iOS Keychain with the `WhenUnlockedThisDeviceOnly` protection class. They never leave the device and are excluded from device backups by design.
- **Encrypted files (`.qvault`)** — written only to the folder you select via the system Files picker (local storage, iCloud Drive, Google Drive, OneDrive, etc.). Storage there is governed by that provider's own terms and your own account; the App itself never connects to any provider.
- **Escrow file (`.vaultkey`)** — a passphrase-encrypted copy of your vault keys, stored in the same folder you choose. It is protected with Argon2id + AES-256-GCM and is useless without your passphrase.

## 3. Biometric Data

If you enable the Face ID / Touch ID gate, biometric authentication is performed **entirely by iOS**. The App never sees, stores, or transmits your biometric data. Apple's LocalAuthentication framework reports only a success/failure result.

## 4. Third Parties

The App integrates with no third-party services, SDKs, or analytics frameworks. If you choose a cloud-storage folder (e.g., iCloud Drive, Google Drive) as your vault location, files stored there are governed by your existing agreement with that provider — not by this policy, and not by the App.

## 5. Children

The App is not directed at children under 13 and does not knowingly collect any data from anyone, of any age.

## 6. Your Control

- **Wipe local keys**: an in-app control deletes all vault key material from the device.
- **Delete vault files**: you can delete any `.qvault` or `.vaultkey` file from the vault folder at any time via the Files app.
- **Uninstall**: removing the App removes the Keychain-stored keys. Files in your chosen vault folder remain (they are yours; the App does not delete data on uninstall).

## 7. Security

The App uses NIST-standardized post-quantum cryptography (ML-KEM-768, FIPS 203) combined with X25519, HKDF-SHA256, AES-256-GCM, and Argon2id. The source code is publicly available for review at:
https://github.com/bamit99/Quantum-Vault-iOS

## 8. Changes

If this policy changes, the updated version will be published at this URL with a new effective date. Given that the App is offline-only and collects nothing, material changes are not expected.

## 9. Contact

Questions about this policy: bamit1979@gmail.com

---

## Host this file

Save this page as `privacy.html` (or `privacy.md` rendered to HTML) and host it at any public URL — GitHub Pages on this repo is the zero-cost option:
`https://bamit99.github.io/Quantum-Vault-iOS/privacy.html`

Apple's App Store Connect only needs the **URL**, not the text.