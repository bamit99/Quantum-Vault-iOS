import Foundation
import Security
import CryptoKit
import QVaultCrypto

/// Persists the vault keypair in the Keychain (device-only) — the iOS analogue of
/// Android's Keystore-sealed prefs. Stores ML-KEM-768 seed (64B) + X25519 raw (32B)
/// + public halves, kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
enum KeychainVaultStore {
    private static let service = "com.aiguru.quantumvault.keys"
    private static let account = "vault-v1"

    private static var baseQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    static func save(_ vault: HybridPQCrypto) throws {
        let blob = vault.mlkemSeed + vault.xPrivRaw + vault.mlkemPubRaw + vault.xPubRaw
        SecItemDelete(baseQuery as CFDictionary)
        var add = baseQuery
        add[kSecValueData as String] = blob
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw QVaultError.cryptoUnderlying("Keychain save failed: \(status)")
        }
    }

    static func load() -> HybridPQCrypto? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let blob = out as? Data, blob.count == 64 + 32 + 1184 + 32 else { return nil }
        do {
            let seed = blob.prefix(64)
            let xPrivData = blob.subdata(in: 64..<96)
            let pubMlkem = blob.subdata(in: 96..<96 + 1184)
            let pubX = blob.subdata(in: 96 + 1184..<blob.count)
            let mlkem = try MLKEM768.PrivateKey(
                seedRepresentation: seed,
                publicKey: try MLKEM768.PublicKey(rawRepresentation: pubMlkem)
            )
            let xPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: xPrivData)
            return HybridPQCrypto(mlkemPriv: mlkem, xPriv: xPriv)
        } catch {
            return nil
        }
    }

    static func wipe() {
        SecItemDelete(baseQuery as CFDictionary)
    }
}