import Foundation
import SwiftUI
import UniformTypeIdentifiers
import QVaultCrypto

/// App model: vault identity (Keychain-backed), security-scoped vault folder
/// (iOS analogue of Android's persisted SAF tree permission), encrypt/decrypt,
/// and escrow save/restore.
@MainActor
final class VaultModel: ObservableObject {
    // MARK: Published state
    @Published var hasKeys = false
    @Published var fingerprint = ""
    @Published var folderName: String?
    @Published var status = "Ready."
    @Published var busy = false
    @Published var files: [VaultEntry] = []
    @Published var decryptedTempURL: URL?

    struct VaultEntry: Identifiable, Hashable {
        let id: URL
        var name: String { id.lastPathComponent }
        let isV2: Bool
    }

    // MARK: Private state
    private var vault: HybridPQCrypto?
    private var scopedURL: URL?
    private let bookmarkKey = "vault.folderBookmark"

    init() {
        if let v = KeychainVaultStore.load() {
            vault = v
            hasKeys = true
            fingerprint = v.fingerprint
        }
        restoreBookmark()
        refreshFiles()
    }

    // MARK: - Vault identity

    func ensureKeys() {
        guard !hasKeys else { return }
        do {
            let v = try HybridPQCrypto.generate()
            try KeychainVaultStore.save(v)
            vault = v
            hasKeys = true
            fingerprint = v.fingerprint
            status = "New post-quantum vault identity created 🔐"
        } catch {
            status = "Key generation failed: \(error)"
        }
    }

    func wipeLocalKeys() {
        KeychainVaultStore.wipe()
        vault = nil
        hasKeys = false
        fingerprint = ""
        files = []
        status = "Local key material wiped (unlink). Recovery: passphrase + .vaultkey"
    }

    // MARK: - Vault folder (security-scoped bookmark)

    func setFolder(_ url: URL) {
        let got = url.startAccessingSecurityScopedResource()
        defer { if got { url.stopAccessingSecurityScopedResource() } }
        do {
            let data = try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
            UserDefaults.standard.set(data, forKey: bookmarkKey)
            UserDefaults.standard.set(url.lastPathComponent, forKey: "vault.folderName")
            scopedURL = url
            folderName = url.lastPathComponent
            status = "Vault location: \(url.lastPathComponent)"
            refreshFiles()
        } catch {
            status = "Bookmark failed: \(error.localizedDescription)"
        }
    }

    private func restoreBookmark() {
        guard let data = UserDefaults.standard.data(forKey: bookmarkKey) else { return }
        var stale = false
        guard let url = try? URL(resolvingBookmarkData: data, options: [], relativeTo: nil, bookmarkDataIsStale: &stale) else { return }
        let got = url.startAccessingSecurityScopedResource()
        defer { if got { url.stopAccessingSecurityScopedResource() } }
        scopedURL = url
        folderName = url.lastPathComponent
    }

    // MARK: - File operations (inside vault folder security scope)

    private func withVaultFolder<T>(_ body: (URL) throws -> T) throws -> T {
        guard let url = scopedURL else { throw QVaultError.cryptoUnderlying("No vault folder selected") }
        let got = url.startAccessingSecurityScopedResource()
        defer { if got { url.stopAccessingSecurityScopedResource() } }
        return try body(url)
    }

    func refreshFiles() {
        guard scopedURL != nil else { files = []; return }
        files = (try? withVaultFolder { folder -> [VaultEntry] in
            let items = try FileManager.default.contentsOfDirectory(
                at: folder, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]
            )
            return items
                .filter { $0.lastPathComponent.hasSuffix(".qvault") }
                .sorted { $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent) == .orderedAscending }
                .map { url in
                    let data = (try? Data(contentsOf: url)) ?? Data()
                    return VaultEntry(id: url, isV2: HybridPQCrypto.isPassphraseCapable(data))
                }
        }) ?? []
    }

    /// Encrypt a picked source file into the vault folder as <name>.qvault.
    func encryptFile(at sourceURL: URL, passphrase: String?) {
        guard let v = vault else { status = "No vault keys"; return }
        guard scopedURL != nil else { status = "Choose a vault location first"; return }
        busy = true
        defer { busy = false }
        do {
            let got = sourceURL.startAccessingSecurityScopedResource()
            defer { if got { sourceURL.stopAccessingSecurityScopedResource() } }
            let plain = try Data(contentsOf: sourceURL)
            let blob = passphrase == nil
                ? try v.encrypt(plain)
                : try v.encrypt(plain, passphrase: passphrase!)
            let outName = sourceURL.lastPathComponent + ".qvault"
            try withVaultFolder { folder in
                let out = folder.appendingPathComponent(outName)
                try blob.write(to: out, options: .atomic)
            }
            status = "Encrypted → \(outName)"
            refreshFiles()
        } catch {
            status = "Encrypt failed: \(error.localizedDescription)"
        }
    }

    /// Decrypt a vault entry; result goes to a temp file exposed via decryptedTempURL.
    func decryptFile(_ entry: VaultEntry, passphrase: String?) {
        guard let v = vault else { status = "No vault keys"; return }
        busy = true
        defer { busy = false }
        do {
            let blob = try withVaultFolder { folder in try Data(contentsOf: entry.id) }
            let plain: Data
            if HybridPQCrypto.isPassphraseCapable(blob), let p = passphrase {
                plain = try v.decrypt(blob, passphrase: p)
            } else {
                plain = try v.decrypt(blob)
            }
            let baseName = entry.name.replacingOccurrences(of: ".qvault", with: "")
            let tmp = FileManager.default.temporaryDirectory
                .appendingPathComponent("\(Int(Date.now.timeIntervalSince1970))-\(baseName)")
            try plain.write(to: tmp)
            status = "Decrypted \(entry.name) ✅"
            decryptedTempURL = tmp
        } catch QVaultError.wrongPassphrase {
            status = "Wrong passphrase."
        } catch {
            status = "Decrypt failed: \(error.localizedDescription)"
        }
    }

    func deleteFile(_ entry: VaultEntry) {
        do {
            try withVaultFolder { _ in try FileManager.default.removeItem(at: entry.id) }
            status = "Deleted \(entry.name)"
            refreshFiles()
        } catch {
            status = "Delete failed: \(error.localizedDescription)"
        }
    }

    // MARK: - Escrow

    func saveEscrow(passphrase: String) {
        guard let v = vault else { status = "No vault keys"; return }
        guard scopedURL != nil else { status = "Choose a vault location first"; return }
        do {
            let blob = try VaultEscrow.export(from: v, passphrase: passphrase)
            let out = try withVaultFolder { folder -> URL in
                let url = folder.appendingPathComponent(VaultEscrow.fileName)
                try blob.write(to: url, options: .atomic)
                return url
            }
            status = "Escrow saved → \(out.lastPathComponent)"
        } catch {
            status = "Escrow save failed: \(error)"
        }
    }

    func restoreEscrow(from url: URL, passphrase: String) {
        busy = true
        defer { busy = false }
        do {
            let got = url.startAccessingSecurityScopedResource()
            defer { if got { url.stopAccessingSecurityScopedResource() } }
            let blob = try Data(contentsOf: url)
            let restored = try VaultEscrow.restore(blob: blob, passphrase: passphrase)
            try KeychainVaultStore.save(restored.vault)
            vault = restored.vault
            hasKeys = true
            fingerprint = restored.fingerprint
            status = "Vault identity restored from escrow ✅"
        } catch QVaultError.wrongPassphrase {
            status = "Wrong passphrase — escrow unchanged."
        } catch {
            status = "Restore failed: \(error)"
        }
    }
}