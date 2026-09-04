import SwiftUI
import UniformTypeIdentifiers
import UIKit
import QVaultCrypto

struct ContentView: View {
    @EnvironmentObject var model: VaultModel
    @EnvironmentObject var gate: BiometricGate
    @State private var biometricsOn = false

    // Pickers
    @State var showFolderPicker = false
    @State var showEncryptPicker = false
    @State var showEscrowPicker = false
    @State var showPassphraseSheet = false
    @State var passphraseField = ""
    @State var passphraseTitle = ""
    @State var passphraseAction: ((String) -> Void)?
    @State var deleteTarget: VaultModel.VaultEntry?

    var body: some View {
        NavigationStack {
            List {
                if !model.hasKeys {
                    Section {
                        Button {
                            model.ensureKeys()
                        } label: {
                            Label("Create post-quantum vault identity", systemImage: "key.fill")
                        }
                    } header: {
                        Text("Setup")
                    }
                } else {
                    Section("Vault identity") {
                        LabeledContent("ML-KEM-768 + X25519", value: "Active")
                        LabeledContent("Fingerprint") {
                            Text(model.fingerprint.prefix(12) + "…")
                                .font(.footnote.monospaced())
                                .textSelection(.enabled)
                        }
                    }
                }

                Section("Vault location") {
                    if let folder = model.folderName {
                        LabeledContent("Folder", value: folder)
                    } else {
                        Text("No location selected — vault files will live wherever you pick (Drive, OneDrive, local…).")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Button {
                        showFolderPicker = true
                    } label: {
                        Label(model.folderName == nil ? "Choose location" : "Change location", systemImage: "folder.badge.plus")
                    }
                }

                if model.folderName != nil {
                    Section("Encrypt a file") {
                        Button {
                            showEncryptPicker = true
                        } label: {
                            Label("Pick file to encrypt", systemImage: "lock.doc.fill")
                        }
                    }

                    Section("Vault contents (\(model.files.count))") {
                        if model.files.isEmpty {
                            Text("No .qvault files yet.")
                                .foregroundStyle(.secondary)
                        }
                        ForEach(model.files) { entry in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(entry.name)
                                    .font(.body.monospaced())
                                HStack {
                                    Text(entry.isV2 ? "dual-wrap v2" : "device-wrap v1")
                                        .font(.caption2)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(.indigo.opacity(0.15), in: Capsule())
                                    Spacer()
                                    Button {
                                        requestPassphrase("Decrypt \(entry.name)") { pass in
                                            model.decryptFile(entry, passphrase: pass.isEmpty ? nil : pass)
                                        }
                                    } label: {
                                        Image(systemName: "lock.open")
                                    }
                                    .buttonStyle(.borderless)
                                    Button(role: .destructive) {
                                        deleteTarget = entry
                                    } label: {
                                        Image(systemName: "trash")
                                    }
                                    .buttonStyle(.borderless)
                                }
                            }
                            .padding(.vertical, 2)
                        }
                    }

                    Section("Escrow (.vaultkey)") {
                        Button {
                            requestPassphrase("Set escrow passphrase") { pass in
                                model.saveEscrow(passphrase: pass)
                            }
                        } label: {
                            Label("Save escrow to vault folder", systemImage: "archivebox")
                        }
                        Button {
                            showEscrowPicker = true
                        } label: {
                            Label("Restore from .vaultkey…", systemImage: "arrow.down.circle")
                        }
                    }
                }

                Section {
                    Text(model.status)
                        .font(.footnote)
                        .foregroundStyle(model.busy ? .orange : .secondary)
                }

                Section("Settings") {
                    Toggle(isOn: $biometricsOn) {
                        Label("Lock with \(BiometricGate.biometryName())", systemImage: "faceid")
                    }
                    .onChange(of: biometricsOn) { _, newValue in
                        gate.biometricsEnabled = newValue
                    }
                    if !gate.biometryAvailable {
                        Text("\(BiometricGate.biometryName()) unavailable here (simulator or not enrolled) — the gate auto-skips.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    LabeledContent("Version", value: "1.0 (iOS)")
                    LabeledContent("Format", value: "QVAULT v1/v2 · FIPS 203")
                }

                Section {
                    Button(role: .destructive) {
                        model.wipeLocalKeys()
                    } label: {
                        Label("Wipe local keys (unlink)", systemImage: "trash.slash")
                    }
                } footer: {
                    Text("Two-tier delete: 'unlink' wipes this device's keys only; vault files and escrow stay in the folder. Full DESTROY with typed confirmation ships in Phase 3.")
                }
            }
            .navigationTitle("Quantum Vault")
            .onAppear { biometricsOn = gate.biometricsEnabled }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        model.refreshFiles()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
            // Folder picker (security-scoped — iOS SAF analogue)
            .fileImporter(
                isPresented: $showFolderPicker,
                allowedContentTypes: [.folder],
                allowsMultipleSelection: false
            ) { result in
                if case .success(let urls) = result, let url = urls.first {
                    model.setFolder(url)
                }
            }
            // Source file to encrypt
            .fileImporter(
                isPresented: $showEncryptPicker,
                allowedContentTypes: [.item],
                allowsMultipleSelection: false
            ) { result in
                if case .success(let urls) = result, let url = urls.first {
                    requestPassphrase("Passphrase for \(url.lastPathComponent).qvault (optional)") { pass in
                        model.encryptFile(at: url, passphrase: pass.isEmpty ? nil : pass)
                    }
                }
            }
            // .vaultkey to restore
            .fileImporter(
                isPresented: $showEscrowPicker,
                allowedContentTypes: [.item],
                allowsMultipleSelection: false
            ) { result in
                if case .success(let urls) = result, let url = urls.first {
                    requestPassphrase("Escrow passphrase") { pass in
                        model.restoreEscrow(from: url, passphrase: pass)
                    }
                }
            }
            // Passphrase prompt
            .alert(passphraseTitle, isPresented: .init(
                get: { passphraseAction != nil },
                set: { if !$0 { passphraseAction = nil } }
            )) {
                SecureField("Passphrase", text: $passphraseField)
                Button("Cancel", role: .cancel) { passphraseField = "" }
                Button("OK") {
                    let action = passphraseAction
                    let pass = passphraseField
                    passphraseField = ""
                    passphraseAction = nil
                    action?(pass)
                }
            }
            // Share decrypted file
            .sheet(isPresented: Binding(
                get: { model.decryptedTempURL != nil },
                set: { if !$0 { model.decryptedTempURL = nil } }
            )) {
                if let url = model.decryptedTempURL {
                    ShareSheet(url: url)
                }
            }
            // Delete confirmation
            .confirmationDialog(
                "Delete \(deleteTarget?.name ?? "")?",
                isPresented: .init(
                    get: { deleteTarget != nil },
                    set: { if !$0 { deleteTarget = nil } }
                ),
                titleVisibility: .visible
            ) {
                Button("Delete encrypted file", role: .destructive) {
                    if let t = deleteTarget { model.deleteFile(t) }
                }
            }
        }
    }

    private func requestPassphrase(_ title: String, action: @escaping (String) -> Void) {
        passphraseTitle = title
        passphraseField = ""
        passphraseAction = action
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let url: URL
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [url], applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}