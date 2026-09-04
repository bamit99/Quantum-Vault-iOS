import SwiftUI
import QVaultCrypto

@main
struct QuantumVaultApp: App {
    @StateObject private var model = VaultModel()
    @StateObject private var gate = BiometricGate()
    @State private var gateAttempted = false

    var body: some Scene {
        WindowGroup {
            Group {
                if gate.unlocked || !gate.biometricsEnabled {
                    ContentView()
                        .environmentObject(model)
                        .environmentObject(gate)
                        .tint(.indigo)
                } else {
                    GateView(gate: gate)
                        .environmentObject(model)
                }
            }
            .onAppear {
                if !gateAttempted {
                    gateAttempted = true
                    gate.authenticate()
                }
            }
            .onChange(of: gate.biometricsEnabled) { _, enabled in
                // Toggling the gate off in Settings unlocks immediately;
                // toggling on requires re-auth on next launch.
                if !enabled { gate.unlocked = true }
            }
        }
    }
}

/// Full-screen biometric gate.
struct GateView: View {
    @ObservedObject var gate: BiometricGate

    var body: some View {
        VStack(spacing: 28) {
            Spacer()
            Image(systemName: "faceid")
                .font(.system(size: 72))
                .foregroundStyle(.indigo)
            Text("Quantum Vault")
                .font(.largeTitle.bold())
            Text("Locked — authenticate to continue")
                .foregroundStyle(.secondary)
            Button {
                gate.authenticate()
            } label: {
                Label("Unlock with \(BiometricGate.biometryName())", systemImage: "faceid")
                    .font(.headline)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
            if !gate.gateMessage.isEmpty {
                Text(gate.gateMessage)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            Spacer()
        }
        .padding()
    }
}