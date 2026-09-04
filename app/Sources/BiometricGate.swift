import Foundation
import LocalAuthentication
import QVaultCrypto

/// Biometric gate — Face ID / Touch ID via LocalAuthentication.
/// Session-scoped: once passed, stays unlocked until app termination
/// (mirrors Android's per-session unlock gate).
@MainActor
final class BiometricGate: ObservableObject {
    @Published var unlocked = false
    @Published var biometryAvailable = false
    @Published var gateMessage = ""

    private let defaultsKey = "gate.biometricsEnabled"

    var biometricsEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: defaultsKey) }
        set { UserDefaults.standard.set(newValue, forKey: defaultsKey) }
    }

    init() {
        biometryAvailable = Self.canUseBiometrics()
    }

    static func canUseBiometrics() -> Bool {
        let ctx = LAContext()
        var error: NSError?
        return ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    static func biometryName() -> String {
        let ctx = LAContext()
        var error: NSError?
        if ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            switch ctx.biometryType {
            case .faceID: return "Face ID"
            case .touchID: return "Touch ID"
            case .opticID: return "Optic ID"
            default: return "Biometrics"
            }
        }
        return "Biometrics"
    }

    /// Show the system biometric prompt. Call when the gate screen is active.
    func authenticate() {
        guard biometricsEnabled else {
            unlocked = true // gate disabled in settings
            return
        }
        let ctx = LAContext()
        var error: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            // Simulator or no biometrics enrolled — allow but note it
            gateMessage = "Biometrics unavailable on this device — gate disabled."
            unlocked = true
            return
        }
        ctx.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Unlock your Quantum Vault"
        ) { [weak self] success, authError in
            Task { @MainActor in
                if success {
                    self?.unlocked = true
                    self?.gateMessage = ""
                } else {
                    self?.gateMessage = Self.describe(authError)
                }
            }
        }
    }

    func lock() {
        unlocked = false
    }

    static func describe(_ error: Error?) -> String {
        guard let laError = error as? LAError else { return "Authentication failed." }
        switch laError.code {
        case .userCancel, .systemCancel, .appCancel: return "Cancelled."
        case .authenticationFailed: return "Authentication failed — try again."
        case .biometryNotEnrolled: return "No biometrics enrolled. Enable the gate after enrolling, or disable it in Settings."
        case .biometryLockout: return "Biometrics locked out — unlock with passcode first."
        default: return laError.localizedDescription
        }
    }
}