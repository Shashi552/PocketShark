import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

@MainActor
public final class BiometricGuard: ObservableObject {
    @Published public var isLocked: Bool = false
    @Published public var isBiometricsAvailable: Bool = false
    @Published public var biometricTypeString: String = "Face ID / Passcode"
    @Published public var lastUnlockTimestamp: Double = Date().timeIntervalSince1970
    @Published public var authErrorMessage: String? = nil

    public init() {
        checkBiometricAvailability()
    }

    public func checkBiometricAvailability() {
        #if canImport(LocalAuthentication)
        let context = LAContext()
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            self.isBiometricsAvailable = true
            switch context.biometryType {
            case .faceID:
                self.biometricTypeString = "Face ID"
            case .touchID:
                self.biometricTypeString = "Touch ID"
            case .none:
                self.biometricTypeString = "Device Passcode"
            @unknown default:
                self.biometricTypeString = "Biometric Sensor"
            }
        } else {
            self.isBiometricsAvailable = false
            self.biometricTypeString = "Device Passcode"
        }
        #else
        self.isBiometricsAvailable = true
        self.biometricTypeString = "Secure Hardware Key"
        #endif
    }

    public func authenticate(reason: String = "Unlock Tactical Mission Files & PCAP Evidence", completion: @escaping (Bool) -> Void) {
        #if canImport(LocalAuthentication)
        let context = LAContext()
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { [weak self] success, evalError in
                DispatchQueue.main.async {
                    if success {
                        self?.isLocked = false
                        self?.lastUnlockTimestamp = Date().timeIntervalSince1970
                        self?.authErrorMessage = nil
                        completion(true)
                    } else {
                        self?.authErrorMessage = evalError?.localizedDescription ?? "Authentication failed"
                        completion(false)
                    }
                }
            }
        } else {
            // Simulator or hardware without biometrics/passcode: allow graceful tactical override
            DispatchQueue.main.async {
                self.isLocked = false
                self.lastUnlockTimestamp = Date().timeIntervalSince1970
                completion(true)
            }
        }
        #else
        self.isLocked = false
        completion(true)
        #endif
    }

    public func lockImmediately() {
        self.isLocked = true
    }

    public func unlockDirect() {
        self.isLocked = false
        self.lastUnlockTimestamp = Date().timeIntervalSince1970
        self.authErrorMessage = nil
    }
}
