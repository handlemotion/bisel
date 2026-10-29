import ArgumentParser
import BiselCore
import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Tries the real Secure Enclave from this (unsigned) tool and reports exactly what works.
struct SEProbe: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "se-probe",
        abstract: "Exercise the Secure Enclave DeviceKeyStore as far as an unsigned CLI can.",
        discussion: "Uses non-persistent keys (no keychain entitlement needed). DK-enc has .biometryAny, so opening an envelope would show Touch ID; that step runs only with --biometric.")
    @Flag var biometric = false
    @Flag(help: "Use persistent keychain keys (needs a signed build with keychain entitlements).") var persistent = false

    func run() async throws {
        say("SecureEnclave.isAvailable = \(SecureEnclave.isAvailable)")
        let store = SecureEnclaveDeviceKeyStore(accessGroup: nil, tagPrefix: "app.bisel.probe", persistent: persistent)
        let keys: DevicePublicKeys
        do { keys = try store.createKeys() } catch {
            say("FAIL createKeys (DK-enc biometryAny + DK-sig): \(error)")
            await rawProbe()
            return
        }
        say("OK createKeys: sig \(keys.sig.count)B enc \(keys.enc.count)B fingerprint \(keys.fingerprint)")
        let msg = Data("probe".utf8)
        let sig = try store.sign(msg)
        let ok = try P256.Signing.PublicKey(x963Representation: keys.sig)
            .isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: sig), for: msg)
        say("\(ok ? "OK" : "FAIL") sign with DK-sig (no prompt), verified with CryptoKit as raw r||s (\(sig.count)B)")
        let envelope = try DeviceEnvelope.seal(vaultKey: Data(repeating: 7, count: 32), toEncryptionKey: keys.enc)
        say("OK sealed envelope to the SE DK-enc public key (\(envelope.count)B)")
        if biometric {
            say("opening envelope: expect a Touch ID prompt...")
            let vk = try await store.openEnvelope(envelope, reason: "bisel-dev se-probe")
            say(vk == Data(repeating: 7, count: 32) ? "OK envelope opened by SE DK-enc after biometrics" : "FAIL wrong plaintext")
        } else {
            say("SKIPPED opening the envelope (DK-enc requires biometrics; pass --biometric to try)")
        }
        if persistent { try? store.deleteKeys() }
        await rawProbe()
    }

    /// SE key with only .privateKeyUsage: proves ECIES (cofactorX963SHA256AESGCM) round-trips on SE keys without a prompt.
    func rawProbe() async {
        var err: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &err) else { return }
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256,
                                      kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
                                      kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false, kSecAttrAccessControl: access]]
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            let e = err?.takeRetainedValue() as Error?
            say("FAIL raw SE key without biometrics: \(e.map { "\($0.localizedDescription) [\(($0 as NSError).code)]" } ?? "?")")
            return
        }
        let pub = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(priv)!, nil)! as Data
        do {
            let sealed = try DeviceEnvelope.seal(vaultKey: Data(repeating: 9, count: 32), toEncryptionKey: pub)
            let opened = SecKeyCreateDecryptedData(priv, DeviceEnvelope.algorithm, sealed as CFData, &err) as Data?
            say(opened == Data(repeating: 9, count: 32)
                ? "OK ECIES envelope round trip on a real Secure Enclave key (no biometrics)"
                : "FAIL ECIES round trip: \(String(describing: err?.takeRetainedValue()))")
        } catch { say("FAIL sealing: \(error)") }
    }
}
