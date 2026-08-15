import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// The phone's non-exportable device identity (§5.4).
///
/// The Android side generates ECDSA P-256 in the Android Keystore — hardware-backed from
/// API 23, StrongBox from 28, never exportable. The iOS equivalent is the Secure Enclave,
/// and it is a *stronger* guarantee: Keystore hardware backing depends on the device's
/// TEE and is queryable-but-variable across the Android fleet, whereas Secure Enclave
/// presence is uniform across every iPhone this app would target.
///
/// The reason this is possible at all is the P1-CURVE amendment. The Secure Enclave
/// supports exactly one key type: NIST P-256. The P0 draft's Ed25519 device key could
/// not have lived in it, and an iOS port under the P0 protocol would have had to fall
/// back to a software key in the Keychain — a materially weaker custody story for the
/// key whose signature the engine's audit log treats as non-repudiable proof of *which
/// device* asked for a change.
public protocol DeviceSigningKey: Sendable {
    /// Uncompressed X9.63 point (65 bytes, `0x04 || X || Y`) — the form §5.2.2 sends
    /// inside the encrypted pairing completion.
    var publicKeyX963: Data { get }

    /// §5.4: raw 64-byte `r || s`, big-endian, fixed width — **not** DER.
    func signature(over input: Data) throws -> Data
}

/// Software key. Correct for tests, the simulator, and Linux CI; not what ships.
public struct SoftwareDeviceSigningKey: DeviceSigningKey, @unchecked Sendable {
    private let key: P256.Signing.PrivateKey

    public init(rawRepresentation: Data) throws {
        self.key = try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation)
    }

    public init() { self.key = P256.Signing.PrivateKey() }

    public var publicKeyX963: Data { key.publicKey.x963Representation }

    public func signature(over input: Data) throws -> Data {
        try key.signature(for: input).rawRepresentation
    }
}

#if os(iOS) || os(macOS)
/// Secure Enclave key. The private half is generated inside the enclave and never exists
/// in addressable memory; `dataRepresentation` is an opaque blob the enclave can reload,
/// not the scalar.
///
/// Not compiled on Linux, so CI proves the protocol logic while this type is proven on
/// device. `SecureEnclave.isAvailable` is false on the simulator, which is exactly why
/// `DeviceSigningKey` is a protocol: the simulator and CI use the software key, hardware
/// is used everywhere real, and the receiver logic above cannot tell the difference.
public struct SecureEnclaveDeviceSigningKey: DeviceSigningKey, @unchecked Sendable {
    private let key: SecureEnclave.P256.Signing.PrivateKey

    /// - Parameter accessControl: pass a control requiring `.privateKeyUsage` plus
    ///   biometry if the product wants a Face ID gate on signing. Note the interaction
    ///   with the background-push path: a key that demands biometry cannot sign inside a
    ///   Notification Service Extension, so a biometric gate here forces every
    ///   state-changing action to be foreground-only. That is a product decision, not a
    ///   crypto one, and it should be made explicitly rather than discovered.
    public init(accessControl: SecAccessControl? = nil) throws {
        self.key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
    }

    public init(dataRepresentation: Data) throws {
        self.key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
    }

    /// Persist this in the Keychain; it is useless without the enclave that made it.
    public var dataRepresentation: Data { key.dataRepresentation }

    public var publicKeyX963: Data { key.publicKey.x963Representation }

    public func signature(over input: Data) throws -> Data {
        try key.signature(for: input).rawRepresentation
    }
}
#endif
