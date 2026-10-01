//! HUP-S8.1: the daemon side of per-device identity.
//!
//! * [`Eip191Verifier`]: the real secp256k1 [`LinkVerifier`] `cluster-core` injects. It recovers the
//!   signer of an EIP-191 `personal_sign` signature (`keccak256("\x19Ethereum Signed Message:\n" ||
//!   len || msg)`, 65-byte `r||s||v`, `v` in {0,1,27,28}) and returns the canonical address. It only
//!   VERIFIES: the daemon never holds a member, wallet or device-link signing key (Rule 3). The
//!   device key it does hold is the libp2p identity, read from the 0600 seed file as before.
//! * The JSON wire shapes for links and revocations on the loopback IPC, and their conversion into
//!   the `cluster-core` types.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use cluster_core::device::{
    DeviceLink, DeviceRevocation, LinkRejection, LinkVerifier, MemberDevices, SignedDeviceLink,
    SignedRevocation,
};

/// EIP-191 `personal_sign` digest of `message`.
pub fn eip191_digest(message: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
    h.update(message);
    h.finalize().into()
}

/// Canonical address (lowercase hex, no `0x`) of a secp256k1 verifying key.
pub fn address_of(key: &VerifyingKey) -> String {
    let point = key.to_encoded_point(false);
    let mut h = Keccak256::new();
    h.update(&point.as_bytes()[1..]);
    let digest = h.finalize();
    hex::encode(&digest[12..])
}

/// Recovers EIP-191 signers with secp256k1. Refuses high-s signatures (malleable duplicates).
#[derive(Debug, Default, Clone, Copy)]
pub struct Eip191Verifier;

impl LinkVerifier for Eip191Verifier {
    fn recover(&self, message: &str, sig_hex: &str) -> Option<String> {
        let raw = hex::decode(sig_hex.trim().trim_start_matches("0x")).ok()?;
        if raw.len() != 65 {
            return None;
        }
        let sig = Signature::from_slice(&raw[..64]).ok()?;
        if sig.normalize_s().is_some() {
            return None; // high-s: refuse the malleable form
        }
        let v = match raw[64] {
            0 | 27 => 0u8,
            1 | 28 => 1u8,
            _ => return None,
        };
        let recid = RecoveryId::from_byte(v)?;
        let digest = eip191_digest(message.as_bytes());
        let key = VerifyingKey::recover_from_prehash(&digest, &sig, recid).ok()?;
        Some(address_of(&key))
    }
}

/// A signed device link as it crosses the IPC (camelCase JSON; signatures are 65-byte hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceLinkWire {
    pub member: String,
    pub device: String,
    pub wallet: String,
    pub index: u32,
    pub label: String,
    pub issued_at: u64,
    pub member_sig: String,
    pub device_sig: String,
    pub wallet_sig: String,
}

impl From<&DeviceLinkWire> for SignedDeviceLink {
    fn from(w: &DeviceLinkWire) -> Self {
        SignedDeviceLink {
            // Taken as received; `DeviceRegistry::update` re-validates and canonicalizes the body.
            link: DeviceLink {
                member: w.member.clone(),
                device: w.device.clone(),
                wallet: w.wallet.clone(),
                index: w.index,
                label: w.label.clone(),
                issued_at: w.issued_at,
            },
            member_sig: w.member_sig.clone(),
            device_sig: w.device_sig.clone(),
            wallet_sig: w.wallet_sig.clone(),
        }
    }
}

/// A member's signed device revocation as it crosses the IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationWire {
    pub member: String,
    pub device: String,
    pub revoked_at: u64,
    pub member_sig: String,
}

impl From<&RevocationWire> for SignedRevocation {
    fn from(w: &RevocationWire) -> Self {
        SignedRevocation {
            revocation: DeviceRevocation {
                member: w.member.clone(),
                device: w.device.clone(),
                revoked_at: w.revoked_at,
            },
            member_sig: w.member_sig.clone(),
        }
    }
}

/// One device under a member in the `Devices` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceViewWire {
    pub device: String,
    pub index: u32,
    pub label: String,
    pub issued_at: u64,
    /// Whether the device is connected over the mesh right now.
    pub online: bool,
}

/// A member with its devices, for the `Devices` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberDevicesWire {
    pub member: String,
    pub role: String,
    pub online: bool,
    pub devices: Vec<DeviceViewWire>,
}

impl MemberDevicesWire {
    pub fn from_core(m: MemberDevices, connected: &std::collections::BTreeSet<String>) -> Self {
        MemberDevicesWire {
            online: connected.contains(&m.member),
            devices: m
                .devices
                .into_iter()
                .map(|d| DeviceViewWire {
                    online: connected.contains(&d.device),
                    device: d.device,
                    index: d.index,
                    label: d.label,
                    issued_at: d.issued_at,
                })
                .collect(),
            member: m.member,
            role: m.role,
        }
    }
}

/// A short, secret-free description of a rejected link for the client (no signatures echoed).
pub fn describe_rejection(r: &LinkRejection) -> String {
    match r {
        LinkRejection::Malformed { device } => format!("{device}: malformed link"),
        LinkRejection::BadSignature { device, which } => {
            format!("{device}: {which} signature does not verify")
        }
        LinkRejection::Conflict { device } => format!("{device}: conflicting links"),
        LinkRejection::Revoked { device } => format!("{device}: revoked"),
        LinkRejection::BadRevocation { device } => {
            format!("{device}: revocation signature does not verify")
        }
        LinkRejection::TooMany => "too many links in one update".to_string(),
    }
}

#[cfg(test)]
#[path = "devices_tests.rs"]
pub(crate) mod devices_tests;
