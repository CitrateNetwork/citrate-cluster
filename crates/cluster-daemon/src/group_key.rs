//! V60 MESH-3: a PeerId per group swarm, bound to the device by a signature.
//!
//! ## Why
//!
//! One daemon runs one swarm per group (HUP-S8.4). They all used the device key, so they all had
//! the same PeerId. A circuit relay keeps reservations by PeerId and routes a circuit to the first
//! connection holding one, so a circuit meant for group B could reach the device's group-A swarm and
//! fail its Noise prologue (found by the S0-NAT-SPIKE; reproduced in
//! `a_relay_routes_each_groups_circuit_to_that_groups_swarm`).
//!
//! ## What
//!
//! When relays are configured, a group swarm uses a **group key**: a secp256k1 key derived from
//! the device secret and the group id (deterministic, so a group link stays valid across restarts).
//! Its PeerId differs per group, so the relay routes by PeerId correctly.
//!
//! The mesh still admits by **device address**. The swarm proves the group key acts for the device
//! with a **binding**: an EIP-191 signature by the device key over
//! `citrate-cluster group key v1 / group / peer`, carried in the identify `agent_version`. A
//! receiver recovers the signer and admits the peer as that address only if the group authorizes
//! it ([`verify`]). The binding names the group and the PeerId, so it cannot be replayed into
//! another group or by another key. Identify runs inside the Noise session, so the PeerId it is
//! checked against is authenticated.
//!
//! The binding tells anyone who connects which device the group key acts for, the same as the
//! device PeerId did before. Without relays, nothing changes (the swarm uses the device key).

use k256::ecdsa::SigningKey;
use libp2p::{identity, PeerId};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use cluster_core::device::LinkVerifier;

use crate::devices::{eip191_digest, Eip191Verifier};

/// Domain separation for the derivation.
const DERIVE_TAG: &[u8] = b"citrate-cluster/group-key/v1";

/// The identify `agent_version` prefix that carries a binding.
pub const AGENT_PREFIX: &str = "citrate-cluster/1 group-key-binding=";

/// The message the device key signs. Line-separated, so no field can run into another.
fn binding_message(group: &str, peer: &PeerId) -> String {
    format!("citrate-cluster group key v1\ngroup: {group}\npeer: {peer}")
}

/// The group key for `group`: keccak256(tag || len(group) || group || device secret || counter),
/// taking the first counter that gives a valid secp256k1 scalar. The intermediate bytes are wiped.
pub fn derive_group_keypair(device: &[u8; 32], group: &str) -> Result<identity::Keypair, String> {
    for counter in 0u8..=255 {
        let mut h = Keccak256::new();
        h.update(DERIVE_TAG);
        h.update((group.len() as u64).to_be_bytes());
        h.update(group.as_bytes());
        h.update(device);
        h.update([counter]);
        let mut bytes = Zeroizing::new(<[u8; 32]>::from(h.finalize()));
        if let Ok(sk) = identity::secp256k1::SecretKey::try_from_bytes(&mut *bytes) {
            return Ok(identity::Keypair::from(identity::secp256k1::Keypair::from(
                sk,
            )));
        }
    }
    Err("could not derive a group key".into())
}

/// The binding for `peer` in `group`, signed by the device key, as an identify `agent_version`.
pub fn bind(device: &[u8; 32], group: &str, peer: &PeerId) -> Result<String, String> {
    let key = SigningKey::from_slice(device).map_err(|_| "invalid device secret".to_string())?;
    let digest = eip191_digest(binding_message(group, peer).as_bytes());
    let (sig, recid) = key
        .sign_prehash_recoverable(&digest)
        .map_err(|_| "signing the group-key binding failed".to_string())?;
    let mut raw = sig.to_bytes().to_vec();
    raw.push(27 + recid.to_byte());
    Ok(format!("{AGENT_PREFIX}0x{}", hex::encode(raw)))
}

/// The device address a binding names, if `agent` carries a valid device signature for exactly
/// this `group` and `peer`. The caller still decides whether that address is authorized.
pub fn verify(agent: &str, group: &str, peer: &PeerId) -> Option<String> {
    let sig = agent.strip_prefix(AGENT_PREFIX)?;
    if sig.len() != 2 + 130 {
        return None;
    }
    Eip191Verifier.recover(&binding_message(group, peer), sig)
}
