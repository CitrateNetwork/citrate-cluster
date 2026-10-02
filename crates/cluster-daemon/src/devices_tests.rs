//! HUP-S8.1 daemon-side tests: the real EIP-191 verifier against real secp256k1 keys, and the
//! device-key address agreeing with the libp2p identity (one key -> one address -> one PeerId).

use super::*;
use crate::libp2p_transport::Libp2pTransport;
use cluster_core::device::{verify_link, DeviceRegistry};
use k256::ecdsa::SigningKey;

pub(crate) fn key(seed: u8) -> SigningKey {
    let mut b = [seed; 32];
    b[0] = seed | 1;
    SigningKey::from_slice(&b).expect("valid scalar")
}

pub(crate) fn addr(k: &SigningKey) -> String {
    address_of(k.verifying_key())
}

pub(crate) fn sign(k: &SigningKey, msg: &str) -> String {
    let (sig, recid) = k
        .sign_prehash_recoverable(&eip191_digest(msg.as_bytes()))
        .expect("sign");
    let mut out = sig.to_bytes().to_vec();
    out.push(27 + recid.to_byte());
    format!("0x{}", hex::encode(out))
}

#[test]
fn address_of_matches_the_well_known_vector() {
    // The web3.js documentation key/address pair.
    let k = SigningKey::from_slice(
        &hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
            .expect("hex"),
    )
    .expect("key");
    assert_eq!(addr(&k), "2c7536e3605d9c16a7a3d7b1898e529396a65c23");
}

#[test]
fn recovers_the_personal_sign_signer() {
    let k = key(7);
    let sig = sign(&k, "hello device");
    assert_eq!(Eip191Verifier.recover("hello device", &sig), Some(addr(&k)));
    // Wrong message -> a different (or no) signer.
    assert_ne!(Eip191Verifier.recover("hello devicE", &sig), Some(addr(&k)));
}

#[test]
fn v_may_be_0_1_or_27_28() {
    let k = key(9);
    let sig = sign(&k, "m");
    let mut raw = hex::decode(sig.trim_start_matches("0x")).expect("hex");
    raw[64] -= 27;
    assert_eq!(
        Eip191Verifier.recover("m", &hex::encode(&raw)),
        Some(addr(&k))
    );
}

#[test]
fn malformed_signatures_do_not_recover() {
    assert_eq!(Eip191Verifier.recover("m", "0x1234"), None);
    assert_eq!(Eip191Verifier.recover("m", "not hex"), None);
    let k = key(3);
    let mut raw = hex::decode(sign(&k, "m").trim_start_matches("0x")).expect("hex");
    raw[64] = 5;
    assert_eq!(Eip191Verifier.recover("m", &hex::encode(&raw)), None);
}

#[test]
fn high_s_signatures_are_refused() {
    let k = key(11);
    let (sig, recid) = k
        .sign_prehash_recoverable(&eip191_digest(b"m"))
        .expect("sign");
    // Flip to the high-s twin (s' = n - s) and the recovery parity: same signer, malleable form.
    let (r, s) = sig.split_scalars();
    let high = Signature::from_scalars(r, -*s).expect("high-s sig");
    let mut raw = high.to_bytes().to_vec();
    raw.push(27 + (recid.to_byte() ^ 1));
    assert_eq!(Eip191Verifier.recover("m", &hex::encode(raw)), None);
}

#[test]
fn device_key_address_is_the_libp2p_identity_address() {
    // The device key is the Noise identity: the address a DeviceLink names must be the address the
    // transport derives from the same secret, so admission by link and admission on the wire agree.
    for seed in [0x21u8, 0x22, 0x23] {
        let k = key(seed);
        let mut secret = [seed; 32];
        secret[0] = seed | 1;
        let (wire_addr, _peer) = Libp2pTransport::identity_from_secret(secret).expect("identity");
        assert_eq!(addr(&k), wire_addr);
    }
}

#[test]
fn distinct_device_keys_have_distinct_peer_ids_and_one_key_one_peer_id() {
    let mut peers = std::collections::BTreeSet::new();
    for seed in [0x31u8, 0x32, 0x33, 0x34] {
        let mut secret = [seed; 32];
        secret[0] = seed | 1;
        let (_, p1) = Libp2pTransport::identity_from_secret(secret).expect("identity");
        let (_, p2) = Libp2pTransport::identity_from_secret(secret).expect("identity");
        assert_eq!(p1, p2, "the PeerId is a function of the device key");
        assert!(peers.insert(p1), "two device keys never share a PeerId");
    }
}

fn real_link(member: &SigningKey, device: &SigningKey, wallet: &SigningKey) -> DeviceLinkWire {
    real_link_at(member, device, wallet, 0, "laptop")
}

/// A real three-signature link for `device` at member index `index`.
pub(crate) fn real_link_at(
    member: &SigningKey,
    device: &SigningKey,
    wallet: &SigningKey,
    index: u32,
    label: &str,
) -> DeviceLinkWire {
    let l = DeviceLink::new(
        &addr(member),
        &addr(device),
        &addr(wallet),
        index,
        label,
        1_790_000_000,
    )
    .expect("valid");
    let msg = l.signing_message();
    DeviceLinkWire {
        member: l.member.clone(),
        device: l.device.clone(),
        wallet: l.wallet.clone(),
        index: l.index,
        label: l.label.clone(),
        issued_at: l.issued_at,
        member_sig: sign(member, &msg),
        device_sig: sign(device, &msg),
        wallet_sig: sign(wallet, &msg),
    }
}

#[test]
fn a_real_three_signature_link_verifies_and_a_swapped_signature_does_not() {
    let (m, d, w) = (key(0x41), key(0x42), key(0x43));
    let wire = real_link(&m, &d, &w);
    assert_eq!(verify_link(&(&wire).into(), &Eip191Verifier), Ok(()));
    let mut swapped = wire.clone();
    std::mem::swap(&mut swapped.member_sig, &mut swapped.wallet_sig);
    assert!(verify_link(&(&swapped).into(), &Eip191Verifier).is_err());
}

#[test]
fn wire_json_is_camel_case_and_round_trips() {
    let (m, d, w) = (key(0x51), key(0x52), key(0x53));
    let wire = real_link(&m, &d, &w);
    let json = serde_json::to_string(&wire).expect("json");
    assert!(json.contains("\"issuedAt\""));
    assert!(json.contains("\"memberSig\""));
    let back: DeviceLinkWire = serde_json::from_str(&json).expect("parse");
    assert_eq!(back, wire);
}

#[test]
fn a_real_revocation_removes_the_device() {
    let (m, d, w) = (key(0x61), key(0x62), key(0x63));
    let wire = real_link(&m, &d, &w);
    let rev = DeviceRevocation::new(&addr(&m), &addr(&d), 1_790_000_100).expect("valid");
    let rev_wire = RevocationWire {
        member: rev.member.clone(),
        device: rev.device.clone(),
        revoked_at: rev.revoked_at,
        member_sig: sign(&m, &rev.signing_message()),
    };
    let mut reg = DeviceRegistry::new();
    reg.update(&[(&wire).into()], &[], &Eip191Verifier);
    assert_eq!(reg.member_of(&addr(&d)), Some(addr(&m).as_str()));
    reg.update(&[(&wire).into()], &[(&rev_wire).into()], &Eip191Verifier);
    assert_eq!(reg.member_of(&addr(&d)), None);
}

/// A real member-signed revocation.
pub(crate) fn real_revocation(member: &SigningKey, device: &SigningKey) -> RevocationWire {
    let rev = DeviceRevocation::new(&addr(member), &addr(device), 1_790_000_100).expect("valid");
    RevocationWire {
        member: rev.member.clone(),
        device: rev.device.clone(),
        revoked_at: rev.revoked_at,
        member_sig: sign(member, &rev.signing_message()),
    }
}
