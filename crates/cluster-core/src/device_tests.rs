//! DeviceLink tests (HUP-S8.1). The verifier here is a test double (cfg(test) only): a "signature"
//! is `ok:<signer>:<fnv64 of the message>`, so a signature only recovers for the exact message it
//! was made over and only to the signer it names. The real secp256k1 verifier lives in
//! cluster-daemon and is tested there against real keys.

use super::*;
use crate::{allowed_set, ClusterMembership};

const M1: &str = "00000000000000000000000000000000000000a1"; // member 1 (comms/roster key)
const M2: &str = "00000000000000000000000000000000000000a2"; // member 2
const W1: &str = "00000000000000000000000000000000000000b1"; // member 1's wallet
const W2: &str = "00000000000000000000000000000000000000b2";
const D1: &str = "00000000000000000000000000000000000000d1"; // member 1, laptop
const D2: &str = "00000000000000000000000000000000000000d2"; // member 1, linux box
const D3: &str = "00000000000000000000000000000000000000d3"; // member 2's device

struct FakeVerifier;

fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn fake_sign(signer: &str, msg: &str) -> String {
    format!("ok:{signer}:{:016x}", fnv(msg))
}

impl LinkVerifier for FakeVerifier {
    fn recover(&self, message: &str, sig_hex: &str) -> Option<String> {
        let mut parts = sig_hex.splitn(3, ':');
        if parts.next()? != "ok" {
            return None;
        }
        let signer = parts.next()?;
        let digest = parts.next()?;
        (digest == format!("{:016x}", fnv(message))).then(|| signer.to_string())
    }
}

fn link(member: &str, device: &str, wallet: &str, index: u32, label: &str) -> DeviceLink {
    DeviceLink::new(member, device, wallet, index, label, 1_790_000_000).expect("valid link")
}

fn signed(l: DeviceLink) -> SignedDeviceLink {
    let msg = l.signing_message();
    SignedDeviceLink {
        member_sig: fake_sign(&l.member, &msg),
        device_sig: fake_sign(&l.device, &msg),
        wallet_sig: fake_sign(&l.wallet, &msg),
        link: l,
    }
}

fn revoke(member: &str, device: &str) -> SignedRevocation {
    let r = DeviceRevocation::new(member, device, 1_790_000_100).expect("valid revocation");
    SignedRevocation {
        member_sig: fake_sign(&r.member, &r.signing_message()),
        revocation: r,
    }
}

fn roster(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(a, r)| (a.to_string(), r.to_string()))
        .collect()
}

// ---- the signed message (golden vector shared with citrate-core) ----

#[test]
fn signing_message_golden_vector() {
    // citrate-core's device_link.rs pins this exact string too; if either side changes the format,
    // both test suites fail until the other side matches.
    let l = DeviceLink::new(
        "0x00000000000000000000000000000000000000A1",
        D1,
        W1,
        0,
        "Studio Mac",
        1_790_000_000,
    )
    .expect("valid");
    assert_eq!(
        l.signing_message(),
        "Citrate DeviceLink v1\n\
         Link this device to my Citrate member identity.\n\
         member: 0x00000000000000000000000000000000000000a1\n\
         device: 0x00000000000000000000000000000000000000d1\n\
         wallet: 0x00000000000000000000000000000000000000b1\n\
         index: 0\n\
         label: Studio Mac\n\
         issued_at: 1790000000"
    );
}

#[test]
fn revocation_message_golden_vector() {
    let r = DeviceRevocation::new(M1, D1, 1_790_000_100).expect("valid");
    assert_eq!(
        r.signing_message(),
        "Citrate DeviceRevocation v1\n\
         Remove this device from my Citrate member identity.\n\
         member: 0x00000000000000000000000000000000000000a1\n\
         device: 0x00000000000000000000000000000000000000d1\n\
         revoked_at: 1790000100"
    );
}

// ---- link validation ----

#[test]
fn device_key_must_differ_from_member_and_wallet() {
    assert!(DeviceLink::new(M1, M1, W1, 0, "x", 1).is_none());
    assert!(DeviceLink::new(M1, W1, W1, 0, "x", 1).is_none());
    assert!(DeviceLink::new(M1, D1, W1, 0, "x", 1).is_some());
}

#[test]
fn labels_are_bounded_and_single_line() {
    assert!(label_is_valid("Studio Mac"));
    assert!(label_is_valid("larry's linux-box_2.0"));
    assert!(!label_is_valid(""));
    assert!(!label_is_valid(" padded"));
    assert!(!label_is_valid("two\nlines"));
    assert!(!label_is_valid("member: 0xabc")); // ':' could mimic a signed field
    assert!(!label_is_valid(&"x".repeat(MAX_LABEL_LEN + 1)));
    assert!(label_is_valid(&"x".repeat(MAX_LABEL_LEN)));
}

#[test]
fn index_is_bounded() {
    assert!(DeviceLink::new(M1, D1, W1, MAX_DEVICE_INDEX, "x", 1).is_some());
    assert!(DeviceLink::new(M1, D1, W1, MAX_DEVICE_INDEX + 1, "x", 1).is_none());
}

#[test]
fn a_fully_signed_link_verifies() {
    assert_eq!(
        verify_link(&signed(link(M1, D1, W1, 0, "laptop")), &FakeVerifier),
        Ok(())
    );
}

#[test]
fn each_missing_signature_is_refused_by_name() {
    for which in ["member", "device", "wallet"] {
        let mut s = signed(link(M1, D1, W1, 0, "laptop"));
        let msg = s.link.signing_message();
        // Re-sign one slot with the WRONG key.
        let wrong = fake_sign(M2, &msg);
        match which {
            "member" => s.member_sig = wrong,
            "device" => s.device_sig = wrong,
            _ => s.wallet_sig = wrong,
        }
        assert_eq!(
            verify_link(&s, &FakeVerifier),
            Err(LinkRejection::BadSignature {
                device: D1.to_string(),
                which
            })
        );
    }
}

#[test]
fn a_tampered_body_does_not_verify() {
    let mut s = signed(link(M1, D1, W1, 0, "laptop"));
    s.link.member = M2.to_string(); // re-point the device at another member, keep the signatures
    assert!(verify_link(&s, &FakeVerifier).is_err());
    let mut s = signed(link(M1, D1, W1, 0, "laptop"));
    s.link.label = "renamed".into();
    assert!(verify_link(&s, &FakeVerifier).is_err());
}

#[test]
fn a_malformed_body_is_refused() {
    let mut s = signed(link(M1, D1, W1, 0, "laptop"));
    s.link.device = s.link.member.clone();
    assert!(matches!(
        verify_link(&s, &FakeVerifier),
        Err(LinkRejection::Malformed { .. })
    ));
}

// ---- the registry ----

#[test]
fn registry_admits_verified_links_only() {
    let mut reg = DeviceRegistry::new();
    let mut bad = signed(link(M1, D2, W1, 1, "box"));
    bad.device_sig = "garbage".into();
    let rej = reg.update(
        &[signed(link(M1, D1, W1, 0, "laptop")), bad],
        &[],
        &FakeVerifier,
    );
    assert_eq!(reg.member_of(D1), Some(M1));
    assert_eq!(reg.member_of(D2), None);
    assert_eq!(rej.len(), 1);
}

#[test]
fn one_device_key_cannot_belong_to_two_members() {
    let mut reg = DeviceRegistry::new();
    let rej = reg.update(
        &[
            signed(link(M1, D1, W1, 0, "laptop")),
            signed(link(M2, D1, W2, 0, "stolen")),
        ],
        &[],
        &FakeVerifier,
    );
    assert_eq!(
        reg.member_of(D1),
        None,
        "a contested key is admitted for nobody"
    );
    assert!(rej.contains(&LinkRejection::Conflict {
        device: D1.to_string()
    }));
}

#[test]
fn conflict_resolution_does_not_depend_on_order() {
    let a = signed(link(M1, D1, W1, 0, "laptop"));
    let b = signed(link(M2, D1, W2, 0, "stolen"));
    let mut r1 = DeviceRegistry::new();
    r1.update(&[a.clone(), b.clone()], &[], &FakeVerifier);
    let mut r2 = DeviceRegistry::new();
    r2.update(&[b, a], &[], &FakeVerifier);
    assert_eq!(r1.links(), r2.links());
}

#[test]
fn the_index_is_a_display_ordinal_not_an_identity() {
    // Two machines picked index 0 independently: both are still admitted (the key is the identity).
    let mut reg = DeviceRegistry::new();
    let rej = reg.update(
        &[
            signed(link(M1, D1, W1, 0, "laptop")),
            signed(link(M1, D2, W1, 0, "box")),
        ],
        &[],
        &FakeVerifier,
    );
    assert!(rej.is_empty(), "{rej:?}");
    assert_eq!(reg.member_of(D1), Some(M1));
    assert_eq!(reg.member_of(D2), Some(M1));
}

#[test]
fn reissued_link_for_the_same_device_keeps_the_newest() {
    let old = signed(DeviceLink::new(M1, D1, W1, 0, "old name", 100).expect("valid"));
    let new = signed(DeviceLink::new(M1, D1, W1, 0, "new name", 200).expect("valid"));
    let mut reg = DeviceRegistry::new();
    let rej = reg.update(&[new, old], &[], &FakeVerifier);
    assert!(rej.is_empty());
    assert_eq!(reg.devices_of(M1)[0].label, "new name");
}

#[test]
fn revocation_is_sticky_across_updates() {
    let mut reg = DeviceRegistry::new();
    let l = signed(link(M1, D1, W1, 0, "laptop"));
    reg.update(std::slice::from_ref(&l), &[], &FakeVerifier);
    assert_eq!(reg.member_of(D1), Some(M1));
    reg.update(std::slice::from_ref(&l), &[revoke(M1, D1)], &FakeVerifier);
    assert_eq!(reg.member_of(D1), None);
    // A later update that omits the revocation still cannot bring the key back.
    let rej = reg.update(&[l], &[], &FakeVerifier);
    assert_eq!(reg.member_of(D1), None);
    assert!(rej.contains(&LinkRejection::Revoked {
        device: D1.to_string()
    }));
    assert!(reg.is_revoked(M1, D1));
}

#[test]
fn a_member_cannot_revoke_another_members_device() {
    let mut reg = DeviceRegistry::new();
    reg.update(
        &[signed(link(M2, D3, W2, 0, "theirs"))],
        &[revoke(M1, D3)],
        &FakeVerifier,
    );
    assert_eq!(
        reg.member_of(D3),
        Some(M2),
        "M1's revocation does not touch M2's link"
    );
}

#[test]
fn a_forged_revocation_is_refused() {
    let mut reg = DeviceRegistry::new();
    let mut r = revoke(M1, D1);
    r.member_sig = fake_sign(M2, &r.revocation.signing_message());
    let rej = reg.update(
        &[signed(link(M1, D1, W1, 0, "laptop"))],
        &[r],
        &FakeVerifier,
    );
    assert_eq!(reg.member_of(D1), Some(M1));
    assert!(matches!(rej[0], LinkRejection::BadRevocation { .. }));
}

#[test]
fn oversized_update_is_refused_whole_and_keeps_prior_state() {
    let mut reg = DeviceRegistry::new();
    reg.update(&[signed(link(M1, D1, W1, 0, "laptop"))], &[], &FakeVerifier);
    let many: Vec<SignedDeviceLink> = (0..=MAX_LINKS_PER_UPDATE)
        .map(|_| signed(link(M1, D2, W1, 1, "box")))
        .collect();
    let rej = reg.update(&many, &[], &FakeVerifier);
    assert_eq!(rej, vec![LinkRejection::TooMany]);
    assert_eq!(reg.member_of(D1), Some(M1));
}

// ---- the effective roster + admission ----

#[test]
fn devices_inherit_their_members_role() {
    let mut reg = DeviceRegistry::new();
    reg.update(
        &[
            signed(link(M1, D1, W1, 0, "laptop")),
            signed(link(M1, D2, W1, 1, "box")),
        ],
        &[],
        &FakeVerifier,
    );
    let eff = effective_roster(&roster(&[(M1, "admin")]), &reg);
    // ADR-003: with devices linked, the member is admitted through them only.
    assert_eq!(eff, roster(&[(D1, "admin"), (D2, "admin")]));
}

#[test]
fn a_device_of_a_non_member_or_guest_is_not_allowed() {
    let mut reg = DeviceRegistry::new();
    reg.update(
        &[
            signed(link(M1, D1, W1, 0, "laptop")),
            signed(link(M2, D3, W2, 0, "theirs")),
        ],
        &[],
        &FakeVerifier,
    );
    // M1 is a guest; M2 is not on the roster at all.
    let allowed = allowed_set(&effective_roster(&roster(&[(M1, "guest")]), &reg));
    assert!(allowed.is_empty());
}

#[test]
fn distinct_devices_get_distinct_admission_identities() {
    let mut reg = DeviceRegistry::new();
    reg.update(
        &[
            signed(link(M1, D1, W1, 0, "laptop")),
            signed(link(M1, D2, W1, 1, "box")),
        ],
        &[],
        &FakeVerifier,
    );
    let eff = effective_roster(&roster(&[(M1, "member")]), &reg);
    let mut m = ClusterMembership::new(&eff);
    assert!(m.join(D1, "member"));
    assert!(m.join(D2, "member"));
    assert_eq!(m.admitted(), vec![D1.to_string(), D2.to_string()]);
}

#[test]
fn revoking_a_device_evicts_it_in_one_reconcile() {
    let mut reg = DeviceRegistry::new();
    let links = [
        signed(link(M1, D1, W1, 0, "laptop")),
        signed(link(M1, D2, W1, 1, "box")),
    ];
    let r = roster(&[(M1, "member")]);
    reg.update(&links, &[], &FakeVerifier);
    let mut m = ClusterMembership::new(&effective_roster(&r, &reg));
    m.join(D1, "member");
    m.join(D2, "member");
    reg.update(&links, &[revoke(M1, D2)], &FakeVerifier);
    let evicted = m.reconcile(&effective_roster(&r, &reg));
    assert_eq!(evicted, vec![D2.to_string()]);
    assert!(m.is_admitted(D1));
    assert!(!m.is_admitted(D2));
    assert!(m.invariant_holds());
}

#[test]
fn offboarding_a_member_evicts_all_of_its_devices() {
    let mut reg = DeviceRegistry::new();
    reg.update(
        &[
            signed(link(M1, D1, W1, 0, "laptop")),
            signed(link(M2, D3, W2, 0, "theirs")),
        ],
        &[],
        &FakeVerifier,
    );
    let mut m = ClusterMembership::new(&effective_roster(
        &roster(&[(M1, "member"), (M2, "member")]),
        &reg,
    ));
    m.join(D1, "member");
    m.join(D3, "member");
    let evicted = m.reconcile(&effective_roster(&roster(&[(M2, "member")]), &reg));
    assert_eq!(evicted, vec![D1.to_string()]);
}

#[test]
fn a_member_key_listed_as_someone_elses_device_stays_a_member_only() {
    // M2 is a roster member; M1 tries to claim M2's key as one of its devices.
    let l = DeviceLink {
        member: M1.to_string(),
        device: M2.to_string(),
        wallet: W1.to_string(),
        index: 0,
        label: "grab".into(),
        issued_at: 1,
    };
    let mut reg = DeviceRegistry::new();
    reg.update(&[signed(l)], &[], &FakeVerifier);
    let eff = effective_roster(&roster(&[(M1, "member"), (M2, "guest")]), &reg);
    // M2 keeps its own (guest) entry and is NOT lifted to member by M1's link.
    assert_eq!(eff, roster(&[(M1, "member"), (M2, "guest")]));
}

#[test]
fn device_roster_lists_devices_under_their_member() {
    let mut reg = DeviceRegistry::new();
    reg.update(
        &[
            signed(link(M1, D2, W1, 1, "box")),
            signed(link(M1, D1, W1, 0, "laptop")),
            signed(link(M2, D3, W2, 0, "theirs")),
        ],
        &[],
        &FakeVerifier,
    );
    let view = device_roster(&roster(&[(M1, "owner"), (M2, "guest")]), &reg);
    assert_eq!(view.len(), 1, "guests are not part of the cluster roster");
    assert_eq!(view[0].member, M1);
    let labels: Vec<&str> = view[0].devices.iter().map(|d| d.label.as_str()).collect();
    assert_eq!(labels, vec!["laptop", "box"]);
}

// ---- the member's comms identity once the member uses device keys ----
//
// The comms key is derived from the wallet, so every machine that holds the wallet can present it.
// While a member's comms identity stays admitted next to its linked devices, a revoked machine
// simply rejoins as that identity. Once a member has a linked device (or has revoked one), the
// member is admitted ONLY through its device keys.

#[test]
fn a_member_with_linked_devices_is_admitted_only_through_its_devices() {
    let mut reg = DeviceRegistry::new();
    reg.update(
        &[
            signed(link(M1, D1, W1, 0, "laptop")),
            signed(link(M1, D2, W1, 1, "box")),
        ],
        &[],
        &FakeVerifier,
    );
    let eff = effective_roster(&roster(&[(M1, "member"), (M2, "member")]), &reg);
    // M2 has no devices and keeps its single-device identity; M1's comms identity is gone.
    assert_eq!(
        eff,
        roster(&[(M2, "member"), (D1, "member"), (D2, "member")])
    );
    let mut m = ClusterMembership::new(&eff);
    assert!(!m.join(M1, "member"), "the comms identity no longer admits");
    assert!(m.join(D1, "member"));
}

#[test]
fn a_revoked_machine_cannot_rejoin_as_the_members_comms_identity() {
    let mut reg = DeviceRegistry::new();
    let links = [
        signed(link(M1, D1, W1, 0, "laptop")),
        signed(link(M1, D2, W1, 1, "box")),
    ];
    let r = roster(&[(M1, "member")]);
    reg.update(&links, &[], &FakeVerifier);
    let mut m = ClusterMembership::new(&effective_roster(&r, &reg));
    assert!(m.join(D2, "member"));
    reg.update(&links, &[revoke(M1, D2)], &FakeVerifier);
    let evicted = m.reconcile(&effective_roster(&r, &reg));
    assert_eq!(evicted, vec![D2.to_string()]);
    // The box still holds the wallet, so it can present M1's comms key. That must not admit.
    assert!(!m.join(M1, "member"));
    assert!(m.invariant_holds());
}

#[test]
fn revoking_the_last_device_does_not_restore_the_comms_identity() {
    let mut reg = DeviceRegistry::new();
    let links = [signed(link(M1, D1, W1, 0, "laptop"))];
    reg.update(&links, &[revoke(M1, D1)], &FakeVerifier);
    assert!(reg.devices_of(M1).is_empty());
    let eff = effective_roster(&roster(&[(M1, "member")]), &reg);
    assert!(
        allowed_set(&eff).is_empty(),
        "a member that has revoked a device stays on device keys: {eff:?}"
    );
}

#[test]
fn a_member_without_devices_keeps_its_single_device_identity() {
    let mut reg = DeviceRegistry::new();
    // Somebody else's device and somebody else's revocation do not touch M1.
    reg.update(
        &[signed(link(M2, D3, W2, 0, "theirs"))],
        &[revoke(M2, D2)],
        &FakeVerifier,
    );
    let eff = effective_roster(&roster(&[(M1, "member"), (M2, "member")]), &reg);
    assert_eq!(eff, roster(&[(M1, "member"), (D3, "member")]));
}

#[test]
fn an_unverified_revocation_does_not_switch_a_member_to_device_keys() {
    let mut reg = DeviceRegistry::new();
    let mut forged = revoke(M1, D1);
    forged.member_sig = fake_sign(M2, &forged.revocation.signing_message());
    reg.update(&[], &[forged], &FakeVerifier);
    let eff = effective_roster(&roster(&[(M1, "member")]), &reg);
    assert_eq!(eff, roster(&[(M1, "member")]));
}

#[test]
fn a_guest_with_a_link_is_still_not_admitted_either_way() {
    let mut reg = DeviceRegistry::new();
    reg.update(&[signed(link(M1, D1, W1, 0, "laptop"))], &[], &FakeVerifier);
    let eff = effective_roster(&roster(&[(M1, "guest")]), &reg);
    assert!(allowed_set(&eff).is_empty(), "{eff:?}");
}

#[test]
fn a_later_update_without_the_members_links_keeps_a_revoker_off_its_comms_identity() {
    // Links are replaced by every roster update; only revocations are sticky. A member that has
    // revoked a device stays on device keys even when a later update carries none of its links.
    let mut reg = DeviceRegistry::new();
    let r = roster(&[(M1, "member")]);
    reg.update(
        &[
            signed(link(M1, D1, W1, 0, "laptop")),
            signed(link(M1, D2, W1, 1, "box")),
        ],
        &[revoke(M1, D2)],
        &FakeVerifier,
    );
    assert_eq!(effective_roster(&r, &reg), roster(&[(D1, "member")]));
    reg.update(&[], &[], &FakeVerifier);
    assert!(
        allowed_set(&effective_roster(&r, &reg)).is_empty(),
        "the revoked box must not come back as the comms identity"
    );
}

#[test]
fn a_member_whose_links_are_withdrawn_without_a_revocation_is_back_on_its_comms_identity() {
    // The client is the source of truth for links: withdrawing a link is not a revocation, so a
    // member that never revoked anything returns to its single-device identity (modelled as
    // DropLink in formal/DeviceLink.tla).
    let mut reg = DeviceRegistry::new();
    let r = roster(&[(M1, "member")]);
    reg.update(&[signed(link(M1, D1, W1, 0, "laptop"))], &[], &FakeVerifier);
    assert_eq!(effective_roster(&r, &reg), roster(&[(D1, "member")]));
    reg.update(&[], &[], &FakeVerifier);
    assert_eq!(effective_roster(&r, &reg), roster(&[(M1, "member")]));
}
