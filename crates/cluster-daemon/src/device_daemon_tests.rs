//! HUP-S8.1 daemon orchestration over the in-process transport, with REAL secp256k1 links: devices
//! join the allowed set under their member, the roster lists them, revocation and offboarding evict
//! in the same `SetRoster`, and a forged link never authorizes anything.

use super::*;
use crate::devices::devices_tests::{addr, key, real_link_at, real_revocation, sign};
use crate::ipc::{handle_request, Request, Response};
use crate::transport::InProcessTransport;

const SELF: &str = "0x1111111111111111111111111111111111111111";
const G: &str = "g-devices";

fn daemon() -> ClusterDaemon<InProcessTransport> {
    ClusterDaemon::new(SELF, InProcessTransport::new)
}

struct Fleet {
    member: k256::ecdsa::SigningKey,
    wallet: k256::ecdsa::SigningKey,
    laptop: k256::ecdsa::SigningKey,
    linux: k256::ecdsa::SigningKey,
}

fn fleet() -> Fleet {
    Fleet {
        member: key(0x71),
        wallet: key(0x72),
        laptop: key(0x73),
        linux: key(0x74),
    }
}

fn links(f: &Fleet) -> Vec<DeviceLinkWire> {
    vec![
        real_link_at(&f.member, &f.laptop, &f.wallet, 0, "Studio Mac"),
        real_link_at(&f.member, &f.linux, &f.wallet, 1, "Linux box"),
    ]
}

fn member_roster(f: &Fleet, role: &str) -> Vec<(String, String)> {
    vec![(addr(&f.member), role.to_string())]
}

#[test]
fn linked_devices_are_allowed_under_their_member_with_distinct_identities() {
    let f = fleet();
    let mut d = daemon();
    let (evicted, rejected) = d
        .set_roster_with_devices(G, &member_roster(&f, "member"), &links(&f), &[])
        .unwrap();
    assert!(evicted.is_empty() && rejected.is_empty(), "{rejected:?}");
    assert!(d.admit_peer(G, &addr(&f.laptop), "member"));
    assert!(d.admit_peer(G, &addr(&f.linux), "member"));
    // ADR-003: the member's comms identity is not a peer once it has linked devices.
    assert!(!d.admit_peer(G, &addr(&f.member), "member"));
    let peers = d.peers(G);
    assert_eq!(peers.len(), 2, "two devices, no comms identity: {peers:?}");
    for dev in [&f.laptop, &f.linux] {
        let p = peers
            .iter()
            .find(|p| p.address == addr(dev))
            .expect("device listed");
        assert!(p.online);
        assert_eq!(p.member.as_deref(), Some(addr(&f.member).as_str()));
    }
    assert!(!peers.iter().any(|p| p.address == addr(&f.member)));
}

#[test]
fn a_revoked_machine_holding_the_wallet_cannot_rejoin_as_the_comms_identity() {
    let f = fleet();
    let mut d = daemon();
    d.set_roster_with_devices(G, &member_roster(&f, "member"), &links(&f), &[])
        .unwrap();
    assert!(d.admit_peer(G, &addr(&f.linux), "member"));
    // Revoke both machines: the member has no active device left.
    let revs = [
        real_revocation(&f.member, &f.linux),
        real_revocation(&f.member, &f.laptop),
    ];
    let (evicted, _) = d
        .set_roster_with_devices(G, &member_roster(&f, "member"), &links(&f), &revs)
        .unwrap();
    assert_eq!(evicted, vec![addr(&f.linux)]);
    // The linux box can still derive the comms key from the wallet; that identity stays out.
    assert!(!d.admit_peer(G, &addr(&f.member), "member"));
    assert!(d.peers(G).is_empty());
}

#[test]
fn a_member_with_no_device_links_keeps_meshing_as_its_comms_identity() {
    let f = fleet();
    let mut d = daemon();
    d.set_roster_with_devices(G, &member_roster(&f, "member"), &[], &[])
        .unwrap();
    assert!(d.admit_peer(G, &addr(&f.member), "member"));
}

#[test]
fn devices_response_lists_devices_under_the_member() {
    let f = fleet();
    let mut d = daemon();
    d.set_roster_with_devices(G, &member_roster(&f, "owner"), &links(&f), &[])
        .unwrap();
    d.admit_peer(G, &addr(&f.linux), "owner");
    match handle_request(&mut d, Request::Devices { group: G.into() }) {
        Response::Devices { members } => {
            assert_eq!(members.len(), 1);
            let m = &members[0];
            assert_eq!(m.member, addr(&f.member));
            assert_eq!(m.role, "owner");
            let labels: Vec<(&str, bool)> = m
                .devices
                .iter()
                .map(|d| (d.label.as_str(), d.online))
                .collect();
            assert_eq!(labels, vec![("Studio Mac", false), ("Linux box", true)]);
        }
        other => panic!("expected Devices, got {other:?}"),
    }
}

#[test]
fn a_device_without_a_valid_link_is_never_admitted() {
    let f = fleet();
    let mut d = daemon();
    let mut forged = links(&f);
    // The linux box's link is re-signed by a stranger in the member slot.
    let stranger = key(0x7f);
    let body = cluster_core::device::DeviceLink::new(
        &forged[1].member,
        &forged[1].device,
        &forged[1].wallet,
        forged[1].index,
        &forged[1].label,
        forged[1].issued_at,
    )
    .expect("valid body");
    forged[1].member_sig = sign(&stranger, &body.signing_message());
    let (_, rejected) = d
        .set_roster_with_devices(G, &member_roster(&f, "member"), &forged, &[])
        .unwrap();
    assert_eq!(rejected.len(), 1, "{rejected:?}");
    assert!(rejected[0].contains("member signature"));
    assert!(d.admit_peer(G, &addr(&f.laptop), "member"));
    assert!(!d.admit_peer(G, &addr(&f.linux), "member"));
}

#[test]
fn revocation_evicts_the_device_in_the_same_set_roster() {
    let f = fleet();
    let mut d = daemon();
    d.set_roster_with_devices(G, &member_roster(&f, "member"), &links(&f), &[])
        .unwrap();
    d.admit_peer(G, &addr(&f.laptop), "member");
    d.admit_peer(G, &addr(&f.linux), "member");
    let (evicted, _) = d
        .set_roster_with_devices(
            G,
            &member_roster(&f, "member"),
            &links(&f),
            &[real_revocation(&f.member, &f.linux)],
        )
        .unwrap();
    assert_eq!(evicted, vec![addr(&f.linux)]);
    assert!(!d.peers(G).iter().any(|p| p.address == addr(&f.linux)));
    // Sticky: a later roster update without the revocation cannot readmit the key.
    let (_, rejected) = d
        .set_roster_with_devices(G, &member_roster(&f, "member"), &links(&f), &[])
        .unwrap();
    assert!(
        rejected.iter().any(|r| r.contains("revoked")),
        "{rejected:?}"
    );
    assert!(!d.admit_peer(G, &addr(&f.linux), "member"));
    assert!(d.admit_peer(G, &addr(&f.laptop), "member"));
}

#[test]
fn revocation_survives_leave_and_rejoin() {
    let f = fleet();
    let mut d = daemon();
    d.set_roster_with_devices(
        G,
        &member_roster(&f, "member"),
        &links(&f),
        &[real_revocation(&f.member, &f.linux)],
    )
    .unwrap();
    d.leave(G);
    d.set_roster_with_devices(G, &member_roster(&f, "member"), &links(&f), &[])
        .unwrap();
    assert!(!d.admit_peer(G, &addr(&f.linux), "member"));
}

#[test]
fn offboarding_the_member_evicts_every_device() {
    let f = fleet();
    let other = key(0x75);
    let mut d = daemon();
    let mut roster = member_roster(&f, "member");
    roster.push((addr(&other), "member".into()));
    d.set_roster_with_devices(G, &roster, &links(&f), &[])
        .unwrap();
    d.admit_peer(G, &addr(&f.laptop), "member");
    d.admit_peer(G, &addr(&f.linux), "member");
    let (mut evicted, _) = d
        .set_roster_with_devices(G, &[(addr(&other), "member".into())], &links(&f), &[])
        .unwrap();
    evicted.sort();
    let mut want = vec![addr(&f.laptop), addr(&f.linux)];
    want.sort();
    assert_eq!(evicted, want);
}

#[test]
fn set_roster_without_devices_keeps_the_old_contract() {
    // An older client: SetRoster JSON without `devices`/`revocations` still parses and works.
    let req: Request = serde_json::from_str(
        r#"{"op":"setRoster","group":"g","roster":[["00000000000000000000000000000000000000aa","member"]]}"#,
    )
    .expect("parses");
    let mut d = daemon();
    match handle_request(&mut d, req) {
        Response::Reconciled { evicted, rejected } => {
            assert!(evicted.is_empty());
            assert!(rejected.is_empty());
        }
        other => panic!("expected Reconciled, got {other:?}"),
    }
    // ...and the response omits the new fields when they are empty.
    let json = serde_json::to_string(&Response::Reconciled {
        evicted: vec![],
        rejected: vec![],
    })
    .expect("json");
    assert_eq!(json, r#"{"type":"reconciled","evicted":[]}"#);
}

#[test]
fn set_roster_ipc_carries_devices_and_reports_rejections() {
    let f = fleet();
    let mut bad = links(&f);
    bad[0].wallet_sig = "0x00".into();
    let json = serde_json::json!({
        "op": "setRoster",
        "group": G,
        "roster": member_roster(&f, "member"),
        "devices": bad,
        "revocations": [],
    });
    let req: Request = serde_json::from_value(json).expect("parses");
    let mut d = daemon();
    match handle_request(&mut d, req) {
        Response::Reconciled { rejected, .. } => {
            assert_eq!(rejected.len(), 1);
            assert!(rejected[0].contains("wallet signature"));
            assert!(!rejected[0].contains("0x00"), "never echo signatures");
        }
        other => panic!("expected Reconciled, got {other:?}"),
    }
}
