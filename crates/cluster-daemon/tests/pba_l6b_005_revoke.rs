//! PBA-L6b-005 regression tests (pre-bounty audit 2026-09-24, lane L6b).
//!
//! These are the audit PoCs (`evidence/cluster/l6b_poc.rs`) turned into real tests over the REAL
//! libp2p transport and the public `ClusterDaemon` API, with the assertions inverted: the vulnerable
//! behaviour must NOT happen. Each test carries a positive control (a still-authorized member whose
//! traffic IS delivered) so a negative result can never pass vacuously because the mesh never formed.
//!
//! * L6b-005 — a member removed from (or demoted out of) the roster while OFFLINE stayed in the
//!   transport's authorized set, so it could reconnect, publish co-pins and read the group topic.

use std::sync::Mutex;
use std::thread::sleep;
use std::time::{Duration, Instant};

use cluster_daemon::libp2p_transport::{Libp2pConfig, Libp2pTransport};
use cluster_daemon::transport::MeshTransport;
use cluster_daemon::ClusterDaemon;
use libp2p::Multiaddr;

// Syntactically valid CIDv1 (base32) strings — the daemon only relays well-formed CIDs (L6b-037).
const CID_REVOKED: &str = "bafkreirevokedmemberrevokedmemberrevokedmemberrevokedmem";
const CID_CONTROL: &str = "bafkreicontrolmembercontrolmembercontrolmembercontrolmemb";

fn secret(seed: u8) -> [u8; 32] {
    let mut b = [seed; 32];
    b[0] = seed | 1;
    b
}

fn transport(seed: u8, group: &str) -> Libp2pTransport {
    Libp2pTransport::new(Libp2pConfig {
        secret: secret(seed),
        listen: "/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"),
        group_id: group.into(),
        bootstrap: vec![],
    })
    .expect("transport starts")
}

fn listen(t: &Libp2pTransport) -> Multiaddr {
    for _ in 0..100 {
        if let Some(a) = t.listeners().ok().and_then(|v| v.into_iter().next()) {
            return a;
        }
        sleep(Duration::from_millis(20));
    }
    panic!("listener never came up");
}

fn host_address(seed: u8) -> String {
    Libp2pTransport::identity_from_secret(secret(seed))
        .expect("identity")
        .0
}

/// Drive a revoked peer and a control peer against a daemon: both dial the host and publish until
/// the control's co-pin is delivered (proving the mesh works), then keep going a little longer so
/// the revoked peer has every chance to get through. Returns everything the daemon accepted.
fn run_revoked_vs_control<T: MeshTransport>(
    d: &mut ClusterDaemon<T>,
    group: &str,
    host_listen: Multiaddr,
    host_addr: &str,
    revoked: &mut Libp2pTransport,
    control: &mut Libp2pTransport,
) -> Vec<(String, String)> {
    let revoked_addr = revoked.self_address().to_string();
    let control_addr = control.self_address().to_string();
    revoked.authorize(host_addr);
    control.authorize(host_addr);
    revoked.dial_multiaddr(host_listen.clone()).expect("dial");
    control.dial_multiaddr(host_listen).expect("dial");

    let mut seen: Vec<(String, String)> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut control_seen_at: Option<Instant> = None;
    while Instant::now() < deadline {
        revoked.publish(&revoked_addr, CID_REVOKED);
        control.publish(&control_addr, CID_CONTROL);
        sleep(Duration::from_millis(250));
        for m in d.poll(group) {
            if m.from == control_addr && control_seen_at.is_none() {
                control_seen_at = Some(Instant::now());
            }
            seen.push((m.from, m.data));
        }
        if let Some(t) = control_seen_at {
            if t.elapsed() > Duration::from_secs(3) {
                break;
            }
        }
    }
    seen
}

// ---------------------------------------------------------------------------------------------
// PBA-L6b-005: revocation / demotion while the member is offline
// ---------------------------------------------------------------------------------------------

const G_DEMOTE: &str = "pba-l6b-005-demote";
static DEMOTE_LISTEN: Mutex<Option<Multiaddr>> = Mutex::new(None);
fn demote_host() -> Libp2pTransport {
    let t = transport(0x51, G_DEMOTE);
    *DEMOTE_LISTEN.lock().unwrap() = Some(listen(&t));
    t
}

#[test]
fn pba_l6b_005_member_demoted_to_guest_while_offline_is_refused_on_reconnect() {
    let host_addr = host_address(0x51);
    let mut d = ClusterDaemon::new_single_group(host_addr.clone(), demote_host, G_DEMOTE);
    let mut ex = transport(0x52, G_DEMOTE);
    let mut keep = transport(0x53, G_DEMOTE);
    let ex_addr = ex.self_address().to_string();
    let keep_addr = keep.self_address().to_string();

    d.set_roster(
        G_DEMOTE,
        &[
            (ex_addr.clone(), "member".into()),
            (keep_addr.clone(), "member".into()),
        ],
    )
    .unwrap();
    // Owner demotes `ex` to guest while it is offline (never connected → never in `admitted`).
    d.set_roster(
        G_DEMOTE,
        &[
            (ex_addr.clone(), "guest".into()),
            (keep_addr.clone(), "member".into()),
        ],
    )
    .unwrap();

    let host_listen = DEMOTE_LISTEN.lock().unwrap().clone().expect("host listen");
    let seen = run_revoked_vs_control(
        &mut d,
        G_DEMOTE,
        host_listen,
        &host_addr,
        &mut ex,
        &mut keep,
    );

    assert!(
        seen.iter().any(|(f, _)| *f == keep_addr),
        "control: the still-authorized member's co-pin must be delivered (mesh formed)"
    );
    assert!(
        !seen.iter().any(|(f, _)| *f == ex_addr),
        "PBA-L6b-005: a demoted member's gossip must never be accepted: {seen:?}"
    );
    let (online, total, shared) = d.status(G_DEMOTE);
    assert!(
        !shared.contains(&CID_REVOKED.to_string()),
        "PBA-L6b-005: a demoted member must not inject co-pins (shared={shared:?})"
    );
    assert_eq!(total, 1, "only the control member is allowed");
    assert!(online <= 1, "the demoted member is never counted online");
}

const G_REVOKE: &str = "pba-l6b-005-revoke";
static REVOKE_LISTEN: Mutex<Option<Multiaddr>> = Mutex::new(None);
fn revoke_host() -> Libp2pTransport {
    let t = transport(0x41, G_REVOKE);
    *REVOKE_LISTEN.lock().unwrap() = Some(listen(&t));
    t
}

#[test]
fn pba_l6b_005_member_removed_while_offline_is_refused_on_reconnect() {
    let host_addr = host_address(0x41);
    let mut d = ClusterDaemon::new_single_group(host_addr.clone(), revoke_host, G_REVOKE);
    let mut ex = transport(0x42, G_REVOKE);
    let mut keep = transport(0x43, G_REVOKE);
    let ex_addr = ex.self_address().to_string();
    let keep_addr = keep.self_address().to_string();

    d.set_roster(
        G_REVOKE,
        &[
            (ex_addr.clone(), "member".into()),
            (keep_addr.clone(), "member".into()),
        ],
    )
    .unwrap();
    // Owner offboards `ex` entirely while it is offline.
    d.set_roster(G_REVOKE, &[(keep_addr.clone(), "member".into())])
        .unwrap();

    let host_listen = REVOKE_LISTEN.lock().unwrap().clone().expect("host listen");
    let seen = run_revoked_vs_control(
        &mut d,
        G_REVOKE,
        host_listen,
        &host_addr,
        &mut ex,
        &mut keep,
    );

    assert!(
        seen.iter().any(|(f, _)| *f == keep_addr),
        "control: the still-authorized member's co-pin must be delivered (mesh formed)"
    );
    assert!(
        !seen.iter().any(|(f, _)| *f == ex_addr),
        "PBA-L6b-005: an offboarded member's gossip must never be accepted: {seen:?}"
    );
    // The host must not count the revoked peer as connected either.
    let peers = d.peers(G_REVOKE);
    assert!(
        !peers.iter().any(|p| p.address == ex_addr),
        "the offboarded member is not a peer"
    );
}
