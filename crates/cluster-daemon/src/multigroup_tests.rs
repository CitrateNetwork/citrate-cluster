//! HUP-S8.4: one daemon serves every group, with per-group state isolated, and the seed IPC.
//! In-process transport (single node), so these are the daemon's own rules; the wire-level proofs
//! are `libp2p_discovery_tests.rs` and `tests/multigroup_multiprocess.rs`.

use std::sync::{Arc, Mutex};

use super::*;
use crate::ipc::{handle_request, Request, Response};
use crate::transport::{InProcessTransport, NO_MESH};

const SELF: &str = "1111111111111111111111111111111111111111";
const A: &str = "00000000000000000000000000000000000000aa";
const B: &str = "00000000000000000000000000000000000000bb";
const PEER: &str = "16Uiu2HAmPLe7Mzm8TsYUubgCAW1aJoeFScxrLj8ppHFivPo97bUZ";

fn roster(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(a, r)| (a.to_string(), r.to_string()))
        .collect()
}

/// A daemon whose factory records the group ids it was asked for.
fn recording() -> (ClusterDaemon<InProcessTransport>, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let d = ClusterDaemon::with_factory(
        SELF,
        Box::new(move |g: &str| {
            log.lock().map_err(|e| e.to_string())?.push(g.to_string());
            Ok(InProcessTransport::new())
        }),
    );
    (d, seen)
}

#[test]
fn the_factory_is_told_which_group_it_builds_for_once_per_group() {
    let (mut d, seen) = recording();
    d.set_roster("g1", &roster(&[(A, "member")])).expect("g1");
    d.join("g1").expect("join g1");
    d.join("g2").expect("join g2");
    d.set_roster("g2", &roster(&[(B, "member")])).expect("g2");
    assert_eq!(*seen.lock().expect("log"), vec!["g1", "g2"]);
    assert_eq!(d.groups(), vec!["g1", "g2"]);
}

#[test]
fn a_transport_that_fails_to_start_creates_no_session_and_no_device_state() {
    let mut d: ClusterDaemon<InProcessTransport> =
        ClusterDaemon::with_factory(SELF, Box::new(|g: &str| Err(format!("port busy for {g}"))));
    let e = d
        .set_roster("g1", &roster(&[(A, "member")]))
        .expect_err("refused");
    assert!(e.contains("port busy for g1"), "{e}");
    assert!(d.join("g1").is_err());
    assert!(d.groups().is_empty());
    assert_eq!(d.status("g1"), (0, 0, Vec::<String>::new()));
    assert!(
        d.devices("g1").is_empty(),
        "no device state for a refused group"
    );
    assert!(!d.admit_peer("g1", A, "member"));
}

#[test]
fn an_empty_group_id_is_refused() {
    let (mut d, seen) = recording();
    assert!(d.join("").is_err());
    assert!(d.join("   ").is_err());
    assert!(seen.lock().expect("log").is_empty());
}

#[test]
fn the_group_cap_holds_and_leaving_frees_a_slot() {
    let (mut d, _) = recording();
    for i in 0..MAX_GROUPS {
        d.join(&format!("g{i}")).expect("under the cap");
    }
    let e = d.join("one-too-many").expect_err("over the cap");
    assert!(e.contains("leave one first"), "{e}");
    // A group already served is not "new".
    assert!(d.set_roster("g0", &roster(&[(A, "member")])).is_ok());
    d.leave("g0");
    assert!(d.join("one-too-many").is_ok(), "leaving freed a slot");
}

/// The core of the multi-group prerequisite: two groups with the same peer; evicting it from one
/// (a roster change, a revocation) leaves the other untouched.
#[test]
fn an_eviction_in_one_group_never_touches_another() {
    let (mut d, _) = recording();
    let both = roster(&[(A, "member"), (B, "member")]);
    d.set_roster("g1", &both).expect("g1");
    d.set_roster("g2", &both).expect("g2");
    for g in ["g1", "g2"] {
        assert!(d.admit_peer(g, A, "member"));
        assert!(d.admit_peer(g, B, "member"));
    }
    let evicted = d
        .set_roster("g1", &roster(&[(B, "member")]))
        .expect("drop A from g1");
    assert_eq!(evicted, vec![A.to_string()]);
    let online = |d: &mut ClusterDaemon<InProcessTransport>, g: &str| -> Vec<String> {
        d.peers(g)
            .into_iter()
            .filter(|p| p.online)
            .map(|p| p.address)
            .collect()
    };
    assert_eq!(online(&mut d, "g1"), vec![B.to_string()]);
    assert_eq!(online(&mut d, "g2"), vec![A.to_string(), B.to_string()]);
    assert_eq!(d.status("g2").1, 2, "g2 still authorizes both");
    // Leaving g1 leaves g2 as it was.
    d.leave("g1");
    assert_eq!(online(&mut d, "g2"), vec![A.to_string(), B.to_string()]);
}

#[test]
fn a_pinned_daemon_with_a_factory_still_refuses_other_groups() {
    let mut d: ClusterDaemon<InProcessTransport> = ClusterDaemon::with_factory_single_group(
        SELF,
        Box::new(|_: &str| Ok(InProcessTransport::new())),
        "alpha",
    );
    assert!(d.join("alpha").is_ok());
    assert!(d.join("beta").is_err());
    assert!(!d.admit_peer("beta", A, "member"), "no session sneaks in");
    assert_eq!(d.groups(), vec!["alpha"]);
}

#[test]
fn seed_requests_are_honest_without_a_mesh() {
    let (mut d, _) = recording();
    assert!(d.seed("g1").is_err(), "not joined");
    d.join("g1").expect("join");
    assert_eq!(d.seed("g1"), Err(NO_MESH.to_string()));
    let seed = cluster_core::seed::GroupSeed::new(
        "g1",
        vec![format!("/ip4/10.0.0.5/tcp/4211/p2p/{PEER}")],
    )
    .expect("seed")
    .encode();
    assert_eq!(d.add_seed("g1", &seed), Err(NO_MESH.to_string()));
    // Checked before the transport is asked.
    assert_eq!(
        d.add_seed("g2", &seed),
        Err("the seed is for a different group".to_string())
    );
    assert!(d.add_seed("g1", "https://example.com").is_err());
    let other = cluster_core::seed::GroupSeed::new(
        "g9",
        vec![format!("/ip4/10.0.0.5/tcp/4211/p2p/{PEER}")],
    )
    .expect("seed")
    .encode();
    assert!(d
        .add_seed("g9", &other)
        .unwrap_err()
        .contains("not in group"));
}

#[test]
fn the_seed_ops_round_trip_over_the_ipc_contract() {
    let (mut d, _) = recording();
    let req: Request =
        serde_json::from_str(r#"{"op":"seed","group":"g1"}"#).expect("seed request parses");
    match handle_request(&mut d, req) {
        Response::Error { message } => assert!(message.contains("not in group"), "{message}"),
        other => panic!("unexpected {other:?}"),
    }
    let req: Request = serde_json::from_str(r#"{"op":"addSeed","group":"g1","seed":"x"}"#)
        .expect("addSeed request parses");
    assert!(matches!(
        handle_request(&mut d, req),
        Response::Error { .. }
    ));
    // The success shapes the client reads.
    let ok = serde_json::to_value(Response::Seed {
        seed: "citrate-cluster://seed?v=1".into(),
        addrs: vec!["/ip4/1.2.3.4/tcp/1/p2p/x".into()],
    })
    .expect("json");
    assert_eq!(ok["type"], "seed");
    assert_eq!(ok["addrs"][0], "/ip4/1.2.3.4/tcp/1/p2p/x");
    let seeded = serde_json::to_value(Response::Seeded { dialing: 2 }).expect("json");
    assert_eq!(seeded, serde_json::json!({"type": "seeded", "dialing": 2}));
}
