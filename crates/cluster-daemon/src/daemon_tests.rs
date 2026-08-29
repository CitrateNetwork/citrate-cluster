//! cluster-daemon orchestration tests over the in-process transport: admission enforced on connect,
//! offboard eviction disconnects, status/peers reflect the wire, and the IPC round-trips.

use super::*;
use crate::ipc::{handle_request, Request, Response};
use crate::transport::InProcessTransport;

const SELF: &str = "0x1111111111111111111111111111111111111111";
const A: &str = "00000000000000000000000000000000000000aa";
const B: &str = "00000000000000000000000000000000000000bb";
const C: &str = "00000000000000000000000000000000000000cc";

fn roster(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(a, r)| (a.to_string(), r.to_string()))
        .collect()
}

fn daemon() -> ClusterDaemon<InProcessTransport> {
    ClusterDaemon::new(SELF, InProcessTransport::new)
}

#[test]
fn set_roster_then_admit_brings_authorized_peers_online() {
    let mut d = daemon();
    d.set_roster("g1", &roster(&[(A, "member"), (B, "member")]))
        .unwrap();
    assert!(d.admit_peer("g1", A, "member"));
    assert!(d.admit_peer("g1", B, "member"));
    assert_eq!(d.status("g1"), (2, 2));
    assert!(d.peers("g1").iter().all(|p| p.online));
}

#[test]
fn admit_peer_rejects_a_stranger_and_a_guest() {
    let mut d = daemon();
    d.set_roster("g1", &roster(&[(A, "member"), (C, "guest")]))
        .unwrap();
    assert!(
        !d.admit_peer("g1", B, "member"),
        "a stranger not in the roster is refused"
    );
    assert!(
        !d.admit_peer("g1", C, "guest"),
        "a guest (role < Member) is refused"
    );
    assert_eq!(
        d.status("g1"),
        (0, 1),
        "only A is authorized, none connected"
    );
}

#[test]
fn offboard_via_set_roster_evicts_and_disconnects_in_one_step() {
    let mut d = daemon();
    d.set_roster("g1", &roster(&[(A, "member"), (B, "member")]))
        .unwrap();
    d.admit_peer("g1", A, "member");
    d.admit_peer("g1", B, "member");
    let evicted = d.set_roster("g1", &roster(&[(A, "member")])).unwrap();
    assert_eq!(evicted, vec![B.to_string()]);
    assert_eq!(d.status("g1"), (1, 1));
    let a = d.peers("g1").into_iter().find(|p| p.address == A).unwrap();
    assert!(a.online, "A stays connected");
    assert!(
        d.peers("g1").iter().all(|p| p.address != B),
        "B is gone from the authorized set"
    );
}

#[test]
fn drop_peer_takes_a_peer_offline_without_deauthorizing() {
    let mut d = daemon();
    d.set_roster("g1", &roster(&[(A, "member")])).unwrap();
    d.admit_peer("g1", A, "member");
    d.drop_peer("g1", A);
    assert_eq!(d.status("g1"), (0, 1), "A still authorized, just offline");
}

#[test]
fn share_file_ok_and_poll_is_empty_on_a_single_node() {
    let mut d = daemon();
    d.join("g1").unwrap();
    assert!(d.share_file("g1", "bafycid").is_ok());
    assert!(d.poll("g1").is_empty(), "no peers → no messages");
    assert!(d.share_file("missing", "cid").is_err());
    assert_eq!(d.status("missing"), (0, 0));
    assert!(d.peers("missing").is_empty());
}

#[test]
fn handle_request_round_trips_the_contract() {
    let mut d = daemon();
    match handle_request(
        &mut d,
        Request::SetRoster {
            group: "g1".into(),
            roster: roster(&[(A, "member")]),
        },
    ) {
        Response::Reconciled { evicted } => assert!(evicted.is_empty()),
        other => panic!("expected Reconciled, got {other:?}"),
    }
    match handle_request(&mut d, Request::Status { group: "g1".into() }) {
        Response::Status { online, total } => assert_eq!((online, total), (0, 1)),
        other => panic!("expected Status, got {other:?}"),
    }
    match handle_request(&mut d, Request::Peers { group: "g1".into() }) {
        Response::Peers { peers } => assert_eq!(peers.len(), 1),
        other => panic!("expected Peers, got {other:?}"),
    }
}

#[test]
fn in_process_transport_delivers_and_drains() {
    let mut t = InProcessTransport::new();
    t.deliver(A, "hello");
    assert_eq!(t.drain().len(), 1);
    assert!(t.drain().is_empty(), "drain is one-shot");
}
