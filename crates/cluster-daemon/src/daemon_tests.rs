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
    assert_eq!(d.status("g1"), (2, 2, Vec::<String>::new()));
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
        (0, 1, Vec::<String>::new()),
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
    assert_eq!(d.status("g1"), (1, 1, Vec::<String>::new()));
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
    assert_eq!(
        d.status("g1"),
        (0, 1, Vec::<String>::new()),
        "A still authorized, just offline"
    );
}

#[test]
fn share_file_ok_and_poll_is_empty_on_a_single_node() {
    let mut d = daemon();
    d.join("g1").unwrap();
    assert!(d.share_file("g1", &cid_n(0)).is_ok());
    assert!(d.poll("g1").is_empty(), "no peers → no messages");
    assert!(d.share_file("missing", "cid").is_err());
    assert_eq!(d.status("missing"), (0, 0, Vec::<String>::new()));
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
        Response::Status {
            online,
            total,
            shared_files,
        } => {
            assert_eq!((online, total), (0, 1));
            assert!(shared_files.is_empty());
        }
        other => panic!("expected Status, got {other:?}"),
    }
    match handle_request(&mut d, Request::Peers { group: "g1".into() }) {
        Response::Peers { peers } => assert_eq!(peers.len(), 1),
        other => panic!("expected Peers, got {other:?}"),
    }
}

// CL-B-002 regression: a group-pinned daemon (the libp2p one-group-per-daemon constraint, S1) must
// refuse any group id other than its configured one with an explicit Error — never silently build a
// second swarm on the same env topic/port/PeerId while judging peers against a different roster.
#[test]
fn a_group_pinned_daemon_refuses_a_second_group() {
    let mut d = ClusterDaemon::new_single_group(SELF, InProcessTransport::new, "alpha");
    // The configured group works.
    assert!(d.set_roster("alpha", &roster(&[(A, "member")])).is_ok());
    assert!(d.join("alpha").is_ok());
    // A second, different group is refused on both session-creating ops.
    assert!(
        d.set_roster("beta", &roster(&[(A, "member")])).is_err(),
        "setRoster on a second group must fail closed, not silently mis-wire"
    );
    assert!(
        d.join("beta").is_err(),
        "join on a second group must fail closed"
    );
    // And no phantom session was created for the refused group.
    assert_eq!(d.status("beta"), (0, 0, Vec::<String>::new()));
    assert!(d.peers("beta").is_empty());
    // An un-pinned daemon (in-process, no wire) keeps multi-group behaviour.
    let mut open = ClusterDaemon::new(SELF, InProcessTransport::new);
    assert!(open.set_roster("g1", &roster(&[(A, "member")])).is_ok());
    assert!(open.set_roster("g2", &roster(&[(B, "member")])).is_ok());
}

// CL-B-007: a secret file (seed / bearer) must be refused unless it is 0600 and owned by us, so a
// packaging bug or a `umask 0` service manager cannot leave the cluster identity secret world-readable
// while the daemon starts happily.
#[cfg(unix)]
#[test]
fn assert_secure_file_fails_closed_on_group_or_world_access() {
    use std::os::unix::fs::PermissionsExt;
    let p = std::env::temp_dir().join(format!("clb007-{}.seed", std::process::id()));
    std::fs::write(&p, "deadbeef").unwrap();
    let path = p.to_str().unwrap();

    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        crate::assert_secure_file(path).is_ok(),
        "0600 owned by us is accepted"
    );

    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = crate::assert_secure_file(path).unwrap_err();
    assert!(
        err.contains("0600") || err.contains("accessible"),
        "a world-readable secret file must fail closed: {err}"
    );

    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(
        crate::assert_secure_file(path).is_err(),
        "a group-readable secret file must fail closed"
    );

    let _ = std::fs::remove_file(&p);
}

#[test]
fn in_process_transport_delivers_and_drains() {
    let mut t = InProcessTransport::new();
    t.deliver(A, "hello");
    assert_eq!(t.drain().len(), 1);
    assert!(t.drain().is_empty(), "drain is one-shot");
}

#[test]
fn share_file_adds_the_cid_to_status_shared_files() {
    let mut d = daemon();
    d.join("g1").unwrap();
    let own = cid_n(1);
    d.share_file("g1", &own).unwrap();
    let (_, _, shared) = d.status("g1");
    assert_eq!(
        shared,
        vec![own.clone()],
        "this node's own co-pin is in the shared set"
    );
    // Idempotent: re-announcing the same CID does not duplicate it.
    d.share_file("g1", &own).unwrap();
    let (_, _, shared) = d.status("g1");
    assert_eq!(shared, vec![own]);
}

#[test]
fn a_received_co_pin_shows_up_in_the_next_status_shared_files() {
    let mut d = daemon();
    d.join("g1").unwrap();
    // A peer's co-pin arrives over the mesh (the libp2p impl fills the inbox from gossipsub; here
    // we inject via the in-process transport's deliver hook). It must appear in the NEXT status —
    // drain-on-status is the accumulation point (the daemon has no background loop).
    d.groups
        .get_mut("g1")
        .expect("group exists after join")
        .transport_mut()
        .deliver(A, &cid_n(2));
    let (_, _, shared) = d.status("g1");
    assert!(
        shared.contains(&cid_n(2)),
        "a received co-pin is accumulated into the shared set on status()"
    );
    // Mixed set stays sorted+deduped across own announcements and received co-pins.
    // (a CIDv0 `Qm…` sorts before every base32 `b…` CIDv1.)
    let own_v0 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG".to_string();
    d.share_file("g1", &own_v0).unwrap();
    let (_, _, shared) = d.status("g1");
    assert_eq!(shared, vec![own_v0, cid_n(2)]);
}

// CL-S3 regression: SetRoster must AUTHORIZE every role-gated roster peer in the transport (else the
// libp2p mesh drops inbound peers as unauthorized). InProcessTransport::authorize is a no-op, so we
// observe the calls with a recording transport (via a thread-local, since the factory is a bare fn).

thread_local! {
    static AUTHORIZED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    static DISCONNECTED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

struct RecordingTransport;
impl RecordingTransport {
    fn new() -> Self {
        RecordingTransport
    }
}
impl cluster_core::ClusterTransport for RecordingTransport {
    fn dial(&mut self, _peer: &str) {}
    fn disconnect(&mut self, peer: &str) {
        DISCONNECTED.with(|d| d.borrow_mut().push(peer.to_string()));
    }
    fn connected(&self) -> Vec<String> {
        Vec::new()
    }
}
impl crate::transport::MeshTransport for RecordingTransport {
    fn publish(&mut self, _from: &str, _data: &str) {}
    fn drain(&mut self) -> Vec<crate::ipc::MeshMessage> {
        Vec::new()
    }
    fn authorize(&mut self, addr: &str) {
        AUTHORIZED.with(|a| a.borrow_mut().push(addr.to_string()));
    }
}

#[test]
fn set_roster_authorizes_every_role_gated_peer_not_guests() {
    AUTHORIZED.with(|a| a.borrow_mut().clear());
    let mut d = ClusterDaemon::new(SELF, RecordingTransport::new);
    d.set_roster("g", &roster(&[(A, "member"), (B, "admin"), (C, "guest")]))
        .unwrap();
    let mut got = AUTHORIZED.with(|a| a.borrow().clone());
    got.sort();
    got.dedup();
    assert!(
        got.contains(&A.to_string()),
        "a member is authorized to mesh"
    );
    assert!(
        got.contains(&B.to_string()),
        "an admin is authorized to mesh"
    );
    assert!(
        !got.contains(&C.to_string()),
        "a guest is NOT authorized to mesh"
    );
}

// PBA-L6b-005: a roster change must DE-AUTHORIZE (transport `disconnect`) every address that left the
// allowed set — including peers that were never admitted (offline at revoke time), which the
// admitted-only `reconcile` eviction never reaches — and must leave still-allowed peers alone.
#[test]
fn pba_l6b_005_set_roster_deauthorizes_every_removed_address_even_if_never_admitted() {
    AUTHORIZED.with(|a| a.borrow_mut().clear());
    DISCONNECTED.with(|d| d.borrow_mut().clear());
    let mut d = ClusterDaemon::new(SELF, RecordingTransport::new);
    d.set_roster("g", &roster(&[(A, "member"), (B, "member"), (C, "admin")]))
        .unwrap();
    assert!(
        DISCONNECTED.with(|d| d.borrow().is_empty()),
        "adding peers de-authorizes nobody"
    );
    // A is offboarded, B is demoted to guest, C stays. None of them was ever admitted.
    let evicted = d
        .set_roster("g", &roster(&[(B, "guest"), (C, "admin")]))
        .unwrap();
    assert!(
        evicted.is_empty(),
        "nobody was admitted, so nobody is evicted"
    );
    let mut gone = DISCONNECTED.with(|d| d.borrow().clone());
    gone.sort();
    assert_eq!(
        gone,
        vec![A.to_string(), B.to_string()],
        "every address removed from the allowed set is de-authorized on the transport, and only those"
    );
    // Re-applying the same roster is a no-op on the wire.
    DISCONNECTED.with(|d| d.borrow_mut().clear());
    d.set_roster("g", &roster(&[(B, "guest"), (C, "admin")]))
        .unwrap();
    assert!(DISCONNECTED.with(|d| d.borrow().is_empty()));
}

/// A syntactically valid, distinct CIDv1 (base32) for index `i` (body chars from the base32 alphabet).
fn cid_n(i: usize) -> String {
    const B32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut s = String::from("bafkrei");
    let mut n = i;
    for _ in 0..52 {
        s.push(B32[n % 32] as char);
        n /= 32;
    }
    s
}

// PBA-L6b-020: the co-pinned shared set is bounded per group. A peer (or, pre-L6b-005, a revoked
// ex-member) flooding distinct CIDs must not grow the daemon's memory or the Status line without
// bound.
#[test]
fn pba_l6b_020_received_co_pins_are_capped_per_group() {
    let mut d = daemon();
    d.join("g1").unwrap();
    let flood = 5_000usize;
    {
        let t = d.groups.get_mut("g1").expect("group").transport_mut();
        for i in 0..flood {
            t.deliver(A, &cid_n(i));
        }
    }
    let _ = d.poll("g1");
    let (_, _, shared) = d.status("g1");
    assert!(
        shared.len() <= 4096,
        "PBA-L6b-020: shared set must be capped, got {}",
        shared.len()
    );
    assert!(
        !shared.is_empty(),
        "the cap keeps the first CIDs, it does not drop everything"
    );
}

#[test]
fn pba_l6b_020_share_file_is_refused_once_the_set_is_full() {
    let mut d = daemon();
    d.join("g1").unwrap();
    for i in 0..4096 {
        d.share_file("g1", &cid_n(i)).unwrap();
    }
    assert!(
        d.share_file("g1", &cid_n(4096)).is_err(),
        "PBA-L6b-020: a new CID past the cap is refused with an explicit error"
    );
    assert!(
        d.share_file("g1", &cid_n(7)).is_ok(),
        "re-announcing a CID already in the set is still fine at the cap"
    );
}

// PBA-L6b-037: only well-formed CIDs cross the daemon boundary (from the local client or the mesh).
#[test]
fn pba_l6b_037_share_file_rejects_a_non_cid() {
    let mut d = daemon();
    d.join("g1").unwrap();
    for bad in [
        "",
        "../../etc/passwd",
        "evil cid",
        "bafy/../x",
        "cid",
        "BAFKREIUPPERCASE",
    ] {
        assert!(
            d.share_file("g1", bad).is_err(),
            "PBA-L6b-037: {bad:?} must be refused"
        );
    }
    let (_, _, shared) = d.status("g1");
    assert!(shared.is_empty());
}

#[test]
fn pba_l6b_037_a_received_non_cid_never_reaches_status_or_poll() {
    let mut d = daemon();
    d.join("g1").unwrap();
    {
        let t = d.groups.get_mut("g1").expect("group").transport_mut();
        t.deliver(A, "../../../home/user/.ssh/id_rsa");
        t.deliver(A, &"b".repeat(60_000));
        t.deliver(A, &cid_n(1));
    }
    let polled = d.poll("g1");
    assert_eq!(
        polled.iter().map(|m| m.data.clone()).collect::<Vec<_>>(),
        vec![cid_n(1)],
        "PBA-L6b-037: only the well-formed CID is surfaced by Poll"
    );
    let (_, _, shared) = d.status("g1");
    assert_eq!(shared, vec![cid_n(1)]);
}

// PBA-L6b-020: the shared set is paged over IPC, with its total size, and a page is clamped.
#[test]
fn pba_l6b_020_shared_files_are_paged_over_ipc() {
    let mut d = daemon();
    d.join("g1").unwrap();
    for i in 0..1500 {
        d.share_file("g1", &cid_n(i)).unwrap();
    }
    let (_, _, all) = d.status("g1");
    let page = |d: &mut ClusterDaemon<InProcessTransport>, offset, limit| match handle_request(
        d,
        Request::SharedFiles {
            group: "g1".into(),
            offset,
            limit,
        },
    ) {
        Response::SharedFiles {
            files,
            offset: o,
            total,
        } => {
            assert_eq!(o, offset);
            (files, total)
        }
        other => panic!("expected SharedFiles, got {other:?}"),
    };
    let (p0, total) = page(&mut d, 0, None);
    assert_eq!(total, 1500);
    assert_eq!(
        p0.len(),
        MAX_SHARED_FILES_PAGE,
        "the default page is the page maximum"
    );
    assert_eq!(p0[..], all[..MAX_SHARED_FILES_PAGE]);
    let (p1, _) = page(&mut d, MAX_SHARED_FILES_PAGE, Some(10_000));
    assert_eq!(p1[..], all[MAX_SHARED_FILES_PAGE..], "the rest, clamped");
    let (p2, _) = page(&mut d, 10, Some(5));
    assert_eq!(p2[..], all[10..15]);
    let (p3, _) = page(&mut d, 1500, Some(5));
    assert!(p3.is_empty());
    // Unknown group: empty, total 0.
    assert_eq!(d.shared_files_page("nope", 0, 10), (Vec::new(), 0));
    // The JSON contract: offset/limit are optional.
    let req: Request =
        serde_json::from_str(r#"{"op":"sharedFiles","group":"g1"}"#).expect("parses");
    assert!(matches!(
        req,
        Request::SharedFiles {
            offset: 0,
            limit: None,
            ..
        }
    ));
}

// R2 variant of PBA-L6b-022 (stat-then-read by path): secret files are read through one no-follow
// open with checks on the fd and a size cap.
#[cfg(unix)]
#[test]
fn pba_r2_read_secret_file_refuses_symlinks_fifos_and_oversize() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("pba-r2-secret-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
    let good = p("good");
    std::fs::write(&good, "deadbeef\n").unwrap();
    std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        crate::read_secret_file(&good).unwrap().as_str(),
        "deadbeef\n"
    );

    // A symlink to a perfectly good 0600 file is refused (the path could be swapped after a stat).
    std::os::unix::fs::symlink(&good, p("link")).unwrap();
    assert!(
        crate::read_secret_file(&p("link")).is_err(),
        "symlink refused"
    );

    // A FIFO is refused promptly (no blocking open, no unbounded read).
    assert!(std::process::Command::new("mkfifo")
        .arg(p("fifo"))
        .status()
        .unwrap()
        .success());
    std::fs::set_permissions(p("fifo"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let t0 = std::time::Instant::now();
    assert!(crate::read_secret_file(&p("fifo")).is_err(), "FIFO refused");
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(2),
        "without blocking"
    );

    // Oversize is refused; exactly the cap is fine.
    let big = p("big");
    std::fs::write(&big, vec![b'a'; crate::MAX_SECRET_FILE as usize + 1]).unwrap();
    std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(crate::read_secret_file(&big).is_err(), "oversize refused");
    std::fs::write(&big, vec![b'a'; crate::MAX_SECRET_FILE as usize]).unwrap();
    assert!(
        crate::read_secret_file(&big).is_ok(),
        "exactly the cap is accepted"
    );

    // Mode is checked on the fd.
    std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(
        crate::read_secret_file(&good).is_err(),
        "group-readable refused"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
