//! cluster-core tests — the admission derivation, the membership lifecycle, and the transport-driven
//! connection lifecycle. Together they cover the `admitted ⊆ allowed` + `connected ⊆ admitted`
//! invariants by example; `formal/ClusterAdmission.tla` covers them exhaustively.

use super::*;

const A: &str = "00000000000000000000000000000000000000aa";
const B: &str = "00000000000000000000000000000000000000bb";
const C: &str = "00000000000000000000000000000000000000cc";

fn roster(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(a, r)| (a.to_string(), r.to_string()))
        .collect()
}

// ---- allowed_peers derivation (S4.1) ----

#[test]
fn empty_roster_yields_no_peers() {
    assert!(allowed_peers(&[]).is_empty());
}

#[test]
fn addresses_are_canonicalized_lowercase_no_prefix() {
    let roster = vec![format!("0x{}", A.to_uppercase()), A.to_string()];
    assert_eq!(allowed_peers(&roster), vec![A.to_string()]);
}

#[test]
fn duplicates_removed_and_sorted() {
    let r = vec![
        B.to_string(),
        A.to_string(),
        B.to_string(),
        format!("0x{A}"),
    ];
    assert_eq!(allowed_peers(&r), vec![A.to_string(), B.to_string()]);
}

#[test]
fn non_addresses_are_dropped() {
    let r = vec![
        A.to_string(),
        "not-an-address".into(),
        "0x1234".into(),
        "".into(),
        format!("{A}zz"),
    ];
    assert_eq!(allowed_peers(&r), vec![A.to_string()]);
}

#[test]
fn two_nodes_derive_the_identical_set_regardless_of_order() {
    let n1 = allowed_peers(&[format!("0x{A}"), B.to_string()]);
    let n2 = allowed_peers(&[B.to_uppercase(), A.to_string()]);
    assert_eq!(n1, n2);
}

// ---- admission gate + membership lifecycle (S4.2) ----

#[test]
fn allowed_set_is_role_gated_at_member() {
    let allowed = allowed_set(&roster(&[(A, "owner"), (B, "member"), (C, "guest")]));
    assert!(allowed.contains(A) && allowed.contains(B));
    assert!(
        !allowed.contains(C),
        "a guest is in the group but not the mesh"
    );
}

#[test]
fn join_admits_a_member_rejects_guest_and_stranger() {
    let mut m = ClusterMembership::new(&roster(&[(A, "member"), (C, "guest")]));
    assert!(m.join(A, "member"));
    assert!(!m.join(C, "guest"));
    assert!(!m.join(B, "member"));
    assert!(m.is_admitted(A) && !m.is_admitted(C) && !m.is_admitted(B));
    assert!(m.invariant_holds());
}

#[test]
fn a_below_member_role_is_never_admitted_even_if_in_roster() {
    let mut m = ClusterMembership::new(&roster(&[(A, "owner")]));
    assert!(
        !m.join(A, "guest"),
        "presented role gates admission, fail closed"
    );
    assert!(m.admitted().is_empty());
}

#[test]
fn leave_removes_and_is_idempotent() {
    let mut m = ClusterMembership::new(&roster(&[(A, "member")]));
    assert!(m.join(A, "member"));
    m.leave(A);
    m.leave(A);
    assert!(!m.is_admitted(A) && m.admitted().is_empty());
}

#[test]
fn reconcile_evicts_an_offboarded_member_in_one_step() {
    let mut m = ClusterMembership::new(&roster(&[(A, "member"), (B, "member")]));
    assert!(m.join(A, "member") && m.join(B, "member"));
    let evicted = m.reconcile(&roster(&[(A, "member")]));
    assert_eq!(evicted, vec![B.to_string()]);
    assert!(m.is_admitted(A) && !m.is_admitted(B) && m.invariant_holds());
}

#[test]
fn reconcile_evicts_on_a_role_drop_below_member() {
    let mut m = ClusterMembership::new(&roster(&[(A, "admin")]));
    assert!(m.join(A, "admin"));
    let evicted = m.reconcile(&roster(&[(A, "guest")]));
    assert_eq!(evicted, vec![A.to_string()]);
    assert!(!m.is_admitted(A) && m.invariant_holds());
}

#[test]
fn invariant_holds_across_join_reconcile_rejoin() {
    let mut m = ClusterMembership::new(&roster(&[(A, "member"), (B, "member")]));
    m.join(A, "member");
    m.join(B, "member");
    assert!(m.invariant_holds());
    m.reconcile(&roster(&[(A, "member")]));
    assert!(m.invariant_holds());
    assert!(!m.join(B, "member"));
    m.reconcile(&roster(&[(A, "member"), (B, "member")]));
    assert!(m.join(B, "member") && m.invariant_holds());
}

// ---- transport-driven connection lifecycle (S4.3) ----

struct FakeTransport {
    connected: BTreeSet<String>,
}
impl FakeTransport {
    fn new() -> Self {
        FakeTransport {
            connected: BTreeSet::new(),
        }
    }
}
impl ClusterTransport for FakeTransport {
    fn dial(&mut self, peer: &str) {
        self.connected.insert(peer.to_string());
    }
    fn disconnect(&mut self, peer: &str) {
        self.connected.remove(peer);
    }
    fn connected(&self) -> Vec<String> {
        self.connected.iter().cloned().collect()
    }
}

// CL-B-005: a transport that admits on the wire (libp2p `identify`) records `connected` without ever
// calling `join`, leaving `admitted` empty and the predicates lying. `sync_admitted_from_wire`
// reconciles `admitted` from `connected ∩ allowed` — truthful, and it can NEVER admit a peer the
// roster does not allow (the intersection preserves `admitted ⊆ allowed`).
#[test]
fn sync_admitted_from_wire_reflects_connected_and_preserves_the_invariant() {
    let mut s = ClusterSession::new(
        &roster(&[(A, "member"), (B, "member")]),
        FakeTransport::new(),
    );
    // Simulate the libp2p path: the transport meshes an allowed peer WITHOUT a `join` call, and even
    // meshes a stranger (C, not in the roster) — as could happen in a connect→identify race window.
    s.transport_mut().dial(A);
    s.transport_mut().dial(C);
    // Before syncing, admission is a lie: A is meshed but not admitted.
    assert!(!s.membership().is_admitted(A));
    assert!(!s.wire_tracks_admitted(), "connected ⊄ admitted before the sync");

    s.sync_admitted_from_wire();
    assert!(s.membership().is_admitted(A), "allowed, connected peer is admitted");
    assert!(
        !s.membership().is_admitted(C),
        "a non-allowed peer is NEVER admitted, even if the wire connected it"
    );
    assert!(
        s.membership().invariant_holds(),
        "sync intersects with allowed → admitted ⊆ allowed"
    );
}

#[test]
fn admitting_dials_rejecting_does_not() {
    let mut s = ClusterSession::new(
        &roster(&[(A, "member"), (C, "guest")]),
        FakeTransport::new(),
    );
    assert!(s.join(A, "member"));
    assert!(!s.join(C, "guest"));
    assert!(!s.join(B, "member"));
    assert_eq!(s.transport().connected(), vec![A.to_string()]);
    assert!(s.wire_tracks_admitted());
}

#[test]
fn leaving_disconnects() {
    let mut s = ClusterSession::new(&roster(&[(A, "member")]), FakeTransport::new());
    s.join(A, "member");
    s.leave(A);
    assert!(s.transport().connected().is_empty() && s.wire_tracks_admitted());
}

#[test]
fn offboard_reconcile_tears_down_the_evicted_wire_in_one_step() {
    let mut s = ClusterSession::new(
        &roster(&[(A, "member"), (B, "member")]),
        FakeTransport::new(),
    );
    s.join(A, "member");
    s.join(B, "member");
    let evicted = s.reconcile(&roster(&[(A, "member")]));
    assert_eq!(evicted, vec![B.to_string()]);
    assert_eq!(s.transport().connected(), vec![A.to_string()]);
    assert!(s.wire_tracks_admitted());
}

#[test]
fn the_wire_never_contains_an_unadmitted_peer_across_a_sequence() {
    let mut s = ClusterSession::new(
        &roster(&[(A, "admin"), (B, "member")]),
        FakeTransport::new(),
    );
    s.join(A, "admin");
    s.join(B, "member");
    s.reconcile(&roster(&[(A, "guest")]));
    assert!(s.transport().connected().is_empty());
    assert!(s.wire_tracks_admitted() && s.membership().admitted().is_empty());
}
