//! CL-S1 gate tests: two real libp2p transports over loopback form a Noise + gossipsub mesh and
//! exchange a message on a shared group topic; an unauthorized inbound peer is refused on the wire.
//! Modeled on the compute-pool transport's two-node loopback tests (TCP on 127.0.0.1:0).

use std::thread::sleep;
use std::time::{Duration, Instant};

use super::*;
use cluster_core::ClusterTransport;

/// A deterministic, valid secp256k1 secret from a seed byte (never a production path).
fn test_secret(seed: u8) -> [u8; 32] {
    let mut b = [seed; 32];
    b[0] = seed | 0x01; // keep the scalar non-zero / in range
    b
}

fn loopback() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().expect("loopback multiaddr")
}

fn transport(seed: u8, group: &str, bootstrap: Vec<Multiaddr>) -> Libp2pTransport {
    Libp2pTransport::new(Libp2pConfig {
        secret: test_secret(seed),
        listen: loopback(),
        group_id: group.to_string(),
        bootstrap,
    })
    .expect("transport starts")
}

/// Poll a transport's concrete listen addr (port 0 is resolved asynchronously).
fn wait_listener(t: &Libp2pTransport) -> Multiaddr {
    for _ in 0..100 {
        if let Ok(addrs) = t.listeners() {
            if let Some(a) = addrs.into_iter().next() {
                return a;
            }
        }
        sleep(Duration::from_millis(20));
    }
    panic!("listener never came up");
}

#[test]
fn self_address_is_derived_from_the_secp256k1_seed() {
    let t = transport(0x11, "g-derive", vec![]);
    let addr = t.self_address().to_string();
    assert_eq!(addr.len(), 40, "canonical 20-byte hex address");
    assert!(addr.bytes().all(|b| b.is_ascii_hexdigit()));
    // Deterministic: same seed → same address.
    let t2 = transport(0x11, "g-derive", vec![]);
    assert_eq!(t2.self_address(), addr);
}

#[test]
fn two_nodes_form_mesh_and_exchange_a_group_message() {
    const GROUP: &str = "group-cross-machine";

    // No bootstrap yet — we authorize BEFORE connecting (the real flow: cluster-core sets the roster,
    // then the mesh dials). Admission is evaluated at the identify handshake, so a peer must be in the
    // authorized set before its connection completes or it is dropped (and would have to redial).
    let mut a = transport(0x0A, GROUP, vec![]);
    let a_listen = wait_listener(&a);
    let mut b = transport(0x0B, GROUP, vec![]);
    let _ = wait_listener(&b);

    let addr_a = a.self_address().to_string();
    let addr_b = b.self_address().to_string();
    assert_ne!(addr_a, addr_b);

    // Both admit each other first (what cluster-core drives via `dial` when the roster authorizes).
    a.dial(&addr_b);
    b.dial(&addr_a);

    // Now connect: B dials A's listener.
    b.dial_multiaddr(a_listen).expect("B dials A");

    // Let the mesh form (connect → identify → gossipsub GRAFT).
    sleep(Duration::from_millis(1_500));

    // A publishes to the group topic; poll B's inbox (retry publish to ride out InsufficientPeers
    // before the mesh has fully formed).
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut got = None;
    while Instant::now() < deadline {
        a.publish(&addr_a, "bafycidshared");
        sleep(Duration::from_millis(250));
        let msgs = b.drain();
        if let Some(m) = msgs.into_iter().next() {
            got = Some(m);
            break;
        }
    }

    let msg = got.expect("B received A's gossipsub message within the deadline");
    assert_eq!(msg.data, "bafycidshared");
    assert_eq!(
        msg.from, addr_a,
        "sender resolved from the authenticated secp256k1 key"
    );

    // The wire tracks admission: A sees B connected and vice versa. POLL for it — the
    // ConnectionEstablished/identify events that populate `connected()` are async and can lag the
    // first delivered gossipsub message by a beat (this was the source of the earlier flake).
    let conn_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < conn_deadline {
        if a.connected().contains(&addr_b) && b.connected().contains(&addr_a) {
            break;
        }
        sleep(Duration::from_millis(100));
    }
    assert!(a.connected().contains(&addr_b), "A meshed with B");
    assert!(b.connected().contains(&addr_a), "B meshed with A");
}

// CL-B-005 regression: on the real libp2p path admission is decided on the wire (at `identify`), not
// through `ClusterSession::join`, so `admitted` stays empty and `wire_tracks_admitted()` / `is_admitted`
// lie while peers are meshed. Driving `sync_admitted_from_wire()` (what the daemon does before every
// read) makes them truthful WITHOUT weakening the invariant `admitted ⊆ allowed`.
#[test]
fn wire_admission_is_reflected_into_the_membership_predicates() {
    use cluster_core::ClusterSession;
    const GROUP: &str = "group-invariant";

    let mut ta = transport(0x2A, GROUP, vec![]);
    let a_listen = wait_listener(&ta);
    let mut tb = transport(0x2B, GROUP, vec![]);
    let _ = wait_listener(&tb);
    let addr_a = ta.self_address().to_string();
    let addr_b = tb.self_address().to_string();
    assert_ne!(addr_a, addr_b);

    // Both authorize each other's address (what the daemon's set_roster does via `authorize`).
    ta.authorize(&addr_b);
    tb.authorize(&addr_a);
    // Connect: B dials A's listener.
    tb.dial_multiaddr(a_listen).expect("B dials A");

    let roster = vec![
        (addr_a.clone(), "member".to_string()),
        (addr_b.clone(), "member".to_string()),
    ];
    let mut sa = ClusterSession::new(&roster, ta);

    // Wait for the mesh to form (A sees B connected).
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if sa.transport().connected().contains(&addr_b) {
            break;
        }
        sleep(Duration::from_millis(100));
    }
    assert!(
        sa.transport().connected().contains(&addr_b),
        "the mesh must form (B connected to A)"
    );

    // The fix: reconcile admission from the wire, then the predicates are truthful.
    sa.sync_admitted_from_wire();
    assert!(
        sa.wire_tracks_admitted(),
        "wire_tracks_admitted() must be truthful once admission is synced from the wire"
    );
    assert!(
        sa.membership().is_admitted(&addr_b),
        "the connected, allowed peer is reported admitted"
    );
    assert!(
        sa.membership().invariant_holds(),
        "admitted ⊆ allowed still holds after syncing from the wire"
    );
}

#[test]
fn an_unauthorized_inbound_peer_is_refused_on_the_wire() {
    const GROUP: &str = "group-admission";

    // The host authorizes NOBODY (empty allowed set for this group).
    let mut host = transport(0x1C, GROUP, vec![]);
    let host_listen = wait_listener(&host);

    // A stranger dials in on the same topic but is not in the host's roster.
    let mut stranger = transport(0x1D, GROUP, vec![host_listen]);
    let _ = wait_listener(&stranger);
    let stranger_addr = stranger.self_address().to_string();

    // Give connect + identify time to run (the host resolves the stranger's address and drops it).
    sleep(Duration::from_millis(1_500));

    // The stranger publishes repeatedly; the host must NEVER surface the message (dropped on the wire
    // by disconnect-on-identify, and on receipt by the authorized-source check).
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        stranger.publish(&stranger_addr, "evil-cid");
        sleep(Duration::from_millis(250));
        assert!(
            host.drain().is_empty(),
            "an unauthorized peer's message must never be accepted"
        );
    }

    assert!(
        !host.connected().contains(&stranger_addr),
        "the unauthorized peer is dropped, never counted connected"
    );
}
