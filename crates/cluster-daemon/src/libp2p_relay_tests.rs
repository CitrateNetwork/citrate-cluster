//! V60 S0-NAT-SPIKE: circuit relay v2 + DCUtR on the cluster mesh.
//!
//! Loopback tests: a relay node and member swarms on 127.0.0.1. They prove the relay path works
//! (reservation, circuit, admission over the circuit, the relay never counted as a mesh peer, the
//! relay's allow list) and the pure helpers. Whether DCUtR gets through a real NAT is measured in the
//! netns spike (`scripts/nat-spike/`), not here: loopback has no NAT.

use std::thread::sleep;
use std::time::{Duration, Instant};

use super::*;
use crate::relay_node::RelayNode;
use cluster_core::ClusterTransport;

const CID: &str = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

fn test_secret(seed: u8) -> [u8; 32] {
    let mut b = [seed; 32];
    b[0] = seed | 0x01;
    b
}

fn peer_of(seed: u8) -> PeerId {
    let (_, p) = Libp2pTransport::identity_from_secret(test_secret(seed)).expect("identity");
    p.parse().expect("peer id")
}

fn loopback() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().expect("loopback multiaddr")
}

fn relay(seed: u8, allowed: &[u8]) -> (RelayNode, Multiaddr) {
    let allowed: Vec<PeerId> = allowed.iter().map(|s| peer_of(*s)).collect();
    let r = RelayNode::start(test_secret(seed), loopback(), &allowed).expect("relay starts");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(a) = r.listeners().expect("listeners").into_iter().next() {
            let id = r.peer_id();
            return (r, a.with(Protocol::P2p(id)));
        }
        sleep(Duration::from_millis(20));
    }
    panic!("relay listener never came up");
}

fn member(seed: u8, group: &str, relays: Vec<Multiaddr>) -> Libp2pTransport {
    Libp2pTransport::new(Libp2pConfig {
        secret: test_secret(seed),
        listen: loopback(),
        group_id: group.to_string(),
        bootstrap: vec![],
        mdns: false,
        relays,
    })
    .expect("member transport starts")
}

fn is_circuit(a: &Multiaddr) -> bool {
    a.iter().any(|p| matches!(p, Protocol::P2pCircuit))
}

/// Wait until the member's seed offers a relayed address (its reservation was accepted).
fn wait_circuit_seed(t: &Libp2pTransport, within: Duration) -> Option<Multiaddr> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(addrs) = t.seed_multiaddrs() {
            if let Some(a) = addrs.into_iter().find(is_circuit) {
                return Some(a);
            }
        }
        sleep(Duration::from_millis(50));
    }
    None
}

fn wait_connected(t: &Libp2pTransport, addr: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if t.connected().iter().any(|a| a == addr) {
            return true;
        }
        sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn the_target_of_a_circuit_address_is_its_last_peer_id() {
    let relay_id = peer_of(0x51);
    let target = peer_of(0x52);
    let circuit: Multiaddr = format!("/ip4/10.0.0.1/tcp/4001/p2p/{relay_id}/p2p-circuit/p2p/{target}")
        .parse()
        .expect("circuit multiaddr");
    assert_eq!(bootstrap_peer_id(&circuit), Some(target));
    // A seed carrying the circuit address names the target, not the relay: a node must not refuse
    // its own circuit address as "another peer", nor accept it as one.
    assert!(parse_peer_addrs(&[circuit.to_string()], &target).is_err());
    assert!(parse_peer_addrs(&[circuit.to_string()], &relay_id).is_ok());
}

#[test]
fn relay_addresses_must_name_the_relay_and_not_a_circuit() {
    let id = peer_of(0x53);
    let good = format!("/ip4/10.0.0.1/tcp/4001/p2p/{id}");
    let parsed = parse_relay_addrs(&good).expect("one relay");
    assert_eq!(parsed.len(), 1);
    assert_eq!(bootstrap_peer_id(&parsed[0]), Some(id));

    assert!(parse_relay_addrs("").expect("empty is no relays").is_empty());
    assert!(parse_relay_addrs("/ip4/10.0.0.1/tcp/4001").is_err(), "no peer id");
    assert!(
        parse_relay_addrs(&format!("{good}/p2p-circuit")).is_err(),
        "a circuit is not a relay"
    );
    assert!(parse_relay_addrs("not-a-multiaddr").is_err());
    let too_many = vec![good.clone(); MAX_RELAYS + 1].join(",");
    assert!(parse_relay_addrs(&too_many).is_err(), "bounded");
}

#[test]
fn a_connection_through_a_relay_is_reported_relayed() {
    let relay_id = peer_of(0x54);
    let direct: Multiaddr = "/ip4/10.0.0.2/tcp/4001".parse().expect("addr");
    let relayed: Multiaddr = format!("/ip4/10.0.0.1/tcp/4001/p2p/{relay_id}/p2p-circuit")
        .parse()
        .expect("addr");
    assert_eq!(link_of(&direct), LinkKind::Direct);
    assert_eq!(link_of(&relayed), LinkKind::Relayed);
    assert_eq!(LinkKind::Direct.as_str(), "direct");
    assert_eq!(LinkKind::Relayed.as_str(), "relayed");
}

#[test]
fn a_peer_view_without_a_link_serializes_as_before() {
    let v = crate::ipc::PeerView {
        address: "ab".repeat(20),
        online: false,
        member: None,
        link: None,
    };
    let json = serde_json::to_string(&v).expect("json");
    assert!(!json.contains("link"), "older clients see the same line: {json}");
    let v = crate::ipc::PeerView {
        link: Some("relayed".into()),
        ..v
    };
    assert!(serde_json::to_string(&v).expect("json").contains("\"link\":\"relayed\""));
}

#[test]
fn a_member_reserves_on_an_allowed_relay_and_offers_the_circuit_in_its_seed() {
    let (r, raddr) = relay(0x60, &[0x61]);
    let a = member(0x61, "g-relay-seed", vec![raddr]);
    let seed = wait_circuit_seed(&a, Duration::from_secs(10))
        .expect("the member's seed offers a relayed address once its reservation is accepted");
    assert_eq!(bootstrap_peer_id(&seed), Some(peer_of(0x61)), "the circuit names the member");
    assert!(r.stats().reservations_accepted >= 1);
    assert_eq!(a.nat_stats().reservations_accepted, 1);
}

#[test]
fn a_relay_refuses_a_member_outside_its_allow_list() {
    let (r, raddr) = relay(0x62, &[0x63]);
    let stranger = member(0x64, "g-relay-deny", vec![raddr]);
    assert!(
        wait_circuit_seed(&stranger, Duration::from_secs(4)).is_none(),
        "no reservation for a peer the relay does not allow"
    );
    let s = r.stats();
    assert_eq!(s.reservations_accepted, 0);
    assert!(!s.connected.contains(&peer_of(0x64)), "the connection itself is refused");
}

#[test]
fn two_members_mesh_through_a_relay_and_the_relay_is_never_a_mesh_peer() {
    const GROUP: &str = "g-relay-mesh";
    let (r, raddr) = relay(0x65, &[0x66, 0x67]);
    let mut a = member(0x66, GROUP, vec![raddr.clone()]);
    let mut b = member(0x67, GROUP, vec![raddr]);
    let addr_a = a.self_address().to_string();
    let addr_b = b.self_address().to_string();
    a.authorize(&addr_b);
    b.authorize(&addr_a);

    let b_circuit = wait_circuit_seed(&b, Duration::from_secs(10)).expect("B reserved");
    // A knows B ONLY by its relayed address.
    assert_eq!(a.add_peers(&[b_circuit.to_string()]).expect("seeded"), 1);

    assert!(wait_connected(&a, &addr_b, Duration::from_secs(15)), "A meshed with B");
    assert!(wait_connected(&b, &addr_a, Duration::from_secs(5)), "B meshed with A");
    assert!(r.stats().circuits_accepted >= 1, "the first connection went through the relay");
    assert!(a.links().contains_key(&addr_b), "A reports a link kind for B");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut got = None;
    while Instant::now() < deadline && got.is_none() {
        a.publish(&addr_a, CID);
        sleep(Duration::from_millis(250));
        got = b.drain().into_iter().next();
    }
    let m = got.expect("B received A's co-pin");
    assert_eq!((m.from.as_str(), m.data.as_str()), (addr_a.as_str(), CID));

    // The relay identified both members but is in neither's mesh, and stays connected past the
    // identify sweep (it is not dropped as an unadmitted peer, or the reservation would be lost).
    sleep(IDENTIFY_TIMEOUT + Duration::from_secs(1));
    assert_eq!(a.connected(), vec![addr_b.clone()]);
    assert_eq!(b.connected(), vec![addr_a.clone()]);
    let s = r.stats();
    assert!(s.connected.contains(&peer_of(0x66)) && s.connected.contains(&peer_of(0x67)));
}

#[test]
fn admission_still_decides_a_relayed_connection() {
    const GROUP: &str = "g-relay-admission";
    let (_r, raddr) = relay(0x68, &[0x69, 0x6A]);
    let a = member(0x69, GROUP, vec![raddr.clone()]);
    let mut stranger = member(0x6A, GROUP, vec![raddr]);
    let a_circuit = wait_circuit_seed(&a, Duration::from_secs(10)).expect("A reserved");
    // The stranger authorizes A and dials it through the relay; A authorizes nobody.
    stranger.authorize(a.self_address());
    stranger
        .add_peers(&[a_circuit.to_string()])
        .expect("seeded");
    let stranger_addr = stranger.self_address().to_string();
    assert!(
        !wait_connected(&a, &stranger_addr, Duration::from_secs(4)),
        "a peer outside the group is refused over the relay exactly as over TCP"
    );
}
