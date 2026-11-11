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

/// The relay tests run one at a time. Under a parallel test run on macOS loopback, a DCUtR hole
/// punch (three simultaneous-open attempts within a few ms) sometimes loses its race to CPU
/// contention and libp2p gives up; the punch itself is not what most of these tests measure, and
/// the one that does (`dcutr_upgrades_…`) needs the machine to itself to be deterministic.
static RELAY_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    RELAY_TESTS.lock().unwrap_or_else(|e| e.into_inner())
}

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
    let circuit: Multiaddr =
        format!("/ip4/10.0.0.1/tcp/4001/p2p/{relay_id}/p2p-circuit/p2p/{target}")
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

    assert!(parse_relay_addrs("")
        .expect("empty is no relays")
        .is_empty());
    assert!(
        parse_relay_addrs("/ip4/10.0.0.1/tcp/4001").is_err(),
        "no peer id"
    );
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
    assert!(
        !json.contains("link"),
        "older clients see the same line: {json}"
    );
    let v = crate::ipc::PeerView {
        link: Some("relayed".into()),
        ..v
    };
    assert!(serde_json::to_string(&v)
        .expect("json")
        .contains("\"link\":\"relayed\""));
}

#[test]
fn a_member_reserves_on_an_allowed_relay_and_offers_the_circuit_in_its_seed() {
    let _serial = serial();
    let (r, raddr) = relay(0x60, &[0x61]);
    let a = member(0x61, "g-relay-seed", vec![raddr]);
    let seed = wait_circuit_seed(&a, Duration::from_secs(10))
        .expect("the member's seed offers a relayed address once its reservation is accepted");
    assert_eq!(
        bootstrap_peer_id(&seed),
        Some(peer_of(0x61)),
        "the circuit names the member"
    );
    assert!(r.stats().reservations_accepted >= 1);
    assert_eq!(a.nat_stats().reservations_accepted, 1);
}

#[test]
fn a_relay_refuses_a_member_outside_its_allow_list() {
    let _serial = serial();
    let (r, raddr) = relay(0x62, &[0x63]);
    let stranger = member(0x64, "g-relay-deny", vec![raddr]);
    assert!(
        wait_circuit_seed(&stranger, Duration::from_secs(4)).is_none(),
        "no reservation for a peer the relay does not allow"
    );
    let s = r.stats();
    assert_eq!(s.reservations_accepted, 0);
    assert!(
        !s.connected.contains(&peer_of(0x64)),
        "the connection itself is refused"
    );
}

#[test]
fn two_members_mesh_through_a_relay_and_the_relay_is_never_a_mesh_peer() {
    let _serial = serial();
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

    assert!(
        wait_connected(&a, &addr_b, Duration::from_secs(15)),
        "A meshed with B"
    );
    assert!(
        wait_connected(&b, &addr_a, Duration::from_secs(5)),
        "B meshed with A"
    );
    assert!(
        r.stats().circuits_accepted >= 1,
        "the first connection went through the relay"
    );
    assert!(
        a.links().contains_key(&addr_b),
        "A reports a link kind for B"
    );

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
    let _serial = serial();
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

#[test]
fn dcutr_upgrades_a_relayed_link_to_direct_when_a_direct_path_exists() {
    // Loopback has no NAT, so a hole punch has a direct path: this proves the DCUtR wiring
    // (address candidates from the relay connection on the listen port, the group prologue on the
    // punched connection, admission and link tracking across both connections). Whether it gets
    // through a real NAT is the netns spike's question.
    //
    // libp2p makes ONE punch per relayed connection (three simultaneous-open attempts a few ms
    // apart). On a loaded macOS runner that race is sometimes lost (about 1 run in 14 of the full
    // suite on the Mac, 2026-11-11), and the pair then correctly stays relayed. So the test gives
    // the punch up to three fresh pairs; every attempt must still mesh (relayed or direct), and
    // one must go direct. Re-punching a pair that stayed relayed is a MESH-3 follow-up.
    let _serial = serial();
    const GROUP: &str = "g-relay-dcutr";
    let direct = |t: &Libp2pTransport, peer: &str| t.links().get(peer) == Some(&LinkKind::Direct);
    for attempt in 0u8..3 {
        let (_r, raddr) = relay(0x70, &[0x71 + 2 * attempt, 0x72 + 2 * attempt]);
        let mut a = member(0x71 + 2 * attempt, GROUP, vec![raddr.clone()]);
        let mut b = member(0x72 + 2 * attempt, GROUP, vec![raddr]);
        let addr_a = a.self_address().to_string();
        let addr_b = b.self_address().to_string();
        a.authorize(&addr_b);
        b.authorize(&addr_a);
        let b_circuit = wait_circuit_seed(&b, Duration::from_secs(10)).expect("B reserved");
        a.add_peers(&[b_circuit.to_string()]).expect("seeded");
        assert!(
            wait_connected(&a, &addr_b, Duration::from_secs(15)),
            "attempt {attempt}: A and B mesh through the relay"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline
            && !(direct(&a, &addr_b) && direct(&b, &addr_a))
            && a.nat_stats().hole_punch_failed + b.nat_stats().hole_punch_failed == 0
        {
            sleep(Duration::from_millis(50));
        }
        if direct(&a, &addr_b) && direct(&b, &addr_a) {
            assert!(a.nat_stats().hole_punch_ok + b.nat_stats().hole_punch_ok >= 1);
            assert_eq!(a.link(&addr_b), Some("direct"));
            return;
        }
        // The punch failed: the pair must still be meshed, over the relay.
        assert!(
            a.connected().contains(&addr_b),
            "attempt {attempt}: still meshed after a failed punch"
        );
    }
    panic!("no hole punch succeeded in three attempts on loopback");
}

/// Found in the netns spike (cone NAT, run 1): a seed lists the member's LAN address before its
/// relayed address. Each address was dialed on its own, and libp2p refuses a second dial to a peer
/// while one is in flight, so the relayed address was never tried and the members never met.
#[test]
fn a_seed_whose_first_address_is_dead_still_reaches_the_peer() {
    const GROUP: &str = "g-dead-first";
    let mut a = member(0x74, GROUP, vec![]);
    let mut b = member(0x75, GROUP, vec![]);
    let addr_a = a.self_address().to_string();
    let addr_b = b.self_address().to_string();
    a.authorize(&addr_b);
    b.authorize(&addr_a);
    let b_live = b
        .seed_multiaddrs()
        .ok()
        .and_then(|v| v.into_iter().next())
        .or_else(|| {
            sleep(Duration::from_millis(300));
            b.seed_multiaddrs().ok().and_then(|v| v.into_iter().next())
        })
        .expect("B listens");
    let b_id = bootstrap_peer_id(&b_live).expect("seed names B");
    // Port 1 on loopback: nothing listens there, the dial fails.
    let dead: Multiaddr = format!("/ip4/127.0.0.1/tcp/1/p2p/{b_id}")
        .parse()
        .expect("addr");
    a.add_peers(&[dead.to_string(), b_live.to_string()])
        .expect("seeded");
    assert!(
        wait_connected(&a, &addr_b, Duration::from_secs(12)),
        "the live address is dialed even though the dead one comes first"
    );
}

#[test]
fn a_redial_plan_dials_every_address_of_a_peer_in_one_attempt() {
    let p1 = peer_of(0x76);
    let p2 = peer_of(0x77);
    let addrs: Vec<Multiaddr> = [
        format!("/ip4/192.168.20.2/tcp/4201/p2p/{p1}"),
        format!("/ip4/10.99.0.9/tcp/4201/p2p/{p2}"),
        format!(
            "/ip4/10.99.0.1/tcp/4100/p2p/{}/p2p-circuit/p2p/{p1}",
            peer_of(0x78)
        ),
        "/ip4/10.0.0.3/tcp/4211".to_string(),
    ]
    .iter()
    .map(|a| a.parse().expect("multiaddr"))
    .collect();
    let plan = redial_plan(&addrs);
    let ids: Vec<Option<PeerId>> = plan.iter().map(|d| d.get_peer_id()).collect();
    assert_eq!(
        ids,
        vec![Some(p1), Some(p2), None],
        "one attempt per peer, in first-seen order"
    );
    let first = format!("{:?}", plan[0]);
    assert!(
        first.contains("192.168.20.2") && first.contains("p2p-circuit"),
        "{first}"
    );
    assert!(plan
        .iter()
        .all(|d| format!("{d:?}").contains("port_use: New")));
}
