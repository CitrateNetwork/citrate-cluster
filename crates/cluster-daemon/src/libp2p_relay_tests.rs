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

/// V60 MESH-3: a group swarm with relays has the group key's PeerId, not the device's.
fn gpeer(seed: u8, group: &str) -> PeerId {
    crate::group_key::derive_group_keypair(&test_secret(seed), group)
        .expect("derive")
        .public()
        .to_peer_id()
}

/// A relay allowing the group swarms named by `(device seed, group)`.
fn relay(seed: u8, allowed: &[(u8, &str)]) -> (RelayNode, Multiaddr) {
    let allowed: Vec<PeerId> = allowed.iter().map(|(s, g)| gpeer(*s, g)).collect();
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
    let (r, raddr) = relay(0x60, &[(0x61, "g-relay-seed")]);
    let a = member(0x61, "g-relay-seed", vec![raddr]);
    let seed = wait_circuit_seed(&a, Duration::from_secs(10))
        .expect("the member's seed offers a relayed address once its reservation is accepted");
    assert_eq!(
        bootstrap_peer_id(&seed),
        Some(gpeer(0x61, "g-relay-seed")),
        "the circuit names the member"
    );
    assert!(r.stats().reservations_accepted >= 1);
    assert_eq!(a.nat_stats().reservations_accepted, 1);
}

#[test]
fn a_relay_refuses_a_member_outside_its_allow_list() {
    let _serial = serial();
    let (r, raddr) = relay(0x62, &[(0x63, "g-relay-deny")]);
    let stranger = member(0x64, "g-relay-deny", vec![raddr]);
    assert!(
        wait_circuit_seed(&stranger, Duration::from_secs(4)).is_none(),
        "no reservation for a peer the relay does not allow"
    );
    let s = r.stats();
    assert_eq!(s.reservations_accepted, 0);
    assert!(
        !s.connected.contains(&gpeer(0x64, "g-relay-deny")),
        "the connection itself is refused"
    );
}

#[test]
fn two_members_mesh_through_a_relay_and_the_relay_is_never_a_mesh_peer() {
    let _serial = serial();
    const GROUP: &str = "g-relay-mesh";
    let (r, raddr) = relay(0x65, &[(0x66, GROUP), (0x67, GROUP)]);
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
    assert!(s.connected.contains(&gpeer(0x66, GROUP)) && s.connected.contains(&gpeer(0x67, GROUP)));
}

#[test]
fn admission_still_decides_a_relayed_connection() {
    let _serial = serial();
    const GROUP: &str = "g-relay-admission";
    let (_r, raddr) = relay(0x68, &[(0x69, GROUP), (0x6A, GROUP)]);
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
        let (_r, raddr) = relay(
            0x70,
            &[(0x71 + 2 * attempt, GROUP), (0x72 + 2 * attempt, GROUP)],
        );
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

// ---------------------------------------------------------------------------------------------
// V60 MESH-3: multi-group circuit routing. Every group swarm of one device used the device's
// PeerId, and a relay routes a circuit to the first connection holding a reservation for that
// PeerId, so a circuit for group B could land on group A's swarm (and fail its Noise prologue).
// With relays configured, each group swarm now has its own PeerId (a key derived from the device
// key and the group), bound to the device address by a device-key signature carried in identify.
// ---------------------------------------------------------------------------------------------

fn member_secret(secret: [u8; 32], group: &str, relays: Vec<Multiaddr>) -> Libp2pTransport {
    Libp2pTransport::new(Libp2pConfig {
        secret,
        listen: loopback(),
        group_id: group.to_string(),
        bootstrap: vec![],
        mdns: false,
        relays,
    })
    .expect("member transport starts")
}

#[test]
fn group_swarms_with_relays_have_their_own_peer_ids_and_the_device_address() {
    let _serial = serial();
    let (_r, raddr) = relay(0x80, &[]);
    let x1 = member_secret(test_secret(0x81), "g-gk-one", vec![raddr.clone()]);
    let x2 = member_secret(test_secret(0x81), "g-gk-two", vec![raddr]);
    assert_ne!(x1.peer_id(), x2.peer_id(), "one PeerId per group swarm");
    assert_ne!(x1.peer_id(), peer_of(0x81), "not the device PeerId");
    assert_eq!(
        x1.self_address(),
        x2.self_address(),
        "both act for the same device"
    );
    // Without relays nothing changes: the swarm is the device PeerId (seeds and soak kits stay valid).
    let plain = member_secret(test_secret(0x81), "g-gk-one", vec![]);
    assert_eq!(plain.peer_id(), peer_of(0x81));
}

#[test]
fn a_group_key_binding_verifies_only_for_its_group_and_its_peer() {
    use crate::group_key::{bind, derive_group_keypair, verify};
    let device = test_secret(0x82);
    let kp = derive_group_keypair(&device, "g-bind").expect("derive");
    let peer = kp.public().to_peer_id();
    let agent = bind(&device, "g-bind", &peer).expect("sign");
    let (device_addr, _) = Libp2pTransport::identity_from_secret(device).expect("identity");
    assert_eq!(verify(&agent, "g-bind", &peer), Some(device_addr.clone()));
    // A signature over another message recovers some other key, never the device's.
    assert_ne!(
        verify(&agent, "g-other", &peer),
        Some(device_addr.clone()),
        "another group"
    );
    let other = derive_group_keypair(&device, "g-other").expect("derive");
    assert_ne!(
        verify(&agent, "g-bind", &other.public().to_peer_id()),
        Some(device_addr.clone()),
        "another peer"
    );
    assert_eq!(
        verify("rust-libp2p/0.47.0", "g-bind", &peer),
        None,
        "no binding"
    );
    assert_ne!(
        verify(&agent.replace('a', "b"), "g-bind", &peer),
        Some(device_addr.clone()),
        "tampered"
    );
    // Deterministic: the same device and group give the same key (seeds stay valid across restarts).
    assert_eq!(
        derive_group_keypair(&device, "g-bind")
            .expect("derive")
            .public()
            .to_peer_id(),
        peer
    );
}

#[test]
fn a_relay_routes_each_groups_circuit_to_that_groups_swarm() {
    const G1: &str = "g-route-one";
    const G2: &str = "g-route-two";
    let _serial = serial();
    let (_r, raddr) = relay(0x83, &[(0x84, G1), (0x84, G2), (0x85, G1), (0x85, G2)]);
    // Device X serves both groups; device Y serves both groups. Each pair meets ONLY via X's
    // relayed addresses.
    let mut x: Vec<Libp2pTransport> = [G1, G2]
        .iter()
        .map(|g| member_secret(test_secret(0x84), g, vec![raddr.clone()]))
        .collect();
    let mut y: Vec<Libp2pTransport> = [G1, G2]
        .iter()
        .map(|g| member_secret(test_secret(0x85), g, vec![raddr.clone()]))
        .collect();
    let (xa, ya) = (
        x[0].self_address().to_string(),
        y[0].self_address().to_string(),
    );
    for t in x.iter_mut() {
        t.authorize(&ya);
    }
    for t in y.iter_mut() {
        t.authorize(&xa);
    }
    for i in 0..2 {
        let seed = wait_circuit_seed(&x[i], Duration::from_secs(10)).expect("X reserved");
        y[i].add_peers(&[seed.to_string()]).expect("seeded");
    }
    for i in 0..2 {
        assert!(
            wait_connected(&y[i], &xa, Duration::from_secs(15)),
            "group {i}: Y meets X through the relay, on that group's swarm"
        );
        assert!(
            wait_connected(&x[i], &ya, Duration::from_secs(5)),
            "group {i}: X admits Y"
        );
    }
}

#[test]
fn a_binding_signed_by_a_device_outside_the_group_is_refused() {
    const GROUP: &str = "g-gk-refuse";
    let _serial = serial();
    let (_r, raddr) = relay(0x86, &[(0x87, GROUP), (0x88, GROUP)]);
    let host = member_secret(test_secret(0x87), GROUP, vec![raddr.clone()]);
    let mut stranger = member_secret(test_secret(0x88), GROUP, vec![raddr]);
    stranger.authorize(host.self_address());
    let seed = wait_circuit_seed(&host, Duration::from_secs(10)).expect("host reserved");
    stranger.add_peers(&[seed.to_string()]).expect("seeded");
    let s_addr = stranger.self_address().to_string();
    assert!(
        !wait_connected(&host, &s_addr, Duration::from_secs(4)),
        "a valid binding by a device the group does not authorize admits nothing"
    );
}
