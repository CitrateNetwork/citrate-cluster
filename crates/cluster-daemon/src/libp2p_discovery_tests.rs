//! HUP-S8.4 mesh prerequisites, transport level: per-group swarms under one device identity on one
//! shared runtime, group seeds (link/QR), opt-in mDNS discovery, and the re-dial helpers.

use std::thread::sleep;
use std::time::{Duration, Instant};

use super::*;
use cluster_core::ClusterTransport;

fn secret(seed: u8) -> [u8; 32] {
    let mut b = [seed; 32];
    b[0] = seed | 0x01;
    b
}

fn cfg(seed: u8, group: &str, listen: &str, mdns: bool) -> Libp2pConfig {
    Libp2pConfig {
        secret: secret(seed),
        listen: listen.parse().expect("multiaddr"),
        group_id: group.to_string(),
        bootstrap: vec![],
        mdns,
    }
}

fn peer_of(seed: u8) -> PeerId {
    let (_, id) = Libp2pTransport::identity_from_secret(secret(seed)).expect("identity");
    id.parse().expect("peer id")
}

fn addr_of(seed: u8) -> String {
    Libp2pTransport::identity_from_secret(secret(seed))
        .expect("identity")
        .0
}

fn wait_seed(t: &Libp2pTransport) -> Vec<Multiaddr> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(v) = t.seed_multiaddrs() {
            if !v.is_empty() {
                return v;
            }
        }
        assert!(Instant::now() < deadline, "no seed address came up");
        sleep(Duration::from_millis(20));
    }
}

fn wait_for(what: &str, secs: u64, f: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        sleep(Duration::from_millis(100));
    }
}

fn tcp_port(a: &Multiaddr) -> Option<u16> {
    a.iter().find_map(|p| match p {
        Protocol::Tcp(port) => Some(port),
        _ => None,
    })
}

#[test]
fn group_listen_gives_each_group_a_stable_port_in_the_span() {
    let base: Multiaddr = "/ip4/0.0.0.0/tcp/4211".parse().expect("ma");
    let a1 = group_listen(&base, "group-alpha");
    let a2 = group_listen(&base, "group-alpha");
    let b = group_listen(&base, "group-beta");
    assert_eq!(a1, a2, "same group, same port across restarts");
    for p in [tcp_port(&a1), tcp_port(&b)] {
        let p = p.expect("tcp");
        assert!((4211..4211 + GROUP_PORT_SPAN).contains(&p), "{p}");
    }
    assert_ne!(tcp_port(&a1), tcp_port(&b), "two groups, two ports");
    assert!(a1.to_string().starts_with("/ip4/0.0.0.0/tcp/"));
    // Ephemeral stays ephemeral; a span past 65535 falls back to ephemeral.
    let eph: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().expect("ma");
    assert_eq!(group_listen(&eph, "group-alpha"), eph);
    let high: Multiaddr = "/ip4/127.0.0.1/tcp/65535".parse().expect("ma");
    let h = group_listen(&high, "group-alpha");
    let hp = tcp_port(&h).expect("tcp");
    assert!(hp == 65535 || hp == 0, "{hp}");
}

#[test]
fn the_mdns_flag_is_off_by_default_and_refuses_junk() {
    assert_eq!(parse_flag(None), Ok(false));
    assert_eq!(parse_flag(Some("")), Ok(false));
    assert_eq!(parse_flag(Some("0")), Ok(false));
    assert_eq!(parse_flag(Some("off")), Ok(false));
    assert_eq!(parse_flag(Some("1")), Ok(true));
    assert_eq!(parse_flag(Some(" TRUE ")), Ok(true));
    assert!(parse_flag(Some("yes please")).is_err());
}

#[test]
fn a_peer_id_resolves_to_the_address_of_its_key() {
    let id = peer_of(0x31);
    assert_eq!(address_from_peer_id(&id), Some(addr_of(0x31)));
    // A non-secp256k1 (hashed) peer id resolves to nothing.
    assert_eq!(address_from_peer_id(&PeerId::random()), None);
    let mut authorized = BTreeSet::new();
    assert!(!peer_authorized(&id, &authorized));
    authorized.insert(addr_of(0x31));
    assert!(peer_authorized(&id, &authorized));
}

#[test]
fn discovered_peers_are_bounded_and_forgotten_when_they_expire() {
    let mut d: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    let p = peer_of(0x41);
    let a = |port: u16| -> Multiaddr { format!("/ip4/10.0.0.2/tcp/{port}").parse().expect("ma") };
    assert!(remember_discovered(&mut d, p, a(1)));
    assert!(
        !remember_discovered(&mut d, p, a(1)),
        "known address: nothing new"
    );
    for port in 2..=(MAX_DISCOVERED_ADDRS as u16 + 2) {
        remember_discovered(&mut d, p, a(port));
    }
    let kept = &d[&p];
    assert_eq!(kept.len(), MAX_DISCOVERED_ADDRS);
    assert!(!kept.contains(&a(1)), "the oldest address made room");
    // Peer cap.
    let mut full: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    for _ in 0..MAX_DISCOVERED_PEERS {
        remember_discovered(&mut full, PeerId::random(), a(1));
    }
    assert!(
        !remember_discovered(&mut full, p, a(1)),
        "a new peer past the cap is ignored"
    );
    assert_eq!(full.len(), MAX_DISCOVERED_PEERS);
    // Expiry.
    let addrs = d[&p].clone();
    for x in &addrs {
        forget_discovered(&mut d, &p, x);
    }
    assert!(d.is_empty(), "a peer with no address left is forgotten");
}

#[test]
fn only_authorized_unconnected_discovered_peers_are_dialed() {
    let mut d: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    let (p1, p2, p3) = (peer_of(0x51), peer_of(0x52), peer_of(0x53));
    for p in [p1, p2, p3] {
        remember_discovered(&mut d, p, "/ip4/10.0.0.9/tcp/4211".parse().expect("ma"));
    }
    let authorized: BTreeSet<String> = [addr_of(0x51), addr_of(0x52)].into_iter().collect();
    let due = discovery_targets(&d, |p| *p == p2, |p| peer_authorized(p, &authorized));
    let ids: Vec<PeerId> = due.iter().map(|(p, _)| *p).collect();
    assert_eq!(ids, vec![p1], "p2 is connected, p3 is not authorized");
    // Bounded per tick.
    let mut many: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    for _ in 0..(MAX_REDIAL_PER_TICK + 5) {
        remember_discovered(
            &mut many,
            PeerId::random(),
            "/ip4/10.0.0.9/tcp/1".parse().expect("ma"),
        );
    }
    assert_eq!(
        discovery_targets(&many, |_| false, |_| true).len(),
        MAX_REDIAL_PER_TICK
    );
}

#[test]
fn seed_addresses_skip_unspecified_and_link_local_and_prefer_routable() {
    let me = peer_of(0x61);
    let ls = |v: &[&str]| -> Vec<Multiaddr> { v.iter().map(|s| s.parse().expect("ma")).collect() };
    let out = seed_addrs_from(
        &ls(&[
            "/ip4/0.0.0.0/tcp/4211",
            "/ip4/127.0.0.1/tcp/4211",
            "/ip4/192.168.1.20/tcp/4211",
            "/ip6/fe80::1/tcp/4211",
            "/ip6/2001:db8::7/tcp/4211",
        ]),
        &me,
    );
    let text: Vec<String> = out.iter().map(Multiaddr::to_string).collect();
    assert_eq!(
        text,
        vec![
            format!("/ip4/192.168.1.20/tcp/4211/p2p/{me}"),
            format!("/ip6/2001:db8::7/tcp/4211/p2p/{me}"),
        ]
    );
    // Loopback only when nothing else is listening.
    let lo = seed_addrs_from(&ls(&["/ip4/127.0.0.1/tcp/9"]), &me);
    assert_eq!(lo.len(), 1);
    assert!(lo[0].to_string().ends_with(&format!("/p2p/{me}")));
    // Capped.
    let many: Vec<Multiaddr> = (1..=20u16)
        .map(|i| format!("/ip4/10.0.0.{i}/tcp/1").parse().expect("ma"))
        .collect();
    assert_eq!(
        seed_addrs_from(&many, &me).len(),
        cluster_core::seed::MAX_SEED_ADDRS
    );
}

#[test]
fn seeded_addresses_must_name_another_peer() {
    let me = peer_of(0x71);
    let other = peer_of(0x72);
    let ok = format!("/ip4/10.0.0.3/tcp/4211/p2p/{other}");
    assert_eq!(
        parse_peer_addrs(std::slice::from_ref(&ok), &me).map(|v| v.len()),
        Ok(1)
    );
    assert!(parse_peer_addrs(&[], &me).is_err());
    assert!(parse_peer_addrs(&["/ip4/10.0.0.3/tcp/4211".into()], &me).is_err());
    assert!(parse_peer_addrs(&["not a multiaddr".into()], &me).is_err());
    let selfie = format!("/ip4/10.0.0.3/tcp/4211/p2p/{me}");
    assert!(
        parse_peer_addrs(&[ok, selfie], &me).is_err(),
        "all or nothing: one bad address refuses the lot"
    );
}

/// One device in two groups: two swarms, one PeerId, one shared runtime. A peer of group A reaches
/// the device only through A's swarm: dialing B's swarm fails the Noise handshake (the prologue is
/// the group id), so it is never counted in B even though it is authorized there by address.
#[test]
fn one_device_two_groups_two_swarms_with_isolated_admission() {
    let rt = Arc::new(swarm_runtime().expect("runtime"));
    let lo = "/ip4/127.0.0.1/tcp/0";
    let mut xa =
        Libp2pTransport::new_on(cfg(0x81, "grp-a", lo, false), Arc::clone(&rt)).expect("x in a");
    let mut xb =
        Libp2pTransport::new_on(cfg(0x81, "grp-b", lo, false), Arc::clone(&rt)).expect("x in b");
    assert_eq!(xa.self_address(), xb.self_address(), "one device identity");
    let mut ya = Libp2pTransport::new(cfg(0x82, "grp-a", lo, false)).expect("y in a");
    let x = xa.self_address().to_string();
    let y = ya.self_address().to_string();
    xa.authorize(&y);
    xb.authorize(&y); // authorized in B by address, but Y runs no B swarm
    ya.authorize(&x);

    // Y dials X's B swarm with A's prologue: refused at Noise, never connected anywhere.
    let xb_seed = wait_seed(&xb);
    ya.add_peers(&[xb_seed[0].to_string()]).expect("dial b");
    sleep(Duration::from_secs(2));
    assert!(
        xb.connected().is_empty(),
        "another group's swarm never meshes"
    );
    assert!(ya.connected().is_empty());

    // Through A's seed it gets in, in A only.
    let xa_seed: Vec<String> = wait_seed(&xa).iter().map(Multiaddr::to_string).collect();
    assert!(xa_seed[0].ends_with(&format!("/p2p/{}", peer_of(0x81))));
    assert_eq!(ya.add_peers(&xa_seed), Ok(xa_seed.len()));
    wait_for("Y meshes with X in group A", 15, || {
        xa.connected().contains(&y) && ya.connected().contains(&x)
    });
    assert!(xb.connected().is_empty(), "group B is untouched");

    // Evicting Y from A leaves B alone; dropping A's swarm leaves B's running on the shared runtime.
    xa.disconnect(&y);
    wait_for("Y evicted from A", 10, || !ya.connected().contains(&x));
    drop(xa);
    assert!(
        !wait_seed(&xb).is_empty(),
        "B's swarm still answers after A's is gone"
    );
    let _ = &mut xb;
}

/// Without the `mdns` cargo feature, asking for mDNS is refused, never silently ignored.
#[cfg(not(feature = "mdns"))]
#[test]
fn a_build_without_mdns_refuses_to_turn_it_on() {
    const { assert!(!MDNS_BUILT_IN) };
    match Libp2pTransport::new(cfg(0xA1, "grp-no-mdns", "/ip4/127.0.0.1/tcp/0", true)) {
        Err(TransportError::Build(m)) => assert_eq!(m, NO_MDNS_BUILD),
        Err(e) => panic!("unexpected error {e}"),
        Ok(_) => panic!("mDNS was requested of a build without it"),
    }
    // Off works as always.
    assert!(Libp2pTransport::new(cfg(0xA1, "grp-no-mdns", "/ip4/127.0.0.1/tcp/0", false)).is_ok());
}

/// HUP-S8.4 opt-in LAN discovery: two swarms that know each other's address (roster) but not each
/// other's location find each other by mDNS and mesh, with no seed and no bootstrap. Needs IPv4
/// multicast on a non-loopback interface (mDNS never runs on loopback), so it is ignored by default.
#[cfg(feature = "mdns")]
#[test]
#[ignore = "needs LAN multicast on a non-loopback interface; run with -- --ignored"]
fn mdns_finds_an_authorized_peer_on_the_lan_without_a_seed() {
    let any = "/ip4/0.0.0.0/tcp/0";
    let mut a = Libp2pTransport::new(cfg(0x91, "grp-mdns", any, true)).expect("a");
    let mut b = Libp2pTransport::new(cfg(0x92, "grp-mdns", any, true)).expect("b");
    let mut c = Libp2pTransport::new(cfg(0x93, "grp-mdns", any, true)).expect("c");
    let (xa, xb, xc) = (addr_of(0x91), addr_of(0x92), addr_of(0x93));
    a.authorize(&xb);
    b.authorize(&xa);
    // C is on the LAN with mDNS on but not authorized by A or B (and authorizes nobody).
    let _ = &mut c;
    wait_for("A and B find and mesh with each other by mDNS", 45, || {
        a.connected().contains(&xb) && b.connected().contains(&xa)
    });
    sleep(Duration::from_secs(2));
    assert!(!a.connected().contains(&xc) && !b.connected().contains(&xc));
    assert!(c.connected().is_empty(), "discovery never admits");
}

/// HUP-S8.4 review: every re-dial takes a NEW local port. A re-dial from the listen port recreates
/// the 4-tuple of a connection this node just closed; macOS refuses it with EADDRINUSE while that
/// tuple sits in TIME_WAIT, so a peer refused once could never get back in from a Mac. The
/// multi-process late-link test only catches this when the timing lines up, so pin it here.
/// `DialOpts` exposes its port policy only through `Debug` (libp2p-swarm, pinned by Cargo.lock).
#[test]
fn every_redial_allocates_a_new_local_port() {
    let peer = peer_of(0x73);
    for addr in [
        format!("/ip4/10.0.0.3/tcp/4211/p2p/{peer}"),
        "/ip4/10.0.0.3/tcp/4211".to_string(),
    ] {
        let ma: Multiaddr = addr.parse().expect("multiaddr");
        let opts = format!("{:?}", redial_opts(ma));
        assert!(opts.contains("port_use: New"), "{addr}: {opts}");
    }
    // The peer id a bootstrap address names is kept, so the dial is checked against it.
    let named: Multiaddr = format!("/ip4/10.0.0.3/tcp/4211/p2p/{peer}")
        .parse()
        .expect("multiaddr");
    assert_eq!(redial_opts(named).get_peer_id(), Some(peer));
}
