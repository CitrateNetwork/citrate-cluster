//! HUP-S8.4 mesh prerequisites, single machine, real processes (US-8.2 / F-9 prep):
//!
//! * **One daemon, every group.** Two `cluster-daemon` processes, each serving two groups from one
//!   process (no `CITRATE_CLUSTER_GROUP`), one swarm per group under one device key.
//! * **Seeded bootstrap.** Neither daemon is given the other's address at start-up: each group meshes
//!   from a group seed (the link/QR text) one node hands the other over IPC.
//! * **Isolation.** A revocation applied in one group evicts the device there and nowhere else.
//! * **Stable per-group ports** from a fixed base, the same after a restart (seeds stay valid).
//! * **mDNS** (ignored by default, needs LAN multicast): two daemons mesh with no seed at all.

#![cfg(unix)]

mod support;

use std::time::Duration;

use cluster_daemon::libp2p_transport::group_listen;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use serde_json::{json, Value};
use support::{addr, key, link_json, revocation_json, start_multi, wait_until};

const G1: &str = "hup-s8-multi-one";
const G2: &str = "hup-s8-multi-two";

fn port_of(addr_text: &str) -> u16 {
    let ma: Multiaddr = addr_text.parse().expect("multiaddr");
    ma.iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .expect("tcp port")
}

fn seed_text(v: &Value) -> String {
    v["seed"].as_str().expect("seed text").to_string()
}

#[test]
fn one_daemon_serves_two_groups_and_a_revocation_in_one_leaves_the_other() {
    let m1 = key(0xC1);
    let w1 = key(0xC2);
    let d1 = key(0xC3);
    let m2 = key(0xC4);
    let w2 = key(0xC5);
    let d2 = key(0xC6);
    let roster = json!([[addr(&m1), "member"], [addr(&m2), "member"]]);
    let links = json!([
        link_json(&m1, &d1, &w1, 0, "Studio Mac"),
        link_json(&m2, &d2, &w2, 0, "Linux box"),
    ]);

    let x = start_multi("mgx", &d1, "/ip4/127.0.0.1/tcp/0", &[]);
    let y = start_multi("mgy", &d2, "/ip4/127.0.0.1/tcp/0", &[]);
    for n in [&x, &y] {
        for g in [G1, G2] {
            let r = n.set_roster_in(g, &roster, &links, &json!([]));
            assert_eq!(r["type"], "reconciled", "{r}");
            assert!(r.get("rejected").is_none(), "{r}");
        }
    }

    // Two swarms in one process: two seeds, two ports, one PeerId.
    let s1 = x.seed(G1);
    let s2 = x.seed(G2);
    let a1 = s1["addrs"][0].as_str().expect("addr").to_string();
    let a2 = s2["addrs"][0].as_str().expect("addr").to_string();
    assert_ne!(port_of(&a1), port_of(&a2), "one swarm (and port) per group");
    assert!(a1.ends_with(&format!("/p2p/{}", x.peer_id)), "{a1}");
    assert!(a2.ends_with(&format!("/p2p/{}", x.peer_id)), "{a2}");

    // A seed only works for its own group.
    let wrong = y.add_seed(G2, &seed_text(&s1));
    assert_eq!(wrong["type"], "error", "{wrong}");

    // Seeded bootstrap: Y learns X's location from the link text alone.
    for (g, s) in [(G1, &s1), (G2, &s2)] {
        let r = y.add_seed(g, &seed_text(s));
        assert_eq!(r["type"], "seeded", "{r}");
        assert_eq!(r["dialing"], 1, "{r}");
    }
    for g in [G1, G2] {
        wait_until("both groups mesh from seeds", 30, || {
            x.online_in(g, &addr(&d2)) && y.online_in(g, &addr(&d1))
        });
    }

    // Member 2 revokes its device; X applies it in G1 only.
    let r = x.set_roster_in(G1, &roster, &links, &json!([revocation_json(&m2, &d2)]));
    assert_eq!(r["evicted"], json!([addr(&d2)]), "{r}");
    wait_until("Y's device leaves X's G1", 20, || {
        !x.online_in(G1, &addr(&d2))
    });
    wait_until("Y sees X gone from G1", 20, || !y.online_in(G1, &addr(&d1)));
    // G2 is untouched, including through Y's G1 re-dials (refused at X for G1).
    std::thread::sleep(Duration::from_secs(7));
    assert!(x.online_in(G2, &addr(&d2)), "G2 keeps Y's device at X");
    assert!(y.online_in(G2, &addr(&d1)), "G2 keeps X's device at Y");
    assert!(!x.online_in(G1, &addr(&d2)), "the revocation holds in G1");
    let st = x.call(json!({ "op": "status", "group": G2 }));
    assert_eq!(st["online"], 1, "{st}");
}

/// A fixed base port gives each group its own port, and the same one after a restart, so a seed
/// handed out yesterday still names the right port today.
#[test]
fn a_fixed_base_port_gives_each_group_a_stable_port_across_restarts() {
    let d = key(0xD1);
    // A base whose two derived ports are free right now.
    let mut base = 0u16;
    for candidate in (21_000u16..60_000).step_by(1_531) {
        let ports: Vec<u16> = [G1, G2]
            .iter()
            .map(|g| {
                let ma: Multiaddr = format!("/ip4/127.0.0.1/tcp/{candidate}")
                    .parse()
                    .expect("ma");
                port_of(&group_listen(&ma, g).to_string())
            })
            .collect();
        if ports
            .iter()
            .all(|p| std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok())
        {
            base = candidate;
            break;
        }
    }
    assert_ne!(base, 0, "no free base port found");
    let listen = format!("/ip4/127.0.0.1/tcp/{base}");
    let want = |g: &str| port_of(&group_listen(&listen.parse().expect("ma"), g).to_string());

    let ports = |n: &support::Node| -> (u16, u16) {
        for g in [G1, G2] {
            n.call(json!({ "op": "join", "group": g }));
        }
        let p1 = port_of(n.seed(G1)["addrs"][0].as_str().expect("addr"));
        let p2 = port_of(n.seed(G2)["addrs"][0].as_str().expect("addr"));
        (p1, p2)
    };
    let first = {
        let n = start_multi("mgp1", &d, &listen, &[]);
        ports(&n)
    }; // dropped: process killed, ports released
    assert_eq!(first, (want(G1), want(G2)));
    let n = start_multi("mgp2", &d, &listen, &[]);
    assert_eq!(ports(&n), first, "same ports after a restart");
}

/// Opt-in LAN discovery end to end: two multi-group daemons with `CITRATE_CLUSTER_MDNS=1`, no seed,
/// no bootstrap, mesh in a group both authorize. mDNS never runs on loopback, so this needs IPv4
/// multicast on a real interface; ignored by default, run with `-- --ignored`.
#[cfg(feature = "mdns")]
#[test]
#[ignore = "needs LAN multicast on a non-loopback interface; run with -- --ignored"]
fn two_daemons_find_each_other_by_mdns_without_a_seed() {
    let m1 = key(0xE1);
    let w1 = key(0xE2);
    let d1 = key(0xE3);
    let m2 = key(0xE4);
    let w2 = key(0xE5);
    let d2 = key(0xE6);
    let roster = json!([[addr(&m1), "member"], [addr(&m2), "member"]]);
    let links = json!([
        link_json(&m1, &d1, &w1, 0, "A"),
        link_json(&m2, &d2, &w2, 0, "B"),
    ]);
    let mdns = [("CITRATE_CLUSTER_MDNS", "1")];
    let a = start_multi("mdA", &d1, "/ip4/0.0.0.0/tcp/0", &mdns);
    let b = start_multi("mdB", &d2, "/ip4/0.0.0.0/tcp/0", &mdns);
    for n in [&a, &b] {
        let r = n.set_roster_in(G1, &roster, &links, &json!([]));
        assert_eq!(r["type"], "reconciled", "{r}");
    }
    wait_until("mDNS mesh with no seed", 60, || {
        a.online_in(G1, &addr(&d2)) && b.online_in(G1, &addr(&d1))
    });
}

/// A default build (no `mdns` feature) refuses `CITRATE_CLUSTER_MDNS=1` at start-up with a reason,
/// instead of starting without the discovery the operator asked for.
#[cfg(not(feature = "mdns"))]
#[test]
fn a_default_build_refuses_mdns_at_startup() {
    let dir = std::env::temp_dir().join(format!("cfl-nomdns-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let seed = dir.join("seed");
    let bearer = dir.join("bearer");
    for (p, v) in [
        (&seed, hex::encode(key(0xA9).to_bytes())),
        (&bearer, "b".repeat(64)),
    ] {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(p)
            .expect("file");
        f.write_all(v.as_bytes()).expect("write");
    }
    let out = std::process::Command::new(support::bin())
        .env("CITRATE_CLUSTER_SOCKET", dir.join("s.sock"))
        .env("CITRATE_CLUSTER_BEARER_FILE", &bearer)
        .env("CITRATE_CLUSTER_SELF_ADDR", addr(&key(0xA9)))
        .env("CITRATE_CLUSTER_LISTEN", "/ip4/127.0.0.1/tcp/0")
        .env("CITRATE_CLUSTER_SEED_FILE", &seed)
        .env("CITRATE_CLUSTER_MDNS", "1")
        .env_remove("CITRATE_CLUSTER_GROUP")
        .output()
        .expect("run daemon");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!out.status.success(), "must not start");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("built without mDNS"), "{err}");
}

/// A daemon that is not told to use mDNS never discovers anyone: without a seed, nothing meshes.
#[test]
fn without_mdns_or_a_seed_nothing_meshes() {
    let m1 = key(0xF1);
    let w1 = key(0xF2);
    let d1 = key(0xF3);
    let m2 = key(0xF4);
    let w2 = key(0xF5);
    let d2 = key(0xF6);
    let roster = json!([[addr(&m1), "member"], [addr(&m2), "member"]]);
    let links = json!([
        link_json(&m1, &d1, &w1, 0, "A"),
        link_json(&m2, &d2, &w2, 0, "B"),
    ]);
    let a = start_multi("nmA", &d1, "/ip4/127.0.0.1/tcp/0", &[]);
    let b = start_multi("nmB", &d2, "/ip4/127.0.0.1/tcp/0", &[]);
    for n in [&a, &b] {
        n.set_roster_in(G1, &roster, &links, &json!([]));
    }
    std::thread::sleep(Duration::from_secs(6));
    assert!(!a.online_in(G1, &addr(&d2)) && !b.online_in(G1, &addr(&d1)));
}
