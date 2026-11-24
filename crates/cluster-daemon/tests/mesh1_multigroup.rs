//! V60 MESH-1 (0.6.0 planset 05, F-C2 "One daemon, many groups"): real `cluster-daemon` processes
//! on loopback, each serving several groups from one process.
//!
//! * `one_daemon_serves_three_groups`: three swarms in one process, each with its own port and
//!   topic, all under one device PeerId; a co-pin in one group reaches that group only.
//! * `group_a_peer_cannot_read_group_b`: a device admitted in group A, and running group B itself,
//!   is refused by the other daemon's group-B swarm and never receives group B's co-pins.

#![cfg(unix)]

mod support;

use std::collections::BTreeSet;
use std::time::Duration;

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use serde_json::{json, Value};
use support::{addr, key, link_json, start_multi, wait_until, Node};

const CID_1: &str = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
const CID_2: &str = "bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";

fn port_of(addr_text: &str) -> u16 {
    let ma: Multiaddr = addr_text.parse().expect("multiaddr");
    ma.iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .expect("tcp port")
}

fn shared_in(n: &Node, group: &str) -> Vec<String> {
    let st = n.call(json!({ "op": "status", "group": group }));
    st["sharedFiles"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn share(n: &Node, group: &str, cid: &str) -> Value {
    n.call(json!({ "op": "shareFile", "group": group, "cid": cid }))
}

#[test]
fn one_daemon_serves_three_groups() {
    const GROUPS: [&str; 3] = ["mesh1-three-a", "mesh1-three-b", "mesh1-three-c"];
    let (m1, w1, d1) = (key(0xE1), key(0xE2), key(0xE3));
    let (m2, w2, d2) = (key(0xE4), key(0xE5), key(0xE6));
    let roster = json!([[addr(&m1), "member"], [addr(&m2), "member"]]);
    let links = json!([
        link_json(&m1, &d1, &w1, 0, "Studio Mac"),
        link_json(&m2, &d2, &w2, 0, "Linux box"),
    ]);
    let x = start_multi("m1x", &d1, "/ip4/127.0.0.1/tcp/0", &[]);
    let y = start_multi("m1y", &d2, "/ip4/127.0.0.1/tcp/0", &[]);
    for n in [&x, &y] {
        for g in GROUPS {
            let r = n.set_roster_in(g, &roster, &links, &json!([]));
            assert_eq!(r["type"], "reconciled", "{r}");
        }
    }

    // Three swarms in X's one process: three ports, one PeerId.
    let seeds: Vec<Value> = GROUPS.iter().map(|g| x.seed(g)).collect();
    let ports: BTreeSet<u16> = seeds
        .iter()
        .map(|s| port_of(s["addrs"][0].as_str().expect("addr")))
        .collect();
    assert_eq!(ports.len(), 3, "one swarm (and port) per group: {ports:?}");
    for s in &seeds {
        let a = s["addrs"][0].as_str().expect("addr");
        assert!(a.ends_with(&format!("/p2p/{}", x.peer_id)), "{a}");
    }

    for (g, s) in GROUPS.iter().zip(&seeds) {
        let r = y.add_seed(g, s["seed"].as_str().expect("seed"));
        assert_eq!(r["type"], "seeded", "{r}");
    }
    for g in GROUPS {
        wait_until("all three groups mesh", 30, || {
            x.online_in(g, &addr(&d2)) && y.online_in(g, &addr(&d1))
        });
    }

    // A co-pin in the middle group reaches Y's copy of that group and no other (one topic per group).
    wait_until("the co-pin reaches Y in its group", 20, || {
        share(&x, GROUPS[1], CID_1);
        shared_in(&y, GROUPS[1]).contains(&CID_1.to_string())
    });
    std::thread::sleep(Duration::from_secs(2));
    assert!(!shared_in(&y, GROUPS[0]).contains(&CID_1.to_string()));
    assert!(!shared_in(&y, GROUPS[2]).contains(&CID_1.to_string()));
}

#[test]
fn group_a_peer_cannot_read_group_b() {
    const GA: &str = "mesh1-iso-a";
    const GB: &str = "mesh1-iso-b";
    let (m1, w1, d1) = (key(0xE7), key(0xE8), key(0xE9));
    let (m2, w2, d2) = (key(0xEA), key(0xEB), key(0xEC));
    let both = json!([[addr(&m1), "member"], [addr(&m2), "member"]]);
    let only_x = json!([[addr(&m1), "member"]]);
    let links = json!([
        link_json(&m1, &d1, &w1, 0, "Studio Mac"),
        link_json(&m2, &d2, &w2, 0, "Linux box"),
    ]);
    let x = start_multi("m1ix", &d1, "/ip4/127.0.0.1/tcp/0", &[]);
    let y = start_multi("m1iy", &d2, "/ip4/127.0.0.1/tcp/0", &[]);
    // X admits Y in A only. Y runs both groups and would admit X in both.
    assert_eq!(
        x.set_roster_in(GA, &both, &links, &json!([]))["type"],
        "reconciled"
    );
    assert_eq!(
        x.set_roster_in(GB, &only_x, &links, &json!([]))["type"],
        "reconciled"
    );
    for g in [GA, GB] {
        assert_eq!(
            y.set_roster_in(g, &both, &links, &json!([]))["type"],
            "reconciled"
        );
    }
    for g in [GA, GB] {
        let s = x.seed(g);
        assert_eq!(
            y.add_seed(g, s["seed"].as_str().expect("seed"))["type"],
            "seeded"
        );
    }
    wait_until("group A meshes", 30, || {
        x.online_in(GA, &addr(&d2)) && y.online_in(GA, &addr(&d1))
    });
    wait_until("X's co-pin in A reaches Y", 20, || {
        share(&x, GA, CID_1);
        shared_in(&y, GA).contains(&CID_1.to_string())
    });

    // Group B: Y keeps re-dialing X's B swarm, and X refuses it at identify every time.
    for _ in 0..12 {
        share(&x, GB, CID_2);
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(!x.online_in(GB, &addr(&d2)), "X's group B never admits Y");
    assert!(
        !y.online_in(GB, &addr(&d1)),
        "Y is never meshed with X in group B"
    );
    assert!(
        !shared_in(&y, GB).contains(&CID_2.to_string()),
        "Y never reads group B's co-pins"
    );
    assert!(
        !shared_in(&y, GA).contains(&CID_2.to_string()),
        "nor through group A"
    );
    assert!(y.online_in(GA, &addr(&d1)), "group A is unaffected");
}
