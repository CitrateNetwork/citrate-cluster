//! HUP-S8.4 / CL-S3: a single-machine ladder step. N real `cluster-daemon` processes, one member and
//! one linked device each, in one group; every node bootstraps to every earlier node (full mesh, the
//! only topology the transport supports today: no peer discovery, and a message is accepted only
//! from a directly identified publisher). Measures time to full mesh and time for one co-pin to
//! reach every node, and prints one JSON line to stderr.
//!
//! This is NOT the CL-S3 ladder (that needs separate machines, real networks and the 50 to 2000
//! steps). It is the per-machine control: if N processes on loopback cannot mesh, N machines will
//! not either. The default test runs N = 4; the ignored one reads `CLUSTER_LADDER_N` (default 16):
//!
//! ```text
//! CLUSTER_LADDER_N=50 cargo test -p cluster-daemon --test ladder_multiprocess -- --ignored --nocapture
//! ```

#![cfg(unix)]

mod support;

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use support::{addr, key16, link_json, start, Node};

const CID: &str = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

fn ladder(n: u16, mesh_deadline: Duration) -> Value {
    assert!(n >= 2, "a ladder step needs at least two nodes");
    let group = format!("hup-s8-ladder-{n}");
    // Keys: member 3i, wallet 3i+1, device 3i+2.
    let member = |i: u16| key16(3 * i);
    let wallet = |i: u16| key16(3 * i + 1);
    let device = |i: u16| key16(3 * i + 2);
    let roster: Vec<Value> = (0..n)
        .map(|i| json!([addr(&member(i)), "member"]))
        .collect();
    let links: Vec<Value> = (0..n)
        .map(|i| link_json(&member(i), &device(i), &wallet(i), 0, &format!("node {i}")))
        .collect();
    let roster = Value::Array(roster);
    let links = Value::Array(links);

    let t0 = Instant::now();
    let mut nodes: Vec<Node> = Vec::with_capacity(n as usize);
    for i in 0..n {
        let boot: Vec<String> = nodes.iter().map(Node::multiaddr).collect();
        let node = start(&format!("l{n}-{i}"), &group, &device(i), &boot);
        let r = node.set_roster(&roster, &links, &json!([]));
        assert_eq!(r["type"], "reconciled", "node {i}: {r}");
        assert!(
            r.get("rejected").is_none(),
            "node {i}: every link verifies: {r}"
        );
        nodes.push(node);
    }
    let started_secs = t0.elapsed().as_secs_f64();

    // Full mesh: every node has n-1 peers online.
    let want = u64::from(n - 1);
    let t1 = Instant::now();
    loop {
        let counts: Vec<u64> = nodes.iter().map(Node::online_count).collect();
        if counts.iter().all(|c| *c == want) {
            break;
        }
        assert!(
            t1.elapsed() < mesh_deadline,
            "no full mesh within {mesh_deadline:?}: online counts {counts:?} (want {want} each)"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let mesh_secs = t1.elapsed().as_secs_f64();

    // One co-pin from the last node reaches every node.
    let last = nodes.last().expect("n >= 2");
    let t2 = Instant::now();
    loop {
        last.call(json!({ "op": "shareFile", "group": group, "cid": CID }));
        std::thread::sleep(Duration::from_millis(500));
        if nodes
            .iter()
            .all(|nd| nd.shared_files().iter().any(|c| c == CID))
        {
            break;
        }
        assert!(
            t2.elapsed() < mesh_deadline,
            "the co-pin did not reach every node within {mesh_deadline:?}"
        );
    }
    let copin_secs = t2.elapsed().as_secs_f64();

    let distinct: std::collections::BTreeSet<&String> = nodes.iter().map(|x| &x.peer_id).collect();
    assert_eq!(distinct.len(), n as usize, "one PeerId per device");
    let report = json!({
        "ladder": "single-machine",
        "nodes": n,
        "start_secs": (started_secs * 100.0).round() / 100.0,
        "full_mesh_secs": (mesh_secs * 100.0).round() / 100.0,
        "copin_all_secs": (copin_secs * 100.0).round() / 100.0,
        "connections_per_node": want,
    });
    eprintln!("{report}");
    report
}

#[test]
fn four_devices_of_four_members_form_a_full_mesh_and_share_a_file() {
    let r = ladder(4, Duration::from_secs(60));
    assert_eq!(r["nodes"], 4);
}

#[test]
#[ignore = "ladder step; run with CLUSTER_LADDER_N=<n> -- --ignored --nocapture"]
fn ladder_step_from_env() {
    let n: u16 = std::env::var("CLUSTER_LADDER_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);
    let secs = 30 + u64::from(n) * 4;
    ladder(n, Duration::from_secs(secs));
}
