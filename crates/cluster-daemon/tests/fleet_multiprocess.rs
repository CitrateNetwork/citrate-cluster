//! HUP-S8.1 / S8.4 single-machine, multi-process fleet proofs.
//!
//! Real `cluster-daemon` processes on loopback (real UDS IPC, real TCP + Noise + gossipsub). They
//! stand in, on one machine, for the two- and three-machine runs the DGX team does across hosts
//! (`scripts/soak/devicelink-node.sh`):
//!
//! * **Cross-member, late link.** Two members, one device each. B's node starts without A's link, so
//!   A's device is refused. A's link then arrives at B in a roster update (what core does after it
//!   learns another member's links over the group relay). No restart: the bootstrap re-dial lets A's
//!   device in.
//! * **Three devices, two members, revocation.** A full mesh of three devices; a revocation applied
//!   on the two nodes that keep the device evicts it from both, and the other two stay meshed.

#![cfg(unix)]

mod support;

use serde_json::json;
use support::{addr, key, link_json, revocation_json, start, wait_until};

/// The DGX two-machine script's shape: two members, one device each, links learned late.
#[test]
fn another_members_device_gets_in_when_its_link_arrives_without_a_restart() {
    const GROUP: &str = "hup-s8-cross-member";
    let m1 = key(0x91); // member 1 comms/roster key
    let w1 = key(0x92); // member 1 wallet (core collects this signature through the ceremony)
    let d1 = key(0x93); // member 1's device
    let m2 = key(0x94);
    let w2 = key(0x95);
    let d2 = key(0x96);

    let roster = json!([[addr(&m1), "member"], [addr(&m2), "member"]]);
    let l1 = link_json(&m1, &d1, &w1, 0, "Studio Mac");
    let l2 = link_json(&m2, &d2, &w2, 0, "Linux box");

    // A knows both links. B knows only its own member's link (before distribution).
    let a = start("xa", GROUP, &d1, &[]);
    let r = a.set_roster(&roster, &json!([l1, l2]), &json!([]));
    assert_eq!(r["type"], "reconciled", "{r}");
    let b = start("xb", GROUP, &d2, &[a.multiaddr()]);
    let r = b.set_roster(&roster, &json!([l2]), &json!([]));
    assert_eq!(r["type"], "reconciled", "{r}");

    // B refuses A's device: no link for it yet. (A admits B; the connection still drops at B.)
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(
        !b.online(&addr(&d1)),
        "a device whose link this node has not seen is not admitted"
    );
    assert_ne!(a.peer_id, b.peer_id, "one PeerId per device key");

    // A's link reaches B (core forwards what it learned over the group relay). No restart.
    let r = b.set_roster(&roster, &json!([l2, l1]), &json!([]));
    assert_eq!(r["type"], "reconciled", "{r}");
    assert!(r.get("rejected").is_none(), "both links verify: {r}");
    wait_until("B admits A's device after the late link", 30, || {
        b.online(&addr(&d1))
    });
    wait_until("A sees B's device", 30, || a.online(&addr(&d2)));

    // Each node lists the other member's device under that member.
    let v = b.call(json!({ "op": "devices", "group": GROUP }));
    let members = v["members"].as_array().cloned().unwrap_or_default();
    let m1_entry = members
        .iter()
        .find(|m| m["member"] == addr(&m1))
        .expect("member 1 listed");
    assert_eq!(m1_entry["devices"][0]["device"], addr(&d1));
    assert_eq!(m1_entry["devices"][0]["online"], true);
}

/// The DGX three-machine script's shape: member 1 has two devices, member 2 has one.
#[test]
fn three_devices_mesh_and_a_revocation_evicts_one_from_every_node_that_applies_it() {
    const GROUP: &str = "hup-s8-three";
    let m1 = key(0xA1);
    let w1 = key(0xA2);
    let d1 = key(0xA3); // member 1, machine A
    let d2 = key(0xA4); // member 1, machine B
    let m2 = key(0xA5);
    let w2 = key(0xA6);
    let d3 = key(0xA7); // member 2, machine C

    let roster = json!([[addr(&m1), "member"], [addr(&m2), "member"]]);
    let links = json!([
        link_json(&m1, &d1, &w1, 0, "Studio Mac"),
        link_json(&m1, &d2, &w1, 1, "Linux box"),
        link_json(&m2, &d3, &w2, 0, "Office PC"),
    ]);

    let a = start("ta", GROUP, &d1, &[]);
    a.set_roster(&roster, &links, &json!([]));
    let b = start("tb", GROUP, &d2, &[a.multiaddr()]);
    b.set_roster(&roster, &links, &json!([]));
    let c = start("tc", GROUP, &d3, &[a.multiaddr(), b.multiaddr()]);
    c.set_roster(&roster, &links, &json!([]));

    // Full mesh: every node sees the other two devices.
    for (n, others) in [
        (&a, [addr(&d2), addr(&d3)]),
        (&b, [addr(&d1), addr(&d3)]),
        (&c, [addr(&d1), addr(&d2)]),
    ] {
        for o in &others {
            wait_until("three-device full mesh", 40, || n.online(o));
        }
    }
    let ids = [&a.peer_id, &b.peer_id, &c.peer_id];
    assert!(
        ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2],
        "three distinct PeerIds"
    );

    // Member 1 removes machine B. The revocation reaches A (its own node) and C (over the relay).
    let rev = json!([revocation_json(&m1, &d2)]);
    let ra = a.set_roster(&roster, &links, &rev);
    let rc = c.set_roster(&roster, &links, &rev);
    assert_eq!(ra["evicted"], json!([addr(&d2)]), "{ra}");
    assert_eq!(rc["evicted"], json!([addr(&d2)]), "{rc}");

    wait_until("B drops off A and C", 20, || b.online_count() == 0);
    assert!(!a.online(&addr(&d2)) && !c.online(&addr(&d2)));
    // A and C stay meshed with each other.
    assert!(a.online(&addr(&d3)), "A still sees C");
    assert!(c.online(&addr(&d1)), "C still sees A");
    // B keeps re-dialing; it is never let back in (sticky revocation).
    std::thread::sleep(std::time::Duration::from_secs(7));
    assert!(
        !a.online(&addr(&d2)) && !c.online(&addr(&d2)),
        "re-dials by a revoked device are refused"
    );
}
