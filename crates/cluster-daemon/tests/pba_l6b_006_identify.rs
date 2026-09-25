//! PBA-L6b-006 regression test (pre-bounty audit 2026-09-24, lane L6b).
//!
//! The audit PoC (`evidence/cluster/l6b_poc.rs::poc_identify_less_peer_eavesdrops_group_topic`)
//! turned into a real test over the REAL libp2p transport with the assertions inverted: a peer that
//! completes Noise (the group id is only a prologue, not a secret) and runs gossipsub but never
//! `identify` must receive NO group gossip and must be disconnected once the identify window lapses.
//! A positive control (an identified, authorized member) proves host gossip is flowing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};

use cluster_core::ClusterTransport;
use cluster_daemon::libp2p_transport::{Libp2pConfig, Libp2pTransport};
use cluster_daemon::transport::MeshTransport;
use futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{gossipsub, identity, noise, tcp, yamux, Multiaddr, SwarmBuilder};

const CID_SECRET: &str = "bafkreisecretcopinsecretcopinsecretcopinsecretcopinsecretc";

fn secret(seed: u8) -> [u8; 32] {
    let mut b = [seed; 32];
    b[0] = seed | 1;
    b
}

fn transport(seed: u8, group: &str) -> Libp2pTransport {
    Libp2pTransport::new(Libp2pConfig {
        secret: secret(seed),
        listen: "/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"),
        group_id: group.into(),
        bootstrap: vec![],
    })
    .expect("transport starts")
}

fn listen(t: &Libp2pTransport) -> Multiaddr {
    for _ in 0..100 {
        if let Some(a) = t.listeners().ok().and_then(|v| v.into_iter().next()) {
            return a;
        }
        sleep(Duration::from_millis(20));
    }
    panic!("listener never came up");
}

#[derive(NetworkBehaviour)]
struct Eaves {
    gossipsub: gossipsub::Behaviour,
}

#[test]
fn pba_l6b_006_identify_less_peer_receives_no_group_gossip_and_is_dropped() {
    const G: &str = "pba-l6b-006-eaves";
    let mut host = transport(0x61, G);
    let host_l = listen(&host);
    let host_addr = host.self_address().to_string();

    // Positive control: a legitimate, authorized member that runs identify.
    let mut member = transport(0x62, G);
    let member_addr = member.self_address().to_string();
    host.authorize(&member_addr);
    member.authorize(&host_addr);
    member.dial_multiaddr(host_l.clone()).expect("dial");

    // The eavesdropper: Noise (group id as prologue) + gossipsub only — NO identify.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let received: Arc<Mutex<Vec<String>>> = Arc::default();
    let dropped = Arc::new(AtomicBool::new(false));
    let rec2 = received.clone();
    let dropped2 = dropped.clone();
    let prologue = G.as_bytes().to_vec();
    rt.spawn(async move {
        let kp = identity::Keypair::generate_secp256k1();
        let mut sw = SwarmBuilder::with_existing_identity(kp)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                move |k: &identity::Keypair| {
                    noise::Config::new(k).map(|c| c.with_prologue(prologue.clone()))
                },
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|key| {
                let cfg = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_millis(200))
                    .build()
                    .unwrap();
                Eaves {
                    gossipsub: gossipsub::Behaviour::new(
                        gossipsub::MessageAuthenticity::Signed(key.clone()),
                        cfg,
                    )
                    .unwrap(),
                }
            })
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(600)))
            .build();
        sw.behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new(G))
            .unwrap();
        sw.dial(host_l).unwrap();
        loop {
            match sw.select_next_some().await {
                SwarmEvent::Behaviour(EavesEvent::Gossipsub(gossipsub::Event::Message {
                    message,
                    ..
                })) => {
                    rec2.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&message.data).into());
                }
                SwarmEvent::ConnectionClosed { .. } => dropped2.store(true, Ordering::SeqCst),
                _ => {}
            }
        }
    });

    // Host publishes throughout (well past any connect→identify window).
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut member_got = 0usize;
    while Instant::now() < deadline {
        // gossipsub message ids are (source, seqno), so re-publishing the same CID is not deduped.
        host.publish(&host_addr, CID_SECRET);
        sleep(Duration::from_millis(300));
        member_got += member.drain().len();
    }

    let got = received.lock().unwrap().clone();
    assert!(
        member_got > 0,
        "control: the identified, authorized member must receive host gossip"
    );
    assert!(
        got.is_empty(),
        "PBA-L6b-006: an identify-less peer must receive NO group gossip; got {} messages",
        got.len()
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "PBA-L6b-006: an identify-less peer must be disconnected after the identify timeout"
    );
}

/// No-regression for the L6b-006 gate: a peer that connects BEFORE it is authorized is gated and
/// dropped at identify; once authorized, a REDIAL must be admitted and exchange gossip both ways
/// (the gate is lifted on disconnect so gossipsub announces our subscription to the new connection).
#[test]
fn pba_l6b_006_peer_refused_before_authorization_is_admitted_after_redial() {
    const G: &str = "pba-l6b-006-redial";
    let mut host = transport(0x71, G);
    let host_l = listen(&host);
    let host_addr = host.self_address().to_string();
    let mut late = transport(0x72, G);
    let late_addr = late.self_address().to_string();
    late.authorize(&host_addr);

    // 1. `late` dials before the host authorizes it: refused on the wire.
    late.dial_multiaddr(host_l.clone()).expect("dial");
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(3) {
        late.publish(&late_addr, CID_SECRET);
        sleep(Duration::from_millis(200));
        assert!(
            host.drain().is_empty(),
            "an unauthorized peer is never accepted"
        );
    }
    assert!(!host.connected().contains(&late_addr));

    // 2. The host authorizes it; `late` redials and must now mesh in both directions.
    host.authorize(&late_addr);
    late.dial_multiaddr(host_l).expect("redial");
    let deadline = Instant::now() + Duration::from_secs(15);
    let (mut host_got, mut late_got) = (false, false);
    while Instant::now() < deadline && !(host_got && late_got) {
        late.publish(&late_addr, CID_SECRET);
        host.publish(&host_addr, CID_SECRET);
        sleep(Duration::from_millis(250));
        host_got |= host.drain().iter().any(|m| m.from == late_addr);
        late_got |= late.drain().iter().any(|m| m.from == host_addr);
    }
    assert!(
        host_got,
        "the host accepts the now-authorized peer's gossip"
    );
    assert!(
        late_got,
        "the now-authorized peer receives the host's gossip"
    );
}
