//! V60 S0-NAT-SPIKE: run a cluster relay node for the netns spike (`scripts/nat-spike/`).
//!
//! Not a deployable relay. It admits a fixed list of PeerIds; MESH-3 builds the production relay
//! (reservations gated by a signed DeviceLink, run on non-producer hosts after an owner go).
//!
//! Env:
//!   CITRATE_RELAY_SEED_FILE  0600 file with the relay's 32-byte hex secp256k1 secret (required)
//!   CITRATE_RELAY_LISTEN     listen multiaddr, e.g. /ip4/0.0.0.0/tcp/4100 (required unless
//!                            --print-identity)
//!   CITRATE_RELAY_ALLOW      comma-separated PeerIds allowed to connect (required; empty refuses all)
//!
//! `--print-identity` prints `{"peerId": …}` and exits. Otherwise the relay prints one JSON line of
//! counters every 2 s until it is killed.

use std::env;
use std::thread::sleep;
use std::time::Duration;

use cluster_daemon::relay_node::RelayNode;
use libp2p::{identity, Multiaddr, PeerId};
use zeroize::Zeroizing;

fn required(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("{key} is required"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed_hex = cluster_daemon::read_secret_file(&required("CITRATE_RELAY_SEED_FILE")?)?;
    let bytes = Zeroizing::new(hex::decode(seed_hex.trim()).map_err(|_| "seed must be hex")?);
    let secret: [u8; 32] =
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "seed must be 32 bytes")?;

    if env::args().any(|a| a == "--print-identity") {
        let mut s = secret;
        let sk = identity::secp256k1::SecretKey::try_from_bytes(&mut s)?;
        let kp = identity::Keypair::from(identity::secp256k1::Keypair::from(sk));
        println!("{{\"peerId\":\"{}\"}}", kp.public().to_peer_id());
        return Ok(());
    }

    let listen: Multiaddr = required("CITRATE_RELAY_LISTEN")?.parse()?;
    let allowed: Vec<PeerId> = required("CITRATE_RELAY_ALLOW")?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<PeerId>().map_err(|e| format!("bad PeerId {s:?}: {e}")))
        .collect::<Result<_, _>>()?;

    let relay = RelayNode::start(secret, listen, &allowed)?;
    eprintln!("spike-relay: {} allows {} peers", relay.peer_id(), allowed.len());
    loop {
        let s = relay.stats();
        println!(
            "{{\"reservations\":{},\"circuits\":{},\"circuitsDenied\":{},\"connected\":{}}}",
            s.reservations_accepted,
            s.circuits_accepted,
            s.circuits_denied,
            s.connected.len()
        );
        sleep(Duration::from_secs(2));
    }
}
