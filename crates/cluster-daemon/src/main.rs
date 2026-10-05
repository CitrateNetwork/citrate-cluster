//! citrate-cluster daemon — the binary.
//!
//! The cluster sidecar citrate-core spawns per user. It runs a group P2P mesh (admission gated by
//! `cluster-core`) and serves a loopback UDS JSON IPC. All config is via ENV (the bearer comes as a
//! FILE PATH, never inline — argv/env leak to `ps`):
//!
//!   CITRATE_CLUSTER_SOCKET       UDS path to bind (required)
//!   CITRATE_CLUSTER_BEARER_FILE  path to the 0600 bearer-token file the client wrote (required)
//!   CITRATE_CLUSTER_SELF_ADDR    this node's member address (hex, its cluster identity) (required)
//!
//! ## Transport selection (CL-S1)
//!
//! When `CITRATE_CLUSTER_LISTEN` is set, the daemon runs the real **libp2p** transport (Noise
//! identity + gossipsub, one topic per group) — a cross-machine mesh. Otherwise it stays on the
//! in-process transport (single node — real admission, no fan-out). The libp2p transport reads:
//!
//!   CITRATE_CLUSTER_LISTEN       listen multiaddr, e.g. /ip4/0.0.0.0/tcp/0 (selects libp2p)
//!   CITRATE_CLUSTER_SEED_FILE    path to a 0600 file with the 32-byte hex secp256k1 secret — the
//!                                Noise/peer identity is bound to this key. HUP-S8.1: this is the
//!                                DEVICE key (random per machine, linked to the member by a signed
//!                                DeviceLink), so the PeerId is per device; a client without a
//!                                link still passes its comms key (legacy single-device identity),
//!                                which the mesh admits only until the member links or revokes a
//!                                device (ADR-003).
//!                                Never the wallet key. The secret NEVER crosses argv/env (they
//!                                leak to `ps`), only a file.
//!   CITRATE_CLUSTER_GROUP        optional: pin the daemon to this one group (the pre-HUP-S8.4 mode).
//!                                Unset: HUP-S8.4, one daemon serves every group the client joins,
//!                                one swarm per group (its own topic, Noise prologue and port).
//!   CITRATE_CLUSTER_BOOTSTRAP    optional comma-separated peer multiaddrs to dial on startup (the
//!                                pinned group only; other groups take peers from group seeds)
//!   CITRATE_CLUSTER_MDNS         optional `1`: LAN discovery for every group (off by default)
//!
//! Per-group listen ports (multi-group mode): a fixed base port P gives each group
//! `P + keccak256(group) mod 1024`, falling back to an ephemeral port when taken; base port 0 stays
//! ephemeral.

use std::env;
use std::path::PathBuf;

use cluster_daemon::libp2p_transport::{Libp2pFactory, Libp2pTransport, NodeConfig};
use cluster_daemon::transport::InProcessTransport;
use cluster_daemon::{server, ClusterDaemon, TransportFactory};
use zeroize::{Zeroize, Zeroizing};

fn required(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("{key} is required"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Soak/ops helper: print this node's {address, peerId} from its seed, OFFLINE (no swarm), so the
    // operator can build the peer's bootstrap multiaddr before starting. Reads CITRATE_CLUSTER_SEED_FILE.
    if env::args().any(|a| a == "--print-identity") {
        let seed_file = required("CITRATE_CLUSTER_SEED_FILE")?;
        // CL-B-001: wipe the hex string, decoded bytes, and the `[u8; 32]` copy handed to
        // `identity_from_secret` (which takes it by value/`Copy`, so the local retains a live copy).
        let seed_hex = cluster_daemon::read_secret_file(&seed_file)?;
        let seed_bytes = Zeroizing::new(
            hex::decode(seed_hex.trim()).map_err(|_| "seed must be hex".to_string())?,
        );
        let mut secret: [u8; 32] = <[u8; 32]>::try_from(seed_bytes.as_slice())
            .map_err(|_| "seed must be 32 bytes".to_string())?;
        let (address, peer_id) = Libp2pTransport::identity_from_secret(secret)?;
        secret.zeroize();
        println!("{{\"address\":\"{address}\",\"peerId\":\"{peer_id}\"}}");
        return Ok(());
    }

    let socket = PathBuf::from(required("CITRATE_CLUSTER_SOCKET")?);
    let bearer_file = required("CITRATE_CLUSTER_BEARER_FILE")?;
    // CL-B-007: the bearer file is a secret — refuse to read it unless it is 0600 and owned by us.
    // R2 (PBA-L6b-022 class): one no-follow open, checks on the fd, capped read.
    let bearer = cluster_daemon::read_secret_file(&bearer_file)?
        .trim()
        .to_string();
    if bearer.is_empty() {
        return Err("bearer file is empty (fail closed)".into());
    }
    let self_addr = required("CITRATE_CLUSTER_SELF_ADDR")?;
    let Some(self_canonical) = cluster_core::canonical_address(&self_addr) else {
        return Err("CITRATE_CLUSTER_SELF_ADDR is not a 20-byte hex address".into());
    };

    // Transport selection: real libp2p mesh when a listen addr is configured, else single-node
    // in-process. Both slot behind the same MeshTransport seam — the daemon logic is identical.
    if env::var("CITRATE_CLUSTER_LISTEN").is_ok() {
        // Validate the libp2p env at startup (fail closed with a clear message). Also opens the 0600
        // seed file per CL-B-007; the secret is wiped when the factory drops (CL-B-001).
        let node = NodeConfig::from_env().map_err(|e| format!("libp2p transport config: {e}"))?;
        // CL-B-007: the identity the daemon advertises (SELF_ADDR) must equal the identity derived
        // from the seed file, or the node reports one address locally while presenting another on the
        // wire.
        let (derived_addr, _) = node
            .identity()
            .map_err(|e| format!("deriving identity from the seed: {e}"))?;
        let want = self_canonical;
        if derived_addr != want {
            return Err(format!(
                "CITRATE_CLUSTER_SELF_ADDR ({want}) does not match the address derived from the seed file ({derived_addr}) — fail closed"
            )
            .into());
        }
        let pinned = node.pinned_group.clone();
        let factory = Libp2pFactory::new(node).map_err(|e| format!("libp2p runtime: {e}"))?;
        let make: TransportFactory<Libp2pTransport> =
            Box::new(move |group: &str| factory.transport_for(group));
        let daemon = match pinned {
            // CL-B-002 / operator mode: exactly one group, on the configured listen address.
            Some(group) => ClusterDaemon::with_factory_single_group(self_addr, make, group),
            // HUP-S8.4: every group the client joins, one swarm each.
            None => ClusterDaemon::with_factory(self_addr, make),
        };
        server::serve(daemon, &socket, &bearer)?;
    } else {
        let daemon = ClusterDaemon::new(self_addr, InProcessTransport::new);
        server::serve(daemon, &socket, &bearer)?;
    }
    Ok(())
}
