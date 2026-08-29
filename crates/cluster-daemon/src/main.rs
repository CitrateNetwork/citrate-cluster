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
//!                                Noise/peer identity is bound to this key (CL-2 = the wallet key).
//!                                The secret NEVER crosses argv/env (they leak to `ps`), only a file.
//!   CITRATE_CLUSTER_GROUP        the group id == the gossipsub topic (one group per daemon in S1)
//!   CITRATE_CLUSTER_BOOTSTRAP    optional comma-separated peer multiaddrs to dial on startup

use std::env;
use std::fs;
use std::path::PathBuf;

use cluster_daemon::libp2p_transport::Libp2pTransport;
use cluster_daemon::transport::InProcessTransport;
use cluster_daemon::{server, ClusterDaemon};

fn required(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("{key} is required"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = PathBuf::from(required("CITRATE_CLUSTER_SOCKET")?);
    let bearer_file = required("CITRATE_CLUSTER_BEARER_FILE")?;
    let bearer = fs::read_to_string(&bearer_file)
        .map_err(|e| format!("reading bearer file {bearer_file}: {e}"))?
        .trim()
        .to_string();
    if bearer.is_empty() {
        return Err("bearer file is empty (fail closed)".into());
    }
    let self_addr = required("CITRATE_CLUSTER_SELF_ADDR")?;
    if cluster_core::canonical_address(&self_addr).is_none() {
        return Err("CITRATE_CLUSTER_SELF_ADDR is not a 20-byte hex address".into());
    }

    // Transport selection: real libp2p mesh when a listen addr is configured, else single-node
    // in-process. Both slot behind the same MeshTransport seam — the daemon logic is identical.
    if env::var("CITRATE_CLUSTER_LISTEN").is_ok() {
        // Pre-validate the libp2p env here so the lazy per-group factory's `expect` never fires on
        // bad config — fail closed at startup with a clear message instead.
        Libp2pTransport::config_from_env().map_err(|e| format!("libp2p transport config: {e}"))?;
        let daemon = ClusterDaemon::new(self_addr, Libp2pTransport::from_env);
        server::serve(daemon, &socket, &bearer)?;
    } else {
        let daemon = ClusterDaemon::new(self_addr, InProcessTransport::new);
        server::serve(daemon, &socket, &bearer)?;
    }
    Ok(())
}
