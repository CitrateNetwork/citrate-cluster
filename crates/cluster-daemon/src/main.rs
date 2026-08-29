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
//! The libp2p transport (Noise identity + gossipsub, listen addr + bootstrap peers) is CL-S1; until
//! then the daemon runs the in-process transport (single node — real admission, no cross-machine
//! fan-out). Its env knobs (CITRATE_CLUSTER_LISTEN, seed) land with that sprint.

use std::env;
use std::fs;
use std::path::PathBuf;

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

    // CL-S1 swaps InProcessTransport for the libp2p (Noise + gossipsub) transport behind the same
    // MeshTransport trait — the daemon logic below does not change.
    let daemon = ClusterDaemon::new(self_addr, InProcessTransport::new);
    server::serve(daemon, &socket, &bearer)?;
    Ok(())
}
