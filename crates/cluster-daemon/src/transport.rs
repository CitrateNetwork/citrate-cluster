//! The daemon's mesh transport: [`cluster_core::ClusterTransport`] (the connection seam the admission
//! lifecycle drives) PLUS gossipsub-style publish/drain for the group topic.
//!
//! [`InProcessTransport`] is the single-node/loopback impl — real connection bookkeeping, but no
//! cross-machine fan-out (a lone node has no peers to deliver to). The **libp2p** impl (TCP with a
//! Noise/gossipsub stack, one topic per group, reusing the compute-pool transport pattern) is the
//! next sprint (planset CL-S1); it slots in behind this same trait, so the daemon logic never changes.

use std::collections::BTreeSet;

use cluster_core::ClusterTransport;

use crate::ipc::MeshMessage;

/// The transport the daemon drives: connection lifecycle + topic publish/drain.
pub trait MeshTransport: ClusterTransport {
    /// Publish a message to the group topic (fans out to connected peers over the real transport).
    fn publish(&mut self, from: &str, data: &str);
    /// Drain messages received from peers since the last poll.
    fn drain(&mut self) -> Vec<MeshMessage>;
    /// Authorize an address to mesh — it will be ADMITTED at the identify handshake — WITHOUT opening
    /// a socket or marking it connected. The daemon calls this for every role-gated roster peer on
    /// `SetRoster` so an inbound connection is not dropped as unauthorized (the "authorize before
    /// connect" ordering). The libp2p transport adds it to its authorized set; the single-node
    /// in-process transport has no mesh, so this is a NO-OP (keeps `online` honest — never fabricated).
    fn authorize(&mut self, addr: &str);
    /// HUP-S8.4: dial peers named by a group seed (link or QR) and keep them for re-dial. Returns how
    /// many addresses were accepted. A seed carries locations only: every resulting connection is
    /// still admitted (or dropped) at the identify handshake. A transport with no network refuses.
    fn add_peers(&mut self, addrs: &[String]) -> Result<usize, String>;
    /// HUP-S8.4: the addresses another machine can dial this node on for this group, each naming
    /// this node's peer id (what a group seed carries). A transport with no network refuses.
    fn seed_addrs(&self) -> Result<Vec<String>, String>;
}

/// The honest answer of a transport with no cross-machine mesh to a seed request.
pub const NO_MESH: &str =
    "this node runs without the cross-machine mesh, so it has no address to share or dial";

/// Single-node / loopback transport. Tracks who is "connected" (so the admission lifecycle + status
/// are exercisable end to end) and holds an inbox. With no real peers, `publish` has nowhere to fan
/// out and `drain` is empty — honest for one node; the libp2p impl delivers across machines.
#[derive(Debug, Default)]
pub struct InProcessTransport {
    connected: BTreeSet<String>,
    inbox: Vec<MeshMessage>,
}

impl InProcessTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test/seam hook: inject a message as if received from a peer (the libp2p impl fills the inbox
    /// from gossipsub delivery).
    pub fn deliver(&mut self, from: &str, data: &str) {
        self.inbox.push(MeshMessage {
            from: from.to_string(),
            data: data.to_string(),
        });
    }
}

impl ClusterTransport for InProcessTransport {
    fn dial(&mut self, peer: &str) {
        self.connected.insert(peer.to_string());
    }
    fn disconnect(&mut self, peer: &str) {
        self.connected.remove(peer);
    }
    fn connected(&self) -> Vec<String> {
        self.connected.iter().cloned().collect()
    }
}

impl MeshTransport for InProcessTransport {
    fn publish(&mut self, _from: &str, _data: &str) {
        // Single node: no peers to fan out to. The libp2p impl gossipsub-publishes to the topic.
    }
    fn drain(&mut self) -> Vec<MeshMessage> {
        std::mem::take(&mut self.inbox)
    }
    fn authorize(&mut self, _addr: &str) {
        // Single node: no mesh, nothing to authorize. `online` stays 0 (honest).
    }
    fn add_peers(&mut self, _addrs: &[String]) -> Result<usize, String> {
        Err(NO_MESH.to_string())
    }
    fn seed_addrs(&self) -> Result<Vec<String>, String> {
        Err(NO_MESH.to_string())
    }
}
