//! citrate-cluster daemon — the library.
//!
//! Owns one [`cluster_core::ClusterSession`] per group (the admission gate + the transport), and maps
//! the loopback JSON IPC ([`ipc`]) onto it. The daemon never re-derives group membership — the client
//! feeds the roster (which comes from the comms daemon) via `SetRoster`, and the daemon reconciles
//! the mesh: it evicts newly-unauthorized peers and admits a peer only when the transport reports it
//! connected AND cluster-core admits it. The RBAC→network boundary is enforced HERE, on every
//! connection, by [`cluster_core`] — the transport can never mesh a peer the roster does not allow.

use std::collections::HashMap;

use cluster_core::ClusterSession;

pub mod ipc;
pub mod libp2p_transport;
pub mod server;
pub mod transport;

use ipc::{MeshMessage, PeerView};
use transport::MeshTransport;

/// The daemon: this node's address + a session per group.
pub struct ClusterDaemon<T: MeshTransport> {
    /// This node's canonical member address (its comms/cluster identity — the gossipsub sender).
    self_address: String,
    /// Factory for a fresh per-group transport (the libp2p impl opens a swarm per group topic).
    make_transport: fn() -> T,
    groups: HashMap<String, ClusterSession<T>>,
}

impl<T: MeshTransport> ClusterDaemon<T> {
    pub fn new(self_address: impl Into<String>, make_transport: fn() -> T) -> Self {
        ClusterDaemon {
            self_address: cluster_core::canonical_address(&self_address.into()).unwrap_or_default(),
            make_transport,
            groups: HashMap::new(),
        }
    }

    fn ensure_session(&mut self, group: &str) -> &mut ClusterSession<T> {
        let make = self.make_transport;
        self.groups
            .entry(group.to_string())
            .or_insert_with(|| ClusterSession::new(&[], make()))
    }

    /// Set/update a group's roster: reconcile the mesh (recompute the allowed set + evict every
    /// admitted peer no longer allowed, in one step). Returns the evicted peers.
    pub fn set_roster(
        &mut self,
        group: &str,
        roster: &[(String, String)],
    ) -> Result<Vec<String>, String> {
        Ok(self.ensure_session(group).reconcile(roster))
    }

    /// This node joins the group's mesh. The real transport begins listening + dialing peers here;
    /// for now it ensures the group's session exists so subsequent ops address it.
    pub fn join(&mut self, group: &str) -> Result<(), String> {
        self.ensure_session(group);
        Ok(())
    }

    /// This node leaves the group's mesh (drop the session; the transport tears down on drop).
    pub fn leave(&mut self, group: &str) {
        self.groups.remove(group);
    }

    /// `(connected, authorized)` for a group. Unknown group → `(0, 0)`.
    pub fn status(&self, group: &str) -> (usize, usize) {
        match self.groups.get(group) {
            Some(s) => (
                s.transport().connected().len(),
                s.membership().allowed().len(),
            ),
            None => (0, 0),
        }
    }

    /// The group's authorized peers, each with its live connection state. Unknown group → `[]`.
    pub fn peers(&self, group: &str) -> Vec<PeerView> {
        let Some(s) = self.groups.get(group) else {
            return Vec::new();
        };
        let connected: std::collections::BTreeSet<String> =
            s.transport().connected().into_iter().collect();
        s.membership()
            .allowed()
            .into_iter()
            .map(|address| {
                let online = connected.contains(&address);
                PeerView { address, online }
            })
            .collect()
    }

    /// Announce a shared file (co-pin) to the group over the mesh. Unknown group → `Err`.
    pub fn share_file(&mut self, group: &str, cid: &str) -> Result<(), String> {
        let from = self.self_address.clone();
        match self.groups.get_mut(group) {
            Some(s) => {
                s.transport_mut().publish(&from, cid);
                Ok(())
            }
            None => Err(format!("not in group {group}")),
        }
    }

    /// Drain received mesh messages for a group. Unknown group → `[]`.
    pub fn poll(&mut self, group: &str) -> Vec<MeshMessage> {
        match self.groups.get_mut(group) {
            Some(s) => s.transport_mut().drain(),
            None => Vec::new(),
        }
    }

    // ---- hooks the transport (libp2p) calls on connection events ----

    /// A peer connected (the transport dialed/accepted it). Admit IFF cluster-core allows it (in the
    /// role-gated roster). Returns whether admitted — the transport drops the connection on `false`.
    pub fn admit_peer(&mut self, group: &str, address: &str, role: &str) -> bool {
        self.ensure_session(group).join(address, role)
    }

    /// A peer disconnected.
    pub fn drop_peer(&mut self, group: &str, address: &str) {
        if let Some(s) = self.groups.get_mut(group) {
            s.leave(address);
        }
    }

    /// This node's canonical address.
    pub fn self_address(&self) -> &str {
        &self.self_address
    }
}

#[cfg(test)]
mod daemon_tests;
