//! citrate-cluster daemon — the library.
//!
//! Owns one [`cluster_core::ClusterSession`] per group (the admission gate + the transport), and maps
//! the loopback JSON IPC ([`ipc`]) onto it. The daemon never re-derives group membership — the client
//! feeds the roster (which comes from the comms daemon) via `SetRoster`, and the daemon reconciles
//! the mesh: it evicts newly-unauthorized peers and admits a peer only when the transport reports it
//! connected AND cluster-core admits it. The RBAC→network boundary is enforced HERE, on every
//! connection, by [`cluster_core`] — the transport can never mesh a peer the roster does not allow.

use std::collections::{BTreeSet, HashMap};

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
    /// Per-group co-pinned shared file set: this node's `ShareFile` announcements plus every CID
    /// received from a peer over the mesh, sorted+deduped. The source of truth for
    /// `Status.sharedFiles`. Drained-into on `status()`/`poll()` (the daemon is request-driven).
    shared_files: HashMap<String, BTreeSet<String>>,
}

impl<T: MeshTransport> ClusterDaemon<T> {
    pub fn new(self_address: impl Into<String>, make_transport: fn() -> T) -> Self {
        ClusterDaemon {
            self_address: cluster_core::canonical_address(&self_address.into()).unwrap_or_default(),
            make_transport,
            groups: HashMap::new(),
            shared_files: HashMap::new(),
        }
    }

    /// Drain the group's transport inbox into its co-pinned shared set (each received
    /// `MeshMessage.data` is a peer's shared CID), returning the raw messages. The daemon has no
    /// background loop, so this is called on `status()`/`poll()` — the only points a client reads
    /// the mesh. Unknown group → `[]`.
    fn drain_into_shared(&mut self, group: &str) -> Vec<MeshMessage> {
        let Some(s) = self.groups.get_mut(group) else {
            return Vec::new();
        };
        let messages = s.transport_mut().drain();
        if !messages.is_empty() {
            let set = self.shared_files.entry(group.to_string()).or_default();
            for m in &messages {
                set.insert(m.data.clone());
            }
        }
        messages
    }

    fn ensure_session(&mut self, group: &str) -> &mut ClusterSession<T> {
        let make = self.make_transport;
        self.groups
            .entry(group.to_string())
            .or_insert_with(|| ClusterSession::new(&[], make()))
    }

    /// Set/update a group's roster: reconcile the mesh (recompute the allowed set + evict every
    /// admitted peer no longer allowed, in one step), then AUTHORIZE every role-gated roster peer in
    /// the transport so its inbound connection is admitted at the identify handshake (the "authorize
    /// before connect" ordering — without this the mesh drops every peer as unauthorized). Authorize
    /// opens no socket and is a no-op for the single-node in-process transport. Returns the evicted.
    pub fn set_roster(
        &mut self,
        group: &str,
        roster: &[(String, String)],
    ) -> Result<Vec<String>, String> {
        let session = self.ensure_session(group);
        let evicted = session.reconcile(roster);
        let allowed = session.membership().allowed();
        for addr in &allowed {
            session.transport_mut().authorize(addr);
        }
        Ok(evicted)
    }

    /// This node joins the group's mesh. The real transport begins listening + dialing peers here;
    /// for now it ensures the group's session exists so subsequent ops address it.
    pub fn join(&mut self, group: &str) -> Result<(), String> {
        self.ensure_session(group);
        Ok(())
    }

    /// This node leaves the group's mesh (drop the session; the transport tears down on drop). Also
    /// forgets the group's co-pinned shared set so a later re-join starts clean.
    pub fn leave(&mut self, group: &str) {
        self.groups.remove(group);
        self.shared_files.remove(group);
    }

    /// `(connected, authorized, sharedFiles)` for a group. Drains any newly-received mesh messages
    /// into the group's co-pinned set first (the daemon is request-driven), so a co-pin received
    /// since the last read shows up here. `sharedFiles` is sorted+deduped. Unknown group →
    /// `(0, 0, [])`.
    pub fn status(&mut self, group: &str) -> (usize, usize, Vec<String>) {
        self.drain_into_shared(group);
        match self.groups.get(group) {
            Some(s) => {
                let shared = self
                    .shared_files
                    .get(group)
                    .map(|set| set.iter().cloned().collect())
                    .unwrap_or_default();
                (
                    s.transport().connected().len(),
                    s.membership().allowed().len(),
                    shared,
                )
            }
            None => (0, 0, Vec::new()),
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
                self.shared_files
                    .entry(group.to_string())
                    .or_default()
                    .insert(cid.to_string());
                Ok(())
            }
            None => Err(format!("not in group {group}")),
        }
    }

    /// Drain received mesh messages for a group, accumulating each into the group's co-pinned set
    /// (so `Status.sharedFiles` sees them) while still returning the raw messages. Unknown group →
    /// `[]`.
    pub fn poll(&mut self, group: &str) -> Vec<MeshMessage> {
        self.drain_into_shared(group)
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
