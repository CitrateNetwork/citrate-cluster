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

/// PBA-L6b-020: the most CIDs a group's co-pinned shared set holds. Past this, newly received co-pins
/// are dropped and a local `ShareFile` of a new CID is refused, so a flooding peer cannot grow the
/// daemon's memory (or the `Status` line) without bound. `SharedFiles` pages through the set.
pub const MAX_SHARED_FILES: usize = 4096;

/// PBA-L6b-020: the largest page `SharedFiles` returns in one response.
pub const MAX_SHARED_FILES_PAGE: usize = 1024;

/// CL-B-007: refuse to read a secret file (the seed, the bearer) unless it is `0600` and owned by the
/// daemon's own uid. A packaging bug, a `umask 0` service manager, or a client that writes the file
/// before `chmod`-ing it otherwise leaves the 32-byte cluster identity secret (or the bearer)
/// readable by every local user while the daemon starts happily and reports healthy. Fails closed.
#[cfg(unix)]
pub fn assert_secure_file(path: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).map_err(|e| format!("stat secret file {path}: {e}"))?;
    let mode = md.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "secret file {path} is group/world-accessible (mode {mode:04o}); it must be 0600 — fail closed"
        ));
    }
    let euid = unsafe { libc::geteuid() };
    if md.uid() != euid {
        return Err(format!(
            "secret file {path} is owned by uid {} not the daemon's uid {euid} — fail closed",
            md.uid()
        ));
    }
    Ok(())
}

/// Non-unix fallback: no POSIX mode/owner to check.
#[cfg(not(unix))]
pub fn assert_secure_file(_path: &str) -> Result<(), String> {
    Ok(())
}

/// The daemon: this node's address + a session per group.
pub struct ClusterDaemon<T: MeshTransport> {
    /// This node's canonical member address (its comms/cluster identity — the gossipsub sender).
    self_address: String,
    /// Factory for a fresh per-group transport (the libp2p impl opens a swarm per group topic).
    make_transport: fn() -> T,
    /// CL-B-002: when `Some(g)`, this daemon is pinned to the single group `g` and REFUSES every
    /// other group id. The libp2p transport factory (`fn() -> T`) carries no group id, so a second
    /// group would silently build another swarm bound to the SAME env-configured topic, port and
    /// PeerId while judging peers against a different roster — a silent mesh mis-wiring. The daemon
    /// is documented "one group per daemon in S1"; this enforces that constraint fail-closed rather
    /// than relying on the client to honour it. `None` for the single-node in-process transport,
    /// which has no wire and no such constraint.
    single_group: Option<String>,
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
            single_group: None,
            groups: HashMap::new(),
            shared_files: HashMap::new(),
        }
    }

    /// Like [`new`](Self::new) but pins the daemon to a single group id (CL-B-002): every operation
    /// addressing a different group is refused with an explicit error, so the libp2p transport — whose
    /// `fn() -> T` factory carries no group id — can never silently build a second swarm on the same
    /// configured topic/port/PeerId. `main.rs` uses this for the libp2p path (`CITRATE_CLUSTER_GROUP`).
    pub fn new_single_group(
        self_address: impl Into<String>,
        make_transport: fn() -> T,
        group: impl Into<String>,
    ) -> Self {
        ClusterDaemon {
            single_group: Some(group.into()),
            ..Self::new(self_address, make_transport)
        }
    }

    /// Fail closed if `group` is not the daemon's pinned single group (CL-B-002). A no-op when the
    /// daemon is not group-pinned (the in-process transport).
    fn ensure_group_allowed(&self, group: &str) -> Result<(), String> {
        match &self.single_group {
            Some(g) if g != group => Err(format!(
                "this daemon serves only group {g:?} (libp2p one-group-per-daemon, S1); refusing group {group:?}"
            )),
            _ => Ok(()),
        }
    }

    /// CL-B-005: reconcile a group's `admitted` set to what the transport has actually meshed, so the
    /// runtime admission predicates stay truthful on the libp2p path (where admission happens on the
    /// wire at `identify`, not through `ClusterSession::join`). Called before every read of a group's
    /// state. No-op for an unknown group.
    fn sync_admission(&mut self, group: &str) {
        if let Some(s) = self.groups.get_mut(group) {
            s.sync_admitted_from_wire();
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
        // PBA-L6b-037: only well-formed CIDs cross into the client (whatever the transport let in).
        let messages: Vec<MeshMessage> = s
            .transport_mut()
            .drain()
            .into_iter()
            .filter(|m| cluster_core::is_valid_cid(&m.data))
            .collect();
        if !messages.is_empty() {
            let set = self.shared_files.entry(group.to_string()).or_default();
            for m in &messages {
                // PBA-L6b-020: bounded — past the cap a new CID is dropped (known ones are no-ops).
                if set.len() < MAX_SHARED_FILES {
                    set.insert(m.data.clone());
                }
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
    ///
    /// PBA-L6b-005: `reconcile` only evicts peers in `admitted`, and on the libp2p path a peer that is
    /// offline at revoke time is never in `admitted` — so it used to stay in the transport's
    /// authorized set and could reconnect, publish and read the topic. We therefore diff the allowed
    /// set before/after and DE-AUTHORIZE (transport `disconnect`) every address that left it, online
    /// or not, keeping the transport's authorized set equal to `allowed` (offboarding guarantee).
    pub fn set_roster(
        &mut self,
        group: &str,
        roster: &[(String, String)],
    ) -> Result<Vec<String>, String> {
        self.ensure_group_allowed(group)?;
        let session = self.ensure_session(group);
        let before: BTreeSet<String> = session.membership().allowed().into_iter().collect();
        let evicted = session.reconcile(roster);
        let allowed = session.membership().allowed();
        let after: BTreeSet<&String> = allowed.iter().collect();
        for removed in before.iter().filter(|a| !after.contains(a)) {
            session.transport_mut().disconnect(removed);
        }
        for addr in &allowed {
            session.transport_mut().authorize(addr);
        }
        Ok(evicted)
    }

    /// This node joins the group's mesh. The real transport begins listening + dialing peers here;
    /// for now it ensures the group's session exists so subsequent ops address it.
    pub fn join(&mut self, group: &str) -> Result<(), String> {
        self.ensure_group_allowed(group)?;
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
        self.sync_admission(group);
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
    pub fn peers(&mut self, group: &str) -> Vec<PeerView> {
        self.sync_admission(group);
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

    /// Announce a shared file (co-pin) to the group over the mesh. Unknown group, a malformed CID
    /// (PBA-L6b-037) or a full shared set (PBA-L6b-020) → `Err`, and nothing is published.
    pub fn share_file(&mut self, group: &str, cid: &str) -> Result<(), String> {
        let from = self.self_address.clone();
        let Some(s) = self.groups.get_mut(group) else {
            return Err(format!("not in group {group}"));
        };
        if !cluster_core::is_valid_cid(cid) {
            return Err("not a well-formed CID".to_string());
        }
        let set = self.shared_files.entry(group.to_string()).or_default();
        if !set.contains(cid) && set.len() >= MAX_SHARED_FILES {
            return Err(format!(
                "shared file set for {group} is full ({MAX_SHARED_FILES} CIDs)"
            ));
        }
        s.transport_mut().publish(&from, cid);
        set.insert(cid.to_string());
        Ok(())
    }

    /// PBA-L6b-020: one page of a group's co-pinned shared set (sorted), plus the set's total size,
    /// so a client can walk a large set without one unbounded response. `limit` is clamped to
    /// [`MAX_SHARED_FILES_PAGE`]. Drains newly-received co-pins first, like `status()`.
    pub fn shared_files_page(
        &mut self,
        group: &str,
        offset: usize,
        limit: usize,
    ) -> (Vec<String>, usize) {
        self.drain_into_shared(group);
        let Some(set) = self.shared_files.get(group) else {
            return (Vec::new(), 0);
        };
        let page = set
            .iter()
            .skip(offset)
            .take(limit.min(MAX_SHARED_FILES_PAGE))
            .cloned()
            .collect();
        (page, set.len())
    }

    /// Drain received mesh messages for a group, accumulating each into the group's co-pinned set
    /// (so `Status.sharedFiles` sees them) while still returning the raw messages. Unknown group →
    /// `[]`.
    pub fn poll(&mut self, group: &str) -> Vec<MeshMessage> {
        self.sync_admission(group);
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
