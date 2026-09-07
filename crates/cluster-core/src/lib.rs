//! # cluster-core — the RBAC→network admission core
//!
//! A Citrate Group's cluster is a private P2P mesh among its members. The one property the whole
//! design exists to guarantee is: **no unauthorized peer is ever in the mesh.** This crate is that
//! guarantee, as pure, `no-libp2p`, `no-tokio` logic so it can be reused by both the `cluster-daemon`
//! (which drives a real libp2p transport over it) and lean clients (citrate-core, which links this
//! crate directly without pulling the networking tree).
//!
//! Three layers, smallest to largest:
//! 1. [`allowed_peers`] / [`allowed_set`] — the roster → authorized-address derivation (role-gated).
//! 2. [`ClusterMembership`] — the admit / leave / reconcile-evict state machine, invariant
//!    `admitted ⊆ allowed`.
//! 3. [`ClusterSession`] — binds membership to a [`ClusterTransport`]: admit→dial, evict→disconnect,
//!    so the wire never outruns the RBAC gate.
//!
//! Formal model: `formal/ClusterAdmission.tla` (the `admitted ⊆ allowed` safety invariant).

use std::collections::BTreeSet;

/// The minimum group role admitted to a cluster (D-24): a **Member**. Guests/agents below this are
/// in the group's conversation but not its compute/file mesh. Unknown roles rank lowest (fail closed).
pub const MIN_CLUSTER_RANK: u8 = 2;

/// Rank the group role vocabulary (matches the comms `Role`) so admission compares by threshold.
pub fn role_rank(role: &str) -> u8 {
    match role {
        "owner" => 5,
        "admin" => 4,
        "partner" => 3,
        "member" => 2,
        "agent" => 1,
        "guest" => 0,
        _ => 0, // unknown → lowest (never admit on an unrecognized role)
    }
}

/// Canonical form of an EVM address for the peer set: lowercase, no `0x`, exactly 40 hex chars.
/// `None` for anything that is not a well-formed 20-byte address (dropped from every set).
pub fn canonical_address(raw: &str) -> Option<String> {
    let h = raw.trim().trim_start_matches("0x").to_ascii_lowercase();
    if h.len() == 40 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(h)
    } else {
        None
    }
}

/// Derive the cluster's allowed-peer set from an **address-only** roster (the S4.1 derivation):
/// canonical, de-duplicated, sorted, non-addresses dropped — so two nodes compute a byte-identical
/// mesh membership from the same roster (the input to per-peer Noise-identity minting).
pub fn allowed_peers(roster: &[String]) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for raw in roster {
        if let Some(addr) = canonical_address(raw) {
            set.insert(addr);
        }
    }
    set.into_iter().collect()
}

/// The **role-gated** allowed set from an `(address, role)` roster: canonical addresses whose role is
/// ≥ Member. This is the admission boundary the transport enforces.
pub fn allowed_set(roster: &[(String, String)]) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for (addr, role) in roster {
        if role_rank(role) >= MIN_CLUSTER_RANK {
            if let Some(a) = canonical_address(addr) {
                set.insert(a);
            }
        }
    }
    set
}

/// Admission policy: a candidate is admitted IFF its canonical address is in the role-gated allowed
/// set. The transport enforces this before dialing / accepting a topic subscription.
pub fn admit(address: &str, allowed: &BTreeSet<String>) -> bool {
    canonical_address(address)
        .map(|a| allowed.contains(&a))
        .unwrap_or(false)
}

/// The cluster's live membership: the role-gated allowed set (from the roster) and the currently
/// admitted peers. INVARIANT (formal: ClusterAdmission): `admitted ⊆ allowed` at all times — no
/// unauthorized peer is ever meshed, and an offboard/role-drop evicts in the same step.
#[derive(Debug, Clone, Default)]
pub struct ClusterMembership {
    allowed: BTreeSet<String>,
    admitted: BTreeSet<String>,
}

impl ClusterMembership {
    /// Open a membership over a group roster `(address, role)`. No peer is admitted until it joins.
    pub fn new(roster: &[(String, String)]) -> Self {
        ClusterMembership {
            allowed: allowed_set(roster),
            admitted: BTreeSet::new(),
        }
    }

    /// A candidate presents a valid owner-signed RoleAssertion (verified upstream → we get its
    /// `(address, role)`). Admit IFF the policy passes. Returns whether it was admitted. Idempotent.
    pub fn join(&mut self, address: &str, role: &str) -> bool {
        if role_rank(role) < MIN_CLUSTER_RANK {
            return false;
        }
        match canonical_address(address) {
            Some(a) if self.allowed.contains(&a) => {
                self.admitted.insert(a);
                true
            }
            _ => false,
        }
    }

    /// A peer leaves or is dropped. Idempotent.
    pub fn leave(&mut self, address: &str) {
        if let Some(a) = canonical_address(address) {
            self.admitted.remove(&a);
        }
    }

    /// Reconcile against a new roster (offboard / role change): recompute the allowed set and EVICT
    /// every admitted peer no longer allowed IN THE SAME STEP (the offboard safety property — no
    /// window where a removed member is still meshed). Returns the evicted peers (canonical).
    pub fn reconcile(&mut self, roster: &[(String, String)]) -> Vec<String> {
        self.allowed = allowed_set(roster);
        let evicted: Vec<String> = self
            .admitted
            .iter()
            .filter(|a| !self.allowed.contains(*a))
            .cloned()
            .collect();
        for e in &evicted {
            self.admitted.remove(e);
        }
        evicted
    }

    /// The currently-admitted peers (canonical addresses), sorted.
    pub fn admitted(&self) -> Vec<String> {
        self.admitted.iter().cloned().collect()
    }

    /// The role-gated allowed peers (canonical), sorted.
    pub fn allowed(&self) -> Vec<String> {
        self.allowed.iter().cloned().collect()
    }

    /// Whether `address` is currently admitted.
    pub fn is_admitted(&self, address: &str) -> bool {
        canonical_address(address)
            .map(|a| self.admitted.contains(&a))
            .unwrap_or(false)
    }

    /// The safety invariant, checkable at runtime + asserted in tests: `admitted ⊆ allowed`.
    pub fn invariant_holds(&self) -> bool {
        self.admitted.is_subset(&self.allowed)
    }

    /// Reconcile the admitted set to `candidates ∩ allowed`. Used by a transport that admits peers on
    /// the wire (the libp2p path) through its own authorized-set gate rather than through [`join`],
    /// so the runtime predicates ([`is_admitted`](Self::is_admitted),
    /// [`ClusterSession::wire_tracks_admitted`]) reflect reality instead of a permanently-empty
    /// `admitted`. Intersecting with `allowed` preserves the safety invariant `admitted ⊆ allowed`
    /// by construction — this can never admit a peer the roster does not allow. (CL-B-005)
    pub fn sync_admitted(&mut self, candidates: &BTreeSet<String>) {
        self.admitted = candidates
            .iter()
            .filter(|a| self.allowed.contains(*a))
            .cloned()
            .collect();
    }
}

/// The cluster's network transport — the seam the membership lifecycle drives. `dial` opens a Noise
/// session + joins the peer to the group's gossipsub topic; `disconnect` tears it down. Both are
/// idempotent. The `cluster-daemon` implements this over libp2p; tests use an in-process double.
pub trait ClusterTransport {
    fn dial(&mut self, peer: &str);
    fn disconnect(&mut self, peer: &str);
    fn connected(&self) -> Vec<String>;
}

/// Binds a [`ClusterMembership`] to a [`ClusterTransport`]: admit → dial, leave/evict → disconnect,
/// so the wire state always tracks the admitted set (which tracks the roster — the RBAC→network
/// boundary end to end). INVARIANT: `connected ⊆ admitted` — the transport cannot outrun the gate.
pub struct ClusterSession<T: ClusterTransport> {
    membership: ClusterMembership,
    transport: T,
}

impl<T: ClusterTransport> ClusterSession<T> {
    pub fn new(roster: &[(String, String)], transport: T) -> Self {
        ClusterSession {
            membership: ClusterMembership::new(roster),
            transport,
        }
    }

    /// A candidate joins: admit per policy, and on success DIAL it. Returns whether admitted.
    pub fn join(&mut self, address: &str, role: &str) -> bool {
        let admitted = self.membership.join(address, role);
        if admitted {
            if let Some(a) = canonical_address(address) {
                self.transport.dial(&a);
            }
        }
        admitted
    }

    /// A peer leaves: drop membership + disconnect the wire.
    pub fn leave(&mut self, address: &str) {
        self.membership.leave(address);
        if let Some(a) = canonical_address(address) {
            self.transport.disconnect(&a);
        }
    }

    /// Roster changed: reconcile membership and DISCONNECT every evicted peer in the same step.
    pub fn reconcile(&mut self, roster: &[(String, String)]) -> Vec<String> {
        let evicted = self.membership.reconcile(roster);
        for e in &evicted {
            self.transport.disconnect(e);
        }
        evicted
    }

    pub fn membership(&self) -> &ClusterMembership {
        &self.membership
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Reconcile `admitted` to the transport's live `connected` set (intersected with `allowed`)
    /// WITHOUT touching the wire — it only records what the transport already admitted through its
    /// own on-wire authorized-set gate. On the libp2p path admission is decided at the `identify`
    /// handshake (not through [`join`](Self::join)), so without this the `admitted` set stays empty
    /// while peers are meshed and [`is_admitted`](ClusterMembership::is_admitted) /
    /// [`wire_tracks_admitted`](Self::wire_tracks_admitted) report false answers. The daemon calls
    /// this before every read of the membership state so those predicates never lie. Because it
    /// intersects with `allowed`, the invariant `admitted ⊆ allowed` is preserved. (CL-B-005)
    pub fn sync_admitted_from_wire(&mut self) {
        let connected: BTreeSet<String> = self.transport.connected().into_iter().collect();
        self.membership.sync_admitted(&connected);
    }

    /// Whether the wire never contains an unadmitted peer (`connected ⊆ admitted`) — the safety
    /// property the transport must preserve.
    pub fn wire_tracks_admitted(&self) -> bool {
        let admitted: BTreeSet<String> = self.membership.admitted().into_iter().collect();
        self.transport
            .connected()
            .iter()
            .all(|p| admitted.contains(p))
    }
}

#[cfg(test)]
mod tests;
