# citrate-cluster

The **group private P2P cluster** for the Citrate federation. A Citrate Group's cluster is a private
peer-to-peer mesh among the group's members: they connect directly (Noise-encrypted), fan messages
out over gossipsub, and co-pin a shared file set — with **one hard guarantee: no unauthorized peer is
ever in the mesh.**

Composable by design — it carries its own weight and depends on nothing but the roster a client feeds
it:

```
┌────────────────────────────────────────────────────────────────────┐
│ cluster-core   pure RBAC→network admission logic — NO libp2p/tokio  │
│   allowed_peers · ClusterMembership (admit/leave/reconcile-evict)   │
│   ClusterTransport seam · ClusterSession (admit→dial, evict→drop)   │
│   invariant: admitted ⊆ allowed   (formal/ClusterAdmission.tla)     │
└────────────────────────────────────────────────────────────────────┘
                   ▲ links directly                ▲ drives
         (lean clients: citrate-core)        ┌─────┴───────────────────┐
                                             │ cluster-daemon          │
                                             │  libp2p (Noise+gossipsub)│
                                             │  + loopback UDS JSON IPC │
                                             └──────────────────────────┘
```

- **`cluster-core`** — the admission engine. Pure logic, no networking, so it is reused by the daemon
  AND by lean clients (citrate-core links it without pulling libp2p). The one property everything
  hangs off — `admitted ⊆ allowed` — lives here and is formally modeled.
- **`cluster-daemon`** — the sidecar. Runs the group meshes (libp2p Noise + gossipsub) and serves a
  loopback **UDS JSON IPC** so a lean client feeds the roster and drives join/status/peers/share/poll
  without linking the networking tree (the citrate-comms member-daemon pattern).

## The boundary

The roster is the admission list. A client (citrate-core, which gets the roster from the comms
daemon) pushes it via `SetRoster`; the daemon reconciles the mesh — evicting any peer no longer
allowed **in the same step** (an offboard tears the wire down with no window) and admitting a peer
**only** when the transport reports it connected AND `cluster-core` admits it (in the role-gated
roster, role ≥ Member). The transport can never mesh a peer the roster does not allow.

## Status

- `cluster-core` + the daemon's admission/UDS/IPC layer are built and tested (single-node: real
  admission, no cross-machine fan-out yet).
- The **libp2p transport** (Noise identity bound to the member's secp256k1 key, gossipsub per-group
  topic, the soak ladder) is the next sprint — see `.agentile/planset/`. It slots behind the
  `MeshTransport` trait; the daemon logic does not change.

## Develop

```
cargo test --workspace          # 25 tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Tier 1. Part of the Citrate federation — see `.agentile/AGENT_ENTRY.md`.
