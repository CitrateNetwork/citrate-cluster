---
created: 2026-08-28T00:00:00Z
branch: main
author: Saul + Claude Opus 4.8
status: planset (Stage-1 draft)
planset: citrate-cluster
code: CL
---

# Sprints & work packages

| Sprint | Goal | Deps | Files | Effort | Status |
|--------|------|------|-------|--------|--------|
| **CL-S0** Admission core + daemon skeleton + CI | The RBAC engine + the UDS/IPC sidecar shell + green CI | — | `cluster-core/*`, `cluster-daemon/{ipc,server,lib,transport}.rs`, `.github/workflows/ci.yml` | L | ✅ done |
| **CL-S1** libp2p transport | Noise + gossipsub `MeshTransport`; per-group topic; peer id bound to the member secp256k1 key; admission enforced on connect/accept | CL-S0 | `cluster-daemon` (`transport` libp2p impl), `Cargo.toml` | XL | ✅ done |
| **CL-S2** co-pin + citrate-core wiring | Shared-file (co-pin) announcements fan out over the mesh; citrate-core spawns + drives the daemon (UDS), rosters from the comms daemon | CL-S1 | `cluster-daemon` (share/poll), citrate-core `cluster.rs`/bridge | L | 🟡 daemon side done; citrate-core wiring open |
| **CL-S3** soak ladder + honest ceiling | Multi-node soak 50→200→500→2000; ship the ceiling that actually holds (RT-3) | CL-S1 | `scripts/soak.sh`, `05`/`gates` | XL | after S1 |
| **CL-S4** security + audit prep | @rule8 sign-off on the transport; threat model; federation manifest pin | CL-S1 | audit docs, `manifest.toml` | M | after S1 |

## CL-S0 — what shipped (done)

- **`cluster-core`** (pure, no libp2p/tokio): `allowed_peers` / `allowed_set` (role-gated),
  `ClusterMembership` (admit/leave/reconcile-evict, invariant `admitted ⊆ allowed`),
  `ClusterTransport` seam, `ClusterSession` (admit→dial, evict→disconnect, `connected ⊆ admitted`).
  16 tests. `formal/ClusterAdmission.tla` models the invariant.
- **`cluster-daemon`**: `ClusterDaemon` (per-group sessions), the `MeshTransport` trait +
  `InProcessTransport` (single-node), the loopback **UDS bearer-authed JSON IPC** (`ipc.rs` +
  `server.rs`) — the exact contract citrate-core speaks. 9 tests (admission on connect, offboard
  eviction, status/peers, IPC + server round-trip, wrong-bearer rejection).
- **CI**: fmt + clippy `-D warnings` + `cargo test --workspace --locked` + release build.

Single-node today: **real admission, no cross-machine fan-out** (that is CL-S1). Honest by
construction — a lone node reports `online: 0`.

## CL-S1 — the libp2p transport (done)

Shipped `crates/cluster-daemon/src/libp2p_transport.rs`: `Libp2pTransport` implements `MeshTransport`
over a real libp2p swarm (TCP + Noise + yamux + gossipsub + identify), adapting the compute-pool
pattern (CL-4). Behind the frozen seam — `cluster-core`, `lib.rs`, `ipc.rs`, `server.rs` orchestration
unchanged (only a one-line `pub mod` in `lib.rs` + transport selection in `main.rs`).

- **One topic per group** (`topic = group_id`).
- **Peer identity = the member secp256k1 key (CL-2)**: the libp2p keypair/`PeerId` and the wallet
  address both derive from the same key; the swarm reads the 32-byte secret from a **0600 seed file**
  (`CITRATE_CLUSTER_SEED_FILE`, never argv/env).
- **Admission on the wire**: on the `identify` handshake the transport resolves the peer's address
  from its authenticated public key and **drops the connection if the address is not in cluster-core's
  authorized set** (relayed via the `dial`/`disconnect` the daemon already drives — no policy
  duplicated). A receive-side authorized-source check backstops the connect→identify window. So
  `connected ⊆ admitted ⊆ allowed` holds on the wire.
- **Sync-over-async bridge**: a dedicated tokio runtime + a background swarm task + channels/shared
  state, mirroring the comms `WsRelay`. The sync `MeshTransport` surface is unchanged.
- **`main.rs`**: selects libp2p when `CITRATE_CLUSTER_LISTEN` is set (else `InProcessTransport`), env
  pre-validated at startup.

**Tests (local green — CI is dark/billing-capped, local is the gate):** 28 workspace tests
(was 25). New: `two_nodes_form_mesh_and_exchange_a_group_message` (two swarms on `127.0.0.1:0`, real
gossipsub delivery, sender resolved from the key), `an_unauthorized_inbound_peer_is_refused_on_the_wire`,
`self_address_is_derived_from_the_secp256k1_seed`. `fmt`/`clippy -D warnings` clean; `cluster-core`
stays pure (no libp2p/tokio).

**Honest gaps (scoped as follow-ons, not faked):**
- Loopback proves the stack; a genuine two-machine soak + honest ceiling is **CL-S3**; NAT
  traversal/relay/discovery are out-of-scope follow-ons (only static bootstrap multiaddrs today).
- **One group per daemon process**: the `fn() -> T` factory carries no group id, so a libp2p daemon
  serves one `CITRATE_CLUSTER_GROUP`/`CITRATE_CLUSTER_LISTEN`. Multi-group needs a per-group config
  channel through that seam (S2).
- **Authorize-before-connect**: admission is decided at `identify`; a peer connecting before it is
  authorized is dropped and must redial (re-admit-on-authorization-change is a possible S2 refinement).
- Relayed (not-yet-identified) message sources are dropped — fine for a small fully-connected mesh.

**TLA+**: the transport preserves `connected ⊆ admitted` (it only marks connected on an authorized
identify and removes on disconnect/deauthorize), so no new state was added to `ClusterAdmission`. A
`Connecting` phase model is deferred to the CL-S4 security pass.

## CL-S2 — co-pin shared-file set (daemon side done)

The group's **shared file set** is now real on the daemon side. Before, `ShareFile{group,cid}` fanned
out over the transport and `Poll` drained received messages, but nothing accumulated the group's
co-pinned CID set — so a client's `ClusterStatus.sharedFiles` had no source. Added that accumulation
in `cluster-daemon` only; `cluster-core` stays pure, the UDS server and admission logic are untouched.

- **Per-group co-pinned set**: `ClusterDaemon` keeps a `BTreeSet<String>` per group (sorted+deduped).
- **On `ShareFile{group,cid}`**: `cid` is added to that group's set, in addition to the existing
  `transport.publish` fan-out.
- **On received mesh messages**: each `MeshMessage.data` (a peer's shared CID) is added to the set.
  The daemon is request-driven (no background loop), so it **drains the transport into the shared set
  at the start of `status()`** (and `poll()` reuses the same drain, so `Poll` still returns the raw
  messages). `Status` is the co-pin source of truth: a received co-pin shows up in the next
  `Status.sharedFiles`.
- **Contract change (additive)**: `ipc::Response::Status` gains `sharedFiles: Vec<String>` (serde
  `#[rename = "sharedFiles"]`, Rust field `shared_files`) — `Status { online, total, sharedFiles }`.
  `online`/`total` are unchanged. A citrate-core client is being written against this in parallel.
  `ClusterDaemon::status` now returns `(usize, usize, Vec<String>)` (drains first); unknown group →
  `(0, 0, [])`. `leave` also forgets the group's shared set so a re-join starts clean.

**Tests (local green — CI is dark/billing-capped, local is the gate):** 30 workspace tests (was 28).
New: `share_file_adds_the_cid_to_status_shared_files` (own co-pin is in the set, idempotent),
`a_received_co_pin_shows_up_in_the_next_status_shared_files` (drain-on-status accumulates a peer's
co-pin injected via the in-process transport's `deliver` hook; mixed set stays sorted+deduped). The
existing daemon test that matches `Response::Status`/`status()` was updated for the new field/tuple.
`fmt`/`clippy -D warnings` clean; `cluster-core` stays pure (no libp2p/tokio).

**Still open (the other half of CL-S2):** the **citrate-core wiring** — spawning + driving the daemon
over UDS, feeding rosters from the comms daemon, and surfacing `sharedFiles` in the client's
`ClusterStatus`. That lives in citrate-core (`cluster.rs`/bridge), tracked as gate2 `g2-wiring`, and is
a separate change. Multi-group-per-process and re-admit-on-authorization-change (noted under CL-S1
gaps) remain follow-ons.
