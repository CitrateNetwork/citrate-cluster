---
created: 2026-08-28T00:00:00Z
branch: main
author: Saul + Claude Opus 4.8
status: planset (Stage-1 draft)
planset: citrate-cluster
code: CL
repo: citrate-cluster (+ consumed by citrate-core; rosters from citrate-comms)
companions: 05_SPRINTS_AND_WPS.md, gates.yaml, adr/ADR-001-hybrid-p2p-cluster.md
---

# citrate-cluster — overview

## Why this exists

A Citrate **Group** (the comms room) needs more than chat: its members want a **private cluster** —
a direct peer-to-peer mesh to share files (co-pinning) and, later, compute. That mesh must admit
**only** the group's members, track the roster as it changes (an offboarded member is off the mesh
instantly), and carry its own weight as a composable federation service rather than bloating a client.

Extracted from citrate-core's CX-S4 (Lane E), where the admission logic (`allowed_peers`,
`ClusterMembership`, the transport seam) was built and tested. Its rightful home is a standalone
Tier-1 repo — libp2p is too heavy to link into citrate-core's lean tree, exactly as MLS was for
comms, so the mesh lives in a sidecar with a lean client, and the pure admission engine is a crate
both can share.

## Locked decisions

| # | Decision | Choice | Date |
|---|----------|--------|------|
| D-24 | P2P substrate | **Hybrid**: libp2p **Noise** for peer identity/encryption + **gossipsub** for fan-out. One topic per group. (ADR-001) | 2026-08-28 |
| CL-1 | Deployment | A **sidecar daemon** (`cluster-daemon`) + a lean client link (`cluster-core`), mirroring the comms member-daemon. src-tauri never links libp2p. | 2026-08-28 |
| CL-2 | Peer identity | A member's libp2p Noise id is **bound to the same secp256k1** key as its comms identity = its wallet address. No fresh keyring: `WalletAddress = comms id = cluster Noise id`. | 2026-08-28 |
| CL-3 | Admission | `admit = address ∈ role-gated-allowed-set(roster) ∧ role ≥ Member`. The roster is fed by the client (from the comms daemon); the cluster never re-derives group membership. | 2026-08-28 |
| CL-4 | Reuse transport | The libp2p transport reuses the proven pattern in `citrate-compute-pool/training-worker/libp2p_transport.rs` (TCP + Noise + yamux + gossipsub), adapted to per-group topics. | 2026-08-28 |
| CL-5 | Scale ceiling (RT-3) | Ship an **honest** ceiling from a soak ladder (50→200→500→2000); 2000 is the ambition, not a claim, until soaked. | 2026-08-28 |

## Core invariant

**No unauthorized peer is ever in the mesh:** `admitted ⊆ allowed`, and the wire tracks it
(`connected ⊆ admitted`). An offboard or role-drop evicts + disconnects in the same step. This is the
one property the whole design exists to guarantee; it is formally modeled in
`formal/ClusterAdmission.tla` and covered by the `cluster-core` tests.

## Architecture at a glance

```
citrate-comms member-daemon ──roster──▶ citrate-core ──UDS JSON IPC──▶ cluster-daemon
                                            │ links                        │ libp2p
                                            ▼                              ▼
                                        cluster-core  ◀──shares──  Noise + gossipsub mesh
                                        (admission)                (peers = group members)
```

## Surfaces we consume / reuse

- **The roster** — `(address, role)` pairs, fed by the client (originating in the comms daemon). The
  cluster is authorization-over-roster; it does not verify RoleAssertions itself (the comms layer
  does) — it trusts the verified roster it is fed and enforces the mesh boundary from it.
- **The libp2p transport pattern** — `citrate-compute-pool/training-worker/libp2p_transport.rs`.
- **The daemon shape** — the citrate-comms member-daemon (UDS bearer-authed JSON, lean-client split).

## Scope

**In (v1):** the admission engine (`cluster-core`); the sidecar (`cluster-daemon`) with the UDS IPC +
per-group mesh; libp2p Noise + gossipsub transport; co-pin shared-file announcements over the mesh;
the soak ladder + an honest scale ceiling; CI/CD.

**Out (follow-ons):** shared **compute** over the mesh (beyond files); NAT traversal / relay for
non-loopback peers beyond the chain-derived bootstrap; a public discovery layer.

## Safety & compliance gates

- The admission invariant holds (formal + tests) — refuse to ship a transport that can mesh an
  unauthorized peer.
- Secrets (IPC bearer, Noise seed) cross as 0600 file paths, never argv/env.
- T1: a security sign-off on the transport before cross-org trust (Rule 8).

## Red-team

Stage-1 draft. The admission core is already adversarially tested (guest/stranger refusal, offboard
eviction, role-drop eviction, order-independence) and formally modeled, but the transport + scale
plan have not had a full red-team pass — hence Stage-1. Building the transport (CL-S1) on this draft
is allowed as it is reversible groundwork behind the frozen `MeshTransport` seam.
