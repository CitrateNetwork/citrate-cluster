---
created: 2026-08-28T00:00:00Z
branch: main
author: Saul + Claude Opus 4.8
status: accepted
adr: 001
---

# ADR-001 — Hybrid P2P cluster: libp2p Noise identity + gossipsub fan-out (D-24)

## Context

A Citrate Group needs a private peer-to-peer mesh among its members (file co-pinning now, compute
later). Two things must be true: (1) peers are cryptographically identified and their traffic
encrypted, and (2) messages fan out to many members without every peer flooding every other — the
only shape with a shot at the 2000-member ambition (RT-3).

## Decision

**Hybrid, both from libp2p:**

- **Noise** is the cryptographic identity + transport encryption. A member's libp2p `PeerId` is
  derived from the **same secp256k1 key** as its comms identity and wallet address (CL-2) — no fresh
  keyring, so `WalletAddress = comms id = cluster Noise id`. Admission maps a connecting peer to its
  address and checks it against the role-gated roster.
- **gossipsub** is the fan-out, one topic per group (`topic = group_id`). Mesh (not flood) routing is
  what makes larger groups feasible; the achievable ceiling is set by a soak ladder, not asserted
  (CL-5 / RT-3).
- Transport stack: TCP + Noise + yamux + gossipsub, **reusing the proven pattern** in
  `citrate-compute-pool/training-worker/libp2p_transport.rs` (CL-4), adapted from per-job to
  per-group topics.

The mesh membership boundary is enforced by `cluster-core` (admission), which is transport-agnostic:
the libp2p layer calls `ClusterDaemon::admit_peer` on connect and **drops the connection if not
admitted**. The invariant `connected ⊆ admitted ⊆ allowed` holds regardless of transport.

## Alternatives considered

- **Flood/broadcast** — simple but does not scale past small groups; rejected for the fan-out role.
- **A bespoke transport** — reinvents Noise/gossipsub and forfeits the reviewed compute-pool code.
- **Fresh per-cluster keys** — a new keyring + a binding attestation for no benefit; the member key
  already identifies the peer.

## Consequences

- libp2p is heavy (tokio, the swarm stack) — hence the **sidecar** decision (CL-1): it lives in
  `cluster-daemon`, never in citrate-core's lean tree. `cluster-core` stays pure so lean clients link
  the admission logic without the networking.
- Peer identity is only as strong as the member key custody (device-sealed, per the comms model).
- The honest scale ceiling is a deliverable (CL-S3), not a marketing number.
