---
created: 2026-08-28T00:00:00Z
branch: main
author: Saul + Claude Opus 4.8
status: active
tier: 1
---

# citrate-cluster — agent entry

**Tier 1.** The group private P2P cluster: a Noise + gossipsub mesh among a Citrate Group's members,
gated so no unauthorized peer is ever in it. Composable — depends only on the roster a client feeds.

## Read order

1. `README.md` — what this is, the two-crate shape, the admission boundary.
2. `CLAUDE.md` — the hard rules (the admission invariant is sacred; `cluster-core` stays pure).
3. `.agentile/planset/00_OVERVIEW.md` — vision, locked decisions (D-24 hybrid), the core invariant.
4. `.agentile/planset/05_SPRINTS_AND_WPS.md` — the WP plan (what is built; what is next).
5. `.agentile/planset/gates.yaml` — machine-checkable exit criteria.
6. The code: `crates/cluster-core/src/lib.rs` (the engine), `crates/cluster-daemon/src/lib.rs` (the
   sidecar), `crates/cluster-daemon/src/ipc.rs` (the client contract).

## Where truth lives

- The admission logic + its invariant: `crates/cluster-core/` + `formal/ClusterAdmission.tla`.
- The client (citrate-core) contract: `crates/cluster-daemon/src/ipc.rs` (`Request`/`Response`).
- What is real vs planned: `.agentile/planset/05_SPRINTS_AND_WPS.md` + `gates.yaml` (honest status).

## Federation context

Consumed by **citrate-core** (the desktop full-node), which spawns `cluster-daemon` as a sidecar and
speaks its UDS IPC, feeding rosters that come from the **citrate-comms** member-daemon. Mirrors that
daemon's lean-client/heavy-sidecar split. Cross-repo pins go through the federation manifest (Rule 12).
