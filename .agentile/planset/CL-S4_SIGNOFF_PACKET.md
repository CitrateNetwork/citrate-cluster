---
created: 2026-10-01
branch: hup/n5-fleet-rest
author: Larry Klosowski + Claude Opus 5.5
status: draft for review (nothing is signed; the sign-off lines below are blank on purpose)
wp: CL-S4 (HUP-S8.4)
gate: gateSec gSec-transport; HUP gate4 g4-fleet ("CL-S4 signed")
---

# CL-S4: the transport sign-off packet

This is what the security lead and the owner review before the cross-machine transport may carry
partner traffic and before citrate-core turns the mesh on by default (`TRANSPORT_SIGNED_OFF` in
citrate-core `src-tauri/src/cluster_mesh.rs`). It collects the claims, the evidence for each, and the
known limits. It decides nothing by itself.

## Scope

The libp2p transport in `crates/cluster-daemon/src/libp2p_transport.rs` (TCP, Noise, yamux,
gossipsub, identify, connection limits), the admission gate it enforces (`cluster-core`), per-device
identity (`cluster-core::device`, `devices.rs`), and the loopback IPC that citrate-core drives
(`server.rs`, `ipc.rs`). Out of scope: the comms relay (its own audit), citrate-core's wallet
ceremony (audited with core), NAT traversal and peer discovery (not built).

## Assets and trust boundaries

| Asset | Where | Boundary |
|---|---|---|
| Device key (mesh identity) | 0600 seed file read by the daemon; OS keyring in core | never on argv/env; never the wallet |
| IPC bearer | 0600 file; constant-time compare | loopback socket, peer-uid checked |
| Group membership | roster from core (comms relay), DeviceLinks | admission decided in `cluster-core` only |
| Co-pinned file set | daemon memory, per group | CIDs only, capped |

## Claims and evidence

| # | Claim | Evidence |
|---|---|---|
| C1 | No peer outside the group's allowed set is ever meshed: `connected ⊆ admitted ⊆ allowed` | `formal/ClusterAdmission.tla`, `ClusterWireAdmission.tla`; transport tests `an_unauthorized_inbound_peer_is_refused_on_the_wire`, `wire_admission_is_reflected_into_the_membership_predicates` |
| C2 | A device is admitted only through a DeviceLink with three valid signatures, its member allowed, not revoked | `formal/DeviceLink.tla` (TLC, invariants mutation-checked); `device_tests`, `device_daemon_tests`; `tests/devicelink_multiprocess.rs`, `tests/fleet_multiprocess.rs` |
| C3 | Revocation evicts in the same reconcile and is permanent per device key | `devicelink_multiprocess.rs` step 4, `fleet_multiprocess.rs` (re-dials refused for 7 s after eviction) |
| C4 | A Noise session is bound to its group (handshake prologue = group id) | `build_swarm`; peers of another group cannot complete a handshake |
| C5 | Unadmitted peers receive nothing and their messages are dropped | gossipsub app-score gating + blacklist (`pba_l6b_006_admission_gate_config_invariants`), authorized-source check on receipt, identify timeout sweep |
| C6 | Only well-formed CIDs cross the wire; inbox and co-pin sets are bounded | `pba_l6b_037_*`, `pba_l6b_020_inbox_is_capped`, `MAX_SHARED_FILES` |
| C7 | Connection surface is capped before a Noise handshake | `connection_limits` (64 established incoming, 16 pending, 2 per peer) |
| C8 | Secrets never cross argv/env; secret files are 0600, owned, no-follow, size-capped, wiped on drop | `read_secret_file`, `tests/zeroize_secret.rs`, CL-B-001/007 fixes |
| C9 | A late authorization takes effect without a restart, without weakening C1 | bootstrap re-dial (5 s, 16 per tick, 64 kept); `a_peer_refused_before_authorization_gets_in_after_it_is_authorized`; mutation-checked through `fleet_multiprocess.rs` |
| C10 | Mixed-version clients are unaffected: requests without device fields are byte-identical | core `set_roster_without_links_serializes_exactly_as_before` |

## Known limits (accepted or to be decided)

* **No discovery.** Peers come only from bootstrap addresses, so every node must bootstrap to every
  other node for a full mesh. With 64 incoming connections per node the full-mesh ceiling is about
  65 nodes. Single-machine ladder control: 50 nodes meshed and one co-pin reached all of them
  (`tests/ladder_multiprocess.rs`, numbers in `scripts/soak/DEVICELINK_MULTI_MACHINE.md`).
* **One group per daemon process** in libp2p mode (`CITRATE_CLUSTER_GROUP`). citrate-core keeps the
  mesh-on-by-default branch closed until this changes (`MULTI_GROUP_DAEMON`).
* **Relayed sources are dropped:** a message is accepted only from a directly identified publisher.
* **Re-dial cost:** a refused peer costs one Noise handshake per 5 s against each bootstrap address.
* **Removal is not a lock-out** for a machine that still holds the member's wallet (it can link a new
  device key); only a new wallet is. Stated in citrate-core's UI and ADR.
* **Dependencies:** libp2p 0.56. Lockfile-only advisories in optional DNS/mDNS crates are not
  compiled into the daemon today; enabling the `dns` or `mdns` features requires the patched
  versions. A libp2p bump needs a re-run of the soak.
* **Open review items** are tracked in the private security register for this sprint; each must be
  closed or explicitly accepted before signing.

## Before signing

1. Two-machine soak on separate hosts (DGX team): `scripts/soak/DEVICELINK_MULTI_MACHINE.md`
   Test 2 (late link) and Test 3 (three machines, revocation), results attached here.
2. The app-level run with people at both machines: citrate-core `docs/FLEET_MULTI_MACHINE_TEST.md`.
3. A ladder step on separate machines (at least the CL-S3 50-node step), or an explicit decision to
   sign for a smaller fleet size with that size written here.
4. The private register reviewed: every open item closed or accepted in writing.
5. `cargo audit`, `cargo test --workspace --locked`, clippy `-D warnings` and TLC re-run on the
   commit being signed.

## Sign-off

| Role | Name | Date | Commit | Decision (sign / sign with limits / refuse) |
|---|---|---|---|---|
| Security lead | | | | |
| Owner | | | | |
