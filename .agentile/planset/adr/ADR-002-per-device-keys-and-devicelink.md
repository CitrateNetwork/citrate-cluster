---
created: 2026-10-01T00:00:00Z
branch: hup/n4-devicelink
author: Larry Klosowski + Claude Opus 5.5
status: accepted
adr: 002
wp: HUP-S8.1
amends: CL-2 (identity clause), ADR-001 (peer identity)
---

# ADR-002: Per-device keys and the DeviceLink

## Context

The mesh admits by `address ∈ roster` and derives each peer's address from its Noise key. Since
citrate-core CONNECT-S5 the member's comms key (the roster identity) is derived from the wallet, so
every machine of one member presented the same key, the same address and the same libp2p PeerId.
The mesh could not tell a member's laptop from its Linux box, and could not cut one off without
cutting off all of them. The Hermes upskill planset (D-31, owner amendment 2026-09-30) settles it:
a random device key per machine plus a wallet-signed DeviceLink.

## Decision

1. **Device key.** Each machine mints its own random secp256k1 key, sealed on that machine. It is
   the libp2p identity (the `CITRATE_CLUSTER_SEED_FILE` secret), so one device key gives one
   address and one PeerId. It is never derived from, and never is, the wallet key.
2. **DeviceLink.** `cluster_core::device::DeviceLink {member, device, wallet, index, label,
   issued_at}` with three EIP-191 signatures over one human-readable message:
   * `member_sig`: the member's roster (comms) key, the identity this mesh checks against the roster;
   * `device_sig`: the device key (proof of possession, so nobody links somebody else's PeerId);
   * `wallet_sig`: the custody wallet, produced by citrate-core's signature ceremony with explicit
     human approval. The member signature covers the wallet address, so the keys vouch for each other.
3. **Admission.** `effective_roster(roster, registry)` adds every verified, unrevoked device of an
   allowed member to the roster with the member's role. The existing `ClusterMembership` gate runs
   on that set, so `admitted ⊆ allowed` (ClusterAdmission) and the eviction-in-one-step behaviour are
   inherited, not re-implemented.
4. **Conflicts admit nobody.** Two members claiming one device key are both refused, so every node
   reaches the same answer regardless of order. The `index` is a display ordinal only: each machine
   picks it locally, so two devices sharing an index are both admitted (the key is the identity).
5. **Revocation is permanent per key.** A member-signed `DeviceRevocation` is recorded for good and
   evicts in the same `SetRoster`. A revoked key never returns; a re-added machine mints a new key.
   Only the member a device is linked to can revoke it.
6. **Purity.** `cluster-core` stays free of crypto, I/O and networking: recovery is the injected
   `LinkVerifier` trait. `cluster-daemon` implements it (`Eip191Verifier`, k256, low-s only). The
   daemon verifies; it never signs a link, a revocation or anything with a wallet key.
7. **Wire.** `SetRoster` gains optional `devices` and `revocations` (an older client's request is
   unchanged); `Reconciled` gains `rejected` (secret-free reasons, omitted when empty); `PeerView`
   gains optional `member`; new `Devices {group}` lists devices under members. At most 64 links per
   update, which fits the 64 KiB IPC line cap.
8. **Legacy identity.** A client with no device link keeps meshing as its comms identity (one
   PeerId per member, as before). Nothing changes for a member until a link exists.

## Proof

* `formal/DeviceLink.tla` (TLC, 2 members x 3 devices x 3 keys, 8248 distinct states, no error):
  `NoActWithoutLink`, `RevokedDeviceEvicted`, `DistinctPeerIds`, `OneMemberPerDevice`, `TypeOK`, and
  ClusterAdmission's `AdmittedSubsetAllowed` via `INSTANCE ... WITH allowed <- AllowedDevices`.
  Every invariant was mutation-checked: dropping eviction on revoke, admitting without a link,
  letting two devices draw one key, dropping the one-member check, dropping eviction on reconcile,
  and making revocation non-sticky each produce a counterexample on the targeted invariant.
* Unit tests: `cluster-core` `device_tests` (link rules, conflicts, sticky revocation, effective
  roster) with mutation checks; `cluster-daemon` `devices_tests` (real secp256k1, a public
  key/address vector, high-s refusal, device address == libp2p identity address, distinct PeerIds)
  and `device_daemon_tests` (IPC contract, forged link refused, revocation evicts in one call).
* `tests/devicelink_multiprocess.rs`: three real daemon processes on loopback (two linked devices of
  one member, one unlinked key). The linked pair meshes with distinct PeerIds, both are listed under
  the member, the unlinked key never gets in, and a revocation evicts and stays evicted.
* Still owed: the two-machine run on separate hosts (DGX soak), and the CL-S4 transport sign-off
  before any of this carries partner traffic (HUP-S8.4).

## Consequences

* CL-2's "wallet address = cluster Noise id" clause is retired: the Noise id is the device key.
* Distributing other members' links between nodes (today each node's client sends the links it
  knows) rides on the comms roster in a follow-on; until then a node admits the devices whose links
  its client supplies.
