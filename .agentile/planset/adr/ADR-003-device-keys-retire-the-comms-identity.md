---
created: 2026-10-01T00:00:00Z
branch: hup/n5-rt-other
author: Larry Klosowski + Claude Opus 5.5
status: proposed (pending owner sign-off)
adr: 003
wp: HUP-S8.1
amends: ADR-002 clause 8 (legacy identity)
---

# ADR-003: Device keys retire the member's comms identity from the mesh

## Context

ADR-002 clause 8 kept a member's comms identity admitted next to its linked devices, so a client
with no device link kept meshing as before. The comms key is derived from the wallet and is the
same on every machine of the member, so per-device revocation only has its intended meaning if the
shared comms identity stops being a peer once the member uses device keys. `formal/DeviceLink.tla`
did not model the comms identity, so this rule was not covered by its invariants.

## Decision

1. **Device keys only, once used.** `effective_roster` drops a member's comms identity from the
   admitted roster as soon as the member has an active device in it, or has a verified revocation
   of its own. Counting revocations means revoking the last device does not bring the comms
   identity back. Each change takes effect in the same `SetRoster` reconcile, like revocation.
2. **Unchanged for members without devices.** A member that has never linked or revoked a device
   keeps meshing as its comms identity, exactly as under ADR-002.
3. **The comms identity still authorizes.** It signs links and revocations and stays the roster
   key. It only stops being a peer.
4. **Consequence for mixed fleets.** After a member links one machine, any of its machines still
   running on the comms identity drops off that group's mesh until it is linked too. Core's link
   flow should link every machine of the member; this is listed for the owner below.
5. **Honest limit.** Revocation retires a device key. It is not a boundary against a machine that
   still holds the wallet: that machine can derive the comms key, mint a new device key and sign a
   new link. Removing a lost or stolen machine for good takes a new wallet (a new comms key).
   Member-facing text must not promise more than this.

## Proof

* `formal/DeviceLink.tla` now models the comms identity (`legacy`, `LegacyAdmit`, `LegacyLeave`,
  eviction on `IssueLink`, `Revoke` and `Reconcile`) with three new invariants:
  `LegacyOnlyWithoutDevices`, `RevokedMachineNotBackAsMember`, `LegacySubsetAllowed`. TLC
  (2 members x 3 devices x 3 keys): 10,404 distinct states, no error, all nine invariants.
  Mutation check, each caught by TLC: admitting the comms identity of any allowed member
  (`LegacyOnlyWithoutDevices`), not evicting it when a link is issued (`LegacyOnlyWithoutDevices`),
  counting only unrevoked links (`RevokedMachineNotBackAsMember`), keeping it after a roster change
  (`LegacySubsetAllowed`).
* `cluster-core` `device_tests`: six new tests (red before the change). Mutation check: dropping the
  revocation seed fails one test, removing the filter fails five.
* `cluster-daemon` `device_daemon_tests`: two new tests with real secp256k1 links, one of them a
  member that revoked both machines and then presents its comms identity.

## Pending owner sign-off

* Whether to ship this as the default (this ADR does). Device links are not in a released build
  yet, so no member is affected today.
* The member-facing revocation text in citrate-core (the wording in point 5), and whether core's
  link flow links every machine of a member before the first revocation.
* Whether to add comms-key rotation on revocation later (a wallet-level change, out of scope here).
