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
  `LegacyOnlyWithoutDevices`, `RevokedMachineNotBackAsMember`, `LegacySubsetAllowed`.
* Review pass (2026-10-04): the first version of the model kept every link forever, while
  cluster-daemon REPLACES the link set on each roster update and only revocations are sticky. The
  model now has `DropLink(d)` (the client stops sending a link without revoking it), the gate's
  sticky `revokedBy` pairs (as in `DeviceRegistry.revoked`), and `RevokedMachineNotBackAsMember`
  is stated over a history variable (`revokeLog`) that no action reads. TLC (2 members x 3 devices
  x 3 keys): 21,456 distinct states, no error, all nine invariants. Mutation check, each caught by
  TLC: admitting the comms identity of any allowed member (`LegacyOnlyWithoutDevices`), not
  evicting it when a link is issued (`LegacyOnlyWithoutDevices`), the gate ignoring revocations
  (`RevokedMachineNotBackAsMember`; the earlier model could not catch this one, because links never
  left it), a revocation not recorded by the gate (`RevokedMachineNotBackAsMember`), keeping it
  after a roster change (`LegacySubsetAllowed`), and a withdrawn link leaving its device meshed
  (`NoActWithoutLink`).
* Withdrawing a link is not a revocation: a member that never revoked anything and whose links the
  client stops sending is back on its comms identity. A member that revoked a device stays on
  device keys for the life of the daemon process. citrate-core keeps its links and revocations in
  a local store and sends them with every roster update, so this survives a daemon restart. Each
  node only knows the links and revocations its own core sends it; distributing them to the other
  members' nodes is citrate-core work (S8.1 follow-up), not a cluster change.
* `cluster-core` `device_tests`: eight new tests (six red before the change; two added in the
  review for the replaced-links case). Mutation check: dropping the
  revocation seed fails one test, removing the filter fails five.
* `cluster-daemon` `device_daemon_tests`: two new tests with real secp256k1 links, one of them a
  member that revoked both machines and then presents its comms identity.

## Pending owner sign-off

* Whether to ship this as the default (this ADR does). Device links are not in a released build
  yet, so no member is affected today.
* The member-facing revocation text in citrate-core (the wording in point 5), and whether core's
  link flow links every machine of a member before the first revocation.
* Whether to add comms-key rotation on revocation later (a wallet-level change, out of scope here).
