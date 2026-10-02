------------------------------ MODULE DeviceLink ------------------------------
(***************************************************************************)
(* HUP-S8.1: per-device keys and the DeviceLink admission rule             *)
(* (crates/cluster-core/src/device.rs).                                    *)
(*                                                                          *)
(* Each device mints its OWN random key (never derived from the wallet),    *)
(* and its libp2p PeerId is a function of that key. A member binds a device *)
(* to itself with a signed DeviceLink; it can revoke the device, and the    *)
(* revocation is permanent for that key. The mesh admits a device only     *)
(* while it holds a valid, unrevoked link to a member the roster allows.    *)
(*                                                                          *)
(* Transitions map to the implementation:                                   *)
(*   MintKey(d)      a device draws a fresh key           (device key mint) *)
(*   IssueLink(d,m)  member m links device d              (DeviceRegistry)  *)
(*                   refused for a revoked key or a key already linked to   *)
(*                   another member (LinkRejection::Revoked / ::Conflict)   *)
(*   Admit(d)        identify-time admission over effective_roster          *)
(*   Leave(d)        connection closed                                      *)
(*   Revoke(d)       member revocation, evicted in the SAME step            *)
(*                   (DeviceRegistry::update + ClusterMembership::reconcile)*)
(*   Reconcile(na)   roster change; devices of dropped members evicted      *)
(*                                                                          *)
(* It reuses ClusterAdmission: the effective allowed set (the devices with  *)
(* a live link to an allowed member) is substituted for its `allowed`, and  *)
(* its AdmittedSubsetAllowed must hold here too.                            *)
(*                                                                          *)
(* ADR-003: the member's comms identity. It is wallet-derived, so ANY       *)
(* machine holding the wallet can present it, a revoked one included.       *)
(* `legacy` is the set of comms identities currently meshed. A comms        *)
(* identity is admissible only while its member has never linked a device;  *)
(* linking or revoking evicts it in the same step.                         *)
(*   LegacyAdmit(m)  a machine meshes as member m's comms identity          *)
(*   LegacyLeave(m)  that connection closes                                 *)
(***************************************************************************)
EXTENDS FiniteSets, Naturals

CONSTANTS
    Members,    \* member roster identities (comms keys)
    Devices,    \* machines
    Keys,       \* the device-key space (a model bound on fresh random keys)
    NoKey       \* marker: device has not minted a key yet

VARIABLES
    allowed,    \* members the role-gated roster currently allows
    key,        \* key[d] = the key device d minted (its PeerId is a function of it)
    links,      \* set of <<device, member>> links that verified
    revoked,    \* devices whose member revoked them (sticky)
    admitted,   \* devices currently meshed
    legacy      \* member comms identities currently meshed (ADR-003)

vars == <<allowed, key, links, revoked, admitted, legacy>>

\* The PeerId is derived from the device key. Modelled as the key itself: any injective function
\* gives the same verdicts, and libp2p's PeerId-from-public-key is injective.
PeerId(d) == key[d]

MemberOf(d) == {m \in Members : <<d, m>> \in links}

LinkedToAllowed(d) == \E m \in allowed : <<d, m>> \in links

\* The effective allowed set the admission gate runs on (cluster-core effective_roster).
AllowedDevices == {d \in Devices : LinkedToAllowed(d) /\ d \notin revoked}

UsedKeys == {key[d] : d \in Devices} \ {NoKey}

\* A member is on device keys once it has linked a device (revoked or not: a revocation needs a
\* link, and the implementation seeds this set from verified revocations too).
OnDeviceKeys(m) == \E d \in Devices : <<d, m>> \in links

\* The comms identities the admission gate accepts (cluster-core effective_roster).
LegacyAllowed == {m \in allowed : ~OnDeviceKeys(m)}

TypeOK ==
    /\ allowed \subseteq Members
    /\ key \in [Devices -> Keys \cup {NoKey}]
    /\ links \subseteq Devices \X Members
    /\ revoked \subseteq Devices
    /\ admitted \subseteq Devices
    /\ legacy \subseteq Members

Init ==
    /\ allowed \in SUBSET Members
    /\ key = [d \in Devices |-> NoKey]
    /\ links = {}
    /\ revoked = {}
    /\ admitted = {}
    /\ legacy = {}

\* A device draws a fresh random key. Two devices never hold the same key (the device key is
\* random per machine; this is exactly what the wallet-derived comms key could NOT give).
MintKey(d) ==
    /\ key[d] = NoKey
    /\ \E k \in Keys \ UsedKeys : key' = [key EXCEPT ![d] = k]
    /\ UNCHANGED <<allowed, links, revoked, admitted, legacy>>

\* Member m signs a link for device d. The device must hold a key (it co-signs: proof of
\* possession). A revoked key is never re-linked, and a key linked to one member cannot be
\* linked to another (the registry refuses the conflict).
IssueLink(d, m) ==
    /\ key[d] # NoKey
    /\ d \notin revoked
    /\ MemberOf(d) \subseteq {m}
    /\ links' = links \cup {<<d, m>>}
    /\ legacy' = legacy \ {m}       \* ADR-003: the member's comms identity leaves in this step
    /\ UNCHANGED <<allowed, key, revoked, admitted>>

\* identify-time admission: only a device in the effective allowed set is meshed.
Admit(d) ==
    /\ d \in AllowedDevices
    /\ d \notin admitted
    /\ admitted' = admitted \cup {d}
    /\ UNCHANGED <<allowed, key, links, revoked, legacy>>

Leave(d) ==
    /\ d \in admitted
    /\ admitted' = admitted \ {d}
    /\ UNCHANGED <<allowed, key, links, revoked, legacy>>

\* The member revokes the device: sticky, and the device is evicted in the SAME step
\* (one admission cycle, US-8.1 AC2).
Revoke(d) ==
    /\ links \cap ({d} \X Members) # {}
    /\ revoked' = revoked \cup {d}
    /\ admitted' = admitted \ {d}
    /\ legacy' = legacy \ MemberOf(d)
    /\ UNCHANGED <<allowed, key, links>>

\* Roster change: recompute the allowed members and evict every device whose member left.
Reconcile(na) ==
    /\ allowed' = na
    /\ admitted' = {d \in admitted : \E m \in na : <<d, m>> \in links}
    /\ legacy' = legacy \cap na
    /\ UNCHANGED <<key, links, revoked>>

\* A machine meshes as member m's comms identity. Any machine holding the wallet can do this,
\* including one whose device key was revoked; only the gate decides.
LegacyAdmit(m) ==
    /\ m \in LegacyAllowed
    /\ m \notin legacy
    /\ legacy' = legacy \cup {m}
    /\ UNCHANGED <<allowed, key, links, revoked, admitted>>

LegacyLeave(m) ==
    /\ m \in legacy
    /\ legacy' = legacy \ {m}
    /\ UNCHANGED <<allowed, key, links, revoked, admitted>>

Next ==
    \/ \E d \in Devices : MintKey(d)
    \/ \E d \in Devices, m \in Members : IssueLink(d, m)
    \/ \E d \in Devices : Admit(d)
    \/ \E d \in Devices : Leave(d)
    \/ \E d \in Devices : Revoke(d)
    \/ \E na \in SUBSET Members : Reconcile(na)
    \/ \E m \in Members : LegacyAdmit(m)
    \/ \E m \in Members : LegacyLeave(m)

Spec == Init /\ [][Next]_vars

(*************************** Safety ****************************************)

\* No device acts for a member without a valid link to a member the roster allows.
NoActWithoutLink == \A d \in admitted : LinkedToAllowed(d)

\* A revoked device is never in the mesh.
RevokedDeviceEvicted == admitted \cap revoked = {}

\* One PeerId per device key: two distinct devices with keys never share a PeerId.
DistinctPeerIds ==
    \A d1, d2 \in Devices :
        (d1 # d2 /\ key[d1] # NoKey /\ key[d2] # NoKey) => PeerId(d1) # PeerId(d2)

\* A device key belongs to at most one member.
OneMemberPerDevice == \A d \in Devices : Cardinality(MemberOf(d)) <= 1

\* Reuse ClusterAdmission: substitute the effective allowed device set for its `allowed`.
CA == INSTANCE ClusterAdmission WITH Peers <- Devices, allowed <- AllowedDevices, admitted <- admitted

AdmittedSubsetAllowed == CA!AdmittedSubsetAllowed

\* ADR-003: a member that has linked a device is never meshed as its comms identity.
LegacyOnlyWithoutDevices == \A m \in legacy : ~OnDeviceKeys(m)

\* ADR-003 (the finding, stated directly): once a member revoked a device, no machine is meshed
\* as that member's comms identity, so the revoked machine cannot come back that way.
RevokedMachineNotBackAsMember ==
    \A m \in legacy : \A d \in revoked : <<d, m>> \notin links

\* Comms identities, like devices, are only meshed while the roster allows their member.
LegacySubsetAllowed == legacy \subseteq allowed

=============================================================================
