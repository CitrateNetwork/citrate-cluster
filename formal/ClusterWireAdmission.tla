------------------------- MODULE ClusterWireAdmission -------------------------
(***************************************************************************)
(* PBA-L6b-005 / PBA-L6b-006 (pre-bounty audit 2026-09-24): the on-WIRE     *)
(* half of the admission invariant, which ClusterAdmission.tla does not     *)
(* model. The libp2p transport keeps its own `authorized` set (fed by the   *)
(* daemon's SetRoster) and admits a connection at `identify` iff the peer's *)
(* address is in it. The bug: SetRoster only ever ADDED to `authorized`, so *)
(* a member revoked while offline stayed authorized and could reconnect.   *)
(*                                                                          *)
(*   SetRoster(na)  allowed' = na ; wire' = wire \cap na ;                  *)
(*                  authorized' = IF RevokeDeauthorizes THEN na             *)
(*                                ELSE authorized \cup na   (pre-fix)       *)
(*   Connect(p)     p identified AND p \in authorized -> wire' = wire+{p}   *)
(*   Unidentified   a connection that never identifies is never in `wire`   *)
(*                  and (L6b-006) receives nothing: modelled by `wire`      *)
(*                  being the ONLY set that receives gossip.                *)
(*   Drop(p)        wire' = wire - {p}                                     *)
(*                                                                          *)
(* With RevokeDeauthorizes = TRUE (the fix) TLC proves AuthorizedIsAllowed  *)
(* and WireSubsetAllowed; with FALSE it finds the L6b-005 counterexample    *)
(* (SetRoster({p1}); SetRoster({}); Connect(p1)).                           *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANTS Peers, RevokeDeauthorizes

VARIABLES allowed, authorized, wire

vars == <<allowed, authorized, wire>>

TypeOK ==
    /\ allowed \subseteq Peers
    /\ authorized \subseteq Peers
    /\ wire \subseteq Peers

Init ==
    /\ allowed = {}
    /\ authorized = {}
    /\ wire = {}

SetRoster(na) ==
    /\ allowed' = na
    /\ wire' = wire \cap na
    /\ authorized' = IF RevokeDeauthorizes THEN na ELSE authorized \cup na

Connect(p) ==
    /\ p \in authorized
    /\ wire' = wire \cup {p}
    /\ UNCHANGED <<allowed, authorized>>

Drop(p) ==
    /\ p \in wire
    /\ wire' = wire \ {p}
    /\ UNCHANGED <<allowed, authorized>>

Next ==
    \/ \E na \in SUBSET Peers : SetRoster(na)
    \/ \E p \in Peers : Connect(p)
    \/ \E p \in Peers : Drop(p)

Spec == Init /\ [][Next]_vars

(* The transport authorizes exactly the roster's allowed set: offboarding is effective on the wire. *)
AuthorizedIsAllowed == authorized = allowed
(* No peer outside the allowed set is ever meshed (receives or sends group gossip). *)
WireSubsetAllowed == wire \subseteq allowed

=============================================================================
