---------------------------- MODULE ClusterAdmission ----------------------------
(***************************************************************************)
(* Formal model of the citrate-core cluster admission state machine        *)
(* (src-tauri/src/cluster.rs :: ClusterMembership), written for CX-S4.2 to  *)
(* pin the ONE safety property the P2P mesh must never violate:            *)
(*                                                                          *)
(*     no unauthorized peer is ever in the mesh  ==  admitted (subseteq) allowed  *)
(*                                                                          *)
(* `allowed` is the role-gated, roster-derived set (allowed_set: canonical  *)
(* addresses with role >= Member). `admitted` is the set of peers currently  *)
(* meshed. The example-based cluster_tests check specific sequences; this    *)
(* model checks the invariant EXHAUSTIVELY over every roster change +        *)
(* join/leave interleaving, so the offboard-eviction step cannot leave a     *)
(* window where a removed member is still meshed.                           *)
(*                                                                          *)
(* Transitions map 1:1 to ClusterMembership methods:                        *)
(*   Join(p)         p in allowed, p notin admitted -> admitted' = +p       *)
(*                   (join(): role-gate is folded into `allowed`)           *)
(*   Leave(p)        p in admitted -> admitted' = -p   (leave())            *)
(*   Reconcile(na)   allowed' = na ; admitted' = admitted (intersect) na    *)
(*                   (reconcile(): recompute allowed + EVICT admitted\allowed)*)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANTS Peers   \* a finite universe of peer addresses (model bound)

VARIABLES
    allowed,      \* the role-gated allowed set (roster-derived); a subset of Peers
    admitted      \* the currently-meshed peers; must stay a subset of `allowed`

vars == <<allowed, admitted>>

TypeOK ==
    /\ allowed  \subseteq Peers
    /\ admitted \subseteq Peers

(* Any role-gated roster derivation is some subset of Peers; admitted starts empty. *)
Init ==
    /\ allowed \in SUBSET Peers
    /\ admitted = {}

(* A candidate presenting a valid RoleAssertion for this group (verified upstream, so it
   appears in `allowed`) is admitted. join() rejects anything not in `allowed`. *)
Join(p) ==
    /\ p \in allowed
    /\ p \notin admitted
    /\ admitted' = admitted \cup {p}
    /\ UNCHANGED allowed

(* A peer leaves or is dropped by the transport. *)
Leave(p) ==
    /\ p \in admitted
    /\ admitted' = admitted \ {p}
    /\ UNCHANGED allowed

(* The roster changed (offboard / role change): recompute `allowed` to any new subset and EVICT in
   the SAME step every admitted peer no longer allowed (admitted' = admitted intersect allowed'). *)
Reconcile(na) ==
    /\ allowed' = na
    /\ admitted' = admitted \cap na
    /\ na \in SUBSET Peers

Next ==
    \/ \E p \in Peers : Join(p)
    \/ \E p \in Peers : Leave(p)
    \/ \E na \in SUBSET Peers : Reconcile(na)

Spec == Init /\ [][Next]_vars

(*************************** Safety ****************************************)
(* INV-1 — no unauthorized peer is ever meshed. This is the property the whole RBAC->network
   boundary exists to guarantee; it must hold in EVERY reachable state. *)
AdmittedSubsetAllowed == admitted \subseteq allowed

=============================================================================
