# CLAUDE.md — citrate-cluster hard rules

Start at `.agentile/AGENT_ENTRY.md`. This repo is the group P2P cluster daemon + its admission core.

## Hard rules (non-negotiable)

1. **No mocks (Rule 1).** No fabricated peers, fake connectivity, or placeholder features that
   pretend to work. A single node with no peers reports `online: 0` — it does not invent a mesh.
   Test doubles live behind `#[cfg(test)]`.
2. **The admission invariant is sacred.** `admitted ⊆ allowed` and `connected ⊆ admitted` must hold
   in every reachable state. No unauthorized peer is ever meshed; an offboard/role-drop evicts in the
   same step. Changing the admission logic requires re-checking `formal/ClusterAdmission.tla` and the
   `cluster-core` tests.
3. **`cluster-core` stays pure.** No `libp2p`, no `tokio`, no I/O in `cluster-core` — it must remain
   linkable by lean clients (citrate-core). Networking lives in `cluster-daemon` only.
4. **Secrets never cross argv/env.** The IPC bearer and any Noise seed cross as a **0600 file path**,
   never inline (they leak to `ps`). Constant-time compare the bearer (no `==`).
5. **Test count monotone (Rule 2).** `cargo test --workspace --locked` count never decreases.
6. **Never commit to main.** Feature branch + PR via `gh`. Commit with explicit paths. The owner
   merges. CI (fmt + clippy `-D warnings` + test) must be green.
7. **Every doc gets YAML frontmatter** (created, branch, author, status).
8. **T1 repo.** Identity-adjacent (Noise ids bound to member keys) + networking. Full audit + a
   security sign-off on the transport before it is trusted cross-org.

End commits with:
`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
