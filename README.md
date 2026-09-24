# citrate-cluster

*Part of the **[Citrate Network](https://citrate.ai)** — own the means of computation. · [Docs](https://docs.citrate.ai) · [Run a node](https://citrate.ai/download) · [Contribute → free membership](https://github.com/CitrateNetwork/.github/blob/main/CONTRIBUTING.md)*

> The group private P2P cluster daemon for the Citrate Network — a Noise-encrypted
> libp2p mesh among a group's members with one hard guarantee: no unauthorized
> peer is ever in the mesh. A lean client (e.g. citrate-core) feeds it a roster
> over a loopback Unix-socket IPC and it reconciles the mesh to match.

## What it is

`citrate-cluster` is two crates:

- **`cluster-core`** — the pure admission engine. RBAC → network admission logic
  with **no libp2p and no tokio**, so lean clients link it directly. The one
  property everything hangs off — `admitted ⊆ allowed` — lives here and is
  formally modeled (`formal/ClusterAdmission.tla`).
- **`cluster-daemon`** — the sidecar. Runs the group meshes (libp2p Noise +
  gossipsub) and serves a loopback **UDS JSON IPC** so a client feeds the roster
  and drives join / status / peers / share / poll without linking the networking
  tree.

The roster is the admission list: a client pushes it via `SetRoster`; the daemon
admits a peer only when the transport reports it connected AND `cluster-core`
admits it, and evicts any peer no longer on the roster in the same step. Unlike
the other Citrate daemons, `citrate-cluster` has **no chain RPC dependency** — it
depends only on the roster its client feeds it.

- Concept docs: https://docs.citrate.ai/cluster
- Consumed by: [citrate-core](https://github.com/CitrateNetwork/citrate-core) (lean
  client that supplies the roster, sourced from the comms daemon).

## Prerequisites

```bash
# Rust (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# System packages (Debian/Ubuntu)
sudo apt-get update && sudo apt-get install -y build-essential pkg-config git curl
# Optional helpers used below to talk to the UDS / mint secrets: socat, xxd
sudo apt-get install -y socat xxd
```

## Build from source

```bash
git clone https://github.com/CitrateNetwork/citrate-cluster
cd citrate-cluster

cargo build --release -p cluster-daemon      # produces target/release/cluster-daemon
cargo test --workspace                        # admission + IPC + transport tests
cargo clippy --workspace --all-targets -- -D warnings
```

## Run locally

Secrets cross as **0600 file paths**, never inline (argv/env leak to `ps`). Mint a
seed + bearer, derive this node's identity, then start the daemon.

```bash
# 1. Mint a per-node 32-byte secp256k1 seed and an IPC bearer, both 0600
( umask 077; head -c32 /dev/urandom | xxd -p | tr -d '\n' > ./seed )
( umask 077; head -c32 /dev/urandom | xxd -p | tr -d '\n' > ./bearer )

# 2. Derive this node's cluster address + libp2p PeerId (offline)
CITRATE_CLUSTER_SEED_FILE=./seed ./target/release/cluster-daemon --print-identity
# -> {"address":"<40-hex>","peerId":"<PeerId>"}

# 3. Start the daemon. Admission-only (no networking):
CITRATE_CLUSTER_SOCKET=./cluster.sock \
CITRATE_CLUSTER_BEARER_FILE=./bearer \
CITRATE_CLUSTER_SELF_ADDR=<the 40-hex address from step 2> \
./target/release/cluster-daemon

#    …or with the real libp2p transport (mesh over TCP):
CITRATE_CLUSTER_SOCKET=./cluster.sock \
CITRATE_CLUSTER_BEARER_FILE=./bearer \
CITRATE_CLUSTER_SELF_ADDR=<40-hex> \
CITRATE_CLUSTER_LISTEN=/ip4/0.0.0.0/tcp/4201 \
CITRATE_CLUSTER_SEED_FILE=./seed \
CITRATE_CLUSTER_GROUP=my-group \
./target/release/cluster-daemon
```

Verify it's up by driving the UDS IPC (line-delimited JSON; the daemon binds the
socket on start). A single node with no peers correctly reports `online: 0` — it
never invents a mesh:

```bash
printf '{"op":"join","group":"my-group"}\n{"op":"status","group":"my-group"}\n' \
  | socat - UNIX-CONNECT:./cluster.sock
# -> {"type":"ok"}
# -> {"type":"status","online":0,"sharedFiles":[]}
```

IPC requests: `setRoster`, `join`, `leave`, `status`, `peers`, `shareFile`, `poll`.

## Connect it locally  ← the differentiator

`citrate-cluster` has **no chain upstream**. Its upstream is the **client that
feeds the roster**. Two ways to bring it up locally:

- **With a client (normal path):** run `cluster-daemon`, then have citrate-core
  (which gets the roster from the comms daemon) push it via `SetRoster` on the UDS
  and drive join/status. The daemon reconciles the mesh to the roster.
- **Standalone / two machines:** use `scripts/soak/soak-node.sh` — run it on each
  of two machines on the same LAN. It mints the 0600 seed + bearer, prints this
  node's bootstrap multiaddr to hand the other operator, starts the daemon in
  libp2p mode, feeds a roster, joins, and verifies the mesh forms (`online ≥ 1`)
  and a co-pinned CID propagates:

  ```bash
  # On each node (exchange the printed bootstrap addr + 40-hex address first):
  SEED_FILE=./seed GROUP=my-group PORT=4201 \
  PEER=/ip4/<other-ip>/tcp/4201/p2p/<other-PeerId> PEER_ADDR=<other-40-hex> \
    bash scripts/soak/soak-node.sh
  ```

Minimal end-to-end check: feed a two-member roster, both nodes `join`, and each
node's `status` reports `online: 1`.

See the full multi-repo bring-up: https://docs.citrate.ai/local-stack

## Configuration

All config is via env (secrets as file paths only):

- `CITRATE_CLUSTER_SOCKET` — UDS path to bind (required).
- `CITRATE_CLUSTER_BEARER_FILE` — path to the 0600 IPC bearer-token file (required;
  refused unless 0600 and owned by you; compared in constant time).
- `CITRATE_CLUSTER_SELF_ADDR` — this node's 20-byte hex member address (required).
- `CITRATE_CLUSTER_LISTEN` — libp2p listen multiaddr (e.g. `/ip4/0.0.0.0/tcp/4201`);
  presence selects the real transport instead of admission-only.
- `CITRATE_CLUSTER_SEED_FILE` — 0600 file with the 32-byte hex secp256k1 secret
  (the Noise/cluster identity; never crosses argv/env).
- `CITRATE_CLUSTER_GROUP` — group id == gossipsub topic (one group per daemon in S1).
- `CITRATE_CLUSTER_BOOTSTRAP` — comma-separated peer multiaddrs to dial on startup.
- `--print-identity` — print this node's `{address, peerId}` and exit.

## Links

- Docs: https://docs.citrate.ai/cluster
- Consumed by: [citrate-core](https://github.com/CitrateNetwork/citrate-core) ·
  Related: [citrate-comms](https://github.com/CitrateNetwork/citrate-comms) (roster source)
- Contributing (DCO): CONTRIBUTING.md · Security: SECURITY.md · License: LICENSE

## License

Source-available under the Business Source License 1.1 (see [`LICENSE`](LICENSE)); converts to Apache-2.0 on the Change Date stated in the license. This is the commercial application-layer / core tier of Citrate's open-core model; the infrastructure tier is Apache-2.0. Licensor: Citrate Inc.
