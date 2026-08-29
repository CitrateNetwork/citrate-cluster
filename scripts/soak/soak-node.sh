#!/usr/bin/env bash
# soak-node.sh — run ONE node of a two-machine cluster soak (CL-S3).
#
# Two machines on the SAME LAN (same router) mesh directly over TCP — no NAT traversal. Each node
# runs this. It writes a 0600 seed + bearer, prints THIS node's bootstrap multiaddr (share it with the
# other operator), starts the cluster-daemon in libp2p mode, feeds the roster + joins, then verifies
# the mesh forms (online >= 1) and a co-pinned CID propagates.
#
# Config via env:
#   SEED        64-hex secp256k1 secret for THIS node (each node MUST differ)              [required]
#   GROUP       shared group id == gossipsub topic (BOTH nodes identical)                  [required]
#   PORT        libp2p TCP listen port (fixed so the peer can bootstrap; default 4201)
#   PEER        the OTHER node's bootstrap multiaddr /ip4/<ip>/tcp/<port>/p2p/<PeerId>     [required]
#   PEER_ADDR   the OTHER node's 40-hex address (for the roster)                           [required]
#   SHARE_CID   if set, THIS node announces this CID after meshing (the other verifies it)
#   CLUSTER_BIN path to the cluster-daemon binary (default: ./target/release/cluster-daemon)
#
# First run WITHOUT PEER/PEER_ADDR to just print your identity + bootstrap addr; exchange, then run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${CLUSTER_BIN:-$REPO_ROOT/target/release/cluster-daemon}"
PORT="${PORT:-4201}"
GROUP="${GROUP:?set GROUP (same on both nodes)}"
SEED="${SEED:?set SEED (64-hex, unique per node)}"

die() { echo "ERROR: $*" >&2; exit 1; }
[ -x "$BIN" ] || die "cluster-daemon not found/executable at $BIN — build it: cargo build --release -p cluster-daemon (set CLUSTER_BIN)"

WORK="$(mktemp -d)"
trap 'kill "${DPID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
printf '%s' "$SEED" > "$WORK/seed"; chmod 600 "$WORK/seed"
head -c32 /dev/urandom | (xxd -p 2>/dev/null || od -An -tx1 | tr -d ' \n') | tr -d '\n' > "$WORK/bearer"; chmod 600 "$WORK/bearer"
SOCK="$WORK/cluster.sock"

# Identity (offline) + this node's LAN IP → the bootstrap addr to hand the other operator.
IDENT="$(CITRATE_CLUSTER_SEED_FILE="$WORK/seed" "$BIN" --print-identity)"
SELF_ADDR="$(printf '%s' "$IDENT" | sed -E 's/.*"address":"([0-9a-f]+)".*/\1/')"
SELF_PEERID="$(printf '%s' "$IDENT" | sed -E 's/.*"peerId":"([^"]+)".*/\1/')"
LAN_IP="$(python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(('8.8.8.8',80));print(s.getsockname()[0]);s.close()")"

echo "──────────────────────────────────────────────────────────────────"
echo " THIS NODE"
echo "   address   : $SELF_ADDR"
echo "   peerId    : $SELF_PEERID"
echo "   LAN IP    : $LAN_IP   (port $PORT)"
echo "   >>> give the OTHER operator these two values:"
echo "       PEER=/ip4/$LAN_IP/tcp/$PORT/p2p/$SELF_PEERID"
echo "       PEER_ADDR=$SELF_ADDR"
echo "──────────────────────────────────────────────────────────────────"

if [ -z "${PEER:-}" ] || [ -z "${PEER_ADDR:-}" ]; then
  echo "PEER / PEER_ADDR not set — identity printed above. Exchange with the other node, then re-run."
  exit 0
fi

echo "▶ starting cluster-daemon (libp2p) — group '$GROUP', listen /ip4/0.0.0.0/tcp/$PORT, dialing $PEER"
CITRATE_CLUSTER_SOCKET="$SOCK" \
CITRATE_CLUSTER_BEARER_FILE="$WORK/bearer" \
CITRATE_CLUSTER_SELF_ADDR="$SELF_ADDR" \
CITRATE_CLUSTER_LISTEN="/ip4/0.0.0.0/tcp/$PORT" \
CITRATE_CLUSTER_SEED_FILE="$WORK/seed" \
CITRATE_CLUSTER_GROUP="$GROUP" \
CITRATE_CLUSTER_BOOTSTRAP="$PEER" \
  "$BIN" & DPID=$!

for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.25; done
[ -S "$SOCK" ] || die "daemon did not bind its socket"

CTL="python3 $REPO_ROOT/scripts/soak/soakctl.py $SOCK $WORK/bearer"
echo "▶ setRoster [self, peer] + join"
$CTL set-roster "$GROUP" "$SELF_ADDR:member,$PEER_ADDR:member" >/dev/null
$CTL join "$GROUP" >/dev/null

echo "▶ polling status (want online>=1)…"
ONLINE=0
for i in $(seq 1 60); do
  ST="$($CTL status "$GROUP")"
  ONLINE="$(printf '%s' "$ST" | sed -E 's/.*"online":([0-9]+).*/\1/')"
  echo "   [$i] $ST"
  [ "${ONLINE:-0}" -ge 1 ] && break
  sleep 1
done

# Share AFTER the mesh has grafted — gossipsub does not replay a publish made to an empty mesh, so
# sharing before online>=1 silently loses the co-pin. Then poll once more so the peer's share (if any)
# has time to arrive in OUR sharedFiles.
if [ "${ONLINE:-0}" -ge 1 ] && [ -n "${SHARE_CID:-}" ]; then
  echo "▶ mesh up — sharing CID $SHARE_CID"
  $CTL share "$GROUP" "$SHARE_CID" >/dev/null
  for i in $(seq 1 6); do echo "   [share-poll $i] $($CTL status "$GROUP")"; sleep 2; done
fi

echo "──────────────────────────────────────────────────────────────────"
if [ "${ONLINE:-0}" -ge 1 ]; then
  echo " ✅ SOAK PASS — mesh formed (online=$ONLINE). Final status above shows sharedFiles (yours +"
  echo "    any co-pin the peer shared AFTER the mesh grafted)."
else
  echo " ❌ SOAK FAIL — peer never connected. Check: same GROUP, firewall allows TCP $PORT inbound,"
  echo "    correct PEER multiaddr (ip/port/peerId), both rosters include both addresses."
fi
echo " (daemon stays up; Ctrl-C to stop)"
wait "$DPID"
