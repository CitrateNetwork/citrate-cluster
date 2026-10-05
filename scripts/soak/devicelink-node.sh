#!/usr/bin/env bash
# devicelink-node.sh: run ONE device of a multi-machine DeviceLink soak (HUP-S8.1 / S8.4).
#
# Every machine runs this with its own device seed from a fixture made by
#   cargo run --release -p cluster-daemon --example devicelink_fixture -- <fleet-dir> <devices per member...>
# (test keys only; see DEVICELINK_MULTI_MACHINE.md). The daemon meshes as the DEVICE key, and is
# admitted by the other nodes only through its signed DeviceLink.
#
# Config via env:
#   FLEET_DIR   the fixture directory (roster.json, links.json, revoke-*.json, this device's seed)  [required]
#   DEVICE      which device this machine is, as <member>-<device>, e.g. 1-1                      [required]
#   GROUP       shared group id == gossipsub topic (identical on every machine)                    [required]
#   PORT        libp2p TCP listen port (default 4211; open it inbound on the firewall)
#   PEERS       comma-separated bootstrap multiaddrs of machines already running (empty on the first)
#   EXPECT      peers that must be online for PASS (default: number of PEERS, minimum 1)
#   LINKS       links file to load at start (default $FLEET_DIR/links.json). Pointing it at a file
#               without some links reproduces "link not known yet"; load the full file later with
#               the set-roster-json command this script prints, to see the late link take effect.
#   CLUSTER_BIN path to the cluster-daemon binary (default: ./target/release/cluster-daemon)
#   PRINT_ONLY  if 1, print this device's identity and bootstrap multiaddr, then exit
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${CLUSTER_BIN:-$REPO_ROOT/target/release/cluster-daemon}"
PORT="${PORT:-4211}"
FLEET_DIR="${FLEET_DIR:?set FLEET_DIR (the devicelink_fixture output directory)}"
DEVICE="${DEVICE:?set DEVICE as <member>-<device>, e.g. 1-1}"
GROUP="${GROUP:?set GROUP (same on every machine)}"
LINKS="${LINKS:-$FLEET_DIR/links.json}"
PEERS="${PEERS:-}"

die() { echo "ERROR: $*" >&2; exit 1; }
[ -x "$BIN" ] || die "cluster-daemon not found at $BIN; build it: cargo build --release -p cluster-daemon (or set CLUSTER_BIN)"
SEED_SRC="$FLEET_DIR/device-$DEVICE.seed"
[ -r "$SEED_SRC" ] || die "no seed for device $DEVICE at $SEED_SRC"
[ -r "$FLEET_DIR/roster.json" ] || die "missing $FLEET_DIR/roster.json"
[ -r "$LINKS" ] || die "missing links file $LINKS"

WORK="$(mktemp -d)"
trap 'kill "${DPID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
install -m 600 "$SEED_SRC" "$WORK/seed" || die "could not stage the seed"
( umask 077; head -c32 /dev/urandom | (xxd -p 2>/dev/null || od -An -tx1 | tr -d ' \n') | tr -d '\n' > "$WORK/bearer" )
SOCK="$WORK/cluster.sock"

IDENT="$(CITRATE_CLUSTER_SEED_FILE="$WORK/seed" "$BIN" --print-identity)"
SELF_ADDR="$(printf '%s' "$IDENT" | sed -E 's/.*"address":"([0-9a-f]+)".*/\1/')"
SELF_PEERID="$(printf '%s' "$IDENT" | sed -E 's/.*"peerId":"([^"]+)".*/\1/')"
LAN_IP="${LAN_IP:-$(python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(('192.0.2.1',9));print(s.getsockname()[0]);s.close()")}"

echo "------------------------------------------------------------------"
echo " THIS DEVICE ($DEVICE)"
echo "   device address : $SELF_ADDR"
echo "   peerId         : $SELF_PEERID"
echo "   bootstrap addr : /ip4/$LAN_IP/tcp/$PORT/p2p/$SELF_PEERID"
echo "   (give the bootstrap addr to the machines started after this one, as PEERS)"
echo "------------------------------------------------------------------"
# Machine-readable line for scripts: BOOTSTRAP=<multiaddr>
echo "BOOTSTRAP=/ip4/$LAN_IP/tcp/$PORT/p2p/$SELF_PEERID"
[ "${PRINT_ONLY:-0}" = "1" ] && exit 0

if [ -n "$PEERS" ]; then
  NPEERS="$(printf '%s' "$PEERS" | tr ',' '\n' | grep -c .)"
else
  NPEERS=0
fi
EXPECT="${EXPECT:-$(( NPEERS > 0 ? NPEERS : 1 ))}"

echo "> starting cluster-daemon (libp2p) group '$GROUP' on tcp/$PORT, bootstrap: ${PEERS:-none}"
env CITRATE_CLUSTER_SOCKET="$SOCK" \
    CITRATE_CLUSTER_BEARER_FILE="$WORK/bearer" \
    CITRATE_CLUSTER_SELF_ADDR="$SELF_ADDR" \
    CITRATE_CLUSTER_LISTEN="/ip4/0.0.0.0/tcp/$PORT" \
    CITRATE_CLUSTER_SEED_FILE="$WORK/seed" \
    CITRATE_CLUSTER_GROUP="$GROUP" \
    ${PEERS:+CITRATE_CLUSTER_BOOTSTRAP="$PEERS"} \
    "$BIN" & DPID=$!

for _ in $(seq 1 80); do [ -S "$SOCK" ] && break; sleep 0.25; done
[ -S "$SOCK" ] || die "daemon did not bind its socket"

CTL="python3 $REPO_ROOT/scripts/soak/soakctl.py $SOCK $WORK/bearer"
echo "> setRoster with links from $(basename "$LINKS"), then join"
$CTL set-roster-json "$GROUP" "$FLEET_DIR/roster.json" "$LINKS"
$CTL join "$GROUP" >/dev/null

echo "------------------------------------------------------------------"
echo " Commands for the next steps (run in a second terminal on THIS machine):"
echo "   load every link (late link):  $CTL set-roster-json $GROUP $FLEET_DIR/roster.json $FLEET_DIR/links.json"
echo "   revoke device M-D:            $CTL set-roster-json $GROUP $FLEET_DIR/roster.json $FLEET_DIR/links.json $FLEET_DIR/revoke-M-D.json"
echo "   status / peers / devices:     $CTL status $GROUP | $CTL peers $GROUP | $CTL devices $GROUP"
echo "------------------------------------------------------------------"
echo "> waiting for online >= $EXPECT (up to 120 s)"
START_TS=$(date +%s)
ONLINE=0
for i in $(seq 1 120); do
  ST="$($CTL status "$GROUP")"
  ONLINE="$(printf '%s' "$ST" | sed -E 's/.*"online":([0-9]+).*/\1/')"
  [ "${ONLINE:-0}" -ge "$EXPECT" ] && break
  [ $(( i % 10 )) -eq 0 ] && echo "   [$i s] $ST"
  sleep 1
done
ELAPSED=$(( $(date +%s) - START_TS ))

echo "> peers:";   $CTL peers "$GROUP"
echo "> devices:"; $CTL devices "$GROUP"
echo "------------------------------------------------------------------"
if [ "${ONLINE:-0}" -ge "$EXPECT" ]; then
  echo " PASS device $DEVICE: online=$ONLINE (want >= $EXPECT) after ${ELAPSED}s"
else
  echo " FAIL device $DEVICE: online=${ONLINE:-0} (want >= $EXPECT) after ${ELAPSED}s."
  echo "      Check: same GROUP everywhere, TCP $PORT open inbound, PEERS multiaddrs correct,"
  echo "      every machine loaded the same roster.json and links.json."
fi
echo "------------------------------------------------------------------"
echo " The commands for the next steps are printed above. Status every 5 s below (UTC)."
echo " Ctrl-C stops the daemon."
while kill -0 "$DPID" 2>/dev/null; do
  echo "   $(date -u +%H:%M:%S) $($CTL status "$GROUP" 2>/dev/null || echo unreachable)"
  sleep 5
done
