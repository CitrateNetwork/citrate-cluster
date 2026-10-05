#!/usr/bin/env bash
# multigroup-node.sh: run ONE device of the HUP-S8.4 multi-group soak. One cluster-daemon process
# serves every group in GROUP_IDS (no CITRATE_CLUSTER_GROUP), one swarm per group on its own port.
# Machines find each other from group links (seeds) passed in SEEDS, or by mDNS when MDNS=1.
#
# Uses the same fixture as devicelink-node.sh (devicelink_fixture; test keys only). See
# DEVICELINK_MULTI_MACHINE.md, section 4.
#
# Config via env:
#   FLEET_DIR   the fixture directory                                                [required]
#   DEVICE      this machine's device, as <member>-<device>, e.g. 1-1                [required]
#   GROUP_IDS      comma-separated group ids, identical on every machine               [required]
#   PORT        base TCP port (default 4211). Each group listens on PORT + keccak(group) mod 1024
#               (printed below); open that range inbound, or at least the printed ports.
#   SEEDS       file with one group link per line (the SEED= lines another machine printed); empty
#               on the first machine
#   MDNS        1 turns on LAN discovery (default 0). Needs a daemon built with
#               `--features mdns`; a default build refuses it at start-up.
#   EXPECT      peers that must be online in EVERY group for PASS (default 1)
#   CLUSTER_BIN path to the cluster-daemon binary (default: ./target/release/cluster-daemon)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${CLUSTER_BIN:-$REPO_ROOT/target/release/cluster-daemon}"
PORT="${PORT:-4211}"
FLEET_DIR="${FLEET_DIR:?set FLEET_DIR (the devicelink_fixture output directory)}"
DEVICE="${DEVICE:?set DEVICE as <member>-<device>, e.g. 1-1}"
GROUP_IDS="${GROUP_IDS:?set GROUP_IDS (comma-separated, same on every machine)}"
SEEDS="${SEEDS:-}"
EXPECT="${EXPECT:-1}"

die() { echo "ERROR: $*" >&2; exit 1; }
[ -x "$BIN" ] || die "cluster-daemon not found at $BIN; build it: cargo build --release -p cluster-daemon"
SEED_SRC="$FLEET_DIR/device-$DEVICE.seed"
[ -r "$SEED_SRC" ] || die "no seed for device $DEVICE at $SEED_SRC"
[ -z "$SEEDS" ] || [ -r "$SEEDS" ] || die "SEEDS file $SEEDS not readable"

WORK="$(mktemp -d)"
trap 'kill "${DPID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
install -m 600 "$SEED_SRC" "$WORK/seed" || die "could not stage the seed"
( umask 077; head -c32 /dev/urandom | (xxd -p 2>/dev/null || od -An -tx1 | tr -d ' \n') | tr -d '\n' > "$WORK/bearer" )
SOCK="$WORK/cluster.sock"
IDENT="$(CITRATE_CLUSTER_SEED_FILE="$WORK/seed" "$BIN" --print-identity)"
SELF_ADDR="$(printf '%s' "$IDENT" | sed -E 's/.*"address":"([0-9a-f]+)".*/\1/')"
SELF_PEERID="$(printf '%s' "$IDENT" | sed -E 's/.*"peerId":"([^"]+)".*/\1/')"

echo "> device $DEVICE  address $SELF_ADDR  peerId $SELF_PEERID"
echo "> starting ONE cluster-daemon for groups: $GROUP_IDS (base port $PORT, mDNS ${MDNS:-0})"
env -u CITRATE_CLUSTER_GROUP -u CITRATE_CLUSTER_BOOTSTRAP \
    CITRATE_CLUSTER_SOCKET="$SOCK" \
    CITRATE_CLUSTER_BEARER_FILE="$WORK/bearer" \
    CITRATE_CLUSTER_SELF_ADDR="$SELF_ADDR" \
    CITRATE_CLUSTER_LISTEN="/ip4/0.0.0.0/tcp/$PORT" \
    CITRATE_CLUSTER_SEED_FILE="$WORK/seed" \
    CITRATE_CLUSTER_MDNS="${MDNS:-0}" \
    "$BIN" & DPID=$!
for _ in $(seq 1 80); do [ -S "$SOCK" ] && break; sleep 0.25; done
[ -S "$SOCK" ] || die "daemon did not bind its socket"

CTL="python3 $REPO_ROOT/scripts/soak/soakctl.py $SOCK $WORK/bearer"
IFS=',' read -r -a GROUP_LIST <<< "$GROUP_IDS"
for g in "${GROUP_LIST[@]}"; do
  $CTL set-roster-json "$g" "$FLEET_DIR/roster.json" "$FLEET_DIR/links.json" >/dev/null
  $CTL join "$g" >/dev/null
done
sleep 1
echo "------------------------------------------------------------------"
echo " This machine's group links (copy the SEED= lines into the SEEDS file of the next machine):"
for g in "${GROUP_LIST[@]}"; do
  S="$($CTL seed "$g")" || die "no link for $g: $S"
  echo "SEED=$(printf '%s' "$S" | python3 -c 'import json,sys;print(json.load(sys.stdin)["seed"])')"
  echo "   $g listens on: $(printf '%s' "$S" | python3 -c 'import json,sys;print(", ".join(json.load(sys.stdin)["addrs"]))')"
done
echo "------------------------------------------------------------------"
if [ -n "$SEEDS" ]; then
  while IFS= read -r line; do
    line="${line#SEED=}"
    [ -z "$line" ] && continue
    g="$(printf '%s' "$line" | python3 -c 'import sys,urllib.parse as u;q=u.parse_qs(sys.stdin.read().split("?",1)[1]);print(q["g"][0])')"
    echo "> add-seed $g: $($CTL add-seed "$g" "$line")"
  done < "$SEEDS"
fi
echo " Commands (second terminal on THIS machine):"
echo "   revoke device M-D in one group: $CTL set-roster-json <group> $FLEET_DIR/roster.json $FLEET_DIR/links.json $FLEET_DIR/revoke-M-D.json"
echo "   status / peers per group:       $CTL status <group> | $CTL peers <group>"
echo "------------------------------------------------------------------"
echo "> waiting for online >= $EXPECT in every group (up to 120 s)"
START_TS=$(date +%s)
ALL_OK=0
for i in $(seq 1 120); do
  ALL_OK=1
  for g in "${GROUP_LIST[@]}"; do
    ON="$($CTL status "$g" | sed -E 's/.*"online":([0-9]+).*/\1/')"
    [ "${ON:-0}" -ge "$EXPECT" ] || ALL_OK=0
  done
  [ "$ALL_OK" = 1 ] && break
  sleep 1
done
ELAPSED=$(( $(date +%s) - START_TS ))
for g in "${GROUP_LIST[@]}"; do echo "   $g: $($CTL status "$g")"; done
if [ "$ALL_OK" = 1 ]; then
  echo " PASS device $DEVICE: every group has >= $EXPECT online after ${ELAPSED}s"
else
  echo " FAIL device $DEVICE: some group below $EXPECT online after ${ELAPSED}s (ports open? same GROUP_IDS? links loaded?)"
fi
echo " Status every 5 s below (UTC). Ctrl-C stops the daemon."
while kill -0 "$DPID" 2>/dev/null; do
  LINE="$(date -u +%H:%M:%S)"
  for g in "${GROUP_LIST[@]}"; do
    LINE="$LINE $g=$($CTL status "$g" 2>/dev/null | sed -E 's/.*"online":([0-9]+).*/\1/' || echo '?')"
  done
  echo "   $LINE"
  sleep 5
done
