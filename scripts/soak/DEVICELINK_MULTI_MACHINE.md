---
created: 2026-10-01
branch: hup/n5-fleet-rest
author: Larry Klosowski + Claude Opus 5.5
status: runbook (ready for the DGX team; not yet run across machines)
---

# DeviceLink soak across two and three machines (HUP-S8.1, S8.4 prep)

This is the daemon-level run: no Citrate Core app, no sign-in, no wallet. It proves on real
networks what `crates/cluster-daemon/tests/fleet_multiprocess.rs` proves on one machine:

1. each device meshes under its own key, so every machine has its own PeerId;
2. a device is admitted only through a signed DeviceLink, including another member's device;
3. a link that arrives after start-up takes effect without a restart (bootstrap re-dial);
4. a revocation evicts the device from every node that applies it, and its re-dials are refused.

The app-level run (wizard, ceremony, two people at two machines) is separate:
citrate-core `docs/FLEET_MULTI_MACHINE_TEST.md` (branch `hup/n5-fleet-rest`).

## Keys

`devicelink_fixture` mints fresh random test keys for every member, wallet and device, signs the
links and revocations in memory, and writes only the device seeds (0600) plus public JSON. Member
and wallet secrets are never written. Never use a real wallet for this run.

## 0. Build (every machine)

```sh
git clone https://github.com/CitrateNetwork/citrate-cluster && cd citrate-cluster
git checkout hup/n5-fleet-rest
cargo build --release -p cluster-daemon
```

## 1. Make the fixture (one machine), copy it

```sh
# two machines: two members, one device each
cargo run --release -p cluster-daemon --example devicelink_fixture -- /tmp/fleet2 1 1
# three machines: member 1 with two devices, member 2 with one
cargo run --release -p cluster-daemon --example devicelink_fixture -- /tmp/fleet3 2 1
```

Copy the directory to every machine (`scp -rp`, keep the 0600 mode on `device-*.seed`). Each
machine only needs its own seed, but the JSON files must be identical everywhere.

Open the listen port inbound on every machine (default TCP 4211; Linux: `sudo ufw allow 4211/tcp`).

## 2. Two machines (Mac = device 1-1, DGX = device 2-1)

On the Mac:

```sh
FLEET_DIR=/tmp/fleet2 DEVICE=1-1 GROUP=hup-s8-two scripts/soak/devicelink-node.sh
```

Copy its `BOOTSTRAP=` value. On the DGX, first load only the DGX's own link, to reproduce "the
other member's link is not known yet":

```sh
python3 - <<'PY'
import json; links=json.load(open('/tmp/fleet2/links.json'))
fleet=json.load(open('/tmp/fleet2/fleet.json'))
mine=fleet['members'][1]['devices'][0]['device']
json.dump([l for l in links if l['device']==mine], open('/tmp/fleet2/links-own.json','w'))
PY
FLEET_DIR=/tmp/fleet2 DEVICE=2-1 GROUP=hup-s8-two PEERS=<Mac BOOTSTRAP> \
  LINKS=/tmp/fleet2/links-own.json EXPECT=1 scripts/soak/devicelink-node.sh
```

Expect: the DGX's progress lines show `online:0` (it refuses the Mac's device: no link yet). While
it waits (120 s), run the "load every link" command the script printed, in a second terminal on
the DGX. Expect within about 10 s: `PASS` on both machines, with no restart. (Dry run on one Mac,
loopback: 0 online before, `PASS` on both about 10 s after the load.)

Record: both PeerIds (printed at start), the time from "load every link" to `online:1`, and the
`peers` and `devices` output on both sides.

## 3. Three machines (Mac = 1-1, DGX = 1-2, x86 droplet or second Linux box = 2-1)

Start in order, each with the earlier machines' `BOOTSTRAP=` values:

```sh
# Mac
FLEET_DIR=/tmp/fleet3 DEVICE=1-1 GROUP=hup-s8-three EXPECT=2 scripts/soak/devicelink-node.sh
# DGX
FLEET_DIR=/tmp/fleet3 DEVICE=1-2 GROUP=hup-s8-three PEERS=<Mac> EXPECT=2 scripts/soak/devicelink-node.sh
# third machine
FLEET_DIR=/tmp/fleet3 DEVICE=2-1 GROUP=hup-s8-three PEERS=<Mac>,<DGX> EXPECT=2 scripts/soak/devicelink-node.sh
```

Expect `PASS ... online=2` on all three (full mesh, three distinct PeerIds).

Revoke device 1-2 (the DGX) on the Mac and on the third machine with the printed "revoke device
M-D" command, using `revoke-1-2.json`. Expect on both: `evicted` names the DGX's device address;
within about 10 s the DGX's status shows `online:0` and the other two keep `online:1`. Leave it
running for 2 minutes: the DGX keeps re-dialing every 5 s and must stay at `online:0`.

Record: the three PeerIds, revoke-to-drop time on each side, and whether any re-dial got in.

## Single-machine reference numbers (2026-10-01, Apple M-series, debug build)

From `CLUSTER_LADDER_N=<n> cargo test -p cluster-daemon --test ladder_multiprocess -- --ignored --nocapture`
(one member and one device per node, full mesh on loopback):

| nodes | full mesh after the last roster update | one co-pin reaches every node |
|---|---|---|
| 4 | 0.28 s | 0.52 s |
| 16 | 0.31 s | 0.53 s |
| 32 | 32.5 s | 0.56 s |
| 50 | 13.1 s | 0.55 s |

The 32-node run's longer mesh time comes from nodes that connected before their roster update and
waited for the next 5-second re-dial. These are per-machine controls, not the CL-S3 ladder: the
transport has no peer discovery, so every node must bootstrap to every other node, and incoming
connections are capped at 64 per node, which makes about 65 nodes the full-mesh ceiling today.
