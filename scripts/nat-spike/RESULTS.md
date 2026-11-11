---
created: 2026-11-11
branch: v60/s0-nat-spike
author: Larry Klosowski + Claude Opus 5.5
status: spike results (V60 S0-NAT-SPIKE); nothing deployed
wp: S0-NAT-SPIKE (0.6.0 planset 05, MESH lane)
---

# S0-NAT-SPIKE: circuit relay v2 + DCUtR through NAT, in network namespaces

## Question

Can two members' machines behind different NATs join one cluster mesh, first through a relay and
then directly (DCUtR hole punching), and does the relay carry the mesh when hole punching fails?

## Answer

- **Endpoint-independent NAT (Linux MASQUERADE, port kept):** yes, in 6 of 6 runs. The members met
  through the relay about 260 ms after A got B's link, and DCUtR produced a direct TCP connection
  185 ms after that. Killing the relay then left the mesh up: a second co-pin reached B over the
  direct connection alone.
- **Symmetric NAT (MASQUERADE `--random-fully`):** hole punching failed in 4 of 4 runs, as expected
  (libp2p gave up after 3 attempts, about 30 s after the members met). The relay carried the mesh:
  B stayed online over the circuit, marked `relayed`, and co-pins arrived in under 300 ms.

What this does not show: real home routers, carrier-grade NAT, NATs that change the mapping while it
is in use, UDP/QUIC hole punching (not built), IPv6, and more than two members. The two-home-network
soak (MESH-5) is the test for those.

## Setup

One Linux host (`citrate-core-linux-build`, kernel 5.15, root), six network namespaces built by
[`netns.sh`](netns.sh). Nothing was added to the host's own namespace, and no other host was used.

```
            v60-inet (bridge, 10.99.0.0/24, "the internet")
           /                 |                    \
  v60-relay 10.99.0.1   v60-nata WAN 10.99.0.2   v60-natb WAN 10.99.0.3
                        NAT, LAN 192.168.10.1     NAT, LAN 192.168.20.1
                              |                         |
                        v60-a 192.168.10.2        v60-b 192.168.20.2
```

- Each router NATs its LAN out of its WAN, forwards only established/related traffic inbound and
  answers nothing on its WAN address. `netns.sh` checks that A and B reach the relay and that neither
  reaches the other (ping to B's LAN address and to B's router both fail).
- 20 ms one-way delay on each router's WAN link (netem), so A to relay is 40 ms round trip and A to
  B direct is 80 ms.
- Relay: `examples/spike_relay` (the `relay_node` module), allow list = the two members' PeerIds.
- Members: `cluster-daemon` release build from this branch, `CITRATE_CLUSTER_LISTEN=/ip4/0.0.0.0/tcp/4201`,
  `CITRATE_CLUSTER_GROUP` pinned to one group, `CITRATE_CLUSTER_RELAYS` = the relay.
- Driver: [`run-spike.py`](run-spike.py) over the daemons' real UDS IPC: roster with both members,
  join, wait for B's link to carry its relayed address, give A only B's link (`addSeed`), poll A's
  `peers` every 100 ms, co-pin from A and check B's `sharedFiles`; with `--kill-relay`, kill the
  relay after the link is direct and co-pin again.

Test keys are fixed bytes, never production keys.

## Results

Times in ms. "met" and "direct" are from A's `addSeed`, polled every 100 ms. "punch" is the gap in
the daemons' own log between admitting B over the relay and the direct connection (or the failure).

| Run | NAT | met (link) | direct | punch | co-pin 1 | co-pin 2 after relay killed |
|---|---|---|---|---|---|---|
| cone-2 | endpoint-independent | 251 (relayed) | 484 | 186 | 308 | 44 |
| cone-3 | endpoint-independent | 280 (relayed) | 400 | 185 | 308 | 42 |
| cone-4 | endpoint-independent | 270 (relayed) | 388 | 185 | 328 | 320 |
| cone-5 | endpoint-independent | 261 (relayed) | 393 | 186 | 321 | 304 |
| cone-6 | endpoint-independent | 263 (relayed) | 377 | 186 | 326 | 306 |
| cone-7 | endpoint-independent | 260 (relayed) | 380 | 185 | 328 | 321 |
| sym-1 | symmetric | 279 (relayed) | never | failed at 30 302 | 293 | not run |
| sym-2 | symmetric | 276 (relayed) | never | failed at 30 293 | 289 | not run |
| sym-3 | symmetric | 247 (relayed) | never | failed at 30 293 | 296 | not run |
| sym-long | symmetric | 207 (relayed) | never | failed at 30 269 | 324 (after 150 s) | not run |

The per-run records (timings, `ss` snapshots, the daemons' NAT log lines) are in
[`runs-2026-11-11.jsonl`](runs-2026-11-11.jsonl), cone-1 (the failed run, see below) included.

Evidence of the path, from `ss -tn` inside the namespaces (cone-2):

- before the relay was killed, A had `192.168.10.2:4201 -> 10.99.0.3:4201` (B's router, so through
  both NATs, no relay) and `192.168.10.2:4201 -> 10.99.0.1:4100` (the relay);
- after the relay was killed, only `192.168.10.2:4201 -> 10.99.0.3:4201` remained, B was still
  online with `link: direct`, and co-pin 2 arrived;
- in the symmetric runs, A's only connection was to the relay, and `peers` showed `link: relayed`.

The relay counted 2 reservations and 1 circuit in every run. sym-long kept the relayed link for
150 s on one circuit, past libp2p's default 2-minute circuit limit (this relay allows 30 minutes).

## Bug found by the spike (fixed on this branch, red test first)

Run cone-1 failed: A never met B. B's link lists its LAN address before its relayed address. The
daemon dialed each address on its own, and libp2p refuses a second dial to a peer while one is in
flight, so only the LAN address (unreachable from A's network) was ever tried, on every re-dial.
Now every address of one peer goes into one dial attempt (`redial_plan`). Tests:
`a_seed_whose_first_address_is_dead_still_reaches_the_peer`,
`a_redial_plan_dials_every_address_of_a_peer_in_one_attempt`.

## Findings for MESH-3 (the production relay) and MESH-4 (reachability in the UI)

1. **The relay hop needs its own Noise prologue.** Every cluster TCP session is bound to its group
   (prologue = group id, CL-B-009). A relay serves many groups, so a member uses
   `/citrate/cluster-relay/1` on a connection it dials to a configured relay, and the group prologue
   everywhere else. The member-to-member session through the relay is a separate Noise session that
   keeps the group prologue, so the relay sees ciphertext and cannot join a group. This needed a
   hand-written TCP upgrade (`mesh_tcp_transport`) because libp2p's builder applies one upgrade to
   every connection.
2. **One daemon, many groups, one PeerId: circuits can reach the wrong swarm.** Each group swarm
   reserves on the relay under the same PeerId, and the relay routes a circuit to the first
   connection holding a reservation for that PeerId (`libp2p-relay` 0.21.1, `behaviour.rs`). A
   circuit for group B can land on group A's swarm and fail the Noise prologue. The spike ran with
   one pinned group. MESH-3 has to pick a fix: a per-group relay PeerId, one relay connection that
   carries every group's circuits, or a relay that routes by group.
3. **AutoNAT does not fit as is.** AutoNAT v1 decides reachability by having a server dial back to
   the member's listen address. The server's TCP session would use its own prologue and the member's
   listener expects the group prologue, so every dial-back would fail and every member would look
   private. It was left out. For MESH-4, the link kind per peer (`direct`/`relayed`, now in `peers`)
   and the hole-punch counters already give the cluster map its solid and dashed edges. A real
   reachability probe needs a listener that accepts the relay prologue (or AutoNAT v2 on it).
4. **The relay must announce its own public address.** A client refuses a reservation that names no
   relay address. The spike relay announces every listen address it binds; the production relay
   should announce only its configured public address.
5. **Reservation gating is an allow list of PeerIds here.** MESH-3's rule is that a reservation
   needs a signed DeviceLink (`relay_refuses_unlinked_device`). The allow list is checked when the
   connection is established, before any relay request is read, which is the right place for the
   DeviceLink check too.
6. **Circuit limits.** This relay allows 30 minutes and 4 MiB per circuit (libp2p defaults: 2
   minutes, 128 KiB). When a circuit closes, a relayed-only pair is offline until the next re-dial
   (at most 5 s). The owner approved these limits on 2026-11-11.
7. **Seeds still carry LAN addresses.** Harmless now (they fail fast and no longer block the relayed
   address), but a member's private address is in every link it shares.

## How to run

On a Linux host, as root, from this directory:

```
cargo build --release --locked -p cluster-daemon --bin cluster-daemon --example spike_relay
./netns.sh up cone 20          # or: ./netns.sh up symmetric 20
python3 run-spike.py --bin-dir ../../target/release --out /tmp/nat-run --label cone-1 --kill-relay
./netns.sh down
```

`run-spike.py` writes `result.json` (timings, `ss` snapshots, peers, the daemons' NAT log lines) and
the three processes' logs into `--out`.
