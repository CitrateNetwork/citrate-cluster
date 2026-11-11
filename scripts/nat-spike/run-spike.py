#!/usr/bin/env python3
"""run-spike.py: one run of the V60 S0-NAT-SPIKE in the netns topology from netns.sh (root).

Starts the spike relay in v60-relay and a cluster-daemon in v60-a and v60-b (pinned to one group,
each reserving on the relay), gives A only B's group link, and measures:

  * when A first sees B online, and over which link (relayed or direct);
  * when the link turns direct (DCUtR hole punch), if it does;
  * that a co-pinned CID from A reaches B;
  * with --kill-relay: after the link is direct, the relay is killed and a second CID must still
    reach B (the direct connection carries the mesh on its own).

Every process runs inside a v60-* namespace on this host. Nothing here reaches another host: the
relay, both members and both NATs are local namespaces. Test keys are fixed bytes (never a
production key). Stdlib only.

Usage: run-spike.py --bin-dir DIR --out DIR --label NAME [--kill-relay] [--wait-direct SECS] [--groups N]

--groups N (V60 MESH-3): N > 1 runs both daemons unpinned (one daemon, N group swarms each) and
checks every group meets over the relay on its own swarm, with its own co-pin.
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time

GROUP = "v60-nat-spike"
CID1 = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
CID2 = "bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
RELAY_IP = "10.99.0.1"
RELAY_PORT = 4100
MEMBER_PORT = 4201


def now_ms():
    return int(time.time() * 1000)


def write_secret(path, hexstr):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(hexstr)


def seed_hex(b):
    return (bytes([b | 1]) + bytes([b] * 31)).hex()


class Ipc:
    def __init__(self, sock, bearer):
        self.sock, self.bearer = sock, bearer

    def call(self, req):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(self.sock)
        f = s.makefile("rw")
        f.write(json.dumps({"token": self.bearer}) + "\n")
        f.flush()
        if "ready" not in f.readline():
            raise RuntimeError("ipc auth failed")
        f.write(json.dumps(req) + "\n")
        f.flush()
        resp = json.loads(f.readline())
        s.close()
        return resp


def wait_socket(path, within=20):
    deadline = time.time() + within
    while time.time() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.05)
    raise RuntimeError(f"socket {path} never appeared")


def ns_ss(ns):
    out = subprocess.run(["ip", "netns", "exec", ns, "ss", "-tn"], capture_output=True, text=True)
    return [l for l in out.stdout.splitlines()[1:] if "ESTAB" in l]


def run_groups(ipc, groups, roster, ida, idb, wait_direct):
    """V60 MESH-3: every group meets over the relay on its own swarm, with its own co-pin."""
    out = {}
    for g in groups:
        for n in ("a", "b"):
            for op in ({"op": "setRoster", "group": g, "roster": roster}, {"op": "join", "group": g}):
                r = ipc[n].call(op)
                assert r.get("type") != "error", r
    for i, g in enumerate(groups):
        rec = {}
        t = now_ms()
        seed = None
        while now_ms() - t < 20000:
            r = ipc["b"].call({"op": "seed", "group": g})
            if r.get("type") == "seed" and any("p2p-circuit" in x for x in r.get("addrs", [])):
                seed = r
                break
            time.sleep(0.1)
        if not seed:
            out[g] = {"error": "B never offered a relayed address"}
            continue
        rec["b_peer"] = seed["addrs"][-1].rsplit("/p2p/", 1)[-1]
        t0 = now_ms()
        ipc["a"].call({"op": "addSeed", "group": g, "seed": seed["seed"]})
        while now_ms() - t0 < (wait_direct + 30) * 1000:
            peers = ipc["a"].call({"op": "peers", "group": g}).get("peers", [])
            pb = next((p for p in peers if p["address"] == idb["address"]), None)
            if pb and pb["online"]:
                rec.setdefault("online_ms", now_ms() - t0)
                rec.setdefault("first_link", pb.get("link"))
                if pb.get("link") == "direct":
                    rec["direct_ms"] = now_ms() - t0
                    break
            if "online_ms" in rec and now_ms() - t0 > rec["online_ms"] + wait_direct * 1000:
                break
            time.sleep(0.1)
        if "online_ms" not in rec:
            rec["error"] = "A never saw B online in this group"
        else:
            cid = CID1[:-1] + "abcdefghijklmnopqrstuvwxyz"[i % 26]  # one valid CID per group
            t1 = now_ms()
            while now_ms() - t1 < 20000:
                ipc["a"].call({"op": "shareFile", "group": g, "cid": cid})
                if cid in ipc["b"].call({"op": "status", "group": g}).get("sharedFiles", []):
                    rec["cid_ms"] = now_ms() - t1
                    break
                time.sleep(0.25)
            others = [h for h in groups if h != g]
            rec["cid_leaked_to"] = [h for h in others if cid in
                                    ipc["b"].call({"op": "status", "group": h}).get("sharedFiles", [])]
        out[g] = rec
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--kill-relay", action="store_true")
    ap.add_argument("--wait-direct", type=float, default=45.0)
    ap.add_argument("--groups", type=int, default=1)
    a = ap.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run as root (ip netns exec)")
    daemon = os.path.join(a.bin_dir, "cluster-daemon")
    relay_bin = os.path.join(a.bin_dir, "examples", "spike_relay")
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    work = os.path.join(out, "work")
    os.makedirs(work, exist_ok=True)
    os.chmod(work, 0o700)

    seeds = {"relay": 0x31, "a": 0x41, "b": 0x42}
    for n, b in seeds.items():
        write_secret(f"{work}/{n}.seed", seed_hex(b))
        write_secret(f"{work}/{n}.bearer", os.urandom(32).hex())

    groups = [GROUP] if a.groups <= 1 else [f"{GROUP}-{i}" for i in range(a.groups)]

    def identity(n):
        env = dict(os.environ, CITRATE_CLUSTER_SEED_FILE=f"{work}/{n}.seed")
        argv = [daemon, "--print-identity"]
        for g in groups:
            argv += ["--group", g]
        return json.loads(subprocess.check_output(argv, env=env))

    ida, idb = identity("a"), identity("b")
    relay_id = json.loads(subprocess.check_output(
        [relay_bin, "--print-identity"],
        env=dict(os.environ, CITRATE_RELAY_SEED_FILE=f"{work}/relay.seed")))["peerId"]
    relay_addr = f"/ip4/{RELAY_IP}/tcp/{RELAY_PORT}/p2p/{relay_id}"

    procs = []
    logs = {}

    def spawn(name, ns, argv, env):
        logs[name] = open(f"{out}/{name}.log", "w")
        p = subprocess.Popen(["ip", "netns", "exec", ns, "env", *[f"{k}={v}" for k, v in env.items()], *argv],
                             stdout=logs[name], stderr=subprocess.STDOUT)
        procs.append(p)
        return p

    result = {"label": a.label, "relay": relay_addr, "a": ida, "b": idb}
    try:
        relay_p = spawn("relay", "v60-relay", [relay_bin], {
            "CITRATE_RELAY_SEED_FILE": f"{work}/relay.seed",
            "CITRATE_RELAY_LISTEN": f"/ip4/0.0.0.0/tcp/{RELAY_PORT}",
            # V60 MESH-3: with relays, each group swarm uses its group key's PeerId.
            "CITRATE_RELAY_ALLOW": ",".join(
                list(ida["groupPeerIds"].values()) + list(idb["groupPeerIds"].values())),
        })
        time.sleep(0.5)
        ipc = {}
        for n, ident in (("a", ida), ("b", idb)):
            sock = f"{work}/{n}.sock"
            if os.path.exists(sock):
                os.unlink(sock)
            env = {
                "CITRATE_CLUSTER_SOCKET": sock,
                "CITRATE_CLUSTER_BEARER_FILE": f"{work}/{n}.bearer",
                "CITRATE_CLUSTER_SELF_ADDR": ident["address"],
                "CITRATE_CLUSTER_SEED_FILE": f"{work}/{n}.seed",
                "CITRATE_CLUSTER_LISTEN": f"/ip4/0.0.0.0/tcp/{MEMBER_PORT}",
                "CITRATE_CLUSTER_RELAYS": relay_addr,
            }
            if len(groups) == 1:
                env["CITRATE_CLUSTER_GROUP"] = GROUP
            spawn(n, f"v60-{n}", [daemon], env)
            wait_socket(sock)
            ipc[n] = Ipc(sock, open(f"{work}/{n}.bearer").read().strip())
        roster = [[ida["address"], "member"], [idb["address"], "member"]]
        if len(groups) > 1:
            result["groups"] = run_groups(ipc, groups, roster, ida, idb, a.wait_direct)
            raise StopIteration
        for n in ("a", "b"):
            r = ipc[n].call({"op": "setRoster", "group": GROUP, "roster": roster})
            assert r.get("type") != "error", r
            r = ipc[n].call({"op": "join", "group": GROUP})
            assert r.get("type") != "error", r

        # B's link must carry its relayed address (its reservation was accepted).
        t_start = now_ms()
        b_seed = None
        while now_ms() - t_start < 20000:
            r = ipc["b"].call({"op": "seed", "group": GROUP})
            if r.get("type") == "seed" and any("p2p-circuit" in x for x in r.get("addrs", [])):
                b_seed = r
                break
            time.sleep(0.1)
        if not b_seed:
            raise RuntimeError("B never offered a relayed address")
        result["b_reservation_ms"] = now_ms() - t_start
        result["b_seed_addrs"] = b_seed["addrs"]

        t0 = now_ms()
        r = ipc["a"].call({"op": "addSeed", "group": GROUP, "seed": b_seed["seed"]})
        result["a_add_seed"] = r
        first_link = t_online = t_direct = None
        while now_ms() - t0 < (a.wait_direct + 30) * 1000:
            peers = ipc["a"].call({"op": "peers", "group": GROUP}).get("peers", [])
            pb = next((p for p in peers if p["address"] == idb["address"]), None)
            if pb and pb["online"]:
                if t_online is None:
                    t_online, first_link = now_ms() - t0, pb.get("link")
                if pb.get("link") == "direct" and t_direct is None:
                    t_direct = now_ms() - t0
                    break
            if t_online is not None and now_ms() - t0 > t_online + a.wait_direct * 1000:
                break
            time.sleep(0.1)
        result.update(online_ms=t_online, first_link=first_link, direct_ms=t_direct)
        if t_online is None:
            raise RuntimeError("A never saw B online")

        def cid_reaches_b(cid, within=20):
            t = now_ms()
            while now_ms() - t < within * 1000:
                ipc["a"].call({"op": "shareFile", "group": GROUP, "cid": cid})
                st = ipc["b"].call({"op": "status", "group": GROUP})
                if cid in st.get("sharedFiles", []):
                    return now_ms() - t
                time.sleep(0.25)
            return None

        result["cid1_ms"] = cid_reaches_b(CID1)
        time.sleep(1)
        result["a_tcp"] = ns_ss("v60-a")
        result["b_tcp"] = ns_ss("v60-b")
        peers = ipc["a"].call({"op": "peers", "group": GROUP}).get("peers", [])
        result["a_peers_before_kill"] = peers

        if a.kill_relay:
            relay_p.terminate()
            relay_p.wait(5)
            time.sleep(3)
            result["cid2_after_relay_killed_ms"] = cid_reaches_b(CID2)
            result["a_peers_after_kill"] = ipc["a"].call({"op": "peers", "group": GROUP}).get("peers", [])
            result["a_tcp_after_kill"] = ns_ss("v60-a")
    except StopIteration:
        if any(g.get("error") for g in result["groups"].values()):
            result["error"] = "a group failed: " + json.dumps(
                {k: v.get("error") for k, v in result["groups"].items() if v.get("error")})
    except Exception as e:  # recorded, not hidden
        result["error"] = str(e)
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        for f in logs.values():
            f.close()

    # The daemons' own timeline (epoch ms) from their NAT log lines.
    for n in ("a", "b"):
        result[f"{n}_log"] = [l.strip() for l in open(f"{out}/{n}.log") if l.startswith("cluster-mesh:")]
    relay_lines = [l for l in open(f"{out}/relay.log") if l.startswith("{")]
    result["relay_last"] = json.loads(relay_lines[-1]) if relay_lines else None
    with open(f"{out}/result.json", "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps({k: result.get(k) for k in (
        "label", "b_reservation_ms", "online_ms", "first_link", "direct_ms", "cid1_ms",
        "cid2_after_relay_killed_ms", "groups", "relay_last", "error") if k in result}))
    return 1 if "error" in result else 0


if __name__ == "__main__":
    sys.exit(main())
