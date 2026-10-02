#!/usr/bin/env python3
"""soakctl — a tiny UDS client for the cluster-daemon IPC (CL-S3 soak).

Speaks the loopback JSON-per-line protocol: authenticate with the bearer, send one request, print the
response. Stdlib only, so it runs unchanged on macOS and Linux (no build).

Usage:
  soakctl.py <socket> <bearer-file> set-roster <group> <addr:role,addr:role,...>
  soakctl.py <socket> <bearer-file> join       <group>
  soakctl.py <socket> <bearer-file> leave      <group>
  soakctl.py <socket> <bearer-file> status     <group>
  soakctl.py <socket> <bearer-file> peers      <group>
  soakctl.py <socket> <bearer-file> share      <group> <cid>
  soakctl.py <socket> <bearer-file> set-roster-json <group> <roster.json> [<links.json> [<revocations.json>]]
  soakctl.py <socket> <bearer-file> devices    <group>

set-roster-json (HUP-S8.1 DeviceLink soak) reads the roster ([[address, role], ...]), the signed
device links and the signed revocations from JSON files, as written by the cluster-daemon example
`devicelink_fixture`; `devices` lists each member's linked devices with live state.

Prints the daemon's JSON response to stdout; exits 0 on an ok/typed response, 1 on an error response
or transport failure.
"""
import json
import socket
import sys


def read_json(path):
    with open(path) as f:
        return json.load(f)


def build_request(op, args):
    if op == "set-roster":
        group, roster = args[0], args[1]
        pairs = [entry.split(":", 1) for entry in roster.split(",") if entry.strip()]
        return {"op": "setRoster", "group": group, "roster": [[a, r] for a, r in pairs]}
    if op == "join":
        return {"op": "join", "group": args[0]}
    if op == "leave":
        return {"op": "leave", "group": args[0]}
    if op == "status":
        return {"op": "status", "group": args[0]}
    if op == "peers":
        return {"op": "peers", "group": args[0]}
    if op == "share":
        return {"op": "shareFile", "group": args[0], "cid": args[1]}
    if op == "set-roster-json":
        group = args[0]
        req = {"op": "setRoster", "group": group, "roster": read_json(args[1])}
        if len(args) > 2:
            req["devices"] = read_json(args[2])
        if len(args) > 3:
            req["revocations"] = read_json(args[3])
        return req
    if op == "devices":
        return {"op": "devices", "group": args[0]}
    raise SystemExit(f"unknown op: {op}")


def main():
    if len(sys.argv) < 5:
        raise SystemExit(__doc__)
    sock_path, bearer_file, op = sys.argv[1], sys.argv[2], sys.argv[3]
    args = sys.argv[4:]
    with open(bearer_file) as f:
        bearer = f.read().strip()

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)
    f = s.makefile("rw")
    # auth handshake
    f.write(json.dumps({"token": bearer}) + "\n")
    f.flush()
    ready = f.readline()
    if "ready" not in ready:
        print(ready.strip() or "no ready", file=sys.stderr)
        return 1
    # one request → one response
    f.write(json.dumps(build_request(op, args)) + "\n")
    f.flush()
    resp = f.readline().strip()
    print(resp)
    try:
        return 1 if json.loads(resp).get("type") == "error" else 0
    except ValueError:
        return 1


if __name__ == "__main__":
    sys.exit(main())
