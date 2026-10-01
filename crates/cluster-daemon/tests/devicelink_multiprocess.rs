//! HUP-S8.1 single-machine, multi-process DeviceLink test.
//!
//! Three real `cluster-daemon` PROCESSES on loopback, each with its own random-style device key as
//! its libp2p identity, speaking the real UDS IPC and the real TCP + Noise + gossipsub transport:
//!
//! * `laptop` and `linux` are two devices of ONE member (one comms identity), each with a real
//!   three-signature DeviceLink (member, device and wallet keys, EIP-191 over secp256k1);
//! * `rogue` is a third process with a device key that has no link.
//!
//! It proves, on one machine, what the two-machine soak proves across a network:
//!   1. the two devices of one member mesh with DISTINCT PeerIds (one per device key);
//!   2. both are listed under the member in the roster (`Devices`);
//!   3. a device with no valid link is never admitted (the positive control is the linked device);
//!   4. a member revocation evicts the device in the same `SetRoster` call, and the evicted process
//!      loses the mesh.
//!
//! The cross-machine run (separate hosts, real NAT/firewall) is the DGX soak; see the S8.1 doc.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use cluster_core::device::{DeviceLink, DeviceRevocation};
use cluster_daemon::devices::{address_of, eip191_digest};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};

const GROUP: &str = "hup-s8-1-devicelink";

fn key(seed: u8) -> SigningKey {
    let mut b = [seed; 32];
    b[0] = seed | 1;
    SigningKey::from_slice(&b).expect("valid scalar")
}

fn addr(k: &SigningKey) -> String {
    address_of(k.verifying_key())
}

fn sign(k: &SigningKey, msg: &str) -> String {
    let (sig, recid) = k
        .sign_prehash_recoverable(&eip191_digest(msg.as_bytes()))
        .expect("sign");
    let mut out = sig.to_bytes().to_vec();
    out.push(27 + recid.to_byte());
    format!("0x{}", hex::encode(out))
}

fn link_json(
    member: &SigningKey,
    device: &SigningKey,
    wallet: &SigningKey,
    index: u32,
    label: &str,
) -> Value {
    let l = DeviceLink::new(
        &addr(member),
        &addr(device),
        &addr(wallet),
        index,
        label,
        1_790_000_000,
    )
    .expect("valid link");
    let msg = l.signing_message();
    json!({
        "member": l.member, "device": l.device, "wallet": l.wallet,
        "index": l.index, "label": l.label, "issuedAt": l.issued_at,
        "memberSig": sign(member, &msg), "deviceSig": sign(device, &msg), "walletSig": sign(wallet, &msg),
    })
}

fn revocation_json(member: &SigningKey, device: &SigningKey) -> Value {
    let r = DeviceRevocation::new(&addr(member), &addr(device), 1_790_000_100).expect("valid");
    json!({
        "member": r.member, "device": r.device, "revokedAt": r.revoked_at,
        "memberSig": sign(member, &r.signing_message()),
    })
}

fn write_0600(path: &Path, contents: &str) {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .expect("create 0600 file");
    f.write_all(contents.as_bytes()).expect("write");
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

/// One running daemon process. Killed (and its files removed) on drop.
struct Node {
    child: Child,
    dir: PathBuf,
    sock: PathBuf,
    bearer: String,
    port: u16,
    peer_id: String,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_cluster-daemon")
}

fn tag() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() % 1_000_000_000)
        .unwrap_or(0)
}

/// The PeerId the daemon derives from a seed file, read through its own `--print-identity`.
fn print_identity(seed_file: &Path) -> (String, String) {
    let out = Command::new(bin())
        .arg("--print-identity")
        .env("CITRATE_CLUSTER_SEED_FILE", seed_file)
        .output()
        .expect("run --print-identity");
    assert!(out.status.success(), "print-identity failed: {out:?}");
    let v: Value = serde_json::from_slice(&out.stdout).expect("identity json");
    (
        v["address"].as_str().expect("address").to_string(),
        v["peerId"].as_str().expect("peerId").to_string(),
    )
}

fn start(name: &str, device: &SigningKey, bootstrap: Option<String>) -> Node {
    let t = tag();
    let dir = std::env::temp_dir().join(format!("cdl-{name}-{}-{t}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    // UDS paths must stay short (SUN_LEN): keep the socket in /tmp.
    let sock = PathBuf::from(format!("/tmp/cdl-{name}-{t}.sock"));
    let bearer = format!("{:064x}", t ^ 0x5eed);
    let bearer_file = dir.join("bearer");
    write_0600(&bearer_file, &bearer);
    let seed_file = dir.join("seed");
    write_0600(&seed_file, &hex::encode(device.to_bytes()));
    let (derived, peer_id) = print_identity(&seed_file);
    assert_eq!(
        derived,
        addr(device),
        "the libp2p identity IS the device key"
    );
    let port = free_port();
    let mut cmd = Command::new(bin());
    cmd.env("CITRATE_CLUSTER_SOCKET", &sock)
        .env("CITRATE_CLUSTER_BEARER_FILE", &bearer_file)
        .env("CITRATE_CLUSTER_SELF_ADDR", addr(device))
        .env(
            "CITRATE_CLUSTER_LISTEN",
            format!("/ip4/127.0.0.1/tcp/{port}"),
        )
        .env("CITRATE_CLUSTER_SEED_FILE", &seed_file)
        .env("CITRATE_CLUSTER_GROUP", GROUP)
        .env_remove("CITRATE_CLUSTER_BOOTSTRAP")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(b) = bootstrap {
        cmd.env("CITRATE_CLUSTER_BOOTSTRAP", b);
    }
    let child = cmd.spawn().expect("spawn cluster-daemon");
    let node = Node {
        child,
        dir,
        sock,
        bearer,
        port,
        peer_id,
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while UnixStream::connect(&node.sock).is_err() {
        assert!(
            Instant::now() < deadline,
            "{name}: daemon socket never came up"
        );
        sleep(Duration::from_millis(25));
    }
    node
}

impl Node {
    fn multiaddr(&self) -> String {
        format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", self.port, self.peer_id)
    }

    fn call(&self, req: Value) -> Value {
        let s = UnixStream::connect(&self.sock).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut w = s.try_clone().expect("clone");
        let mut r = BufReader::new(s);
        writeln!(w, "{}", json!({ "token": self.bearer })).expect("auth");
        let mut line = String::new();
        r.read_line(&mut line).expect("ready");
        assert!(line.contains("ready"), "handshake: {line}");
        writeln!(w, "{req}").expect("request");
        line.clear();
        r.read_line(&mut line).expect("response");
        serde_json::from_str(line.trim()).expect("response json")
    }

    fn peers(&self) -> Vec<Value> {
        let v = self.call(json!({ "op": "peers", "group": GROUP }));
        v["peers"].as_array().cloned().unwrap_or_default()
    }

    fn online(&self, address: &str) -> bool {
        self.peers()
            .iter()
            .any(|p| p["address"] == address && p["online"] == true)
    }
}

fn wait_until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        sleep(Duration::from_millis(200));
    }
}

#[test]
fn two_devices_of_one_member_mesh_with_distinct_peer_ids_and_revocation_evicts() {
    let member = key(0x81); // the member's comms/roster key
    let wallet = key(0x82); // the member's custody wallet (signs through the ceremony in core)
    let laptop = key(0x83);
    let linux = key(0x84);
    let rogue = key(0x85); // a device key with NO link

    let roster = json!([[addr(&member), "member"]]);
    let devices = json!([
        link_json(&member, &laptop, &wallet, 0, "Studio Mac"),
        link_json(&member, &linux, &wallet, 1, "Linux box"),
    ]);

    // Authorize before connect: the laptop gets the roster first, then the others dial it.
    let a = start("laptop", &laptop, None);
    let r =
        a.call(json!({ "op": "setRoster", "group": GROUP, "roster": roster, "devices": devices }));
    assert_eq!(r["type"], "reconciled", "{r}");
    assert!(r.get("rejected").is_none(), "all links verify: {r}");

    let b = start("linux", &linux, Some(a.multiaddr()));
    let r =
        b.call(json!({ "op": "setRoster", "group": GROUP, "roster": roster, "devices": devices }));
    assert_eq!(r["type"], "reconciled", "{r}");

    let c = start("rogue", &rogue, Some(a.multiaddr()));
    // The rogue knows the roster and even forwards the real links: it still has no link of its own.
    c.call(json!({ "op": "setRoster", "group": GROUP, "roster": roster, "devices": devices }));

    // 1. The two devices of one member mesh, as two distinct PeerIds.
    assert_ne!(a.peer_id, b.peer_id, "one PeerId per device key");
    wait_until("laptop sees the linux box online", 30, || {
        a.online(&addr(&linux))
    });
    wait_until("linux box sees the laptop online", 30, || {
        b.online(&addr(&laptop))
    });

    // 2. Both devices are listed under the member.
    let v = a.call(json!({ "op": "devices", "group": GROUP }));
    let members = v["members"].as_array().expect("members");
    assert_eq!(members.len(), 1, "{v}");
    assert_eq!(members[0]["member"], addr(&member));
    let listed: Vec<(String, String)> = members[0]["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .map(|d| {
            (
                d["device"].as_str().unwrap_or_default().to_string(),
                d["label"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        vec![
            (addr(&laptop), "Studio Mac".to_string()),
            (addr(&linux), "Linux box".to_string())
        ]
    );
    let linux_peer = a
        .peers()
        .into_iter()
        .find(|p| p["address"] == addr(&linux))
        .expect("linux listed in peers");
    assert_eq!(
        linux_peer["member"],
        addr(&member),
        "a device peer names its member"
    );

    // 3. The unlinked device never gets in (the linked one did, so this is not vacuous).
    sleep(Duration::from_secs(2));
    assert!(
        !a.peers().iter().any(|p| p["address"] == addr(&rogue)),
        "a device with no valid link is never authorized"
    );

    // 4. Revoke the linux box: evicted by the same SetRoster, and it loses the mesh.
    let r = a.call(json!({
        "op": "setRoster", "group": GROUP, "roster": roster, "devices": devices,
        "revocations": [revocation_json(&member, &linux)],
    }));
    assert_eq!(r["type"], "reconciled", "{r}");
    assert_eq!(r["evicted"], json!([addr(&linux)]), "{r}");
    assert!(
        !a.peers().iter().any(|p| p["address"] == addr(&linux)),
        "a revoked device is no longer authorized"
    );
    wait_until("the revoked device drops off the laptop's mesh", 15, || {
        let st = b.call(json!({ "op": "status", "group": GROUP }));
        st["online"] == 0
    });

    // Sticky: re-sending the links without the revocation does not readmit it.
    let r =
        a.call(json!({ "op": "setRoster", "group": GROUP, "roster": roster, "devices": devices }));
    let rejected = r["rejected"].as_array().cloned().unwrap_or_default();
    assert!(
        rejected
            .iter()
            .any(|x| x.as_str().unwrap_or_default().contains("revoked")),
        "{r}"
    );
    assert!(!a.peers().iter().any(|p| p["address"] == addr(&linux)));
}
