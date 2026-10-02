//! Shared helpers for the multi-process fleet tests (HUP-S8): real `cluster-daemon` processes on
//! loopback, each with its own device key as its libp2p identity, driven over the real UDS IPC.
//!
//! Test keys come from fixed seed bytes (never a production path). Links are signed here with the
//! same EIP-191 rules the daemon verifies, standing in for core (which collects the wallet signature
//! through its SignatureCeremony).

#![allow(dead_code)] // each test binary uses a different subset

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

/// A valid secp256k1 key from a seed byte (tests only).
pub fn key(seed: u8) -> SigningKey {
    let mut b = [seed; 32];
    b[0] = seed | 1;
    SigningKey::from_slice(&b).expect("valid scalar")
}

/// A valid secp256k1 key from a 16-bit seed, for ladders with more than 255 nodes' worth of keys.
pub fn key16(seed: u16) -> SigningKey {
    let mut b = [0x5au8; 32];
    b[0] = 0x11;
    b[30] = (seed >> 8) as u8;
    b[31] = (seed & 0xff) as u8;
    SigningKey::from_slice(&b).expect("valid scalar")
}

pub fn addr(k: &SigningKey) -> String {
    address_of(k.verifying_key())
}

pub fn sign(k: &SigningKey, msg: &str) -> String {
    let (sig, recid) = k
        .sign_prehash_recoverable(&eip191_digest(msg.as_bytes()))
        .expect("sign");
    let mut out = sig.to_bytes().to_vec();
    out.push(27 + recid.to_byte());
    format!("0x{}", hex::encode(out))
}

/// A three-signature DeviceLink as the daemon's `DeviceLinkWire` JSON.
pub fn link_json(
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

/// A member-signed revocation as the daemon's `RevocationWire` JSON.
pub fn revocation_json(member: &SigningKey, device: &SigningKey) -> Value {
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
pub struct Node {
    child: Child,
    dir: PathBuf,
    sock: PathBuf,
    bearer: String,
    pub port: u16,
    pub peer_id: String,
    pub address: String,
    pub group: String,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = std::fs::remove_file(&self.sock);
    }
}

pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_cluster-daemon")
}

fn tag() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() % 1_000_000_000)
        .unwrap_or(0)
}

/// The `(address, peerId)` the daemon derives from a seed file, through its own `--print-identity`.
pub fn print_identity(seed_file: &Path) -> (String, String) {
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

/// Start one daemon in libp2p mode for `group`, meshing as `device`, dialing `bootstrap` (if any).
pub fn start(name: &str, group: &str, device: &SigningKey, bootstrap: &[String]) -> Node {
    let t = tag();
    let dir = std::env::temp_dir().join(format!("cfl-{name}-{}-{t}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    // UDS paths must stay short (SUN_LEN): keep the socket in /tmp.
    let sock = PathBuf::from(format!("/tmp/cfl-{name}-{t}.sock"));
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
        .env("CITRATE_CLUSTER_GROUP", group)
        .env_remove("CITRATE_CLUSTER_BOOTSTRAP")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !bootstrap.is_empty() {
        cmd.env("CITRATE_CLUSTER_BOOTSTRAP", bootstrap.join(","));
    }
    let child = cmd.spawn().expect("spawn cluster-daemon");
    let node = Node {
        child,
        dir,
        sock,
        bearer,
        port,
        peer_id,
        address: addr(device),
        group: group.to_string(),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
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
    pub fn multiaddr(&self) -> String {
        format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", self.port, self.peer_id)
    }

    pub fn call(&self, req: Value) -> Value {
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

    /// `setRoster` with links and revocations; returns the daemon's answer.
    pub fn set_roster(&self, roster: &Value, devices: &Value, revocations: &Value) -> Value {
        self.call(json!({
            "op": "setRoster", "group": self.group, "roster": roster,
            "devices": devices, "revocations": revocations,
        }))
    }

    pub fn peers(&self) -> Vec<Value> {
        let v = self.call(json!({ "op": "peers", "group": self.group }));
        v["peers"].as_array().cloned().unwrap_or_default()
    }

    pub fn online(&self, address: &str) -> bool {
        self.peers()
            .iter()
            .any(|p| p["address"] == address && p["online"] == true)
    }

    pub fn online_count(&self) -> u64 {
        let st = self.call(json!({ "op": "status", "group": self.group }));
        st["online"].as_u64().unwrap_or(0)
    }

    pub fn shared_files(&self) -> Vec<String> {
        let st = self.call(json!({ "op": "status", "group": self.group }));
        st["sharedFiles"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

pub fn wait_until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        sleep(Duration::from_millis(200));
    }
}
