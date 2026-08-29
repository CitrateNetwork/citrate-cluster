//! End-to-end UDS server test: a real socket, the bearer handshake, and a request round-trip; plus a
//! wrong-bearer rejection. A short socket path is used (UDS paths must be < SUN_LEN ~104).

use super::*;
use crate::transport::InProcessTransport;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

const A: &str = "00000000000000000000000000000000000000aa";

fn short_sock(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() % 100_000_000)
        .unwrap_or(0);
    PathBuf::from(format!("/tmp/ctzc-{tag}-{n}.sock"))
}

fn spawn_server(sock: &Path, bearer: &str) {
    let sock_owned = sock.to_path_buf();
    let bearer_owned = bearer.to_string();
    std::thread::spawn(move || {
        let daemon = ClusterDaemon::new(
            "0x1111111111111111111111111111111111111111",
            InProcessTransport::new,
        );
        let _ = serve(daemon, &sock_owned, &bearer_owned);
    });
    for _ in 0..100 {
        if sock.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn server_authenticates_and_serves_the_contract() {
    let sock = short_sock("srv");
    let _ = std::fs::remove_file(&sock);
    let bearer = "b".repeat(64);
    spawn_server(&sock, &bearer);

    let stream = UnixStream::connect(&sock).expect("connect");
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);

    writeln!(w, "{{\"token\":\"{bearer}\"}}").unwrap();
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert!(line.contains("ready"), "handshake: {line}");

    // SetRoster (roster is [[address, role]]).
    writeln!(
        w,
        "{{\"op\":\"setRoster\",\"group\":\"g1\",\"roster\":[[\"{A}\",\"member\"]]}}"
    )
    .unwrap();
    line.clear();
    r.read_line(&mut line).unwrap();
    assert!(line.contains("reconciled"), "setRoster: {line}");

    // Status → total 1 authorized.
    writeln!(w, "{{\"op\":\"status\",\"group\":\"g1\"}}").unwrap();
    line.clear();
    r.read_line(&mut line).unwrap();
    assert!(line.contains("\"total\":1"), "status: {line}");
}

#[test]
fn a_wrong_bearer_is_rejected_with_no_ready() {
    let sock = short_sock("bad");
    let _ = std::fs::remove_file(&sock);
    spawn_server(&sock, &"b".repeat(64));

    let stream = UnixStream::connect(&sock).expect("connect");
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);
    writeln!(w, "{{\"token\":\"{}\"}}", "w".repeat(64)).unwrap();
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    assert!(
        line.contains("unauthorized") && !line.contains("ready"),
        "got: {line}"
    );
}
