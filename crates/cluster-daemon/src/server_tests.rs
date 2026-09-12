//! End-to-end UDS server test: a real socket, the bearer handshake, and a request round-trip; plus a
//! wrong-bearer rejection. A short socket path is used (UDS paths must be < SUN_LEN ~104).

use super::*;
use crate::transport::InProcessTransport;
use interprocess::local_socket::Stream;
use interprocess::TryClone;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const A: &str = "00000000000000000000000000000000000000aa";

/// Connect to the server through the SAME endpoint rule the daemon binds with (issue #1) — on Unix
/// this is the Unix-domain socket at `sock`; the citrate-core client applies the identical rule.
fn connect(sock: &Path) -> std::io::Result<Stream> {
    let s = sock
        .to_str()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "sock path utf-8"))?;
    Stream::connect(endpoint_name(s)?)
}

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

    let stream = connect(&sock).expect("connect");
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

// CL-B-003: a silent unauthenticated connection must NOT wedge the control surface — a second client
// must still complete the handshake promptly (the old serial accept loop + un-timed pre-auth read
// blocked head-of-line for the full timeout).
#[test]
fn a_silent_connection_does_not_wedge_the_control_surface() {
    let sock = short_sock("dos");
    let _ = std::fs::remove_file(&sock);
    let bearer = "b".repeat(64);
    spawn_server(&sock, &bearer);

    // Attacker opens a connection and sends NOTHING (held open for the whole test).
    let _silent = connect(&sock).expect("attacker connects");

    // A legitimate client must still complete the handshake well under a second. A bounded read
    // timeout makes the buggy (serial, head-of-line-blocking) case fail cleanly instead of hanging.
    let start = std::time::Instant::now();
    let stream = connect(&sock).expect("victim connects");
    stream
        .set_recv_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);
    writeln!(w, "{{\"token\":\"{bearer}\"}}").unwrap();
    let mut line = String::new();
    let _ = r.read_line(&mut line);
    assert!(
        line.contains("ready"),
        "a second client must handshake despite a silent connection (head-of-line): got {line:?}"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "a silent connection must not delay a second client (head-of-line blocking) — took {:?}",
        start.elapsed()
    );
}

// CL-B-003: an over-long line (no newline) must be capped and the connection dropped, never grown
// into an unbounded String.
#[test]
fn an_over_long_handshake_line_is_rejected_not_grown_unbounded() {
    let sock = short_sock("big");
    let _ = std::fs::remove_file(&sock);
    let bearer = "b".repeat(64);
    spawn_server(&sock, &bearer);

    let stream = connect(&sock).expect("connect");
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);
    // Just over MAX_LINE (64 KiB) with no newline → the server caps the read and drops the connection.
    let flood = "x".repeat(64 * 1024 + 16);
    let _ = w.write_all(flood.as_bytes());
    let _ = w.flush();
    let mut line = String::new();
    let _ = r.read_line(&mut line); // EOF after the server drops the connection
    assert!(
        !line.contains("ready"),
        "an over-long handshake must never authenticate: {line}"
    );
}

// CL-B-006: the control socket is created 0600 (no world-connectable window before harden).
#[cfg(unix)]
#[test]
fn the_control_socket_is_created_0600() {
    use std::os::unix::fs::PermissionsExt;
    let sock = short_sock("mode");
    let _ = std::fs::remove_file(&sock);
    spawn_server(&sock, &"b".repeat(64));
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "control socket must be 0600");
}

#[test]
fn a_wrong_bearer_is_rejected_with_no_ready() {
    let sock = short_sock("bad");
    let _ = std::fs::remove_file(&sock);
    spawn_server(&sock, &"b".repeat(64));

    let stream = connect(&sock).expect("connect");
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
