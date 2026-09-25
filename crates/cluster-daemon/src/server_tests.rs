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
    // The socket FILE appears at bind(), a moment before listen(); `spawn_server` only waits for the
    // file, so on a loaded machine the first connect can land in that gap (ECONNREFUSED). Retry that
    // one error briefly — every other error, and a refusal that persists, still fails the test.
    let mut tries = 0;
    loop {
        match Stream::connect(endpoint_name(s)?) {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused && tries < 100 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            other => return other,
        }
    }
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

/// Run `serve` on `sock` in a thread and report whether it RETURNED an error within `wait` (a healthy
/// `serve` never returns — it blocks accepting).
#[cfg(unix)]
fn serve_error_within(sock: &Path, wait: std::time::Duration) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let sock_owned = sock.to_path_buf();
    std::thread::spawn(move || {
        let daemon = ClusterDaemon::new(
            "0x1111111111111111111111111111111111111111",
            InProcessTransport::new,
        );
        let r = serve(daemon, &sock_owned, &"b".repeat(64));
        let _ = tx.send(r.err().map(|e| e.to_string()));
    });
    rx.recv_timeout(wait).ok().flatten()
}

// PBA-L6b-038: the control socket must not be bound in a directory another local user can write to
// (they could swap the socket path for their own listener or pre-create it). A group/world-writable
// parent without the sticky bit is refused, fail closed.
#[cfg(unix)]
#[test]
fn pba_l6b_038_a_world_writable_socket_dir_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = PathBuf::from(format!("/tmp/ctzc-ww-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = serve_error_within(&dir.join("c.sock"), std::time::Duration::from_secs(2));
    assert!(
        !dir.join("c.sock").exists(),
        "PBA-L6b-038: nothing may be bound in a world-writable dir"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let err = err.expect("PBA-L6b-038: serve must refuse a world-writable socket dir");
    assert!(err.contains("writable"), "explicit reason: {err}");
}

// No-regression: a private (0700) dir and a sticky world-writable dir (/tmp) are both accepted.
#[cfg(unix)]
#[test]
fn pba_l6b_038_private_and_sticky_socket_dirs_are_accepted() {
    use std::os::unix::fs::PermissionsExt;
    let dir = PathBuf::from(format!("/tmp/ctzc-pv-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        serve_error_within(&dir.join("c.sock"), std::time::Duration::from_millis(500)),
        None,
        "a private socket dir is served"
    );
    assert!(dir.join("c.sock").exists());
    let sticky = short_sock("sticky");
    let _ = std::fs::remove_file(&sticky);
    assert_eq!(
        serve_error_within(&sticky, std::time::Duration::from_millis(500)),
        None,
        "a root-owned sticky dir (/tmp) is served"
    );
}

// PBA-L6b-038: if the peer's credentials cannot be read, the connection is refused (fail closed),
// not waved through to the bearer check.
#[cfg(unix)]
#[test]
fn pba_l6b_038_peer_uid_check_fails_closed_on_error() {
    let me = unsafe { libc::geteuid() };
    assert!(
        peer_uid_decision(0, me, me),
        "same uid, credentials read → allowed"
    );
    assert!(
        !peer_uid_decision(0, me.wrapping_add(1), me),
        "different uid → refused"
    );
    assert!(
        !peer_uid_decision(-1, me, me),
        "PBA-L6b-038: credentials unreadable → refused (fail closed)"
    );
}

// PBA-L6b-038: a socket dir owned by another (non-root) user is refused; ours and root's are not.
#[cfg(unix)]
#[test]
fn pba_l6b_038_a_socket_dir_owned_by_another_user_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = PathBuf::from(format!("/tmp/ctzc-own-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let me = unsafe { libc::geteuid() };
    let sock = dir.join("c.sock");
    assert!(
        check_socket_dir_for(&sock, me).is_ok(),
        "our own private dir is fine"
    );
    let other = if me == 0 { 4242 } else { me + 1 };
    let err =
        check_socket_dir_for(&sock, other).expect_err("a dir owned by someone else is refused");
    assert!(err.to_string().contains("owned by uid"), "{err}");
    // Root-owned (e.g. `/`, not group/world-writable) is accepted for any caller.
    assert!(check_socket_dir_for(Path::new("/c.sock"), other).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}
