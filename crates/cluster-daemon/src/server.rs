//! The loopback UDS server: a bearer-authed, line-delimited JSON surface over [`crate::ipc`].
//!
//! Clients (citrate-core) connect, send `{"token":"..."}`, the server constant-time-compares it to
//! the bearer (minted by the client, handed via a 0600 file — never argv/env), replies
//! `{"type":"ready"}`, then it is a request→response loop of one JSON object per line. The socket
//! itself is created 0600 (from bind time — CL-B-006). Each connection is served on its own thread so
//! one silent or slow client cannot wedge the whole control surface (CL-B-003), and every read is
//! length-capped and the pre-auth read is time-bounded.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::ipc::{handle_request, Request, Response};
use crate::transport::MeshTransport;
use crate::ClusterDaemon;

/// Maximum bytes accepted for one line (handshake or request) before the connection is dropped. Ample
/// for `{"token":...}` and the JSON request contract; caps the unbounded `read_line` growth (CL-B-003).
const MAX_LINE: u64 = 64 * 1024;

/// Read timeout applied to the PRE-AUTH handshake read (CL-B-003): a connection that opens and sends
/// nothing is reaped rather than holding a file descriptor. Cleared once the client authenticates so a
/// legitimate, idle client is never reaped between requests.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
struct Auth {
    token: String,
}

/// Serve the daemon on `socket_path`, gating every connection on `bearer`. Blocks forever.
pub fn serve<T: MeshTransport + Send + 'static>(
    daemon: ClusterDaemon<T>,
    socket_path: &Path,
    bearer: &str,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(socket_path);
    let listener = bind_hardened(socket_path)?;
    eprintln!(
        "cluster-daemon: node {} serving on {}",
        daemon.self_address(),
        socket_path.display()
    );
    let daemon = Arc::new(Mutex::new(daemon));
    let bearer: Arc<str> = Arc::from(bearer);
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                // CL-B-003: handle each connection on its own thread so one silent/slow client cannot
                // hold the serial accept loop and wedge the whole control surface (head-of-line
                // blocking). The daemon is shared behind a mutex, locked only around a request.
                let daemon = Arc::clone(&daemon);
                let bearer = Arc::clone(&bearer);
                std::thread::spawn(move || {
                    if let Err(e) = handle_conn(&daemon, stream, &bearer) {
                        eprintln!("cluster-daemon: connection ended: {e}");
                    }
                });
            }
            Err(e) => eprintln!("cluster-daemon: accept error: {e}"),
        }
    }
    Ok(())
}

fn handle_conn<T: MeshTransport>(
    daemon: &Mutex<ClusterDaemon<T>>,
    stream: UnixStream,
    bearer: &str,
) -> std::io::Result<()> {
    // CL-B-006: defence-in-depth — serve only a peer running as our own uid. The bearer remains the
    // authorization gate; this refuses a *different* local user before the token is even read.
    if !peer_uid_matches(&stream) {
        return Ok(());
    }
    // CL-B-003: bound the pre-auth read so a silent connection is reaped, not left holding an fd.
    let _ = stream.set_read_timeout(Some(AUTH_TIMEOUT));
    let mut w = stream.try_clone()?;
    let mut r = BufReader::new(stream);

    // Auth handshake (length-capped, time-bounded — CL-B-003).
    let mut line = String::new();
    match read_capped_line(&mut r, &mut line, MAX_LINE) {
        Ok(0) => return Ok(()),  // client closed with nothing
        Ok(_) => {}
        Err(_) => return Ok(()), // over-long handshake line or read timeout → drop the connection
    }
    if !authorized(&line, bearer) {
        writeln!(w, "{}", err_json("unauthorized"))?;
        return Ok(());
    }
    writeln!(w, "{{\"type\":\"ready\"}}")?;
    // Authenticated: relax the read timeout so a legitimate, idle client is not reaped between requests.
    let _ = r.get_ref().set_read_timeout(None);

    // Request → response loop, one JSON object per line (each line length-capped — CL-B-003).
    loop {
        match read_capped_line(&mut r, &mut line, MAX_LINE) {
            Ok(0) => break, // client closed
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                writeln!(w, "{}", err_json("request too large"))?;
                break;
            }
            Err(e) => return Err(e),
        }
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => {
                // Lock only around the request — never across a read — so a slow client never holds
                // the daemon lock and starve others.
                let mut d = daemon.lock().unwrap_or_else(|p| p.into_inner());
                handle_request(&mut d, req)
            }
            Err(e) => Response::Error {
                message: format!("bad request: {e}"),
            },
        };
        let out =
            serde_json::to_string(&resp).unwrap_or_else(|_| err_json("response encode failed"));
        writeln!(w, "{out}")?;
    }
    Ok(())
}

/// Read one `\n`-terminated line but never more than `max` bytes (CL-B-003). Over-length without a
/// newline is an `InvalidData` error (the caller drops or rejects), not unbounded `String` growth.
fn read_capped_line<R: BufRead>(r: &mut R, buf: &mut String, max: u64) -> std::io::Result<usize> {
    buf.clear();
    let n = r.by_ref().take(max).read_line(buf)?;
    if n as u64 == max && !buf.ends_with('\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "line exceeds maximum length",
        ));
    }
    Ok(n)
}

/// Constant-time bearer check (length compared first — length is not secret).
fn authorized(auth_line: &str, bearer: &str) -> bool {
    let Ok(auth) = serde_json::from_str::<Auth>(auth_line.trim()) else {
        return false;
    };
    auth.token.len() == bearer.len() && bool::from(auth.token.as_bytes().ct_eq(bearer.as_bytes()))
}

fn err_json(msg: &str) -> String {
    serde_json::to_string(&Response::Error {
        message: msg.to_string(),
    })
    .unwrap_or_else(|_| "{\"type\":\"error\",\"message\":\"error\"}".to_string())
}

/// Bind the control socket with the socket file created `0600` from the start (CL-B-006): a
/// restrictive `umask` closes the world-connectable window that would otherwise exist between `bind`
/// and the explicit `chmod`. [`harden`] still enforces `0600` afterwards (belt and suspenders).
#[cfg(unix)]
fn bind_hardened(socket_path: &Path) -> std::io::Result<UnixListener> {
    let old = unsafe { libc::umask(0o177) };
    let res = UnixListener::bind(socket_path);
    unsafe { libc::umask(old) };
    let listener = res?;
    harden(socket_path)?;
    Ok(listener)
}

/// Whether the connecting peer runs as the daemon's own effective uid (CL-B-006). If the peer uid
/// cannot be determined, defer to the bearer (do not break the legitimate path) — this is defence in
/// depth, not a replacement for the token. Linux uses `SO_PEERCRED`; other unixes use `getpeereid`.
#[cfg(target_os = "linux")]
fn peer_uid_matches(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return true;
    }
    cred.uid == unsafe { libc::geteuid() }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peer_uid_matches(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return true;
    }
    uid == unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn harden(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod server_tests;
