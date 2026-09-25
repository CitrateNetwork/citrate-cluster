//! The loopback UDS server: a bearer-authed, line-delimited JSON surface over [`crate::ipc`].
//!
//! Clients (citrate-core) connect, send `{"token":"..."}`, the server constant-time-compares it to
//! the bearer (minted by the client, handed via a 0600 file — never argv/env), replies
//! `{"type":"ready"}`, then it is a request→response loop of one JSON object per line. The socket
//! itself is created 0600 (from bind time — CL-B-006). Each connection is served on its own thread so
//! one silent or slow client cannot wedge the whole control surface (CL-B-003), and every read is
//! length-capped and the pre-auth read is time-bounded.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(unix)]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{prelude::*, ListenerOptions, Name};
use interprocess::local_socket::{Listener, Stream};
use interprocess::TryClone;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::ipc::{handle_request, Request, Response};
use crate::transport::MeshTransport;
use crate::ClusterDaemon;

/// Map a socket path to the platform's local-socket [`Name`] (issue #1). BOTH ends — this daemon and
/// the citrate-core client — apply this EXACT rule, so the endpoints agree byte-for-byte:
///
/// * **Unix:** the filesystem path is used verbatim (a Unix-domain socket at that path).
/// * **Windows:** named pipes live in a flat namespace, not the filesystem, so the *basename* of the
///   path is slugged — every char outside `[A-Za-z0-9._-]` becomes `-` — and used as a namespaced name.
///
/// The rule is fixed; only the interprocess 2.x call spelling is adapted per platform.
pub fn endpoint_name(p: &str) -> io::Result<Name<'static>> {
    #[cfg(unix)]
    {
        p.to_string().to_fs_name::<GenericFilePath>()
    }
    #[cfg(windows)]
    {
        let base = std::path::Path::new(p)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("citrate.sock");
        let slug: String = base
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        slug.to_ns_name::<GenericNamespaced>()
    }
}

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
    // Unix domain sockets leave a stale socket FILE behind that blocks re-`bind` (AddrInUse); remove
    // it first. Windows named pipes have no filesystem entry, so this is Unix-only.
    #[cfg(unix)]
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
    stream: Stream,
    bearer: &str,
) -> std::io::Result<()> {
    // CL-B-006: defence-in-depth — serve only a peer running as our own uid. The bearer remains the
    // authorization gate; this refuses a *different* local user before the token is even read.
    if !peer_uid_matches(&stream) {
        return Ok(());
    }
    // CL-B-003: bound the pre-auth read so a silent connection is reaped, not left holding an fd.
    // `set_recv_timeout` maps to `SO_RCVTIMEO` (std `set_read_timeout`) on Unix — behaviour unchanged.
    let _ = stream.set_recv_timeout(Some(AUTH_TIMEOUT));
    let mut w = stream.try_clone()?;
    let mut r = BufReader::new(stream);

    // Auth handshake (length-capped, time-bounded — CL-B-003).
    let mut line = String::new();
    match read_capped_line(&mut r, &mut line, MAX_LINE) {
        Ok(0) => return Ok(()), // client closed with nothing
        Ok(_) => {}
        Err(_) => return Ok(()), // over-long handshake line or read timeout → drop the connection
    }
    if !authorized(&line, bearer) {
        writeln!(w, "{}", err_json("unauthorized"))?;
        return Ok(());
    }
    writeln!(w, "{{\"type\":\"ready\"}}")?;
    // Authenticated: relax the read timeout so a legitimate, idle client is not reaped between requests.
    let _ = r.get_ref().set_recv_timeout(None);

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
fn bind_hardened(socket_path: &Path) -> std::io::Result<Listener> {
    let sock_str = socket_path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path is not valid UTF-8",
        )
    })?;
    check_socket_dir(socket_path)?;
    let name = endpoint_name(sock_str)?;
    let old = unsafe { libc::umask(0o177) };
    // interprocess binds the same underlying Unix-domain socket as `UnixListener::bind`, honouring the
    // umask (no mode is set on the builder, so it does not fchmod). `harden` still enforces 0600.
    let res = ListenerOptions::new().name(name).create_sync();
    unsafe { libc::umask(old) };
    let listener = res?;
    harden(socket_path)?;
    Ok(listener)
}

/// PBA-L6b-038: refuse to bind the control socket in a directory another local user could write to
/// — they could unlink/replace the socket path with their own listener (harvesting the bearer from
/// the next client) or pre-create it. The parent must be owned by us (or root) and must not be
/// group/world-writable unless it carries the sticky bit (as `/tmp` does — there only the owner may
/// unlink or rename our socket). Fails closed with an explicit reason.
#[cfg(unix)]
fn check_socket_dir(socket_path: &Path) -> std::io::Result<()> {
    check_socket_dir_for(socket_path, unsafe { libc::geteuid() })
}

/// [`check_socket_dir`] against an explicit effective uid (unit-testable ownership branch).
#[cfg(unix)]
fn check_socket_dir_for(socket_path: &Path, euid: libc::uid_t) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let parent = match socket_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let md = std::fs::metadata(parent)?;
    let mode = md.mode();
    if md.uid() != euid && md.uid() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket dir {} is owned by uid {} (not us or root) — fail closed",
                parent.display(),
                md.uid()
            ),
        ));
    }
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "socket dir {} is group/world-writable without the sticky bit (mode {:04o}) — fail closed",
                parent.display(),
                mode & 0o7777
            ),
        ));
    }
    Ok(())
}

/// Bind the control socket on Windows: a named pipe endpoint derived from the socket path's basename
/// (see [`endpoint_name`]). Named pipes carry no filesystem entry, so there is no `umask`/`chmod`
/// hardening step — the pipe's default ACL grants the creating user; the bearer remains the gate.
#[cfg(windows)]
fn bind_hardened(socket_path: &Path) -> std::io::Result<Listener> {
    let sock_str = socket_path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path is not valid UTF-8",
        )
    })?;
    let name = endpoint_name(sock_str)?;
    ListenerOptions::new().name(name).create_sync()
}

/// The raw fd underlying an interprocess local-socket [`Stream`] on Unix. The enum dispatcher
/// deliberately omits `AsRawFd`, so the concrete Unix-domain-socket variant is matched out; on Unix
/// that is the only variant. The borrowed fd is valid for the duration of the borrow of `stream`.
#[cfg(unix)]
fn raw_fd(stream: &Stream) -> std::os::unix::io::RawFd {
    use std::os::unix::io::{AsFd, AsRawFd};
    match stream {
        Stream::UdSocket(s) => s.as_fd().as_raw_fd(),
    }
}

/// Whether the connecting peer runs as the daemon's own effective uid (CL-B-006). If the peer uid
/// cannot be determined the connection is refused (PBA-L6b-038 — fail closed). This is defence in
/// depth; the bearer remains the authorization gate. Linux uses `SO_PEERCRED`; other unixes use
/// `getpeereid`.
#[cfg(target_os = "linux")]
fn peer_uid_matches(stream: &Stream) -> bool {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            raw_fd(stream),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    peer_uid_decision(rc, cred.uid, unsafe { libc::geteuid() })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peer_uid_matches(stream: &Stream) -> bool {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(raw_fd(stream), &mut uid, &mut gid) };
    peer_uid_decision(rc, uid, unsafe { libc::geteuid() })
}

/// The peer-uid gate as a pure decision over the credential syscall's return code (`rc`), the peer's
/// uid and our effective uid.
#[cfg(unix)]
///
/// PBA-L6b-038: if the credentials cannot be read the connection is REFUSED (fail closed). A peer
/// check that waves an unidentifiable caller through is not a check.
fn peer_uid_decision(rc: libc::c_int, peer_uid: libc::uid_t, euid: libc::uid_t) -> bool {
    rc == 0 && peer_uid == euid
}

/// Windows has no `getpeereid`/`SO_PEERCRED` equivalent for named pipes here — the named pipe's ACL
/// already restricts it to the creating user, and the bearer token remains the authorization gate.
#[cfg(windows)]
fn peer_uid_matches(_stream: &Stream) -> bool {
    true
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
