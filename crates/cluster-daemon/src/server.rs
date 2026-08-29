//! The loopback UDS server: a bearer-authed, line-delimited JSON surface over [`crate::ipc`].
//!
//! One client (citrate-core) at a time. The handshake mirrors the comms member-daemon: the client
//! sends `{"token":"..."}`, the server constant-time-compares it to the bearer (minted by the client,
//! handed via a 0600 file — never argv/env), replies `{"type":"ready"}`, then it is a request→response
//! loop of one JSON object per line. The socket itself is created 0600.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::ipc::{handle_request, Request, Response};
use crate::transport::MeshTransport;
use crate::ClusterDaemon;

#[derive(Deserialize)]
struct Auth {
    token: String,
}

/// Serve the daemon on `socket_path`, gating every connection on `bearer`. Blocks forever.
pub fn serve<T: MeshTransport>(
    mut daemon: ClusterDaemon<T>,
    socket_path: &Path,
    bearer: &str,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    harden(socket_path)?;
    eprintln!(
        "cluster-daemon: node {} serving on {}",
        daemon.self_address(),
        socket_path.display()
    );
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                // One client at a time (citrate-core). A per-connection error is logged, not fatal.
                if let Err(e) = handle_conn(&mut daemon, stream, bearer) {
                    eprintln!("cluster-daemon: connection ended: {e}");
                }
            }
            Err(e) => eprintln!("cluster-daemon: accept error: {e}"),
        }
    }
    Ok(())
}

fn handle_conn<T: MeshTransport>(
    daemon: &mut ClusterDaemon<T>,
    stream: UnixStream,
    bearer: &str,
) -> std::io::Result<()> {
    let mut w = stream.try_clone()?;
    let mut r = BufReader::new(stream);

    // Auth handshake.
    let mut line = String::new();
    r.read_line(&mut line)?;
    if !authorized(&line, bearer) {
        writeln!(w, "{}", err_json("unauthorized"))?;
        return Ok(());
    }
    writeln!(w, "{{\"type\":\"ready\"}}")?;

    // Request → response loop, one JSON object per line.
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            break; // client closed
        }
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => handle_request(daemon, req),
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
