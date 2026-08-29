//! The daemon's loopback JSON-per-line IPC — the surface a lean client (citrate-core) speaks over a
//! UDS. Requests/responses are line-delimited JSON. `handle_request` maps one request onto the
//! [`ClusterDaemon`] and is pure over it (socket-free), so it is tested directly.
//!
//! The client feeds a group's roster (it comes from the comms daemon — the cluster never re-derives
//! group membership) and the daemon reconciles the mesh; the client then polls status/peers, pushes
//! shared-file announcements, and drains received messages. Group ids + addresses cross as hex; a
//! malformed id is an honest `Error` response, never a panic.

use serde::{Deserialize, Serialize};

use crate::transport::MeshTransport;
use crate::ClusterDaemon;

/// A request from the client. `op` tags the variant.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Request {
    /// Set/update a group's roster `(address, role)`. Recomputes the role-gated allowed set and
    /// reconciles the mesh: newly-unauthorized peers are evicted (disconnected) in one step.
    SetRoster {
        group: String,
        roster: Vec<(String, String)>,
    },
    /// This node joins the group's mesh (begins participating; the transport dials known peers).
    Join { group: String },
    /// This node leaves the group's mesh.
    Leave { group: String },
    /// Mesh status: connected peers / authorized peers.
    Status { group: String },
    /// The group's peers with their live connection state.
    Peers { group: String },
    /// Announce a shared file (co-pin) to the group over gossipsub. `cid` is the content id.
    ShareFile { group: String, cid: String },
    /// Drain received gossipsub messages for the group (e.g. peers' co-pin announcements).
    Poll { group: String },
}

/// One peer in a status/peers response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerView {
    /// Canonical member address (hex, no 0x).
    pub address: String,
    /// Whether the peer is currently connected over the mesh transport.
    pub online: bool,
}

/// One received message (a peer's gossipsub publication).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MeshMessage {
    /// The sender's canonical address (hex).
    pub from: String,
    /// The message body (a co-pin CID today; opaque bytes as hex in general).
    pub data: String,
}

/// A response to the client. `type` tags the variant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Response {
    Ok,
    /// The result of a reconcile: how many peers were evicted (newly unauthorized).
    Reconciled {
        evicted: Vec<String>,
    },
    /// Mesh status: `online` connected of `total` authorized.
    Status {
        online: usize,
        total: usize,
    },
    Peers {
        peers: Vec<PeerView>,
    },
    Messages {
        messages: Vec<MeshMessage>,
    },
    Error {
        message: String,
    },
}

/// Map one request onto the daemon. Never panics — every failure becomes an `Error` response.
pub fn handle_request<T: MeshTransport>(daemon: &mut ClusterDaemon<T>, req: Request) -> Response {
    match req {
        Request::SetRoster { group, roster } => match daemon.set_roster(&group, &roster) {
            Ok(evicted) => Response::Reconciled { evicted },
            Err(e) => Response::Error { message: e },
        },
        Request::Join { group } => match daemon.join(&group) {
            Ok(()) => Response::Ok,
            Err(e) => Response::Error { message: e },
        },
        Request::Leave { group } => {
            daemon.leave(&group);
            Response::Ok
        }
        Request::Status { group } => {
            let (online, total) = daemon.status(&group);
            Response::Status { online, total }
        }
        Request::Peers { group } => Response::Peers {
            peers: daemon.peers(&group),
        },
        Request::ShareFile { group, cid } => match daemon.share_file(&group, &cid) {
            Ok(()) => Response::Ok,
            Err(e) => Response::Error { message: e },
        },
        Request::Poll { group } => Response::Messages {
            messages: daemon.poll(&group),
        },
    }
}
