//! The daemon's loopback JSON-per-line IPC — the surface a lean client (citrate-core) speaks over a
//! UDS. Requests/responses are line-delimited JSON. `handle_request` maps one request onto the
//! [`ClusterDaemon`] and is pure over it (socket-free), so it is tested directly.
//!
//! The client feeds a group's roster (it comes from the comms daemon — the cluster never re-derives
//! group membership) and the daemon reconciles the mesh; the client then polls status/peers, pushes
//! shared-file announcements, and drains received messages. Group ids + addresses cross as hex; a
//! malformed id is an honest `Error` response, never a panic.

use serde::{Deserialize, Serialize};

use crate::devices::{DeviceLinkWire, MemberDevicesWire, RevocationWire};
use crate::transport::MeshTransport;
use crate::ClusterDaemon;

/// A request from the client. `op` tags the variant.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Request {
    /// Set/update a group's roster `(address, role)`. Recomputes the role-gated allowed set and
    /// reconciles the mesh: newly-unauthorized peers are evicted (disconnected) in one step.
    ///
    /// HUP-S8.1: `devices` carries the group's signed DeviceLinks and `revocations` the members'
    /// signed revocations (both optional on the wire, so an older client's `SetRoster` is unchanged).
    /// The update is atomic: links are verified, revocations recorded (sticky), the member roster is
    /// widened with each allowed member's linked devices, and the mesh is reconciled in ONE step, so
    /// a revoked device is evicted by the same request that carries its revocation.
    SetRoster {
        group: String,
        roster: Vec<(String, String)>,
        #[serde(default)]
        devices: Vec<DeviceLinkWire>,
        #[serde(default)]
        revocations: Vec<RevocationWire>,
    },
    /// HUP-S8.1: the roster with each member's linked devices listed under it.
    Devices { group: String },
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
    /// PBA-L6b-020: one page of the group's co-pinned shared set (sorted). `limit` defaults to and is
    /// clamped at the daemon's page maximum.
    SharedFiles {
        group: String,
        #[serde(default)]
        offset: usize,
        #[serde(default)]
        limit: Option<usize>,
    },
}

/// One peer in a status/peers response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PeerView {
    /// Canonical member address (hex, no 0x).
    pub address: String,
    /// Whether the peer is currently connected over the mesh transport.
    pub online: bool,
    /// HUP-S8.1: when this peer is a linked device, the member it acts for. Absent for a member's
    /// own identity (and on the wire from an older daemon).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
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
        /// HUP-S8.1: links/revocations that were not accepted, one short reason each (never a
        /// signature). Omitted when empty.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        rejected: Vec<String>,
    },
    /// HUP-S8.1: members with their linked devices (answer to [`Request::Devices`]).
    Devices {
        members: Vec<MemberDevicesWire>,
    },
    /// Mesh status: `online` connected of `total` authorized, plus the group's co-pinned shared
    /// file set (`sharedFiles`, sorted+deduped CIDs — this node's announcements + peers' received
    /// co-pins). Additive over `online`/`total`.
    Status {
        online: usize,
        total: usize,
        #[serde(rename = "sharedFiles")]
        shared_files: Vec<String>,
    },
    Peers {
        peers: Vec<PeerView>,
    },
    Messages {
        messages: Vec<MeshMessage>,
    },
    /// PBA-L6b-020: a page of the co-pinned shared set and the set's total size.
    SharedFiles {
        files: Vec<String>,
        offset: usize,
        total: usize,
    },
    Error {
        message: String,
    },
}

/// Map one request onto the daemon. Never panics — every failure becomes an `Error` response.
pub fn handle_request<T: MeshTransport>(daemon: &mut ClusterDaemon<T>, req: Request) -> Response {
    match req {
        Request::SetRoster {
            group,
            roster,
            devices,
            revocations,
        } => match daemon.set_roster_with_devices(&group, &roster, &devices, &revocations) {
            Ok((evicted, rejected)) => Response::Reconciled { evicted, rejected },
            Err(e) => Response::Error { message: e },
        },
        Request::Devices { group } => Response::Devices {
            members: daemon.devices(&group),
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
            let (online, total, shared_files) = daemon.status(&group);
            Response::Status {
                online,
                total,
                shared_files,
            }
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
        Request::SharedFiles {
            group,
            offset,
            limit,
        } => {
            let (files, total) = daemon.shared_files_page(
                &group,
                offset,
                limit.unwrap_or(crate::MAX_SHARED_FILES_PAGE),
            );
            Response::SharedFiles {
                files,
                offset,
                total,
            }
        }
    }
}
