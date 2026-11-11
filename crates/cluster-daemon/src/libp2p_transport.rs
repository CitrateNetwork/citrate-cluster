//! The **libp2p** [`MeshTransport`] (CL-S1): a real cross-machine, Noise-encrypted gossipsub mesh
//! among a group's members. One gossipsub topic per group (`topic = group_id`, D-24), peer identity
//! bound to the device's **secp256k1** key (HUP-S8.1: a per-device key linked to its member by a
//! signed DeviceLink, never the wallet key; ADR-002 supersedes CL-2), and admission
//! enforced **on the wire**: a connecting peer whose address is not in the group's authorized set is
//! disconnected, and its messages are never accepted.
//!
//! ## Shape (reuses the compute-pool pattern, CL-4)
//!
//! Adapted from `citrate-compute-pool/training-worker/src/libp2p_transport.rs`: a libp2p swarm
//! (TCP + Noise + yamux + gossipsub + identify) driven by a background tokio task, with the sync
//! [`MeshTransport`] surface bridging to it over channels + shared state — the same sync-over-async
//! bridge the comms member-daemon's `WsRelay` uses (a dedicated [`tokio::runtime::Runtime`]). The
//! `cluster-daemon` is sync (it must link into lean clients' expectations), so the transport hides
//! all async behind the frozen seam.
//!
//! ## The admission seam (no policy duplication — `cluster-core` is the source of truth)
//!
//! The transport does NOT re-derive group membership. `cluster-core` (via the daemon) tells it who is
//! authorized through the [`ClusterTransport`] surface it already drives:
//!
//! * [`dial`](ClusterTransport::dial)`(address)` → "this address is admitted; it may mesh with us."
//! * [`disconnect`](ClusterTransport::disconnect)`(address)` → "this address is evicted; drop it."
//!
//! On an inbound connection the swarm task resolves the peer's **address from its authenticated
//! secp256k1 public key** (carried in the Noise-authenticated `identify` exchange; we double-check the
//! key hashes to the connection's `PeerId`), and:
//!
//! * if the address is in the authorized set → the peer is meshed and counted `connected`;
//! * else → the connection is dropped (`disconnect_peer_id`) and, as a backstop for the brief
//!   connect→identify window, any gossipsub message whose authenticated source is not authorized is
//!   discarded on receipt.
//!
//! This keeps `connected ⊆ admitted ⊆ allowed` on the wire (the core invariant, ADR-001).
//!
//! ## Honest scope / gaps (S1)
//!
//! * **Discovery**: [`dial`](ClusterTransport::dial) carries only an *address*, not a network
//!   location, so it authorizes but cannot itself open a socket. Network locations come from three
//!   places, none of which grants admission (every connection is still decided at `identify`):
//!   the bootstrap list ([`dial_multiaddr`](Libp2pTransport::dial_multiaddr) /
//!   `CITRATE_CLUSTER_BOOTSTRAP`); a group seed shared as a link or QR code
//!   (`cluster_core::seed`, [`MeshTransport::add_peers`]); and, HUP-S8.4, opt-in mDNS on the local
//!   network ([`Libp2pConfig::mdns`], off by default). mDNS only dials a discovered peer whose
//!   PeerId resolves to an address the group authorizes, and re-dials it while it stays discovered.
//!   Kademlia remains a follow-on.
//! * **NAT traversal** (V60 S0-NAT-SPIKE): with relays configured ([`Libp2pConfig::relays`],
//!   `CITRATE_CLUSTER_RELAYS`), the swarm holds a circuit relay v2 reservation on each relay, offers
//!   the relayed address in its seed, and runs DCUtR so two members that first meet through a relay
//!   try to hole-punch a direct connection. A relayed connection is admitted at `identify` exactly
//!   like a direct one; the relay itself is identified but never admitted or counted. The relay hop
//!   uses [`RELAY_PROLOGUE`] (a relay serves many groups), every other connection the group prologue.
//! * **One swarm per group, one daemon for every group** (HUP-S8.4): each group gets its own swarm
//!   (its own topic, Noise prologue and listen port) under the same device identity, built by a
//!   per-group factory ([`Libp2pFactory`]) on one shared tokio runtime. Admission state never
//!   crosses groups: a peer admitted in one group's swarm is a stranger to another's, and the Noise
//!   prologue (the group id) refuses a handshake between swarms of different groups.
//! * **Relayed sources**: a message's authenticated source must be a peer we have `identify`d (in a
//!   fully-connected small mesh, every publisher is a direct peer). Multi-hop relay of not-yet-
//!   identified sources is dropped; larger-mesh source resolution is future work (soak ladder, CL-S3).
//! * **Authorize-before-connect**: admission is decided once, at the `identify` handshake. A peer that
//!   connects before its address is authorized (via `dial`) is dropped. HUP-S8.4: every node re-dials
//!   its bootstrap peers that are not connected every [`BOOTSTRAP_REDIAL`] (at most
//!   [`MAX_REDIAL_PER_TICK`] per tick, [`MAX_BOOTSTRAP`] kept), so a peer authorized later (a roster or
//!   DeviceLink update) gets in on the next re-dial from either side that knows the other's address,
//!   without a restart. Each re-dial is still admitted only at `identify`, so the invariant is
//!   unchanged; a refused peer costs one Noise handshake per interval.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use futures::{AsyncRead, AsyncWrite};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{Boxed, ListenerId};
use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo};
use libp2p::core::{ConnectedPoint, Transport};
#[cfg(feature = "mdns")]
use libp2p::mdns;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{connection_limits, dcutr, gossipsub, identify, identity, noise, relay, tcp, yamux};
use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder};
use sha3::{Digest, Keccak256};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use zeroize::{Zeroize, Zeroizing};

use cluster_core::{canonical_address, ClusterTransport};

use crate::ipc::MeshMessage;
pub use crate::relay_node::RELAY_PROLOGUE;
use crate::transport::MeshTransport;

/// libp2p protocol string advertised over `identify` (carries our public key for address resolution).
const IDENTIFY_PROTOCOL: &str = "/citrate/cluster/1.0.0";

/// gossipsub heartbeat — small mesh, snappy formation (matches the compute-pool transport).
const GOSSIPSUB_HEARTBEAT: Duration = Duration::from_millis(200);

/// Idle connection timeout — keep an authorized-but-quiet peer meshed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// CL-B-009: connection-limit caps. A cluster group is a small mesh, so a handful of peers is ample;
/// these bound the inbound surface an off-roster host can force before admission drops it (each
/// inbound connection costs a full Noise_XX handshake + a secp256k1 verify before `identify` runs).
const MAX_ESTABLISHED_INCOMING: u32 = 64;
const MAX_PENDING_INCOMING: u32 = 16;
const MAX_ESTABLISHED_PER_PEER: u32 = 2;

/// PBA-L6b-020: the most accepted mesh messages buffered between two daemon drains. The daemon is
/// request-driven (it drains on Status/Poll), so an authorized-but-flooding peer could otherwise grow
/// the inbox without bound between polls. Past the cap new messages are dropped.
pub const MAX_INBOX: usize = 1024;

/// PBA-L6b-006: how long a connection may stay un-identified before it is dropped. `identify` runs
/// immediately after the Noise/yamux upgrade, so a legitimate peer is identified in well under a
/// second; a peer that never speaks `identify` is reaped instead of being left meshed forever.
const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the swarm task sweeps for connections past [`IDENTIFY_TIMEOUT`].
const IDENTIFY_SWEEP: Duration = Duration::from_millis(500);

/// HUP-S8.4 (CL-S4 prep): how often the swarm re-dials bootstrap peers that are not connected.
/// Admission is decided at `identify`, so a peer that connected before it was authorized is dropped;
/// re-dialing lets it in once a roster or DeviceLink update authorizes it, without a restart.
pub(crate) const BOOTSTRAP_REDIAL: Duration = Duration::from_secs(5);

/// Most bootstrap addresses the swarm keeps for re-dial (start-up list plus requested dials).
pub(crate) const MAX_BOOTSTRAP: usize = 64;

/// Most bootstrap addresses re-dialed per tick (bounds the work an oversized list can cause).
pub(crate) const MAX_REDIAL_PER_TICK: usize = 16;

/// HUP-S8.4: how often mDNS re-queries the local network once its start-up probe is done (the
/// probe itself starts at 500 ms and doubles). PENDING OWNER SIGN-OFF.
#[cfg(feature = "mdns")]
pub(crate) const MDNS_QUERY_INTERVAL: Duration = Duration::from_secs(30);

/// HUP-S8.4: how long an mDNS record we announce stays valid at the listener. PENDING OWNER SIGN-OFF.
#[cfg(feature = "mdns")]
pub(crate) const MDNS_TTL: Duration = Duration::from_secs(120);

/// HUP-S8.4: most mDNS-discovered peers kept per group swarm (a LAN flood cannot grow memory).
pub(crate) const MAX_DISCOVERED_PEERS: usize = 256;

/// HUP-S8.4: most addresses kept per discovered peer.
pub(crate) const MAX_DISCOVERED_ADDRS: usize = 8;

/// HUP-S8.4: per-group listen ports are spread over this many ports above the configured base
/// (`base + keccak(group) mod span`), so a group's port is stable across restarts and a seed stays
/// valid. A port already taken falls back to an ephemeral one. PENDING OWNER SIGN-OFF.
pub const GROUP_PORT_SPAN: u16 = 1024;

/// PBA-L6b-006: the gossipsub application score given to every peer that is not (yet) admitted.
/// It sits below the gossip and publish thresholds (so the peer is never sent a publication, a
/// forward, IHAVE gossip or an IWANT reply, and is never grafted into the mesh) but ABOVE the
/// graylist threshold, so the peer's own SUBSCRIBE is still recorded — otherwise a legitimate peer
/// admitted a moment later at `identify` would never be sent anything.
const UNADMITTED_APP_SCORE: f64 = -1_000.0;
/// Score thresholds paired with [`UNADMITTED_APP_SCORE`] (the gossipsub defaults, except a graylist
/// low enough that an unadmitted peer's subscription is still processed).
const GOSSIP_THRESHOLD: f64 = -10.0;
const PUBLISH_THRESHOLD: f64 = -50.0;
const GRAYLIST_THRESHOLD: f64 = -10_000.0;

/// V60 S0-NAT-SPIKE: the most relays a node holds reservations on (`CITRATE_CLUSTER_RELAYS`).
pub const MAX_RELAYS: usize = 4;

/// V60 S0-NAT-SPIKE: how a member is reached right now. `Direct` when at least one connection to it
/// is a plain TCP connection (dialed, accepted or hole-punched), `Relayed` when every connection
/// goes through a circuit relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    Direct,
    Relayed,
}

impl LinkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkKind::Direct => "direct",
            LinkKind::Relayed => "relayed",
        }
    }
}

/// V60 S0-NAT-SPIKE: the kind of a connection, from an address on its endpoint.
pub(crate) fn link_of(addr: &Multiaddr) -> LinkKind {
    if addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
        LinkKind::Relayed
    } else {
        LinkKind::Direct
    }
}

/// V60 S0-NAT-SPIKE: NAT traversal counters for one group swarm (tests and the spike numbers).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NatStats {
    /// New reservations a relay accepted for us (renewals not counted).
    pub reservations_accepted: u64,
    /// DCUtR hole punches that produced a direct connection.
    pub hole_punch_ok: u64,
    /// DCUtR hole punches that failed (the members stay on the relay).
    pub hole_punch_failed: u64,
}

/// Errors from constructing / listening the transport. The [`ClusterTransport`] surface itself is
/// infallible (the daemon drives it with `()` returns); all fallible work is in [`Libp2pTransport::new`].
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("invalid secp256k1 secret: {0}")]
    BadSecret(String),
    #[error("could not derive this node's address from its key")]
    SelfAddress,
    #[error("tokio runtime: {0}")]
    Runtime(String),
    #[error("swarm build: {0}")]
    Build(String),
    #[error("subscribe to group topic: {0}")]
    Subscribe(String),
    #[error("listen on {addr}: {reason}")]
    Listen { addr: Multiaddr, reason: String },
    #[error("swarm task is gone")]
    Closed,
}

/// Construction config for a group's libp2p mesh transport.
pub struct Libp2pConfig {
    /// The device's 32-byte secp256k1 secret (HUP-S8.1 device key; a client without a DeviceLink
    /// passes its comms key; never the wallet key). NEVER inline in
    /// argv/env: read from a 0600 file (`CITRATE_CLUSTER_SEED_FILE`). Wiped from memory when this
    /// `Libp2pConfig` is dropped (see the `Drop` impl below — CL-B-001).
    pub secret: [u8; 32],
    /// The multiaddr to listen on (e.g. `/ip4/0.0.0.0/tcp/0`). `CITRATE_CLUSTER_LISTEN`.
    pub listen: Multiaddr,
    /// The group id — the single gossipsub topic this mesh fans out on (`topic = group_id`).
    pub group_id: String,
    /// Static bootstrap peers to dial on startup (the "chain-derived bootstrap"). Errors are tolerated
    /// (a peer may not be up yet); inbound admission still gates every connection.
    pub bootstrap: Vec<Multiaddr>,
    /// HUP-S8.4: announce and discover peers on the local network with mDNS. Off unless the operator
    /// opts in (`CITRATE_CLUSTER_MDNS=1`): mDNS tells the LAN this device's PeerId. Discovery never
    /// admits anyone; it only supplies addresses to dial.
    pub mdns: bool,
    /// V60 S0-NAT-SPIKE: circuit relays to reserve on, each `/…/p2p/<relay peer id>`
    /// ([`parse_relay_addrs`]). Empty: no relay, no reservation (the pre-spike behaviour).
    pub relays: Vec<Multiaddr>,
}

/// CL-B-001: scrub the 32-byte secp256k1 secret from memory when the config is dropped. A manual
/// `Drop` (not `#[derive(ZeroizeOnDrop)]`) because the other fields (`Multiaddr`, `String`, `Vec`)
/// are not `Zeroize`; only `secret` carries key material and needs wiping.
impl Drop for Libp2pConfig {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Commands the sync surface hands to the swarm task.
enum SwarmCmd {
    /// Publish bytes to the group topic.
    Publish(Vec<u8>),
    /// Network-dial a bootstrap/peer multiaddr.
    Dial(Multiaddr),
    /// Network-dial seeded addresses, every address of one peer in a single attempt
    /// ([`redial_plan`]).
    DialMany(Vec<Multiaddr>),
    /// Drop every live connection to a (now-deauthorized) address.
    Disconnect(String),
    /// Report the concrete listen multiaddrs (for tests / bootstrap wiring).
    Listeners(oneshot::Sender<Vec<Multiaddr>>),
    /// HUP-S8.4: report the addresses another machine can dial us on, each ending in our PeerId.
    SeedAddrs(oneshot::Sender<Vec<Multiaddr>>),
}

/// State shared between the sync surface and the swarm task. `std::sync::Mutex` with only short,
/// await-free critical sections inside the task.
#[derive(Default)]
struct Shared {
    /// Addresses `cluster-core` has admitted (via `dial`) — the on-wire authorization set.
    authorized: BTreeSet<String>,
    /// Addresses currently connected AND authorized (`connected ⊆ admitted`).
    connected: BTreeSet<String>,
    /// Inbox of accepted mesh messages, drained by the daemon.
    inbox: Vec<MeshMessage>,
    /// V60 S0-NAT-SPIKE: how each connected address is reached (keys ⊆ `connected`).
    links: BTreeMap<String, LinkKind>,
    /// V60 S0-NAT-SPIKE: NAT traversal counters.
    nat: NatStats,
}

/// The libp2p-backed [`MeshTransport`]. One instance == one group's mesh (one topic, one swarm).
pub struct Libp2pTransport {
    /// The runtime the swarm task runs on. HUP-S8.4: shared by every group's swarm in one daemon
    /// ([`Libp2pFactory`]); a transport built with [`Libp2pTransport::new`] owns its own.
    _rt: Arc<Runtime>,
    /// The swarm task. Aborted on drop, so leaving a group tears its swarm down (and frees its
    /// port) even while other groups keep the shared runtime alive.
    task: tokio::task::JoinHandle<()>,
    /// This node's canonical address (derived from `secret`).
    self_address: String,
    /// The group topic (== group id).
    topic: String,
    /// This device's PeerId (derived from the same key as `self_address`).
    local_peer: PeerId,
    shared: Arc<Mutex<Shared>>,
    cmd_tx: mpsc::UnboundedSender<SwarmCmd>,
}

impl Drop for Libp2pTransport {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(NetworkBehaviour)]
struct ClusterBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    /// CL-B-009: refuse connections past the caps before they cost a Noise handshake.
    connection_limits: connection_limits::Behaviour,
    /// V60 S0-NAT-SPIKE: circuit relay v2 client (reservations on the configured relays, and dials
    /// through them). Idle when no relay is configured.
    relay_client: relay::client::Behaviour,
    /// V60 S0-NAT-SPIKE: direct connection upgrade through relay (hole punching).
    dcutr: dcutr::Behaviour,
    /// HUP-S8.4: LAN discovery, present only when [`Libp2pConfig::mdns`] is set (and the daemon is
    /// built with the `mdns` feature).
    mdns: Toggle<MdnsBehaviour>,
}

/// The mDNS behaviour when the `mdns` feature is built in.
#[cfg(feature = "mdns")]
type MdnsBehaviour = mdns::tokio::Behaviour;
/// Without the `mdns` feature the slot holds a behaviour that never does anything (and is never
/// enabled: [`Libp2pTransport::new_on`] refuses `mdns: true`).
#[cfg(not(feature = "mdns"))]
type MdnsBehaviour = libp2p::swarm::dummy::Behaviour;

/// Whether this build carries mDNS discovery (the `mdns` cargo feature).
pub const MDNS_BUILT_IN: bool = cfg!(feature = "mdns");

/// A fresh multi-thread tokio runtime for swarm tasks.
pub fn swarm_runtime() -> Result<Runtime, TransportError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| TransportError::Runtime(e.to_string()))
}

impl Libp2pTransport {
    /// Build and start the mesh transport for one group on its own tokio runtime. Synchronous: it
    /// stands up the runtime, builds + starts the swarm (listening on `cfg.listen`, subscribed to
    /// the group topic), and spawns the driver task before returning.
    pub fn new(cfg: Libp2pConfig) -> Result<Self, TransportError> {
        let rt = Arc::new(swarm_runtime()?);
        Self::new_on(cfg, rt)
    }

    /// HUP-S8.4: like [`new`](Self::new), but the swarm task runs on `rt`, which other groups' swarms
    /// may share. Dropping the transport aborts only this group's task.
    pub fn new_on(cfg: Libp2pConfig, rt: Arc<Runtime>) -> Result<Self, TransportError> {
        if cfg.mdns && !MDNS_BUILT_IN {
            return Err(TransportError::Build(NO_MDNS_BUILD.to_string()));
        }
        // Build the libp2p identity from the device's secp256k1 secret. `try_from_bytes`
        // zeroizes the buffer we pass; `Zeroizing` also wipes it on the error path, and `cfg` (whose
        // `secret` is a copy) is wiped by its `Drop` when `new` returns (CL-B-001).
        let mut secret_buf = Zeroizing::new(cfg.secret);
        let secp_secret = identity::secp256k1::SecretKey::try_from_bytes(&mut *secret_buf)
            .map_err(|e| TransportError::BadSecret(e.to_string()))?;
        let secp_keypair = identity::secp256k1::Keypair::from(secp_secret);
        let device_keypair = identity::Keypair::from(secp_keypair);
        let self_address =
            address_from_public_key(&device_keypair.public()).ok_or(TransportError::SelfAddress)?;
        // V60 MESH-3: with relays, this group's swarm has its own PeerId (a group key derived from
        // the device key) and proves it acts for the device with a signed binding in identify, so a
        // relay routes each group's circuits to that group's swarm. Without relays: the device key.
        let (keypair, agent) = if cfg.relays.is_empty() {
            (device_keypair, None)
        } else {
            let kp = crate::group_key::derive_group_keypair(&cfg.secret, &cfg.group_id)
                .map_err(TransportError::Build)?;
            let agent =
                crate::group_key::bind(&cfg.secret, &cfg.group_id, &kp.public().to_peer_id())
                    .map_err(TransportError::Build)?;
            (kp, Some(agent))
        };
        let local_peer = keypair.public().to_peer_id();

        let shared = Arc::new(Mutex::new(Shared::default()));
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<SwarmCmd>();

        let topic_name = cfg.group_id.clone();
        let topic_task = topic_name.clone();
        let listen = cfg.listen.clone();
        let bootstrap = cfg.bootstrap.clone();
        let mdns_on = cfg.mdns;
        let relays = cfg.relays.clone();
        let shared_task = Arc::clone(&shared);

        // All swarm construction must happen inside the runtime context (`.with_tokio()`), so build +
        // listen + spawn under `block_on`; the spawned task then runs on the runtime's worker threads.
        let build = rt.block_on(async move {
            let relay_ids: BTreeSet<PeerId> = relays.iter().filter_map(bootstrap_peer_id).collect();
            let mut swarm = build_swarm(keypair, &topic_task, mdns_on, relay_ids, agent)?;
            let topic = gossipsub::IdentTopic::new(topic_task.clone());
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&topic)
                .map_err(|e| TransportError::Subscribe(format!("{e:?}")))?;
            swarm
                .listen_on(listen.clone())
                .map_err(|e| TransportError::Listen {
                    addr: listen.clone(),
                    reason: e.to_string(),
                })?;
            for addr in &bootstrap {
                // Tolerate transient dial failures — inbound admission still gates every peer.
                let _ = swarm.dial(addr.clone());
            }
            let task = tokio::spawn(swarm_loop(
                swarm,
                topic_task,
                cmd_rx,
                shared_task,
                bootstrap,
                relays,
            ));
            Ok::<_, TransportError>(task)
        })?;

        Ok(Self {
            _rt: rt,
            task: build,
            self_address,
            topic: topic_name,
            local_peer,
            shared,
            cmd_tx,
        })
    }

    /// Derive `(address, peer_id)` from a 32-byte secp256k1 secret WITHOUT starting a swarm — so a
    /// node can print its identity offline (to build the other node's bootstrap multiaddr for a soak,
    /// and to verify the deterministic PeerId↔address binding). `try_from_bytes` zeroizes the buffer.
    pub fn identity_from_secret(mut secret: [u8; 32]) -> Result<(String, String), TransportError> {
        let secp_secret = identity::secp256k1::SecretKey::try_from_bytes(&mut secret)
            .map_err(|e| TransportError::BadSecret(e.to_string()))?;
        let keypair = identity::Keypair::from(identity::secp256k1::Keypair::from(secp_secret));
        let address =
            address_from_public_key(&keypair.public()).ok_or(TransportError::SelfAddress)?;
        Ok((address, keypair.public().to_peer_id().to_string()))
    }

    /// This node's canonical address (its device identity on the mesh; never the wallet address).
    pub fn self_address(&self) -> &str {
        &self.self_address
    }

    /// This group swarm's PeerId: the device PeerId, or (V60 MESH-3, with relays) the group key's.
    pub fn peer_id(&self) -> PeerId {
        self.local_peer
    }

    /// The group topic this transport meshes on.
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// The concrete listen multiaddrs (useful when listening on port 0). Blocks briefly.
    pub fn listeners(&self) -> Result<Vec<Multiaddr>, TransportError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCmd::Listeners(tx))
            .map_err(|_| TransportError::Closed)?;
        rx.blocking_recv().map_err(|_| TransportError::Closed)
    }

    /// HUP-S8.4: the addresses another machine can dial this group's swarm on, each ending in our
    /// PeerId (what a group seed carries). Unspecified and IPv6 link-local addresses are left out;
    /// loopback only when nothing else is listening. Blocks briefly.
    pub fn seed_multiaddrs(&self) -> Result<Vec<Multiaddr>, TransportError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SwarmCmd::SeedAddrs(tx))
            .map_err(|_| TransportError::Closed)?;
        rx.blocking_recv().map_err(|_| TransportError::Closed)
    }

    /// V60 S0-NAT-SPIKE: how each connected member address is reached (direct or relayed).
    pub fn links(&self) -> BTreeMap<String, LinkKind> {
        self.shared
            .lock()
            .map(|s| s.links.clone())
            .unwrap_or_default()
    }

    /// V60 S0-NAT-SPIKE: this swarm's NAT traversal counters.
    pub fn nat_stats(&self) -> NatStats {
        self.shared
            .lock()
            .map(|s| s.nat.clone())
            .unwrap_or_default()
    }

    /// Network-dial a peer's multiaddr (bootstrap wiring). Admission still gates the resulting
    /// connection — dialing does not imply authorizing.
    pub fn dial_multiaddr(&self, addr: Multiaddr) -> Result<(), TransportError> {
        self.cmd_tx
            .send(SwarmCmd::Dial(addr))
            .map_err(|_| TransportError::Closed)
    }
}

impl ClusterTransport for Libp2pTransport {
    /// Authorize `peer` (admitted by `cluster-core`) to mesh with us. Carries no network location, so
    /// it records authorization; the socket opens via inbound accept or an explicit bootstrap dial.
    fn dial(&mut self, peer: &str) {
        if let Some(a) = canonical_address(peer) {
            if let Ok(mut s) = self.shared.lock() {
                s.authorized.insert(a);
            }
        }
    }

    /// Deauthorize `peer` and drop any live connection to it (eviction, in one step).
    fn disconnect(&mut self, peer: &str) {
        if let Some(a) = canonical_address(peer) {
            if let Ok(mut s) = self.shared.lock() {
                s.authorized.remove(&a);
                s.connected.remove(&a);
                s.links.remove(&a);
            }
            let _ = self.cmd_tx.send(SwarmCmd::Disconnect(a));
        }
    }

    fn connected(&self) -> Vec<String> {
        self.shared
            .lock()
            .map(|s| s.connected.iter().cloned().collect())
            .unwrap_or_default()
    }
}

impl MeshTransport for Libp2pTransport {
    /// Publish `data` to the group topic. The sender identity on the wire is the gossipsub message
    /// signature over our secp256k1 key — receivers derive `from` from that authenticated source, so
    /// the `from` argument (always this node's own address) is implicit and not trusted from the wire.
    fn publish(&mut self, _from: &str, data: &str) {
        let _ = self
            .cmd_tx
            .send(SwarmCmd::Publish(data.as_bytes().to_vec()));
    }

    fn drain(&mut self) -> Vec<MeshMessage> {
        self.shared
            .lock()
            .map(|mut s| std::mem::take(&mut s.inbox))
            .unwrap_or_default()
    }
    fn authorize(&mut self, addr: &str) {
        // For libp2p, `dial` IS the authorize (adds to the authorized set; opens no socket). The
        // socket comes from the bootstrap dial or the peer dialing us; identify then admits it.
        self.dial(addr);
    }

    /// HUP-S8.4: dial seeded peers and keep them for re-dial. Every address must parse and name a
    /// peer other than us; nothing is dialed unless all of them do. Admission is still decided at
    /// `identify`, so a seed never lets anyone in by itself.
    fn add_peers(&mut self, addrs: &[String]) -> Result<usize, String> {
        let parsed = parse_peer_addrs(addrs, &self.local_peer)?;
        let n = parsed.len();
        self.cmd_tx
            .send(SwarmCmd::DialMany(parsed))
            .map_err(|_| "the group's mesh has stopped".to_string())?;
        Ok(n)
    }

    fn link(&self, addr: &str) -> Option<&'static str> {
        let a = canonical_address(addr)?;
        self.shared
            .lock()
            .ok()
            .and_then(|s| s.links.get(&a).map(|k| k.as_str()))
    }

    fn seed_addrs(&self) -> Result<Vec<String>, String> {
        self.seed_multiaddrs()
            .map(|v| v.iter().map(Multiaddr::to_string).collect())
            .map_err(|e| e.to_string())
    }
}

/// HUP-S8.4: parse seeded peer addresses. Each must be a multiaddr naming a `/p2p/` peer that is not
/// `local`. All-or-nothing, with a short secret-free reason.
pub(crate) fn parse_peer_addrs(addrs: &[String], local: &PeerId) -> Result<Vec<Multiaddr>, String> {
    if addrs.is_empty() || addrs.len() > cluster_core::seed::MAX_SEED_ADDRS {
        return Err(format!(
            "between 1 and {} peer addresses, got {}",
            cluster_core::seed::MAX_SEED_ADDRS,
            addrs.len()
        ));
    }
    addrs
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let ma: Multiaddr = a
                .trim()
                .parse()
                .map_err(|_| format!("peer address {} is not a multiaddr", i + 1))?;
            match bootstrap_peer_id(&ma) {
                None => Err(format!("peer address {} names no /p2p/ peer", i + 1)),
                Some(p) if p == *local => Err(format!("peer address {} is this node", i + 1)),
                Some(_) => Ok(ma),
            }
        })
        .collect()
}

/// HUP-S8.4: the node-wide libp2p settings, read once from the environment at start-up. One per
/// daemon; each group's swarm is built from it by [`Libp2pFactory`].
pub struct NodeConfig {
    /// The device's 32-byte secp256k1 secret (wiped on drop). Never crosses argv/env, only a 0600 file.
    secret: Zeroizing<[u8; 32]>,
    /// `CITRATE_CLUSTER_LISTEN`: the base listen multiaddr.
    pub listen: Multiaddr,
    /// `CITRATE_CLUSTER_GROUP`: when set, the daemon serves only this group (the pre-HUP-S8.4 mode,
    /// kept so operator soak setups behave exactly as before).
    pub pinned_group: Option<String>,
    /// `CITRATE_CLUSTER_BOOTSTRAP`: peers to dial at start-up. Used by the pinned group only; a
    /// multi-group daemon takes per-group peers from seeds (a bootstrap address names one group's
    /// port, so it cannot serve every group).
    pub bootstrap: Vec<Multiaddr>,
    /// `CITRATE_CLUSTER_MDNS=1`: LAN discovery for every group's swarm. Off by default.
    pub mdns: bool,
    /// V60 S0-NAT-SPIKE: `CITRATE_CLUSTER_RELAYS`, comma-separated relay multiaddrs. Every group's
    /// swarm reserves on them. Unset: no relay.
    pub relays: Vec<Multiaddr>,
}

impl NodeConfig {
    /// Read and validate the libp2p environment:
    ///
    /// * `CITRATE_CLUSTER_SEED_FILE`: a **0600** file with the 32-byte hex secp256k1 secret.
    /// * `CITRATE_CLUSTER_LISTEN`: the listen multiaddr.
    /// * `CITRATE_CLUSTER_GROUP`: optional: pin the daemon to one group (pre-HUP-S8.4 behaviour).
    /// * `CITRATE_CLUSTER_BOOTSTRAP`: optional comma-separated peer multiaddrs (pinned group only).
    /// * `CITRATE_CLUSTER_MDNS`: optional, `1`/`true` turns LAN discovery on.
    /// * `CITRATE_CLUSTER_RELAYS`: optional comma-separated relay multiaddrs (`…/p2p/<relay id>`).
    pub fn from_env() -> Result<Self, String> {
        let seed_file = std::env::var("CITRATE_CLUSTER_SEED_FILE")
            .ok()
            .filter(|p| !p.is_empty())
            .ok_or("CITRATE_CLUSTER_SEED_FILE is required for the libp2p transport")?;
        // CL-B-007: the seed file holds the 32-byte cluster identity secret — refuse to read it
        // unless it is 0600 and owned by us (fail closed on a world/group-readable key file).
        // CL-B-001: the hex string and the decoded raw-secret bytes both carry key material — wrap
        // them in `Zeroizing` so they are wiped from the heap when they drop, not left un-scrubbed.
        // R2 (PBA-L6b-022 class): one no-follow open, checks on the fd, capped read.
        let seed_hex_owned = crate::read_secret_file(&seed_file)?;
        let seed_hex = seed_hex_owned.trim();
        if seed_hex.is_empty() {
            return Err("seed file is empty (fail closed)".into());
        }
        let seed_bytes =
            Zeroizing::new(hex::decode(seed_hex).map_err(|_| "seed must be hex".to_string())?);
        let secret: Zeroizing<[u8; 32]> = Zeroizing::new(
            <[u8; 32]>::try_from(seed_bytes.as_slice())
                .map_err(|_| "seed must be 32 bytes".to_string())?,
        );

        let listen: Multiaddr = std::env::var("CITRATE_CLUSTER_LISTEN")
            .map_err(|_| "CITRATE_CLUSTER_LISTEN is required".to_string())?
            .parse()
            .map_err(|e| format!("CITRATE_CLUSTER_LISTEN is not a multiaddr: {e}"))?;

        let pinned_group = match std::env::var("CITRATE_CLUSTER_GROUP") {
            Ok(g) if g.trim().is_empty() => return Err("CITRATE_CLUSTER_GROUP is empty".into()),
            Ok(g) => Some(g),
            Err(_) => None,
        };

        let bootstrap = match std::env::var("CITRATE_CLUSTER_BOOTSTRAP") {
            Ok(list) if !list.trim().is_empty() => list
                .split(',')
                .map(|s| {
                    s.trim()
                        .parse::<Multiaddr>()
                        .map_err(|e| format!("bad bootstrap multiaddr {s:?}: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => Vec::new(),
        };

        let mdns = parse_flag(std::env::var("CITRATE_CLUSTER_MDNS").ok().as_deref())?;
        if mdns && !MDNS_BUILT_IN {
            return Err(NO_MDNS_BUILD.to_string());
        }

        let relays =
            parse_relay_addrs(&std::env::var("CITRATE_CLUSTER_RELAYS").unwrap_or_default())
                .map_err(|e| format!("CITRATE_CLUSTER_RELAYS: {e}"))?;

        Ok(NodeConfig {
            secret,
            listen,
            pinned_group,
            bootstrap,
            mdns,
            relays,
        })
    }

    /// `(address, peer id)` of this node's identity.
    pub fn identity(&self) -> Result<(String, String), TransportError> {
        Libp2pTransport::identity_from_secret(*self.secret)
    }
}

/// An on/off env flag: unset or empty is off; `1`/`true`/`on` is on; `0`/`false`/`off` is off;
/// anything else is refused (fail closed rather than guess).
pub(crate) fn parse_flag(v: Option<&str>) -> Result<bool, String> {
    match v.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("0") | Some("false") | Some("off") => Ok(false),
        Some("1") | Some("true") | Some("on") => Ok(true),
        Some(other) => Err(format!(
            "CITRATE_CLUSTER_MDNS must be 1 or 0, got {other:?}"
        )),
    }
}

/// V60 S0-NAT-SPIKE: parse a comma-separated relay list. Each entry must be a multiaddr ending in the
/// relay's `/p2p/<peer id>` (the relay hop is chosen by that id) and must not itself be a circuit.
/// At most [`MAX_RELAYS`]. Empty entries are skipped; an empty list is no relays.
pub fn parse_relay_addrs(list: &str) -> Result<Vec<Multiaddr>, String> {
    let mut out: Vec<Multiaddr> = Vec::new();
    for (i, raw) in list.split(',').map(str::trim).enumerate() {
        if raw.is_empty() {
            continue;
        }
        let ma: Multiaddr = raw
            .parse()
            .map_err(|_| format!("relay {} is not a multiaddr", i + 1))?;
        if ma.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
            return Err(format!("relay {} is a circuit address, not a relay", i + 1));
        }
        if !matches!(ma.iter().last(), Some(Protocol::P2p(_))) {
            return Err(format!("relay {} must end in /p2p/<relay peer id>", i + 1));
        }
        if !out.contains(&ma) {
            out.push(ma);
        }
    }
    if list.split(',').filter(|r| !r.trim().is_empty()).count() > MAX_RELAYS {
        return Err(format!("at most {MAX_RELAYS} relays"));
    }
    Ok(out)
}

/// HUP-S8.4: the listen address for `group`'s swarm. A base with TCP port 0 stays ephemeral; a fixed
/// base port `P` becomes `P + keccak256(group)[0..2] mod GROUP_PORT_SPAN` (or ephemeral if that
/// overflows), so each group has its own stable port. The pinned group of a pinned daemon listens on
/// the base exactly (see [`Libp2pFactory`]).
pub fn group_listen(base: &Multiaddr, group: &str) -> Multiaddr {
    base.iter()
        .map(|p| match p {
            Protocol::Tcp(0) => Protocol::Tcp(0),
            Protocol::Tcp(port) => {
                let h = Keccak256::digest(group.as_bytes());
                let off = u16::from_be_bytes([h[0], h[1]]) % GROUP_PORT_SPAN;
                Protocol::Tcp(port.checked_add(off).unwrap_or(0))
            }
            other => other,
        })
        .collect()
}

/// The same address with its TCP port set to 0 (ephemeral).
fn ephemeral(addr: &Multiaddr) -> Multiaddr {
    addr.iter()
        .map(|p| match p {
            Protocol::Tcp(_) => Protocol::Tcp(0),
            other => other,
        })
        .collect()
}

/// HUP-S8.4: builds one group's swarm on demand, all on one shared runtime and under one device
/// identity. This is what lets one daemon process serve every group the device belongs to.
pub struct Libp2pFactory {
    node: NodeConfig,
    rt: Arc<Runtime>,
}

impl Libp2pFactory {
    pub fn new(node: NodeConfig) -> Result<Self, TransportError> {
        Ok(Libp2pFactory {
            node,
            rt: Arc::new(swarm_runtime()?),
        })
    }

    /// The group this daemon is pinned to, if any.
    pub fn pinned_group(&self) -> Option<&str> {
        self.node.pinned_group.as_deref()
    }

    /// Start `group`'s swarm. The pinned group listens on the configured address and dials the
    /// configured bootstrap peers (exactly the pre-HUP-S8.4 behaviour); any other group listens on
    /// its derived port ([`group_listen`]), falling back to an ephemeral port if that one is taken.
    pub fn transport_for(&self, group: &str) -> Result<Libp2pTransport, String> {
        if group.trim().is_empty() {
            return Err("empty group id".into());
        }
        let pinned = self.node.pinned_group.as_deref() == Some(group);
        let listen = if pinned {
            self.node.listen.clone()
        } else {
            group_listen(&self.node.listen, group)
        };
        let bootstrap = if pinned {
            self.node.bootstrap.clone()
        } else {
            Vec::new()
        };
        let cfg = |listen: Multiaddr| Libp2pConfig {
            secret: *self.node.secret,
            listen,
            group_id: group.to_string(),
            bootstrap: bootstrap.clone(),
            mdns: self.node.mdns,
            relays: self.node.relays.clone(),
        };
        match Libp2pTransport::new_on(cfg(listen.clone()), Arc::clone(&self.rt)) {
            Ok(t) => Ok(t),
            Err(TransportError::Listen { .. }) if !pinned => {
                Libp2pTransport::new_on(cfg(ephemeral(&listen)), Arc::clone(&self.rt))
                    .map_err(|e| e.to_string())
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Build the swarm: TCP + Noise + yamux, gossipsub (signed, strict) + identify. Must run inside a
/// tokio runtime context.
fn build_swarm(
    keypair: identity::Keypair,
    group_id: &str,
    mdns_on: bool,
    relay_ids: BTreeSet<PeerId>,
    agent: Option<String>,
) -> Result<Swarm<ClusterBehaviour>, TransportError> {
    // CL-B-009: bind the Noise session to the group by using the group id as the handshake prologue,
    // so a session is cryptographically scoped to the cluster it claims — a peer serving a different
    // group cannot complete a Noise handshake with us at all (the transport gains a notion of cluster
    // it previously lacked; app-layer admission remains the authorization boundary).
    // V60 S0-NAT-SPIKE: the only exception is a TCP connection we dial to a configured relay, which
    // uses RELAY_PROLOGUE (see `mesh_tcp_transport`). The end-to-end connection to a member through
    // a relay is its own Noise session and keeps the group prologue (the relay-client upgrade below).
    let prologue = group_id.as_bytes().to_vec();
    let circuit_prologue = prologue.clone();
    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_other_transport(|k: &identity::Keypair| mesh_tcp_transport(k, prologue, relay_ids))
        .map_err(|e| TransportError::Build(format!("tcp: {e}")))?
        .with_relay_client(
            move |k: &identity::Keypair| {
                noise::Config::new(k).map(|c| c.with_prologue(circuit_prologue.clone()))
            },
            yamux::Config::default,
        )
        .map_err(|e| TransportError::Build(format!("relay client: {e}")))?
        .with_behaviour(|key, relay_client| {
            // PBA-L6b-006: never flood-publish. With the default `flood_publish(true)` every peer
            // subscribed to the topic — including one that never ran `identify` and so was never
            // admitted — received every publication. Publications now go to the mesh (plus
            // above-threshold peers), and admission gates mesh membership through the peer score.
            let gossipsub_config = gossipsub_config()
                .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))?;
            let mut gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))?;
            gossipsub
                .with_peer_score(admission_score_params(), admission_score_thresholds())
                .map_err(Box::<dyn std::error::Error + Send + Sync>::from)?;
            let mut identify_config = identify::Config::new(IDENTIFY_PROTOCOL.into(), key.public());
            if let Some(agent) = agent {
                // V60 MESH-3: the group-key binding (see `group_key`).
                identify_config = identify_config.with_agent_version(agent);
            }
            let identify = identify::Behaviour::new(identify_config);
            // CL-B-009: cap the connection surface so an off-roster host cannot force unbounded Noise
            // handshakes against the listen address.
            let connection_limits = connection_limits::Behaviour::new(
                connection_limits::ConnectionLimits::default()
                    .with_max_established_incoming(Some(MAX_ESTABLISHED_INCOMING))
                    .with_max_pending_incoming(Some(MAX_PENDING_INCOMING))
                    .with_max_established_per_peer(Some(MAX_ESTABLISHED_PER_PEER)),
            );
            // HUP-S8.4: LAN discovery only when the operator opted in (and it is built in).
            let mdns = mdns_behaviour(mdns_on, key)
                .map_err(Box::<dyn std::error::Error + Send + Sync>::from)?;
            let dcutr = dcutr::Behaviour::new(key.public().to_peer_id());
            Ok(ClusterBehaviour {
                gossipsub,
                identify,
                connection_limits,
                relay_client,
                dcutr,
                mdns: Toggle::from(mdns),
            })
        })
        .map_err(|e| TransportError::Build(format!("behaviour: {e}")))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_TIMEOUT))
        .build();
    Ok(swarm)
}

/// The member's TCP output: the authenticated peer and its multiplexed connection.
type MeshConn = (PeerId, StreamMuxerBox);

/// V60 S0-NAT-SPIKE: TCP + Noise + yamux, with the Noise prologue chosen per connection: a connection
/// we DIAL whose target `/p2p/` id is a configured relay uses [`RELAY_PROLOGUE`]; every other
/// connection (inbound, dialed to a member, hole-punched) uses the group prologue. libp2p's upgrade
/// builder applies one fixed upgrade to every connection, so the negotiation is done here with the
/// same steps it takes (multistream-select V1Lazy, Noise, then yamux).
fn mesh_tcp_transport(
    key: &identity::Keypair,
    group_prologue: Vec<u8>,
    relay_ids: BTreeSet<PeerId>,
) -> Boxed<MeshConn> {
    let key = key.clone();
    tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .and_then(move |stream, endpoint: ConnectedPoint| {
            let prologue = if dials_a_relay(&endpoint, &relay_ids) {
                RELAY_PROLOGUE.to_vec()
            } else {
                group_prologue.clone()
            };
            let key = key.clone();
            async move { secure_and_multiplex(stream, endpoint, &key, prologue).await }
        })
        .boxed()
}

/// Whether this connection is one we dialed to a configured relay (the swarm appends the target's
/// `/p2p/` id to every dial address). A hole-punch dial (`role_override` = listener) is never a relay.
fn dials_a_relay(endpoint: &ConnectedPoint, relay_ids: &BTreeSet<PeerId>) -> bool {
    match endpoint {
        ConnectedPoint::Dialer {
            address,
            role_override,
            ..
        } => {
            role_override.is_dialer()
                && bootstrap_peer_id(address).is_some_and(|p| relay_ids.contains(&p))
        }
        ConnectedPoint::Listener { .. } => false,
    }
}

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Negotiate and run Noise (with `prologue`) and then yamux on `stream`, as dialer or listener per
/// `endpoint` (a hole-punch dial with a listener `role_override` takes the listener side).
async fn secure_and_multiplex<S>(
    stream: S,
    endpoint: ConnectedPoint,
    key: &identity::Keypair,
    prologue: Vec<u8>,
) -> Result<MeshConn, std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use multistream_select::{dialer_select_proto, listener_select_proto, Version};
    let outbound = matches!(
        &endpoint,
        ConnectedPoint::Dialer { role_override, .. } if role_override.is_dialer()
    );
    let noise = noise::Config::new(key)
        .map_err(io_err)?
        .with_prologue(prologue);
    let (peer, secured) = if outbound {
        let (proto, io) = dialer_select_proto(stream, noise.protocol_info(), Version::V1Lazy)
            .await
            .map_err(io_err)?;
        noise.upgrade_outbound(io, proto).await.map_err(io_err)?
    } else {
        let (proto, io) = listener_select_proto(stream, noise.protocol_info())
            .await
            .map_err(io_err)?;
        noise.upgrade_inbound(io, proto).await.map_err(io_err)?
    };
    let mux = yamux::Config::default();
    let muxer = if outbound {
        let (proto, io) = dialer_select_proto(secured, mux.protocol_info(), Version::V1Lazy)
            .await
            .map_err(io_err)?;
        mux.upgrade_outbound(io, proto).await.map_err(io_err)?
    } else {
        let (proto, io) = listener_select_proto(secured, mux.protocol_info())
            .await
            .map_err(io_err)?;
        mux.upgrade_inbound(io, proto).await.map_err(io_err)?
    };
    Ok((peer, StreamMuxerBox::new(muxer)))
}

/// V60 S0-NAT-SPIKE: recompute how each admitted address is reached from its live connections.
fn refresh_links(
    conn_kind: &HashMap<ConnectionId, (PeerId, LinkKind)>,
    peer_addr: &HashMap<PeerId, String>,
    shared: &Arc<Mutex<Shared>>,
) {
    let mut links: BTreeMap<String, LinkKind> = BTreeMap::new();
    for (peer, kind) in conn_kind.values() {
        let Some(address) = peer_addr.get(peer) else {
            continue;
        };
        let e = links.entry(address.clone()).or_insert(*kind);
        if *kind == LinkKind::Direct {
            *e = LinkKind::Direct;
        }
    }
    if let Ok(mut s) = shared.lock() {
        links.retain(|a, _| s.connected.contains(a));
        s.links = links;
    }
}

/// Milliseconds since the Unix epoch, for the mesh's NAT log lines.
fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// The refusal when mDNS is asked of a build without it.
pub const NO_MDNS_BUILD: &str =
    "this cluster-daemon was built without mDNS (cargo feature `mdns`); unset CITRATE_CLUSTER_MDNS";

/// HUP-S8.4: the mDNS behaviour for a swarm, or none. IPv4; see [`MDNS_QUERY_INTERVAL`], [`MDNS_TTL`].
#[cfg(feature = "mdns")]
fn mdns_behaviour(on: bool, key: &identity::Keypair) -> Result<Option<MdnsBehaviour>, String> {
    if !on {
        return Ok(None);
    }
    let cfg = mdns::Config {
        ttl: MDNS_TTL,
        query_interval: MDNS_QUERY_INTERVAL,
        enable_ipv6: false,
    };
    mdns::tokio::Behaviour::new(cfg, key.public().to_peer_id())
        .map(Some)
        .map_err(|e| format!("mDNS: {e}"))
}

/// Without the `mdns` feature: never any discovery (`new_on` already refused `mdns: true`).
#[cfg(not(feature = "mdns"))]
fn mdns_behaviour(on: bool, _key: &identity::Keypair) -> Result<Option<MdnsBehaviour>, String> {
    if on {
        return Err(NO_MDNS_BUILD.to_string());
    }
    Ok(None)
}

/// The group topic's gossipsub config: signed + strict validation, and (PBA-L6b-006) NO flood
/// publishing — publications go to mesh peers, and admission gates the mesh through the peer score.
fn gossipsub_config() -> Result<gossipsub::Config, gossipsub::ConfigBuilderError> {
    gossipsub::ConfigBuilder::default()
        .heartbeat_interval(GOSSIPSUB_HEARTBEAT)
        .validation_mode(gossipsub::ValidationMode::Strict)
        .flood_publish(false)
        .build()
}

/// PBA-L6b-006: peer-score parameters used purely as an admission gate. Only the application score
/// carries weight (1.0, so a peer's score IS its app score); IP colocation is disabled so a LAN of
/// legitimate members behind one NAT is never penalised. No topic scoring is configured.
fn admission_score_params() -> gossipsub::PeerScoreParams {
    gossipsub::PeerScoreParams {
        app_specific_weight: 1.0,
        ip_colocation_factor_weight: 0.0,
        ..Default::default()
    }
}

fn admission_score_thresholds() -> gossipsub::PeerScoreThresholds {
    gossipsub::PeerScoreThresholds {
        gossip_threshold: GOSSIP_THRESHOLD,
        publish_threshold: PUBLISH_THRESHOLD,
        graylist_threshold: GRAYLIST_THRESHOLD,
        ..Default::default()
    }
}

/// PBA-L6b-006: shut a (not-yet- or no-longer-) admitted peer out of the group topic: its messages
/// are rejected (blacklist) and it is scored below the gossip/publish thresholds, so it is sent
/// nothing and never grafted into the mesh.
fn gate_peer(swarm: &mut Swarm<ClusterBehaviour>, peer: &PeerId) {
    let gs = &mut swarm.behaviour_mut().gossipsub;
    gs.blacklist_peer(peer);
    gs.set_application_score(peer, UNADMITTED_APP_SCORE);
}

/// PBA-L6b-006: admit a peer to the group topic after `identify` resolved it to an authorized address.
fn ungate_peer(swarm: &mut Swarm<ClusterBehaviour>, peer: &PeerId) {
    let gs = &mut swarm.behaviour_mut().gossipsub;
    gs.remove_blacklisted_peer(peer);
    gs.set_application_score(peer, 0.0);
}

/// The swarm driver: processes commands from the sync surface and swarm events, enforcing admission
/// on the wire.
async fn swarm_loop(
    mut swarm: Swarm<ClusterBehaviour>,
    topic_name: String,
    mut cmd_rx: mpsc::UnboundedReceiver<SwarmCmd>,
    shared: Arc<Mutex<Shared>>,
    mut bootstrap: Vec<Multiaddr>,
    relays: Vec<Multiaddr>,
) {
    // PeerId → resolved member address, for authenticated senders we have identified.
    let mut peer_addr: HashMap<PeerId, String> = HashMap::new();
    // V60 S0-NAT-SPIKE: the configured relays (identified, kept connected, never admitted), the
    // circuit listener held on each (None until listening or after it closed), and every live
    // connection's kind (direct or relayed).
    let relay_ids: BTreeSet<PeerId> = relays.iter().filter_map(bootstrap_peer_id).collect();
    let mut relay_listen: Vec<(Multiaddr, Option<ListenerId>)> = relays
        .iter()
        .map(|r| (r.clone().with(Protocol::P2pCircuit), None))
        .collect();
    // Reservations start once our TCP listener is up, so the relay connection leaves from the
    // listen port (port reuse) and the relay observes the NAT mapping a hole punch will use.
    let mut relays_started = false;
    let mut conn_kind: HashMap<ConnectionId, (PeerId, LinkKind)> = HashMap::new();
    // PBA-L6b-006: connections established but not yet identified, with when they were first seen.
    let mut unidentified: HashMap<PeerId, Instant> = HashMap::new();
    let mut sweep = tokio::time::interval(IDENTIFY_SWEEP);
    // HUP-S8.4: re-dial bootstrap peers that are not connected (the first tick fires at once and is
    // skipped, since start-up already dialed them).
    let mut redial = tokio::time::interval(BOOTSTRAP_REDIAL);
    redial.tick().await;
    bootstrap.truncate(MAX_BOOTSTRAP);
    let topic_hash = gossipsub::IdentTopic::new(topic_name.clone()).hash();
    let local_peer = *swarm.local_peer_id();
    // HUP-S8.4: peers found by mDNS (empty unless mDNS is on), re-dialed while authorized.
    #[cfg_attr(not(feature = "mdns"), allow(unused_mut))]
    let mut discovered: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    let authorized_now = |shared: &Arc<Mutex<Shared>>| -> BTreeSet<String> {
        shared
            .lock()
            .map(|s| s.authorized.clone())
            .unwrap_or_default()
    };

    loop {
        tokio::select! {
            _ = sweep.tick() => {
                // PBA-L6b-006: drop every connection that has not identified within the window.
                let now = Instant::now();
                let expired: Vec<PeerId> = unidentified
                    .iter()
                    .filter(|(_, since)| now.duration_since(**since) >= IDENTIFY_TIMEOUT)
                    .map(|(p, _)| *p)
                    .collect();
                for p in expired {
                    unidentified.remove(&p);
                    gate_peer(&mut swarm, &p);
                    let _ = swarm.disconnect_peer_id(p);
                }
            }
            _ = redial.tick() => {
                if relays_started {
                    for (circuit, listener) in relay_listen.iter_mut().filter(|(_, l)| l.is_none()) {
                        *listener = swarm.listen_on(circuit.clone()).ok();
                    }
                }
                let any_admitted = !peer_addr.is_empty();
                let due = redial_targets(&bootstrap, |p| swarm.is_connected(p), any_admitted);
                for opts in redial_plan(&due) {
                    let _ = swarm.dial(opts);
                }
                // HUP-S8.4: a discovered peer authorized since it was found gets in on this tick.
                let authorized = authorized_now(&shared);
                let due = discovery_targets(
                    &discovered,
                    |p| swarm.is_connected(p),
                    |p| peer_authorized(p, &authorized),
                );
                for (peer, addrs) in due {
                    let _ = swarm.dial(
                        DialOpts::peer_id(peer).addresses(addrs).allocate_new_port().build(),
                    );
                }
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { return; }; // surface dropped → shut down
                match cmd {
                    SwarmCmd::Publish(bytes) => {
                        let topic = gossipsub::IdentTopic::new(topic_name.clone());
                        // `InsufficientPeers` before the mesh forms is expected; the caller retries.
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic, bytes);
                    }
                    SwarmCmd::Dial(addr) => {
                        // A peer dialed on request is kept for re-dial like a bootstrap peer.
                        remember_bootstrap(&mut bootstrap, addr.clone());
                        let _ = swarm.dial(redial_opts(addr));
                    }
                    SwarmCmd::DialMany(addrs) => {
                        for a in &addrs {
                            remember_bootstrap(&mut bootstrap, a.clone());
                        }
                        for opts in redial_plan(&addrs) {
                            let _ = swarm.dial(opts);
                        }
                    }
                    SwarmCmd::Disconnect(address) => {
                        let targets: Vec<PeerId> = peer_addr
                            .iter()
                            .filter(|(_, a)| **a == address)
                            .map(|(p, _)| *p)
                            .collect();
                        for p in targets {
                            gate_peer(&mut swarm, &p);
                            let _ = swarm.disconnect_peer_id(p);
                        }
                    }
                    SwarmCmd::Listeners(tx) => {
                        let _ = tx.send(swarm.listeners().cloned().collect());
                    }
                    SwarmCmd::SeedAddrs(tx) => {
                        let listeners: Vec<Multiaddr> = swarm.listeners().cloned().collect();
                        let _ = tx.send(seed_addrs_from(&listeners, &local_peer));
                    }
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    // Admission on the wire: `identify` carries the peer's authenticated secp256k1
                    // public key. Resolve its address, double-check the key hashes to the connection's
                    // PeerId, and admit-or-drop against the authorized set.
                    // PBA-L6b-006: every new connection starts GATED — no gossip in or out — until
                    // `identify` admits it; the sweep above drops it if it never identifies.
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                        let kind = if endpoint.is_relayed() { LinkKind::Relayed } else { LinkKind::Direct };
                        conn_kind.insert(connection_id, (peer_id, kind));
                        if !peer_addr.contains_key(&peer_id) {
                            gate_peer(&mut swarm, &peer_id);
                            unidentified.entry(peer_id).or_insert_with(Instant::now);
                        } else {
                            refresh_links(&conn_kind, &peer_addr, &shared);
                            if let Some(a) = peer_addr.get(&peer_id) {
                                eprintln!("cluster-mesh: t={} {a} connected {}", now_ms(), kind.as_str());
                            }
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        if !relays_started && link_of(&address) == LinkKind::Direct {
                            relays_started = true;
                            for (circuit, listener) in relay_listen.iter_mut() {
                                *listener = swarm.listen_on(circuit.clone()).ok();
                            }
                        }
                    }
                    SwarmEvent::ListenerClosed { listener_id, .. } => {
                        for (_, l) in relay_listen.iter_mut().filter(|(_, l)| *l == Some(listener_id)) {
                            *l = None;
                        }
                    }
                    SwarmEvent::Behaviour(ClusterBehaviourEvent::RelayClient(
                        relay::client::Event::ReservationReqAccepted { relay_peer_id, renewal, .. },
                    )) => {
                        if !renewal {
                            if let Ok(mut s) = shared.lock() {
                                s.nat.reservations_accepted += 1;
                            }
                            eprintln!("cluster-mesh: t={} relay {relay_peer_id} reservation accepted", now_ms());
                        }
                    }
                    SwarmEvent::Behaviour(ClusterBehaviourEvent::Dcutr(dcutr::Event {
                        remote_peer_id,
                        result,
                    })) => {
                        let ok = result.is_ok();
                        if let Ok(mut s) = shared.lock() {
                            if ok {
                                s.nat.hole_punch_ok += 1;
                            } else {
                                s.nat.hole_punch_failed += 1;
                            }
                        }
                        match result {
                            Ok(_) => eprintln!("cluster-mesh: t={} hole punch to {remote_peer_id} ok", now_ms()),
                            Err(e) => eprintln!("cluster-mesh: t={} hole punch to {remote_peer_id} failed: {e}", now_ms()),
                        }
                    }
                    SwarmEvent::Behaviour(ClusterBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. },
                    )) => {
                        unidentified.remove(&peer_id);
                        if relay_ids.contains(&peer_id) {
                            // V60 S0-NAT-SPIKE: a configured relay. Keep the connection (it carries
                            // our reservation) but never admit it: it stays gated in gossipsub and
                            // out of `connected`.
                            continue;
                        }
                        if info.public_key.to_peer_id() != peer_id {
                            // Key does not match the Noise-authenticated PeerId — refuse.
                            let _ = swarm.disconnect_peer_id(peer_id);
                            continue;
                        }
                        // The peer's address: its key's own address if the group authorizes it,
                        // else (V60 MESH-3) the device address its group-key binding names, if
                        // the group authorizes that. Anything else is refused below.
                        let is_authorized = |a: &str| {
                            shared.lock().map(|s| s.authorized.contains(a)).unwrap_or(false)
                        };
                        let resolved = address_from_public_key(&info.public_key)
                            .filter(|a| is_authorized(a))
                            .or_else(|| {
                                crate::group_key::verify(&info.agent_version, &topic_name, &peer_id)
                                    .filter(|a| is_authorized(a))
                            });
                        if let Some(address) = resolved {
                            let fresh = !peer_addr.contains_key(&peer_id);
                            peer_addr.insert(peer_id, address.clone());
                            ungate_peer(&mut swarm, &peer_id);
                            if let Ok(mut s) = shared.lock() {
                                s.connected.insert(address.clone());
                            }
                            refresh_links(&conn_kind, &peer_addr, &shared);
                            if fresh {
                                let kind = shared
                                    .lock()
                                    .ok()
                                    .and_then(|s| s.links.get(&address).copied())
                                    .unwrap_or(LinkKind::Direct);
                                eprintln!("cluster-mesh: t={} {address} admitted {}", now_ms(), kind.as_str());
                            }
                        } else {
                            // Not in the group's allowed set → keep it gated and drop the connection.
                            gate_peer(&mut swarm, &peer_id);
                            let _ = swarm.disconnect_peer_id(peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(ClusterBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. },
                    )) => {
                        if message.topic != topic_hash {
                            continue; // never widen the accept surface beyond our group topic
                        }
                        // Backstop for the connect→identify window: accept ONLY from an authenticated,
                        // authorized, already-identified source.
                        let Some(source) = message.source else { continue };
                        let Some(address) = peer_addr.get(&source).cloned() else { continue };
                        let authorized = shared
                            .lock()
                            .map(|s| s.authorized.contains(&address))
                            .unwrap_or(false);
                        if !authorized {
                            continue;
                        }
                        if let Some(data) = accept_payload(message.data) {
                            if let Ok(mut s) = shared.lock() {
                                push_inbox(&mut s.inbox, MeshMessage { from: address, data });
                            }
                        }
                    }
                    // HUP-S8.4: LAN discovery. Remember what was found (bounded) and dial a newly found
                    // peer at once if the group already authorizes it; admission is still decided
                    // at `identify`, and the Noise prologue refuses another group's swarm.
                    #[cfg(feature = "mdns")]
                    SwarmEvent::Behaviour(ClusterBehaviourEvent::Mdns(mdns::Event::Discovered(
                        found,
                    ))) => {
                        let mut fresh: Vec<PeerId> = Vec::new();
                        for (peer, addr) in found {
                            if peer != local_peer
                                && remember_discovered(&mut discovered, peer, addr)
                                && !fresh.contains(&peer)
                            {
                                fresh.push(peer);
                            }
                        }
                        let authorized = authorized_now(&shared);
                        for peer in fresh {
                            if swarm.is_connected(&peer) || !peer_authorized(&peer, &authorized) {
                                continue;
                            }
                            if let Some(addrs) = discovered.get(&peer) {
                                let _ = swarm.dial(
                                    DialOpts::peer_id(peer)
                                        .addresses(addrs.clone())
                                        .allocate_new_port()
                                        .build(),
                                );
                            }
                        }
                    }
                    #[cfg(feature = "mdns")]
                    SwarmEvent::Behaviour(ClusterBehaviourEvent::Mdns(mdns::Event::Expired(
                        gone,
                    ))) => {
                        for (peer, addr) in gone {
                            forget_discovered(&mut discovered, &peer, &addr);
                        }
                    }
                    // Only forget the peer once its LAST connection is gone (up to
                    // MAX_ESTABLISHED_PER_PEER may be open).
                    SwarmEvent::ConnectionClosed { connection_id, num_established: 1.., .. } => {
                        conn_kind.remove(&connection_id);
                        refresh_links(&conn_kind, &peer_addr, &shared);
                    }
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, num_established: 0, .. } => {
                        conn_kind.remove(&connection_id);
                        unidentified.remove(&peer_id);
                        // Lift the blacklist so a later reconnect is handled afresh (gossipsub
                        // ignores a blacklisted peer's new connection entirely, which would stop us
                        // announcing our subscription to it once it is admitted). The reconnect is
                        // re-gated at ConnectionEstablished.
                        swarm
                            .behaviour_mut()
                            .gossipsub
                            .remove_blacklisted_peer(&peer_id);
                        if let Some(address) = peer_addr.remove(&peer_id) {
                            if let Ok(mut s) = shared.lock() {
                                s.connected.remove(&address);
                                s.links.remove(&address);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Keep `addr` for re-dial: an address already listed stays where it is; a full list
/// ([`MAX_BOOTSTRAP`]) drops its oldest entry first, so a peer dialed late in a long session is still
/// re-dialed.
pub(crate) fn remember_bootstrap(bootstrap: &mut Vec<Multiaddr>, addr: Multiaddr) {
    if bootstrap.contains(&addr) {
        return;
    }
    if bootstrap.len() >= MAX_BOOTSTRAP {
        bootstrap.remove(0);
    }
    bootstrap.push(addr);
}

/// HUP-S8.4: how a re-dial is made: from a NEW local port. A dial that reuses the listen port as
/// its source recreates the exact 4-tuple of a connection this node just closed, and while that
/// tuple sits in TIME_WAIT macOS refuses it with EADDRINUSE (libp2p only falls back to a new port
/// on EADDRNOTAVAIL, the Linux error). Without this, a peer refused once and authorized later could
/// never get back in from a Mac until a restart.
pub(crate) fn redial_opts(addr: Multiaddr) -> DialOpts {
    match bootstrap_peer_id(&addr) {
        Some(id) => DialOpts::peer_id(id)
            .addresses(vec![addr])
            .allocate_new_port()
            .build(),
        None => DialOpts::unknown_peer_id()
            .address(addr)
            .allocate_new_port()
            .build(),
    }
}

/// V60 S0-NAT-SPIKE: how a list of addresses is dialed. libp2p refuses a second dial to a peer while
/// one is in flight, so dialing a peer's addresses one by one tries only the first (a seed that
/// lists a LAN address before a relayed one never reached the relay). Every address naming the same
/// peer goes into ONE attempt (libp2p dials them concurrently), in first-seen peer order; an address
/// without a peer id is its own attempt. Each attempt allocates a new local port ([`redial_opts`]).
pub(crate) fn redial_plan(addrs: &[Multiaddr]) -> Vec<DialOpts> {
    let mut order: Vec<PeerId> = Vec::new();
    let mut by_peer: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    let mut anonymous: Vec<Multiaddr> = Vec::new();
    for a in addrs {
        match bootstrap_peer_id(a) {
            Some(id) => {
                let v = by_peer.entry(id).or_insert_with(|| {
                    order.push(id);
                    Vec::new()
                });
                if !v.contains(a) {
                    v.push(a.clone());
                }
            }
            None => anonymous.push(a.clone()),
        }
    }
    let mut plan: Vec<DialOpts> = order
        .into_iter()
        .map(|id| {
            DialOpts::peer_id(id)
                .addresses(by_peer.remove(&id).unwrap_or_default())
                .allocate_new_port()
                .build()
        })
        .collect();
    plan.extend(anonymous.into_iter().map(redial_opts));
    plan
}

/// The peer id a bootstrap multiaddr names (its LAST `/p2p/<id>`), if any. V60 S0-NAT-SPIKE: a
/// circuit address `<relay>/p2p/<relay id>/p2p-circuit/p2p/<target>` names the target, not the relay.
fn bootstrap_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter()
        .filter_map(|p| match p {
            libp2p::multiaddr::Protocol::P2p(id) => Some(id),
            _ => None,
        })
        .last()
}

/// HUP-S8.4: the bootstrap addresses due for a re-dial. An address naming a peer id is due while
/// that peer is not connected; one without a peer id is due only while no peer is admitted (it
/// cannot be matched to a connection). At most [`MAX_REDIAL_PER_TICK`] per tick.
pub(crate) fn redial_targets(
    bootstrap: &[Multiaddr],
    is_connected: impl Fn(&PeerId) -> bool,
    any_admitted: bool,
) -> Vec<Multiaddr> {
    bootstrap
        .iter()
        .filter(|a| match bootstrap_peer_id(a) {
            Some(id) => !is_connected(&id),
            None => !any_admitted,
        })
        .take(MAX_REDIAL_PER_TICK)
        .cloned()
        .collect()
}

/// HUP-S8.4: record an mDNS-discovered `(peer, addr)`. Returns whether anything new was learned.
/// Bounded: at most [`MAX_DISCOVERED_PEERS`] peers (a new peer past the cap is ignored) and
/// [`MAX_DISCOVERED_ADDRS`] addresses per peer (the oldest address makes room).
#[cfg_attr(not(feature = "mdns"), allow(dead_code))]
pub(crate) fn remember_discovered(
    discovered: &mut HashMap<PeerId, Vec<Multiaddr>>,
    peer: PeerId,
    addr: Multiaddr,
) -> bool {
    if !discovered.contains_key(&peer) && discovered.len() >= MAX_DISCOVERED_PEERS {
        return false;
    }
    let addrs = discovered.entry(peer).or_default();
    if addrs.contains(&addr) {
        return false;
    }
    if addrs.len() >= MAX_DISCOVERED_ADDRS {
        addrs.remove(0);
    }
    addrs.push(addr);
    true
}

/// HUP-S8.4: drop an expired mDNS record; a peer with no address left is forgotten.
#[cfg_attr(not(feature = "mdns"), allow(dead_code))]
pub(crate) fn forget_discovered(
    discovered: &mut HashMap<PeerId, Vec<Multiaddr>>,
    peer: &PeerId,
    addr: &Multiaddr,
) {
    if let Some(addrs) = discovered.get_mut(peer) {
        addrs.retain(|a| a != addr);
        if addrs.is_empty() {
            discovered.remove(peer);
        }
    }
}

/// HUP-S8.4: the discovered peers due for a dial: authorized by the group and not connected. At most
/// [`MAX_REDIAL_PER_TICK`] per tick, in PeerId order (deterministic).
pub(crate) fn discovery_targets(
    discovered: &HashMap<PeerId, Vec<Multiaddr>>,
    is_connected: impl Fn(&PeerId) -> bool,
    is_authorized: impl Fn(&PeerId) -> bool,
) -> Vec<(PeerId, Vec<Multiaddr>)> {
    let mut due: Vec<(PeerId, Vec<Multiaddr>)> = discovered
        .iter()
        .filter(|(p, _)| !is_connected(p) && is_authorized(p))
        .map(|(p, a)| (*p, a.clone()))
        .collect();
    due.sort_by_key(|d| d.0);
    due.truncate(MAX_REDIAL_PER_TICK);
    due
}

/// HUP-S8.4: whether `peer`'s key resolves to an address in `authorized`.
fn peer_authorized(peer: &PeerId, authorized: &BTreeSet<String>) -> bool {
    address_from_peer_id(peer).is_some_and(|a| authorized.contains(&a))
}

/// HUP-S8.4: the member/device address a PeerId stands for, read from the PeerId itself. A
/// secp256k1 key is small enough that libp2p inlines it in the PeerId (identity multihash), so no
/// connection is needed. Anything else → `None`. This only decides whom to DIAL; the dialed peer
/// must still prove the key in the Noise handshake and pass admission at `identify`.
pub(crate) fn address_from_peer_id(peer: &PeerId) -> Option<String> {
    let mh: &libp2p::multihash::Multihash<64> = peer.as_ref();
    if mh.code() != 0x00 {
        return None;
    }
    let pk = identity::PublicKey::try_decode_protobuf(mh.digest()).ok()?;
    address_from_public_key(&pk)
}

/// HUP-S8.4: the listen addresses worth putting in a seed, each ending in `/p2p/<local>`. Leaves out
/// unspecified and IPv6 link-local addresses; keeps loopback only when nothing else is listening;
/// at most `cluster_core::seed::MAX_SEED_ADDRS`, routable ones first.
pub(crate) fn seed_addrs_from(listeners: &[Multiaddr], local: &PeerId) -> Vec<Multiaddr> {
    let class = |a: &Multiaddr| -> Option<bool> {
        // Some(true) = loopback, Some(false) = routable, None = never offered.
        match a.iter().next() {
            Some(Protocol::Ip4(ip)) if ip.is_unspecified() => None,
            Some(Protocol::Ip4(ip)) => Some(ip.is_loopback()),
            Some(Protocol::Ip6(ip)) if ip.is_unspecified() => None,
            Some(Protocol::Ip6(ip)) if (ip.segments()[0] & 0xffc0) == 0xfe80 => None,
            Some(Protocol::Ip6(ip)) => Some(ip.is_loopback()),
            Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)) => Some(false),
            _ => None,
        }
    };
    let mut routable: Vec<Multiaddr> = Vec::new();
    let mut loopback: Vec<Multiaddr> = Vec::new();
    for a in listeners {
        let mut with_id = a.clone();
        // A circuit listener (`<relay>/p2p/<relay id>/p2p-circuit`) still needs our id at the end.
        if !matches!(with_id.iter().last(), Some(Protocol::P2p(_))) {
            with_id.push(Protocol::P2p(*local));
        }
        match class(a) {
            Some(false) if !routable.contains(&with_id) => routable.push(with_id),
            Some(true) if !loopback.contains(&with_id) => loopback.push(with_id),
            _ => {}
        }
    }
    let mut out = if routable.is_empty() {
        loopback
    } else {
        routable
    };
    out.truncate(cluster_core::seed::MAX_SEED_ADDRS);
    out
}

/// PBA-L6b-037: a gossip payload is accepted only if it is UTF-8 AND a well-formed CID (the only
/// thing the co-pin mesh carries). Anything else is dropped at the wire.
fn accept_payload(data: Vec<u8>) -> Option<String> {
    String::from_utf8(data)
        .ok()
        .filter(|s| cluster_core::is_valid_cid(s))
}

/// PBA-L6b-020: append to the inbox unless it already holds [`MAX_INBOX`] messages.
fn push_inbox(inbox: &mut Vec<MeshMessage>, m: MeshMessage) -> bool {
    if inbox.len() >= MAX_INBOX {
        return false;
    }
    inbox.push(m);
    true
}

/// Derive an EVM address (canonical: lowercase, no `0x`, 40 hex) from a libp2p **secp256k1** public
/// key: `keccak256(uncompressed_pubkey[1..])[12..]`. Non-secp256k1 keys → `None`.
fn address_from_public_key(pk: &identity::PublicKey) -> Option<String> {
    let secp = pk.clone().try_into_secp256k1().ok()?;
    let uncompressed = secp.to_bytes_uncompressed(); // [u8; 65] = 0x04 || X || Y
    let mut hasher = Keccak256::new();
    hasher.update(&uncompressed[1..]);
    let digest = hasher.finalize();
    Some(hex::encode(&digest[12..]))
}

#[cfg(test)]
#[path = "libp2p_transport_tests.rs"]
mod libp2p_transport_tests;

#[cfg(test)]
#[path = "libp2p_discovery_tests.rs"]
mod libp2p_discovery_tests;

#[cfg(test)]
#[path = "libp2p_relay_tests.rs"]
mod libp2p_relay_tests;
