//! The **libp2p** [`MeshTransport`] (CL-S1): a real cross-machine, Noise-encrypted gossipsub mesh
//! among a group's members. One gossipsub topic per group (`topic = group_id`, D-24), peer identity
//! bound to the member's **secp256k1** key (CL-2 — the same key as its wallet address), and admission
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
//!   location, so it authorizes but cannot itself open a socket. Network dials come from an explicit
//!   bootstrap multiaddr list ([`dial_multiaddr`](Libp2pTransport::dial_multiaddr) /
//!   `CITRATE_CLUSTER_BOOTSTRAP`) — the "chain-derived bootstrap" model. Kademlia/mDNS/NAT traversal
//!   are follow-ons (planset "Out (follow-ons)").
//! * **One group per daemon process**: the frozen `fn() -> T` transport factory carries no group id,
//!   so a libp2p daemon serves one configured group's mesh (`CITRATE_CLUSTER_GROUP` → topic) bound to
//!   one `CITRATE_CLUSTER_LISTEN`. Multi-group-per-daemon needs a per-group config channel through
//!   that seam — a deliberate S2 follow-on, not faked here.
//! * **Relayed sources**: a message's authenticated source must be a peer we have `identify`d (in a
//!   fully-connected small mesh, every publisher is a direct peer). Multi-hop relay of not-yet-
//!   identified sources is dropped; larger-mesh source resolution is future work (soak ladder, CL-S3).
//! * **Authorize-before-connect**: admission is decided once, at the `identify` handshake. A peer that
//!   connects before its address is authorized (via `dial`) is dropped and does not auto-rejoin when
//!   later authorized — it must redial. The intended flow authorizes first (cluster-core sets the
//!   roster, then the mesh dials), so this is a natural ordering, not a gap in the invariant; a
//!   re-admit-on-authorization-change hook is a possible S2 refinement.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::stream::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{gossipsub, identify, identity, noise, tcp, yamux};
use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder};
use sha3::{Digest, Keccak256};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};

use cluster_core::{canonical_address, ClusterTransport};

use crate::ipc::MeshMessage;
use crate::transport::MeshTransport;

/// libp2p protocol string advertised over `identify` (carries our public key for address resolution).
const IDENTIFY_PROTOCOL: &str = "/citrate/cluster/1.0.0";

/// gossipsub heartbeat — small mesh, snappy formation (matches the compute-pool transport).
const GOSSIPSUB_HEARTBEAT: Duration = Duration::from_millis(200);

/// Idle connection timeout — keep an authorized-but-quiet peer meshed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// The member's 32-byte secp256k1 secret (its wallet/comms/cluster key — CL-2). NEVER inline in
    /// argv/env: read from a 0600 file (`CITRATE_CLUSTER_SEED_FILE`). Zeroized once the keypair is built.
    pub secret: [u8; 32],
    /// The multiaddr to listen on (e.g. `/ip4/0.0.0.0/tcp/0`). `CITRATE_CLUSTER_LISTEN`.
    pub listen: Multiaddr,
    /// The group id — the single gossipsub topic this mesh fans out on (`topic = group_id`).
    pub group_id: String,
    /// Static bootstrap peers to dial on startup (the "chain-derived bootstrap"). Errors are tolerated
    /// (a peer may not be up yet); inbound admission still gates every connection.
    pub bootstrap: Vec<Multiaddr>,
}

/// Commands the sync surface hands to the swarm task.
enum SwarmCmd {
    /// Publish bytes to the group topic.
    Publish(Vec<u8>),
    /// Network-dial a bootstrap/peer multiaddr.
    Dial(Multiaddr),
    /// Drop every live connection to a (now-deauthorized) address.
    Disconnect(String),
    /// Report the concrete listen multiaddrs (for tests / bootstrap wiring).
    Listeners(oneshot::Sender<Vec<Multiaddr>>),
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
}

/// The libp2p-backed [`MeshTransport`]. One instance == one group's mesh (one topic, one swarm).
pub struct Libp2pTransport {
    /// Owns the swarm task; dropping it tears the mesh down.
    _rt: Runtime,
    _task: tokio::task::JoinHandle<()>,
    /// This node's canonical address (derived from `secret`).
    self_address: String,
    /// The group topic (== group id).
    topic: String,
    shared: Arc<Mutex<Shared>>,
    cmd_tx: mpsc::UnboundedSender<SwarmCmd>,
}

#[derive(NetworkBehaviour)]
struct ClusterBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
}

impl Libp2pTransport {
    /// Build and start the mesh transport for one group. Synchronous: it stands up a dedicated tokio
    /// runtime, builds + starts the swarm (listening on `cfg.listen`, subscribed to the group topic),
    /// and spawns the driver task before returning.
    pub fn new(cfg: Libp2pConfig) -> Result<Self, TransportError> {
        // Build the libp2p identity from the member's secp256k1 secret (CL-2). `try_from_bytes`
        // zeroizes the buffer we pass, so the raw secret does not linger.
        let mut secret_buf = cfg.secret;
        let secp_secret = identity::secp256k1::SecretKey::try_from_bytes(&mut secret_buf)
            .map_err(|e| TransportError::BadSecret(e.to_string()))?;
        let secp_keypair = identity::secp256k1::Keypair::from(secp_secret);
        let keypair = identity::Keypair::from(secp_keypair);
        let self_address =
            address_from_public_key(&keypair.public()).ok_or(TransportError::SelfAddress)?;

        let rt = Runtime::new().map_err(|e| TransportError::Runtime(e.to_string()))?;
        let shared = Arc::new(Mutex::new(Shared::default()));
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<SwarmCmd>();

        let topic_name = cfg.group_id.clone();
        let topic_task = topic_name.clone();
        let listen = cfg.listen.clone();
        let bootstrap = cfg.bootstrap.clone();
        let shared_task = Arc::clone(&shared);

        // All swarm construction must happen inside the runtime context (`.with_tokio()`), so build +
        // listen + spawn under `block_on`; the spawned task then runs on the runtime's worker threads.
        let build = rt.block_on(async move {
            let mut swarm = build_swarm(keypair)?;
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
            for addr in bootstrap {
                // Tolerate transient dial failures — inbound admission still gates every peer.
                let _ = swarm.dial(addr);
            }
            let task = tokio::spawn(swarm_loop(swarm, topic_task, cmd_rx, shared_task));
            Ok::<_, TransportError>(task)
        })?;

        Ok(Self {
            _rt: rt,
            _task: build,
            self_address,
            topic: topic_name,
            shared,
            cmd_tx,
        })
    }

    /// Build from the process environment — the factory `main.rs` hands the daemon when
    /// `CITRATE_CLUSTER_LISTEN` is set. Reads:
    ///
    /// * `CITRATE_CLUSTER_SEED_FILE` — a **0600** file with the 32-byte hex secp256k1 secret (the
    ///   secret NEVER crosses argv/env, which leak to `ps` — mirrors the comms `CITRATE_MEMBER_SEED_FILE`).
    /// * `CITRATE_CLUSTER_LISTEN` — the listen multiaddr.
    /// * `CITRATE_CLUSTER_GROUP` — the group id (== gossipsub topic). One group per daemon in S1.
    /// * `CITRATE_CLUSTER_BOOTSTRAP` — comma-separated peer multiaddrs to dial (optional).
    ///
    /// `main.rs` pre-validates these before serving, so the `expect`s document invariants rather than
    /// guarding untrusted input.
    pub fn from_env() -> Libp2pTransport {
        let cfg = Self::config_from_env().expect("libp2p transport env (pre-validated in main)");
        Self::new(cfg).expect("libp2p transport start (pre-validated in main)")
    }

    /// Parse + validate the env config (shared by `from_env` and `main.rs`'s startup check).
    pub fn config_from_env() -> Result<Libp2pConfig, String> {
        let seed_file = std::env::var("CITRATE_CLUSTER_SEED_FILE")
            .ok()
            .filter(|p| !p.is_empty())
            .ok_or("CITRATE_CLUSTER_SEED_FILE is required for the libp2p transport")?;
        let seed_hex = std::fs::read_to_string(&seed_file)
            .map_err(|e| format!("reading seed file {seed_file}: {e}"))?;
        let seed_hex = seed_hex.trim();
        if seed_hex.is_empty() {
            return Err("seed file is empty (fail closed)".into());
        }
        let seed_bytes = hex::decode(seed_hex).map_err(|_| "seed must be hex".to_string())?;
        let secret: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| "seed must be 32 bytes".to_string())?;

        let listen: Multiaddr = std::env::var("CITRATE_CLUSTER_LISTEN")
            .map_err(|_| "CITRATE_CLUSTER_LISTEN is required".to_string())?
            .parse()
            .map_err(|e| format!("CITRATE_CLUSTER_LISTEN is not a multiaddr: {e}"))?;

        let group_id = std::env::var("CITRATE_CLUSTER_GROUP")
            .map_err(|_| "CITRATE_CLUSTER_GROUP is required (the mesh topic)".to_string())?;
        if group_id.trim().is_empty() {
            return Err("CITRATE_CLUSTER_GROUP is empty".into());
        }

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

        Ok(Libp2pConfig {
            secret,
            listen,
            group_id,
            bootstrap,
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

    /// This node's canonical address (its cluster/comms/wallet identity).
    pub fn self_address(&self) -> &str {
        &self.self_address
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
        self._rt.block_on(rx).map_err(|_| TransportError::Closed)
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
}

/// Build the swarm: TCP + Noise + yamux, gossipsub (signed, strict) + identify. Must run inside a
/// tokio runtime context.
fn build_swarm(keypair: identity::Keypair) -> Result<Swarm<ClusterBehaviour>, TransportError> {
    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| TransportError::Build(format!("tcp: {e}")))?
        .with_behaviour(|key| {
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(GOSSIPSUB_HEARTBEAT)
                .validation_mode(gossipsub::ValidationMode::Strict)
                .build()
                .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))?;
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))?;
            let identify = identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.into(),
                key.public(),
            ));
            Ok(ClusterBehaviour {
                gossipsub,
                identify,
            })
        })
        .map_err(|e| TransportError::Build(format!("behaviour: {e}")))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_TIMEOUT))
        .build();
    Ok(swarm)
}

/// The swarm driver: processes commands from the sync surface and swarm events, enforcing admission
/// on the wire.
async fn swarm_loop(
    mut swarm: Swarm<ClusterBehaviour>,
    topic_name: String,
    mut cmd_rx: mpsc::UnboundedReceiver<SwarmCmd>,
    shared: Arc<Mutex<Shared>>,
) {
    // PeerId → resolved member address, for authenticated senders we have identified.
    let mut peer_addr: HashMap<PeerId, String> = HashMap::new();
    let topic_hash = gossipsub::IdentTopic::new(topic_name.clone()).hash();

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { return; }; // surface dropped → shut down
                match cmd {
                    SwarmCmd::Publish(bytes) => {
                        let topic = gossipsub::IdentTopic::new(topic_name.clone());
                        // `InsufficientPeers` before the mesh forms is expected; the caller retries.
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic, bytes);
                    }
                    SwarmCmd::Dial(addr) => {
                        let _ = swarm.dial(addr);
                    }
                    SwarmCmd::Disconnect(address) => {
                        let targets: Vec<PeerId> = peer_addr
                            .iter()
                            .filter(|(_, a)| **a == address)
                            .map(|(p, _)| *p)
                            .collect();
                        for p in targets {
                            let _ = swarm.disconnect_peer_id(p);
                        }
                    }
                    SwarmCmd::Listeners(tx) => {
                        let _ = tx.send(swarm.listeners().cloned().collect());
                    }
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    // Admission on the wire: `identify` carries the peer's authenticated secp256k1
                    // public key. Resolve its address, double-check the key hashes to the connection's
                    // PeerId, and admit-or-drop against the authorized set.
                    SwarmEvent::Behaviour(ClusterBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. },
                    )) => {
                        if info.public_key.to_peer_id() != peer_id {
                            // Key does not match the Noise-authenticated PeerId — refuse.
                            let _ = swarm.disconnect_peer_id(peer_id);
                            continue;
                        }
                        let Some(address) = address_from_public_key(&info.public_key) else {
                            let _ = swarm.disconnect_peer_id(peer_id);
                            continue;
                        };
                        let authorized = shared
                            .lock()
                            .map(|s| s.authorized.contains(&address))
                            .unwrap_or(false);
                        if authorized {
                            peer_addr.insert(peer_id, address.clone());
                            if let Ok(mut s) = shared.lock() {
                                s.connected.insert(address);
                            }
                        } else {
                            // Not in the group's allowed set → drop the connection.
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
                        if let Ok(data) = String::from_utf8(message.data) {
                            if let Ok(mut s) = shared.lock() {
                                s.inbox.push(MeshMessage { from: address, data });
                            }
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        if let Some(address) = peer_addr.remove(&peer_id) {
                            if let Ok(mut s) = shared.lock() {
                                s.connected.remove(&address);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
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
