//! V60 S0-NAT-SPIKE: a circuit relay v2 node for the cluster mesh.
//!
//! Two members' machines behind different NATs cannot dial each other. Each one keeps a connection
//! to a relay and holds a reservation there; a peer reaches it through the relay
//! (`<relay>/p2p-circuit/p2p/<peer>`), and the two then try DCUtR hole punching to get a direct
//! connection. The relay forwards bytes only: the end-to-end connection between the members is its
//! own Noise session (with the group prologue), so the relay sees ciphertext.
//!
//! ## Who may use the relay
//!
//! A relay accepts a connection only from a peer on its allow list (`allow_block_list`, checked
//! when the connection is established, before any reservation or circuit request is read). An empty
//! allow list refuses everyone. In this spike the allow list is a fixed set of PeerIds the operator
//! passes in. MESH-3 replaces it with the planset rule: a reservation needs a signed DeviceLink for
//! a group (`relay_refuses_unlinked_device`). Until then this node is for the netns spike and tests
//! only; it is not deployed (production relays on non-producer hosts need an owner go).
//!
//! ## The relay hop uses its own Noise prologue
//!
//! Cluster swarms bind every TCP Noise session to the group (`prologue = group id`, CL-B-009). A
//! relay serves many groups, so it cannot share that prologue. The member side therefore uses
//! [`RELAY_PROLOGUE`] on a TCP connection it DIALS to a configured relay's PeerId, and the group
//! prologue on every other TCP connection (see `libp2p_transport::mesh_tcp_transport`). The relay
//! never dials members, so its inbound side always expects [`RELAY_PROLOGUE`].

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::stream::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{allow_block_list, identify, identity, noise, relay, tcp, yamux};
use libp2p::{Multiaddr, PeerId, Swarm, SwarmBuilder};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::libp2p_transport::{swarm_runtime, TransportError};

/// The Noise prologue on a member's connection to a relay (and on the relay's inbound side).
pub const RELAY_PROLOGUE: &[u8] = b"/citrate/cluster-relay/1";

/// The identify protocol string a relay advertises.
pub const RELAY_IDENTIFY_PROTOCOL: &str = "/citrate/cluster-relay/1.0.0";

/// How long one relayed circuit may stay open before the relay closes it (the members' re-dial
/// opens a new one). The libp2p default is 2 minutes. PENDING OWNER SIGN-OFF.
pub const MAX_CIRCUIT_DURATION: Duration = Duration::from_secs(30 * 60);

/// Most bytes one relayed circuit may carry (each direction counted together). The libp2p default
/// is 128 KiB. The co-pin mesh carries CIDs and gossip control frames only. PENDING OWNER SIGN-OFF.
pub const MAX_CIRCUIT_BYTES: u64 = 4 << 20;

/// Most reservations one relay holds at a time (libp2p default 128).
pub const MAX_RESERVATIONS: usize = 128;

/// Most relayed circuits open at a time (libp2p default 16).
pub const MAX_CIRCUITS: usize = 64;

/// What a relay node counts, for tests and the spike numbers.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RelayStats {
    /// Reservations accepted (renewals included).
    pub reservations_accepted: u64,
    /// Circuits the relay opened between two peers.
    pub circuits_accepted: u64,
    /// Circuit requests refused (no reservation for the target, limits).
    pub circuits_denied: u64,
    /// Peers currently connected to the relay (only allow-listed peers get this far).
    pub connected: BTreeSet<PeerId>,
}

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    /// Refuse every connection from a peer that is not on the allow list.
    allow: allow_block_list::Behaviour<allow_block_list::AllowedPeers>,
    relay: relay::Behaviour,
    identify: identify::Behaviour,
}

enum RelayCmd {
    Listeners(oneshot::Sender<Vec<Multiaddr>>),
}

/// A running relay node. Dropping it stops the relay.
pub struct RelayNode {
    _rt: Arc<Runtime>,
    task: tokio::task::JoinHandle<()>,
    peer_id: PeerId,
    stats: Arc<Mutex<RelayStats>>,
    cmd_tx: mpsc::UnboundedSender<RelayCmd>,
}

impl Drop for RelayNode {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RelayNode {
    /// Start a relay listening on `listen`, accepting connections only from `allowed`.
    pub fn start(
        secret: [u8; 32],
        listen: Multiaddr,
        allowed: &[PeerId],
    ) -> Result<Self, TransportError> {
        let rt = Arc::new(swarm_runtime()?);
        let mut secret_buf = Zeroizing::new(secret);
        let secp_secret = identity::secp256k1::SecretKey::try_from_bytes(&mut *secret_buf)
            .map_err(|e| TransportError::BadSecret(e.to_string()))?;
        let keypair = identity::Keypair::from(identity::secp256k1::Keypair::from(secp_secret));
        let peer_id = keypair.public().to_peer_id();
        let stats = Arc::new(Mutex::new(RelayStats::default()));
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let allowed = allowed.to_vec();
        let stats_task = Arc::clone(&stats);
        let task = rt.block_on(async move {
            let mut swarm = build_relay_swarm(keypair)?;
            for p in allowed {
                swarm.behaviour_mut().allow.allow_peer(p);
            }
            swarm
                .listen_on(listen.clone())
                .map_err(|e| TransportError::Listen {
                    addr: listen.clone(),
                    reason: e.to_string(),
                })?;
            Ok::<_, TransportError>(tokio::spawn(relay_loop(swarm, cmd_rx, stats_task)))
        })?;
        Ok(RelayNode {
            _rt: rt,
            task,
            peer_id,
            stats,
            cmd_tx,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The concrete listen addresses (port 0 resolves asynchronously). Blocks briefly.
    pub fn listeners(&self) -> Result<Vec<Multiaddr>, TransportError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(RelayCmd::Listeners(tx))
            .map_err(|_| TransportError::Closed)?;
        rx.blocking_recv().map_err(|_| TransportError::Closed)
    }

    pub fn stats(&self) -> RelayStats {
        self.stats.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

/// The relay's limits: the libp2p defaults except the ones named above.
fn relay_config() -> relay::Config {
    relay::Config {
        max_reservations: MAX_RESERVATIONS,
        max_circuits: MAX_CIRCUITS,
        max_circuit_duration: MAX_CIRCUIT_DURATION,
        max_circuit_bytes: MAX_CIRCUIT_BYTES,
        ..relay::Config::default()
    }
}

fn build_relay_swarm(keypair: identity::Keypair) -> Result<Swarm<RelayBehaviour>, TransportError> {
    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            |k: &identity::Keypair| {
                noise::Config::new(k).map(|c| c.with_prologue(RELAY_PROLOGUE.to_vec()))
            },
            yamux::Config::default,
        )
        .map_err(|e| TransportError::Build(format!("tcp: {e}")))?
        .with_behaviour(|key| RelayBehaviour {
            allow: allow_block_list::Behaviour::default(),
            relay: relay::Behaviour::new(key.public().to_peer_id(), relay_config()),
            identify: identify::Behaviour::new(identify::Config::new(
                RELAY_IDENTIFY_PROTOCOL.into(),
                key.public(),
            )),
        })
        .map_err(|e| TransportError::Build(format!("behaviour: {e}")))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();
    Ok(swarm)
}

async fn relay_loop(
    mut swarm: Swarm<RelayBehaviour>,
    mut cmd_rx: mpsc::UnboundedReceiver<RelayCmd>,
    stats: Arc<Mutex<RelayStats>>,
) {
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { return; };
                match cmd {
                    RelayCmd::Listeners(tx) => {
                        let _ = tx.send(swarm.listeners().cloned().collect());
                    }
                }
            }
            event = swarm.select_next_some() => {
                // A relay must name at least one address of its own in every reservation (the
                // client refuses a reservation without one), so each listen address the relay
                // binds is confirmed as external. The spike relay is reached on those addresses
                // directly; a relay behind its own NAT is not supported.
                if let SwarmEvent::NewListenAddr { address, .. } = &event {
                    swarm.add_external_address(address.clone());
                    continue;
                }
                let Ok(mut s) = stats.lock() else { continue };
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        s.connected.insert(peer_id);
                    }
                    SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => {
                        s.connected.remove(&peer_id);
                    }
                    SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(e)) => match e {
                        relay::Event::ReservationReqAccepted { .. } => s.reservations_accepted += 1,
                        relay::Event::CircuitReqAccepted { .. } => s.circuits_accepted += 1,
                        relay::Event::CircuitReqDenied { .. } => s.circuits_denied += 1,
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }
}
