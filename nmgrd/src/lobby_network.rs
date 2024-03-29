// copy pasted from libp2p-rust-dht's domolibp2p.rs file,
// plus minor modifications

use anyhow::Result;

// Gossip includes
use libp2p::gossipsub::MessageId;
use libp2p::gossipsub::{
    // Gossipsub, GossipsubMessage,
    IdentTopic as Topic,
    MessageAuthenticity,
    ValidationMode,
};
use libp2p::{gossipsub, tcp};

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use libp2p::core::{muxing::StreamMuxerBox, transport, transport::upgrade::Version};

use libp2p::noise;
use libp2p::pnet::{PnetConfig, PreSharedKey};
use libp2p::yamux::Config as YamuxConfig;
//use libp2p::tcp::TcpConfig;
use libp2p::Transport;

use libp2p::{identity, mdns, swarm::NetworkBehaviour, PeerId};

use libp2p::swarm::SwarmBuilder;
use std::time::Duration;

pub const KEY_SIZE: usize = 32;
pub const LOBBY_TOPIC: &str = "node-manager-lobby";

pub type Swarm = libp2p::Swarm<Behaviour>;

pub fn build_transport(
    key_pair: identity::Keypair,
    psk: Option<PreSharedKey>,
) -> transport::Boxed<(PeerId, StreamMuxerBox)> {
    let noise_config = noise::Config::new(&key_pair).unwrap();
    let yamux_config = YamuxConfig::default();

    let base_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let maybe_encrypted = match psk {
        Some(psk) => either::Either::Left(
            base_transport.and_then(move |socket, _| PnetConfig::new(psk).handshake(socket)),
        ),
        None => either::Either::Right(base_transport),
    };
    maybe_encrypted
        .upgrade(Version::V1)
        .authenticate(noise_config)
        .multiplex(yamux_config)
        .timeout(Duration::from_secs(20))
        .boxed()
}

pub async fn start(
    shared_key: [u8; KEY_SIZE],
    local_key_pair: identity::Keypair,
    loopback_only: bool,
) -> Result<Swarm> {
    let topics = [Topic::new(LOBBY_TOPIC)];
    start_with_topics(shared_key, local_key_pair, loopback_only, &topics).await
}

pub async fn start_with_topics(
    shared_key: [u8; KEY_SIZE],
    local_key_pair: identity::Keypair,
    loopback_only: bool,
    topics: &[Topic],
) -> Result<Swarm> {
    let local_peer_id = PeerId::from(local_key_pair.public());

    let psk = Some(PreSharedKey::new(shared_key));

    let transport = build_transport(local_key_pair.clone(), psk);

    // Create a swarm to manage peers and events.
    let mut swarm = {
        let mdnsconf = mdns::Config {
            ttl: Duration::from_secs(600),
            query_interval: Duration::from_secs(580),
            enable_ipv6: false,
        };

        let mdns = mdns::tokio::Behaviour::new(mdnsconf, local_peer_id)?;

        // Do NOT content-address messages, also take the sequence number into account,
        // which is ever increasing.
        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            message.sequence_number.hash(&mut s);
            MessageId::from(s.finish().to_string())
        };

        // Set a custom gossipsub
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .idle_timeout(Duration::from_secs(60 * 60 * 24))
            .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
            .validation_mode(ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
            .message_id_fn(message_id_fn)
            .build()
            .expect("Valid config");

        // build a gossipsub network behaviour
        let mut gossipsub: gossipsub::Behaviour = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(local_key_pair),
            gossipsub_config,
        )
        .expect("Correct configuration");

        // subscribes to the GossipSub topics
        for topic in topics {
            gossipsub.subscribe(topic).unwrap();
        }

        let behaviour = Behaviour { mdns, gossipsub };

        SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id).build()
    };

    if !loopback_only {
        // Listen on all interfaces and whatever port the OS assigns.
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    } else {
        // Listen only on loopack interface
        swarm.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
    }

    Ok(swarm)
}

// We create a custom network behaviour that combines mDNS and gossipsub.
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "OutEvent")]
pub struct Behaviour {
    pub mdns: libp2p::mdns::tokio::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
}

#[derive(Debug)]
pub enum OutEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
}

impl From<mdns::Event> for OutEvent {
    fn from(v: mdns::Event) -> Self {
        Self::Mdns(v)
    }
}

impl From<gossipsub::Event> for OutEvent {
    fn from(v: gossipsub::Event) -> Self {
        Self::Gossipsub(v)
    }
}
