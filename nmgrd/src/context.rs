use crate::config::Config;
use crate::lobby_network::{Swarm, LOBBY_TOPIC};
use crate::ws_api::AsyncWebSocketDomoMessage;
use crate::ws_api::SyncWebSocketDomoRequest;
use crate::ws_context::WsContext;
use anyhow::Error;
use base64ct::{Base64, Encoding};
use core::fmt::Display;
use libp2p::futures::StreamExt;
use libp2p::gossipsub::IdentTopic as Topic;
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, mdns};
use node_manager::keys::priv_key_pem_to_der;
use node_manager::keys::PublicKey;
use node_manager::{timestamp, NodeManager, NodeManagerBuilder, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tokio::time::{Interval, MissedTickBehavior};
use tokio_tungstenite::tungstenite::Message as WsMessage;

const MEMBERS_TOPIC: &str = "SIFIS:node-manager-members";
const VOTE_SUGGESTION_TOPIC: &str = "SIFIS:node-manager-kick-vote-sugg";

pub struct Context {
    cfg: Config,
    #[allow(unused)]
    cfg_path: String,
    topic: Topic,
    swarm: Swarm,
    ws_conn: WsContext,
    pub(crate) node: NodeManager,
    make_member_interval: Interval,
    keepalive_interval: Interval,
    vote_interval: Interval,
    start_time: Instant,
    never_had_key: bool,
    wait_until_set_own: Duration,
}

impl Context {
    pub async fn start(cfg: Config, cfg_path: &str) -> Result<Self, Error> {
        fn id_gen_fn(data: &[u8]) -> Result<Vec<u8>, ()> {
            let mut hasher = Sha256::new();
            hasher.update(data);
            let bytes = hasher.finalize().to_vec();
            assert_eq!(bytes.len(), 32);
            Ok(bytes)
        }

        let key_pem = cfg.priv_key()?;
        let key_der = priv_key_pem_to_der(&key_pem);
        let mut builder = NodeManagerBuilder::new(&key_der, id_gen_fn);

        builder = builder.self_should_auto_pause(!cfg.no_self_auto_pause());

        if let Some(key) = cfg.shared_key() {
            builder = builder.shared_key(key.to_vec());
        }

        let mut node = builder.build();

        let admin_key_pem = cfg.admin_key()?;
        let admin_key = PublicKey::from_public_key_pem(&admin_key_pem)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        node.add_admin_key(admin_key)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;

        let ws_conn = crate::ws_context::WsContext::new(cfg.dht_url()).await?;

        // TODO use key_der here instead of generating the key on the fly
        let key_pair = identity::Keypair::generate_ed25519();

        let swarm =
            crate::lobby_network::start(cfg.lobby_key(), key_pair, cfg.lobby_loopback_only())
                .await
                .map_err(|err| anyhow::anyhow!("{:?}", err))?;

        let topic = Topic::new(LOBBY_TOPIC);

        let cfg_path = cfg_path.to_string();

        let mut make_member_interval = tokio::time::interval(Duration::from_millis(2000));
        make_member_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        const KEEPALIVE_TIMER_INTERVAL: u64 = 1157;
        let mut keepalive_interval =
            tokio::time::interval(Duration::from_millis(KEEPALIVE_TIMER_INTERVAL));
        keepalive_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        const VOTE_TIMER_INTERVAL: u64 = 1060;
        let mut vote_interval = tokio::time::interval(Duration::from_millis(VOTE_TIMER_INTERVAL));
        vote_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let start_time = Instant::now();
        let never_had_key = node.shared_key().is_empty();

        // This is a random value that we set between 10 seconds and 25 seconds.
        let rand_add = rand::random::<f64>() * 15_000.0;
        let wait_until_set_own = Duration::from_millis(10_000 + rand_add as u64);

        let mut this = Self {
            cfg,
            cfg_path,
            swarm,
            topic,
            ws_conn,
            node,
            make_member_interval,
            keepalive_interval,
            vote_interval,
            start_time,
            never_had_key,
            wait_until_set_own,
        };

        this.send_ws_msg(SyncWebSocketDomoRequest::RequestGetTopicName {
            topic_name: VOTE_SUGGESTION_TOPIC.to_string(),
        })
        .await?;

        // Set the key for the DHT, for the case the config file is desynchronized
        this.handle_rekeying(None).await?;

        Ok(this)
    }
    pub async fn run_loop_iter(&mut self) -> Result<(), Error> {
        tokio::select!(
            _ = self.make_member_interval.tick() => {
                let has_key = !self.node.shared_key().is_empty();
                let conn_present = self.ws_conn.conn_present();
                if has_key {
                    self.never_had_key = false;
                }
                if !has_key && conn_present && (self.never_had_key || (self.cfg.try_rejoin_on_pause() && self.should_send_keepalive()?)) {
                    let peers_count = self.swarm.behaviour().gossipsub.all_peers().count();
                    if peers_count > 0 {
                        log::info!("Broadcasting admin join message to {} peers", peers_count);
                        self.broadcast_admin_join_msg().await?;
                    }
                    let since_start = Instant::now() - self.start_time;
                    if since_start > self.wait_until_set_own && !self.cfg.no_auto_first_node() && self.never_had_key {
                        // Assume that we are the first node and generate our own shared key
                        log::info!("Didn't get any responses on lobby network. Setting shared key to a random one, assuming we are the first node.");
                        self.node.set_random_shared_key();
                        self.handle_rekeying(None).await?;
                    }
                }
            }
            _ = self.keepalive_interval.tick() => {
                if !self.node.shared_key().is_empty() && self.should_send_keepalive()? {
                    let resp = self.node.make_keepalive(timestamp()?)?;
                    self.handle_responses(&resp).await?;

                    let should_be_first = (rand::random::<f64>() < 0.05) as u64 * 10_000;
                    let resp = self.node.check_timeouts(timestamp()?, should_be_first)?;
                    self.handle_responses(&resp).await?;
                }
            }
            _ = self.vote_interval.tick() => {
                if !self.node.shared_key().is_empty() {
                    let resp = self.node.check_finish_votes(timestamp()?)?;
                    self.handle_responses(&resp).await?;
                }
            }
            ws_msg = self.ws_conn.select_next_some() => {
                let ws_msg = ws_msg?;
                match ws_msg {
                    WsMessage::Text(json_msg) => {
                        if let Ok(msg) = serde_json::from_str(&json_msg) {
                            self.handle_ws_json_msg(msg).await?;
                        } else if let Ok(msg) = serde_json::from_str(&json_msg) {
                            self.handle_ws_sync_response(msg).await?;
                        } else {
                            log::warn!("Web socket received json message of invalid format: '{json_msg}'");
                        }
                    }
                    WsMessage::Close(_) => {
                        log::info!("Web socket connection closed, trying to connect again...");
                        // Reconnection handled by ws_conn
                    }
                    WsMessage::Frame(_) => panic!("Received raw ws frame which was supposed to be handled by tungstenite"),
                    WsMessage::Binary(_) | WsMessage::Ping(_) | WsMessage::Pong(_) => {
                        // We got an unexpected ws message kind
                        log::warn!("Received unexpected ws message kind");
                    }
                }
            }
            event = self.swarm.select_next_some() => {
            match event {
                SwarmEvent::ExpiredListenAddr { address, .. } => {
                    log::info!("Lobby: Address {address:?} expired");
                }
                SwarmEvent::ConnectionEstablished {..} => {
                    log::info!("Lobby: Connection with swarm member established");
                }
                SwarmEvent::ConnectionClosed { .. } => {
                    log::info!("Lobby: Connection with swarm member closed");
                }
                SwarmEvent::ListenerError { .. } => {
                    log::info!("Lobby: Listener Error");
                }
                SwarmEvent::OutgoingConnectionError { peer_id, ..} => {
                    log::info!("Lobby: Outgoing connection error{}", if let Some(p) = peer_id { format!(" for ID {p}") } else { String::new() });
                }
                SwarmEvent::ListenerClosed { .. } => {
                    log::info!("Lobby: Listener Closed");
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Lobby: Listening on {address:?} with ID {}", self.swarm.local_peer_id());
                }
                SwarmEvent::Behaviour(crate::lobby_network::OutEvent::Gossipsub(
                    libp2p::gossipsub::Event::Message {
                        propagation_source: _peer_id,
                        message_id: _id,
                        message,
                    },
                )) => match message.topic.to_string().as_str() {
                    LOBBY_TOPIC => {
                        return self.handle_lobby_msg(&message.data).await;
                    }
                    topic => {
                        log::info!("Lobby: Not able to recognize message on topic {topic}");
                    }
                }
                SwarmEvent::Behaviour(crate::lobby_network::OutEvent::Mdns(
                    mdns::Event::Expired(list),
                )) => {
                    // Deduplicate the peers by going through a HashSet
                    let peers = list.map(|(peer, _)| peer)
                        .collect::<HashSet<_>>();
                    for peer in peers {
                        log::info!("Lobby: MDNS for peer {peer} expired");
                    }
                }
                SwarmEvent::Behaviour(crate::lobby_network::OutEvent::Mdns(
                    mdns::Event::Discovered(list),
                )) => {
                    // Deduplicate the peers by going through a HashSet
                    let peers = list.map(|(peer, _)| peer)
                        .collect::<HashSet<_>>();
                    for peer in peers {
                        self.swarm
                            .behaviour_mut()
                            .gossipsub
                            .add_explicit_peer(&peer);
                        log::info!("Lobby: Discovered peer {peer}");
                    }
                }
                _ => {}
                }
            }
        );
        Ok(())
    }
    async fn handle_ws_json_msg(&mut self, msg: AsyncWebSocketDomoMessage) -> Result<(), Error> {
        match msg {
            AsyncWebSocketDomoMessage::Volatile { value } => {
                let topic_opt = value.get("topic").and_then(|topic| topic.as_str());
                if topic_opt == Some(MEMBERS_TOPIC) {
                    if let Some(content) = value.get("content").and_then(|v| v.as_str()) {
                        if let Ok(msg) = Base64::decode_vec(content) {
                            self.handle_members_msg(&msg).await?;
                        }
                    }
                }
            }
            AsyncWebSocketDomoMessage::Persistent {
                topic_name,
                topic_uuid,
                value,
                deleted,
            } => {
                if topic_name != VOTE_SUGGESTION_TOPIC {
                    return Ok(());
                }
                let Some(topic_key) = VoteSuggKey::parse(&topic_uuid) else {
                    log::warn!("Failed to parse vote suggestion: Can't parse UUID '{topic_uuid}'");
                    return Ok(());
                };
                if topic_key.caster_id != self.node.node_id() {
                    // We aren't really interested in suggestions for other nodes
                    return Ok(());
                }
                let Some(should_kick) = value.get("kick").and_then(|v| v.as_bool()) else {
                    log::warn!("Failed to parse vote suggestion: No 'kick' bool payload");
                    return Ok(());
                };
                log::info!("saving vote suggestion for subject {}, should_kick={should_kick}, deleted={deleted}", fmt_hex_arr(&topic_key.subject));
                self.node
                    .save_vote_suggestion(&topic_key.subject, should_kick, deleted)?;
            }
        }
        Ok(())
    }
    async fn handle_ws_sync_response(
        &mut self,
        req: SyncWebSocketDomoRequest,
    ) -> Result<(), Error> {
        match req {
            SyncWebSocketDomoRequest::Response { value } => {
                let Some(arr) = value.as_array() else {
                    log::warn!("Received invalid sync ws response from DHT");
                    return Ok(());
                };
                #[derive(Deserialize)]
                struct TopicEntry {
                    topic_name: String,
                    topic_uuid: String,
                    value: serde_json::Value,
                }
                for val in arr.iter() {
                    let Ok(entry) = TopicEntry::deserialize(val) else {
                        log::warn!("Received invalid value in sync ws response from DHT: {val}");
                        return Ok(());
                    };
                    if entry.topic_name != VOTE_SUGGESTION_TOPIC {
                        log::info!(
                            "Ignoring ws response for topic we didn't request: {}",
                            entry.topic_name
                        );
                        return Ok(());
                    }
                    let Some(topic_key) = VoteSuggKey::parse(&entry.topic_uuid) else {
                        log::warn!("Failed to parse vote suggestion: Can't parse UUID '{}'", entry.topic_uuid);
                        return Ok(());
                    };
                    let Some(should_kick) = entry.value.get("kick").and_then(|v| v.as_bool()) else {
                        log::warn!("Failed to parse vote suggestion: No 'kick' bool payload");
                        return Ok(());
                    };
                    let deleted = false;
                    log::info!("saving initial vote suggestion for subject {}, should_kick={should_kick}, deleted={deleted}", fmt_hex_arr(&topic_key.subject));
                    self.node
                        .save_vote_suggestion(&topic_key.subject, should_kick, deleted)?;
                }
            }
            _ => {
                log::warn!("Received invalid sync ws msg from DHT");
            }
        }
        Ok(())
    }
    pub async fn broadcast_admin_join_msg(&mut self) -> Result<(), Error> {
        let admin_join_msg = self.cfg.admin_join_msg()?;
        let msg = Base64::decode_vec(&admin_join_msg)?;
        // TODO do some validation on the message
        self.broadcast_lobby_msg(&msg)
    }
    fn broadcast_lobby_msg(&mut self, msg: &[u8]) -> Result<(), Error> {
        log::debug!("Broadcasting lobby message...");
        if let Err(err) = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topic.hash(), msg)
        {
            log::warn!("Error during sending of lobby message: {err}");
        }
        Ok(())
    }
    async fn broadcast_members_msg(&mut self, msg: &[u8]) -> Result<(), Error> {
        log::debug!("Broadcasting members message...");
        let msg_b64 = Base64::encode_string(msg);
        let msg_json = serde_json::json!({
            "topic": MEMBERS_TOPIC,
            "content": msg_b64,
        });
        self.send_ws_msg(SyncWebSocketDomoRequest::RequestPubMessage { value: msg_json })
            .await?;
        Ok(())
    }
    async fn send_ws_msg(&mut self, msg: SyncWebSocketDomoRequest) -> Result<(), Error> {
        // The conversion here is not supposed to error:
        let msg_json_str = serde_json::to_string(&msg)?;
        self.ws_conn.send(WsMessage::Text(msg_json_str)).await?;
        Ok(())
    }
    async fn handle_lobby_msg(&mut self, msg: &[u8]) -> Result<(), Error> {
        let from_members_network = false;
        let resps = self
            .node
            .handle_msg(msg, from_members_network)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        self.handle_responses(&resps).await
    }
    async fn handle_members_msg(&mut self, msg: &[u8]) -> Result<(), Error> {
        let from_members_network = true;
        let resps = self
            .node
            .handle_msg(msg, from_members_network)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        self.handle_responses(&resps).await
    }
    async fn handle_responses(&mut self, resps: &[Response]) -> Result<(), Error> {
        for resp in resps.iter() {
            match resp {
                Response::Message(msg, from_members_network) => {
                    let msg = msg.serialize();
                    if *from_members_network {
                        self.broadcast_members_msg(&msg).await?;
                    } else {
                        self.broadcast_lobby_msg(&msg)?;
                    }
                }
                Response::SetSharedKey(key) => self.handle_rekeying(Some(key)).await?,
            }
        }
        Ok(())
    }

    pub async fn self_pause(&mut self) -> Result<(), Error> {
        let msg_self_pause = self
            .node
            .self_pause(timestamp().map_err(|err| anyhow::anyhow!("{:?}", err))?)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        self.handle_responses(&msg_self_pause).await?;
        // Set an empty key to indicate that we have left.
        // But do this only after a delay to make sure we got the earlier message out on the DHT.
        // Ideally we'd wait for the confirmation by the DHT that it got sent or such... but
        // there is no such mechanism so we just delay by a constant amount of time instead.
        sleep(Duration::from_millis(500)).await;
        self.handle_rekeying(Some(&[])).await?;
        Ok(())
    }
    pub async fn self_rejoin(&mut self) -> Result<(), Error> {
        let msg_self_rejoin = self
            .node
            .self_rejoin(timestamp().map_err(|err| anyhow::anyhow!("{:?}", err))?)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        self.handle_responses(&msg_self_rejoin).await?;
        Ok(())
    }
    pub async fn start_vote(&mut self, id: &[u8]) -> Result<(), Error> {
        let ts = timestamp().map_err(|err| anyhow::anyhow!("{:?}", err))?;
        let msgs_vote = self
            .node
            .start_vote(ts, id)
            .map_err(|err| anyhow::anyhow!("{:?}", err))?;
        self.handle_responses(&msgs_vote).await?;
        Ok(())
    }

    async fn handle_rekeying(&self, key_override: Option<&[u8]>) -> Result<(), Error> {
        let key = key_override.unwrap_or(self.node.shared_key());
        let key = if key.is_empty() {
            // The reloader isn't handling empty keys well, as they cause crashes of the DHT.
            // Instead, specify a hardcoded key. This isn't optimal but a good preliminary solution.
            &[42; 32]
        } else {
            key
        };
        let paths = self.cfg.rekeying_cfg_paths();
        log::info!("Rekeying: writing new shared key to {} files", paths.len());
        for path in paths {
            crate::config::set_new_key_for_path(path, key)?;
        }
        Ok(())
    }
    pub fn lobby_local_peer_id_display(&self) -> impl Display + '_ {
        self.swarm.local_peer_id()
    }

    pub fn lobby_peer_table_str(&self) -> String {
        let mut ret = self
            .swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .map(|(peer_id, _topics_subscribed)| format!("{peer_id} ; "))
            .collect::<String>();
        if !ret.is_empty() {
            ret.pop();
            ret.pop();
            ret.pop();
        }
        ret
    }
    pub fn connected_to_dht(&self) -> bool {
        self.ws_conn.conn_present()
    }
    fn should_send_keepalive(&self) -> Result<bool, Error> {
        if !self.cfg.debug_sometimes_send_keepalive {
            // We are always sending keepalives
            return Ok(true);
        }
        let ts = timestamp()?;
        // The interval length, of both the interval in which we should send a
        // keepalive, and in which we shouldn't.
        const INTERVAL_MS: u64 = 30 * 1000;
        let should_send = (ts / INTERVAL_MS) % 2 == 0;
        Ok(should_send)
    }
}

pub(crate) fn fmt_hex_arr(arr: &[u8]) -> String {
    arr.iter().map(|v| format!("{v:02x}")).collect()
}

struct VoteSuggKey {
    caster_id: Vec<u8>,
    subject: Vec<u8>,
}

impl VoteSuggKey {
    /// Parses a key in the form `<node-caster>:<casted-upon>`
    fn parse(key: &str) -> Option<Self> {
        let mut it = key.split(':');
        let caster_str = it.next()?;
        let subject_str = it.next()?;
        let caster_id = parse_hex(caster_str)?;
        let subject = parse_hex(subject_str)?;
        Some(VoteSuggKey { caster_id, subject })
    }
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let mut res = Vec::new();
    for byte_hex in s.as_bytes().chunks(2) {
        let hex_digit = |byte| {
            Some(match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => return None,
            })
        };
        if let (Some(hi), Some(lo)) = (hex_digit(byte_hex[0]), hex_digit(byte_hex[1])) {
            res.push((hi << 4) | lo);
        } else {
            return None;
        }
    }
    Some(res)
}
