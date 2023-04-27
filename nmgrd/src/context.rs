use crate::config::Config;
use crate::lobby_network::{Swarm, LOBBY_TOPIC};
use crate::ws_api::AsyncWebSocketDomoMessage;
use crate::ws_context::WsContext;
use anyhow::Error;
use base64ct::{Base64, Encoding};
use libp2p::futures::StreamExt;
use libp2p::gossipsub::IdentTopic as Topic;
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, mdns};
use node_manager::keys::priv_key_pem_to_der;
use node_manager::keys::PublicKey;
use node_manager::{NodeManager, NodeManagerBuilder, Response};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const MEMBERS_TOPIC: &str = "node-manager-members";

pub struct Context {
    cfg: Config,
    cfg_path: String,
    topic: Topic,
    swarm: Swarm,
    ws_conn: WsContext,
    node: NodeManager,
}

impl Context {
    pub async fn start(cfg: Config, cfg_path: &str) -> Result<Self, Error> {
        fn id_gen_fn(data: &[u8]) -> Result<Vec<u8>, ()> {
            let mut hasher = Sha256::new();
            hasher.update(data);
            let bytes = hasher.finalize()[..8].to_vec();
            Ok(bytes)
        }

        let key_pem = cfg.priv_key()?;
        let key_der = priv_key_pem_to_der(&key_pem);
        let mut builder = NodeManagerBuilder::new(&key_der, id_gen_fn);

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

        Ok(Self {
            cfg,
            cfg_path,
            swarm,
            topic,
            ws_conn,
            node,
        })
    }
    pub async fn run_loop_iter(&mut self) -> Result<(), Error> {
        tokio::select!(
            ws_msg = self.ws_conn.select_next_some() => {
                let ws_msg = ws_msg?;
                match ws_msg {
                    WsMessage::Text(json_msg) => match serde_json::from_str(&json_msg) {
                            Ok(msg) => {
                                let msg: AsyncWebSocketDomoMessage = msg;
                                match msg {
                                    AsyncWebSocketDomoMessage::Volatile { value } => {
                                        if value.get("topic").and_then(|topic| topic.as_str()) == Some(MEMBERS_TOPIC) {
                                            if let Some(content) = value.get("content").and_then(|v| v.as_str()) {
                                                if let Ok(msg) = Base64::decode_vec(content) {
                                                    self.handle_members_msg(&msg).await?;
                                                }
                                            }
                                        }
                                    }
                                    // We don't care about persistent messages
                                    AsyncWebSocketDomoMessage::Persistent { .. } => (),
                                }
                            },
                            Err(_err) => {
                                log::warn!("Received json message of invalid format: '{json_msg}'");
                            },
                    }
                    WsMessage::Close(_) => {
                        log::info!("Web socket connection closed, trying to connect again...");
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
                    log::info!("Address {address:?} expired");
                }
                SwarmEvent::ConnectionEstablished {..} => {
                        log::info!("Connection established ...");
                }
                SwarmEvent::ConnectionClosed { .. } => {
                    log::info!("Connection closed");
                }
                SwarmEvent::ListenerError { .. } => {
                    log::info!("Listener Error");
                }
                SwarmEvent::OutgoingConnectionError { .. } => {
                    log::info!("Outgoing connection error");
                }
                SwarmEvent::ListenerClosed { .. } => {
                    log::info!("Listener Closed");
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening in {address:?}");
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
                        log::info!("Not able to recognize message on topic {topic}");
                    }
                }
                SwarmEvent::Behaviour(crate::lobby_network::OutEvent::Mdns(
                    mdns::Event::Expired(list),
                )) => {
                    let local = OffsetDateTime::now_utc();

                    for (peer, _) in list {
                        log::info!("MDNS for peer {peer} expired {local:?}");
                    }
                }
                SwarmEvent::Behaviour(crate::lobby_network::OutEvent::Mdns(
                    mdns::Event::Discovered(list),
                )) => {
                    let local = OffsetDateTime::now_utc();
                    for (peer, _) in list {
                        self.swarm
                            .behaviour_mut()
                            .gossipsub
                            .add_explicit_peer(&peer);
                        log::info!("Discovered peer {peer} {local:?}");
                    }

                }
                _ => {}
                }
            }
        );
        Ok(())
    }
    pub async fn broadcast_admin_join_msg(&mut self) -> Result<(), Error> {
        let admin_join_msg = self.cfg.admin_join_msg()?;
        let msg = Base64::decode_vec(&admin_join_msg)?;
        // TODO do some validation on the message
        self.broadcast_lobby_msg(&msg)
    }
    fn broadcast_lobby_msg(&mut self, msg: &[u8]) -> Result<(), Error> {
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
        let msg_b64 = Base64::encode_string(msg);
        let msg_json = serde_json::json!({
            "topic": MEMBERS_TOPIC,
            "content": msg_b64,
        });
        // The conversion here is not supposed to error:
        let msg_json_str = serde_json::to_string(&msg_json)?;
        self.ws_conn.send(WsMessage::Text(msg_json_str)).await?;
        todo!()
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
                        self.broadcast_lobby_msg(&msg)?;
                    } else {
                        self.broadcast_members_msg(&msg).await?;
                    }
                }
                Response::SetSharedKey(key) => self.handle_rekeying(key).await?,
            }
        }
        Ok(())
    }
    async fn handle_rekeying(&self, key: &[u8]) -> Result<(), Error> {
        crate::config::set_new_key_for_file(&self.cfg_path, key)?;
        Ok(())
    }
}
