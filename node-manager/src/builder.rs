use crate::keys::PrivateKey;
use crate::{
    ManagerState, NodeEntry, NodeId, NodeIdGenerator, NodeManager, NodeStatus, Thresholds,
    SHARED_KEY_LEN,
};
use std::collections::HashMap;

#[derive(Clone)]
pub struct NodeManagerBuilder {
    key_pair_pkcs8_der: Vec<u8>,
    node_id_generator: NodeIdGenerator,
    shared_key: Option<Vec<u8>>,
    thresholds: Thresholds,
    self_should_auto_pause: bool,
    sometimes_vote_wrongly: bool,
}

impl NodeManagerBuilder {
    pub fn new(key_pair_pkcs8_der: &[u8], node_id_generator: NodeIdGenerator) -> Self {
        Self {
            key_pair_pkcs8_der: key_pair_pkcs8_der.to_owned(),
            node_id_generator,
            shared_key: None,
            thresholds: Thresholds::new(),
            self_should_auto_pause: true,
            sometimes_vote_wrongly: false,
        }
    }
    pub fn shared_key(self, shared_key: Vec<u8>) -> Self {
        Self {
            shared_key: Some(shared_key),
            ..self
        }
    }
    pub fn thresholds(self, thresholds: Thresholds) -> Self {
        Self { thresholds, ..self }
    }
    pub fn self_should_auto_pause(self, self_should_auto_pause: bool) -> Self {
        Self {
            self_should_auto_pause,
            ..self
        }
    }
    pub fn build(self) -> NodeManager {
        let Self {
            key_pair_pkcs8_der,
            node_id_generator,
            shared_key,
            thresholds,
            self_should_auto_pause,
            sometimes_vote_wrongly,
        } = self;
        let key_pair = PrivateKey::from_pkcs8_der(&key_pair_pkcs8_der).unwrap();
        let public_key_der = key_pair.to_public_key().to_public_key_der().unwrap();
        let sometimes_wrongly_vote_counter = sometimes_vote_wrongly.then_some(0);

        let node_id = node_id_generator(&public_key_der).unwrap();

        let mut nodes = HashMap::new();

        nodes.insert(
            NodeId::from_data(&node_id),
            NodeEntry {
                public_key: key_pair.to_public_key(),
                public_key_der,
                // If a shared key is specified, this will be set later by set_init_random_shared_key
                status: NodeStatus::WaitingEntry,
                last_seen_time: super::ts(),
                trust: Default::default(),
            },
        );

        let mut res = NodeManager {
            key_pair,
            node_id_generator,
            shared_key: Vec::new(),
            node_id,
            admin_keys: Vec::new(),
            nodes,
            // If a shared key is specified, this will be set later by set_init_random_shared_key
            state: ManagerState::WaitingForKey,
            vote_proposal: None,
            vote_suggestions: HashMap::new(),
            thresholds,
            self_should_auto_pause,
            sometimes_wrongly_vote_counter,
        };

        if let Some(k) = shared_key {
            if SHARED_KEY_LEN != k.len() {
                panic!("Invalid length for shared key: {}", k.len());
            }
            res.set_init_random_shared_key(k);
        }

        res
    }
}
