use crate::{ManagerState, NodeIdGenerator, NodeManager, SHARED_KEY_LEN};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;
use std::collections::HashMap;

#[derive(Clone)]
pub struct NodeManagerBuilder {
    key_pair_pkcs8_der: Vec<u8>,
    node_id_generator: NodeIdGenerator,
    shared_key: Option<Vec<u8>>,
}

impl NodeManagerBuilder {
    pub fn new(key_pair_pkcs8_der: &[u8], node_id_generator: NodeIdGenerator) -> Self {
        Self {
            key_pair_pkcs8_der: key_pair_pkcs8_der.to_owned(),
            node_id_generator,
            shared_key: None,
        }
    }
    pub fn shared_key(self, shared_key: Vec<u8>) -> Self {
        Self {
            shared_key: Some(shared_key),
            ..self
        }
    }
    pub fn build(self) -> NodeManager {
        let Self {
            key_pair_pkcs8_der,
            node_id_generator,
            shared_key,
        } = self;
        let key_pair = RsaPrivateKey::from_pkcs8_der(&key_pair_pkcs8_der).unwrap();
        /*let mut key_pair_pkcs8_der = key_pair_pkcs8_der.to_vec();
        let local_key_pair = Keypair::rsa_from_pkcs8(&mut key_pair_pkcs8_der).unwrap();
        let local_peer_id = PeerId::from(local_key_pair.public());
        local_peer_id.to_bytes();*/
        let key_pub = key_pair.to_public_key().to_public_key_der().unwrap();

        let node_id = node_id_generator(key_pub.as_ref()).unwrap();

        let (shared_key, state) = if let Some(k) = shared_key {
            (k, ManagerState::WaitingForKey)
        } else {
            // TODO we need to do more than just wait for MemberOkay
            (Vec::new(), ManagerState::MemberOkay)
        };

        if ![0, SHARED_KEY_LEN].contains(&shared_key.len()) {
            panic!("Invalid length for shared key: {}", shared_key.len());
        }

        NodeManager {
            key_pair,
            node_id_generator,
            shared_key,
            node_id,
            admin_keys: Vec::new(),
            nodes: HashMap::new(),
            state,
            vote_proposal: None,
        }
    }
}
