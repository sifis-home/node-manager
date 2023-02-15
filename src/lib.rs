#![allow(dead_code, unused_variables)]

pub use crate::node_table::{NodeEntry, NodeStatus};
use rsa::padding::PaddingScheme;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::rand_core::OsRng;
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{hash_map::Entry, HashMap};
use std::error::Error;

pub mod admin;
mod node_table;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum VoteOperation {
    /// Remove a specified node
    ///
    /// Data: (node id)
    Remove(Vec<u8>),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct VoteProposal {
    pub timestamp: u64,
    pub state_hash: Vec<u8>,
    pub initiator_id: Vec<u8>,
    pub operation: VoteOperation,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum Response {
    /// Sets the shared key to the specified key
    SetSharedKey(Vec<u8>),
    /// Broadcast a message
    ///
    /// The bool is true if the message is for the members network
    Message(Message, bool),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum Descision {
    Yes,
    No,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum Operation {
    // ------------------------------------
    // Operations for the lobby network:
    // ------------------------------------
    /// The admin key adds a specific node to the network
    ///
    /// Data: (node id)
    AddByAdmin(Vec<u8>),
    /// The node requests itself to be added on the network
    SelfRejoin,
    /// The encapsulated shared key, encrypted for member with the specified node id.
    ///
    /// Data: (key, node id)
    EncapsulatedKey(Vec<u8>, Vec<u8>),

    // ------------------------------------
    // Operations for the members network:
    // ------------------------------------
    /// A proposal for a vote
    VoteProposal(VoteProposal),
    /// Participation in a vote proposal
    Vote(Vec<u8>, Descision),
    /// The encapsulated shared keys, encrypted for each member
    ///
    /// Data: list of (member node id, encrypted shared key) tuples
    EncapsulatedKeys(Vec<(Vec<u8>, Vec<u8>)>),
    /// The node wants to leave the network temporarily
    SelfPause,
    /// The node wants to leave the network permanently
    SelfRemove,
    /// The node signals that it is still around
    ///
    /// Data: (node table hash)
    KeepAlive(Vec<u8>),
}

impl Operation {
    fn can_be_sent_to_lobby_or_members(&self) -> (bool, bool) {
        use Operation::*;
        match self {
            AddByAdmin(..) | SelfRejoin | EncapsulatedKey(..) => (true, false),
            VoteProposal(..) | EncapsulatedKeys(..) | Vote(..) | SelfPause | SelfRemove
            | KeepAlive(..) => (false, true),
        }
    }
    fn digest(&self) -> Vec<u8> {
        let data = bincode::serialize(self).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    pub fn sign(
        self,
        timestamp: u64,
        signer_key: &RsaPrivateKey,
    ) -> Result<Message, Box<dyn Error>> {
        let mut msg = Message {
            timestamp,
            signer_id: vec![], // TODO
            signature: Vec::new(),
            operation: self,
        };
        let msg_digest = msg.digest();
        msg.signature = signer_key.sign(padding_scheme_sign(), &msg_digest)?;
        Ok(msg)
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Message {
    pub timestamp: u64,
    pub signer_id: Vec<u8>,
    pub signature: Vec<u8>,
    pub operation: Operation,
}

impl Message {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
    /// Checks if the signature of the message is valid
    pub fn signature_is_valid(&self, key: &RsaPublicKey) -> bool {
        let digest = self.digest();
        self.digest_is_valid(&digest, key)
    }
    /// Checks if the signature is valid for the given digest
    ///
    /// The digest mut fit to the message! Use [`Self::signature_is_valid`]
    pub(crate) fn digest_is_valid(&self, digest: &[u8], key: &RsaPublicKey) -> bool {
        if key
            .verify(padding_scheme_sign(), &digest, &self.signature)
            .is_err()
        {
            return false;
        }
        true
    }
    fn digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"Message");
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update((self.signer_id.len() as u64).to_be_bytes());
        hasher.update(&self.signer_id);
        hasher.update(self.operation.digest());
        hasher.finalize().to_vec()
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(Vec<u8>);

impl NodeId {
    pub fn from_data(data: &[u8]) -> Self {
        Self(data.to_vec())
    }
    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

/// A function that converts a DER encoded RSA key into a NodeId
pub type NodeIdGenerator = fn(&[u8]) -> Result<Vec<u8>, ()>;

fn padding_scheme_sign() -> PaddingScheme {
    PaddingScheme::PSS {
        digest: Box::new(sha2::Sha256::new()),
        salt_rng: Box::new(OsRng),
        salt_len: Some(16),
    }
}

fn padding_scheme_encrypt() -> PaddingScheme {
    PaddingScheme::OAEP {
        digest: Box::new(sha2::Sha256::new()),
        mgf_digest: Box::new(sha2::Sha256::new()),
        label: Some(String::new()),
    }
}

/// Returns the current time in miliseconds since the unix epoch
fn timestamp() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

#[derive(PartialEq, Eq, Debug)]
enum ManagerState {
    WaitingForKey,
    MemberOkay,
    WaitingForRekeying,
}

/// Maximum age for a message in order for the NodeManager to respond to it
const MAX_MSG_AGE: u64 = 1_000;

const SHARED_KEY_LEN: usize = 32;

pub struct NodeManager {
    key_pair: RsaPrivateKey,
    node_id_generator: NodeIdGenerator,
    /// Shared key of the members network
    shared_key: Vec<u8>,
    node_id: Vec<u8>,
    /// List of admin keys, given as tuples of `(<DER formatted key>, RsaPublicKey)`
    admin_keys: Vec<(Vec<u8>, RsaPublicKey)>,
    nodes: HashMap<NodeId, NodeEntry>,
    // TODO: field storing possibly outstanding vote ID+initialization,
    //       possible "waiting for EncapsulatedKey msg" state,
    //       possible "waiting for EncapsulatedKeys msg" state ...
    // Whether we are waiting for some specific message
    state: ManagerState,
    // TODO: table storing voting proposal cooldowns for nodes
}

impl NodeManager {
    pub fn new_with_shared_key(
        key_pair_pkcs8_der: &[u8],
        node_id_generator: NodeIdGenerator,
        shared_key: Option<Vec<u8>>,
    ) -> Self {
        let key_pair = RsaPrivateKey::from_pkcs8_der(key_pair_pkcs8_der).unwrap();
        /*let mut key_pair_pkcs8_der = key_pair_pkcs8_der.to_vec();
        let local_key_pair = Keypair::rsa_from_pkcs8(&mut key_pair_pkcs8_der).unwrap();
        let local_peer_id = PeerId::from(local_key_pair.public());
        local_peer_id.to_bytes();*/
        let node_id = node_id_generator(key_pair_pkcs8_der).unwrap();

        let (shared_key, state) = if let Some(k) = shared_key {
            (k, ManagerState::WaitingForKey)
        } else {
            // TODO we need to do more than just wait for MemberOkay
            (Vec::new(), ManagerState::MemberOkay)
        };

        if ![0, SHARED_KEY_LEN].contains(&shared_key.len()) {
            panic!("Invalid length for shared key: {}", shared_key.len());
        }

        Self {
            key_pair,
            node_id_generator,
            shared_key,
            node_id,
            admin_keys: Vec::new(),
            nodes: HashMap::new(),
            state,
        }
    }
    pub fn new(key_pair_pkcs8_der: &[u8], node_id_generator: NodeIdGenerator) -> Self {
        Self::new_with_shared_key(key_pair_pkcs8_der, node_id_generator, None)
    }
    fn table_hash(&self) -> Vec<u8> {
        let adm_hash = {
            let mut adm_hasher = Sha256::new();
            adm_hasher.update(b"AdminKeys");
            adm_hasher.update((self.admin_keys.len() as u64).to_be_bytes());
            for admin_key in self.admin_keys.iter() {
                let key_hash = Sha256::digest(&admin_key.0);
                adm_hasher.update(key_hash);
            }
            adm_hasher.finalize()
        };

        let nodes_hash = {
            let mut nodes_vec = self.nodes.iter().collect::<Vec<_>>();
            // Do sorting to be deterministic
            nodes_vec.sort_by_key(|(id, _nd)| *id);
            let mut nodes_hasher = Sha256::new();
            nodes_hasher.update(b"Nodes");
            nodes_hasher.update((nodes_vec.len() as u64).to_be_bytes());
            for (_id, node) in nodes_vec.iter() {
                let mut node_hasher = Sha256::new();
                node_hasher.update([node.status as u8, 0, 0, 0]);
                node_hasher.update(&node.public_key_der);
                let node_hash = node_hasher.finalize();
                nodes_hasher.update(node_hash);
            }
            nodes_hasher.finalize()
        };

        let mut hasher = Sha256::new();
        hasher.update(adm_hash);
        hasher.update(nodes_hash);
        let result = hasher.finalize();

        result[..].to_vec()
    }
    pub fn signature_is_valid(&self, msg: &Message) -> bool {
        let peer_id = NodeId::from_data(&msg.signer_id);
        if matches!(msg.operation, Operation::AddByAdmin(..)) {
            // Look in the list of admin keys for the right one
            let digest = msg.digest();
            self.admin_keys
                .iter()
                .any(|(_der, key)| msg.digest_is_valid(&digest, &key))
        } else {
            let Some(node_entry) = self.nodes.get(&peer_id) else { return false };
            msg.signature_is_valid(&node_entry.public_key)
        }
    }
    /// Whether the given node should respond to the specified question on the lobby network
    pub fn is_node_that_responds_lobby(&self) -> bool {
        // TODO: implement logic for choosing node that responds
        !self.shared_key.is_empty()
    }
    /// Whether the given node should engage in rekeying
    pub fn is_node_that_does_rekeying(&self) -> bool {
        // TODO: implement logic for choosing node that performs rekeying
        !self.shared_key.is_empty()
    }
    /// Make the node yield a rekeying message, and update its internal key
    fn make_rekeying_msg(&mut self, timestamp: u64) -> Result<Response, Box<dyn Error>> {
        // Randomly generate a new key
        let mut buf = [0; SHARED_KEY_LEN];
        getrandom::getrandom(&mut buf).expect("getrandom call failed to fill key");
        self.shared_key = buf.to_vec();
        let mut keys = self
            .nodes
            .iter()
            // Important: only the nodes that are members should get the new key
            .filter(|(_id, nd_entry)| nd_entry.status == NodeStatus::Member)
            .map(|(id, nd_entry)| {
                let enc_key = nd_entry.public_key.encrypt(
                    &mut OsRng,
                    padding_scheme_encrypt(),
                    &self.shared_key,
                )?;
                let id: Vec<_> = id.0.to_owned();
                Ok((id, enc_key))
            })
            .collect::<Result<Vec<(Vec<_>, _)>, Box<dyn Error>>>()?;
        keys.sort_by_key(|(id, _enc_key)| id.to_owned());
        let msg = Operation::EncapsulatedKeys(keys).sign(timestamp, &self.key_pair)?;
        Ok(Response::Message(msg, true))
    }
    pub fn handle_msg(
        &mut self,
        msg: &[u8],
        from_members_network: bool,
    ) -> Result<Vec<Response>, Box<dyn Error>> {
        let Ok(msg): Result<Message, _> = bincode::deserialize(msg) else {
            log::info!("Ignoring message that we couldn't parse.");
            return Ok(Vec::new());
        };
        let (cbs_lobby, cbs_members) = msg.operation.can_be_sent_to_lobby_or_members();
        let can_be_sent = if from_members_network {
            cbs_members
        } else {
            cbs_lobby
        };
        if !can_be_sent {
            log::info!("Ignoring message that was sent on the wrong network (members={from_members_network}).");
            return Ok(Vec::new());
        }
        if !self.signature_is_valid(&msg) {
            log::info!("Ignoring message that had an invalid signature.");
            return Ok(Vec::new());
        }
        let timestamp = timestamp();
        if !matches!(msg.operation, Operation::AddByAdmin(..))
            && msg.timestamp < timestamp - MAX_MSG_AGE
        {
            let msg_age = timestamp - msg.timestamp;
            log::info!("Ignoring message with too large age {msg_age} (max={MAX_MSG_AGE}).");
            return Ok(Vec::new());
        }
        if from_members_network
            && (self.shared_key.is_empty() || self.state == ManagerState::WaitingForKey)
        {
            // TODO should this be an assertion failure? Maybe not, it might lead to DOS vulnerabilities.
            log::info!("Ignoring message sent on members network while we are not actually on it.");
            return Ok(Vec::new());
        }

        match msg.operation {
            // Lobby messages
            Operation::AddByAdmin(node_public_key_der) => {
                let node_public_key_res = RsaPublicKey::from_public_key_der(&node_public_key_der);
                let node_id_res = (self.node_id_generator)(&node_public_key_der);
                let (Ok(node_public_key), Ok(node_id)) = (node_public_key_res, node_id_res) else {
                    log::info!("Couldn't parse public key of node. Ignoring AddByAdmin message.");
                    return Ok(Vec::new());
                };
                let node_id = NodeId(node_id);
                // Add node to table as waiting
                match self.nodes.entry(node_id.clone()) {
                    Entry::Occupied(_ocd) => {
                        // We still have this node in our table.
                        // This might be due to a bug
                        log::info!(
                            "Couldn't parse public key of node. Ignoring AddByAdmin message."
                        );
                        return Ok(Vec::new());
                    }
                    Entry::Vacant(vcnt) => {
                        vcnt.insert(NodeEntry {
                            public_key: node_public_key.clone(),
                            public_key_der: node_public_key_der,
                            status: NodeStatus::WaitingEntry,
                        });
                    }
                }
                let mut rsps = Vec::new();

                if self.is_node_that_responds_lobby() {
                    let Ok(encrypted_key) = node_public_key.encrypt(&mut OsRng, padding_scheme_encrypt(), &self.shared_key) else {
                        log::info!("Couldn't encrypt encapsulated key. Ignoring AddByAdmin message.");
                        return Ok(Vec::new());
                    };
                    let op = Operation::EncapsulatedKey(encrypted_key, node_id.0);
                    let Ok(msg) = op.sign(timestamp, &self.key_pair) else {
                        log::info!("Couldn't sign encapsulated key msg. Ignoring AddByAdmin message.");
                        return Ok(Vec::new());
                    };
                    rsps.push(Response::Message(msg, false))
                }
                return Ok(rsps);
            }
            Operation::SelfRejoin => {
                // TODO deduplicate with AddByAdmin
                let responds_lobby = self.is_node_that_responds_lobby();
                let node_id = NodeId::from_data(&msg.signer_id);
                let Some(node_entry) = self.nodes.get_mut(&node_id) else {
                    log::info!("Couldn't encrypt encapsulated key. Ignoring SelfRejoin message.");
                    return Ok(Vec::new());
                };
                if responds_lobby {
                    let Ok(encrypted_key) = node_entry.public_key.encrypt(&mut OsRng, padding_scheme_encrypt(), &self.shared_key) else {
                        log::info!("Couldn't encrypt encapsulated key. Ignoring SelfRejoin message.");
                        return Ok(Vec::new());
                    };
                    let op = Operation::EncapsulatedKey(encrypted_key, self.node_id.clone());
                    let Ok(msg) = op.sign(timestamp, &self.key_pair) else {
                        log::info!("Couldn't sign encapsulated key msg. Ignoring SelfRejoin message.");
                        return Ok(Vec::new());
                    };
                    return Ok(vec![Response::Message(msg, false)]);
                }
            }
            Operation::EncapsulatedKey(encrypted_key, node_id) => {
                if node_id == self.node_id {
                    // Check if we actually *want* to (re)join, as in, if we've
                    // requested that before
                    if self.state == ManagerState::WaitingForKey {
                        log::info!("Didn't expect EncapsulatedKey message. Ignoring it.");
                        return Ok(Vec::new());
                    }
                    if let Ok(key) = self
                        .key_pair
                        .decrypt(padding_scheme_encrypt(), &encrypted_key)
                    {
                        if key.len() == SHARED_KEY_LEN {
                            self.state = ManagerState::MemberOkay;
                            return Ok(vec![Response::SetSharedKey(key)]);
                        } else {
                            log::info!("Shared key has invalid length {}.", key.len());
                        }
                    } else {
                        log::info!("Ignoring encapsulated key message that we couldn't decrypt.");
                    }
                } else {
                    // discard, not for us
                }
            }

            // Members messages
            Operation::VoteProposal(proposal) => todo!(),
            Operation::Vote(proposal_hash, desc) => todo!(),
            Operation::EncapsulatedKeys(keys_enc) => {
                // Check that we are in a rekeying state
                if self.state == ManagerState::WaitingForRekeying {
                    log::info!("Didn't expect EncapsulatedKeys message. Ignoring it.");
                    return Ok(Vec::new());
                }
                let Some((_, enc_key)) = keys_enc.iter()
                    .find(|(node_id, _enc_key)| *node_id == self.node_id) else
                {
                    log::info!("Didn't find entry for our node in EncapsulatedKeys message, ignoring it.");
                    return Ok(Vec::new());
                };

                let Ok(shared_key) = self.key_pair.decrypt(padding_scheme_encrypt(), enc_key) else {
                    log::info!("Couldn't decrypt encapsulated key. Ignoring rekeying.");
                    return Ok(Vec::new());
                };

                // TODO do some kind of validation (e.g. comparing with a hash shared in the clear)
                // to ensure that the node does not partition the network

                if shared_key.len() != SHARED_KEY_LEN {
                    log::info!("Shared key has invalid length {}.", shared_key.len());
                    return Ok(Vec::new());
                }

                self.shared_key = shared_key.clone();

                return Ok(vec![Response::SetSharedKey(shared_key)]);
            }
            Operation::SelfPause => {
                // Change node entry in node table
                let peer_id = NodeId::from_data(&msg.signer_id);
                let Some(nd) = self.nodes.get_mut(&peer_id) else {
                    log::info!("Couldn't find node that pauses membership. Ignoring SelfPause");
                    return Ok(Vec::new());
                };
                nd.status = NodeStatus::Paused;
                // Engage in rekeying
                self.state = ManagerState::WaitingForRekeying;
                if self.is_node_that_does_rekeying() {
                    return Ok(vec![self.make_rekeying_msg(timestamp)?]);
                }
            }
            Operation::SelfRemove => {
                // Remove node from node table
                // Engage in rekeying
                // TODO
            }
            Operation::KeepAlive(_node_table_hash) => {
                // Ignore for now.
                // TODO implement keep alive logic
            }
        }

        Ok(Vec::new())
    }
}
