#![allow(dead_code)]

pub use crate::builder::NodeManagerBuilder;
use crate::keys::{PrivateKey, PublicKey, VerifySignature};
pub use crate::node_table::JosangTrust;
pub use crate::node_table::{NodeEntry, NodeStatus, NodeTable};
use anyhow::Result;
use core::fmt::{self, Debug};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{hash_map::Entry, HashMap};

pub mod admin;
mod builder;
pub mod keys;
mod node_table;

#[derive(Deserialize, Serialize, Clone)]
pub enum VoteOperation {
    /// Remove a specified node
    ///
    /// Data: (node id)
    Remove(Vec<u8>),
    /// Pause a specified node due to keepalive failing
    ///
    /// Data: (node id)
    Pause(Vec<u8>),
}

impl VoteOperation {
    fn kind_str(&self) -> &'static str {
        match self {
            VoteOperation::Remove(..) => "Remove",
            VoteOperation::Pause(..) => "Pause",
        }
    }
}

impl Debug for VoteOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            VoteOperation::Remove(op) => write!(f, "remove {}", fmt_hex_arr(op)),
            VoteOperation::Pause(op) => write!(f, "pause {}", fmt_hex_arr(op)),
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct VoteProposal {
    initiator_id: Vec<u8>,
    hash: Vec<u8>,
    initiation_time: u64,
    /// Tally of the Votes
    votes: HashMap<Vec<u8>, VoteEntry>,
    operation: VoteOperation,
}

impl VoteProposal {
    fn maybe_get_descision_simple(&self) -> Option<Descision> {
        let possible_votes_count = self.votes.len();
        let mut yes_count = 0;
        let mut no_count = 0;
        for (_node_id, v_en) in self.votes.iter() {
            if v_en == &VoteEntry::Voted(Descision::Yes) {
                yes_count += 1;
            } else if v_en == &VoteEntry::Voted(Descision::No) {
                no_count += 1;
            }
        }
        let descision = if yes_count * 2 >= possible_votes_count - 1 {
            Some(Descision::Yes)
        } else if no_count * 2 >= possible_votes_count - 1 {
            Some(Descision::No)
        } else {
            None
        };
        if descision.is_some() {
            log::debug!(
                "Descision results: yes={yes_count}, no={no_count}, eligible={}",
                possible_votes_count
            );
        }
        descision
    }
    fn maybe_get_descision_trust(&self, nodes: &NodeTable<JosangTrust>) -> Option<Descision> {
        let possible_votes_count = self.votes.len();
        let mut yes_sum = 0.0;
        let mut no_sum = 0.0;
        for (node_id, v_en) in self.votes.iter() {
            let nid = NodeId::from_data(node_id);
            let Some(nd_entry) = nodes.get(&nid) else {
                log::info!("Couldn't find node {nid:?} in node table");
                continue
            };
            let nd_rep = nd_entry.trust.reputation();
            if v_en == &VoteEntry::Voted(Descision::Yes) {
                yes_sum += nd_rep;
            } else if v_en == &VoteEntry::Voted(Descision::No) {
                no_sum += nd_rep;
            }
        }

        let quorum_reached = (yes_sum + no_sum) >= possible_votes_count as f64 * 0.6;
        quorum_reached.then(|| {
            let desc = if yes_sum > no_sum {
                Descision::Yes
            } else {
                Descision::No
            };
            log::info!(
                "Descision results: yes={yes_sum}, no={no_sum}, quorum={}, eligible={possible_votes_count} -> {desc:?}",
                yes_sum + no_sum
            );
            desc
        })
    }
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

#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteEntry {
    Voted(Descision),
    NotVoted,
    VotedBadly,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Descision {
    Yes,
    No,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum Operation {
    // -------------------------------------------------
    // Operations for the lobby network:
    // -------------------------------------------------
    /// The admin key adds a specific node to the network
    ///
    /// Data: (node id)
    AddByAdmin(Vec<u8>),
    /// The node requests itself to be added on the network
    SelfRejoin,
    /// The encapsulated shared key, encrypted for member with the specified node id.
    ///
    /// Data: (key, node id, node table)
    EncapsulatedKey(Vec<u8>, Vec<u8>, Vec<u8>),

    // -------------------------------------------------
    // Operations for both lobby and members networks:
    // -------------------------------------------------
    /// Sends a ping message to all nodes
    Ping,
    /// Response to ping event (either on lobby or members network)
    ///
    /// Data: (node id of the originator, timestamp of the original ping)
    Pong(Vec<u8>, u64),

    // -------------------------------------------------
    // Operations for the members network:
    // -------------------------------------------------
    /// A proposal for a vote
    VoteProposal(VoteOperation),
    /// Participation in a vote proposal
    ///
    /// Data: (vote hash, descision)
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
            Ping | Pong(..) => (true, true),
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
        signer_id: &[u8],
        signer_key: &PrivateKey,
    ) -> Result<Message> {
        let mut msg = Message {
            timestamp,
            signer_id: signer_id.to_owned(),
            signature: Vec::new(),
            operation: self,
        };
        let msg_digest = msg.digest();
        msg.signature = signer_key.sign(&msg_digest)?;
        Ok(msg)
    }
    pub fn kind_str(&self) -> &'static str {
        use Operation::*;
        match self {
            AddByAdmin(..) => "AddByAdmin",
            SelfRejoin => "SelfRejoin",
            EncapsulatedKey(..) => "EncapsulatedKey",
            Ping => "Ping",
            Pong(..) => "Pong",
            VoteProposal(..) => "VoteProposal",
            EncapsulatedKeys(..) => "EncapsulatedKeys",
            Vote(..) => "Vote",
            SelfPause => "SelfPause",
            SelfRemove => "SelfRemove",
            KeepAlive(..) => "KeepAlive",
        }
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
    pub fn signature_is_valid(&self, key: &impl VerifySignature) -> bool {
        let digest = self.digest();
        self.digest_is_valid(&digest, key)
    }
    /// Checks if the signature is valid for the given digest
    ///
    /// The digest mut fit to the message! Use [`Self::signature_is_valid`]
    pub(crate) fn digest_is_valid(&self, digest: &[u8], key: &impl VerifySignature) -> bool {
        if key.verify(digest, &self.signature).is_err() {
            return false;
        }
        true
    }
    pub(crate) fn digest(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"Message");
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update((self.signer_id.len() as u64).to_be_bytes());
        hasher.update(&self.signer_id);
        hasher.update(self.operation.digest());
        hasher.finalize().to_vec()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(Vec<u8>);

impl NodeId {
    pub fn from_data(data: &[u8]) -> Self {
        Self(data.to_vec())
    }
    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

fn fmt_hex_arr(arr: &[u8]) -> String {
    if let Some(bytes) = arr.get(..3) {
        bytes.iter().map(|v| format!("{v:02x}")).collect()
    } else {
        "<empty>".to_string()
    }
}

impl Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", fmt_hex_arr(&self.0))?;
        Ok(())
    }
}

/// A function that converts a DER encoded RSA key into a NodeId
pub type NodeIdGenerator = fn(&[u8]) -> Result<Vec<u8>, ()>;

/// Returns the current time in miliseconds since the unix epoch
///
/// Useful helper function for passing the timestamp to the API
pub fn timestamp() -> Result<u64> {
    use std::time::SystemTime;
    let t = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    Ok(t)
}

fn ts() -> u64 {
    timestamp().unwrap()
}

#[derive(PartialEq, Eq, Debug)]
enum ManagerState {
    WaitingForKey,
    MemberOkay,
    WaitingForRekeying,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Thresholds {
    /// Maximum age for a message in order for the NodeManager to consider it as valid
    pub max_msg_age: u64,
    /// Lifetime of a vote proposal after which each node counts the votes and decides what to do about it
    pub vote_proposal_lifetime: u64,
    /// The max seen time, comprised of a (yellow, red) tuple
    ///
    /// After `yellow` time has passed, nodes will vote yes on any proposal to pause a node.
    /// After `red` time has passed, nodes will start votes of their own.
    pub max_seen_time: (u64, u64),
}

impl Thresholds {
    fn new() -> Self {
        Default::default()
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            max_msg_age: 1_000,
            vote_proposal_lifetime: 400,
            max_seen_time: (33_000, 45_000),
        }
    }
}

/// The length of an expected shared key
pub const SHARED_KEY_LEN: usize = 32;

pub fn gen_shared_key() -> [u8; SHARED_KEY_LEN] {
    let mut buf = [0; SHARED_KEY_LEN];
    getrandom::getrandom(&mut buf).expect("getrandom call failed to fill key");
    buf
}

pub struct NodeManager {
    key_pair: PrivateKey,
    node_id_generator: NodeIdGenerator,
    /// Shared key of the members network
    shared_key: Vec<u8>,
    node_id: Vec<u8>,
    /// List of admin keys, given as tuples of `(<DER formatted key>, PublicKey)`
    admin_keys: Vec<(Vec<u8>, PublicKey)>,
    nodes: NodeTable<JosangTrust>,
    /// Field storing a multitude of states for the node,
    /// mostly whether we wait for something to happen
    ///
    /// * possible "waiting for EncapsulatedKey msg" state
    /// * possible "waiting for EncapsulatedKeys msg" state
    state: ManagerState,
    vote_proposal: Option<VoteProposal>,
    // TODO: table storing voting proposal cooldowns for nodes
    vote_suggestions: HashMap<Vec<u8>, bool>,
    thresholds: Thresholds,
    self_should_auto_pause: bool,
    /// Mostly there for debugging and experiment reasons
    sometimes_wrongly_vote_counter: Option<u8>,
}

impl NodeManager {
    pub fn new(key_pair_pkcs8_der: &[u8], node_id_generator: NodeIdGenerator) -> Self {
        NodeManagerBuilder::new(key_pair_pkcs8_der, node_id_generator).build()
    }
    /// The id of the node represented by this node manager
    pub fn node_id(&self) -> &[u8] {
        &self.node_id
    }
    /// The current shared key
    ///
    /// During rekeying, the shared key returned by this function might be
    /// updated before you should send out a message with that shared key.
    /// Or to be more specific, always use a shared key from before calling
    /// [`handle_msg`], and then update that key accordingly as you go through
    /// the responses, respecting `SetSharedKey`. Never use the output of this
    /// function *after* you have called [`handle_msg`].
    ///
    /// [`handle_msg`]: Self::handle_msg
    pub fn shared_key(&self) -> &[u8] {
        &self.shared_key
    }
    /// The public key in DER format
    pub fn public_key_der(&self) -> Vec<u8> {
        self.key_pair.to_public_key().to_public_key_der().unwrap()
    }
    /// The used threshold values for various actions
    pub fn thresholds(&self) -> &Thresholds {
        &self.thresholds
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
        let digest = msg.digest();
        self.digest_is_valid_for_msg(&digest, msg)
    }
    pub(crate) fn digest_is_valid_for_msg(&self, digest: &[u8], msg: &Message) -> bool {
        let peer_id = NodeId::from_data(&msg.signer_id);
        if msg.signer_id == admin::ADMIN_ID {
            if !matches!(msg.operation, Operation::AddByAdmin(..)) {
                return false;
            }
            // Look in the list of admin keys for the right one
            self.admin_keys
                .iter()
                .any(|(_der, key)| msg.digest_is_valid(digest, key))
        } else {
            let Some(node_entry) = self.nodes.get(&peer_id) else { return false };
            msg.digest_is_valid(digest, &node_entry.public_key)
        }
    }
    /// Adds the given der formatted key as an admin key
    pub fn add_admin_key_der(&mut self, admin_key_der: &[u8]) -> Result<()> {
        let admin_public_key = PublicKey::from_public_key_der(admin_key_der)?;
        self.add_admin_key(admin_public_key)
    }
    /// Adds the given key as an admin key
    pub fn add_admin_key(&mut self, admin_public_key: PublicKey) -> Result<()> {
        let admin_key_der = admin_public_key.to_public_key_der()?;
        if self.admin_keys.iter().any(|d| d.0 == admin_key_der) {
            // admin key already exists
            return Ok(());
        }

        self.admin_keys.push((admin_key_der, admin_public_key));
        Ok(())
    }
    /// Sets a random shared key
    ///
    /// This function is supposed to be called when the node manager is the first one in the network,
    /// at the point of time when the code running the node decides that the node is likely the first one.
    ///
    /// The returned slice is the shared key. If you get into problems with the mutable reference still being held,
    /// we recommend using the [shared_key](Self::shared_key) function as an alternative (or copying).
    pub fn set_random_shared_key(&mut self) -> &[u8] {
        if !self.shared_key.is_empty() {
            log::info!("Tried to set random shared key, but the shared key is already set!");
            return &self.shared_key;
        }
        self.set_init_random_shared_key(gen_shared_key().to_vec());
        &self.shared_key
    }
    // This function is only supposed to be called upon initial shared key settings.
    // it is wrong to call it for rekeying!
    fn set_init_random_shared_key(&mut self, shared_key: Vec<u8>) {
        self.shared_key = shared_key;
        self.state = ManagerState::MemberOkay;
        if let Some(nd) = self.nodes.get_mut(&NodeId::from_data(&self.node_id)) {
            nd.status = NodeStatus::Member;
        }
    }
    /// Returns a user-displayable string listing the nodes that are member of the node table
    pub fn table_str(&self) -> String {
        node_table::table_str(&self.nodes)
    }
    /// Like [table_str](Self::table_str), but prints more detail
    pub fn table_str_ext(&self, timestamp: u64) -> String {
        node_table::table_str_ext(&self.nodes, timestamp)
    }
    /// Whether the given node should respond to the specified question on the lobby network
    fn is_node_that_responds_lobby(&self, _timestamp: u64) -> bool {
        if self.shared_key.is_empty() {
            // We don't have a shared key ourselves yet
            return false;
        }
        let min_node_qualifying = self
            .nodes
            .iter()
            .filter(|(_nd, entry)| {
                entry.status == NodeStatus::Member
                //&& timestamp.saturating_sub(entry.last_seen_time) <= MAX_SEEN_TIME_FOR_RESPONSE
            })
            .min_by_key(|&(id, _nd)| id);
        let Some(min_node_qualifying) = min_node_qualifying else {
            // No node is qualifying! This is bad.
            log::info!("No qualifying leader node found, at least there should be us!");
            return true;
        };
        log::debug!(
            "Min: {}, us: {}",
            fmt_hex_arr(&(min_node_qualifying.0).0),
            fmt_hex_arr(&self.node_id)
        );
        if self.node_id > (min_node_qualifying.0).0 {
            return false;
        }
        true
    }
    /// Whether the given node should engage in rekeying
    fn is_node_that_does_rekeying(&self, timestamp: u64) -> bool {
        let does_rekeying = self.is_node_that_responds_lobby(timestamp);
        log::debug!("does_rekeying = {does_rekeying}");
        does_rekeying
    }
    /// Make the node yield a rekeying message, and update its internal key
    fn make_rekeying(&mut self, timestamp: u64) -> Result<Vec<Response>> {
        // Randomly generate a new key
        self.shared_key = gen_shared_key().to_vec();
        let mut keys = self
            .nodes
            .iter()
            // Important: only the nodes that are members should get the new key
            .filter(|(_id, nd_entry)| nd_entry.status == NodeStatus::Member)
            .map(|(id, nd_entry)| {
                let enc_key = nd_entry.public_key.encrypt(&self.shared_key)?;
                let id: Vec<_> = id.0.to_owned();
                Ok((id, enc_key))
            })
            .collect::<Result<Vec<(Vec<_>, _)>>>()?;
        keys.sort_by_key(|(id, _enc_key)| id.to_owned());
        let table_str = node_table::table_str(&self.nodes);
        log::debug!("rekeying for n={} node table = {}", keys.len(), table_str);
        let msg =
            Operation::EncapsulatedKeys(keys).sign(timestamp, &self.node_id, &self.key_pair)?;
        Ok(vec![
            Response::Message(msg, true),
            Response::SetSharedKey(self.shared_key.clone()),
        ])
    }
    fn decide_vote(&mut self, op: &VoteOperation, timestamp: u64) -> Descision {
        let vote = self.decide_vote_inner(op, timestamp);
        if let Some(mut ctr) = self.sometimes_wrongly_vote_counter {
            const SOMETIMES_WRONGLY_VOTE_INTERVAL: u8 = 5;
            if ctr == SOMETIMES_WRONGLY_VOTE_INTERVAL {
                ctr = 0;
            } else {
                ctr += 1;
            }
            self.sometimes_wrongly_vote_counter = Some(ctr);
            match vote {
                Descision::No => Descision::Yes,
                Descision::Yes => Descision::No,
            }
        } else {
            vote
        }
    }
    fn decide_vote_inner(&self, op: &VoteOperation, timestamp: u64) -> Descision {
        match op {
            VoteOperation::Remove(id) => {
                if id == &self.node_id {
                    // Obviously, if this is about *ourselves* being kicked out,
                    // argue against it.
                    return Descision::No;
                }
                if let Some(sugg) = self.vote_suggestions.get(id) {
                    log::info!(
                        "Using stored suggestion '{sugg}' for voting descision on {}.",
                        fmt_hex_arr(id)
                    );
                    if *sugg {
                        Descision::Yes
                    } else {
                        Descision::No
                    }
                } else {
                    log::info!(
                        "Falling back to random generator for voting descision on {}.",
                        fmt_hex_arr(id)
                    );
                    // Fallback to rng if the suggestion is not stored
                    // Default: accept, but deny in 1/8 of cases
                    // TODO: implement a trust based scheme here, instead of just random choice.
                    fn rng(this: &NodeManager, timestamp: u64) -> bool {
                        let tbl_hash = this.table_hash();
                        let mut hasher = Sha256::new();
                        hasher.update(tbl_hash);
                        hasher.update(&this.node_id);
                        hasher.update(timestamp.to_be_bytes());
                        let hash = hasher.finalize().to_vec();
                        hash[0] & 0b111 == 0
                    }
                    if rng(self, timestamp) {
                        Descision::No
                    } else {
                        Descision::Yes
                    }
                }
            }
            VoteOperation::Pause(id) => {
                if id == &self.node_id {
                    // Apparently some node didn't receive our keepalive in time and started a vote on our removal.
                    // Obviously, argue against it, but at this point we cannot exclude the possibility that
                    // we are voted out.
                    log::info!(
                        "There is a vote about us being paused, and we received the proposal"
                    );
                    return Descision::No;
                }
                let nid = NodeId::from_data(id);
                let Some(nd) = self.nodes.get(&nid) else {
                    log::info!("Couldn't find node with {nid:?} in table for deciding pause vote. Deciding against.");
                    return Descision::No;
                };
                let Some(since_last_seen) = timestamp.checked_sub(nd.last_seen_time) else {
                    log::info!("Overflow in node age calculation during vote descision. Deciding against.");
                    return Descision::No;
                };
                if since_last_seen > self.thresholds.max_seen_time.0 {
                    return Descision::Yes;
                }
                Descision::No
            }
        }
    }

    /// Broadcasts a self removal message
    ///
    /// Like in [`handle_msg`](Self::handle_msg), the caller has to broadcast
    /// the message.
    pub fn self_remove(&mut self, timestamp: u64) -> Result<Vec<Response>> {
        let op = Operation::SelfRemove;
        let Ok(msg) = op.sign(timestamp, &self.node_id, &self.key_pair) else {
            log::info!("Couldn't sign self remove msg. Not creating self removal msg.");
            return Ok(Vec::new());
        };
        self.shared_key = Vec::new();
        // We aren't really waiting for a key here, but this is the closest...
        self.state = ManagerState::WaitingForKey;
        Ok(vec![Response::Message(msg, true)])
    }

    /// Broadcasts a self pause message
    ///
    /// Like in [`handle_msg`](Self::handle_msg), the caller has to broadcast
    /// the message.
    pub fn self_pause(&mut self, timestamp: u64) -> Result<Vec<Response>> {
        let op = Operation::SelfPause;
        let Ok(msg) = op.sign(timestamp, &self.node_id, &self.key_pair) else {
            log::info!("Couldn't sign self pause msg. Not creating self pause msg.");
            return Ok(Vec::new());
        };
        self.shared_key = Vec::new();

        // Not really needed, but we still do it
        if let Some(nd) = self.nodes.get_mut(&NodeId::from_data(&self.node_id)) {
            nd.status = NodeStatus::Paused;
        }

        // We aren't really waiting for a key here, but this is the closest...
        self.state = ManagerState::WaitingForKey;
        Ok(vec![Response::Message(msg, true)])
    }

    /// Broadcasts a self rejoin message
    ///
    /// Like in [`handle_msg`](Self::handle_msg), the caller has to broadcast
    /// the message.
    pub fn self_rejoin(&mut self, timestamp: u64) -> Result<Vec<Response>> {
        let op = Operation::SelfRejoin;
        let Ok(msg) = op.sign(timestamp, &self.node_id, &self.key_pair) else {
            log::info!("Couldn't sign self rejoin msg. Not creating self rejoin msg.");
            return Ok(Vec::new());
        };
        self.shared_key = Vec::new();
        // We aren't really waiting for a key here, but this is the closest...
        self.state = ManagerState::WaitingForKey;
        Ok(vec![Response::Message(msg, false)])
    }

    /// Broadcasts a ping message
    ///
    /// Like in [`handle_msg`](Self::handle_msg), the caller has to broadcast
    /// the message.
    pub fn ping(&self, timestamp: u64, for_members_network: bool) -> Result<Vec<Response>> {
        let op = Operation::Ping;

        let Ok(msg) = op.sign(timestamp, &self.node_id, &self.key_pair) else {
            log::info!("Couldn't sign ping msg. Not creating ping msg.");
            return Ok(Vec::new());
        };
        Ok(vec![Response::Message(msg, for_members_network)])
    }

    /// Obtain a complete node id from a partial node id
    ///
    /// The function received a (potentially partial) node id as an input,
    /// and searches the node table for the node with that id.
    /// If no unique result exists, `None` is returned.
    ///
    /// The node id can be fed to [`start_vote`](Self::start_vote) for example.
    pub fn complete_node_id(&self, needle: &[u8]) -> Option<Vec<u8>> {
        let nodes = self
            .nodes
            .iter()
            .filter(|(nd_id, _ne)| nd_id.0.starts_with(needle))
            .collect::<Vec<_>>();
        if let [(nd_id, _ne)] = nodes[..] {
            Some(nd_id.0.to_owned())
        } else {
            None
        }
    }

    /// Broadcasts a message to initiate a vote
    ///
    /// Like in [`handle_msg`](Self::handle_msg), the caller has to broadcast
    /// the message.
    pub fn start_vote(&mut self, timestamp: u64, to_remove_id: &[u8]) -> Result<Vec<Response>> {
        self.start_vote_op(timestamp, VoteOperation::Remove(to_remove_id.to_owned()))
    }

    fn start_vote_op(&mut self, timestamp: u64, operation: VoteOperation) -> Result<Vec<Response>> {
        let op = Operation::VoteProposal(operation.clone());
        let Ok(msg) = op.sign(timestamp, &self.node_id, &self.key_pair) else {
            log::info!("Couldn't sign vote proposal msg.");
            return Ok(Vec::new());
        };
        log::info!("Starting vote with operation {operation:?}...");

        let mut votes: HashMap<_, _> = self
            .nodes
            .iter()
            .filter_map(|(node_id, node_entry)| {
                if node_entry.status != NodeStatus::Member {
                    return None;
                }
                Some((node_id.0.clone(), VoteEntry::NotVoted))
            })
            .collect();
        votes.insert(self.node_id.clone(), VoteEntry::Voted(Descision::Yes));

        let hash = msg.digest();

        // Create and store the proposal
        let proposal = VoteProposal {
            initiator_id: msg.signer_id.clone(),
            initiation_time: timestamp,
            hash,
            votes,
            operation,
        };
        self.vote_proposal = Some(proposal);

        Ok(vec![Response::Message(msg, true)])
    }

    pub fn save_vote_suggestion(
        &mut self,
        subject: &[u8],
        timestamp: u64,
        should_kick: bool,
        deleted: bool,
        auto_start_vote: bool,
    ) -> Result<Vec<Response>> {
        let entry = self.vote_suggestions.entry(subject.to_vec());
        if deleted {
            if let Entry::Occupied(e) = entry {
                e.remove_entry();
            }
        } else {
            // TODO use Entry::insert_entry function once that's stable
            match entry {
                Entry::Occupied(mut e) => {
                    e.insert(should_kick);
                }
                Entry::Vacant(e) => {
                    e.insert(should_kick);
                }
            }
            if auto_start_vote && should_kick && self.vote_proposal.is_none() {
                return self.start_vote_op(timestamp, VoteOperation::Remove(subject.to_owned()));
            }
        }
        Ok(Vec::new())
    }

    /// Creates a keepalive message to be sent to the outside world
    pub fn make_keepalive(&self, timestamp: u64) -> Result<Vec<Response>> {
        let op = Operation::KeepAlive(self.table_hash());
        let Ok(msg) = op.sign(timestamp, &self.node_id, &self.key_pair) else {
            log::info!("Couldn't sign keep alive msg.");
            return Ok(Vec::new());
        };
        Ok(vec![Response::Message(msg, true)])
    }

    /// Checks whether any node has not sent their in time
    ///
    /// The `add_val` is some random value used to add to the threshold,
    /// to prevent multiple nodes from starting votes on the same time.
    pub fn check_timeouts(&mut self, timestamp: u64, add_val: u64) -> Result<Vec<Response>> {
        if self.shared_key.is_empty() {
            log::info!("Not currently member so we don't check timeouts");
            return Ok(Vec::new());
        }
        // If there is ongoing vote proposals, don't bring up anything new
        if self.vote_proposal.is_some() {
            return Ok(Vec::new());
        }
        let max_seen_time_red = self.thresholds.max_seen_time.1;
        let max_seen_time_yellow = self.thresholds.max_seen_time.0;
        let mut res = Vec::new();
        let mut nids = Vec::new();
        {
            let nd_iter = self.nodes.iter().filter_map(|(nid, nd_entry)| {
                if nid.0 == self.node_id {
                    return None;
                }
                if nd_entry.status != NodeStatus::Member {
                    return None;
                }
                let time_since_last = timestamp.checked_sub(nd_entry.last_seen_time)?;
                Some((nid, time_since_last))
            });

            if self.self_should_auto_pause {
                let num_other_nodes = nd_iter.clone().count();
                let all_nodes_timed_out = nd_iter
                    .clone()
                    .all(|(_nid, time_since_last)| time_since_last > max_seen_time_yellow);
                if all_nodes_timed_out && num_other_nodes > 0 {
                    log::info!(
                        "All {num_other_nodes} other member nodes have timed out, \
                        which probably means some network issue. Remove ourselves from the network."
                    );
                    // This message will probably not reach the other nodes,
                    // but there will be some updates of internal state.
                    return self.self_pause(timestamp);
                }
            }

            for (nid, time_since_last) in nd_iter {
                if time_since_last > max_seen_time_red + add_val {
                    log::info!("Starting vote on pausing timed out node {nid:?}.");
                    nids.push(nid.0.to_owned());
                }
            }
        }
        // More than one ongoing vote at the same time is not supported
        if let Some(nid) = nids.first() {
            let op = VoteOperation::Pause(nid.clone());
            res.extend(self.start_vote_op(timestamp, op)?.into_iter());
        }
        if nids.len() > 1 {
            log::info!(
                "Found {} many nodes to start vote on, only starting vote on first.",
                nids.len()
            );
        }
        Ok(res)
    }

    /// Checks if there are any votes finishing and if yes, performs the actions needed to finish
    pub fn check_finish_votes(&mut self, timestamp: u64) -> Result<Vec<Response>> {
        if let Some(prop) = &self.vote_proposal {
            let since_proposal = timestamp.saturating_sub(prop.initiation_time);
            if since_proposal < self.thresholds.vote_proposal_lifetime {
                return Ok(Vec::new());
            }
            //log::debug!("Vote time for vote is over, elapsed: {since_proposal}.");
            let opt_desc = prop.maybe_get_descision_trust(&self.nodes);
            if let Some(desc) = opt_desc {
                return self.handle_decided_vote(desc, timestamp);
            }
        }
        Ok(Vec::new())
    }

    /// Handles the message
    ///
    /// Same as [`handle_msg_ts`](Self::handle_msg_ts), but the timestamp is set
    /// to the current timestamp.
    ///
    /// Returns a list of actions that the caller must perform (change the key
    /// for the members network, broadcast a message...).
    pub fn handle_msg(&mut self, msg: &[u8], from_members_network: bool) -> Result<Vec<Response>> {
        let timestamp = ts();
        self.handle_msg_ts(msg, from_members_network, timestamp)
    }

    /// Handles the message
    ///
    /// Same as [`handle_msg`](Self::handle_msg), but you can customize the
    /// timestamp.
    pub fn handle_msg_ts(
        &mut self,
        msg: &[u8],
        from_members_network: bool,
        timestamp: u64,
    ) -> Result<Vec<Response>> {
        let Ok(msg): Result<Message, _> = bincode::deserialize(msg) else {
            log::info!("Ignoring message that we couldn't parse.");
            return Ok(Vec::new());
        };
        log::debug!(
            "Received message {} from {}",
            msg.operation.kind_str(),
            fmt_hex_arr(&msg.signer_id)
        );
        let (cbs_lobby, cbs_members) = msg.operation.can_be_sent_to_lobby_or_members();
        let can_be_sent = if from_members_network {
            cbs_members
        } else {
            cbs_lobby
        };
        if !can_be_sent {
            log::info!("Ignoring {} message that was sent on the wrong network (members={from_members_network}).", msg.operation.kind_str());
            return Ok(Vec::new());
        }
        if msg.signer_id == self.node_id {
            log::debug!(
                "Ignoring {} message that was sent by ourselves.",
                msg.operation.kind_str()
            );
            return Ok(Vec::new());
        }
        let msg_digest = msg.digest();
        let key_for_us = if let Operation::EncapsulatedKey(_enc_key, node_id, _nt) = &msg.operation
        {
            node_id == &self.node_id
        } else {
            false
        };
        if !key_for_us && !self.digest_is_valid_for_msg(&msg_digest, &msg) {
            log::info!(
                "Ignoring {} message that had an invalid signature or unknown signer.",
                msg.operation.kind_str()
            );
            return Ok(Vec::new());
        }
        let max_msg_age = self.thresholds.max_msg_age;
        if !matches!(msg.operation, Operation::AddByAdmin(..))
            && msg.timestamp < timestamp - max_msg_age
        {
            let msg_age = timestamp - msg.timestamp;
            log::info!(
                "Ignoring {} message with too large age {msg_age} (max={max_msg_age}).",
                msg.operation.kind_str()
            );
            return Ok(Vec::new());
        }
        if from_members_network
            && (self.shared_key.is_empty() || self.state == ManagerState::WaitingForKey)
        {
            log::info!(
                "Ignoring {} message sent on members network while we are not actually on it.",
                msg.operation.kind_str()
            );
            return Ok(Vec::new());
        }

        match msg.operation {
            // Lobby messages
            Operation::AddByAdmin(node_public_key_der) => {
                let node_public_key_res = PublicKey::from_public_key_der(&node_public_key_der);
                let node_id_res = (self.node_id_generator)(&node_public_key_der);
                let (Ok(node_public_key), Ok(node_id)) = (node_public_key_res, node_id_res) else {
                    log::info!("Couldn't parse public key of node. Ignoring AddByAdmin message.");
                    return Ok(Vec::new());
                };
                let node_id = NodeId(node_id);
                if self.shared_key.is_empty() {
                    log::info!("We are not in the node table yet. Ignoring AddByAdmin message from node {}.", fmt_hex_arr(&node_id.0));
                    return Ok(Vec::new());
                }
                // This needs to be read before we add the node as member,
                // otherwise we might think that the new node is a possible
                // candidate. We also can't add the node as waiting,
                // because the creator of the EncapsulatedKey message won't
                // read it.
                let responds_lobby = self.is_node_that_responds_lobby(timestamp);
                // Add node to table as member
                match self.nodes.entry(node_id.clone()) {
                    Entry::Occupied(mut ocd) => {
                        if ocd.get().status == NodeStatus::Paused {
                            // The node might have crashed, and has restarted so we want to allow it back.
                            log::info!("Node {node_id:?} is already in table, but marked as paused. Treating AddByAdmin as valid.");
                            ocd.get_mut().status = NodeStatus::Member;
                        } else {
                            // We still have this node in our table.
                            // This might be due to a bug
                            log::info!(
                                "Node {node_id:?} already in table. Ignoring AddByAdmin message."
                            );
                            return Ok(Vec::new());
                        }
                    }
                    Entry::Vacant(vcnt) => {
                        vcnt.insert(NodeEntry {
                            public_key: node_public_key.clone(),
                            public_key_der: node_public_key_der,
                            status: NodeStatus::Member,
                            last_seen_time: timestamp,
                            trust: Default::default(),
                        });
                    }
                }
                let mut rsps = Vec::new();

                if responds_lobby {
                    let Ok(encrypted_key) = node_public_key.encrypt(&self.shared_key) else {
                        log::info!("Couldn't encrypt encapsulated key. Ignoring AddByAdmin message.");
                        return Ok(Vec::new());
                    };
                    let node_table_bytes = node_table::serialize(&self.nodes)?;
                    let op = Operation::EncapsulatedKey(encrypted_key, node_id.0, node_table_bytes);
                    let Ok(msg) = op.sign(timestamp, &self.node_id, &self.key_pair) else {
                        log::info!("Couldn't sign encapsulated key msg. Ignoring AddByAdmin message.");
                        return Ok(Vec::new());
                    };
                    rsps.push(Response::Message(msg, false))
                }
                return Ok(rsps);
            }
            Operation::SelfRejoin => {
                // TODO deduplicate with AddByAdmin
                let responds_lobby = self.is_node_that_responds_lobby(timestamp);
                let node_id = NodeId::from_data(&msg.signer_id);
                let Some(node_entry) = self.nodes.get_mut(&node_id) else {
                    log::info!("Couldn't find node in table. Ignoring SelfRejoin message.");
                    return Ok(Vec::new());
                };
                if node_entry.status != NodeStatus::Paused {
                    log::info!("Node wasn't actually paused but instead {:?}. Ignoring SelfRejoin message.", node_entry.status);
                    return Ok(Vec::new());
                }
                node_entry.status = NodeStatus::Member;
                if responds_lobby {
                    let Ok(encrypted_key) = node_entry.public_key.encrypt(&self.shared_key) else {
                        log::info!("Couldn't encrypt encapsulated key. Ignoring SelfRejoin message.");
                        return Ok(Vec::new());
                    };
                    let node_table_bytes = node_table::serialize(&self.nodes)?;
                    let op = Operation::EncapsulatedKey(
                        encrypted_key,
                        msg.signer_id.clone(),
                        node_table_bytes,
                    );
                    let Ok(msg) = op.sign(timestamp, &self.node_id, &self.key_pair) else {
                        log::info!("Couldn't sign encapsulated key msg. Ignoring SelfRejoin message.");
                        return Ok(Vec::new());
                    };
                    return Ok(vec![Response::Message(msg, false)]);
                }
            }
            Operation::EncapsulatedKey(encrypted_key, node_id, node_table_bytes) => {
                if node_id == self.node_id {
                    // Check if we actually *want* to (re)join, as in, if we've
                    // requested that before
                    if self.state != ManagerState::WaitingForKey {
                        log::info!("Didn't expect EncapsulatedKey message. Ignoring it.");
                        return Ok(Vec::new());
                    }
                    let Ok(node_table) = node_table::from_data(&node_table_bytes, timestamp) else {
                        log::info!("Couldn't parse NodeTable. Ignoring EncapsulatedKey message.");
                        return Ok(Vec::new());
                    };
                    if let Ok(key) = self.key_pair.decrypt(&encrypted_key) {
                        if key.len() == SHARED_KEY_LEN {
                            // TODO check that the msg_digest corresponds to the entry in the node table
                            // This check would not bring much though for security.
                            self.nodes = node_table;
                            if let Some(ne) = self.nodes.get(&NodeId::from_data(&node_id)) {
                                if ne.status != NodeStatus::Member {
                                    log::warn!(
                                        "Not listed as member in table but as {:?}.",
                                        ne.status
                                    );
                                }
                            } else {
                                log::warn!("Couldn't find ourselves in the node table.");
                            }
                            log::debug!(
                                "Successfully joining as {}. nodes={}",
                                fmt_hex_arr(&self.node_id),
                                node_table::table_str(&self.nodes)
                            );
                            self.shared_key = key.clone();
                            self.state = ManagerState::MemberOkay;
                            return Ok(vec![Response::SetSharedKey(key)]);
                        } else {
                            log::info!("Shared key has invalid length {}.", key.len());
                        }
                    } else {
                        log::info!("Ignoring encapsulated key message that we couldn't decrypt.");
                    }
                } else {
                    // not for us, but we use this opportunity to turn the node into a member.
                    if let Some(ne) = self.nodes.get_mut(&NodeId::from_data(&node_id)) {
                        ne.status = NodeStatus::Member;
                    } else {
                        log::info!("Couldn't find node receiving the encapsulated key in the node table. Ignoring EncapsulatedKey message.");
                    }
                }
            }

            // Messages that can be sent via the lobby as well as the members network
            Operation::Ping => {
                // Respond with a pong
                let op = Operation::Pong(msg.signer_id.clone(), msg.timestamp);
                let Ok(msg) = op.sign(timestamp, &self.node_id, &self.key_pair) else {
                    log::info!("Couldn't sign pong msg.");
                    return Ok(Vec::new());
                };
                let net = if from_members_network {
                    "members network"
                } else {
                    "lobby"
                };
                log::info!(
                    "Received ping message from {}, on the {net}, responding with pong",
                    fmt_hex_arr(&msg.signer_id)
                );
                // Send the pong back on right the same medium as it was received
                return Ok(vec![Response::Message(msg, from_members_network)]);
            }
            Operation::Pong(node_id, ts_orig) => {
                let ts_diff = timestamp.saturating_sub(ts_orig);
                let for_str = if node_id == self.node_id {
                    "us".to_string()
                } else {
                    fmt_hex_arr(&node_id)
                };
                let net = if from_members_network {
                    "members"
                } else {
                    "lobby"
                };
                log::info!(
                    "Received {net} pong message for {for_str} from {} after {ts_diff}ms",
                    fmt_hex_arr(&msg.signer_id)
                );
            }

            // Members messages
            Operation::VoteProposal(operation) => {
                // Reject the newer proposal
                let prop_hash = msg_digest;
                if let Some(vp) = &self.vote_proposal {
                    if vp.hash == prop_hash {
                        // The proposal is just the same we are currently voting on
                        // (there should be no degradation from replay-like attacks)
                        return Ok(Vec::new());
                    }
                    if vp.initiation_time < msg.timestamp {
                        // The currently ongoing vote proposal is older,
                        // ignore the newer one.
                        // TODO: implement better choice logic
                        return Ok(Vec::new());
                    }
                }
                // Of course the proposal can't be from the future.
                let initiation_time = timestamp.max(msg.timestamp);
                let mut votes: HashMap<_, _> = self
                    .nodes
                    .iter()
                    .filter_map(|(node_id, node_entry)| {
                        if node_entry.status != NodeStatus::Member {
                            return None;
                        }
                        Some((node_id.0.clone(), VoteEntry::NotVoted))
                    })
                    .collect();
                votes.insert(msg.signer_id.clone(), VoteEntry::Voted(Descision::Yes));

                // Determine our own descision on the proposal
                let desc = self.decide_vote(&operation, timestamp);

                log::info!(
                    "Incoming proposal to {} by node {} -> {desc:?}",
                    operation.kind_str(),
                    fmt_hex_arr(&msg.signer_id)
                );

                votes.insert(self.node_id.clone(), VoteEntry::Voted(desc));
                let op = Operation::Vote(prop_hash.clone(), desc);

                let Ok(msg) = op.sign(timestamp, &self.node_id, &self.key_pair) else {
                    log::warn!("Couldn't sign vote msg. Ignoring VoteProposal message.");
                    return Ok(Vec::new());
                };

                // Create and store the proposal
                let proposal = VoteProposal {
                    initiator_id: msg.signer_id.clone(),
                    initiation_time,
                    hash: prop_hash,
                    votes,
                    operation,
                };
                self.vote_proposal = Some(proposal);

                // Broadcast our descision
                return Ok(vec![Response::Message(msg, true)]);
            }
            Operation::Vote(proposal_hash, desc) => {
                if let Some(vp) = &mut self.vote_proposal {
                    if proposal_hash != vp.hash {
                        // TODO, same as above, we should maybe keep these in a buffer or such.
                        log::info!(
                            "Hash mismatch of vote and ongoing vote proposal. Ignoring vote."
                        );
                        return Ok(Vec::new());
                    }
                    if let Some(ven) = vp.votes.get_mut(&msg.signer_id) {
                        match *ven {
                            VoteEntry::NotVoted => *ven = VoteEntry::Voted(desc),
                            VoteEntry::Voted(ven_desc) => {
                                if ven_desc != desc {
                                    // Duplicate vote, with different descisions.
                                    // Set to error.
                                    *ven = VoteEntry::VotedBadly;
                                    // TODO lower trust
                                    log::info!("Duplicate vote by the same node with disjunct descision {desc:?} vs earlier {ven_desc:?}.");
                                    return Ok(Vec::new());
                                } else {
                                    // Duplicate vote, but with the same descision. Ignore.
                                    log::info!("Duplicate vote by the same node.");
                                    return Ok(Vec::new());
                                }
                            }
                            // Don't do anything here. Maybe log?
                            VoteEntry::VotedBadly => (),
                        }
                    } else {
                        log::info!(
                            "Node tried to vote even though it wasn't allowed to. Ignoring."
                        );
                        return Ok(Vec::new());
                    }
                } else {
                    // TODO, due to ordering noise, it is possible that votes arrive before proposals.
                    // Therefore, we should instead keep a buffer of these votes and only discard if we have reason to.
                    log::info!(
                        "Got a vote from {} while no vote proposal was active. Ignoring vote.",
                        fmt_hex_arr(&msg.signer_id)
                    );
                    return Ok(Vec::new());
                }
            }
            Operation::EncapsulatedKeys(keys_enc) => {
                // Check that we are in a rekeying state
                if self.state != ManagerState::WaitingForRekeying {
                    log::info!("Didn't expect EncapsulatedKeys message. Ignoring it.");
                    return Ok(Vec::new());
                }
                let Some((_, enc_key)) = keys_enc.iter()
                    .find(|(node_id, _enc_key)| *node_id == self.node_id) else
                {
                    log::info!("Didn't find entry for our node in EncapsulatedKeys msg (cnt = {}), ignoring it.", keys_enc.len());
                    return Ok(Vec::new());
                };

                let Ok(shared_key) = self.key_pair.decrypt(enc_key) else {
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
                if self.is_node_that_does_rekeying(timestamp) {
                    return self.make_rekeying(timestamp);
                }
            }
            Operation::SelfRemove => {
                // Change node entry in node table
                let peer_id = NodeId::from_data(&msg.signer_id);
                if self.nodes.remove(&peer_id).is_none() {
                    log::info!("Couldn't find node for removal. Not doing any removal.");
                    return Ok(Vec::new());
                };
                // Engage in rekeying
                self.state = ManagerState::WaitingForRekeying;
                if self.is_node_that_does_rekeying(timestamp) {
                    return self.make_rekeying(timestamp);
                }
            }
            Operation::KeepAlive(_node_table_hash) => {
                // Update last seen value in node's entry
                let peer_id = NodeId::from_data(&msg.signer_id);
                let Some(nd) = self.nodes.get_mut(&peer_id) else {
                    log::info!("Couldn't find node that pauses membership. Ignoring KeepAlive");
                    return Ok(Vec::new());
                };
                nd.last_seen_time = timestamp;
            }
        }

        Ok(Vec::new())
    }

    fn handle_decided_vote(&mut self, desc: Descision, timestamp: u64) -> Result<Vec<Response>> {
        log::debug!(
            "Descision was reached by {}: {desc:?}",
            fmt_hex_arr(&self.node_id)
        );
        // Descision reached: remove the vote proposal
        let vp = self.vote_proposal.take().unwrap();

        const DELTA_BELIEF: f64 = 0.01;
        const DELTA_DISBELIEF: f64 = 0.4;
        const DELTA_UNCERTAINTY: f64 = 0.2;
        for (nd_id, nd_entry) in self.nodes.iter_mut() {
            if nd_id.0 == self.node_id {
                continue;
            }
            enum ToInc {
                Belief,
                Disbelief,
                Uncertainty,
            }
            let to_inc = if let Some(vt_entry) = vp.votes.get(&nd_id.0) {
                match vt_entry {
                    VoteEntry::Voted(nd_desc) => {
                        if desc == *nd_desc {
                            ToInc::Belief
                        } else {
                            ToInc::Disbelief
                        }
                    }
                    VoteEntry::VotedBadly => ToInc::Disbelief,
                    VoteEntry::NotVoted => ToInc::Uncertainty,
                }
            } else {
                // This can occur if the node joined after the vote started, for example.
                log::info!("Node {nd_id:?} not found in vote table, although even if it didn't vote, it should be in there.");
                ToInc::Uncertainty
            };
            match to_inc {
                ToInc::Belief => nd_entry.trust.inc_belief(DELTA_BELIEF),
                ToInc::Disbelief => nd_entry.trust.inc_disbelief(DELTA_DISBELIEF),
                ToInc::Uncertainty => nd_entry.trust.inc_uncertainty(DELTA_UNCERTAINTY),
            }
            log::debug!(
                "Updating trust for {nd_id:?}: ({}, {}, {}).",
                nd_entry.trust.belief,
                nd_entry.trust.disbelief,
                nd_entry.trust.uncertainty
            );
        }

        if desc == Descision::Yes {
            // Enact the descision, and perform a rekeying (as currently all operations perform removals).
            match vp.operation {
                VoteOperation::Remove(node_to_remove) => {
                    let node_to_remove = NodeId::from_data(&node_to_remove);
                    self.nodes.remove(&node_to_remove);
                }
                VoteOperation::Pause(node_to_pause) => {
                    let node_to_pause = NodeId::from_data(&node_to_pause);
                    let Some(nd) = self.nodes.get_mut(&node_to_pause) else {
                        log::info!("Couldn't find node for pausing. Ignoring vote result.");
                        return Ok(Vec::new());
                    };
                    nd.status = NodeStatus::Paused;
                }
            }
            self.state = ManagerState::WaitingForRekeying;
            if self.is_node_that_does_rekeying(timestamp) {
                return self.make_rekeying(timestamp);
            }
        }
        Ok(Vec::new())
    }
}
