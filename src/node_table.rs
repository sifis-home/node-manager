use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Copy, Clone, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    Member,
    Paused,
    /// A node is waiting to be let in
    ///
    /// We use this status when we add nodes to the table after they show up
    /// with an AddByAdmin message. If we didn't add nodes to the table, their
    /// friends could show up with a EncapsulatedKey message and bypass the
    /// entire entrance mechanism.
    WaitingEntry,
}

#[derive(Clone)]
pub struct NodeEntry {
    pub public_key: RsaPublicKey,
    pub public_key_der: Vec<u8>,
    pub status: NodeStatus,
    // TODO: trust
}
