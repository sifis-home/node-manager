use super::NodeId;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

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
    pub last_seen_time: u64,
    // TODO: trust
}

pub type NodeTable = HashMap<NodeId, NodeEntry>;

pub fn from_data(data: &[u8], timestamp: u64) -> Result<NodeTable, Box<dyn Error>> {
    let nodes_list: Vec<(NodeId, (Vec<u8>, NodeStatus))> = bincode::deserialize(data)?;
    let nodes = nodes_list
        .into_iter()
        .map(|(id, (public_key_der, status))| {
            let tuple = (
                id,
                NodeEntry {
                    public_key: RsaPublicKey::from_public_key_der(&public_key_der).unwrap(),
                    public_key_der,
                    status,
                    last_seen_time: timestamp,
                },
            );
            Ok(tuple)
        })
        .collect::<Result<HashMap<NodeId, NodeEntry>, Box<dyn Error>>>()?;
    Ok(nodes)
}

pub fn serialize(this: &NodeTable) -> Result<Vec<u8>, Box<dyn Error>> {
    let nodes_vec = this
        .iter()
        .map(
            |(
                id,
                NodeEntry {
                    public_key_der,
                    public_key: _,
                    status,
                    last_seen_time: _,
                },
            )| (id, public_key_der, status),
        )
        .collect::<Vec<_>>();
    Ok(bincode::serialize(&nodes_vec)?)
}

pub(crate) fn table_str(nodes: &NodeTable) -> String {
    let mut res = String::new();
    for (nd, nd_entry) in nodes.iter() {
        use std::fmt::Write;
        write!(
            res,
            "({}; {:?}), ",
            super::fmt_hex_arr(&nd.0),
            nd_entry.status
        )
        .unwrap();
    }
    res
}
