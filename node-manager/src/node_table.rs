use super::NodeId;
use crate::PublicKey;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

#[derive(Clone, Copy)]
pub struct JosangTrust {
    pub belief: f64,
    pub disbelief: f64,
    pub uncertainty: f64,
}

impl Default for JosangTrust {
    fn default() -> Self {
        Self {
            belief: 1.0,
            disbelief: 0.0,
            uncertainty: 0.0,
        }
    }
}

impl JosangTrust {
    pub fn inc_belief(&mut self, d_b: f64) {
        self.belief += d_b;
        self.uncertainty -= d_b / 2.0;
        self.disbelief -= d_b / 2.0;
    }
    pub fn inc_disbelief(&mut self, d_d: f64) {
        self.disbelief += d_d;
        self.uncertainty -= d_d / 2.0;
        self.belief -= d_d / 2.0;
    }
    pub fn inc_uncertainty(&mut self, d_u: f64) {
        self.belief -= d_u;
        self.uncertainty += d_u;
    }
}

#[derive(Clone)]
pub struct NodeEntry<T> {
    pub public_key: PublicKey,
    pub public_key_der: Vec<u8>,
    pub status: NodeStatus,
    pub last_seen_time: u64,
    pub trust: T,
}

pub type NodeTable<T> = HashMap<NodeId, NodeEntry<T>>;

pub fn from_data<T: Default>(data: &[u8], timestamp: u64) -> Result<NodeTable<T>> {
    let nodes_list: Vec<(NodeId, (Vec<u8>, NodeStatus))> = bincode::deserialize(data)?;
    let nodes = nodes_list
        .into_iter()
        .map(|(id, (public_key_der, status))| {
            let tuple = (
                id,
                NodeEntry {
                    public_key: PublicKey::from_public_key_der(&public_key_der)?,
                    public_key_der,
                    status,
                    last_seen_time: timestamp,
                    trust: Default::default(),
                },
            );
            Ok(tuple)
        })
        .collect::<Result<HashMap<NodeId, NodeEntry<T>>>>()?;
    Ok(nodes)
}

pub fn serialize<T>(this: &NodeTable<T>) -> Result<Vec<u8>> {
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
                    trust: _,
                },
            )| (id, public_key_der, status),
        )
        .collect::<Vec<_>>();
    Ok(bincode::serialize(&nodes_vec)?)
}

pub(crate) fn table_str<T>(nodes: &NodeTable<T>) -> String {
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
