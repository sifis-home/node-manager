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

#[derive(Clone, Copy, Debug)]
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

fn inc_val(delta: f64, v_to_inc: &mut f64, v1: &mut f64, v2: &mut f64) {
    let delta = delta.min(1.0 - *v_to_inc);
    *v_to_inc += delta;
    let dh = delta / 2.0;
    match (*v1 >= dh, *v2 >= dh) {
        (true, true) => {
            *v1 -= dh;
            *v2 -= dh;
        }
        (true, false) => {
            let v2_val = *v2;
            *v2 = 0.0;
            // TODO this should not make v1 be smaller than 0.0, but maybe add an assertion?
            *v1 -= delta - v2_val;
        }
        (false, true) => {
            let v1_val = *v1;
            *v1 = 0.0;
            // TODO this should not make v2 be smaller than 0.0, but maybe add an assertion?
            *v2 -= delta - v1_val;
        }
        (false, false) => {
            // This actually shouldn't happen, as we ensured that delta <= (1.0 - *v_to_inc)
            // which as per precondition of the vector being L1-normal is equal to v1 + v2.
            // TODO print an error or something
        }
    }
    // TODO this isn't it: it reduces too little if one of the two values are below
    let max_reduce = (delta / 2.0).min(v1.max(*v2));
    *v1 = (*v1 - max_reduce).max(0.0);
    *v2 -= (*v2 - max_reduce).max(0.0);
}

impl JosangTrust {
    pub fn inc_belief(&mut self, d_b: f64) {
        inc_val(
            d_b,
            &mut self.belief,
            &mut self.uncertainty,
            &mut self.disbelief,
        );
    }
    pub fn inc_disbelief(&mut self, d_d: f64) {
        inc_val(
            d_d,
            &mut self.disbelief,
            &mut self.uncertainty,
            &mut self.belief,
        );
    }
    pub fn inc_uncertainty(&mut self, d_u: f64) {
        let d_u = d_u.min(1.0 - self.uncertainty);
        self.belief -= d_u;
        self.uncertainty += d_u;
    }
    pub fn reputation(&self) -> f64 {
        self.belief - self.disbelief - self.uncertainty
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
