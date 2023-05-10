//! Utilities for admin devices

use super::{Message, Operation};
use crate::keys::PrivateKey;
use anyhow::Result;

pub(crate) const ADMIN_ID: &[u8] = b"admin";

#[derive(Clone)]
pub struct AdminNode {
    key_pair_der: Vec<u8>,
    key_pair: PrivateKey,
}

impl AdminNode {
    pub fn from_key_pair_der(der: &[u8]) -> Self {
        Self {
            key_pair: PrivateKey::from_pkcs8_der(der).unwrap(),
            key_pair_der: der.to_vec(),
        }
    }
    pub fn sign_addition(&self, node_to_add_der_key: &[u8], timestamp: u64) -> Result<Message> {
        sign_addition(&self.key_pair, node_to_add_der_key, timestamp)
    }
    pub fn public_key_der(&self) -> Vec<u8> {
        let doc = self.key_pair.to_public_key().to_public_key_der().unwrap();
        let sl: &[u8] = doc.as_ref();
        sl.to_owned()
    }
}

pub fn sign_addition(
    key_pair: &PrivateKey,
    node_to_add_der_key: &[u8],
    timestamp: u64,
) -> Result<Message> {
    let op = Operation::AddByAdmin(node_to_add_der_key.to_owned());
    op.sign(timestamp, ADMIN_ID, key_pair)
}
