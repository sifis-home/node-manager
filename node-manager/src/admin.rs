//! Utilities for admin devices

use super::{Message, Operation};
use crate::keys::PrivateKey;
use std::error::Error;

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
    pub fn sign_addition(
        &self,
        node_to_add_der_key: &[u8],
        timestamp: u64,
    ) -> Result<Message, Box<dyn Error>> {
        let op = Operation::AddByAdmin(node_to_add_der_key.to_owned());
        op.sign(timestamp, ADMIN_ID, &self.key_pair)
    }
    pub fn public_key_der(&self) -> Vec<u8> {
        let doc = self.key_pair.to_public_key().to_public_key_der().unwrap();
        let sl: &[u8] = doc.as_ref();
        sl.to_owned()
    }
}
