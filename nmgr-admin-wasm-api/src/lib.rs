use base64ct::{Base64, Encoding};
use node_manager::admin::sign_addition;
use node_manager::keys::PrivateKey;
use rand_chacha::rand_core::SeedableRng;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsError;

#[wasm_bindgen]
pub struct AdminKey {
    key: PrivateKey,
}

#[wasm_bindgen]
impl AdminKey {
    pub fn from_pem(pem: &str) -> Result<AdminKey, JsError> {
        // TODO don't use unwrap here but ?
        let key = PrivateKey::from_pkcs8_pem(pem).unwrap();
        Ok(Self { key })
    }
    pub fn generate_from_buffer(buf: &[u8]) -> Result<AdminKey, JsError> {
        // TODO don't use unwrap here but ?
        // TODO hash the buffer first with sha256
        let mut seed = [0; 32];
        for (si, bi) in seed.iter_mut().zip(buf.iter()) {
            *si = *bi;
        }
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        let key = PrivateKey::generate_ed25519_rng(&mut rng);
        Ok(Self { key })
    }
    pub fn as_pem(&self) -> Result<String, JsError> {
        // TODO don't use unwrap here but ?
        let pem = self.key.to_pkcs8_pem().unwrap();
        Ok(pem)
    }
    pub fn sign_node_public_key(
        &self,
        timestamp: u64,
        node_public_key_b64: &str,
        _buf: &[u8],
    ) -> Result<String, JsError> {
        let node_public_key_der = Base64::decode_vec(node_public_key_b64)?;
        // TODO don't use unwrap here but ?
        let msg = sign_addition(&self.key, &node_public_key_der, timestamp).unwrap();
        let msg_buf = msg.serialize();
        Ok(Base64::encode_string(&msg_buf))
    }
}

#[wasm_bindgen]
pub fn set_panic_hook() {
    console_error_panic_hook::set_once();
}
