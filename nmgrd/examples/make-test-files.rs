use anyhow::Result;
use base64ct::{Base64, Encoding};
use node_manager::admin::AdminNode;
use node_manager::keys::PrivateKey;
use node_manager::timestamp;
use serde::Serialize;
use std::fs::write as write_file;
use std::str::FromStr;

#[derive(Serialize)]
struct Config {
    dht_url: String,
    admin_key: String,
    priv_key: String,
    admin_join_msg: String,
    lobby_key: String,
    shared_key: Option<String>,
    lobby_loopback_only: bool,
}

const INIT_SHARED_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn make_test_files(count: u16, dir: &str) -> Result<()> {
    let admin_key = PrivateKey::generate_ed25519();
    let admin_key_der = admin_key.to_pkcs8_der().unwrap();
    let admin_key_public_pem = admin_key.to_public_key().to_pkcs8_pem().unwrap();
    let admin_node = AdminNode::from_key_pair_der(&admin_key_der);
    for i in 0..count {
        let priv_key = PrivateKey::generate_ed25519();
        let node_key_pub_der = priv_key.to_public_key().to_public_key_der().unwrap();
        let admin_join_msg_buf = admin_node
            .sign_addition(&node_key_pub_der, timestamp().unwrap())
            .unwrap()
            .serialize();
        let admin_join_msg = Base64::encode_string(&admin_join_msg_buf);
        let shared_key = (i == 0).then(|| INIT_SHARED_KEY.to_string());
        let cfg = Config {
            dht_url: "ws://127.0.0.1:3000/ws".into(),
            admin_key: admin_key_public_pem.clone(),
            priv_key: priv_key.to_pkcs8_pem().unwrap(),
            admin_join_msg,
            lobby_key: "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1fffff".into(),
            shared_key,
            // Don't enable loopback only mode. It doesn't work (no peers are being discovered).
            lobby_loopback_only: false,
        };
        let cfg_toml = toml::to_string(&cfg)?;
        write_file(format!("{dir}/config-{i:02}.toml"), cfg_toml)?;
    }
    Ok(())
}

fn main() {
    let count = std::env::args()
        .nth(1)
        .and_then(|n_str| u16::from_str(&n_str).ok())
        .unwrap_or(5);
    let dir = std::env::args().nth(2).unwrap_or_else(|| ".".to_string());
    make_test_files(count, &dir).unwrap();
}
