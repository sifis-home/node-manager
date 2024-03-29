use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use toml_edit::Document;
use url::Url;

const KEY_SIZE: usize = node_manager::SHARED_KEY_LEN;

pub(crate) fn parse_hex_key(s: &str) -> Result<[u8; KEY_SIZE], String> {
    if s.len() == KEY_SIZE * 2 {
        let mut r = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            let ret = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16);
            match ret {
                Ok(res) => {
                    r[i] = res;
                }
                Err(_e) => return Err(String::from("Error while parsing")),
            }
        }
        Ok(r)
    } else {
        Err(format!(
            "Len Error: expected {} but got {}",
            KEY_SIZE * 2,
            s.len()
        ))
    }
}

#[derive(Deserialize, Serialize)]
pub struct RekeyingPath {
    file: String,
    config: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    dht_url: String,

    admin_key_path: Option<String>,
    admin_key: Option<String>,

    priv_key_path: Option<String>,
    priv_key: Option<String>,

    admin_join_msg_path: Option<String>,
    admin_join_msg: Option<String>,

    #[serde(default)]
    rekeying_cfg_paths: Vec<RekeyingPath>,

    lobby_key: String,

    shared_key: Option<String>,

    #[serde(default)]
    lobby_loopback_only: bool,

    #[serde(default)]
    no_auto_first_node: bool,

    #[serde(default)]
    no_self_auto_pause: bool,

    #[serde(default)]
    try_rejoin_on_pause: bool,

    #[serde(default)]
    debug_console: bool,

    #[serde(default)]
    auto_start_vote_on_suggestion: bool,

    #[serde(default)]
    no_ip_publishing: bool,

    #[serde(default)]
    pub debug_sometimes_send_keepalive: bool,

    #[serde(default)]
    pub debug_sometimes_vote_wrongly: bool,
}

impl Config {
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();

        // Some basic validation check of the URL.
        // Of course the final test is if connecting to the URL actually works.
        if let Err(err) = Url::parse(&self.dht_url) {
            errs.push(format!("DHT url parsing error: {err:?}"));
        }

        if self.admin_key.is_none() && self.admin_key_path.is_none() {
            errs.push("Neither admin_key nor admin_key_path specified".to_owned());
        }
        if self.admin_key.is_some() && self.admin_key_path.is_some() {
            errs.push(
                "Both admin_key and admin_key_path specified, please specify only one".to_owned(),
            );
        }

        if self.priv_key.is_none() && self.priv_key_path.is_none() {
            errs.push("Neither priv_key nor priv_key_path specified".to_owned());
        }
        if self.priv_key.is_some() && self.priv_key_path.is_some() {
            errs.push(
                "Both priv_key and priv_key_path specified, please specify only one".to_owned(),
            );
        }

        if self.admin_join_msg.is_none() && self.admin_join_msg_path.is_none() {
            errs.push("Neither admin_join_msg nor admin_join_msg_path specified".to_owned());
        }
        if self.admin_join_msg.is_some() && self.admin_join_msg_path.is_some() {
            errs.push(
                "Both admin_join_msg and admin_join_msg_path specified, please specify only one"
                    .to_owned(),
            );
        }

        if let Err(err) = parse_hex_key(&self.lobby_key) {
            errs.push(format!("Can't parse hex shared key: {err}"));
        }

        if let Some(shared_key) = &self.shared_key {
            if let Err(err) = parse_hex_key(shared_key) {
                errs.push(format!("Can't parse hex lobby key: {err}"));
            }
        }

        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    pub fn dht_url(&self) -> &str {
        &self.dht_url
    }

    pub fn admin_key(&self) -> Result<String, anyhow::Error> {
        if let Some(admin_key) = &self.admin_key {
            return Ok(admin_key.clone());
        }
        if let Some(admin_key_path) = &self.admin_key_path {
            let admin_key_str = read_to_string(admin_key_path)?;
            return Ok(admin_key_str);
        }
        panic!("Invalid config: admin_key or admin_key_path required.");
    }

    pub fn priv_key(&self) -> Result<String, anyhow::Error> {
        if let Some(priv_key) = &self.priv_key {
            return Ok(priv_key.clone());
        }
        if let Some(priv_key_path) = &self.priv_key_path {
            let priv_key_str = read_to_string(priv_key_path)?;
            return Ok(priv_key_str);
        }
        panic!("Invalid config: priv_key or priv_key_path required.");
    }

    pub fn admin_join_msg(&self) -> Result<String, anyhow::Error> {
        if let Some(admin_join_msg) = &self.admin_join_msg {
            return Ok(admin_join_msg.clone());
        }
        if let Some(admin_join_msg_path) = &self.admin_join_msg_path {
            let admin_join_msg_str = read_to_string(admin_join_msg_path)?;
            return Ok(admin_join_msg_str);
        }
        panic!("Invalid config: admin_join_msg or admin_join_msg_path required.");
    }

    pub fn rekeying_cfg_paths(&self) -> &[RekeyingPath] {
        &self.rekeying_cfg_paths
    }

    pub fn lobby_key(&self) -> [u8; KEY_SIZE] {
        // We unwrap here because the error should have been caught by validate(),
        // and if the user didn't call it before, it's an usage error.
        parse_hex_key(&self.lobby_key).expect("Hex key parsing error")
    }

    pub fn shared_key(&self) -> Option<[u8; KEY_SIZE]> {
        if let Some(key) = &self.shared_key {
            // We unwrap here because the error should have been caught by validate(),
            // and if the user didn't call it before, it's an usage error.
            let key = parse_hex_key(key).expect("Hex key parsing error");
            Some(key)
        } else {
            None
        }
    }
    pub fn lobby_loopback_only(&self) -> bool {
        self.lobby_loopback_only
    }
    pub fn no_auto_first_node(&self) -> bool {
        self.no_auto_first_node
    }
    pub fn no_self_auto_pause(&self) -> bool {
        self.no_self_auto_pause
    }
    pub fn try_rejoin_on_pause(&self) -> bool {
        self.try_rejoin_on_pause
    }
    pub fn debug_console(&self) -> bool {
        self.debug_console
    }
    pub fn auto_start_vote_on_suggestion(&self) -> bool {
        self.auto_start_vote_on_suggestion
    }
    pub fn no_ip_publishing(&self) -> bool {
        self.no_ip_publishing
    }
}

pub fn set_new_key_for_path(path: &RekeyingPath, key: &[u8]) -> Result<()> {
    let config = path.config.as_deref().unwrap_or("shared_key");
    let file_str = read_to_string(&path.file)?;
    let mut doc = file_str.parse::<Document>()?;

    let hex_key = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let members = config.split('.');
    let mut view = doc.as_item_mut();
    for member in members {
        if view.is_none() {
            *view = toml_edit::Item::Table(toml_edit::Table::new());
        }
        view = &mut view[member];
    }
    if view.as_str() == Some(&hex_key) {
        // Nothing to do, the key we want to set is already the one present in the file
        return Ok(());
    }
    *view = toml_edit::value(hex_key);

    std::fs::write(&path.file, doc.to_string())?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use toml::from_str;

    #[test]
    fn test_loading_valid() {
        let st = r#"
            dht_url = "ws://localhost:3000"
            admin_key_path = "/path/to/admin-pub-key.pem"
            priv_key_path = "/path/to/admin-pub-key.pem"
            admin_join_msg_path = "/path/to/admin-join-msg.base64"
            lobby_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "#;
        let cfg: Config = from_str(st).unwrap();
        cfg.validate().unwrap();

        let st = r#"
            dht_url = "ws://localhost:3000"
            admin_key_path = "/path/to/admin-pub-key.pem"
            priv_key_path = "/path/to/admin-pub-key.pem"
            admin_join_msg_path = "/path/to/admin-join-msg.base64"
            lobby_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            rekeying_cfg_paths = [{ file = "/path/1.toml" }, { file = "/path/2.toml", config = "hi.hello" }]
            shared_key = "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            lobby_loopback_only = false
            no_auto_first_node = true
        "#;
        let cfg: Config = from_str(st).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn test_loading_invalid() {
        let st = r#"
            dht_url = "ws://localhost:3000"
            #admin_key_path = "/path/to/admin-pub-key.pem"
            priv_key_path = "/path/to/admin-pub-key.pem"
            admin_join_msg_path = "/path/to/admin-join-msg.base64"
            lobby_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "#;
        let cfg: Config = from_str(st).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert_eq!(errs.len(), 1);

        let st = r#"
            dht_url = "ws://localhost:3000"
            admin_key_path = "/path/to/admin-pub-key.pem"
            #priv_key_path = "/path/to/admin-pub-key.pem"
            admin_join_msg_path = "/path/to/admin-join-msg.base64"
            lobby_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "#;
        let cfg: Config = from_str(st).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert_eq!(errs.len(), 1);

        let st = r#"
            dht_url = "ws://localhost:3000"
            #admin_key_path = "/path/to/admin-pub-key.pem"
            #priv_key_path = "/path/to/admin-pub-key.pem"
            admin_join_msg_path = "/path/to/admin-join-msg.base64"
            lobby_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "#;
        let cfg: Config = from_str(st).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert_eq!(errs.len(), 2);

        let st = r#"
            dht_url = "ws://localhost:3000"
            admin_key_path = "/path/to/admin-pub-key.pem"
            priv_key_path = "/path/to/admin-pub-key.pem"
            admin_join_msg_path = "/path/to/admin-join-msg.base64"
            lobby_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            shared_key = "invalid"
        "#;
        let cfg: Config = from_str(st).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert_eq!(errs.len(), 1);

        let st = r#"
            dht_url = "ws://localhost:3000"
            admin_key_path = "/path/to/admin-pub-key.pem"
            priv_key_path = "/path/to/admin-pub-key.pem"
            admin_join_msg_path = "/path/to/admin-join-msg.base64"
            lobby_key = "invalid"
        "#;
        let cfg: Config = from_str(st).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert_eq!(errs.len(), 1);

        let st = r#"
            dht_url = "definitely not an URL :)"
            admin_key_path = "/path/to/admin-pub-key.pem"
            priv_key_path = "/path/to/admin-pub-key.pem"
            admin_join_msg_path = "/path/to/admin-join-msg.base64"
            lobby_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "#;
        let cfg: Config = from_str(st).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert_eq!(errs.len(), 1);
    }
}
