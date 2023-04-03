use serde::{Deserialize, Serialize};

const KEY_SIZE: usize = node_manager::SHARED_KEY_LEN;

fn parse_hex_key(s: &str) -> Result<[u8; KEY_SIZE], String> {
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
        Err(String::from("Len Error"))
    }
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    addr_dht: String,
    admin_key_path: Option<String>,
    admin_key: Option<String>,
    priv_key_path: Option<String>,
    priv_key: Option<String>,
    shared_key: Option<String>,
}

impl Config {
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
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
        if let Some(shared_key) = &self.shared_key {
            if let Err(err) = parse_hex_key(shared_key) {
                errs.push(format!("Can't parse hex key: {err}"));
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }
    pub fn admin_key(&self) -> Result<String, anyhow::Error> {
        if let Some(admin_key) = &self.admin_key {
            return Ok(admin_key.clone());
        }
        if let Some(admin_key_path) = &self.admin_key_path {
            let admin_key_str = std::fs::read_to_string(admin_key_path)?;
            return Ok(admin_key_str);
        }
        panic!("Invalid config: admin_key or admin_key_path required.");
    }
    pub fn priv_key(&self) -> Result<String, anyhow::Error> {
        if let Some(priv_key) = &self.priv_key {
            return Ok(priv_key.clone());
        }
        if let Some(priv_key_path) = &self.priv_key_path {
            let priv_key_str = std::fs::read_to_string(priv_key_path)?;
            return Ok(priv_key_str);
        }
        panic!("Invalid config: priv_key or priv_key_path required.");
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
}

#[cfg(test)]
mod test {
    use super::*;
    use toml::from_str;

    #[test]
    fn test_loading_valid() {
        let st = r#"
            addr_dht = "Hi"
            admin_key_path = "/path/to/admin-pub-key.pem"
            priv_key_path = "/path/to/admin-pub-key.pem"
        "#;
        let cfg: Config = from_str(st).unwrap();
        cfg.validate().unwrap();

        let st = r#"
            addr_dht = "Hi"
            admin_key_path = "/path/to/admin-pub-key.pem"
            priv_key_path = "/path/to/admin-pub-key.pem"
            shared_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "#;
        let cfg: Config = from_str(st).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn test_loading_invalid() {
        let st = r#"
            addr_dht = "Hi"
            #admin_key_path = "/path/to/admin-pub-key.pem"
            priv_key_path = "/path/to/admin-pub-key.pem"
        "#;
        let cfg: Config = from_str(st).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert_eq!(errs.len(), 1);

        let st = r#"
            addr_dht = "Hi"
            admin_key_path = "/path/to/admin-pub-key.pem"
            #priv_key_path = "/path/to/admin-pub-key.pem"
        "#;
        let cfg: Config = from_str(st).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert_eq!(errs.len(), 1);

        let st = r#"
            addr_dht = "Hi"
            #admin_key_path = "/path/to/admin-pub-key.pem"
            #priv_key_path = "/path/to/admin-pub-key.pem"
        "#;
        let cfg: Config = from_str(st).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert_eq!(errs.len(), 2);

        let st = r#"
            addr_dht = "Hi"
            admin_key_path = "/path/to/admin-pub-key.pem"
            priv_key_path = "/path/to/admin-pub-key.pem"
            shared_key = "invalid"
        "#;
        let cfg: Config = from_str(st).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert_eq!(errs.len(), 1);
    }
}
