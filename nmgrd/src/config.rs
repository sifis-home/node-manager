use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Config {
    addr_dht: String,
    admin_key_path: Option<String>,
    admin_key: Option<String>,
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
        "#;
        let cfg: Config = from_str(st).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn test_loading_invalid() {
        let st = r#"
            addr_dht = "Hi"
            # missing admin_key_path
        "#;
        let cfg: Config = from_str(st).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert_eq!(errs.len(), 1);
    }
}
