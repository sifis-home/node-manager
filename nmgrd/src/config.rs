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
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }
}
