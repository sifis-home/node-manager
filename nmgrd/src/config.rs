use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Config {
    addr_dht: String,
}
