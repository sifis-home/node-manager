pub use crate::config::Config;
use anyhow::{bail, Error};
use node_manager::keys::priv_key_pem_to_der;
use node_manager::{NodeManager, NodeManagerBuilder};
use sha2::{Digest, Sha256};

mod config;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::builder().try_init()?;
    let cfg = load_config()?;
    run(cfg).await?;
    Ok(())
}

fn load_config() -> Result<Config, Error> {
    let Some(cfg_file_path) = std::env::args().nth(1) else {
        bail!("Please specify path to config.toml on the command line");
    };
    let cfg_file_str = std::fs::read_to_string(cfg_file_path)?;
    let cfg: Config = toml::from_str(&cfg_file_str)?;
    if let Err(errs) = cfg.validate() {
        let errs_string = errs.join("\n");
        bail!("Invalid config file due to the following errors: \n{errs_string}");
    }
    Ok(cfg)
}

async fn run(cfg: Config) -> Result<(), Error> {
    fn id_gen_fn(data: &[u8]) -> Result<Vec<u8>, ()> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let bytes = hasher.finalize()[..8].to_vec();
        Ok(bytes)
    }

    let key_pem = cfg.priv_key()?;
    let key_der = priv_key_pem_to_der(&key_pem);
    let mut builder = NodeManagerBuilder::new(&key_der, id_gen_fn);

    if let Some(key) = cfg.shared_key() {
        builder = builder.shared_key(key.to_vec());
    }

    Ok(())
}
