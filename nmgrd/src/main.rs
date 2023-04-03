pub use crate::config::Config;
use anyhow::{bail, Error};
use node_manager::NodeManager;

mod config;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cfg = load_config()?;
    run(cfg).await?;
    Ok(())
}

fn load_config() -> Result<Config, Error> {
    let Some(cfg_file_path) = std::env::args().nth(1) else {
        bail!("Please specify path to config.toml on the command line");
    };
    let cfg_file_str = std::fs::read_to_string(cfg_file_path)?;
    let cfg = toml::from_str(&cfg_file_str)?;
    Ok(cfg)
}

async fn run(cfg: Config) -> Result<(), Error> {
    Ok(())
}
