use crate::config::Config;
use crate::context::Context;
use anyhow::{bail, Context as _, Error};

mod config;
mod context;
mod lobby_network;
mod ws_api;
mod ws_context;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::builder().try_init()?;
    let (cfg, cfg_path) = load_config()?;
    run(cfg, &cfg_path).await?;
    Ok(())
}

fn load_config() -> Result<(Config, String), Error> {
    let Some(cfg_file_path) = std::env::args().nth(1) else {
        bail!("Please specify path to config.toml on the command line");
    };
    let cfg_file_str = std::fs::read_to_string(&cfg_file_path)
        .with_context(|| format!("Failed to read config file from {cfg_file_path}"))?;
    let cfg: Config = toml::from_str(&cfg_file_str)?;
    if let Err(errs) = cfg.validate() {
        let errs_string = errs.join("\n");
        bail!("Invalid config file due to the following errors: \n{errs_string}");
    }
    Ok((cfg, cfg_file_path))
}

#[allow(unused)]
async fn run(cfg: Config, cfg_path: &str) -> Result<(), Error> {
    let mut ctx = Context::start(cfg, cfg_path).await?;

    // main loop
    loop {
        ctx.run_loop_iter().await?;
    }

    Ok(())
}
