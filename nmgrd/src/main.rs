use crate::config::Config;
use crate::context::Context;
use anyhow::{bail, Context as _, Error};
use tokio::io::AsyncBufReadExt;

mod config;
mod context;
mod lobby_network;
mod ws_api;
mod ws_context;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::builder().try_init()?;
    let (cfg, _cfg_path) = load_config()?;
    run(cfg).await?;
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

async fn run(cfg: Config) -> Result<(), Error> {
    let debug_console = cfg.debug_console() || std::env::var("NMGR_DEBUG_CONSOLE").is_ok();
    let mut ctx = Context::start(cfg).await?;

    // main loop
    if !debug_console {
        loop {
            ctx.run_loop_iter().await?;
        }
    } else {
        // TODO: This might not be 100% optimal as for interactive uses, tokio docs
        // recommend using a synchronous thread instead of Stdin.
        let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        println!("Debug console active. Enter an invalid command to get a command listing.");
        loop {
            tokio::select! {
                line = stdin.next_line() => {
                    handle_input_line(line, &mut ctx).await;
                },
                r = ctx.run_loop_iter() => {
                    r?;
                },
            }
        }
    }
}

async fn handle_input_line(line: std::io::Result<Option<String>>, ctx: &mut Context) {
    let line = match line {
        Err(_) | Ok(None) => return,
        Ok(Some(s)) => s,
    };

    let mut args = line.split(' ');

    let cmd = args.next().unwrap();

    match cmd {
        "info" | "i" | "t" | "td" => {
            let detail = match args.next() {
                Some("d" | "detail") => true,
                Some(v) => {
                    println!("error: wrong parameter '{v}'. Must be 'd' or 'detail'.");
                    false
                }
                None => false,
            };
            let detail = detail || cmd == "td";
            let node = &ctx.node;
            let ts = node_manager::timestamp().unwrap();
            println!(
                "Own node manager ID: {}",
                context::fmt_hex_arr(node.node_id())
            );
            println!("Shared key: {}", context::fmt_hex_arr(node.shared_key()));
            if detail {
                println!("Node manager table:\n{}", node.table_str_ext(ts));
            } else {
                println!("Node manager table: {}", node.table_str());
            }
            println!(
                "Connected to DHT: {}",
                if ctx.connected_to_dht() { "Yes" } else { "No" }
            );
            println!("Own lobby ID: {}", ctx.lobby_local_peer_id_display());
            println!("Lobby peers: {}", ctx.lobby_peer_table_str());
        }
        "config" | "c" => {
            println!("Configuration toml:");
            println!("{}", toml::to_string(ctx.config()).unwrap());
        }
        "pause" | "p" => {
            ctx.self_pause().await.unwrap();
        }
        "rejoin" | "r" => {
            ctx.self_rejoin().await.unwrap();
        }
        "ping" => {
            let for_members_network = match args.next() {
                Some(s) if s.to_lowercase() == "lobby" => false,
                Some(s) if s.to_lowercase() == "members" => true,
                Some(s) => {
                    println!(
                        "error: wrong network specifier '{s}' for ping. \
                        Need to be either 'lobby' or 'members'."
                    );
                    true
                }
                None => true,
            };
            ctx.send_ping(for_members_network).await.unwrap();
        }
        // TODO turn this into an if-let guard once those are stable
        "start-vote" => {
            if let Some(id_str) = args.next() {
                let partial_id = parse_hex(id_str);
                let Some(partial_id) = partial_id else {
                    println!("invalid hex array: '{id_str}'");
                    return
                };
                let id_opt = ctx.node.complete_node_id(&partial_id);
                if let Some(id) = id_opt {
                    ctx.start_vote(&id).await.unwrap();
                } else {
                    println!("error: couldn't find node id '{id_str}' or it was not unique");
                }
            } else {
                println!("error: start-vote command missing an argument.");
            }
        }
        _ => {
            println!("Commands:");
            println!("info|i|t");
            println!("pause|p");
            println!("rejoin|r");
            println!("ping (lobby|members|)");
            println!("start-vote <id>");
        }
    }
}

// We cannot use config::parse_hex_key here because it expects a certain length
fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let mut res = Vec::new();
    for v in 0..(s.len() / 2) {
        let byte_str = s.get((v * 2)..)?.get(..2)?;
        let byte = u8::from_str_radix(byte_str, 16).ok()?;
        res.push(byte);
    }
    Some(res)
}

#[tokio::test]
#[cfg(test)]
async fn simple_test_run() {
    // Just to ensure that one run of the loop does not cause any errors.
    const CFG: &str = r#"
    # Admin key:
    # /csvh/PjgRobztEuThwVb/EG3mUJ8oRW1g0na/w6mHPX3r/SEmRqFyMb0jzHar2iikZbN944S4/CiMoVnW/CtA==
    dht_url = "ws://127.0.0.1:32101/ws"
    admin_key = "IAAAAAAAAACsAMnUq3dqX8BeRXkLaPCEfWubkD74Tt5IYglkJwflUNfev9ISZGoXIxvSPMdqvaKKRls33jhLj8KIyhWdb8K0"
    priv_key = "l7ZUIqe4fyMrpmqQ5Fhz1w4PlGraid/rP2NbAKjcRmulgZxO9pH/u3jbXwICz/C6aC2BmGLlpUy2n8YjRWHItw=="
    admin_join_msg = "MvRYs4gBAAAFAAAAAAAAAGFkbWluQAAAAAAAAACJUBWRW5/Dq2ioi0GkoMSju03huDfqVbVyg85v1ldacq0sBoyb/riSS5OTeZguC0Dz5EiwSZeEA2aqddvbKLAGAAAAAEgAAAAAAAAAIAAAAAAAAAAYtsDUPGmkwq2Q/tgovIpvovfgDqJ1INPrFy1x6gnnfaWBnE72kf+7eNtfAgLP8LpoLYGYYuWlTLafxiNFYci3"
    lobby_key = "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1fffff"
    shared_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    lobby_loopback_only = true
    "#;

    let cfg: Config = toml::from_str(CFG).unwrap();
    let mut ctx = Context::start(cfg).await.unwrap();
    ctx.run_loop_iter().await.unwrap();
}
