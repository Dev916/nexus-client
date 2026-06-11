//! `nexus-client` — attach a self-hosted LLM to the GNN compute network.
//!
//! T5 scope: the `init` / `status` lifecycle plus key + config management.
//! `start` (pull loop + upstream forward) and `earnings` are stubbed and
//! exit 2 with "not implemented" for now — they land in T6 / later.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use nexus_client::config::{self, Config};
use nexus_client::keys::{
    NodeKey, generate_wallet, load_wallet_pubkey, node_key_exists, save_wallet,
};
use nexus_client::run::{self, SessionOutcome};

/// Default client directory (`~/.nexus-client`) when `--dir` is omitted.
fn default_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".nexus-client")
}

#[derive(Parser)]
#[command(
    name = "nexus-client",
    about = "Attach a self-hosted LLM to the GNN compute network and earn GNN.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a client dir: generate node key + wallet, write config.
    Init {
        /// Client directory (default: ~/.nexus-client).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Model this node will serve.
        #[arg(long, default_value = config::DEFAULT_MODEL)]
        model: String,
        /// Wallet source: `new` to generate one (only `new` supported in T5).
        #[arg(long, default_value = "new")]
        wallet: String,
    },
    /// Print this client's configured model + endpoints + node pubkey.
    Status {
        /// Client directory (default: ~/.nexus-client).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Connect to the gateway and serve jobs (not implemented in T5).
    Start {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show earnings for this node — GETs the gateway's earnings endpoint
    /// for this node's pubkey and prints lifetime / unpaid GNN + last payout.
    Earnings {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { dir, model, wallet } => {
            let dir = dir.unwrap_or_else(default_dir);
            cmd_init(dir, model, wallet)
        }
        Command::Status { dir } => {
            let dir = dir.unwrap_or_else(default_dir);
            cmd_status(dir)
        }
        Command::Start { dir } => {
            let dir = dir.unwrap_or_else(default_dir);
            cmd_start(dir)
        }
        Command::Earnings { dir } => {
            let dir = dir.unwrap_or_else(default_dir);
            cmd_earnings(dir)
        }
    }
}

/// Format a micros amount as GNN with 6 decimal places (1 GNN = 1_000_000
/// micros). e.g. `4_000_000` → `"4.000000"`, `999_999` → `"0.999999"`.
fn fmt_gnn(micros: i64) -> String {
    let whole = micros / 1_000_000;
    let frac = (micros % 1_000_000).abs();
    format!("{whole}.{frac:06}")
}

/// `earnings`: load config + node key from the client dir, derive the
/// gateway's HTTP origin from its WS URL, GET
/// `/api/compute/nodes/{node_pubkey}/earnings`, and pretty-print lifetime /
/// unpaid GNN plus the last payout line. Refuses an uninitialized dir
/// (exit 1) and exits 1 on a network / non-2xx error.
fn cmd_earnings(dir: PathBuf) -> ExitCode {
    if !node_key_exists(&dir) {
        eprintln!("not initialized: {} (run `nexus-client init`)", dir.display());
        return ExitCode::FAILURE;
    }
    let cfg = match Config::load(&dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to read config: {e}");
            return ExitCode::FAILURE;
        }
    };
    let node_pubkey = match NodeKey::load(&dir) {
        Ok(k) => k.pubkey_base58(),
        Err(e) => {
            eprintln!("failed to read node key: {e}");
            return ExitCode::FAILURE;
        }
    };

    let origin = cfg.gateway_http_origin();
    let url = format!("{origin}/api/compute/nodes/{node_pubkey}/earnings");

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result: Result<serde_json::Value, String> = runtime.block_on(async {
        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("request to {url} failed: {e}"))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("reading response body failed: {e}"))?;
        if !status.is_success() {
            return Err(format!("gateway returned {status}: {body}"));
        }
        serde_json::from_str::<serde_json::Value>(&body)
            .map_err(|e| format!("invalid JSON from gateway: {e} (body: {body})"))
    });

    let earnings = match result {
        Ok(v) => v,
        Err(e) => {
            eprintln!("earnings: {e}");
            return ExitCode::FAILURE;
        }
    };

    let lifetime = earnings["lifetime_micros"].as_i64().unwrap_or(0);
    let unpaid = earnings["unpaid_micros"].as_i64().unwrap_or(0);

    println!("node:     {node_pubkey}");
    println!("lifetime: {} GNN", fmt_gnn(lifetime));
    println!("unpaid:   {} GNN", fmt_gnn(unpaid));
    match earnings.get("last_payout") {
        Some(p) if p.is_object() => {
            let epoch = p["epoch"].as_str().unwrap_or("?");
            let amount = p["gnn_micros"].as_i64().unwrap_or(0);
            let pstatus = p["status"].as_str().unwrap_or("?");
            println!(
                "last payout: {} GNN ({pstatus}) for epoch {epoch}",
                fmt_gnn(amount)
            );
        }
        _ => println!("last payout: none"),
    }

    ExitCode::SUCCESS
}

/// `start`: load config + keys from the client dir and run the pull loop
/// until ctrl-c. A gateway `rejected` (bad auth / not staked / banned) is
/// terminal: print the reason and exit 1 with no retry. Clean ctrl-c
/// shutdown exits 0.
fn cmd_start(dir: PathBuf) -> ExitCode {
    if !node_key_exists(&dir) {
        eprintln!("not initialized: {} (run `nexus-client init`)", dir.display());
        return ExitCode::FAILURE;
    }
    let cfg = match Config::load(&dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to read config: {e}");
            return ExitCode::FAILURE;
        }
    };
    let node_key = match NodeKey::load(&dir) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("failed to read node key: {e}");
            return ExitCode::FAILURE;
        }
    };
    let wallet_pubkey = match load_wallet_pubkey(&dir) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("failed to read wallet pubkey: {e}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("connecting to gateway {} as model `{}`", cfg.gateway, cfg.model);
    match runtime.block_on(run::run(cfg, node_key, wallet_pubkey)) {
        SessionOutcome::Shutdown => {
            println!("shutting down");
            ExitCode::SUCCESS
        }
        SessionOutcome::Rejected(reason) => {
            eprintln!("gateway rejected this node: {reason}");
            ExitCode::FAILURE
        }
        // `run` only returns on shutdown or rejection; Disconnected is
        // handled internally by the reconnect loop.
        SessionOutcome::Disconnected => {
            eprintln!("gateway connection ended");
            ExitCode::FAILURE
        }
    }
}

/// `init`: refuse if already initialized, else generate node key + wallet
/// and write config.toml. Prints both pubkeys.
fn cmd_init(dir: PathBuf, model: String, wallet: String) -> ExitCode {
    if node_key_exists(&dir) {
        eprintln!("already initialized: {}", dir.display());
        return ExitCode::FAILURE;
    }

    if wallet != "new" {
        eprintln!("--wallet: only `new` is supported in this version (got `{wallet}`)");
        return ExitCode::FAILURE;
    }

    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("failed to create dir {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }

    // Node key (refuses overwrite internally too — double safety).
    let node_key = NodeKey::generate();
    if let Err(e) = node_key.save(&dir) {
        eprintln!("failed to write node key: {e}");
        return ExitCode::FAILURE;
    }
    let node_pubkey = node_key.pubkey_base58();

    // Solana wallet.
    let wallet_kp = generate_wallet();
    if let Err(e) = save_wallet(&wallet_kp, &dir) {
        eprintln!("failed to write wallet: {e}");
        return ExitCode::FAILURE;
    }
    let wallet_pubkey = match load_wallet_pubkey(&dir) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("failed to read back wallet pubkey: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Config.
    let cfg = Config::with_model(model);
    if let Err(e) = cfg.save(&dir) {
        eprintln!("failed to write config: {e}");
        return ExitCode::FAILURE;
    }

    println!("Initialized nexus-client in {}", dir.display());
    println!("node pubkey:   {node_pubkey}");
    println!("wallet pubkey: {wallet_pubkey}");
    ExitCode::SUCCESS
}

/// `status`: print model + endpoints + node pubkey from the existing dir.
fn cmd_status(dir: PathBuf) -> ExitCode {
    if !node_key_exists(&dir) {
        eprintln!("not initialized: {} (run `nexus-client init`)", dir.display());
        return ExitCode::FAILURE;
    }

    let cfg = match Config::load(&dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to read config: {e}");
            return ExitCode::FAILURE;
        }
    };
    let node_pubkey = match NodeKey::load(&dir) {
        Ok(k) => k.pubkey_base58(),
        Err(e) => {
            eprintln!("failed to read node key: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("model:    {}", cfg.model);
    println!("upstream: {}", cfg.upstream);
    println!("gateway:  {}", cfg.gateway);
    println!("node:     {node_pubkey}");
    ExitCode::SUCCESS
}
