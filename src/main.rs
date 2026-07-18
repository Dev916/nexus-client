//! `nexus-client` — attach a self-hosted LLM to the GNN compute network.
//!
//! T5 scope: the `init` / `status` lifecycle plus key + config management.
//! `start` (pull loop + upstream forward) and `earnings` are stubbed and
//! exit 2 with "not implemented" for now — they land in T6 / later.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use agenc_worker::builder::McpClient;

use nexus_client::config::{self, Config};
use nexus_client::keys::{
    NodeKey, generate_wallet, import_wallet_from, load_wallet, load_wallet_pubkey, node_key_exists,
    save_wallet,
};
use nexus_client::run::{self, SessionOutcome};
use nexus_client::solana_stake::{Rpc, build_signed_stake_tx};
use nexus_client::wallet_auth::get_wallet_jwt;
use nexus_client::work::{self, WorkCfg};

/// Public Solana RPC for `getTokenAccountsByOwner` / `sendTransaction` when
/// `--rpc` is omitted. Picked from the gateway's reported network so the CLI
/// never needs the server's (secret) Helius key. Devnet uses the devnet
/// endpoint; anything else falls back to mainnet-beta's public endpoint.
fn default_rpc_for(network: &str) -> &'static str {
    if network == "devnet" {
        "https://api.devnet.solana.com"
    } else {
        "https://api.mainnet-beta.solana.com"
    }
}

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
    command: Option<Command>,
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
        /// Wallet source: `new` (default) generates a fresh keypair, or
        /// import a funded wallet by passing a path to a solana-keygen
        /// 64-byte JSON keypair file, or a base58-encoded 64-byte secret.
        #[arg(long, default_value = "new")]
        wallet: String,
    },
    /// Print this client's configured model + endpoints + node pubkey.
    Status {
        /// Client directory (default: ~/.nexus-client).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Connect to the gateway and serve inference jobs from your local model.
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
    /// Stake GNN for this node: send an on-chain GNN transfer to the
    /// gateway's treasury, then record it so `start` is accepted. The chain
    /// addresses + network come from the gateway's `/api/compute/config`;
    /// only the RPC endpoint is client-chosen (`--rpc`, else a public
    /// default for the gateway's network).
    Stake {
        /// Amount of GNN to stake (e.g. `1.5`). 1 GNN = 1_000_000 micros.
        #[arg(long)]
        amount: f64,
        /// Solana JSON-RPC endpoint. Defaults to the public RPC for the
        /// gateway's network (devnet: https://api.devnet.solana.com).
        #[arg(long)]
        rpc: Option<String>,
        /// Client directory (default: ~/.nexus-client).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Run the AgenC provider loop: register + bond, then discover jobs on the
    /// Nexus board, evaluate each against your reward floor + margin, drive a
    /// delegated Builder session for the best one, and settle it on-chain — all
    /// with your node wallet. Reconnects with backoff; ctrl-c exits cleanly.
    Work {
        /// Client directory (default: ~/.nexus-client).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match cli.command {
        Some(Command::Init { dir, model, wallet }) => {
            let dir = dir.unwrap_or_else(default_dir);
            cmd_init(dir, model, wallet)
        }
        Some(Command::Status { dir }) => {
            let dir = dir.unwrap_or_else(default_dir);
            cmd_status(dir)
        }
        Some(Command::Start { dir }) => {
            let dir = dir.unwrap_or_else(default_dir);
            cmd_start(dir)
        }
        Some(Command::Earnings { dir }) => {
            let dir = dir.unwrap_or_else(default_dir);
            cmd_earnings(dir)
        }
        Some(Command::Stake { amount, rpc, dir }) => {
            let dir = dir.unwrap_or_else(default_dir);
            cmd_stake(dir, amount, rpc)
        }
        Some(Command::Work { dir }) => {
            let dir = dir.unwrap_or_else(default_dir);
            cmd_work(dir)
        }
        // No subcommand — the usual result of DOUBLE-CLICKING the .exe on
        // Windows. Without this, clap exits with a terse "requires a
        // subcommand" error and Explorer's transient console closes
        // instantly (the "console flashes and disappears" report). Show a
        // readable quick-start instead; `pause_if_double_click` below then
        // keeps the window open so it can actually be read.
        None => welcome(),
    };
    // Any double-click exit path (welcome, init result, an error) would
    // otherwise vanish before it could be read — hold the window open.
    pause_if_double_click();
    code
}

/// Quick-start shown when the binary runs with no subcommand — the typical
/// result of double-clicking the `.exe` on Windows.
fn welcome() -> ExitCode {
    println!("Nexus Client — attach your LLM to the GNN compute network and earn GNN.");
    println!();
    println!("This is a command-line tool. Open a terminal (on Windows: PowerShell)");
    println!("and run:");
    println!();
    println!("  nexus-client init      one-time setup — creates your node key + wallet");
    println!("  nexus-client status    show your model + gateway + node id");
    println!("  nexus-client start     connect to the gateway and start serving jobs");
    println!("  nexus-client earnings  show your GNN earnings");
    println!();
    println!("Before `start`: run a local LLM (Ollama/vLLM at http://localhost:11434/v1)");
    println!("and stake GNN for your node's wallet so the gateway accepts it.");
    println!();
    println!("Tip (Windows): Shift+Right-click this folder -> \"Open PowerShell window");
    println!("here\", then type a command above. Run `nexus-client --help` for all options.");
    ExitCode::SUCCESS
}

/// Whether this process was launched by double-clicking in a GUI file manager
/// (Windows Explorer), which spawns a *transient* console that closes the
/// instant the process exits. Detected via the number of processes attached
/// to the console: exactly one means we own a fresh console (double-click);
/// running from an existing shell attaches at least the shell too.
#[cfg(windows)]
fn launched_by_double_click() -> bool {
    // kernel32!GetConsoleProcessList returns the count of processes sharing
    // this console. <= 1 ⇒ launched by double-click.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetConsoleProcessList(lpdw_process_list: *mut u32, dw_process_count: u32) -> u32;
    }
    let mut buf = [0u32; 2];
    let count = unsafe { GetConsoleProcessList(buf.as_mut_ptr(), buf.len() as u32) };
    count <= 1
}

#[cfg(not(windows))]
fn launched_by_double_click() -> bool {
    false
}

/// On a Windows double-click, wait for Enter before exiting so the console
/// window doesn't vanish before the user can read it. No-op when run from a
/// terminal (so shell usage isn't interrupted) and on non-Windows platforms.
fn pause_if_double_click() {
    if launched_by_double_click() {
        use std::io::Write;
        print!("\nPress Enter to close this window . . . ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
}

/// Format a micros amount as GNN with 6 decimal places (1 GNN = 1_000_000
/// micros). e.g. `4_000_000` → `"4.000000"`, `999_999` → `"0.999999"`.
fn fmt_gnn(micros: i64) -> String {
    let whole = micros / 1_000_000;
    let frac = (micros % 1_000_000).abs();
    format!("{whole}.{frac:06}")
}

/// Build the authenticated earnings GET request: the `/.../earnings` endpoint
/// requires a wallet JWT, attached as `Authorization: Bearer <jwt>`. Factored
/// out so the header construction is unit-testable without a live server.
fn earnings_request(client: &reqwest::Client, url: &str, jwt: &str) -> reqwest::RequestBuilder {
    client.get(url).bearer_auth(jwt)
}

/// `earnings`: load config + node key + wallet from the client dir, derive the
/// gateway's HTTP origin from its WS URL, acquire a wallet JWT (SIWS), GET
/// `/api/compute/nodes/{node_pubkey}/earnings` with `Authorization: Bearer
/// <jwt>`, and pretty-print lifetime / unpaid GNN plus the last payout line.
/// Refuses an uninitialized dir (exit 1) and exits 1 on a JWT-acquire /
/// network / non-2xx error.
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
    let wallet = match load_wallet(&dir) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("failed to read wallet: {e}");
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
        // The earnings endpoint requires a wallet JWT (SIWS) — authenticate with
        // the wallet key before issuing the GET.
        let jwt = get_wallet_jwt(&origin, &wallet).await?;
        let client = reqwest::Client::new();
        let resp = earnings_request(&client, &url, &jwt)
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

/// `stake`: send an on-chain GNN transfer to the gateway's treasury and
/// record it so this node passes `start`'s stake gate.
///
/// Flow (mirrors the spec's Component 3 / data flow):
///   1. Load the wallet keypair + node pubkey + config from `dir`; derive the
///      gateway HTTP origin.
///   2. `GET {origin}/api/compute/config` → `{gnn_mint, treasury,
///      min_stake_micros, network}` (single source of truth for addresses +
///      network — never hardcoded, never the server's secret RPC).
///   3. Pick the RPC: `--rpc` if given, else the public default for the
///      gateway's network.
///   4. Check the wallet's GNN balance; refuse BEFORE sending a tx if it's
///      short, printing the funding hint.
///   5. Build + sign `transfer_checked` against a fresh blockhash; send; poll
///      to `finalized`.
///   6. Acquire the wallet JWT (SIWS) and `POST {origin}/api/compute/stake`
///      `{node_pubkey, tx_signature, amount_micros}` with `Bearer`.
///   7. Print the new staked total + whether it meets the minimum.
///
/// Refuses an uninitialized dir (exit 1). Any network / on-chain / non-2xx
/// failure exits 1. A non-positive `--amount` is rejected up front.
fn cmd_stake(dir: PathBuf, amount: f64, rpc: Option<String>) -> ExitCode {
    use solana_signer::Signer;

    if !node_key_exists(&dir) {
        eprintln!("not initialized: {} (run `nexus-client init`)", dir.display());
        return ExitCode::FAILURE;
    }

    // Reject a non-positive (or NaN) amount before touching the chain.
    // `partial_cmp` yields `None` for NaN, so the `Some(Greater)` match also
    // rejects NaN without the clippy-flagged `!(amount > 0.0)` form.
    if !matches!(amount.partial_cmp(&0.0), Some(std::cmp::Ordering::Greater)) {
        eprintln!("stake: --amount must be greater than 0 (got {amount})");
        return ExitCode::FAILURE;
    }
    // GNN has 6 decimals: 1 GNN = 1_000_000 micros. Round to the nearest
    // micro so float imprecision (e.g. 1.5 → 1499999.999…) doesn't truncate.
    let amount_micros = (amount * 1_000_000.0).round() as i64;
    if amount_micros <= 0 {
        eprintln!("stake: --amount rounds to 0 micros (got {amount})");
        return ExitCode::FAILURE;
    }
    let amount_raw = amount_micros as u64;

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
    let wallet = match load_wallet(&dir) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("failed to read wallet: {e}");
            return ExitCode::FAILURE;
        }
    };
    let wallet_pubkey = wallet.pubkey().to_string();
    let origin = cfg.gateway_http_origin();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result: Result<serde_json::Value, String> = runtime.block_on(async {
        // 1. Fetch chain config from the gateway (addresses + network).
        let cfg_url = format!("{origin}/api/compute/config");
        let client = reqwest::Client::new();
        let resp = client
            .get(&cfg_url)
            .send()
            .await
            .map_err(|e| format!("request to {cfg_url} failed: {e}"))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("reading {cfg_url} body failed: {e}"))?;
        if !status.is_success() {
            return Err(format!("gateway returned {status} for {cfg_url}: {body}"));
        }
        let chain: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| format!("invalid JSON from {cfg_url}: {e} (body: {body})"))?;
        let gnn_mint = chain["gnn_mint"]
            .as_str()
            .ok_or_else(|| "config: missing gnn_mint".to_string())?
            .to_string();
        let treasury = chain["treasury"]
            .as_str()
            .ok_or_else(|| "config: missing treasury".to_string())?
            .to_string();
        let network = chain["network"].as_str().unwrap_or("mainnet").to_string();

        // 2. Pick the RPC endpoint (never the server's secret Helius key).
        let rpc_url = rpc
            .clone()
            .unwrap_or_else(|| default_rpc_for(&network).to_string());
        let rpc_client = Rpc::new(rpc_url);

        // 3. Balance gate — refuse BEFORE sending any tx if short.
        let balance = rpc_client.get_gnn_balance(&wallet_pubkey, &gnn_mint).await?;
        if balance < amount_raw {
            return Err(format!(
                "insufficient GNN: have {balance}, need {amount_raw}; fund {wallet_pubkey}"
            ));
        }

        // 4. Build + sign + send the GNN transfer, then confirm finalized.
        let blockhash = rpc_client.get_latest_blockhash().await?;
        let signed_b64 =
            build_signed_stake_tx(&wallet, &gnn_mint, &treasury, amount_raw, &blockhash)?;
        let tx_signature = rpc_client.send_transaction(&signed_b64).await?;
        println!("submitted stake tx {tx_signature}; awaiting finalization…");
        rpc_client.confirm_finalized(&tx_signature).await?;

        // 5. Authenticate with the wallet key and record the stake.
        let jwt = get_wallet_jwt(&origin, &wallet).await?;
        let stake_url = format!("{origin}/api/compute/stake");
        let stake_body = serde_json::json!({
            "node_pubkey": node_pubkey,
            "tx_signature": tx_signature,
            "amount_micros": amount_micros,
        });
        let resp = client
            .post(&stake_url)
            .bearer_auth(&jwt)
            .json(&stake_body)
            .send()
            .await
            .map_err(|e| format!("request to {stake_url} failed: {e}"))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("reading {stake_url} body failed: {e}"))?;
        if !status.is_success() {
            return Err(format!("gateway returned {status} for {stake_url}: {body}"));
        }
        serde_json::from_str::<serde_json::Value>(&body)
            .map_err(|e| format!("invalid JSON from {stake_url}: {e} (body: {body})"))
    });

    let staked = match result {
        Ok(v) => v,
        Err(e) => {
            eprintln!("stake: {e}");
            return ExitCode::FAILURE;
        }
    };

    let staked_micros = staked["staked_micros"].as_i64().unwrap_or(0);
    let meets_minimum = staked["meets_minimum"].as_bool().unwrap_or(false);

    println!("node:    {node_pubkey}");
    println!("staked:  {} GNN total", fmt_gnn(staked_micros));
    if meets_minimum {
        println!("status:  meets the minimum stake — run `nexus-client start`");
    } else {
        let min = staked["min_stake_micros"].as_i64().unwrap_or(0);
        println!(
            "status:  below the minimum stake ({} GNN) — stake more before `nexus-client start`",
            fmt_gnn(min)
        );
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

/// `work`: run the AgenC provider loop. Load the wallet + config, register +
/// bond once (idempotent — an already-registered agent is fine), then a
/// supervised loop: spawn a fresh MCP child, run one `work_once` (discover →
/// evaluate → drive a delegated Builder session → settle on-chain), and on a
/// transient error or an idle poll (`Ok(None)`) sleep `jittered(next_backoff)`
/// before retrying. A successful claim resets the backoff. Races
/// `tokio::signal::ctrl_c()` like `run.rs`, so a signal during a backoff sleep
/// also exits cleanly (exit 0). Refuses an uninitialized dir (exit 1).
fn cmd_work(dir: PathBuf) -> ExitCode {
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
    let wallet = match load_wallet(&dir) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("failed to read wallet: {e}");
            return ExitCode::FAILURE;
        }
    };
    let work_cfg = WorkCfg::from_config(&cfg);
    let mcp_bin = cfg.agenc.mcp_bin.clone();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "AgenC provider loop: board {} — reward floor {} lamports",
        work_cfg.nexus_origin, work_cfg.min_reward_lamports
    );

    runtime.block_on(async move {
        let http = reqwest::Client::new();

        // Register + bond once. Idempotent: a re-register of an already-bonded
        // agent fails at broadcast — log and continue into the loop.
        if let Err(e) = work::register(&work_cfg, &wallet, &http).await {
            eprintln!("register: {e} (continuing — the agent may already be registered)");
        }

        // Supervised loop with run.rs's backoff cadence, raced against ctrl-c.
        let mut backoff: Option<std::time::Duration> = None;
        loop {
            // A fresh MCP child per iteration (dropped at end of scope → SIGKILL).
            let outcome = match McpClient::spawn(&mcp_bin, &work_cfg.nexus_origin).await {
                Ok(mut mcp) => work::work_once(&work_cfg, &wallet, &mut mcp, &http).await,
                Err(e) => Err(e),
            };

            // Delay before the next iteration: none after a successful claim
            // (poll promptly for more work, backoff reset), else jittered backoff.
            let delay = match outcome {
                Ok(Some(submit)) => {
                    println!("submitted result for task {}", submit.task_pda);
                    backoff = None;
                    std::time::Duration::ZERO
                }
                Ok(None) => {
                    let d = run::next_backoff(backoff);
                    backoff = Some(d);
                    run::jittered(d)
                }
                Err(e) => {
                    eprintln!("work iteration failed: {e}");
                    let d = run::next_backoff(backoff);
                    backoff = Some(d);
                    run::jittered(d)
                }
            };

            // Race the backoff sleep against ctrl-c so a signal mid-sleep (or
            // between busy iterations) exits cleanly.
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = tokio::signal::ctrl_c() => {
                    println!("shutting down");
                    return ExitCode::SUCCESS;
                }
            }
        }
    })
}

/// `init`: refuse if already initialized, else generate node key + wallet
/// and write config.toml. Prints both pubkeys.
fn cmd_init(dir: PathBuf, model: String, wallet: String) -> ExitCode {
    if node_key_exists(&dir) {
        eprintln!("already initialized: {}", dir.display());
        return ExitCode::FAILURE;
    }

    // Resolve the wallet up front so an unparseable `--wallet` import fails
    // before we create any on-disk state. `new` (default) generates a fresh
    // keypair; anything else is a path-or-base58 import of a funded wallet.
    let wallet_kp = if wallet == "new" {
        generate_wallet()
    } else {
        match import_wallet_from(&wallet) {
            Ok(kp) => kp,
            Err(e) => {
                eprintln!("--wallet: {e}");
                return ExitCode::FAILURE;
            }
        }
    };

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

    // Solana wallet (generated or imported above).
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The earnings GET must carry the wallet JWT as `Authorization: Bearer
    /// <jwt>` — the endpoint rejects unauthenticated requests. Build the request
    /// and assert the header is present and exactly right.
    #[test]
    fn earnings_request_sets_bearer_auth() {
        let client = reqwest::Client::new();
        let req = earnings_request(
            &client,
            "https://nexus.ghostnn.ai/api/compute/nodes/NODE/earnings",
            "test.jwt.token",
        )
        .build()
        .expect("request builds");

        let auth = req
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .expect("Authorization header is set")
            .to_str()
            .expect("header is valid ascii");
        assert_eq!(auth, "Bearer test.jwt.token");
        assert_eq!(req.method(), reqwest::Method::GET);
    }
}
