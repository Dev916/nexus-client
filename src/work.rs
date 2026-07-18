//! `work` — the AgenC **provider loop** (`nexus-client work`).
//!
//! A staked node earns by taking work off the Nexus AgenC job board: discover
//! open jobs, decide which clear the reward floor + token-cost margin, drive a
//! delegated Builder session over the Nexus MCP, and settle the genuine result
//! on-chain — all with the node's OWN wallet, never a platform/creator key and
//! never a DB handle.
//!
//! The loop is assembled entirely from the slim, client-consumable
//! `agenc-worker` crate:
//!   * [`agenc_worker::tx`] — assert-before-sign + local Ed25519 sign + raw
//!     JSON-RPC broadcast (used by [`register`] for the register+bond tx).
//!   * [`agenc_worker::builder::drive_builder`] — drive a delegated Builder
//!     session (auth → create → pin community tier → advance → promote) over an
//!     [`Mcp`], returning the live `session_id` **and** the real
//!     `artifact_sha256` (canonical `manifest_hash` of the promoted app files).
//!   * [`agenc_worker::worker::worker_roundtrip`] — the claim → worker-signed
//!     proof → submit round-trip against the keyless sidecar build endpoints.
//!
//! Composition mirrors `server::agenc::live_loop::run_live_loop`: `drive_builder`
//! → the settle tail. There the tail is the DB-backed `run_roundtrip`; here it is
//! the slim, DB-free sibling `worker_roundtrip`. The on-chain claim is
//! `worker_roundtrip`'s own first leg — there is no separate (double-)claim.
//!
//! Everything HTTP is injected (`reqwest::Client`) and the MCP is abstracted
//! behind [`Mcp`], so the loop body ([`work_once`]) is exercised end-to-end
//! against an in-process wiremock + a scripted fake with zero live infra.

use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use solana_keypair::Keypair;
use solana_program::pubkey::Pubkey;
use solana_signer::Signer;

use agenc_worker::builder::{drive_builder, Mcp};
use agenc_worker::tx::{assert_expected, sign_and_send};
use agenc_worker::worker::{worker_roundtrip, WorkerCfg, WorkerMeta, WorkerSubmit};

use crate::config::Config;

/// Orchestrator-verified AgenC program id + the `register_agent` Anchor
/// discriminator. The register tx is asserted against these BEFORE the node
/// signs — a headless wallet never signs an opaque or tampered blob.
const AGENC_PROGRAM: &str = "HJsZ53Zb27b8QMRbQpuDngE44AdwCGxvEZr61Zmxw1xK";
const REGISTER_DISC: [u8; 8] = [135, 157, 66, 195, 2, 113, 175, 30];

/// Default profit margin numerator/denominator (`3/4`): a job is worth claiming
/// when the estimated token cost is ≤ 75% of the reward.
pub const DEFAULT_MARGIN_NUM: u64 = 3;
pub const DEFAULT_MARGIN_DEN: u64 = 4;
/// Default wall-clock budget for the delegated Builder poll/advance loop.
pub const DEFAULT_BUDGET_SECS: u64 = 900;
/// Coarse advisory: lamports per estimated inference token. Only feeds the
/// skip/claim decision — a miss skips a job, it never mis-signs — so the exact
/// value is not load-bearing.
const LAMPORTS_PER_EST_TOKEN: u64 = 500;

/// Runtime configuration for one provider-loop run — the flattened, non-secret
/// knobs [`work_once`]/[`register`] need. Built from the on-disk [`Config`] via
/// [`WorkCfg::from_config`]; constructed directly in tests pointed at a mock.
#[derive(Debug, Clone)]
pub struct WorkCfg {
    /// Gateway HTTP origin. Serves both discovery (`GET /api/agenc/jobs`) and
    /// the MCP child's `NEXUS_API_BASE` for the delegated Builder session.
    pub nexus_origin: String,
    /// Keyless AgenC sidecar base (`/build-register-agent-tx`, `/build-claim-tx`,
    /// `/build-submit-tx`).
    pub build_api_url: String,
    /// Solana JSON-RPC endpoint for `sendTransaction` broadcast.
    pub rpc_url: String,
    /// Reward floor (lamports): jobs below this are always skipped.
    pub min_reward_lamports: u64,
    /// Profit-margin numerator / denominator (est cost ≤ reward·num/den).
    pub margin_num: u64,
    pub margin_den: u64,
    /// Model label recorded in the worker proof.
    pub model: String,
    /// This agent's advertised endpoint (recorded on register; may be empty).
    pub endpoint: String,
    /// `nexus-city-mcp` binary to spawn for the delegated session.
    pub mcp_bin: String,
    /// Wall-clock budget for the Builder poll/advance loop.
    pub budget_secs: u64,
}

impl WorkCfg {
    /// Flatten a loaded client [`Config`] into the runtime work knobs. Both
    /// discovery and the MCP target the gateway's HTTP origin (derived from its
    /// WS URL); the sidecar/RPC/floor/endpoint/mcp come from the `[agenc]` block.
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            nexus_origin: cfg.gateway_http_origin(),
            build_api_url: cfg.agenc.build_api_url.clone(),
            rpc_url: cfg.agenc.rpc_url.clone(),
            min_reward_lamports: cfg.agenc.min_reward_lamports,
            margin_num: DEFAULT_MARGIN_NUM,
            margin_den: DEFAULT_MARGIN_DEN,
            model: cfg.model.clone(),
            endpoint: cfg.agenc.endpoint.clone(),
            mcp_bin: cfg.agenc.mcp_bin.clone(),
            budget_secs: DEFAULT_BUDGET_SECS,
        }
    }
}

/// A discovered job that cleared the claim decision, distilled to what the
/// settle path needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedJob {
    pub task_pda: String,
    pub parcel_uid: String,
    pub reward_lamports: u64,
    /// Opening brief posted as the Builder session's first message.
    pub brief: String,
}

/// Pure claim decision: a job is worth claiming when its reward clears the floor
/// AND the estimated token cost stays within the margin fraction of the reward
/// (`est_token_cost ≤ reward · margin_num / margin_den`). The reward·margin
/// product is computed in `u128` so large lamport rewards never overflow.
/// Advisory only — a wrong answer skips a job, it can never mis-sign.
pub fn should_claim(
    reward_lamports: u64,
    est_token_cost: u64,
    floor: u64,
    margin_num: u64,
    margin_den: u64,
) -> bool {
    if reward_lamports < floor {
        return false;
    }
    if margin_den == 0 {
        return false; // guard against a misconfigured zero denominator
    }
    (est_token_cost as u128)
        <= (reward_lamports as u128) * (margin_num as u128) / (margin_den as u128)
}

/// Coarse per-job token-cost estimate from the jobSpec size: ~4 bytes/token at a
/// flat per-token lamport cost. Deliberately rough — it only feeds
/// [`should_claim`].
pub fn est_token_cost_for_spec(spec_bytes: usize) -> u64 {
    ((spec_bytes as u64) / 4).saturating_mul(LAMPORTS_PER_EST_TOKEN)
}

/// Pick the best claimable job from a board response: `status == "open"`, not our
/// own posting (`owner_pk != own_pubkey`), reward ≥ floor, and clearing
/// [`should_claim`] against the spec-size cost estimate. Ties broken by highest
/// reward. Pure over the parsed job array so it is unit-testable without HTTP.
pub fn select_job(jobs: &[Value], own_pubkey: &str, cfg: &WorkCfg) -> Option<SelectedJob> {
    let mut best: Option<SelectedJob> = None;
    for job in jobs {
        // Open jobs only, and never claim our own posting.
        if job.get("status").and_then(|s| s.as_str()) != Some("open") {
            continue;
        }
        if job.get("owner_pk").and_then(|s| s.as_str()) == Some(own_pubkey) {
            continue;
        }
        // reward_lamports is i64 in the board JSON; a negative value is nonsense.
        let reward = match job.get("reward_lamports").and_then(|r| r.as_i64()) {
            Some(r) if r >= 0 => r as u64,
            _ => continue,
        };
        let task_pda = match job.get("task_pda").and_then(|s| s.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let parcel_uid = match job.get("parcel_uid").and_then(|s| s.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let spec = job.get("spec").cloned().unwrap_or(Value::Null);
        let spec_bytes = serde_json::to_vec(&spec).map(|b| b.len()).unwrap_or(0);
        let est = est_token_cost_for_spec(spec_bytes);
        if !should_claim(reward, est, cfg.min_reward_lamports, cfg.margin_num, cfg.margin_den) {
            continue;
        }
        let candidate = SelectedJob {
            task_pda,
            parcel_uid,
            reward_lamports: reward,
            brief: brief_from_job(job),
        };
        // Keep the highest-reward candidate.
        if best.as_ref().is_none_or(|b| candidate.reward_lamports > b.reward_lamports) {
            best = Some(candidate);
        }
    }
    best
}

/// Compose the Builder opening brief from a job's `title` + `spec.short_description`.
fn brief_from_job(job: &Value) -> String {
    let title = job.get("title").and_then(|t| t.as_str()).unwrap_or("").trim();
    let desc = job
        .get("spec")
        .and_then(|s| s.get("short_description"))
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .trim();
    match (title.is_empty(), desc.is_empty()) {
        (false, false) => format!("{title}\n\n{desc}"),
        (false, true) => title.to_string(),
        (true, false) => desc.to_string(),
        (true, true) => "Build the requested parcel app.".to_string(),
    }
}

/// Register (idempotently) the node wallet as an AgenC agent and post the bond:
/// POST `/build-register-agent-tx {workerPubkey}` → assert-before-sign (AgenC +
/// `register_agent` disc) → local `wallet.json` sign → JSON-RPC broadcast. The
/// bond amount is encoded in the sidecar-built tx. A re-register of an
/// already-registered agent fails at broadcast (the account exists); the caller
/// treats that as benign and proceeds to the loop.
pub async fn register(cfg: &WorkCfg, wallet: &Keypair, http: &reqwest::Client) -> Result<()> {
    let program = Pubkey::from_str(AGENC_PROGRAM).expect("valid AgenC program id");
    let worker_pubkey = wallet.pubkey().to_string();

    let url = format!("{}/build-register-agent-tx", cfg.build_api_url);
    let mut body = json!({ "workerPubkey": worker_pubkey });
    if !cfg.endpoint.is_empty() {
        body["endpoint"] = json!(cfg.endpoint);
    }
    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let text = resp.text().await.context("read register response body")?;
    if !status.is_success() {
        bail!("/build-register-agent-tx returned {status}: {text}");
    }
    let v: Value =
        serde_json::from_str(&text).with_context(|| format!("parse register JSON: {text}"))?;
    let unsigned = v
        .get("unsignedTxB64")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("register response missing unsignedTxB64: {text}"))?;

    // Assert-before-sign: the register tx MUST target AgenC with register_agent.
    assert_expected(unsigned, &program, &[REGISTER_DISC])
        .context("register tx failed assert-before-sign")?;
    // Local sign (wallet.json) + broadcast; bonds the stake encoded in the tx.
    sign_and_send(&cfg.rpc_url, unsigned, wallet)
        .await
        .context("register sign_and_send")?;
    Ok(())
}

/// One iteration of the provider loop: discover → evaluate → (delegated) build →
/// settle. Returns `Ok(Some(submit))` when a job was claimed, built, and
/// submitted; `Ok(None)` when no open job clears the claim decision; `Err` on a
/// (transient) discovery/build/settle failure — the caller backs off and retries.
///
/// Generic over the [`Mcp`] transport so the whole body runs against a scripted
/// fake in tests; production hands in a live [`agenc_worker::builder::McpClient`].
pub async fn work_once<M: Mcp>(
    cfg: &WorkCfg,
    wallet: &Keypair,
    mcp: &mut M,
    http: &reqwest::Client,
) -> Result<Option<WorkerSubmit>> {
    let own_pubkey = wallet.pubkey().to_string();

    // 1. Discover open jobs on the Nexus board.
    let jobs = discover(cfg, http).await?;

    // 2. Evaluate + pick the best claimable job. No claimable job → no work.
    let job = match select_job(&jobs, &own_pubkey, cfg) {
        Some(j) => j,
        None => return Ok(None),
    };

    // 3. Drive the DELEGATED Builder session over the MCP. Slice 2 authorizes it
    //    off the worker's SIWS auth (+ the on-chain claim settled below). Returns
    //    the promoted `session_id` AND the REAL `artifact_sha256` — the canonical
    //    `manifest_hash` of the promoted app's files (gnn-ved1), the SAME hash the
    //    server commits. Mirrors run_live_loop: drive_builder → tail.
    let worker_key = signing_key_from_wallet(wallet);
    let (session_id, artifact_sha256) = drive_builder(
        mcp,
        &worker_key,
        &own_pubkey,
        &job.parcel_uid,
        &job.brief,
        cfg.budget_secs,
    )
    .await
    .context("drive_builder (delegated session)")?;

    // 4. Settle on-chain via the slim worker round-trip (its FIRST leg IS the
    //    claim): build-claim → assert → sign+send → worker-signed proof →
    //    build-submit → assert → sign+send. The proof binds `artifact_sha256`,
    //    the genuine manifest hash of the app this node built. Consumed verbatim
    //    from agenc-worker.
    let worker_cfg = WorkerCfg {
        build_api_url: cfg.build_api_url.clone(),
        rpc_url: cfg.rpc_url.clone(),
    };
    let meta = WorkerMeta {
        worker_agent: own_pubkey.clone(),
        model: cfg.model.clone(),
        compute_job_id: session_id.clone(),
        node_pubkey: own_pubkey.clone(),
        node_stake_micros: 0,
        stake_tx_sig: String::new(),
        canary_passed: true,
        verified_at: now_unix_secs(),
    };
    let submit = worker_roundtrip(&worker_cfg, wallet, &job.task_pda, &artifact_sha256, meta)
        .await
        .map_err(|e| anyhow!("worker round-trip failed: {e}"))?;

    Ok(Some(submit))
}

/// `GET {nexus_origin}/api/agenc/jobs?status=open` → the `jobs` array from the
/// board envelope `{ agenc_available, jobs }`. A non-2xx is a (transient) error
/// the caller retries with backoff.
async fn discover(cfg: &WorkCfg, http: &reqwest::Client) -> Result<Vec<Value>> {
    let url = format!("{}/api/agenc/jobs?status=open", cfg.nexus_origin);
    let resp = http.get(&url).send().await.with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    let text = resp.text().await.context("read jobs board response body")?;
    if !status.is_success() {
        bail!("job board {url} returned {status}: {text}");
    }
    let v: Value =
        serde_json::from_str(&text).with_context(|| format!("parse jobs board JSON: {text}"))?;
    Ok(v.get("jobs")
        .and_then(|j| j.as_array())
        .cloned()
        .unwrap_or_default())
}

/// Derive the Ed25519 signing key from a Solana keypair (the signing-key *seed*
/// is the first 32 bytes of the 64-byte secret). The verifying key equals the
/// wallet pubkey, so the worker signs SIWS with the SAME identity it signs txs.
fn signing_key_from_wallet(kp: &Keypair) -> SigningKey {
    let bytes = kp.to_bytes(); // [seed(32)][pubkey(32)]
    let seed: [u8; 32] = bytes[..32]
        .try_into()
        .expect("keypair secret is at least 32 bytes");
    SigningKey::from_bytes(&seed)
}

/// Current unix time (seconds), threaded into the worker proof's `verified_at`.
fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use std::collections::VecDeque;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // REAL unsigned web3.js LEGACY claim/submit txs captured from the sidecar
    // builders (the same fixtures agenc-worker's round-trip test uses). They
    // carry the AgenC program + claim/submit discriminators, so worker_roundtrip's
    // assert-before-sign accepts them.
    const CLAIM_TX_B64: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAUJxz7HowzB5mS69nWiCu+u0+14vA3KF2+KMwCPDqoacWoiGeX2SAlnVofWlXJqbp1U8dTptvDrnwS5hZuhT6pd9q7u8oGBh8G/dVCauiU7ykwM3del+HosFmBuUR2A2JFF6AJtxs+kfZOMlGCWmf87PrBeT5GDBJcySlrgf+BK/iAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAAu9J71yR3FOHwTeg+1scjy59xDh8N4gz3N6eU9SK9qHjyTwZjQCaGvZn+Y82/+nVRTbbSKIfGIqrvTvbb7UT16PLwXXGJLaaMm6Na6xX4dSXEgKpDV+yLvCagOmB0hwJT69uecUz5z3Qnnl1iKXiUTEVbXSekrHd2wZ6UrNvdwqACBQAFAkANAwAHBwEIAwYCAAQI5ihrbdDkrx8=";
    const SUBMIT_TX_B64: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAUKxz7HowzB5mS69nWiCu+u0+14vA3KF2+KMwCPDqoacWoRhjOyEUEmdpuR2uVOZSzmL6pgQJsw/HptTYgFX1kgCCIZ5fZICWdWh9aVcmpunVTx1Om28OufBLmFm6FPql32plAmamcnpxT4a8Fud+JgLAkvReuiU2xjyXIWBDTqHhroAm3Gz6R9k4yUYJaZ/zs+sF5PkYMElzJKWuB/4Er+IAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAru7ygYGHwb91UJq6JTvKTAzd16X4eiwWYG5RHYDYkUUDBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAALvSe9ckdxTh8E3oPtbHI8ufcQ4fDeIM9zenlPUivah48k8GY0Amhr2Z/mPNv/p1UU220iiHxiKq70722+1E9ejr255xTPnPdCeeXWIpeJRMRVtdJ6Ssd3bBnpSs293CoAIHAAUCQA0DAAkIAgQBAwgGAAVpJ2xKBEJ9nQeqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgFhcnRpZmFjdDpzaGEyNTY6ZGVhZGJlZWYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // An owner pubkey that is NOT our test wallet — jobs owned by us are skipped.
    const OTHER_OWNER: &str = "Owner111111111111111111111111111111111111111";

    fn test_cfg(base: &str) -> WorkCfg {
        WorkCfg {
            nexus_origin: base.to_string(),
            build_api_url: base.to_string(),
            rpc_url: base.to_string(),
            min_reward_lamports: 1_000_000,
            margin_num: DEFAULT_MARGIN_NUM,
            margin_den: DEFAULT_MARGIN_DEN,
            model: "hermes-3".into(),
            endpoint: String::new(),
            mcp_bin: "unused-in-tests".into(),
            budget_secs: 30,
        }
    }

    fn open_job(owner: &str, reward: i64) -> Value {
        json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "parcel_uid": "11111111-1111-1111-1111-111111111111",
            "owner_pk": owner,
            "task_pda": "TaskPda11111111111111111111111111111111111",
            "task_id": "task-1",
            "title": "Build a scoreboard",
            "spec": {"short_description": "A tiny scoreboard app", "kind": "agenc.marketplace.jobSpec"},
            "reward_lamports": reward,
            "status": "open",
            "tx_sig": null,
            "claimed_by": null,
            "error_message": null,
            "spec_pinned": true,
            "created_at_ms": 1000
        })
    }

    fn board(jobs: Value) -> Value {
        json!({ "agenc_available": true, "jobs": jobs })
    }

    /// The promoted app's `files` payload the scripted `done` status carries —
    /// the same `{name: contents}` shape the server persists and hashes.
    fn scripted_files() -> Value {
        json!({
            "index.html": "<h1>Scoreboard</h1>",
            "app.js": "console.log('score');",
        })
    }

    // ── should_claim boundary conditions ─────────────────────────────────────

    #[test]
    fn should_claim_at_floor_is_claimed() {
        // reward exactly at the floor, trivial cost → claim.
        assert!(should_claim(500, 0, 500, 3, 4));
    }

    #[test]
    fn should_claim_below_floor_is_skipped() {
        // one lamport under the floor → never claim, regardless of cost.
        assert!(!should_claim(499, 0, 500, 3, 4));
    }

    #[test]
    fn should_claim_cost_equal_to_margin_is_claimed() {
        // cost == reward·3/4 exactly (750 == 1000·3/4) → claim (boundary is `<=`).
        assert!(should_claim(1000, 750, 500, 3, 4));
    }

    #[test]
    fn should_claim_cost_over_margin_is_skipped() {
        // one lamport over the margin (751 > 750) → skip.
        assert!(!should_claim(1000, 751, 500, 3, 4));
    }

    #[test]
    fn should_claim_zero_denominator_is_safe() {
        // A misconfigured zero denominator never divides-by-zero; it just skips.
        assert!(!should_claim(1_000_000, 0, 0, 3, 0));
    }

    #[test]
    fn est_token_cost_scales_with_spec_size() {
        assert_eq!(est_token_cost_for_spec(0), 0);
        // 4000 bytes → 1000 tokens → 1000·500 lamports.
        assert_eq!(est_token_cost_for_spec(4000), 1000 * LAMPORTS_PER_EST_TOKEN);
    }

    // ── select_job filtering ─────────────────────────────────────────────────

    #[test]
    fn select_job_picks_highest_reward_open_not_own() {
        let cfg = test_cfg("http://unused");
        let mut low = open_job(OTHER_OWNER, 2_000_000);
        low["task_pda"] = json!("LowTaskPda1111111111111111111111111111111");
        let mut high = open_job(OTHER_OWNER, 9_000_000);
        high["task_pda"] = json!("HighTaskPda111111111111111111111111111111");
        let jobs = vec![low, high];
        let sel = select_job(&jobs, "MyWallet", &cfg).expect("a claimable job");
        assert_eq!(sel.reward_lamports, 9_000_000);
        assert_eq!(sel.task_pda, "HighTaskPda111111111111111111111111111111");
    }

    #[test]
    fn select_job_skips_own_below_floor_and_non_open() {
        let cfg = test_cfg("http://unused");
        let own = open_job("MyWallet", 9_000_000); // ours — skip
        let below = open_job(OTHER_OWNER, 500_000); // under 1_000_000 floor — skip
        let mut claimed = open_job(OTHER_OWNER, 9_000_000);
        claimed["status"] = json!("claimed"); // not open — skip
        let jobs = vec![own, below, claimed];
        assert!(select_job(&jobs, "MyWallet", &cfg).is_none());
    }

    // ── scripted fake MCP (mirrors agenc-worker::builder's FakeMcp) ───────────
    struct FakeMcp {
        calls: Vec<(String, Value)>,
        status_seq: VecDeque<Value>,
    }
    impl FakeMcp {
        fn happy() -> Self {
            Self {
                calls: Vec::new(),
                status_seq: VecDeque::from(vec![
                    json!({"phase": "brainstorm", "status": "waiting_approval"}),
                    json!({"phase": "plan", "status": "waiting_approval"}),
                    json!({"phase": "execute", "status": "waiting_user"}),
                    json!({"phase": "done", "status": "done", "files": scripted_files()}),
                ]),
            }
        }
    }
    impl Mcp for FakeMcp {
        async fn call(&mut self, name: &str, args: Value) -> Result<Value> {
            self.calls.push((name.to_string(), args));
            Ok(match name {
                "nexus_auth_challenge" => json!({"message": "SIWS-CHALLENGE", "pubkey": "PK"}),
                "nexus_auth_verify" => json!({"authenticated": true, "pubkey": "PK"}),
                "nexus_builder_create" => json!({"session_id": "SESSION-123"}),
                "nexus_builder_tier" => json!({"ok": true}),
                "nexus_builder_status" => self
                    .status_seq
                    .pop_front()
                    .ok_or_else(|| anyhow!("status polled more times than scripted"))?,
                "nexus_builder_advance" => json!({"ok": true}),
                "nexus_builder_promote" => json!({"promoted": true}),
                other => bail!("unexpected tool call: {other}"),
            })
        }
    }

    // Mount the keyless sidecar (build-claim/build-submit) + JSON-RPC broadcast.
    // `expect` pins the exact call count each mock must receive.
    async fn mount_settle_mocks(server: &MockServer, expect_each: u64) {
        Mock::given(method("POST"))
            .and(path("/build-claim-tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "unsignedTxB64": CLAIM_TX_B64 })))
            .expect(expect_each)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/build-submit-tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "unsignedTxB64": SUBMIT_TX_B64 })))
            .expect(expect_each)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 1, "result": "5xSignatureBase58Placeholder1111111111111111"
            })))
            .expect(expect_each * 2) // claim + submit broadcast
            .mount(server)
            .await;
    }

    // ── work_once happy path: claim → build → submit ─────────────────────────
    #[tokio::test]
    async fn work_once_happy_path_returns_submit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agenc/jobs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(board(json!([open_job(OTHER_OWNER, 5_000_000)]))))
            .mount(&server)
            .await;
        mount_settle_mocks(&server, 1).await;

        let cfg = test_cfg(&server.uri());
        let wallet = Keypair::new();
        let http = reqwest::Client::new();
        let mut mcp = FakeMcp::happy();

        let submit = work_once(&cfg, &wallet, &mut mcp, &http)
            .await
            .expect("work_once must succeed")
            .expect("a job was claimed → Some(submit)");

        // The submitted result binds the discovered task + the REAL artifact hash
        // of the promoted app: the canonical `manifest_hash` of the scripted
        // `files` (gnn-ved1) — NOT the old `sha256(session_id)` placeholder.
        use sha2::{Digest, Sha256};
        assert_eq!(submit.task_pda, "TaskPda11111111111111111111111111111111111");
        let expected =
            agenc_worker::manifest_hash(&agenc_worker::files_from_json(&scripted_files()));
        assert_eq!(
            submit.artifact_sha256, expected,
            "work_once must submit manifest_hash(files), the genuine built-app hash"
        );
        let placeholder = hex::encode(Sha256::digest(b"SESSION-123"));
        assert_ne!(
            submit.artifact_sha256, placeholder,
            "artifact hash must NOT be the old sha256(session_id) placeholder"
        );

        // The delegated Builder session ran the full auth→create→advance→promote.
        let names: Vec<&str> = mcp.calls.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names.first(), Some(&"nexus_auth_challenge"));
        assert!(names.contains(&"nexus_builder_promote"));
    }

    // ── work_once below-floor: skipped, ZERO claim/build/RPC calls ───────────
    #[tokio::test]
    async fn work_once_below_floor_skips_with_no_claim_or_rpc() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/agenc/jobs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(board(json!([open_job(OTHER_OWNER, 500_000)]))))
            .mount(&server)
            .await;
        // Every settle mock MUST receive ZERO calls (wiremock verifies on drop).
        mount_settle_mocks(&server, 0).await;

        let cfg = test_cfg(&server.uri());
        let wallet = Keypair::new();
        let http = reqwest::Client::new();
        let mut mcp = FakeMcp::happy();

        let out = work_once(&cfg, &wallet, &mut mcp, &http)
            .await
            .expect("work_once must succeed");
        assert!(out.is_none(), "below-floor job → Ok(None)");

        // The delegated Builder session was never opened for a skipped job.
        assert!(mcp.calls.is_empty(), "drive_builder must not run when nothing is claimable");

        // Belt-and-suspenders: no request ever reached claim/submit/RPC.
        let reqs = server.received_requests().await.unwrap();
        let touched = reqs
            .iter()
            .filter(|r| r.url.path() == "/build-claim-tx" || r.url.path() == "/build-submit-tx" || r.url.path() == "/")
            .count();
        assert_eq!(touched, 0, "a skipped job must make zero claim/submit/RPC calls");
    }

    // ── supervisor retry: a transient discovery failure then success ─────────
    #[tokio::test]
    async fn work_once_retries_after_transient_discovery_failure() {
        let server = MockServer::start().await;
        // First discovery poll 500s (transient); the next one 200s with a job.
        Mock::given(method("GET"))
            .and(path("/api/agenc/jobs"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/agenc/jobs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(board(json!([open_job(OTHER_OWNER, 5_000_000)]))))
            .with_priority(2)
            .mount(&server)
            .await;
        mount_settle_mocks(&server, 1).await;

        let cfg = test_cfg(&server.uri());
        let wallet = Keypair::new();
        let http = reqwest::Client::new();

        // First iteration errors on the transient 500 — the supervisor's cue to
        // back off (next_backoff/jittered) and retry, exactly as run.rs drives it.
        let mut mcp1 = FakeMcp::happy();
        assert!(
            work_once(&cfg, &wallet, &mut mcp1, &http).await.is_err(),
            "a 500 from the board is a transient error"
        );

        // The retry succeeds and returns the submitted result.
        let mut mcp2 = FakeMcp::happy();
        let submit = work_once(&cfg, &wallet, &mut mcp2, &http)
            .await
            .expect("retry must succeed")
            .expect("a job was claimed on the retry");
        assert_eq!(submit.task_pda, "TaskPda11111111111111111111111111111111111");
    }

    // ── register: build → assert-before-sign → sign → broadcast ──────────────
    #[tokio::test]
    async fn register_asserts_then_signs_and_sends() {
        // A synthetic UNSIGNED register tx carrying the AgenC program +
        // register_agent discriminator (same shape the sidecar builds).
        let register_tx = {
            use solana_instruction::Instruction;
            use solana_message::Message;
            use solana_transaction::Transaction;
            let program = Pubkey::from_str(AGENC_PROGRAM).unwrap();
            let payer = Pubkey::from([7u8; 32]);
            let ix = Instruction {
                program_id: program,
                accounts: vec![],
                data: REGISTER_DISC.to_vec(),
            };
            let tx = Transaction::new_unsigned(Message::new(&[ix], Some(&payer)));
            B64.encode(bincode::serialize(&tx).unwrap())
        };

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/build-register-agent-tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "unsignedTxB64": register_tx, "agentPda": "Agent1" })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 1, "result": "5xRegisterSigPlaceholder111111111111111111111"
            })))
            .expect(1) // exactly one broadcast (the register+bond tx)
            .mount(&server)
            .await;

        let cfg = test_cfg(&server.uri());
        let wallet = Keypair::new();
        let http = reqwest::Client::new();
        register(&cfg, &wallet, &http)
            .await
            .expect("register must build → assert → sign → broadcast");
    }

    // ── register: a tampered (non-AgenC) tx aborts BEFORE any broadcast ───────
    #[tokio::test]
    async fn register_rejects_tampered_tx_and_never_broadcasts() {
        // A tx whose sole instruction targets a FOREIGN program — the AgenC
        // assert must reject it, so no signature is ever produced or sent.
        let foreign_tx = {
            use solana_instruction::Instruction;
            use solana_message::Message;
            use solana_transaction::Transaction;
            let foreign = Pubkey::from([2u8; 32]);
            let payer = Pubkey::from([7u8; 32]);
            let ix = Instruction {
                program_id: foreign,
                accounts: vec![],
                data: REGISTER_DISC.to_vec(),
            };
            let tx = Transaction::new_unsigned(Message::new(&[ix], Some(&payer)));
            B64.encode(bincode::serialize(&tx).unwrap())
        };

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/build-register-agent-tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "unsignedTxB64": foreign_tx })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc": "2.0", "id": 1, "result": "NOPE"})))
            .expect(0) // the assert fails first — nothing is ever broadcast
            .mount(&server)
            .await;

        let cfg = test_cfg(&server.uri());
        let wallet = Keypair::new();
        let http = reqwest::Client::new();
        assert!(
            register(&cfg, &wallet, &http).await.is_err(),
            "a non-AgenC register tx must abort at assert-before-sign"
        );
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(
            reqs.iter().filter(|r| r.url.path() == "/").count(),
            0,
            "no broadcast when the register assert fails"
        );
    }
}
