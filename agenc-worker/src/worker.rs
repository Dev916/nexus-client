//! `worker` — the headless AgenC worker round-trip.
//!
//! `worker_roundtrip` drives the worker-signed leg of the AgenC lifecycle
//! entirely with the worker's OWN key, never touching a Nexus/creator key:
//!
//!   build-claim-tx → assert → sign+send → build_worker_proof →
//!   build-submit-tx → assert → sign+send
//!
//! The unsigned claim/submit txs come from the KEYLESS sidecar build endpoints
//! (`sidecar::BuildApi`, a thin reqwest wrapper over `/build-claim-tx` +
//! `/build-submit-tx`). BEFORE signing anything, every fetched tx is run through
//! [`crate::tx::assert_expected`] so a headless signer never signs an opaque or
//! tampered blob — a wrong program id / discriminator aborts the round-trip with
//! NO signature ever produced. The proof commitment (`proof_hash`) is built by
//! [`crate::proof::build_worker_proof`] and rides the submit tx.
//!
//! This crate stays slim: broadcast is a raw JSON-RPC POST (see `tx`), and no
//! `solana-sdk` / `solana-client` is pulled.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::SigningKey;
use solana_keypair::Keypair;
use solana_program::pubkey::Pubkey;
use solana_signer::Signer;

use crate::proof::{build_worker_proof, WorkerProofInput};
use crate::tx::{assert_expected, sign_and_send, TxError};

/// Orchestrator-verified AgenC program id + Anchor discriminators. The
/// assert-before-sign guardrail rejects any tx that does not target this program
/// with one of these discriminators.
const AGENC_PROGRAM: &str = "HJsZ53Zb27b8QMRbQpuDngE44AdwCGxvEZr61Zmxw1xK";
const CLAIM_DISC: [u8; 8] = [230, 40, 107, 109, 208, 228, 175, 31]; // claim_task_with_job_spec
const SUBMIT_DISC: [u8; 8] = [39, 108, 74, 4, 66, 125, 157, 7]; // submit_task_result

/// Worker-side configuration: where to fetch unsigned txs and where to broadcast.
#[derive(Clone, Debug)]
pub struct WorkerCfg {
    /// Base URL of the keyless sidecar build API (`/build-claim-tx`, `/build-submit-tx`).
    pub build_api_url: String,
    /// Solana JSON-RPC URL for `sendTransaction` broadcast.
    pub rpc_url: String,
}

/// Proof metadata the worker threads into `build_worker_proof`. This is the
/// non-verdict, non-artifact subset the DB/verdict read assembles upstream —
/// `task_pda` + `artifact_sha256` are passed to `worker_roundtrip` separately.
#[derive(Clone, Debug)]
pub struct WorkerMeta {
    pub worker_agent: String,
    pub model: String,
    pub compute_job_id: String,
    pub node_pubkey: String,
    pub node_stake_micros: u64,
    pub stake_tx_sig: String,
    pub canary_passed: bool,
    pub verified_at: i64,
}

/// The result of a worker round-trip: the task it acted on, the hex proof-hash
/// commitment submitted on-chain, and the artifact hash it committed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerSubmit {
    pub task_pda: String,
    pub proof_hash: String,
    pub artifact_sha256: String,
}

/// Errors from the worker round-trip.
#[derive(Debug)]
pub enum WorkerError {
    /// Transport/JSON error talking to the sidecar build API.
    Http(String),
    /// The sidecar build endpoint returned a non-2xx response.
    Sidecar {
        endpoint: String,
        status: u16,
        body: String,
    },
    /// A sidecar response was missing an expected string field.
    MissingField(String),
    /// The assert-before-sign guardrail (or broadcast) failed. When this is an
    /// assert failure NO transaction was ever signed or sent.
    Tx(TxError),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkerError::Http(e) => write!(f, "sidecar transport error: {e}"),
            WorkerError::Sidecar {
                endpoint,
                status,
                body,
            } => write!(f, "sidecar {endpoint} returned {status}: {body}"),
            WorkerError::MissingField(k) => write!(f, "sidecar response missing field `{k}`"),
            WorkerError::Tx(e) => write!(f, "tx guardrail/broadcast failed: {e}"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl From<TxError> for WorkerError {
    fn from(e: TxError) -> Self {
        WorkerError::Tx(e)
    }
}

/// The keyless sidecar build API client. Fetches UNSIGNED claim/submit txs whose
/// fee payer + sole signer is the caller-supplied worker pubkey — no key material
/// ever leaves the worker.
pub mod sidecar {
    use super::WorkerError;

    /// Thin reqwest wrapper over the sidecar's keyless build endpoints.
    pub struct BuildApi {
        client: reqwest::Client,
        base_url: String,
    }

    impl BuildApi {
        /// Build a client pointed at `base_url` (the sidecar's base, no trailing path).
        pub fn new(base_url: impl Into<String>) -> Self {
            BuildApi {
                client: reqwest::Client::new(),
                base_url: base_url.into(),
            }
        }

        async fn post_unsigned_tx(
            &self,
            path: &str,
            body: &serde_json::Value,
        ) -> Result<String, WorkerError> {
            let url = format!("{}{}", self.base_url, path);
            let resp = self
                .client
                .post(&url)
                .json(body)
                .send()
                .await
                .map_err(|e| WorkerError::Http(e.to_string()))?;
            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| WorkerError::Http(e.to_string()))?;
            if !status.is_success() {
                return Err(WorkerError::Sidecar {
                    endpoint: path.to_string(),
                    status: status.as_u16(),
                    body: text,
                });
            }
            let v: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| WorkerError::Http(format!("parse {path} JSON: {e}: {text}")))?;
            v.get("unsignedTxB64")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| WorkerError::MissingField("unsignedTxB64".to_string()))
        }

        /// POST `/build-claim-tx` → the unsigned claim tx (base64).
        pub async fn build_claim_tx(
            &self,
            task_pda: &str,
            worker_pubkey: &str,
        ) -> Result<String, WorkerError> {
            let body = serde_json::json!({ "taskPda": task_pda, "workerPubkey": worker_pubkey });
            self.post_unsigned_tx("/build-claim-tx", &body).await
        }

        /// POST `/build-submit-tx` → the unsigned submit tx (base64).
        pub async fn build_submit_tx(
            &self,
            task_pda: &str,
            worker_pubkey: &str,
            proof_hash_hex: &str,
            result_data: &str,
        ) -> Result<String, WorkerError> {
            let body = serde_json::json!({
                "taskPda": task_pda,
                "workerPubkey": worker_pubkey,
                "proofHashHex": proof_hash_hex,
                "resultData": result_data,
            });
            self.post_unsigned_tx("/build-submit-tx", &body).await
        }
    }
}

/// Derive the Ed25519 signing key from a Solana keypair: the signing-key *seed*
/// is the first 32 bytes of the 64-byte secret key. The resulting verifying key
/// equals the keypair's pubkey, so the worker signs its proof with the SAME
/// identity it signs its transactions with.
fn signing_key_from_keypair(kp: &Keypair) -> SigningKey {
    let bytes = kp.to_bytes(); // [u8; 64] = [seed(32)][pubkey(32)]
    let seed: [u8; 32] = bytes[..32]
        .try_into()
        .expect("keypair secret is at least 32 bytes");
    SigningKey::from_bytes(&seed)
}

/// Drive the worker-signed leg of the AgenC round-trip for an EXISTING task.
///
/// Sequence: build-claim → assert (claim disc) → sign+send → build the worker
/// proof (`proof_hash`) → build-submit (carrying `proof_hash`) → assert (submit
/// disc) → sign+send. Every tx is asserted BEFORE signing; a tampered tx aborts
/// with `WorkerError::Tx(..)` and NO signature is ever produced.
pub async fn worker_roundtrip(
    cfg: &WorkerCfg,
    worker_key: &Keypair,
    task_pda: &str,
    artifact_sha256: &str,
    meta: WorkerMeta,
) -> Result<WorkerSubmit, WorkerError> {
    let program = Pubkey::from_str(AGENC_PROGRAM).expect("valid AgenC program id");
    let worker_pubkey = worker_key.pubkey().to_string();
    let api = sidecar::BuildApi::new(cfg.build_api_url.clone());

    // 1. Claim: fetch unsigned → assert (claim disc) BEFORE signing → sign+send.
    let claim_tx = api.build_claim_tx(task_pda, &worker_pubkey).await?;
    assert_expected(&claim_tx, &program, &[CLAIM_DISC])?;
    sign_and_send(&cfg.rpc_url, &claim_tx, worker_key).await?;

    // 2. Build the worker-signed proof-of-inference commitment.
    let signing_key = signing_key_from_keypair(worker_key);
    let (_proof, proof_hash) = build_worker_proof(
        &signing_key,
        WorkerProofInput {
            task_pda: task_pda.to_string(),
            worker_agent: meta.worker_agent,
            model: meta.model,
            compute_job_id: meta.compute_job_id,
            node_pubkey: meta.node_pubkey,
            node_stake_micros: meta.node_stake_micros,
            stake_tx_sig: meta.stake_tx_sig,
            canary_passed: meta.canary_passed,
            artifact_sha256: artifact_sha256.to_string(),
            verified_at: meta.verified_at,
        },
    );
    let proof_hash_hex = hex::encode(proof_hash);

    // 3. Submit: fetch unsigned (carrying proof_hash) → assert (submit disc) → sign+send.
    let result_data = format!("artifact:sha256:{artifact_sha256}");
    let submit_tx = api
        .build_submit_tx(task_pda, &worker_pubkey, &proof_hash_hex, &result_data)
        .await?;
    assert_expected(&submit_tx, &program, &[SUBMIT_DISC])?;
    sign_and_send(&cfg.rpc_url, &submit_tx, worker_key).await?;

    Ok(WorkerSubmit {
        task_pda: task_pda.to_string(),
        proof_hash: proof_hash_hex,
        artifact_sha256: artifact_sha256.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde_json::json;
    use solana_transaction::Transaction;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // REAL unsigned web3.js LEGACY claim/submit txs captured from the Task-2
    // sidecar builders (reused from the Task-3 fixtures). Hardcoding real sidecar
    // output keeps the worker round-trip honest about web3.js ↔ Rust wire format.
    const CLAIM_TX_B64: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAUJxz7HowzB5mS69nWiCu+u0+14vA3KF2+KMwCPDqoacWoiGeX2SAlnVofWlXJqbp1U8dTptvDrnwS5hZuhT6pd9q7u8oGBh8G/dVCauiU7ykwM3del+HosFmBuUR2A2JFF6AJtxs+kfZOMlGCWmf87PrBeT5GDBJcySlrgf+BK/iAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAAu9J71yR3FOHwTeg+1scjy59xDh8N4gz3N6eU9SK9qHjyTwZjQCaGvZn+Y82/+nVRTbbSKIfGIqrvTvbb7UT16PLwXXGJLaaMm6Na6xX4dSXEgKpDV+yLvCagOmB0hwJT69uecUz5z3Qnnl1iKXiUTEVbXSekrHd2wZ6UrNvdwqACBQAFAkANAwAHBwEIAwYCAAQI5ihrbdDkrx8=";
    const SUBMIT_TX_B64: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAUKxz7HowzB5mS69nWiCu+u0+14vA3KF2+KMwCPDqoacWoRhjOyEUEmdpuR2uVOZSzmL6pgQJsw/HptTYgFX1kgCCIZ5fZICWdWh9aVcmpunVTx1Om28OufBLmFm6FPql32plAmamcnpxT4a8Fud+JgLAkvReuiU2xjyXIWBDTqHhroAm3Gz6R9k4yUYJaZ/zs+sF5PkYMElzJKWuB/4Er+IAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAru7ygYGHwb91UJq6JTvKTAzd16X4eiwWYG5RHYDYkUUDBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAALvSe9ckdxTh8E3oPtbHI8ufcQ4fDeIM9zenlPUivah48k8GY0Amhr2Z/mPNv/p1UU220iiHxiKq70722+1E9ejr255xTPnPdCeeXWIpeJRMRVtdJ6Ssd3bBnpSs293CoAIHAAUCQA0DAAkIAgQBAwgGAAVpJ2xKBEJ9nQeqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgFhcnRpZmFjdDpzaGEyNTY6ZGVhZGJlZWYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn sample_meta() -> WorkerMeta {
        WorkerMeta {
            worker_agent: "Worker1111111111111111111111111111111111111".into(),
            model: "hermes-3".into(),
            compute_job_id: "11111111-1111-1111-1111-111111111111".into(),
            node_pubkey: "Node111111111111111111111111111111111111111".into(),
            node_stake_micros: 5_000_000,
            stake_tx_sig: String::new(),
            canary_passed: true,
            verified_at: 1_700_000_000,
        }
    }

    fn expected_proof_hash(worker: &Keypair, task_pda: &str, artifact: &str, meta: &WorkerMeta) -> String {
        let sk = signing_key_from_keypair(worker);
        let (_p, h) = build_worker_proof(
            &sk,
            WorkerProofInput {
                task_pda: task_pda.to_string(),
                worker_agent: meta.worker_agent.clone(),
                model: meta.model.clone(),
                compute_job_id: meta.compute_job_id.clone(),
                node_pubkey: meta.node_pubkey.clone(),
                node_stake_micros: meta.node_stake_micros,
                stake_tx_sig: meta.stake_tx_sig.clone(),
                canary_passed: meta.canary_passed,
                artifact_sha256: artifact.to_string(),
                verified_at: meta.verified_at,
            },
        );
        hex::encode(h)
    }

    // Decode a real tx, swap the AgenC program key for a foreign one, re-encode:
    // the instruction now targets a non-AgenC program → the guardrail must reject.
    fn tamper_program(tx_b64: &str) -> String {
        let raw = B64.decode(tx_b64).unwrap();
        let mut tx: Transaction = bincode::deserialize(&raw).unwrap();
        let prog = Pubkey::from_str(AGENC_PROGRAM).unwrap();
        let foreign = Pubkey::from([3u8; 32]);
        let mut swapped = false;
        for k in tx.message.account_keys.iter_mut() {
            if *k == prog {
                *k = foreign;
                swapped = true;
            }
        }
        assert!(swapped, "real tx must contain the AgenC program key");
        B64.encode(bincode::serialize(&tx).unwrap())
    }

    // ── Happy path: full worker round-trip returns the expected proof hash ─────
    #[tokio::test]
    async fn worker_roundtrip_happy_path_returns_expected_proof_hash() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/build-claim-tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "unsignedTxB64": CLAIM_TX_B64, "claimPda": "Claim1", "agentPda": "Agent1"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/build-submit-tx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "unsignedTxB64": SUBMIT_TX_B64, "claimPda": "Claim1", "agentPda": "Agent1", "submissionPda": "Sub1"
            })))
            .mount(&server)
            .await;
        // JSON-RPC sendTransaction at the root path.
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 1, "result": "5xSignatureBase58Placeholder1111111111111111"
            })))
            .expect(2) // exactly two broadcasts: claim + submit
            .mount(&server)
            .await;

        let worker = Keypair::new();
        let cfg = WorkerCfg {
            build_api_url: server.uri(),
            rpc_url: server.uri(),
        };
        let meta = sample_meta();
        let task_pda = "TaskPda11111111111111111111111111111111111";
        let artifact = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";

        let submit = worker_roundtrip(&cfg, &worker, task_pda, artifact, meta.clone())
            .await
            .expect("happy path must succeed");

        assert_eq!(submit.task_pda, task_pda);
        assert_eq!(submit.artifact_sha256, artifact);
        assert_eq!(
            submit.proof_hash,
            expected_proof_hash(&worker, task_pda, artifact, &meta),
            "proof_hash must match build_worker_proof for the same input"
        );
    }

    // ── Abort path: tampered claim tx → error at assert, ZERO broadcasts ───────
    #[tokio::test]
    async fn worker_roundtrip_aborts_at_assert_and_never_sends() {
        let server = MockServer::start().await;
        let tampered = tamper_program(CLAIM_TX_B64);

        Mock::given(method("POST"))
            .and(path("/build-claim-tx"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "unsignedTxB64": tampered })),
            )
            .mount(&server)
            .await;
        // The RPC sendTransaction mock MUST NOT be called — wiremock verifies 0 on drop.
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 1, "result": "SHOULD_NEVER_BE_RETURNED"
            })))
            .expect(0)
            .mount(&server)
            .await;

        let worker = Keypair::new();
        let cfg = WorkerCfg {
            build_api_url: server.uri(),
            rpc_url: server.uri(),
        };

        let err = worker_roundtrip(
            &cfg,
            &worker,
            "TaskPda11111111111111111111111111111111111",
            "deadbeef",
            sample_meta(),
        )
        .await
        .expect_err("tampered claim tx must abort the round-trip");

        assert!(
            matches!(err, WorkerError::Tx(TxError::ProgramAbsent)),
            "must abort at the assert step (ProgramAbsent), got {err:?}"
        );

        // Belt-and-suspenders: no request ever reached the JSON-RPC root path.
        let reqs = server.received_requests().await.unwrap();
        let sends = reqs.iter().filter(|r| r.url.path() == "/").count();
        assert_eq!(sends, 0, "worker must NOT broadcast when the assert fails");
    }
}
