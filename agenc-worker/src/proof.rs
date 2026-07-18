//! Worker-signed proof-of-inference: the worker wraps its job/node metadata and
//! artifact hash into a signed object + a 32-byte on-chain commitment
//! (`proof_hash`).
//!
//! The signed [`WorkerProofBody`] has a fixed field order and contains no maps,
//! so `serde_json::to_vec` is byte-stable across runs — that determinism is
//! what makes `proof_hash` reproducible. `signature` is added AFTER signing and
//! is not part of the signed body.
//!
//! Unlike the Nexus attestation, this body carries NO `judge`/verdict field and
//! NO `nexusAttestorPubkey` field: the worker signs with its own key, and its
//! pubkey is already present as `workerAgent`/`nodePubkey`.
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Inputs a worker assembles from its job/node metadata and the built-artifact
/// hash. This is the non-verdict subset of the former `VerificationInput`
/// (no `verdict_pass` / `verdict_reason` / `judge_model`).
pub struct WorkerProofInput {
    pub task_pda: String,
    pub worker_agent: String,
    pub model: String,
    pub compute_job_id: String,
    pub node_pubkey: String,
    pub node_stake_micros: u64,
    pub stake_tx_sig: String,
    pub canary_passed: bool,
    pub artifact_sha256: String,
    pub verified_at: i64,
}

#[derive(Serialize, Clone)]
pub struct Canary {
    pub passed: bool,
}

/// The signed body. Fixed field order, no maps → deterministic serialization.
/// Deliberately omits `judge` and `nexusAttestorPubkey`.
#[derive(Serialize, Clone)]
pub struct WorkerProofBody {
    pub version: u32,
    pub kind: &'static str,
    #[serde(rename = "taskPda")]
    pub task_pda: String,
    #[serde(rename = "workerAgent")]
    pub worker_agent: String,
    pub model: String,
    #[serde(rename = "computeJobId")]
    pub compute_job_id: String,
    #[serde(rename = "nodePubkey")]
    pub node_pubkey: String,
    #[serde(rename = "nodeStakeMicros")]
    pub node_stake_micros: u64,
    #[serde(rename = "stakeTxSig")]
    pub stake_tx_sig: String,
    pub canary: Canary,
    #[serde(rename = "artifactSha256")]
    pub artifact_sha256: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: i64,
}

/// The signed proof: the body flattened at top level + a hex signature.
#[derive(Serialize)]
pub struct SignedWorkerProof {
    #[serde(flatten)]
    pub body: WorkerProofBody,
    /// hex(ed25519 signature over `canonical_body_bytes`).
    pub signature: String,
}

/// Canonical bytes of the SIGNED body (deterministic; excludes signature).
/// This is exactly what the Ed25519 signature covers.
pub fn canonical_body_bytes(proof: &SignedWorkerProof) -> Vec<u8> {
    serde_json::to_vec(&proof.body).expect("WorkerProofBody serializes")
}

/// Build a worker-signed proof and its 32-byte on-chain commitment.
///
/// `proof_hash = sha256(canonical(signed proof))` — it commits the full signed
/// object (body + signature). The body is Ed25519-signed by `worker_key` (the
/// worker's own key). The deterministic serialization of the body is what makes
/// `proof_hash` reproducible across runs for identical inputs.
pub fn build_worker_proof(
    worker_key: &SigningKey,
    input: WorkerProofInput,
) -> (SignedWorkerProof, [u8; 32]) {
    let body = WorkerProofBody {
        version: 1,
        kind: "nexus.worker.proof",
        task_pda: input.task_pda,
        worker_agent: input.worker_agent,
        model: input.model,
        compute_job_id: input.compute_job_id,
        node_pubkey: input.node_pubkey,
        node_stake_micros: input.node_stake_micros,
        stake_tx_sig: input.stake_tx_sig,
        canary: Canary {
            passed: input.canary_passed,
        },
        artifact_sha256: input.artifact_sha256,
        verified_at: input.verified_at,
    };
    let body_bytes = serde_json::to_vec(&body).expect("serialize body");
    let sig = worker_key.sign(&body_bytes);
    let proof = SignedWorkerProof {
        body,
        signature: hex::encode(sig.to_bytes()),
    };
    let signed_bytes = serde_json::to_vec(&proof).expect("serialize signed proof");
    let proof_hash: [u8; 32] = Sha256::digest(&signed_bytes).into();
    (proof, proof_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    /// A fixed input, reconstructed each call (build consumes it by value).
    fn fixed_input() -> WorkerProofInput {
        WorkerProofInput {
            task_pda: "TaskPda11111111111111111111111111111111111".into(),
            worker_agent: "Worker1111111111111111111111111111111111111".into(),
            model: "hermes-3".into(),
            compute_job_id: "11111111-1111-1111-1111-111111111111".into(),
            node_pubkey: "Node111111111111111111111111111111111111111".into(),
            node_stake_micros: 5_000_000,
            stake_tx_sig: "sig111".into(),
            canary_passed: true,
            artifact_sha256: "abcd".into(),
            verified_at: 1_700_000_000,
        }
    }

    #[test]
    fn proof_hash_is_reproducible() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (proof1, h1) = build_worker_proof(&key, fixed_input());
        let (_proof2, h2) = build_worker_proof(&key, fixed_input());
        // Same input + key ⇒ identical 32-byte commitment across runs.
        assert_eq!(h1, h2, "proof_hash must be stable across runs");
        // Re-serializing the returned signed proof re-hashes to the same bytes.
        let rehash: [u8; 32] =
            Sha256::digest(serde_json::to_vec(&proof1).expect("reserialize")).into();
        assert_eq!(rehash, h1, "re-hash of re-serialized signed proof must match");
    }

    #[test]
    fn worker_signature_verifies_against_worker_pubkey() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (proof, _h) = build_worker_proof(&key, fixed_input());
        let body = canonical_body_bytes(&proof);
        let sig =
            ed25519_dalek::Signature::from_slice(&hex::decode(&proof.signature).unwrap()).unwrap();
        // Verifies against the WORKER verifying key (there is no separate verifier key).
        assert!(
            key.verifying_key().verify(&body, &sig).is_ok(),
            "signature must verify against the worker pubkey"
        );
        // A different key must NOT verify — proves it is the worker's signature.
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(
            other.verifying_key().verify(&body, &sig).is_err(),
            "signature must not verify against a foreign key"
        );
    }

    #[test]
    fn body_has_no_verdict_or_attestor_fields() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (proof, _h) = build_worker_proof(&key, fixed_input());
        let body_json = String::from_utf8(canonical_body_bytes(&proof)).unwrap();
        assert!(
            !body_json.contains("judge"),
            "worker proof body must not contain a judge/verdict field: {body_json}"
        );
        assert!(
            !body_json.contains("nexusAttestorPubkey"),
            "worker proof body must not contain nexusAttestorPubkey: {body_json}"
        );
        // Full signed object (body + signature) must also be free of them.
        let signed_json = serde_json::to_string(&proof).unwrap();
        assert!(!signed_json.contains("judge"));
        assert!(!signed_json.contains("nexusAttestorPubkey"));
    }
}
