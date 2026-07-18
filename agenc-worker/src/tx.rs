//! `tx` — assert-before-sign guardrail, local Ed25519 signing, and raw JSON-RPC
//! broadcast for the headless AgenC worker.
//!
//! A headless signer must NEVER sign an opaque blob. Before signing, the worker
//! deserializes the unsigned (web3.js LEGACY) transaction, confirms it carries
//! the expected AgenC program id, and confirms every AgenC-program instruction's
//! 8-byte Anchor discriminator is in the caller's allow-list. Only then does it
//! sign locally with its OWN keypair and broadcast via a raw `sendTransaction`
//! JSON-RPC POST over `reqwest` (rustls, no openssl).
//!
//! This crate deliberately avoids `solana-sdk`/`solana-client`/`solana-rpc-client`
//! so it stays client-consumable (nexus-client's slim-deps rule). Parsing uses
//! the slim `solana-transaction`/`solana-message` crates; broadcast is a
//! hand-rolled JSON-RPC request — nothing pulls the fat SDK.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use solana_keypair::Keypair;
use solana_program::pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::fmt;

/// Errors from the assert-before-sign / broadcast path.
#[derive(Debug)]
pub enum TxError {
    /// The base64 payload could not be decoded.
    Base64(String),
    /// The bytes did not deserialize as a legacy Solana transaction.
    Deserialize(String),
    /// No instruction in the tx targets the expected AgenC program id.
    ProgramAbsent,
    /// An AgenC-program instruction's discriminator is not in the allow-list.
    BadDiscriminator([u8; 8]),
    /// An AgenC-program instruction's data is too short to hold a discriminator.
    ShortData,
    /// Transport/JSON failure talking to the RPC.
    Http(String),
    /// The RPC returned a JSON-RPC `error` object (or no `result`).
    Rpc(String),
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxError::Base64(e) => write!(f, "base64 decode failed: {e}"),
            TxError::Deserialize(e) => write!(f, "tx deserialize failed: {e}"),
            TxError::ProgramAbsent => {
                write!(f, "no instruction targets the expected AgenC program id")
            }
            TxError::BadDiscriminator(d) => {
                write!(f, "AgenC instruction has unexpected discriminator: {d:?}")
            }
            TxError::ShortData => write!(f, "AgenC instruction data shorter than 8 bytes"),
            TxError::Http(e) => write!(f, "rpc transport error: {e}"),
            TxError::Rpc(e) => write!(f, "rpc returned error: {e}"),
        }
    }
}

impl std::error::Error for TxError {}

/// Assert the unsigned tx is EXACTLY what we expect BEFORE signing.
///
/// Decodes + deserializes the web3.js legacy tx, then for every instruction whose
/// program == `program_id` requires its first 8 bytes (the Anchor discriminator)
/// to be in `expected`. Requires AT LEAST ONE such instruction. Benign
/// ComputeBudget/System instructions (different program ids) are ignored. Errs on
/// the side of REJECTING anything unexpected.
pub fn assert_expected(
    unsigned_tx_b64: &str,
    program_id: &Pubkey,
    expected: &[[u8; 8]],
) -> Result<(), TxError> {
    let raw = B64
        .decode(unsigned_tx_b64.trim())
        .map_err(|e| TxError::Base64(e.to_string()))?;
    let tx: Transaction =
        bincode::deserialize(&raw).map_err(|e| TxError::Deserialize(e.to_string()))?;

    let keys = &tx.message.account_keys;
    let mut saw_agenc = false;
    for ix in &tx.message.instructions {
        let prog = keys
            .get(ix.program_id_index as usize)
            .ok_or_else(|| TxError::Deserialize("program_id_index out of range".into()))?;
        if prog != program_id {
            // Benign ComputeBudget / System / etc. instruction — not our concern.
            continue;
        }
        saw_agenc = true;
        if ix.data.len() < 8 {
            return Err(TxError::ShortData);
        }
        let mut disc = [0u8; 8];
        disc.copy_from_slice(&ix.data[..8]);
        if !expected.contains(&disc) {
            return Err(TxError::BadDiscriminator(disc));
        }
    }
    if !saw_agenc {
        return Err(TxError::ProgramAbsent);
    }
    Ok(())
}

/// Ed25519-sign `message_bytes` with the worker's OWN keypair.
pub fn sign_message(key: &Keypair, message_bytes: &[u8]) -> Signature {
    // `Signer::sign_message` is the ed25519 sign over the raw message bytes.
    key.sign_message(message_bytes)
}

/// Assemble the Solana wire tx: `shortvec(1) ++ sig(64) ++ message_bytes`.
pub fn assemble_wire_tx(sig: &Signature, message_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 64 + message_bytes.len());
    // shortvec length of a single-element signature vec: 1 fits in one byte (<128).
    out.push(1u8);
    out.extend_from_slice(sig.as_ref()); // exactly 64 bytes
    out.extend_from_slice(message_bytes);
    out
}

/// Broadcast a base64 signed tx via a raw `sendTransaction` JSON-RPC POST.
pub async fn send_json_rpc(rpc_url: &str, signed_tx_b64: &str) -> Result<String, TxError> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": [signed_tx_b64, {"encoding": "base64"}],
    });
    let client = reqwest::Client::new();
    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| TxError::Http(e.to_string()))?;
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| TxError::Http(e.to_string()))?;
    if let Some(err) = v.get("error") {
        return Err(TxError::Rpc(err.to_string()));
    }
    v.get("result")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| TxError::Rpc(format!("no result in response: {v}")))
}

/// Decode → extract message bytes → sign locally → assemble wire tx → broadcast.
pub async fn sign_and_send(
    rpc_url: &str,
    unsigned_tx_b64: &str,
    key: &Keypair,
) -> Result<String, TxError> {
    let raw = B64
        .decode(unsigned_tx_b64.trim())
        .map_err(|e| TxError::Base64(e.to_string()))?;
    let tx: Transaction =
        bincode::deserialize(&raw).map_err(|e| TxError::Deserialize(e.to_string()))?;
    // The message bytes are exactly what web3.js signs: the bincode/shortvec
    // legacy-message wire format. Sign those, then frame [1][sig][message].
    let message_bytes =
        bincode::serialize(&tx.message).map_err(|e| TxError::Deserialize(e.to_string()))?;
    let sig = sign_message(key, &message_bytes);
    let wire = assemble_wire_tx(&sig, &message_bytes);
    let signed_b64 = B64.encode(&wire);
    send_json_rpc(rpc_url, &signed_b64).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use std::str::FromStr;

    // Orchestrator-verified AgenC program id + Anchor discriminators.
    const AGENC_PROGRAM: &str = "HJsZ53Zb27b8QMRbQpuDngE44AdwCGxvEZr61Zmxw1xK";
    const CLAIM_DISC: [u8; 8] = [230, 40, 107, 109, 208, 228, 175, 31]; // claim_task_with_job_spec
    const SUBMIT_DISC: [u8; 8] = [39, 108, 74, 4, 66, 125, 157, 7]; // submit_task_result

    // REAL unsigned web3.js LEGACY txs captured from the Task-2 sidecar builders
    // (buildClaimTx / buildSubmitTx, offline via an injected getBlockhash stub).
    // Hardcoding real sidecar output proves web3.js ↔ Rust wire-format compat.
    const CLAIM_TX_B64: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAUJxz7HowzB5mS69nWiCu+u0+14vA3KF2+KMwCPDqoacWoiGeX2SAlnVofWlXJqbp1U8dTptvDrnwS5hZuhT6pd9q7u8oGBh8G/dVCauiU7ykwM3del+HosFmBuUR2A2JFF6AJtxs+kfZOMlGCWmf87PrBeT5GDBJcySlrgf+BK/iAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAAu9J71yR3FOHwTeg+1scjy59xDh8N4gz3N6eU9SK9qHjyTwZjQCaGvZn+Y82/+nVRTbbSKIfGIqrvTvbb7UT16PLwXXGJLaaMm6Na6xX4dSXEgKpDV+yLvCagOmB0hwJT69uecUz5z3Qnnl1iKXiUTEVbXSekrHd2wZ6UrNvdwqACBQAFAkANAwAHBwEIAwYCAAQI5ihrbdDkrx8=";
    const SUBMIT_TX_B64: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAUKxz7HowzB5mS69nWiCu+u0+14vA3KF2+KMwCPDqoacWoRhjOyEUEmdpuR2uVOZSzmL6pgQJsw/HptTYgFX1kgCCIZ5fZICWdWh9aVcmpunVTx1Om28OufBLmFm6FPql32plAmamcnpxT4a8Fud+JgLAkvReuiU2xjyXIWBDTqHhroAm3Gz6R9k4yUYJaZ/zs+sF5PkYMElzJKWuB/4Er+IAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAru7ygYGHwb91UJq6JTvKTAzd16X4eiwWYG5RHYDYkUUDBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAALvSe9ckdxTh8E3oPtbHI8ufcQ4fDeIM9zenlPUivah48k8GY0Amhr2Z/mPNv/p1UU220iiHxiKq70722+1E9ejr255xTPnPdCeeXWIpeJRMRVtdJ6Ssd3bBnpSs293CoAIHAAUCQA0DAAkIAgQBAwgGAAVpJ2xKBEJ9nQeqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgFhcnRpZmFjdDpzaGEyNTY6ZGVhZGJlZWYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn agenc() -> Pubkey {
        Pubkey::from_str(AGENC_PROGRAM).unwrap()
    }

    // Build a synthetic unsigned legacy tx carrying ONE instruction for `program`
    // whose data starts with `disc`. Uses solana-instruction/message/transaction
    // (the same slim crates) so the fixture round-trips through the same decoder.
    fn build_unsigned(program: Pubkey, disc: [u8; 8], payer: &Pubkey) -> String {
        use solana_instruction::Instruction;
        use solana_message::Message;
        let ix = Instruction {
            program_id: program,
            accounts: vec![],
            data: disc.to_vec(),
        };
        let msg = Message::new(&[ix], Some(payer));
        let tx = Transaction::new_unsigned(msg);
        B64.encode(bincode::serialize(&tx).unwrap())
    }

    // ── Guardrail: ACCEPT real claim + submit txs ────────────────────────────

    #[test]
    fn accepts_real_claim_and_submit_fixtures() {
        let prog = agenc();
        let allow = [CLAIM_DISC, SUBMIT_DISC];
        assert!(
            assert_expected(CLAIM_TX_B64, &prog, &allow).is_ok(),
            "real claim tx must be accepted"
        );
        assert!(
            assert_expected(SUBMIT_TX_B64, &prog, &allow).is_ok(),
            "real submit tx must be accepted"
        );
    }

    // ── Guardrail: REJECT tampered program id (primary negative case) ─────────

    #[test]
    fn rejects_tampered_program_id_synthetic() {
        // A wrong program id carrying a REAL claim discriminator: the AgenC
        // program is absent, so the guardrail must reject.
        let payer = Pubkey::from([1u8; 32]);
        let wrong_program = Pubkey::from([2u8; 32]);
        let b64 = build_unsigned(wrong_program, CLAIM_DISC, &payer);
        let err = assert_expected(&b64, &agenc(), &[CLAIM_DISC, SUBMIT_DISC]).unwrap_err();
        assert!(
            matches!(err, TxError::ProgramAbsent),
            "wrong program id must be ProgramAbsent, got {err:?}"
        );
    }

    #[test]
    fn rejects_tampered_program_id_on_real_tx() {
        // Decode the REAL claim tx, swap the AgenC account key for a foreign one,
        // re-encode: the instruction now points at a non-AgenC program.
        let raw = B64.decode(CLAIM_TX_B64).unwrap();
        let mut tx: Transaction = bincode::deserialize(&raw).unwrap();
        let prog = agenc();
        let foreign = Pubkey::from([3u8; 32]);
        let mut swapped = false;
        for k in tx.message.account_keys.iter_mut() {
            if *k == prog {
                *k = foreign;
                swapped = true;
            }
        }
        assert!(swapped, "real tx must contain the AgenC program key");
        let tampered = B64.encode(bincode::serialize(&tx).unwrap());
        let err = assert_expected(&tampered, &prog, &[CLAIM_DISC, SUBMIT_DISC]).unwrap_err();
        assert!(
            matches!(err, TxError::ProgramAbsent),
            "tampered real tx must be ProgramAbsent, got {err:?}"
        );
    }

    // ── Guardrail: REJECT a discriminator outside the expected set ────────────

    #[test]
    fn rejects_wrong_discriminator_synthetic() {
        let payer = Pubkey::from([1u8; 32]);
        let bogus = [9u8; 8];
        let b64 = build_unsigned(agenc(), bogus, &payer);
        let err = assert_expected(&b64, &agenc(), &[CLAIM_DISC, SUBMIT_DISC]).unwrap_err();
        assert!(
            matches!(err, TxError::BadDiscriminator(d) if d == bogus),
            "unexpected discriminator must be BadDiscriminator, got {err:?}"
        );
    }

    #[test]
    fn rejects_real_claim_tx_when_disc_not_in_expected_set() {
        // The REAL claim tx carries the claim discriminator; if the caller only
        // allows submit, the guardrail must reject it.
        let err = assert_expected(CLAIM_TX_B64, &agenc(), &[SUBMIT_DISC]).unwrap_err();
        assert!(
            matches!(err, TxError::BadDiscriminator(d) if d == CLAIM_DISC),
            "claim tx against submit-only allow-list must reject, got {err:?}"
        );
    }

    // ── Local signing + wire framing ─────────────────────────────────────────

    #[test]
    fn sign_message_verifies_and_wire_framing_is_correct() {
        let key = Keypair::new();
        let message_bytes = b"nexus.agenc.worker unsigned message bytes".to_vec();

        let sig = sign_message(&key, &message_bytes);

        // The Ed25519 signature verifies against the worker pubkey.
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&key.pubkey().to_bytes())
            .expect("worker pubkey is a valid ed25519 point");
        let dsig = ed25519_dalek::Signature::from_slice(sig.as_ref()).unwrap();
        assert!(
            vk.verify(&message_bytes, &dsig).is_ok(),
            "signature must verify against the worker pubkey"
        );
        // A foreign key must NOT verify.
        let other = Keypair::new();
        let other_vk = ed25519_dalek::VerifyingKey::from_bytes(&other.pubkey().to_bytes()).unwrap();
        assert!(
            other_vk.verify(&message_bytes, &dsig).is_err(),
            "signature must not verify against a foreign key"
        );

        // Wire framing: [num_sigs=1][sig(64)][message].
        let wire = assemble_wire_tx(&sig, &message_bytes);
        assert_eq!(wire[0], 1, "shortvec signature count must be 1");
        assert_eq!(&wire[1..65], sig.as_ref(), "bytes 1..65 must be the 64-byte sig");
        assert_eq!(&wire[65..], &message_bytes[..], "remaining bytes must be the message");
        assert_eq!(wire.len(), 1 + 64 + message_bytes.len(), "wire length = 1+64+|msg|");
    }
}
