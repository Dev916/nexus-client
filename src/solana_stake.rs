//! On-chain GNN staking helpers — raw Solana JSON-RPC over the existing
//! rustls `reqwest` client (NO `solana-client`/`solana-rpc-client`, which
//! would drag in openssl and break the static Windows/musl release builds).
//!
//! This module is split into two layers:
//!
//! * **Pure parsers** (`parse_blockhash`, `parse_token_balance`,
//!   `parse_send_sig`, `parse_signature_finalized`) — operate on a
//!   `serde_json::Value` and have no I/O, so they are exhaustively
//!   unit-testable against fixtures that mirror real JSON-RPC responses.
//! * **`Rpc`** — a thin async client that POSTs JSON-RPC requests to a
//!   configured endpoint and threads the body through the pure parsers.
//!
//! `build_signed_stake_tx` builds and signs the GNN `transfer_checked` SPL
//! transfer using the slim Solana/SPL crate stack (NO `solana-sdk`).

use std::str::FromStr;

use base64::prelude::{BASE64_STANDARD, Engine as _};
use serde_json::{Value, json};
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_message::Message;
// `solana_program` re-exports `solana_pubkey::Pubkey`, so this is the same
// `Pubkey` type the slim ATA/signer crates use. `solana-program` is a direct
// dep; `solana-pubkey` is only transitive.
use solana_program::pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

/// Build and sign a GNN `transfer_checked` SPL transfer from `wallet` to the
/// associated token account of `treasury`, returning the base64-encoded,
/// bincode-serialized [`Transaction`] ready for `sendTransaction`.
///
/// * `mint` / `treasury` — base58 pubkeys.
/// * `amount_raw` — token amount in raw units (GNN has 6 decimals).
/// * `recent_blockhash` — base58 blockhash from `getLatestBlockhash`.
///
/// The source/destination accounts are the associated token accounts (ATAs)
/// of the wallet and treasury respectively, derived deterministically. The
/// transaction is fully signed by `wallet` (the fee payer and transfer
/// authority) against `recent_blockhash`.
///
/// Deliberately uses only the slim crates — `solana-sdk`/`solana-client` would
/// drag in openssl and break the static release builds.
pub fn build_signed_stake_tx(
    wallet: &Keypair,
    mint: &str,
    treasury: &str,
    amount_raw: u64,
    recent_blockhash: &str,
) -> Result<String, String> {
    let mint_pk = Pubkey::from_str(mint).map_err(|e| format!("invalid mint pubkey {mint:?}: {e}"))?;
    let treasury_pk = Pubkey::from_str(treasury)
        .map_err(|e| format!("invalid treasury pubkey {treasury:?}: {e}"))?;
    let blockhash = Hash::from_str(recent_blockhash)
        .map_err(|e| format!("invalid recent blockhash {recent_blockhash:?}: {e}"))?;

    let owner = wallet.pubkey();
    let src_ata =
        spl_associated_token_account::get_associated_token_address(&owner, &mint_pk);
    let dst_ata =
        spl_associated_token_account::get_associated_token_address(&treasury_pk, &mint_pk);

    // GNN has 6 decimals; `transfer_checked` validates this on-chain.
    let ix = spl_token::instruction::transfer_checked(
        &spl_token::id(),
        &src_ata,
        &mint_pk,
        &dst_ata,
        &owner,
        &[],
        amount_raw,
        6,
    )
    .map_err(|e| format!("building transfer_checked instruction failed: {e}"))?;

    let message = Message::new(&[ix], Some(&owner));
    // `Transaction::new` records `blockhash` into the message and signs.
    let tx = Transaction::new(&[wallet], message, blockhash);

    let bytes = bincode::serialize(&tx)
        .map_err(|e| format!("bincode-serializing transaction failed: {e}"))?;
    Ok(BASE64_STANDARD.encode(bytes))
}

// ---------------------------------------------------------------------------
// Pure parsers (no network) — unit-tested below.
// ---------------------------------------------------------------------------

/// Extract the recent blockhash from a `getLatestBlockhash` response.
///
/// Shape: `{"jsonrpc":"2.0","result":{"context":{...},"value":{"blockhash":"...","lastValidBlockHeight":N}},"id":1}`
pub fn parse_blockhash(v: &Value) -> Result<String, String> {
    if let Some(err) = rpc_error(v) {
        return Err(err);
    }
    v.get("result")
        .and_then(|r| r.get("value"))
        .and_then(|val| val.get("blockhash"))
        .and_then(|bh| bh.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "getLatestBlockhash: missing result.value.blockhash".to_string())
}

/// Sum the GNN token amount across a wallet's parsed token accounts.
///
/// Accepts both response shapes:
/// * `getTokenAccountsByOwner` →
///   `result.value[*].account.data.parsed.info.tokenAmount.amount` (decimal
///   string of raw units). Multiple matching accounts are summed.
/// * `getTokenAccountBalance` → `result.value.amount` (single account).
///
/// Returns the total raw amount (u64). Zero accounts ⇒ `Ok(0)`.
pub fn parse_token_balance(v: &Value) -> Result<u64, String> {
    if let Some(err) = rpc_error(v) {
        return Err(err);
    }
    let value = v
        .get("result")
        .and_then(|r| r.get("value"))
        .ok_or_else(|| "token balance: missing result.value".to_string())?;

    // getTokenAccountBalance: result.value.amount is a decimal string.
    if let Some(amount) = value.get("amount").and_then(|a| a.as_str()) {
        return parse_amount_str(amount);
    }

    // getTokenAccountsByOwner: result.value is an array of accounts.
    if let Some(accounts) = value.as_array() {
        let mut total: u64 = 0;
        for acct in accounts {
            let amount = acct
                .pointer("/account/data/parsed/info/tokenAmount/amount")
                .and_then(|a| a.as_str())
                .ok_or_else(|| {
                    "token balance: missing account.data.parsed.info.tokenAmount.amount".to_string()
                })?;
            let raw = parse_amount_str(amount)?;
            total = total
                .checked_add(raw)
                .ok_or_else(|| "token balance: overflow summing accounts".to_string())?;
        }
        return Ok(total);
    }

    Err("token balance: result.value is neither an amount object nor an account array".to_string())
}

/// Extract the transaction signature returned by `sendTransaction`.
///
/// Shape: `{"jsonrpc":"2.0","result":"<base58 signature>","id":1}`.
pub fn parse_send_sig(v: &Value) -> Result<String, String> {
    if let Some(err) = rpc_error(v) {
        return Err(err);
    }
    v.get("result")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "sendTransaction: result is not a signature string".to_string())
}

/// Inspect a `getSignatureStatuses` response and decide whether the first
/// signature has reached the `finalized` confirmation level.
///
/// Shape: `result.value[0]` is either `null` (unknown/dropped) or
/// `{"slot":N,"confirmations":..,"err":null,"confirmationStatus":"finalized"}`.
///
/// Returns:
/// * `Ok(true)`  — finalized and no on-chain error.
/// * `Ok(false)` — known but not yet finalized (processed/confirmed/unknown).
/// * `Err(..)`   — the transaction failed on-chain (`err` is non-null) or the
///   RPC returned an error envelope.
pub fn parse_signature_finalized(v: &Value) -> Result<bool, String> {
    if let Some(err) = rpc_error(v) {
        return Err(err);
    }
    let first = v
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|val| val.as_array())
        .and_then(|arr| arr.first())
        .ok_or_else(|| "getSignatureStatuses: missing result.value[0]".to_string())?;

    // null status => not yet visible to this RPC node.
    if first.is_null() {
        return Ok(false);
    }

    // On-chain failure surfaces in `err`.
    if let Some(err) = first.get("err").filter(|e| !e.is_null()) {
        return Err(format!("transaction failed on-chain: {err}"));
    }

    let status = first
        .get("confirmationStatus")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    Ok(status == "finalized")
}

/// Parse a decimal raw-unit amount string into a u64.
fn parse_amount_str(s: &str) -> Result<u64, String> {
    s.parse::<u64>()
        .map_err(|e| format!("invalid token amount {s:?}: {e}"))
}

/// If the JSON-RPC envelope carries an `error`, render it as a `String`.
fn rpc_error(v: &Value) -> Option<String> {
    v.get("error").filter(|e| !e.is_null()).map(|e| {
        let msg = e
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown RPC error");
        let code = e.get("code").and_then(|c| c.as_i64());
        match code {
            Some(c) => format!("RPC error {c}: {msg}"),
            None => format!("RPC error: {msg}"),
        }
    })
}

// ---------------------------------------------------------------------------
// Rpc — thin async JSON-RPC client over the existing rustls reqwest.
// ---------------------------------------------------------------------------

/// A minimal Solana JSON-RPC client targeting a single endpoint URL.
///
/// Deliberately does NOT use `solana-client`/`solana-rpc-client` — those pull
/// openssl and would break the static release builds. All requests go through
/// the existing rustls `reqwest::Client`.
pub struct Rpc {
    url: String,
}

impl Rpc {
    /// Construct an `Rpc` for the given JSON-RPC endpoint (e.g.
    /// `https://api.devnet.solana.com`).
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// The configured endpoint URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// POST a JSON-RPC request and return the parsed response `Value`.
    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let client = reqwest::Client::new();
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("{method} request to {} failed: {e}", self.url))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("{method}: reading response body failed: {e}"))?;
        if !status.is_success() {
            return Err(format!("{method}: RPC returned {status}: {text}"));
        }
        serde_json::from_str::<Value>(&text)
            .map_err(|e| format!("{method}: invalid JSON from RPC: {e} (body: {text})"))
    }

    /// Fetch the latest blockhash (`getLatestBlockhash`).
    pub async fn get_latest_blockhash(&self) -> Result<String, String> {
        let v = self
            .call(
                "getLatestBlockhash",
                json!([{"commitment": "finalized"}]),
            )
            .await?;
        parse_blockhash(&v)
    }

    /// Fetch the wallet's total GNN balance (raw units) for `mint`
    /// (`getTokenAccountsByOwner`, filtered by mint, jsonParsed encoding).
    pub async fn get_gnn_balance(&self, owner: &str, mint: &str) -> Result<u64, String> {
        let v = self
            .call(
                "getTokenAccountsByOwner",
                json!([
                    owner,
                    {"mint": mint},
                    {"encoding": "jsonParsed", "commitment": "confirmed"}
                ]),
            )
            .await?;
        parse_token_balance(&v)
    }

    /// Submit a base64-encoded signed transaction (`sendTransaction`).
    pub async fn send_transaction(&self, b64: &str) -> Result<String, String> {
        let v = self
            .call(
                "sendTransaction",
                json!([
                    b64,
                    {"encoding": "base64", "skipPreflight": false, "preflightCommitment": "confirmed"}
                ]),
            )
            .await?;
        parse_send_sig(&v)
    }

    /// Poll `getSignatureStatuses` until the signature reaches `finalized`
    /// (or the on-chain tx fails). Bounded retry budget (~30 attempts × 2s).
    pub async fn confirm_finalized(&self, sig: &str) -> Result<(), String> {
        const MAX_ATTEMPTS: usize = 30;
        for attempt in 0..MAX_ATTEMPTS {
            let v = self
                .call(
                    "getSignatureStatuses",
                    json!([[sig], {"searchTransactionHistory": true}]),
                )
                .await?;
            if parse_signature_finalized(&v)? {
                return Ok(());
            }
            if attempt + 1 < MAX_ATTEMPTS {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
        Err(format!(
            "transaction {sig} not finalized within retry budget (still pending)"
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests — pure parsers against fixtures mirroring real JSON-RPC responses.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_blockhash() {
        // getLatestBlockhash response shape.
        let v = json!({
            "jsonrpc": "2.0",
            "result": {
                "context": {"slot": 2792},
                "value": {
                    "blockhash": "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N",
                    "lastValidBlockHeight": 3090
                }
            },
            "id": 1
        });
        assert_eq!(
            parse_blockhash(&v).unwrap(),
            "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"
        );
    }

    #[test]
    fn blockhash_missing_value_errors() {
        let v = json!({"jsonrpc": "2.0", "result": {}, "id": 1});
        assert!(parse_blockhash(&v).is_err());
    }

    #[test]
    fn parses_token_balance_by_owner_single() {
        // getTokenAccountsByOwner (jsonParsed) shape, one account.
        let v = json!({
            "jsonrpc": "2.0",
            "result": {
                "context": {"slot": 1114},
                "value": [
                    {
                        "account": {
                            "data": {
                                "parsed": {
                                    "info": {
                                        "tokenAmount": {
                                            "amount": "2500000",
                                            "decimals": 6,
                                            "uiAmount": 2.5,
                                            "uiAmountString": "2.5"
                                        }
                                    },
                                    "type": "account"
                                },
                                "program": "spl-token"
                            }
                        },
                        "pubkey": "ATA1111111111111111111111111111111111111111"
                    }
                ]
            },
            "id": 1
        });
        assert_eq!(parse_token_balance(&v).unwrap(), 2_500_000);
    }

    #[test]
    fn parses_token_balance_by_owner_summed() {
        // Two matching accounts are summed.
        let v = json!({
            "result": {
                "value": [
                    {"account": {"data": {"parsed": {"info": {"tokenAmount": {"amount": "1000000"}}}}}},
                    {"account": {"data": {"parsed": {"info": {"tokenAmount": {"amount": "500000"}}}}}}
                ]
            }
        });
        assert_eq!(parse_token_balance(&v).unwrap(), 1_500_000);
    }

    #[test]
    fn parses_token_balance_empty_is_zero() {
        // No token accounts for this owner/mint => 0 balance.
        let v = json!({"result": {"value": []}});
        assert_eq!(parse_token_balance(&v).unwrap(), 0);
    }

    #[test]
    fn parses_token_balance_get_token_account_balance() {
        // getTokenAccountBalance single-account shape.
        let v = json!({
            "result": {
                "context": {"slot": 1114},
                "value": {
                    "amount": "9864",
                    "decimals": 6,
                    "uiAmount": 0.009864,
                    "uiAmountString": "0.009864"
                }
            }
        });
        assert_eq!(parse_token_balance(&v).unwrap(), 9_864);
    }

    #[test]
    fn parses_send_sig() {
        // sendTransaction returns the signature string directly.
        let v = json!({
            "jsonrpc": "2.0",
            "result": "2id3YC2jK9G5Wo2phDx4gJVAew8DcY5NAojnVuao8rkxwPYPe8cSwE5GzhEgJA2y8fVjDEo6iR6ykBvDxrTQrtpb",
            "id": 1
        });
        assert_eq!(
            parse_send_sig(&v).unwrap(),
            "2id3YC2jK9G5Wo2phDx4gJVAew8DcY5NAojnVuao8rkxwPYPe8cSwE5GzhEgJA2y8fVjDEo6iR6ykBvDxrTQrtpb"
        );
    }

    #[test]
    fn send_sig_rpc_error_surfaces() {
        let v = json!({
            "jsonrpc": "2.0",
            "error": {"code": -32002, "message": "Transaction simulation failed"},
            "id": 1
        });
        let err = parse_send_sig(&v).unwrap_err();
        assert!(err.contains("-32002"));
        assert!(err.contains("simulation failed"));
    }

    #[test]
    fn signature_status_finalized_ok() {
        let v = json!({
            "result": {
                "context": {"slot": 82},
                "value": [
                    {"slot": 48, "confirmations": null, "err": null, "confirmationStatus": "finalized"}
                ]
            }
        });
        assert_eq!(parse_signature_finalized(&v).unwrap(), true);
    }

    #[test]
    fn signature_status_processed_not_yet_finalized() {
        let v = json!({
            "result": {
                "value": [
                    {"slot": 48, "confirmations": 5, "err": null, "confirmationStatus": "processed"}
                ]
            }
        });
        assert_eq!(parse_signature_finalized(&v).unwrap(), false);
    }

    #[test]
    fn signature_status_null_not_yet_seen() {
        let v = json!({"result": {"value": [null]}});
        assert_eq!(parse_signature_finalized(&v).unwrap(), false);
    }

    #[test]
    fn signature_status_onchain_error_is_err() {
        let v = json!({
            "result": {
                "value": [
                    {"slot": 48, "err": {"InstructionError": [0, "Custom(1)"]}, "confirmationStatus": "finalized"}
                ]
            }
        });
        assert!(parse_signature_finalized(&v).is_err());
    }

    #[test]
    fn builds_decodable_transfer_checked() {
        // GNN mint (mainnet) + treasury — both valid base58 pubkeys.
        const GNN_MINT: &str = "5EyGMW1wNxMj7YtVP54uBH6ktwpTNCvX9DDEnmcsHdev";
        const TREASURY: &str = "8fj621jPjBV4jHrrV1LDd9LHzSHJ6ras2YvwFgG6sx18";
        // A valid 32-byte base58 blockhash (the default/all-zero hash). Signing
        // succeeds against any well-formed blockhash; only *on-chain* validity
        // would fail with this dummy value, which we don't assert here.
        const BLOCKHASH: &str = "11111111111111111111111111111111";

        let wallet = Keypair::new();
        let b64 = build_signed_stake_tx(&wallet, GNN_MINT, TREASURY, 1_000_000, BLOCKHASH)
            .expect("build_signed_stake_tx should succeed");
        assert!(!b64.is_empty(), "base64 output must be non-empty");

        let bytes = BASE64_STANDARD
            .decode(b64.as_bytes())
            .expect("output must be valid base64");
        let tx: Transaction =
            bincode::deserialize(&bytes).expect("bytes must bincode-decode to a Transaction");
        assert_eq!(
            tx.message.instructions.len(),
            1,
            "transfer should compile to exactly one instruction"
        );
    }
}
