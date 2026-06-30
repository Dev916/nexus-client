//! Wallet SIWS (Sign In With Solana) → JWT authentication.
//!
//! The Nexus client authenticates to the gateway's HTTP API with the Solana
//! **wallet** key (NOT the node key). The flow mirrors the server exactly:
//!
//!   1. `POST {origin}/api/auth/challenge` → returns the SIWS challenge fields
//!      (`domain`, `nonce`, `issuedAt`, `chainId`, `statement`).
//!   2. Build the canonical SIWS message string from those fields + the
//!      wallet pubkey, BYTE-IDENTICAL to the server's `build_siws_message`
//!      (`server/src/auth.rs`) — the server reconstructs the same string and
//!      compares it verbatim before verifying the signature.
//!   3. Sign the message bytes with the wallet's ed25519 key and base58-encode
//!      the 64-byte signature (the format the server's `bs58::decode` +
//!      `verify_siws_signature` expect).
//!   4. `POST {origin}/api/auth/verify` with `{message, signature, pubkey}`
//!      → returns `{token, pubkey, expiresAt}`; we return the `token`.
//!
//! Uses the existing rustls `reqwest` client — NO `solana-sdk`/`solana-client`
//! (which would drag in openssl and break the static release builds).

use serde::Deserialize;
use solana_keypair::Keypair;
use solana_signer::Signer;

/// Build a SIWS message string, BYTE-IDENTICAL to the server's
/// `build_siws_message` in `server/src/auth.rs`.
///
/// The server uses a `format!` with string-continuation backslashes, so the
/// leading whitespace on each continuation line is consumed — the produced
/// string is a plain `\n`-separated CAIP-122 message with no stray spaces.
///
/// Parameters mirror the server signature exactly: `pubkey` is the SIWS
/// `address` line.
pub fn build_siws_message(
    domain: &str,
    pubkey: &str,
    statement: &str,
    nonce: &str,
    issued_at: &str,
    chain_id: &str,
) -> String {
    format!(
        "{domain} wants you to sign in with your Solana account:\n\
         {pubkey}\n\
         \n\
         {statement}\n\
         \n\
         URI: https://{domain}\n\
         Version: 1\n\
         Chain ID: {chain_id}\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}"
    )
}

/// SIWS challenge returned by `POST /api/auth/challenge` (camelCase JSON).
#[derive(Debug, Deserialize)]
struct Challenge {
    domain: String,
    nonce: String,
    #[serde(rename = "issuedAt")]
    issued_at: String,
    #[serde(rename = "chainId")]
    chain_id: String,
    statement: String,
}

/// Verify response from `POST /api/auth/verify`.
#[derive(Debug, Deserialize)]
struct VerifyResponse {
    token: String,
}

/// Authenticate to the gateway with the Solana `wallet` key via SIWS and
/// return the issued JWT.
///
/// `gateway_http_origin` is the scheme+host (e.g. `https://nexus.ghostnn.ai`)
/// — endpoints are appended (`/api/auth/challenge`, `/api/auth/verify`).
///
/// The signature is the base58 of the 64-byte ed25519 signature over the
/// canonical SIWS message bytes, matching the server's
/// `bs58::decode(signature)` + `verify_siws_signature`.
pub async fn get_wallet_jwt(
    gateway_http_origin: &str,
    wallet: &Keypair,
) -> Result<String, String> {
    let origin = gateway_http_origin.trim_end_matches('/');
    let client = reqwest::Client::new();

    // 1. Fetch the SIWS challenge.
    let challenge_url = format!("{origin}/api/auth/challenge");
    let resp = client
        .post(&challenge_url)
        .send()
        .await
        .map_err(|e| format!("challenge request to {challenge_url} failed: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("challenge: reading response body failed: {e}"))?;
    if !status.is_success() {
        return Err(format!("challenge: server returned {status}: {text}"));
    }
    let challenge: Challenge = serde_json::from_str(&text)
        .map_err(|e| format!("challenge: invalid JSON: {e} (body: {text})"))?;

    // 2. Build the canonical SIWS message (BYTE-IDENTICAL to the server).
    let pubkey = wallet.pubkey().to_string();
    let message = build_siws_message(
        &challenge.domain,
        &pubkey,
        &challenge.statement,
        &challenge.nonce,
        &challenge.issued_at,
        &challenge.chain_id,
    );

    // 3. Sign the message bytes with the wallet ed25519 key; base58-encode the
    //    64-byte signature (the format the server's verify_siws_signature wants).
    let signature = wallet.sign_message(message.as_bytes());
    let signature_b58 = bs58::encode(signature.as_ref()).into_string();

    // 4. POST the verify request and return the JWT.
    let verify_url = format!("{origin}/api/auth/verify");
    let body = serde_json::json!({
        "message": message,
        "signature": signature_b58,
        "pubkey": pubkey,
    });
    let resp = client
        .post(&verify_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("verify request to {verify_url} failed: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("verify: reading response body failed: {e}"))?;
    if !status.is_success() {
        return Err(format!("verify: server returned {status}: {text}"));
    }
    let verified: VerifyResponse = serde_json::from_str(&text)
        .map_err(|e| format!("verify: invalid JSON: {e} (body: {text})"))?;

    Ok(verified.token)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client's `build_siws_message` MUST be byte-identical to the server's
    /// (`server/src/auth.rs::build_siws_message`). This reproduces the server's
    /// exact `format!` output for the same fixed inputs as an explicit literal
    /// (each field on its own line, blank lines after the address and after the
    /// statement, no leading whitespace on continuation lines).
    #[test]
    fn siws_message_matches_server() {
        let msg = build_siws_message(
            "localhost",
            "GovL7Y7t9R6yYrN9dV2Kc3PxY3z3hG3rJ2sD8qF1aBcD",
            "Sign in to Nexus Energy City",
            "0123456789abcdef0123456789abcdef",
            "2026-06-27T06:34:24+00:00",
            "mainnet",
        );

        let expected = "localhost wants you to sign in with your Solana account:\n\
GovL7Y7t9R6yYrN9dV2Kc3PxY3z3hG3rJ2sD8qF1aBcD\n\
\n\
Sign in to Nexus Energy City\n\
\n\
URI: https://localhost\n\
Version: 1\n\
Chain ID: mainnet\n\
Nonce: 0123456789abcdef0123456789abcdef\n\
Issued At: 2026-06-27T06:34:24+00:00";

        assert_eq!(msg, expected);
    }

    /// A standalone assertion of the exact byte structure — independent of the
    /// `build_siws_message` continuation formatting — so a regression in the
    /// newline layout is caught directly.
    #[test]
    fn siws_message_has_exact_newline_layout() {
        let msg = build_siws_message("d", "ADDR", "STMT", "NON", "IAT", "CID");
        assert_eq!(
            msg,
            "d wants you to sign in with your Solana account:\nADDR\n\nSTMT\n\nURI: https://d\nVersion: 1\nChain ID: CID\nNonce: NON\nIssued At: IAT"
        );
    }
}
