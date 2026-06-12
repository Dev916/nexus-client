//! Security limits + input sanitization for the hostile-gateway threat
//! model. The client runs on a host's machine and the gateway on the
//! other end of the socket is untrusted (it may be malicious or MITM'd).
//! Everything here is pure + exhaustively unit-tested so the policy is
//! auditable in one place.
//!
//! Findings addressed (see bd epic gnn-cg6):
//!   * NX-1/NX-5 — `validate_nonce`: bound the challenge string, decode,
//!     and require exactly 32 bytes before the node key ever signs it.
//!   * NX-2     — `ws_config`: cap inbound WebSocket frame/message size.
//!   * NX-3     — `sanitize_job_body`: the gateway-supplied body is
//!     untrusted input to the LOCAL model. Pin the served model, clamp
//!     `max_tokens`, and drop unexpected top-level keys.
//!   * NX-4     — byte/line/time ceilings for a single job's streamed
//!     response so one job can't pin the host forever.

use std::time::Duration;

use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

// ── NX-2: WebSocket message/frame size caps ──────────────────────────
/// Largest single WS message we'll buffer from the gateway. A legitimate
/// `job` frame is a small chat-completions request; 1 MiB is generous.
pub const MAX_WS_MESSAGE_BYTES: usize = 1024 * 1024;
/// Largest single WS frame. Messages can be multi-frame but each frame is
/// bounded so a partial read can't balloon memory.
pub const MAX_WS_FRAME_BYTES: usize = 256 * 1024;

// ── NX-1/NX-5: challenge nonce bounds ────────────────────────────────
/// Max length of the base58 nonce STRING before we decode it. 32 raw
/// bytes encode to ≤ 44 base58 chars; 64 is slack for any framing.
pub const MAX_NONCE_CHARS: usize = 64;
/// The exact decoded nonce length the protocol requires. Signing anything
/// other than a 32-byte challenge is refused (blind-signing guard).
pub const NONCE_BYTES: usize = 32;

/// Domain-separation tag prepended to the nonce before signing (NX-1).
/// The node key signs `AUTH_DOMAIN_TAG ++ nonce`, never the bare nonce,
/// so a captured signature is meaningless to any other Ed25519 verifier
/// (a different protocol, a Solana tx digest, etc.). The server MUST
/// prepend the identical tag when verifying. Bump the `:vN` suffix to
/// rotate the auth scheme. MUST stay byte-identical to the server's copy
/// in `server/src/compute/ws.rs`.
pub const AUTH_DOMAIN_TAG: &[u8] = b"nexus-compute-node-auth:v1\n";

/// Build the exact bytes the node key signs for the auth handshake:
/// the domain tag followed by the validated 32-byte nonce (NX-1).
pub fn auth_message(nonce: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(AUTH_DOMAIN_TAG.len() + nonce.len());
    m.extend_from_slice(AUTH_DOMAIN_TAG);
    m.extend_from_slice(nonce);
    m
}

// ── NX-4: per-job streaming ceilings ─────────────────────────────────
/// Wall-clock ceiling for a single job's full upstream stream.
pub const JOB_TIMEOUT: Duration = Duration::from_secs(300);
/// Max total bytes we'll stream back for one job before aborting it.
pub const MAX_JOB_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
/// Max length the line-accumulation buffer may reach with no newline
/// before we treat the upstream as hostile/broken and abort the job.
pub const MAX_SSE_BUFFER_BYTES: usize = 1024 * 1024;

// ── NX-3: job-body request param ceiling ─────────────────────────────
/// Hard ceiling on `max_tokens` the gateway may request, regardless of
/// what the body asks for. Keeps a single job from pinning the model.
pub const MAX_OUTPUT_TOKENS: u64 = 8192;

/// Top-level chat-completions keys the gateway is permitted to set. Any
/// other key is dropped before the body reaches the local model. `model`
/// and `stream` are set by us, not the gateway, so they're not listed.
const ALLOWED_BODY_KEYS: &[&str] = &[
    "messages",
    "max_tokens",
    "temperature",
    "top_p",
    "top_k",
    "stop",
    "presence_penalty",
    "frequency_penalty",
    "seed",
    "response_format",
    "tools",
    "tool_choice",
];

/// Why a challenge nonce was rejected (NX-1/NX-5).
#[derive(Debug, PartialEq, Eq)]
pub enum NonceError {
    /// The base58 string is implausibly long — refuse before decoding.
    TooLong(usize),
    /// The string isn't valid base58.
    Undecodable,
    /// Decoded to the wrong number of bytes (must be exactly 32).
    WrongLength(usize),
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NonceError::TooLong(n) => write!(f, "nonce string too long ({n} > {MAX_NONCE_CHARS})"),
            NonceError::Undecodable => write!(f, "nonce is not valid base58"),
            NonceError::WrongLength(n) => {
                write!(f, "nonce must decode to {NONCE_BYTES} bytes, got {n}")
            }
        }
    }
}

/// Validate a base58 challenge nonce and return its raw bytes, ready to
/// sign. Refuses anything that isn't exactly [`NONCE_BYTES`] so the node
/// key never signs an attacker-chosen blob of arbitrary length/content.
pub fn validate_nonce(b58: &str) -> Result<Vec<u8>, NonceError> {
    if b58.len() > MAX_NONCE_CHARS {
        return Err(NonceError::TooLong(b58.len()));
    }
    let bytes = bs58::decode(b58)
        .into_vec()
        .map_err(|_| NonceError::Undecodable)?;
    if bytes.len() != NONCE_BYTES {
        return Err(NonceError::WrongLength(bytes.len()));
    }
    Ok(bytes)
}

/// Build the tungstenite config that caps inbound message + frame size
/// (NX-2). tokio-tungstenite 0.20's `WebSocketConfig` is non-exhaustive,
/// so we start from default and only override the size fields.
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(MAX_WS_MESSAGE_BYTES),
        max_frame_size: Some(MAX_WS_FRAME_BYTES),
        ..Default::default()
    }
}

/// Sanitize the gateway-supplied job body before it reaches the LOCAL
/// model (NX-3). The body is untrusted: we
///   * force `model` to the host's configured model (the gateway cannot
///     make us run a different/heavier model than we advertised),
///   * clamp `max_tokens` to [`MAX_OUTPUT_TOKENS`] (and inject the cap if
///     absent, so an unbounded generation can't pin the GPU),
///   * drop every top-level key not in [`ALLOWED_BODY_KEYS`] (no injected
///     control fields), and
///   * force `stream: true` (we always parse SSE).
///
/// A non-object body is replaced with a minimal valid object so the
/// upstream call is well-formed regardless of what the gateway sent.
pub fn sanitize_job_body(raw: serde_json::Value, model: &str) -> serde_json::Value {
    use serde_json::Value;
    let mut out = serde_json::Map::new();
    if let Value::Object(map) = raw {
        for (k, v) in map {
            if ALLOWED_BODY_KEYS.contains(&k.as_str()) {
                out.insert(k, v);
            }
        }
    }
    // Clamp / inject max_tokens.
    let clamped = out
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .map(|n| n.min(MAX_OUTPUT_TOKENS))
        .unwrap_or(MAX_OUTPUT_TOKENS);
    out.insert("max_tokens".into(), Value::from(clamped));
    // We own these two — never the gateway.
    out.insert("model".into(), Value::from(model));
    out.insert("stream".into(), Value::Bool(true));
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce32_b58() -> String {
        bs58::encode([7u8; NONCE_BYTES]).into_string()
    }

    #[test]
    fn validate_nonce_accepts_exactly_32_bytes() {
        let b58 = nonce32_b58();
        let bytes = validate_nonce(&b58).expect("32-byte nonce accepted");
        assert_eq!(bytes.len(), NONCE_BYTES);
        assert_eq!(bytes, vec![7u8; NONCE_BYTES]);
    }

    #[test]
    fn validate_nonce_rejects_wrong_length() {
        let short = bs58::encode([1u8; 16]).into_string();
        assert_eq!(validate_nonce(&short), Err(NonceError::WrongLength(16)));
        let long = bs58::encode([1u8; 33]).into_string();
        assert_eq!(validate_nonce(&long), Err(NonceError::WrongLength(33)));
    }

    #[test]
    fn validate_nonce_rejects_overlong_string_before_decode() {
        // A megabyte of base58 must be refused on length alone (NX-5),
        // never handed to the decoder.
        let huge = "1".repeat(MAX_NONCE_CHARS + 1);
        assert_eq!(validate_nonce(&huge), Err(NonceError::TooLong(huge.len())));
    }

    #[test]
    fn validate_nonce_rejects_non_base58() {
        // '0', 'O', 'I', 'l' are not in the base58 alphabet.
        assert_eq!(validate_nonce("0OIl"), Err(NonceError::Undecodable));
    }

    #[test]
    fn auth_message_is_tag_then_nonce() {
        // NX-1: the signed message is the domain tag followed by the
        // nonce — never the bare nonce. This is what makes a captured
        // signature useless to any other Ed25519 verifier.
        let nonce = [9u8; NONCE_BYTES];
        let m = auth_message(&nonce);
        assert!(m.starts_with(AUTH_DOMAIN_TAG), "message must start with the tag");
        assert_eq!(&m[AUTH_DOMAIN_TAG.len()..], &nonce, "tag is followed by the nonce");
        assert_ne!(m.as_slice(), &nonce, "must not equal the bare nonce");
    }

    #[test]
    fn ws_config_caps_sizes() {
        let c = ws_config();
        assert_eq!(c.max_message_size, Some(MAX_WS_MESSAGE_BYTES));
        assert_eq!(c.max_frame_size, Some(MAX_WS_FRAME_BYTES));
    }

    #[test]
    fn sanitize_pins_model_and_forces_stream() {
        let raw = serde_json::json!({
            "model": "some-huge-model-the-gateway-picked",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": false,
        });
        let out = sanitize_job_body(raw, "hermes-3");
        assert_eq!(out["model"], "hermes-3", "model pinned to config");
        assert_eq!(out["stream"], true, "stream forced on");
    }

    #[test]
    fn sanitize_clamps_max_tokens() {
        let raw = serde_json::json!({ "max_tokens": 100_000_000u64, "messages": [] });
        let out = sanitize_job_body(raw, "hermes-3");
        assert_eq!(out["max_tokens"], MAX_OUTPUT_TOKENS);
    }

    #[test]
    fn sanitize_injects_max_tokens_when_absent() {
        let raw = serde_json::json!({ "messages": [] });
        let out = sanitize_job_body(raw, "hermes-3");
        assert_eq!(out["max_tokens"], MAX_OUTPUT_TOKENS);
    }

    #[test]
    fn sanitize_preserves_small_max_tokens() {
        let raw = serde_json::json!({ "max_tokens": 256, "messages": [] });
        let out = sanitize_job_body(raw, "hermes-3");
        assert_eq!(out["max_tokens"], 256);
    }

    #[test]
    fn sanitize_drops_unknown_keys() {
        let raw = serde_json::json!({
            "messages": [],
            "evil_field": "rm -rf /",
            "logprobs": true,
            "n": 50,
        });
        let out = sanitize_job_body(raw, "hermes-3");
        assert!(out.get("evil_field").is_none(), "unknown key dropped");
        assert!(out.get("logprobs").is_none(), "unlisted key dropped");
        assert!(out.get("n").is_none(), "fan-out key n dropped");
        assert!(out.get("messages").is_some(), "allowed key kept");
    }

    #[test]
    fn sanitize_keeps_allowed_sampling_params() {
        let raw = serde_json::json!({
            "messages": [{"role":"user","content":"x"}],
            "temperature": 0.7,
            "top_p": 0.9,
            "stop": ["\n\n"],
        });
        let out = sanitize_job_body(raw, "hermes-3");
        assert_eq!(out["temperature"], 0.7);
        assert_eq!(out["top_p"], 0.9);
        assert_eq!(out["stop"][0], "\n\n");
    }

    #[test]
    fn sanitize_non_object_body_becomes_valid_object() {
        let out = sanitize_job_body(serde_json::json!("not an object"), "hermes-3");
        assert!(out.is_object());
        assert_eq!(out["model"], "hermes-3");
        assert_eq!(out["max_tokens"], MAX_OUTPUT_TOKENS);
    }
}
