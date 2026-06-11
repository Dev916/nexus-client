//! Wire protocol shapes shared with the gateway (`/api/compute/node`).
//!
//! These mirror `server/src/compute/ws.rs`. There is no shared crate for
//! this slice, so the shapes are duplicated minimally here. The handshake
//! convention the client MUST follow:
//!
//!   1. gateway → `{"kind":"challenge","nonce":<base58>}`
//!   2. client  → `{"kind":"auth", node_pubkey, wallet_pubkey, model,
//!                  context_len, signature}` where `node_pubkey` is the
//!      base58 Ed25519 public key and `signature` is the base58 Ed25519
//!      signature over the **raw decoded nonce bytes** (not the base58
//!      text). Server verifies with `verify_strict`.
//!   3. gateway → `{"kind":"ready"}` or `{"kind":"rejected","reason":…}`
//!   4. gateway → `{"kind":"job", job_id, body}`; client streams
//!      `{"kind":"chunk", job_id, delta}` then `{"kind":"done", job_id,
//!      usage}`, or `{"kind":"job_error", job_id, error}`.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Gateway → client: the auth challenge. `nonce` is base58; decode it and
/// sign the raw bytes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Challenge {
    pub nonce: String,
}

/// Client → gateway: the auth frame. `node_pubkey` + `signature` are
/// base58; `signature` covers the raw decoded nonce bytes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthFrame {
    pub node_pubkey: String,
    pub wallet_pubkey: String,
    pub model: String,
    pub context_len: Option<i64>,
    pub signature: String,
}

impl AuthFrame {
    /// Tag this frame with `kind:"auth"` and serialize to JSON text.
    pub fn to_text(&self) -> Result<String, serde_json::Error> {
        let mut v = serde_json::to_value(self)?;
        if let serde_json::Value::Object(ref mut map) = v {
            map.insert("kind".to_string(), serde_json::Value::from("auth"));
        }
        serde_json::to_string(&v)
    }
}

/// Gateway → client: a job to run. `body` is an OpenAI chat-completions
/// request payload.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Job {
    pub job_id: String,
    pub body: serde_json::Value,
}

/// Gateway → client frames the client reacts to. Anything else (pings are
/// handled by the transport) is ignored.
#[derive(Debug, Clone)]
pub enum ServerFrame {
    Challenge { nonce: String },
    Ready,
    Rejected { reason: String },
    Job { job_id: String, body: serde_json::Value },
}

impl ServerFrame {
    /// Parse a gateway text frame. Returns `None` for unknown / malformed
    /// frames (the loop ignores those).
    pub fn parse(txt: &str) -> Option<ServerFrame> {
        let v: serde_json::Value = serde_json::from_str(txt).ok()?;
        match v.get("kind")?.as_str()? {
            "challenge" => Some(ServerFrame::Challenge {
                nonce: v.get("nonce")?.as_str()?.to_string(),
            }),
            "ready" => Some(ServerFrame::Ready),
            "rejected" => Some(ServerFrame::Rejected {
                reason: v
                    .get("reason")
                    .and_then(|r| r.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            }),
            "job" => Some(ServerFrame::Job {
                job_id: v.get("job_id")?.as_str()?.to_string(),
                body: v.get("body").cloned().unwrap_or(serde_json::Value::Null),
            }),
            _ => None,
        }
    }
}

/// Client → gateway: a streamed completion chunk for an in-flight job.
pub fn chunk_frame(job_id: &str, delta: &str) -> String {
    serde_json::json!({ "kind": "chunk", "job_id": job_id, "delta": delta }).to_string()
}

/// Client → gateway: the terminal `done` frame for a job. `usage` is
/// whatever the upstream reported (or `{}` if it gave none).
pub fn done_frame(job_id: &str, usage: serde_json::Value) -> String {
    serde_json::json!({ "kind": "done", "job_id": job_id, "usage": usage }).to_string()
}

/// Client → gateway: a job failed upstream (HTTP error / timeout / parse).
pub fn job_error_frame(job_id: &str, error: &str) -> String {
    serde_json::json!({ "kind": "job_error", "job_id": job_id, "error": error }).to_string()
}

/// Parse one OpenAI-style SSE `data:` payload into its delta content, if
/// any. Returns:
///   * `SseEvent::Done` for the `[DONE]` sentinel,
///   * `SseEvent::Delta(text)` for a content piece (may be empty string),
///   * `SseEvent::Other` for keep-alives / role-only deltas / unparseable.
pub enum SseEvent {
    Delta(String),
    Usage(serde_json::Value),
    Done,
    Other,
}

/// Strip a leading `data:` (with optional space) and classify the payload.
pub fn parse_sse_line(line: &str) -> Option<SseEvent> {
    let payload = line.strip_prefix("data:")?.trim_start();
    if payload == "[DONE]" {
        return Some(SseEvent::Done);
    }
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    // Some final frames carry usage with no choices/delta.
    if let Some(content) = v
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("delta"))
        .and_then(|d| d.get("content"))
        .and_then(|c| c.as_str())
    {
        return Some(SseEvent::Delta(content.to_string()));
    }
    if let Some(usage) = v.get("usage")
        && !usage.is_null()
    {
        return Some(SseEvent::Usage(usage.clone()));
    }
    Some(SseEvent::Other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_challenge_and_job() {
        match ServerFrame::parse(r#"{"kind":"challenge","nonce":"abc"}"#) {
            Some(ServerFrame::Challenge { nonce }) => assert_eq!(nonce, "abc"),
            other => panic!("expected challenge, got {other:?}"),
        }
        match ServerFrame::parse(r#"{"kind":"job","job_id":"j1","body":{"x":1}}"#) {
            Some(ServerFrame::Job { job_id, body }) => {
                assert_eq!(job_id, "j1");
                assert_eq!(body["x"], 1);
            }
            other => panic!("expected job, got {other:?}"),
        }
    }

    #[test]
    fn parses_ready_and_rejected() {
        assert!(matches!(
            ServerFrame::parse(r#"{"kind":"ready"}"#),
            Some(ServerFrame::Ready)
        ));
        match ServerFrame::parse(r#"{"kind":"rejected","reason":"not_staked"}"#) {
            Some(ServerFrame::Rejected { reason }) => assert_eq!(reason, "not_staked"),
            other => panic!("expected rejected, got {other:?}"),
        }
    }

    #[test]
    fn ignores_unknown_frames() {
        assert!(ServerFrame::parse(r#"{"kind":"weird"}"#).is_none());
        assert!(ServerFrame::parse("not json").is_none());
    }

    #[test]
    fn auth_frame_tags_kind() {
        let f = AuthFrame {
            node_pubkey: "np".into(),
            wallet_pubkey: "wp".into(),
            model: "hermes-3".into(),
            context_len: Some(8192),
            signature: "sig".into(),
        };
        let txt = f.to_text().unwrap();
        let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
        assert_eq!(v["kind"], "auth");
        assert_eq!(v["node_pubkey"], "np");
        assert_eq!(v["model"], "hermes-3");
        assert_eq!(v["context_len"], 8192);
    }

    #[test]
    fn sse_delta_done_and_usage() {
        match parse_sse_line(r#"data: {"choices":[{"delta":{"content":"hi"}}]}"#) {
            Some(SseEvent::Delta(s)) => assert_eq!(s, "hi"),
            _ => panic!("expected delta"),
        }
        assert!(matches!(parse_sse_line("data: [DONE]"), Some(SseEvent::Done)));
        match parse_sse_line(r#"data: {"choices":[],"usage":{"total_tokens":5}}"#) {
            Some(SseEvent::Usage(u)) => assert_eq!(u["total_tokens"], 5),
            _ => panic!("expected usage"),
        }
        // role-only delta → Other (no content)
        assert!(matches!(
            parse_sse_line(r#"data: {"choices":[{"delta":{"role":"assistant"}}]}"#),
            Some(SseEvent::Other)
        ));
        // non-data line → None
        assert!(parse_sse_line(": keep-alive").is_none());
    }
}
