//! `builder` — drive a live Community-tier Builder run through the Nexus MCP.
//!
//! Lifted out of the server (gnn-z8hl.3) so the slim client can consume it: the
//! MCP transport ([`McpClient`]), the small [`Mcp`] trait it satisfies, the SIWS
//! challenge signer ([`sign_siws`]), and the [`drive_builder`] state machine that
//! authenticates the worker wallet, opens a Builder session, pins the community
//! tier, and walks brainstorm→plan→execute→done to a promoted `session_id`.
//!
//! This module is deliberately server-free: `drive_builder` returns the live
//! `session_id` (a `String`) — it does NOT settle on-chain. The caller composes
//! it with the round-trip tail (`run_roundtrip` / `worker_roundtrip`) separately.
//!
//! The MCP surface is abstracted behind the small [`Mcp`] trait so the state
//! machine can be exercised against a scripted fake with zero live infra;
//! [`McpClient`] is the production implementation.

use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::manifest::{files_from_json, manifest_hash};

/// A live handle to a spawned `nexus-city-mcp` child process.
///
/// The AgenC orchestrator acts as an external MCP client: it spawns the
/// `nexus-city-mcp` binary as a child process, points it at the Nexus HTTP API
/// via `NEXUS_API_BASE`, and speaks JSON-RPC 2.0 over the child's stdin/stdout
/// (one JSON object per line). The MCP wraps every `tools/call` result as
/// `{"content":[{"type":"text","text":"<json-string>"}]}`; `call_tool` unwraps
/// that inner JSON so callers get the tool's real payload.
pub struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl McpClient {
    /// Spawn the mcp binary at `mcp_bin` with `NEXUS_API_BASE=api_base`, then
    /// complete the JSON-RPC `initialize` handshake before returning.
    pub async fn spawn(mcp_bin: &str, api_base: &str) -> Result<Self> {
        let mut child = Command::new(mcp_bin)
            .env("NEXUS_API_BASE", api_base)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn mcp binary `{mcp_bin}`"))?;

        let stdin = child
            .stdin
            .take()
            .context("mcp child stdin was not piped")?;
        let stdout = child
            .stdout
            .take()
            .context("mcp child stdout was not piped")?;

        let mut client = McpClient {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 0,
        };

        client
            .request("initialize", json!({}))
            .await
            .context("mcp `initialize` handshake failed")?;

        Ok(client)
    }

    /// Call an MCP tool and return its UNWRAPPED inner JSON payload. A transport
    /// failure, a JSON-RPC `error`, a malformed envelope, or a tool payload that
    /// is itself an `{"error": …}` object all surface as `Err` — never a panic.
    pub async fn call_tool(&mut self, name: &str, args: Value) -> Result<Value> {
        let resp = self
            .request("tools/call", json!({"name": name, "arguments": args}))
            .await?;

        let text = resp
            .get("result")
            .and_then(|r| r.get("content"))
            .and_then(|c| c.get(0))
            .and_then(|first| first.get("text"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| {
                anyhow!("tool `{name}` response missing result.content[0].text: {resp}")
            })?;

        let inner: Value = serde_json::from_str(text)
            .with_context(|| format!("parse inner tool payload for `{name}`: {text}"))?;

        // The MCP encodes every failure path (unknown tool, backend error, not
        // authenticated, …) as a top-level `{"error": …}` — bubble it as Err.
        if let Some(err) = inner.get("error") {
            return Err(anyhow!("tool `{name}` error: {err}"));
        }

        Ok(inner)
    }

    /// The child's OS process id, or `None` once it has been reaped.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Write one JSON-RPC request line, read exactly one response line, parse it,
    /// and bubble any JSON-RPC-level `error` as `Err`.
    async fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let mut line = serde_json::to_string(&req).context("serialize JSON-RPC request")?;
        line.push('\n');

        self.stdin
            .write_all(line.as_bytes())
            .await
            .with_context(|| format!("write `{method}` request to mcp stdin"))?;
        self.stdin
            .flush()
            .await
            .with_context(|| format!("flush `{method}` request to mcp stdin"))?;

        let mut resp_line = String::new();
        let n = self
            .stdout
            .read_line(&mut resp_line)
            .await
            .with_context(|| format!("read `{method}` response from mcp stdout"))?;
        if n == 0 {
            return Err(anyhow!(
                "mcp closed stdout before responding to `{method}` (child exited?)"
            ));
        }

        let resp: Value = serde_json::from_str(resp_line.trim())
            .with_context(|| format!("parse mcp response line: {}", resp_line.trim()))?;

        if let Some(err) = resp.get("error") {
            if !err.is_null() {
                return Err(anyhow!("mcp `{method}` returned JSON-RPC error: {err}"));
            }
        }

        Ok(resp)
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // Best-effort SIGKILL so the child never outlives its client.
        let _ = self.child.start_kill();
    }
}

/// The MCP tool surface the live loop drives. One method — call a tool by name
/// with a JSON argument object, get its unwrapped JSON payload back (or `Err`).
///
/// Implemented by [`McpClient`] (spawns the real `nexus-city-mcp` child) and by
/// the test fake. Uses a native `async fn` in trait (edition 2024 / rustc ≥1.75)
/// — the loop is generic over `M: Mcp`, never `dyn`, so no boxing is needed.
#[allow(async_fn_in_trait)]
pub trait Mcp {
    async fn call(&mut self, name: &str, args: Value) -> Result<Value>;
}

impl Mcp for McpClient {
    async fn call(&mut self, name: &str, args: Value) -> Result<Value> {
        self.call_tool(name, args).await
    }
}

/// Sign a SIWS challenge message with the worker's Ed25519 key and return the
/// **base58-encoded** 64-byte signature — exactly what `nexus_auth_verify`
/// expects (the server rebuilds the message and calls `verify_siws_signature`,
/// which base58-decodes this back into a `[u8; 64]`).
pub fn sign_siws(message: &str, key: &SigningKey) -> String {
    let sig = key.sign(message.as_bytes());
    bs58::encode(sig.to_bytes()).into_string()
}

/// Drive a Builder session through the MCP from auth to promote, returning the
/// live `session_id` **and** the real `artifact_sha256` of the promoted app once
/// the session is `done` and promoted.
///
/// Sequence: `nexus_auth_challenge` → sign → `nexus_auth_verify` →
/// `nexus_builder_create` → `nexus_builder_tier(community)` → poll
/// (`nexus_builder_status` → `nexus_builder_advance(<action>)`) until `done` →
/// `nexus_builder_promote`.
///
/// Phase/status → action mapping (server strings from `builder_agent::state`):
/// `(brainstorm, waiting_approval)`→`approve_spec`; `(plan, waiting_approval)`→
/// `approve_plan`; `(execute, waiting_user)`→`next_task`. `status=running` (or
/// any other non-terminal state) sleeps ~2s and re-polls; `status=done` breaks;
/// `status=error` bails with the session's `error_message`.
///
/// The terminal `done` `nexus_builder_status` snapshot carries the promoted
/// app's `files` (same `{name: contents}` shape the server persists in
/// `builder_sessions.files`). We hash those with the canonical
/// [`manifest_hash`](crate::manifest::manifest_hash) — the SAME hash the server
/// commits — so the worker's on-chain proof binds the REAL built app, not a
/// `sha256(session_id)` placeholder (gnn-ved1). A `done` snapshot with no files
/// (edge) falls back to the empty-manifest hash and logs to stderr.
pub async fn drive_builder<M: Mcp>(
    mcp: &mut M,
    worker_key: &SigningKey,
    worker_pubkey_b58: &str,
    parcel_uid: &str,
    brief: &str,
    budget_secs: u64,
) -> Result<(String, String)> {
    // 1. Auth: challenge → sign the returned message → verify.
    let challenge = mcp
        .call("nexus_auth_challenge", json!({ "pubkey": worker_pubkey_b58 }))
        .await
        .context("nexus_auth_challenge")?;
    let message = challenge
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("auth challenge missing `message`: {challenge}"))?;
    let signature = sign_siws(message, worker_key);
    let verify = mcp
        .call(
            "nexus_auth_verify",
            json!({ "pubkey": worker_pubkey_b58, "signature": signature, "message": message }),
        )
        .await
        .context("nexus_auth_verify")?;
    if verify.get("authenticated").and_then(|v| v.as_bool()) == Some(false) {
        bail!("SIWS auth rejected: {verify}");
    }

    // 2. Open the Builder session. The tier is pinned to `community` LATER, at
    //    the execute boundary (step 3) — NOT here. The server's `run_turn` routes
    //    EVERY turn by `model_tier` with no phase gate (worker.rs `route_decision`),
    //    so pinning community up front would send the brainstorm/plan tool turns
    //    (`propose_spec`/`propose_plan`) to the open-weight node, which returns
    //    schema-shaped junk and stalls the session. Per the design (spec §2:
    //    "Community tier routes ONLY the execute/emit_files turn … brainstorm/plan
    //    stay on Anthropic"), brainstorm + plan run on the default premium tier and
    //    the switch happens once, on first entry to the execute phase.
    let created = mcp
        .call(
            "nexus_builder_create",
            json!({ "parcel_uid": parcel_uid, "brief": brief }),
        )
        .await
        .context("nexus_builder_create")?;
    let session_id = created
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("builder_create missing `session_id`: {created}"))?
        .to_string();

    // 3. Poll/advance loop under a wall-clock budget. The terminal `done`
    //    snapshot carries the promoted app `files`, which we capture out of the
    //    loop to hash below.
    let start = Instant::now();
    let mut tier_pinned = false;
    let done_files: Value = loop {
        if start.elapsed().as_secs() >= budget_secs {
            bail!("live loop exceeded {budget_secs}s budget for session {session_id}");
        }

        let snap = mcp
            .call(
                "nexus_builder_status",
                json!({ "session_id": session_id.as_str() }),
            )
            .await
            .context("nexus_builder_status")?;
        let phase = snap.get("phase").and_then(|v| v.as_str()).unwrap_or("");
        let status = snap.get("status").and_then(|v| v.as_str()).unwrap_or("");

        match status {
            // Capture the promoted `files` payload from the terminal snapshot so
            // the settle proof can commit its real manifest hash.
            "done" => break snap.get("files").cloned().unwrap_or(Value::Null),
            "error" => {
                let msg = snap
                    .get("error_message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no error_message)");
                bail!("builder session {session_id} entered error state: {msg}");
            }
            "running" => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            _ => {}
        }

        // Pin the community tier ONCE, at plan approval — AFTER the brainstorm +
        // plan tool turns have completed on premium, but BEFORE `approve_plan`
        // transitions the session into execute. `approve_plan` auto-runs the first
        // execute task on whatever `model_tier` is current, so the switch must land
        // here (not at the execute phase, which the server reaches already running
        // task 0). This keeps brainstorm/plan on premium and routes every
        // emit_files execute turn to the compute node (spec §2).
        if phase == "plan" && status == "waiting_approval" && !tier_pinned {
            mcp.call(
                "nexus_builder_tier",
                json!({ "session_id": session_id.as_str(), "tier": "community" }),
            )
            .await
            .context("nexus_builder_tier")?;
            tier_pinned = true;
        }

        let action = match (phase, status) {
            ("brainstorm", "waiting_approval") => "approve_spec",
            ("plan", "waiting_approval") => "approve_plan",
            ("execute", "waiting_user") => "next_task",
            // Unknown-but-non-terminal snapshot: wait and re-poll rather than
            // spin or bail — the session may still be settling between turns.
            _ => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        mcp.call(
            "nexus_builder_advance",
            json!({ "session_id": session_id.as_str(), "action": action }),
        )
        .await
        .with_context(|| format!("nexus_builder_advance({action})"))?;
    };

    // 4. Promote the completed session's draft as the parcel's live app.
    mcp.call(
        "nexus_builder_promote",
        json!({ "session_id": session_id.as_str() }),
    )
    .await
    .context("nexus_builder_promote")?;

    // 5. Commit the REAL artifact hash of the promoted app (gnn-ved1). Decode the
    //    terminal snapshot's `files` the same way the server does and hash them
    //    with the canonical `manifest_hash`, so the worker's on-chain proof binds
    //    the actual built app — not `sha256(session_id)`. No files (edge) → the
    //    empty-manifest hash, with a stderr note.
    let file_bundle = files_from_json(&done_files);
    if file_bundle.is_empty() {
        eprintln!(
            "drive_builder: session {session_id} promoted with no files in the terminal \
             status snapshot; committing the empty-manifest artifact hash"
        );
    }
    let artifact_sha256 = manifest_hash(&file_bundle);

    Ok((session_id, artifact_sha256))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signature;
    use std::collections::VecDeque;

    // ── sign_siws round-trip ────────────────────────────────────────────
    #[test]
    fn sign_siws_round_trips_under_worker_key() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let msg = "localhost wants you to sign in with your Solana account:\n\
                   Pk\n\nSign in to Nexus Energy City\n\nNonce: deadbeef";

        let sig_b58 = sign_siws(msg, &key);

        // Decodes to exactly 64 bytes …
        let sig_bytes = bs58::decode(&sig_b58)
            .into_vec()
            .expect("sign_siws must emit valid base58");
        assert_eq!(sig_bytes.len(), 64, "ed25519 signature is 64 bytes");

        // … and verifies under the key's VerifyingKey (server uses verify_strict).
        let arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let sig = Signature::from_bytes(&arr);
        key.verifying_key()
            .verify_strict(msg.as_bytes(), &sig)
            .expect("signature must verify under the worker pubkey");
    }

    // ── scripted fake MCP ────────────────────────────────────────────────
    /// Records every `(name, args)` call in order and replays a scripted
    /// `nexus_builder_status` sequence; all other tools return canned success.
    struct FakeMcp {
        calls: Vec<(String, Value)>,
        status_seq: VecDeque<Value>,
    }

    impl FakeMcp {
        fn new(status_seq: Vec<Value>) -> Self {
            Self {
                calls: Vec::new(),
                status_seq: status_seq.into(),
            }
        }
        fn names(&self) -> Vec<&str> {
            self.calls.iter().map(|(n, _)| n.as_str()).collect()
        }
    }

    impl Mcp for FakeMcp {
        async fn call(&mut self, name: &str, args: Value) -> Result<Value> {
            self.calls.push((name.to_string(), args));
            Ok(match name {
                "nexus_auth_challenge" => json!({"message": "SIWS-CHALLENGE", "pubkey": "PK"}),
                "nexus_auth_verify" => json!({"authenticated": true, "pubkey": "PK"}),
                "nexus_builder_create" => {
                    json!({"session_id": "SESSION-123", "created": {}, "message": {}})
                }
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

    // ── drive_builder walks the full state machine in order ──────────────
    #[tokio::test]
    async fn drive_builder_walks_auth_create_tier_advance_promote() {
        use crate::manifest::{files_from_json, manifest_hash};
        use sha2::{Digest, Sha256};

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pk = bs58::encode(key.verifying_key().to_bytes()).into_string();

        // The promoted app the `done` status snapshot carries — the SAME
        // `{name: contents}` shape the server persists in `builder_sessions.files`.
        let known_files = json!({
            "index.html": "<h1>Scoreboard</h1>",
            "app.js": "console.log('go');",
        });

        // Scripted status sequence: brainstorm→plan→execute→done. The terminal
        // `done` snapshot carries the promoted `files`.
        let mut fake = FakeMcp::new(vec![
            json!({"phase": "brainstorm", "status": "waiting_approval"}),
            json!({"phase": "plan", "status": "waiting_approval"}),
            json!({"phase": "execute", "status": "waiting_user"}),
            json!({"phase": "done", "status": "done", "files": known_files.clone()}),
        ]);

        let (session_id, artifact_sha256) =
            drive_builder(&mut fake, &key, &pk, "PARCEL-1", "build me a game", 30)
                .await
                .expect("drive_builder should complete against the scripted fake");

        // Returns the live session id.
        assert_eq!(session_id, "SESSION-123");

        // …and the REAL promoted-app manifest hash (gnn-ved1), computed exactly
        // the way the server does — NOT the `sha256(session_id)` placeholder.
        let expected = manifest_hash(&files_from_json(&known_files));
        assert_eq!(
            artifact_sha256, expected,
            "drive_builder must commit the real manifest hash of the promoted files"
        );
        let placeholder = hex::encode(Sha256::digest(session_id.as_bytes()));
        assert_ne!(
            artifact_sha256, placeholder,
            "artifact hash must NOT be the old sha256(session_id) placeholder"
        );

        // Exact ordered tool-call sequence. `nexus_builder_tier` fires at plan
        // approval — after the plan status poll, BEFORE the `approve_plan` advance —
        // so brainstorm/plan run premium and the (auto-started) execute turn is
        // routed to the community node.
        assert_eq!(
            fake.names(),
            vec![
                "nexus_auth_challenge",
                "nexus_auth_verify",
                "nexus_builder_create",
                "nexus_builder_status",
                "nexus_builder_advance",
                "nexus_builder_status",
                "nexus_builder_tier",
                "nexus_builder_advance",
                "nexus_builder_status",
                "nexus_builder_advance",
                "nexus_builder_status",
                "nexus_builder_promote",
            ]
        );

        // The three advance actions, in order.
        let actions: Vec<String> = fake
            .calls
            .iter()
            .filter(|(n, _)| n == "nexus_builder_advance")
            .map(|(_, a)| {
                a.get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        assert_eq!(actions, vec!["approve_spec", "approve_plan", "next_task"]);

        // The tier was pinned to community.
        let (_, tier_args) = fake
            .calls
            .iter()
            .find(|(n, _)| n == "nexus_builder_tier")
            .expect("tier call recorded");
        assert_eq!(
            tier_args.get("tier").and_then(|v| v.as_str()),
            Some("community")
        );

        // Auth signed the challenge the server returned (signature present + b58).
        let (_, verify_args) = fake
            .calls
            .iter()
            .find(|(n, _)| n == "nexus_auth_verify")
            .expect("verify call recorded");
        let sig = verify_args
            .get("signature")
            .and_then(|v| v.as_str())
            .expect("verify carries a signature");
        assert_eq!(
            bs58::decode(sig).into_vec().expect("b58 signature").len(),
            64
        );
    }

    // ── error status bails cleanly with the error_message ────────────────
    #[tokio::test]
    async fn drive_builder_bails_on_error_status() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let pk = bs58::encode(key.verifying_key().to_bytes()).into_string();

        let mut fake = FakeMcp::new(vec![
            json!({"phase": "execute", "status": "error", "error_message": "node timed out"}),
        ]);

        let err = drive_builder(&mut fake, &key, &pk, "PARCEL-1", "brief", 30)
            .await
            .expect_err("error status must surface as Err");
        assert!(
            err.to_string().contains("node timed out"),
            "error should carry the session error_message, got: {err}"
        );
    }
}
