//! `start` — the pull loop. Dials the gateway, authenticates with the
//! node key, then for each `job` frame POSTs the body to the local
//! upstream (`/chat/completions`, stream forced on), parses the OpenAI SSE
//! response, and streams `chunk` frames back followed by a terminal `done`
//! (or a `job_error` on upstream failure). Reconnects with exponential
//! backoff (1s → 30s cap) when the socket drops.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::config::Config;
use crate::keys::NodeKey;
use crate::protocol::{
    self, AuthFrame, ServerFrame, SseEvent, chunk_frame, done_frame, job_error_frame,
};

/// Backoff floor (first reconnect delay).
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Backoff ceiling.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Next backoff delay given the current one: double, capped at
/// [`BACKOFF_MAX`]. A `None` (no previous attempt) yields [`BACKOFF_MIN`].
/// Pure + exposed so the reconnect schedule is unit-testable.
pub fn next_backoff(prev: Option<Duration>) -> Duration {
    match prev {
        None => BACKOFF_MIN,
        Some(d) => std::cmp::min(d.saturating_mul(2), BACKOFF_MAX),
    }
}

/// Why a single connection attempt ended. Drives the reconnect decision.
pub enum SessionOutcome {
    /// Socket dropped / dialed failed / a job mid-flight died — retry with
    /// backoff.
    Disconnected,
    /// The gateway sent `rejected` — a terminal auth/eligibility failure.
    /// No retry; the caller exits non-zero.
    Rejected(String),
    /// Clean shutdown requested (ctrl-c).
    Shutdown,
}

/// A connected, authenticated gateway socket. Generic over the stream so
/// tests can drive an in-process (plain TCP) socket and production uses a
/// TLS-capable one.
type GatewaySocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Run the pull loop until ctrl-c. Reconnects on socket drop with
/// exponential backoff; exits early (returning `Rejected`) if the gateway
/// rejects auth.
pub async fn run(config: Config, node_key: NodeKey, wallet_pubkey: String) -> SessionOutcome {
    let client = reqwest::Client::new();
    let loop_fut = reconnect_loop(
        || async {
            match tokio_tungstenite::connect_async(&config.gateway).await {
                Ok((ws, _resp)) => Some(ws),
                Err(e) => {
                    eprintln!("gateway dial failed: {e}");
                    None
                }
            }
        },
        |ws| serve(ws, &config, &node_key, &wallet_pubkey, &client),
        |delay| {
            eprintln!("gateway disconnected; reconnecting in {}s", delay.as_secs());
            tokio::time::sleep(delay)
        },
    );
    // Race the whole supervised loop against ctrl-c so a signal during a
    // backoff sleep (not just mid-session) also exits cleanly.
    tokio::select! {
        outcome = loop_fut => outcome,
        _ = tokio::signal::ctrl_c() => SessionOutcome::Shutdown,
    }
}

/// The reconnect supervisor: repeatedly `connect`, hand the socket to
/// `serve_fn`, and on a disconnect sleep via `sleep_fn` with exponentially
/// increasing backoff before reconnecting. Generic over the connector,
/// session runner, and the sleeper so tests can inject an in-process
/// gateway and observe the backoff schedule without real-time waits.
///
/// `connect` returns `None` on dial failure (treated as a disconnect, so a
/// failed dial still backs off). `serve_fn` runs one session and returns
/// its [`SessionOutcome`]. `sleep_fn` is handed each backoff `Duration` and
/// returns a future to await — production sleeps for real; tests record the
/// delay and return immediately.
pub async fn reconnect_loop<C, CFut, S, SFut, Slp, SlpFut>(
    connect: C,
    mut serve_fn: S,
    mut sleep_fn: Slp,
) -> SessionOutcome
where
    C: Fn() -> CFut,
    CFut: std::future::Future<Output = Option<GatewaySocket>>,
    S: FnMut(GatewaySocket) -> SFut,
    SFut: std::future::Future<Output = SessionOutcome>,
    Slp: FnMut(Duration) -> SlpFut,
    SlpFut: std::future::Future<Output = ()>,
{
    let mut backoff: Option<Duration> = None;
    loop {
        let outcome = match connect().await {
            Some(ws) => serve_fn(ws).await,
            None => SessionOutcome::Disconnected,
        };
        match outcome {
            SessionOutcome::Rejected(reason) => return SessionOutcome::Rejected(reason),
            SessionOutcome::Shutdown => return SessionOutcome::Shutdown,
            SessionOutcome::Disconnected => {
                let delay = next_backoff(backoff);
                backoff = Some(delay);
                sleep_fn(delay).await;
            }
        }
    }
}

/// Drive an already-connected socket: complete the handshake, then run the
/// job loop. Split out from dialing so tests can hand in a plain-TCP socket.
pub async fn serve(
    mut ws: GatewaySocket,
    config: &Config,
    node_key: &NodeKey,
    wallet_pubkey: &str,
    client: &reqwest::Client,
) -> SessionOutcome {
    // --- Handshake: await challenge, sign nonce, send auth, await ready. ---
    let challenge_nonce = loop {
        match ws.next().await {
            Some(Ok(Message::Text(txt))) => match ServerFrame::parse(&txt) {
                Some(ServerFrame::Challenge { nonce }) => break nonce,
                Some(ServerFrame::Rejected { reason }) => {
                    return SessionOutcome::Rejected(reason);
                }
                _ => {} // ignore anything before the challenge
            },
            Some(Ok(Message::Ping(_))) => {} // tungstenite auto-pongs
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return SessionOutcome::Disconnected,
        }
    };

    let nonce_bytes = match bs58::decode(&challenge_nonce).into_vec() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("gateway sent an undecodable nonce: {e}");
            return SessionOutcome::Disconnected;
        }
    };
    let signature = node_key.sign_base58(&nonce_bytes);
    let auth = AuthFrame {
        node_pubkey: node_key.pubkey_base58(),
        wallet_pubkey: wallet_pubkey.to_string(),
        model: config.model.clone(),
        context_len: None,
        signature,
    };
    let auth_txt = match auth.to_text() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("failed to encode auth frame: {e}");
            return SessionOutcome::Disconnected;
        }
    };
    if ws.send(Message::Text(auth_txt)).await.is_err() {
        return SessionOutcome::Disconnected;
    }

    // Await ready / rejected.
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(txt))) => match ServerFrame::parse(&txt) {
                Some(ServerFrame::Ready) => break,
                Some(ServerFrame::Rejected { reason }) => {
                    return SessionOutcome::Rejected(reason);
                }
                _ => {}
            },
            Some(Ok(Message::Ping(_))) => {}
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return SessionOutcome::Disconnected,
        }
    }

    eprintln!("authenticated; serving model `{}`", config.model);

    // --- Job loop. ---
    let upstream_url = format!("{}/chat/completions", config.upstream.trim_end_matches('/'));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                let _ = ws.send(Message::Close(None)).await;
                return SessionOutcome::Shutdown;
            }
            msg = ws.next() => {
                match msg {
                    Some(Ok(Message::Text(txt))) => {
                        if let Some(ServerFrame::Job { job_id, body }) = ServerFrame::parse(&txt) {
                            // Forward + stream back. A send failure means the
                            // socket died → reconnect.
                            if !handle_job(&mut ws, client, &upstream_url, &job_id, body).await {
                                return SessionOutcome::Disconnected;
                            }
                        }
                        // Other server frames (e.g. a late rejected) are ignored
                        // mid-session.
                    }
                    Some(Ok(Message::Ping(_))) => { /* tungstenite auto-pongs */ }
                    Some(Ok(Message::Close(_))) => return SessionOutcome::Disconnected,
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => return SessionOutcome::Disconnected,
                }
            }
        }
    }
}

/// POST a job body to the upstream (stream forced on), parse the SSE
/// response, and stream `chunk` frames back followed by `done`. On any
/// upstream failure, send a `job_error` frame instead. Returns `false` if
/// writing back to the gateway failed (socket dead → caller reconnects).
async fn handle_job(
    ws: &mut GatewaySocket,
    client: &reqwest::Client,
    upstream_url: &str,
    job_id: &str,
    mut body: serde_json::Value,
) -> bool {
    // Force streaming so we get SSE deltas regardless of the request body.
    if let serde_json::Value::Object(ref mut map) = body {
        map.insert("stream".to_string(), serde_json::Value::Bool(true));
    }

    let resp = match client.post(upstream_url).json(&body).send().await {
        Ok(r) => r,
        Err(e) => {
            return send_text(ws, job_error_frame(job_id, &format!("upstream request failed: {e}")))
                .await;
        }
    };
    if !resp.status().is_success() {
        let status = resp.status();
        let detail = resp.text().await.unwrap_or_default();
        let msg = format!("upstream HTTP {status}: {}", detail.chars().take(200).collect::<String>());
        return send_text(ws, job_error_frame(job_id, &msg)).await;
    }

    // Stream the SSE body line by line. reqwest gives us a byte stream; we
    // accumulate into a buffer and split on newlines so a chunk boundary
    // never splits an SSE line.
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut final_usage: Option<serde_json::Value> = None;

    loop {
        let chunk = match stream.next().await {
            Some(Ok(bytes)) => bytes,
            Some(Err(e)) => {
                return send_text(ws, job_error_frame(job_id, &format!("upstream stream error: {e}")))
                    .await;
            }
            None => break, // stream ended
        };
        buf.push_str(&String::from_utf8_lossy(&chunk));

        // Drain complete lines from the buffer.
        while let Some(nl) = buf.find('\n') {
            let line: String = buf.drain(..=nl).collect();
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                continue;
            }
            match protocol::parse_sse_line(line) {
                Some(SseEvent::Delta(delta)) => {
                    if !delta.is_empty()
                        && !send_text(ws, chunk_frame(job_id, &delta)).await
                    {
                        return false;
                    }
                }
                Some(SseEvent::Usage(u)) => final_usage = Some(u),
                Some(SseEvent::Done) => {
                    let usage = final_usage.take().unwrap_or_else(|| serde_json::json!({}));
                    return send_text(ws, done_frame(job_id, usage)).await;
                }
                Some(SseEvent::Other) | None => {}
            }
        }
    }

    // Stream ended without an explicit [DONE]: still finalize the job.
    let usage = final_usage.unwrap_or_else(|| serde_json::json!({}));
    send_text(ws, done_frame(job_id, usage)).await
}

/// Send a text frame; `true` on success, `false` if the socket is dead.
async fn send_text(ws: &mut GatewaySocket, text: String) -> bool {
    ws.send(Message::Text(text)).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps() {
        let d1 = next_backoff(None);
        assert_eq!(d1, Duration::from_secs(1));
        let d2 = next_backoff(Some(d1));
        assert_eq!(d2, Duration::from_secs(2));
        let d3 = next_backoff(Some(d2));
        assert_eq!(d3, Duration::from_secs(4));
        // Walk up to and past the cap.
        let mut d = d3;
        for _ in 0..10 {
            d = next_backoff(Some(d));
        }
        assert_eq!(d, BACKOFF_MAX);
        // Capped delays stay capped, never exceed 30s.
        assert_eq!(next_backoff(Some(BACKOFF_MAX)), BACKOFF_MAX);
    }

    #[test]
    fn second_delay_exceeds_first() {
        let first = next_backoff(None);
        let second = next_backoff(Some(first));
        assert!(second > first, "second backoff {second:?} must exceed first {first:?}");
    }
}
