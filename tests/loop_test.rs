//! Loop + reconnect integration tests for the `start` pull loop (T6).
//!
//! These exercise the real `nexus_client::run` against an *in-process*
//! mock gateway (a `tokio_tungstenite::accept_async` server on an ephemeral
//! port) and a mock upstream (a raw tokio `TcpListener` serving a canned
//! OpenAI-style SSE HTTP response). No network, no Docker, no real gateway.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use nexus_client::config::Config;
use nexus_client::keys::NodeKey;
use nexus_client::run::{self, SessionOutcome};

/// Spin up the mock upstream: a raw HTTP/1.1 server that answers any POST
/// with a canned `text/event-stream` body carrying two content deltas and
/// `[DONE]`. Returns the base URL (`http://127.0.0.1:PORT`) — the client
/// appends `/chat/completions`.
async fn spawn_mock_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Serve a single connection then exit — one job in the test.
        if let Ok((mut sock, _)) = listener.accept().await {
            // Drain the request (read until headers end). We don't need the
            // body; the canned response is fixed.
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;

            let sse = concat!(
                "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
                "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n",
                "data: {\"choices\":[{\"delta\":{\"content\":\", world\"}}]}\n\n",
                "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\n",
                "data: [DONE]\n\n",
            );
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/event-stream\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                sse.len(),
                sse
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });
    format!("http://{addr}")
}

/// Outcome of running the mock gateway for one connection: the frames the
/// client streamed back (kind strings + their parsed JSON).
struct GatewayCapture {
    auth_ok: bool,
    chunks: Vec<String>,
    done: bool,
}

/// Spin up the mock gateway: accept one WS connection, run the full
/// handshake (challenge → verify signature → ready), push one job, then
/// collect the client's chunk/done frames until `done` (or the socket
/// closes). Sends the capture over `tx`. Returns the `ws://` URL to dial.
async fn spawn_mock_gateway(job_body: serde_json::Value, tx: mpsc::Sender<GatewayCapture>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

        // 1. Challenge with a random 32-byte nonce (base58).
        let nonce: [u8; 32] = rand_nonce();
        let nonce_b58 = bs58::encode(nonce).into_string();
        ws.send(Message::Text(
            serde_json::json!({ "kind": "challenge", "nonce": nonce_b58 }).to_string(),
        ))
        .await
        .unwrap();

        // 2. Await + verify the auth frame's signature over the raw nonce.
        let auth_ok = loop {
            match ws.next().await {
                Some(Ok(Message::Text(txt))) => {
                    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
                    if v.get("kind").and_then(|k| k.as_str()) == Some("auth") {
                        break verify_auth(&v, &nonce);
                    }
                }
                Some(Ok(_)) => {}
                _ => break false,
            }
        };

        if !auth_ok {
            ws.send(Message::Text(
                serde_json::json!({"kind":"rejected","reason":"bad_signature"}).to_string(),
            ))
            .await
            .ok();
            tx.send(GatewayCapture { auth_ok: false, chunks: vec![], done: false })
                .await
                .ok();
            return;
        }

        // 3. ready, then push one job.
        ws.send(Message::Text(
            serde_json::json!({ "kind": "ready" }).to_string(),
        ))
        .await
        .unwrap();
        ws.send(Message::Text(
            serde_json::json!({ "kind": "job", "job_id": "job-1", "body": job_body }).to_string(),
        ))
        .await
        .unwrap();

        // 4. Collect chunk/done frames the client streams back.
        let mut chunks = Vec::new();
        let mut done = false;
        while let Some(Ok(msg)) = ws.next().await {
            if let Message::Text(txt) = msg {
                let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
                match v.get("kind").and_then(|k| k.as_str()) {
                    Some("chunk") => {
                        chunks.push(v["delta"].as_str().unwrap_or("").to_string());
                    }
                    Some("done") => {
                        done = true;
                        break;
                    }
                    Some("job_error") => {
                        break;
                    }
                    _ => {}
                }
            }
        }

        tx.send(GatewayCapture { auth_ok, chunks, done }).await.ok();
    });

    format!("ws://{addr}")
}

/// Verify the client's auth frame: decode node_pubkey + signature (base58)
/// and `verify_strict` over the DOMAIN-SEPARATED message (AUTH_DOMAIN_TAG ++
/// nonce) — exactly the server's NX-1 rule.
fn verify_auth(v: &serde_json::Value, nonce: &[u8; 32]) -> bool {
    let Some(pk_b58) = v.get("node_pubkey").and_then(|x| x.as_str()) else { return false };
    let Some(sig_b58) = v.get("signature").and_then(|x| x.as_str()) else { return false };
    let Ok(pk_bytes) = bs58::decode(pk_b58).into_vec() else { return false };
    let Ok(pk_arr): Result<[u8; 32], _> = pk_bytes.try_into() else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else { return false };
    let Ok(sig_bytes) = bs58::decode(sig_b58).into_vec() else { return false };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else { return false };
    let sig = Signature::from_bytes(&sig_arr);
    const AUTH_DOMAIN_TAG: &[u8] = b"nexus-compute-node-auth:v1\n";
    let mut message = Vec::with_capacity(AUTH_DOMAIN_TAG.len() + nonce.len());
    message.extend_from_slice(AUTH_DOMAIN_TAG);
    message.extend_from_slice(nonce);
    vk.verify_strict(&message, &sig).is_ok()
}

fn rand_nonce() -> [u8; 32] {
    // Deterministic-ish but unique per call is unnecessary for the test;
    // any 32 bytes work since the client signs whatever it's given.
    let mut n = [0u8; 32];
    for (i, b) in n.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(13);
    }
    n
}

#[tokio::test]
async fn authenticates_runs_job_and_streams_chunks_back() {
    let upstream = spawn_mock_upstream().await;
    let (tx, mut rx) = mpsc::channel(1);
    let job_body = serde_json::json!({
        "model": "hermes-3",
        "messages": [{ "role": "user", "content": "hi" }]
    });
    let gateway_url = spawn_mock_gateway(job_body, tx).await;

    let config = Config {
        model: "hermes-3".to_string(),
        upstream,
        gateway: gateway_url.clone(),
    };
    let node_key = NodeKey::generate();
    let wallet_pubkey = "WaLLeTPubKey1111111111111111111111111111111".to_string();

    // Dial the mock gateway and run ONE session via `serve`.
    let (ws, _resp) = tokio_tungstenite::connect_async(&gateway_url).await.unwrap();
    let client = reqwest::Client::new();
    let session = tokio::spawn(async move {
        run::serve(ws, &config, &node_key, &wallet_pubkey, &client).await
    });

    // The gateway capture arrives once the client sends `done`.
    let capture = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("gateway capture timed out")
        .expect("gateway dropped without a capture");

    assert!(capture.auth_ok, "client must authenticate (valid signature over nonce)");
    assert!(
        capture.chunks.len() >= 2,
        "expected >=2 chunk frames, got {}: {:?}",
        capture.chunks.len(),
        capture.chunks
    );
    assert!(capture.done, "expected a terminal done frame");
    assert_eq!(
        capture.chunks.join(""),
        "Hello, world",
        "chunk deltas must reassemble the upstream content"
    );

    // The session future may still be awaiting more jobs; abort it now.
    session.abort();
    let _ = session.await;
}

#[tokio::test]
async fn reconnects_with_increasing_backoff() {
    // Drive the reconnect supervisor with an injected connector that always
    // "fails" (returns None → Disconnected) and a sleeper that records the
    // backoff delays instead of actually sleeping. After 3 attempts we
    // shut it down by returning Shutdown from the connector path.
    let attempts = Arc::new(AtomicU32::new(0));
    let delays = Arc::new(std::sync::Mutex::new(Vec::<Duration>::new()));

    let attempts_c = attempts.clone();
    let delays_c = delays.clone();

    // connect: count attempts; after enough, signal shutdown by returning a
    // sentinel the serve_fn turns into Shutdown. We model "always drops" by
    // returning None (dial failure → Disconnected) for the first attempts,
    // then a magic socket is impossible to fabricate, so instead we stop the
    // loop from the sleeper side once we've seen two backoffs.
    let stop = Arc::new(AtomicU32::new(0));
    let stop_c = stop.clone();

    let outcome = run::reconnect_loop(
        move || {
            let attempts = attempts_c.clone();
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                None::<tokio_tungstenite::WebSocketStream<
                    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                >>
            }
        },
        // serve_fn is never called because connect always returns None.
        |_ws| async { SessionOutcome::Disconnected },
        move |delay| {
            let delays = delays_c.clone();
            let stop = stop_c.clone();
            async move {
                delays.lock().unwrap().push(delay);
                // Stop after we've recorded two backoff delays by aborting
                // the loop: we can't return Shutdown from the sleeper, so we
                // just sleep a hair and rely on the outer timeout/abort.
                if stop.fetch_add(1, Ordering::SeqCst) >= 1 {
                    // Park "forever" so the spawned task is cleanly aborted
                    // after we've captured what we need.
                    futures_util::future::pending::<()>().await;
                }
            }
        },
    );

    // Run the supervisor in a task and give it time to record >=2 delays.
    let handle = tokio::spawn(outcome);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();
    let _ = handle.await;

    let recorded = delays.lock().unwrap().clone();
    assert!(
        attempts.load(Ordering::SeqCst) >= 2,
        "expected >=2 reconnect attempts, got {}",
        attempts.load(Ordering::SeqCst)
    );
    assert!(
        recorded.len() >= 2,
        "expected >=2 backoff delays recorded, got {recorded:?}"
    );
    assert!(
        recorded[1] > recorded[0],
        "second backoff {:?} must exceed first {:?}",
        recorded[1],
        recorded[0]
    );
    // Delays are jittered ±25% around the 1s→2s doubling schedule (NX-6),
    // so assert the bands, not exact values: first ∈ [750ms,1250ms],
    // second ∈ [1500ms,2500ms]. The bands don't overlap, so the strict
    // ordering checked above holds for every draw.
    assert!(
        recorded[0] >= Duration::from_millis(750) && recorded[0] <= Duration::from_millis(1250),
        "first backoff {:?} outside jittered 1s band",
        recorded[0]
    );
    assert!(
        recorded[1] >= Duration::from_millis(1500) && recorded[1] <= Duration::from_millis(2500),
        "second backoff {:?} outside jittered 2s band",
        recorded[1]
    );
}
