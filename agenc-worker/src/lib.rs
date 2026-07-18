//! `agenc-worker` — client-consumable worker-signed proof-of-inference.
//!
//! The worker signs its OWN proof with its OWN key. There is deliberately NO
//! judge/verdict in this body: a worker cannot self-judge, so approval is a
//! Nexus-only concern layered on top elsewhere. Keeping this crate free of
//! `sqlx` / `solana-sdk` / `solana-client` / `solana-rpc-client` is the whole
//! point — it must stay slim enough to embed in `nexus-client`.
//! gnn-z8hl.3 — the `builder` module lifts the live Builder driver
//! (`drive_builder` + the `Mcp` trait + `McpClient`) out of the server so the
//! slim client can drive a run through the Nexus MCP without pulling server deps.
pub mod builder;
pub mod manifest;
pub mod proof;
pub mod tx;
pub mod worker;

pub use builder::{drive_builder, sign_siws, Mcp, McpClient};

// gnn-ved1 — the SINGLE-SOURCE artifact hash. Both the slim client and the
// server commit this exact hash; the server re-exports it from here so there is
// only ONE implementation.
pub use manifest::{files_from_json, manifest_hash};

pub use proof::{
    build_worker_proof, canonical_body_bytes, Canary, SignedWorkerProof, WorkerProofBody,
    WorkerProofInput,
};

pub use tx::{
    assemble_wire_tx, assert_expected, send_json_rpc, sign_and_send, sign_message, TxError,
};

pub use worker::{worker_roundtrip, WorkerCfg, WorkerError, WorkerMeta, WorkerSubmit};
