//! `nexus-client` library surface.
//!
//! The binary (`src/main.rs`) is a thin CLI shell over these modules.
//! Exposing them as a library lets integration tests in `tests/` drive the
//! pull loop (`run::serve`, `run::reconnect_loop`) against an in-process
//! mock gateway + mock upstream, instead of only black-box testing the
//! compiled binary.

pub mod config;
pub mod keys;
pub mod limits;
pub mod protocol;
pub mod run;
pub mod solana_stake;
pub mod wallet_auth;
/// gnn-z8hl.3 (Task 5) — the AgenC provider loop (`nexus-client work`):
/// discover → evaluate (`should_claim`) → drive a delegated Builder session →
/// settle on-chain via `agenc_worker::worker_roundtrip`. Exposed as a library
/// module so the loop body (`work_once`) + the pure claim decision are
/// unit/integration-tested against a mock Nexus + a scripted MCP.
pub mod work;
