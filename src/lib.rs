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
