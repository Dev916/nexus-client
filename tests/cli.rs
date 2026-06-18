//! CLI integration tests for `nexus-client` — exercises the binary as a
//! subprocess, mirroring the T5 acceptance criteria (init / re-init refuse
//! / status), the T6 `start` guard (refuse uninitialized dir), and the
//! still-stubbed `earnings` subcommand.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn bin() -> Command {
    Command::cargo_bin("nexus-client").unwrap()
}

#[test]
fn no_subcommand_prints_quickstart_and_succeeds() {
    // Double-clicking the .exe runs it with no subcommand. That must NOT be a
    // clap error (which on Windows flashes a transient console and vanishes);
    // it shows a readable quick-start and exits 0. The Windows "press Enter"
    // pause only fires on an actual double-click, never from a shell, so this
    // subprocess test neither blocks nor pauses.
    bin()
        .assert()
        .success()
        .stdout(predicate::str::contains("nexus-client init"))
        .stdout(predicate::str::contains("nexus-client start"));
}

#[test]
fn init_creates_files_and_prints_pubkeys() {
    let dir = tempdir().unwrap();
    let path = dir.path();

    bin()
        .args(["init", "--dir"])
        .arg(path)
        .assert()
        .success()
        .stdout(predicate::str::contains("node pubkey:"))
        .stdout(predicate::str::contains("wallet pubkey:"));

    assert!(path.join("node_key").exists(), "node_key created");
    assert!(path.join("wallet.json").exists(), "wallet.json created");
    assert!(path.join("config.toml").exists(), "config.toml created");

    // wallet.json must be the 64-byte JSON-array solana format.
    let wallet: Vec<u8> =
        serde_json::from_str(&std::fs::read_to_string(path.join("wallet.json")).unwrap()).unwrap();
    assert_eq!(wallet.len(), 64, "wallet.json is a 64-byte array");

    // node_key must be exactly 32 raw bytes.
    let node_key = std::fs::read(path.join("node_key")).unwrap();
    assert_eq!(node_key.len(), 32, "node_key is 32 raw seed bytes");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path.join("node_key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "node_key is mode 0600");
    }
}

#[test]
fn reinit_refuses_with_already_initialized() {
    let dir = tempdir().unwrap();
    let path = dir.path();

    bin().args(["init", "--dir"]).arg(path).assert().success();

    // Capture the node pubkey from a status to ensure the key is untouched.
    let before = String::from_utf8(
        bin()
            .args(["status", "--dir"])
            .arg(path)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();

    bin()
        .args(["init", "--dir"])
        .arg(path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already initialized"));

    let after = String::from_utf8(
        bin()
            .args(["status", "--dir"])
            .arg(path)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();

    assert_eq!(before, after, "re-init must not overwrite the existing key");
}

#[test]
fn status_prints_model_and_endpoints() {
    let dir = tempdir().unwrap();
    let path = dir.path();

    bin().args(["init", "--dir"]).arg(path).assert().success();

    bin()
        .args(["status", "--dir"])
        .arg(path)
        .assert()
        .success()
        .stdout(predicate::str::contains("model:    hermes-3"))
        .stdout(predicate::str::contains(
            "upstream: http://localhost:11434/v1",
        ))
        .stdout(predicate::str::contains(
            "gateway:  wss://nexus.ghostnn.ai/api/compute/node",
        ));
}

#[test]
fn init_honors_model_flag() {
    let dir = tempdir().unwrap();
    let path = dir.path();

    bin()
        .args(["init", "--dir"])
        .arg(path)
        .args(["--model", "kimi-k2"])
        .assert()
        .success();

    bin()
        .args(["status", "--dir"])
        .arg(path)
        .assert()
        .success()
        .stdout(predicate::str::contains("model:    kimi-k2"));
}

#[test]
fn start_refuses_uninitialized_dir() {
    // `start` is implemented as of T6 (the pull loop). With no node key in
    // the target dir it must refuse fast (exit 1, "not initialized") rather
    // than try to dial a gateway.
    let dir = tempdir().unwrap();
    bin()
        .args(["start", "--dir"])
        .arg(dir.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not initialized"));
}

#[test]
fn earnings_refuses_uninitialized_dir() {
    // `earnings` is implemented as of T10. With no node key in the target
    // dir it must refuse fast (exit 1, "not initialized") rather than try
    // to hit the gateway.
    let dir = tempdir().unwrap();
    bin()
        .args(["earnings", "--dir"])
        .arg(dir.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not initialized"));
}
