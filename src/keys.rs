//! Node + wallet key material for the Nexus client.
//!
//! Two distinct keypairs live side-by-side in the client dir:
//!
//!   * **Node key** (`node_key`) — an Ed25519 keypair the gateway knows the
//!     client by. Stored as the raw 32-byte *seed* (mode 0600). The public
//!     key is derived from the seed on load. The auth handshake (T6) signs
//!     the gateway's raw nonce bytes with this key and base58-encodes both
//!     the pubkey and the signature — matching the server's `verify_strict`
//!     over raw nonce bytes (see `server/src/compute/ws.rs`).
//!
//!   * **Wallet key** (`wallet.json`) — a Solana keypair for payouts + stake,
//!     written in the standard 64-byte JSON array format that `solana-keygen`
//!     and the rest of the Solana tooling read/write.

use std::fs;
use std::io;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use solana_keypair::Keypair;
use solana_signer::Signer;

/// Filename of the raw 32-byte Ed25519 node seed.
pub const NODE_KEY_FILE: &str = "node_key";
/// Filename of the Solana wallet (64-byte JSON array, solana-tooling format).
pub const WALLET_FILE: &str = "wallet.json";

/// The client's Ed25519 node identity. Wraps a `SigningKey`; the seed is
/// the 32 bytes persisted to `node_key`.
pub struct NodeKey {
    signing: SigningKey,
}

impl NodeKey {
    /// Generate a fresh random node key.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// The Ed25519 public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Base58-encoded public key — the on-wire `node_pubkey`.
    pub fn pubkey_base58(&self) -> String {
        bs58::encode(self.verifying_key().to_bytes()).into_string()
    }

    /// Sign `msg` (e.g. the raw challenge nonce) and return the base58
    /// signature, matching the server's verification convention. Used by
    /// the auth handshake in T6 (the `start` pull loop); exercised by unit
    /// tests now so the convention is locked in.
    #[allow(dead_code)]
    pub fn sign_base58(&self, msg: &[u8]) -> String {
        use ed25519_dalek::Signer as _;
        let sig = self.signing.sign(msg);
        bs58::encode(sig.to_bytes()).into_string()
    }

    /// Write the raw 32-byte seed to `<dir>/node_key` with mode 0600.
    /// Refuses (errors) if the file already exists, so an existing identity
    /// is never silently overwritten.
    pub fn save(&self, dir: &Path) -> io::Result<()> {
        let path = dir.join(NODE_KEY_FILE);
        if path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "already initialized",
            ));
        }
        fs::write(&path, self.signing.to_bytes())?;
        set_mode_0600(&path)?;
        Ok(())
    }

    /// Load a node key from the raw 32-byte seed at `<dir>/node_key`.
    pub fn load(dir: &Path) -> io::Result<Self> {
        let path = dir.join(NODE_KEY_FILE);
        let bytes = fs::read(&path)?;
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "node_key must be exactly 32 bytes",
            )
        })?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }
}

/// True if a node key already exists under `dir`.
pub fn node_key_exists(dir: &Path) -> bool {
    dir.join(NODE_KEY_FILE).exists()
}

/// Generate a fresh Solana wallet keypair.
pub fn generate_wallet() -> Keypair {
    Keypair::new()
}

/// Write a Solana keypair to `<dir>/wallet.json` in the standard 64-byte
/// JSON array format (`[u8; 64]` = secret 32 || pubkey 32) that the Solana
/// CLI tooling reads. Mode 0600.
pub fn save_wallet(wallet: &Keypair, dir: &Path) -> io::Result<()> {
    let path = dir.join(WALLET_FILE);
    let bytes: Vec<u8> = wallet.to_bytes().to_vec();
    let json = serde_json::to_string(&bytes)?;
    fs::write(&path, json)?;
    set_mode_0600(&path)?;
    Ok(())
}

/// Read the wallet pubkey (base58) from `<dir>/wallet.json`.
pub fn load_wallet_pubkey(dir: &Path) -> io::Result<String> {
    let path = dir.join(WALLET_FILE);
    let json = fs::read_to_string(&path)?;
    let bytes: Vec<u8> = serde_json::from_str(&json)?;
    let arr: [u8; 64] = bytes.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "wallet.json must be a 64-byte array",
        )
    })?;
    let wallet = Keypair::try_from(&arr[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(wallet.pubkey().to_string())
}

/// Set file permissions to owner-read/write only (0600) on Unix. No-op on
/// other platforms (where filesystem ACLs differ).
fn set_mode_0600(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn node_key_roundtrip_preserves_pubkey() {
        let dir = tempdir().unwrap();
        let key = NodeKey::generate();
        let pubkey = key.pubkey_base58();
        key.save(dir.path()).unwrap();

        let loaded = NodeKey::load(dir.path()).unwrap();
        assert_eq!(loaded.pubkey_base58(), pubkey, "pubkey must survive save→load");
    }

    #[test]
    fn node_key_signature_is_stable_across_load() {
        let dir = tempdir().unwrap();
        let key = NodeKey::generate();
        key.save(dir.path()).unwrap();
        let loaded = NodeKey::load(dir.path()).unwrap();

        let nonce = b"a-known-32-byte-nonce-value-here!";
        assert_eq!(
            key.sign_base58(nonce),
            loaded.sign_base58(nonce),
            "same key must produce the same signature after reload"
        );
    }

    #[test]
    fn save_refuses_overwrite() {
        let dir = tempdir().unwrap();
        let key = NodeKey::generate();
        key.save(dir.path()).unwrap();

        // A second save (even of a different key) must be refused.
        let other = NodeKey::generate();
        let err = other.save(dir.path()).expect_err("second save must fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("already initialized"));
    }

    #[test]
    fn node_key_file_is_mode_0600() {
        let dir = tempdir().unwrap();
        let key = NodeKey::generate();
        key.save(dir.path()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(NODE_KEY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn wallet_roundtrip_preserves_pubkey() {
        let dir = tempdir().unwrap();
        let wallet = generate_wallet();
        let pubkey = wallet.pubkey().to_string();
        save_wallet(&wallet, dir.path()).unwrap();

        let loaded = load_wallet_pubkey(dir.path()).unwrap();
        assert_eq!(loaded, pubkey, "wallet pubkey must survive save→load");
    }
}
