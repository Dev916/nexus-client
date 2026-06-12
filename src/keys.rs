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
use std::io::{self, Write};
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zeroize::{Zeroize, Zeroizing};

/// Filename of the raw 32-byte Ed25519 node seed.
pub const NODE_KEY_FILE: &str = "node_key";
/// Filename of the Solana wallet (64-byte JSON array, solana-tooling format).
pub const WALLET_FILE: &str = "wallet.json";

/// Atomically create `path` (refusing to overwrite) with owner-only
/// permissions and write `bytes`. This is the single safe-write primitive
/// for every secret/config file the client persists (NX-8/NX-9):
///   * `create_new(true)` makes creation atomic + exclusive at the OS
///     level — no check-then-write TOCTOU, and an existing file is never
///     clobbered (protects the only copy of a payout key).
///   * On Unix the file is created with mode 0600 BEFORE any bytes land,
///     so the secret is never briefly group/other-readable.
///   * On Windows (where the binary also ships) the file inherits the
///     parent-dir ACL; we surface that rather than silently no-op.
pub fn write_new_secure(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// The client's Ed25519 node identity. Wraps a `SigningKey`; the seed is
/// the 32 bytes persisted to `node_key`.
pub struct NodeKey {
    signing: SigningKey,
}

impl NodeKey {
    /// Generate a fresh random node key. The transient seed buffer is
    /// zeroized on drop (NX-7).
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed.as_mut());
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

    /// Write the raw 32-byte seed to `<dir>/node_key`, created atomically
    /// with mode 0600 and refusing to overwrite an existing identity
    /// (NX-8/NX-9). The seed bytes are zeroized after writing (NX-7).
    pub fn save(&self, dir: &Path) -> io::Result<()> {
        let path = dir.join(NODE_KEY_FILE);
        let seed = Zeroizing::new(self.signing.to_bytes());
        write_new_secure(&path, seed.as_ref()).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(io::ErrorKind::AlreadyExists, "already initialized")
            } else {
                e
            }
        })
    }

    /// Load a node key from the raw 32-byte seed at `<dir>/node_key`. The
    /// file bytes are zeroized after the key is constructed (NX-7).
    pub fn load(dir: &Path) -> io::Result<Self> {
        let path = dir.join(NODE_KEY_FILE);
        let bytes = Zeroizing::new(fs::read(&path)?);
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "node_key must be exactly 32 bytes",
            )
        })?;
        let mut seed = Zeroizing::new(seed);
        let key = Self {
            signing: SigningKey::from_bytes(&seed),
        };
        seed.zeroize();
        Ok(key)
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
/// CLI tooling reads. Created atomically with mode 0600, refusing to
/// overwrite (NX-8/NX-9). The serialized secret bytes are zeroized (NX-7).
pub fn save_wallet(wallet: &Keypair, dir: &Path) -> io::Result<()> {
    let path = dir.join(WALLET_FILE);
    let bytes = Zeroizing::new(wallet.to_bytes().to_vec());
    let json = Zeroizing::new(serde_json::to_string(bytes.as_slice())?);
    write_new_secure(&path, json.as_bytes())
}

/// Read the wallet pubkey (base58) from `<dir>/wallet.json`. The secret
/// bytes loaded only to derive the pubkey are zeroized (NX-7).
pub fn load_wallet_pubkey(dir: &Path) -> io::Result<String> {
    let path = dir.join(WALLET_FILE);
    let json = Zeroizing::new(fs::read_to_string(&path)?);
    let bytes = Zeroizing::new(serde_json::from_str::<Vec<u8>>(&json)?);
    let arr: [u8; 64] = bytes.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "wallet.json must be a 64-byte array",
        )
    })?;
    let mut arr = Zeroizing::new(arr);
    let wallet = Keypair::try_from(&arr[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let pubkey = wallet.pubkey().to_string();
    arr.zeroize();
    Ok(pubkey)
}

/// Set file permissions to owner-read/write only (0600) on Unix. Retained
/// for any post-hoc tightening; the primary write path now creates files
/// 0600 atomically via [`write_new_secure`]. No-op on non-Unix.
#[allow(dead_code)]
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

    // NX-8: wallet.json must refuse to overwrite (it holds the only copy
    // of the payout key) and leave the original untouched.
    #[test]
    fn save_wallet_refuses_overwrite_and_preserves_original() {
        let dir = tempdir().unwrap();
        let original = generate_wallet();
        let original_pubkey = original.pubkey().to_string();
        save_wallet(&original, dir.path()).unwrap();

        let intruder = generate_wallet();
        let err = save_wallet(&intruder, dir.path()).expect_err("second wallet save must fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        // The on-disk wallet is still the original — not clobbered.
        assert_eq!(load_wallet_pubkey(dir.path()).unwrap(), original_pubkey);
    }

    // NX-9: wallet.json is created 0600 atomically (never world-readable).
    #[test]
    fn wallet_file_is_mode_0600() {
        let dir = tempdir().unwrap();
        save_wallet(&generate_wallet(), dir.path()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(WALLET_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "wallet.json must be owner-only");
        }
    }

    // NX-8: write_new_secure is atomic-exclusive — a second write of the
    // same path errors AlreadyExists and the first content survives.
    #[test]
    fn write_new_secure_is_exclusive() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret");
        write_new_secure(&path, b"first").unwrap();
        let err = write_new_secure(&path, b"second").expect_err("overwrite must fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"first", "original content preserved");
    }
}
