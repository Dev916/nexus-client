//! `manifest` — the canonical, deterministic artifact hash over a built app's
//! file bundle, plus the JSON→bundle decode the Builder status snapshot uses.
//!
//! This is the SINGLE source of the manifest hash (gnn-ved1). The server's
//! `agenc::orchestrator` re-exports [`manifest_hash`] from here instead of
//! keeping its own copy, so the slim worker (`nexus-client work`) and the
//! DB-backed server commit **byte-identical** `artifact_sha256` values for the
//! same promoted app. Divergent copies would let the on-chain proof commit a
//! hash the server never agrees with — exactly the Slice 5 acceptance/payout
//! footgun this fix removes.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Deterministic, order-independent manifest hash over a bundle's files.
///
/// For each `(path, content)` we form the line `"{path}:{sha256hex(content)}"`,
/// sort the lines (→ order-independence), join with `"\n"`, and sha256 the
/// result. Returns lowercase hex (64 chars).
pub fn manifest_hash(files: &[(String, Vec<u8>)]) -> String {
    let mut lines: Vec<String> = files
        .iter()
        .map(|(path, content)| {
            let content_hash = hex::encode(Sha256::digest(content));
            format!("{path}:{content_hash}")
        })
        .collect();
    lines.sort();
    let joined = lines.join("\n");
    hex::encode(Sha256::digest(joined.as_bytes()))
}

/// Decode a Builder session's `files` JSON object `{ name: contents }` into the
/// ordered `Vec<(String, Vec<u8>)>` shape [`manifest_hash`] expects.
///
/// This MIRRORS the server's `orchestrator::files_to_vec` decode byte-for-byte
/// so the two layers hash the same bytes: string contents map to their UTF-8
/// bytes; any non-string value falls back to its compact JSON serialization so
/// the hash stays stable. A `files` value that is absent or not a JSON object
/// yields an EMPTY bundle — the caller treats that as the empty-manifest edge
/// case (a promoted session should always carry files on the happy path).
pub fn files_from_json(files: &Value) -> Vec<(String, Vec<u8>)> {
    let Some(obj) = files.as_object() else {
        return Vec::new();
    };
    obj.iter()
        .map(|(name, contents)| {
            let bytes = match contents.as_str() {
                Some(s) => s.as_bytes().to_vec(),
                None => contents.to_string().into_bytes(),
            };
            (name.clone(), bytes)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_hex64(s: &str) -> bool {
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    #[test]
    fn manifest_hash_is_64_hex() {
        let files = vec![("index.html".to_string(), b"<html></html>".to_vec())];
        let h = manifest_hash(&files);
        assert!(is_hex64(&h), "expected 64-char hex, got {h:?}");
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let files = vec![
            ("index.html".to_string(), b"<html></html>".to_vec()),
            ("game.js".to_string(), b"let x = 1;".to_vec()),
        ];
        let a = manifest_hash(&files);
        let b = manifest_hash(&files);
        assert_eq!(a, b, "same input → same hash");
    }

    #[test]
    fn manifest_hash_is_order_independent() {
        let forward = vec![
            ("a.txt".to_string(), b"alpha".to_vec()),
            ("b.txt".to_string(), b"beta".to_vec()),
            ("c.txt".to_string(), b"gamma".to_vec()),
        ];
        let mut reversed = forward.clone();
        reversed.reverse();
        assert_eq!(
            manifest_hash(&forward),
            manifest_hash(&reversed),
            "hash must not depend on file order"
        );
    }

    #[test]
    fn manifest_hash_changes_with_content() {
        let a = manifest_hash(&[("f".to_string(), b"one".to_vec())]);
        let b = manifest_hash(&[("f".to_string(), b"two".to_vec())]);
        assert_ne!(a, b, "different content → different hash");
    }

    #[test]
    fn manifest_hash_changes_with_path() {
        let a = manifest_hash(&[("x".to_string(), b"same".to_vec())]);
        let b = manifest_hash(&[("y".to_string(), b"same".to_vec())]);
        assert_ne!(a, b, "different path → different hash");
    }

    #[test]
    fn files_from_json_maps_string_object() {
        let files = serde_json::json!({ "index.html": "<h1>hi</h1>", "app.js": "console.log(1)" });
        let v = files_from_json(&files);
        assert_eq!(v.len(), 2);
        // manifest_hash over the mapped vec is stable 64-hex.
        assert!(is_hex64(&manifest_hash(&v)));
    }

    #[test]
    fn files_from_json_non_object_is_empty() {
        // A null / missing `files` (the promote-without-files edge) → empty bundle,
        // so the caller commits the empty-manifest hash rather than panicking.
        assert!(files_from_json(&Value::Null).is_empty());
        assert!(files_from_json(&serde_json::json!([1, 2, 3])).is_empty());
    }
}
