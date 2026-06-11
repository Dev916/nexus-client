//! Client configuration (`config.toml`).
//!
//! Holds the three knobs the client needs to operate: which `model` it
//! serves, the `upstream` OpenAI-compatible local inference server it
//! forwards jobs to, and the `gateway` WebSocket URL it dials for work.
//! Defaults are the spec defaults (Hermes 3 / local Ollama / prod gateway).

use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Default model served by a fresh client.
pub const DEFAULT_MODEL: &str = "hermes-3";
/// Default upstream OpenAI-compatible server (Ollama's default port).
pub const DEFAULT_UPSTREAM: &str = "http://localhost:11434/v1";
/// Default gateway WebSocket endpoint.
pub const DEFAULT_GATEWAY: &str = "wss://nexus.ghostnn.ai/api/compute/node";

/// Filename of the client config under the client dir.
pub const CONFIG_FILE: &str = "config.toml";

/// On-disk client config. All fields default to the spec values when a
/// key is absent, so partial configs still load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_upstream")]
    pub upstream: String,
    #[serde(default = "default_gateway")]
    pub gateway: String,
}

fn default_model() -> String {
    DEFAULT_MODEL.to_string()
}
fn default_upstream() -> String {
    DEFAULT_UPSTREAM.to_string()
}
fn default_gateway() -> String {
    DEFAULT_GATEWAY.to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            model: default_model(),
            upstream: default_upstream(),
            gateway: default_gateway(),
        }
    }
}

impl Config {
    /// A config with the given model and the default upstream + gateway.
    pub fn with_model(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            ..Self::default()
        }
    }

    /// Serialize to a TOML string.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Parse from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Write the config to `<dir>/config.toml`.
    pub fn save(&self, dir: &Path) -> io::Result<()> {
        let path = dir.join(CONFIG_FILE);
        let toml = self
            .to_toml()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        fs::write(path, toml)
    }

    /// Load the config from `<dir>/config.toml`.
    pub fn load(dir: &Path) -> io::Result<Self> {
        let path = dir.join(CONFIG_FILE);
        let s = fs::read_to_string(path)?;
        Self::from_toml(&s).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    /// The gateway's HTTP origin (scheme + authority), derived from the
    /// configured `gateway` WebSocket URL: `ws://` → `http://`, `wss://` →
    /// `https://`, with the `/api/compute/node` path (and anything else
    /// after the authority) stripped. Used by `earnings` to hit the
    /// REST endpoints on the same gateway the node dials for work.
    ///
    /// e.g. `wss://nexus.ghostnn.ai/api/compute/node`
    ///   → `https://nexus.ghostnn.ai`.
    ///
    /// An unrecognized scheme (not ws/wss) is passed through unchanged so a
    /// caller that already configured an `http(s)` origin still works.
    pub fn gateway_http_origin(&self) -> String {
        http_origin_from_ws(&self.gateway)
    }
}

/// Pure helper: turn a `ws(s)://host[:port]/path…` gateway URL into the
/// `http(s)://host[:port]` origin (scheme mapped, path/query/fragment
/// dropped). Extracted out of `Config` so it's unit-testable in isolation.
pub fn http_origin_from_ws(gateway: &str) -> String {
    // Map the scheme; keep the rest of the URL as the "remainder" after `://`.
    let (http_scheme, remainder) = if let Some(rest) = gateway.strip_prefix("wss://") {
        ("https://", rest)
    } else if let Some(rest) = gateway.strip_prefix("ws://") {
        ("http://", rest)
    } else if gateway.starts_with("http://") || gateway.starts_with("https://") {
        // Already an http(s) URL — strip the path off the authority below.
        let scheme_end = gateway.find("://").map(|i| i + 3).unwrap_or(0);
        let (scheme, rest) = gateway.split_at(scheme_end);
        return format!("{scheme}{}", authority_only(rest));
    } else {
        // Unknown scheme: pass through unchanged.
        return gateway.to_string();
    };
    format!("{http_scheme}{}", authority_only(remainder))
}

/// Take only the authority (`host[:port]`) from `host[:port]/path?query#frag`
/// by truncating at the first `/`, `?`, or `#`.
fn authority_only(s: &str) -> &str {
    let end = s.find(['/', '?', '#']).unwrap_or(s.len());
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn defaults_match_spec() {
        let c = Config::default();
        assert_eq!(c.model, "hermes-3");
        assert_eq!(c.upstream, "http://localhost:11434/v1");
        assert_eq!(c.gateway, "wss://nexus.ghostnn.ai/api/compute/node");
    }

    #[test]
    fn toml_roundtrip_preserves_values() {
        let c = Config {
            model: "kimi-k2".to_string(),
            upstream: "http://localhost:8000/v1".to_string(),
            gateway: "wss://example.test/api/compute/node".to_string(),
        };
        let s = c.to_toml().unwrap();
        let back = Config::from_toml(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn missing_keys_fall_back_to_defaults() {
        // An empty config file must yield all spec defaults.
        let back = Config::from_toml("").unwrap();
        assert_eq!(back, Config::default());
    }

    #[test]
    fn partial_config_keeps_other_defaults() {
        let back = Config::from_toml("model = \"qwen-3\"\n").unwrap();
        assert_eq!(back.model, "qwen-3");
        assert_eq!(back.upstream, DEFAULT_UPSTREAM);
        assert_eq!(back.gateway, DEFAULT_GATEWAY);
    }

    #[test]
    fn save_load_roundtrip_via_disk() {
        let dir = tempdir().unwrap();
        let c = Config::with_model("hermes-3");
        c.save(dir.path()).unwrap();
        let back = Config::load(dir.path()).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn ws_origin_maps_scheme_and_strips_path() {
        // wss → https, strip /api/compute/node (the default prod gateway).
        assert_eq!(
            http_origin_from_ws("wss://nexus.ghostnn.ai/api/compute/node"),
            "https://nexus.ghostnn.ai"
        );
        // ws → http, with a port preserved and the path dropped.
        assert_eq!(
            http_origin_from_ws("ws://127.0.0.1:8080/api/compute/node"),
            "http://127.0.0.1:8080"
        );
        // No path at all still works.
        assert_eq!(
            http_origin_from_ws("wss://gw.example"),
            "https://gw.example"
        );
        // Query / fragment after the authority are dropped too.
        assert_eq!(
            http_origin_from_ws("ws://host:9/path?q=1#frag"),
            "http://host:9"
        );
        // Already-http(s) input: scheme kept, path stripped.
        assert_eq!(
            http_origin_from_ws("http://localhost:3000/api/compute/node"),
            "http://localhost:3000"
        );
        // Unknown scheme: pass through unchanged (defensive).
        assert_eq!(http_origin_from_ws("tcp://nope"), "tcp://nope");
    }

    #[test]
    fn config_method_delegates_to_helper() {
        let c = Config {
            model: "hermes-3".into(),
            upstream: DEFAULT_UPSTREAM.into(),
            gateway: "ws://127.0.0.1:5555/api/compute/node".into(),
        };
        assert_eq!(c.gateway_http_origin(), "http://127.0.0.1:5555");
    }
}
