//! The broker manifest: the operator-authoritative description of which servers
//! the broker supervises and how each of their tools is classified.
//!
//! Trust model (from `docs/DESIGN.md`):
//! * The manifest is **operator-authoritative**. It is owned by the broker's
//!   service account and is not writable by the operator's interactive user.
//! * A server's own annotation hints (`readOnlyHint` etc.) are used ONLY to
//!   *prefill a proposed* classification at registration time
//!   ([`propose_from_hint`]). They are NEVER trusted at runtime. The gated party
//!   does not get to redraw its own boundary.
//! * The manifest is **integrity-hashed at load** and the hash is logged
//!   ([`LoadedManifest::integrity_sha256`]). The hash is a tamper-detection aid,
//!   not the security boundary; file ownership and permissions are.
//!
//! The format is JSON. Parsing a security-critical config file with a
//! well-audited parser (serde_json) is safer than hand-rolling one.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

// Bounds on a parsed manifest. The manifest is operator-authoritative, so these
// are not an attack surface today; they bound the blast radius of a malformed or
// accidentally-huge file (memory, log spam) and make the limits explicit before
// the spawn path in later slices consumes these fields.
const MAX_MANIFEST_BYTES: usize = 1 << 20; // 1 MiB
const MAX_SERVERS: usize = 256;
const MAX_TOOLS_PER_SERVER: usize = 1024;
const MAX_ENV_PER_SERVER: usize = 256;
const MAX_ARGS: usize = 256;
const MAX_ID_LEN: usize = 128;
const MAX_NAME_LEN: usize = 128; // tool names
const MAX_COMMAND_LEN: usize = 4096;
const MAX_VALUE_LEN: usize = 8192; // args, env values
const MAX_ENV_KEY_LEN: usize = 256;

/// Reject an environment-variable key that is malformed or could influence the
/// dynamic loader of the child process spawned in a later slice.
///
/// The manifest `env` is the *non-secret* child environment. There is no
/// legitimate reason for it to carry loader-injection variables, and accepting
/// them would be a code-injection vector into the child even though the child is
/// first-party. We also reject keys that are not a well-formed env name (empty,
/// or containing `=`, NUL, or whitespace/control characters) since those cannot
/// be passed to `execve` cleanly.
fn validate_env_key(server_id: &str, key: &str) -> Result<(), ManifestError> {
    let invalid = |why: &str| {
        Err(ManifestError::Invalid(format!(
            "server '{server_id}' env key {key:?} {why}"
        )))
    };
    if key.is_empty() {
        return invalid("is empty");
    }
    if key.len() > MAX_ENV_KEY_LEN {
        return invalid("is too long");
    }
    if key
        .bytes()
        .any(|b| b == b'=' || b == 0 || (b as char).is_whitespace() || b.is_ascii_control())
    {
        return invalid("contains '=', NUL, whitespace, or a control character");
    }
    // Loader-injection variables (Linux `LD_*`, macOS `DYLD_*`). Matched
    // case-insensitively on the prefix so casing tricks cannot slip through.
    let upper = key.to_ascii_uppercase();
    if upper.starts_with("LD_") || upper.starts_with("DYLD_") {
        return invalid("is a dynamic-loader variable and is not allowed in the manifest");
    }
    Ok(())
}

/// How a single tool is classified. This is the authority that decides whether a
/// tool is exposed by default or only under elevation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolClass {
    /// Safe to expose by default. Read-only.
    Read,
    /// Gated: exposed only while a server is elevated.
    Write,
    /// Gated like [`ToolClass::Write`], and additionally requires a fresh
    /// per-action presence confirmation at call time, even during an active
    /// elevation window (e.g. send/delete). The call-time gate is enforced in
    /// Slice 5; classification records the requirement now.
    Confirm,
}

impl ToolClass {
    /// Whether this class is exposed without elevation.
    pub fn is_read(self) -> bool {
        matches!(self, ToolClass::Read)
    }

    /// Whether exposure of this tool requires an active elevation.
    pub fn requires_elevation(self) -> bool {
        !self.is_read()
    }

    /// Whether each call requires a fresh presence confirmation even while
    /// elevated.
    pub fn requires_per_action_presence(self) -> bool {
        matches!(self, ToolClass::Confirm)
    }
}

/// One supervised server, as declared in the manifest.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerManifest {
    /// Stable identifier for the server (unique within the manifest).
    pub id: String,
    /// Executable to spawn (used by the aggregator in Slice 3).
    pub command: String,
    /// Arguments passed to the executable.
    #[serde(default)]
    pub args: Vec<String>,
    /// Non-secret environment for the child. **Never put secrets here**: scoped
    /// credentials are delivered via the platform key store at spawn time (see
    /// `crate::exec` / `crate::platform::SecureKeyStore`), not stored in the
    /// manifest.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Operator-authoritative tool classification, keyed by tool name. A tool a
    /// running child advertises that is absent from this map is treated as
    /// [`ToolClass::Write`] (default-deny) by the classifier.
    #[serde(default)]
    pub tools: BTreeMap<String, ToolClass>,
}

/// The whole manifest.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// The supervised servers.
    #[serde(default)]
    pub servers: Vec<ServerManifest>,
}

impl Manifest {
    /// Validate structural invariants the type system does not capture.
    fn validate(&self) -> Result<(), ManifestError> {
        if self.servers.len() > MAX_SERVERS {
            return Err(ManifestError::Invalid(format!(
                "too many servers (max {MAX_SERVERS})"
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for server in &self.servers {
            if server.id.trim().is_empty() {
                return Err(ManifestError::Invalid(
                    "a server has an empty id".to_string(),
                ));
            }
            if server.id.len() > MAX_ID_LEN {
                return Err(ManifestError::Invalid(format!(
                    "server id {:?} is too long (max {MAX_ID_LEN})",
                    server.id
                )));
            }
            if server.command.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "server '{}' has an empty command",
                    server.id
                )));
            }
            if server.command.len() > MAX_COMMAND_LEN {
                return Err(ManifestError::Invalid(format!(
                    "server '{}' command is too long (max {MAX_COMMAND_LEN})",
                    server.id
                )));
            }
            if server.args.len() > MAX_ARGS {
                return Err(ManifestError::Invalid(format!(
                    "server '{}' has too many args (max {MAX_ARGS})",
                    server.id
                )));
            }
            if server.args.iter().any(|a| a.len() > MAX_VALUE_LEN) {
                return Err(ManifestError::Invalid(format!(
                    "server '{}' has an arg that is too long (max {MAX_VALUE_LEN})",
                    server.id
                )));
            }
            if server.tools.len() > MAX_TOOLS_PER_SERVER {
                return Err(ManifestError::Invalid(format!(
                    "server '{}' declares too many tools (max {MAX_TOOLS_PER_SERVER})",
                    server.id
                )));
            }
            if server.tools.keys().any(|t| t.len() > MAX_NAME_LEN) {
                return Err(ManifestError::Invalid(format!(
                    "server '{}' has a tool name that is too long (max {MAX_NAME_LEN})",
                    server.id
                )));
            }
            if server.env.len() > MAX_ENV_PER_SERVER {
                return Err(ManifestError::Invalid(format!(
                    "server '{}' declares too many env vars (max {MAX_ENV_PER_SERVER})",
                    server.id
                )));
            }
            for (key, value) in &server.env {
                validate_env_key(&server.id, key)?;
                if value.len() > MAX_VALUE_LEN {
                    return Err(ManifestError::Invalid(format!(
                        "server '{}' env value for {key:?} is too long (max {MAX_VALUE_LEN})",
                        server.id
                    )));
                }
            }
            if !seen.insert(&server.id) {
                return Err(ManifestError::Invalid(format!(
                    "duplicate server id: {}",
                    server.id
                )));
            }
        }
        Ok(())
    }

    /// Look up a server by id.
    pub fn server(&self, id: &str) -> Option<&ServerManifest> {
        self.servers.iter().find(|s| s.id == id)
    }
}

/// A manifest together with the integrity hash of the exact bytes it was loaded
/// from.
#[derive(Debug, Clone)]
pub struct LoadedManifest {
    /// The parsed, validated manifest.
    pub manifest: Manifest,
    /// Lowercase hex SHA-256 of the raw manifest bytes. Log this so an
    /// unexpected change between runs is visible.
    pub integrity_sha256: String,
}

/// Why a manifest could not be loaded.
#[derive(Debug)]
pub enum ManifestError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The bytes were not valid JSON for the manifest schema.
    Parse(String),
    /// The manifest parsed but violated a structural invariant.
    Invalid(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::Io(e) => write!(f, "could not read manifest: {e}"),
            ManifestError::Parse(e) => write!(f, "could not parse manifest: {e}"),
            ManifestError::Invalid(e) => write!(f, "invalid manifest: {e}"),
        }
    }
}

impl std::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ManifestError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Load and validate a manifest from raw bytes, computing its integrity hash.
///
/// The hash is computed over the exact bytes provided, before parsing, so it
/// reflects what is on disk byte-for-byte.
pub fn load_from_bytes(bytes: &[u8]) -> Result<LoadedManifest, ManifestError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::Invalid(format!(
            "manifest is too large ({} bytes, max {MAX_MANIFEST_BYTES})",
            bytes.len()
        )));
    }
    let integrity_sha256 = sha256_hex(bytes);
    let manifest: Manifest =
        serde_json::from_slice(bytes).map_err(|e| ManifestError::Parse(e.to_string()))?;
    manifest.validate()?;
    Ok(LoadedManifest {
        manifest,
        integrity_sha256,
    })
}

/// Load and validate a manifest from a file path.
pub fn load_from_path(path: &Path) -> Result<LoadedManifest, ManifestError> {
    let bytes = std::fs::read(path).map_err(ManifestError::Io)?;
    load_from_bytes(&bytes)
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Propose a classification from a server's self-declared `readOnlyHint`.
///
/// This is ONLY a registration-time convenience to prefill a *proposed* manifest
/// entry for the operator to confirm. It is never consulted at runtime, and it
/// fails safe: anything not explicitly hinted read-only is proposed as
/// [`ToolClass::Write`] (the gated side).
pub fn propose_from_hint(read_only_hint: Option<bool>) -> ToolClass {
    match read_only_hint {
        Some(true) => ToolClass::Read,
        _ => ToolClass::Write,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "servers": [
            {
                "id": "mail",
                "command": "mcp-lock-mail",
                "tools": {
                    "search": "read",
                    "list_messages": "read",
                    "fetch_message": "read",
                    "send_message": "confirm"
                }
            }
        ]
    }"#;

    #[test]
    fn loads_and_classifies_from_manifest() {
        let loaded = load_from_bytes(SAMPLE.as_bytes()).unwrap();
        let server = loaded.manifest.server("mail").unwrap();
        assert_eq!(server.tools["search"], ToolClass::Read);
        assert_eq!(server.tools["send_message"], ToolClass::Confirm);
        assert!(server.tools["send_message"].requires_per_action_presence());
    }

    #[test]
    fn integrity_hash_is_stable_and_sensitive() {
        let a = load_from_bytes(SAMPLE.as_bytes()).unwrap();
        let b = load_from_bytes(SAMPLE.as_bytes()).unwrap();
        assert_eq!(a.integrity_sha256, b.integrity_sha256);
        assert_eq!(a.integrity_sha256.len(), 64);
        // A single-byte change changes the hash.
        let mutated = SAMPLE.replacen("read", "write", 1);
        let c = load_from_bytes(mutated.as_bytes()).unwrap();
        assert_ne!(a.integrity_sha256, c.integrity_sha256);
    }

    #[test]
    fn known_sha256_vector() {
        // "abc" -> standard SHA-256 test vector.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rejects_duplicate_ids() {
        let dup = r#"{"servers":[
            {"id":"x","command":"a"},
            {"id":"x","command":"b"}
        ]}"#;
        assert!(matches!(
            load_from_bytes(dup.as_bytes()),
            Err(ManifestError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_empty_command() {
        let bad = r#"{"servers":[{"id":"x","command":""}]}"#;
        assert!(matches!(
            load_from_bytes(bad.as_bytes()),
            Err(ManifestError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_unknown_tool_class() {
        let bad = r#"{"servers":[{"id":"x","command":"a","tools":{"t":"superuser"}}]}"#;
        assert!(matches!(
            load_from_bytes(bad.as_bytes()),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn rejects_unknown_fields() {
        // deny_unknown_fields guards against a typo silently disabling a control.
        let bad = r#"{"servers":[{"id":"x","command":"a","toolz":{}}]}"#;
        assert!(matches!(
            load_from_bytes(bad.as_bytes()),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn empty_manifest_is_valid() {
        let loaded = load_from_bytes(b"{}").unwrap();
        assert!(loaded.manifest.servers.is_empty());
    }

    #[test]
    fn rejects_loader_injection_env_keys() {
        for key in ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "dyld_library_path"] {
            let bad =
                format!(r#"{{"servers":[{{"id":"x","command":"a","env":{{"{key}":"/evil"}}}}]}}"#);
            assert!(
                matches!(
                    load_from_bytes(bad.as_bytes()),
                    Err(ManifestError::Invalid(_))
                ),
                "expected {key} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_malformed_env_keys() {
        for key in ["", "HAS=EQUALS", "HAS SPACE"] {
            let bad =
                format!(r#"{{"servers":[{{"id":"x","command":"a","env":{{"{key}":"v"}}}}]}}"#);
            assert!(
                matches!(
                    load_from_bytes(bad.as_bytes()),
                    Err(ManifestError::Invalid(_))
                ),
                "expected key {key:?} to be rejected"
            );
        }
    }

    #[test]
    fn accepts_normal_env_keys() {
        let ok = r#"{"servers":[{"id":"x","command":"a","env":{"IMAP_HOST":"mail.example.com","RUST_LOG":"info"}}]}"#;
        assert!(load_from_bytes(ok.as_bytes()).is_ok());
    }

    #[test]
    fn rejects_overlong_id() {
        let long_id = "x".repeat(MAX_ID_LEN + 1);
        let bad = format!(r#"{{"servers":[{{"id":"{long_id}","command":"a"}}]}}"#);
        assert!(matches!(
            load_from_bytes(bad.as_bytes()),
            Err(ManifestError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_oversized_manifest() {
        // A blob larger than the cap is rejected before parsing.
        let huge = vec![b' '; MAX_MANIFEST_BYTES + 1];
        assert!(matches!(
            load_from_bytes(&huge),
            Err(ManifestError::Invalid(_))
        ));
    }

    #[test]
    fn hint_prefill_fails_safe() {
        assert_eq!(propose_from_hint(Some(true)), ToolClass::Read);
        assert_eq!(propose_from_hint(Some(false)), ToolClass::Write);
        assert_eq!(propose_from_hint(None), ToolClass::Write);
    }
}
