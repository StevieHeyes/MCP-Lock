//! Presence-gated, time-boxed write elevation: the cryptographic core.
//!
//! Flow (from `docs/DESIGN.md`):
//! 1. A client requests elevation (or a per-action confirm) for a server.
//! 2. The broker issues a fresh, single-use [`Nonce`] bound to that request.
//! 3. Presence (Touch ID / passcode) unlocks the client's signing key, which
//!    signs the canonical [`challenge_message`] over (nonce, client, purpose).
//! 4. The broker verifies the signature against the client's *registered* public
//!    key ([`ClientRegistry`]), checks the nonce is fresh and unused, and only
//!    then yields a verified result.
//!
//! Security properties this module enforces (all unit-tested):
//! * **No replay.** A nonce is consumed on the first verification attempt
//!   (success *or* failure), so a captured signature cannot be reused, and a
//!   fixed nonce cannot be brute-forced.
//! * **Binding.** The signature covers the nonce, the client id, the server id,
//!   and the purpose (elevate vs confirm-a-specific-tool), so a signature for one
//!   request cannot authorise another.
//! * **Freshness.** Unused nonces expire quickly ([`NONCE_TTL_SECS`]).
//! * **Ship closed.** An empty [`ClientRegistry`] can verify nothing, so a fresh
//!   install grants no elevation until a client key is registered.
//!
//! The broker only ever *verifies* (`verify_strict`, which rejects malleable
//! signatures). Signing happens on the client with a presence-unlocked key; in
//! v1 that key lives behind the [`crate::platform::SecureKeyStore`] /
//! [`crate::platform::PresenceProvider`] seams (real Keychain wiring is a
//! documented follow-up). Tests here use an in-process Ed25519 signer.

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey, SIGNATURE_LENGTH};
use serde::Serialize;

use crate::policy::{Elevation, Timestamp};

/// Length of an elevation nonce, in bytes.
pub const NONCE_LEN: usize = 32;
/// How long an issued-but-unused nonce remains valid (seconds). Short, because
/// the client signs and returns it immediately.
pub const NONCE_TTL_SECS: u64 = 60;
/// Length of an Ed25519 public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// A fresh, single-use challenge nonce. Not secret (it is sent to the client as a
/// challenge); its security comes from being random, single-use, and short-lived.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Generate a cryptographically random nonce.
    pub fn generate() -> Result<Nonce, ElevationError> {
        let mut bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut bytes).map_err(|_| ElevationError::Rng)?;
        Ok(Nonce(bytes))
    }

    /// Lowercase hex encoding (how the nonce travels on the wire).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(NONCE_LEN * 2);
        for b in &self.0 {
            use fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Parse a hex-encoded nonce.
    pub fn from_hex(s: &str) -> Option<Nonce> {
        if s.len() != NONCE_LEN * 2 {
            return None;
        }
        let mut bytes = [0u8; NONCE_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(Nonce(bytes))
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", self.to_hex())
    }
}

/// What a challenge authorises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    /// Grant write elevation on a server for a window.
    Elevate {
        /// Server to elevate.
        server_id: String,
        /// Time-boxed or until-revoked.
        mode: RequestedMode,
    },
    /// Confirm a single destructive (`confirm`-classified) tool action, even
    /// mid-elevation.
    Confirm {
        /// Server the tool belongs to.
        server_id: String,
        /// The specific tool being confirmed.
        tool: String,
    },
}

/// The elevation window a client requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedMode {
    /// Auto-revoke after `ttl_secs`.
    Duration {
        /// Window length in seconds.
        ttl_secs: u64,
    },
    /// Stay active until explicitly revoked (opt-in; never survives a restart).
    UntilRevoked,
}

/// The result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// A write elevation to apply to the server.
    Elevation {
        /// Server to elevate.
        server_id: String,
        /// The elevation (carrying its own expiry).
        elevation: Elevation,
    },
    /// A confirmed per-action presence for one tool.
    Confirm {
        /// Server the tool belongs to.
        server_id: String,
        /// The confirmed tool.
        tool: String,
    },
}

/// Why an elevation step failed. Deliberately coarse where leaking detail would
/// help an attacker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationError {
    /// The OS RNG failed.
    Rng,
    /// The nonce is unknown, already used, or for a different client.
    UnknownOrUsedNonce,
    /// The nonce expired before it was used.
    NonceExpired,
    /// No registered key for this client.
    UnknownClient,
    /// A key or signature was malformed (wrong length / not a valid point).
    Malformed,
    /// The signature did not verify against the registered key.
    BadSignature,
}

impl fmt::Display for ElevationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ElevationError::Rng => "random number generation failed",
            ElevationError::UnknownOrUsedNonce => "unknown or already-used nonce",
            ElevationError::NonceExpired => "nonce expired",
            ElevationError::UnknownClient => "unknown client",
            ElevationError::Malformed => "malformed key or signature",
            ElevationError::BadSignature => "signature verification failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ElevationError {}

/// Canonical, deterministic bytes a client signs for a challenge.
///
/// JSON of a fixed-field-order struct: both signer and verifier call this exact
/// function, and JSON escaping removes any delimiter-injection ambiguity in the
/// identifiers.
pub fn challenge_message(nonce: &Nonce, client_id: &str, purpose: &Purpose) -> Vec<u8> {
    #[derive(Serialize)]
    struct Doc<'a> {
        v: u8,
        purpose: &'a str,
        client: &'a str,
        nonce: String,
        server: &'a str,
        tool: Option<&'a str>,
        mode: Option<&'a str>,
        ttl: Option<u64>,
    }
    let doc = match purpose {
        Purpose::Elevate { server_id, mode } => {
            let (mode_s, ttl) = match mode {
                RequestedMode::Duration { ttl_secs } => ("duration", Some(*ttl_secs)),
                RequestedMode::UntilRevoked => ("until_revoked", None),
            };
            Doc {
                v: 1,
                purpose: "elevate",
                client: client_id,
                nonce: nonce.to_hex(),
                server: server_id,
                tool: None,
                mode: Some(mode_s),
                ttl,
            }
        }
        Purpose::Confirm { server_id, tool } => Doc {
            v: 1,
            purpose: "confirm",
            client: client_id,
            nonce: nonce.to_hex(),
            server: server_id,
            tool: Some(tool),
            mode: None,
            ttl: None,
        },
    };
    // Serializing our own fixed struct cannot fail.
    serde_json::to_vec(&doc).unwrap_or_default()
}

/// The set of registered, trusted client signing identities.
///
/// Per-deployment configuration, populated on first run (DESIGN: never hardwired
/// to one identity). Empty means "no one can elevate" — the ship-closed default.
#[derive(Default)]
pub struct ClientRegistry {
    keys: BTreeMap<String, VerifyingKey>,
}

impl fmt::Debug for ClientRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRegistry")
            .field("clients", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ClientRegistry {
    /// An empty registry. No client can elevate until one is registered.
    pub fn new() -> Self {
        ClientRegistry::default()
    }

    /// Register `client_id` with its Ed25519 public key. Rejects a malformed key.
    pub fn register(
        &mut self,
        client_id: impl Into<String>,
        public_key: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(), ElevationError> {
        let key = VerifyingKey::from_bytes(public_key).map_err(|_| ElevationError::Malformed)?;
        self.keys.insert(client_id.into(), key);
        Ok(())
    }

    /// Whether any client is registered.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn key(&self, client_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(client_id)
    }
}

/// A pending challenge awaiting a signature.
struct Pending {
    nonce: Nonce,
    client_id: String,
    purpose: Purpose,
    issued_at: Timestamp,
}

/// Issues nonces and verifies the signed assertions that consume them.
///
/// Single-use is enforced by removing the pending entry on the first
/// verification attempt, before checking the signature.
#[derive(Default)]
pub struct NonceStore {
    pending: Vec<Pending>,
}

impl fmt::Debug for NonceStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonceStore")
            .field("pending", &self.pending.len())
            .finish()
    }
}

impl NonceStore {
    /// An empty store.
    pub fn new() -> Self {
        NonceStore::default()
    }

    /// Issue a fresh nonce bound to `purpose` for `client_id`.
    pub fn issue(
        &mut self,
        client_id: impl Into<String>,
        purpose: Purpose,
        now: Timestamp,
    ) -> Result<Nonce, ElevationError> {
        self.prune(now);
        let nonce = Nonce::generate()?;
        self.pending.push(Pending {
            nonce,
            client_id: client_id.into(),
            purpose,
            issued_at: now,
        });
        Ok(nonce)
    }

    /// Verify a signed assertion and consume its nonce.
    ///
    /// The nonce is removed up front, so any outcome (including a bad signature)
    /// consumes it — no replay, no brute force against a fixed nonce.
    pub fn verify_and_consume(
        &mut self,
        client_id: &str,
        nonce: &Nonce,
        signature: &[u8],
        registry: &ClientRegistry,
        now: Timestamp,
    ) -> Result<Verified, ElevationError> {
        // Take the pending entry out immediately (single-use), matching nonce and
        // client.
        let position = self
            .pending
            .iter()
            .position(|p| &p.nonce == nonce && p.client_id == client_id);
        let pending = match position {
            Some(i) => self.pending.swap_remove(i),
            None => return Err(ElevationError::UnknownOrUsedNonce),
        };

        if now.saturating_sub(pending.issued_at) > NONCE_TTL_SECS {
            return Err(ElevationError::NonceExpired);
        }

        let key = registry
            .key(client_id)
            .ok_or(ElevationError::UnknownClient)?;
        let sig_bytes: [u8; SIGNATURE_LENGTH] = signature
            .try_into()
            .map_err(|_| ElevationError::Malformed)?;
        let signature = Signature::from_bytes(&sig_bytes);
        let message = challenge_message(nonce, client_id, &pending.purpose);
        key.verify_strict(&message, &signature)
            .map_err(|_| ElevationError::BadSignature)?;

        Ok(match pending.purpose {
            Purpose::Elevate { server_id, mode } => {
                let elevation = match mode {
                    RequestedMode::Duration { ttl_secs } => Elevation::for_duration(now, ttl_secs),
                    RequestedMode::UntilRevoked => Elevation::until_revoked(now),
                };
                Verified::Elevation {
                    server_id,
                    elevation,
                }
            }
            Purpose::Confirm { server_id, tool } => Verified::Confirm { server_id, tool },
        })
    }

    /// Drop expired pending nonces.
    fn prune(&mut self, now: Timestamp) {
        self.pending
            .retain(|p| now.saturating_sub(p.issued_at) <= NONCE_TTL_SECS);
    }

    /// Number of outstanding pending nonces (for tests/diagnostics).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// An in-process stand-in for the presence-unlocked client signing key.
    struct TestSigner {
        key: SigningKey,
    }
    impl TestSigner {
        fn new(seed: u8) -> Self {
            TestSigner {
                key: SigningKey::from_bytes(&[seed; 32]),
            }
        }
        fn public(&self) -> [u8; 32] {
            self.key.verifying_key().to_bytes()
        }
        fn sign(&self, nonce: &Nonce, client_id: &str, purpose: &Purpose) -> Vec<u8> {
            let message = challenge_message(nonce, client_id, purpose);
            self.key.sign(&message).to_bytes().to_vec()
        }
    }

    fn setup() -> (NonceStore, ClientRegistry, TestSigner) {
        let signer = TestSigner::new(7);
        let mut registry = ClientRegistry::new();
        registry.register("client-1", &signer.public()).unwrap();
        (NonceStore::new(), registry, signer)
    }

    fn elevate_purpose() -> Purpose {
        Purpose::Elevate {
            server_id: "mail".to_string(),
            mode: RequestedMode::Duration { ttl_secs: 300 },
        }
    }

    #[test]
    fn happy_path_yields_a_time_boxed_elevation() {
        let (mut store, registry, signer) = setup();
        let nonce = store.issue("client-1", elevate_purpose(), 100).unwrap();
        let sig = signer.sign(&nonce, "client-1", &elevate_purpose());
        let verified = store
            .verify_and_consume("client-1", &nonce, &sig, &registry, 110)
            .unwrap();
        match verified {
            Verified::Elevation {
                server_id,
                elevation,
            } => {
                assert_eq!(server_id, "mail");
                assert!(elevation.is_active(110));
                assert!(!elevation.is_active(410)); // expired after ttl
            }
            other => panic!("expected elevation, got {other:?}"),
        }
        assert_eq!(store.pending_count(), 0, "nonce consumed");
    }

    #[test]
    fn a_nonce_cannot_be_replayed() {
        let (mut store, registry, signer) = setup();
        let nonce = store.issue("client-1", elevate_purpose(), 0).unwrap();
        let sig = signer.sign(&nonce, "client-1", &elevate_purpose());
        assert!(store
            .verify_and_consume("client-1", &nonce, &sig, &registry, 1)
            .is_ok());
        // Second use of the same nonce+signature fails.
        assert_eq!(
            store.verify_and_consume("client-1", &nonce, &sig, &registry, 1),
            Err(ElevationError::UnknownOrUsedNonce)
        );
    }

    #[test]
    fn a_bad_signature_still_consumes_the_nonce() {
        let (mut store, registry, _signer) = setup();
        let nonce = store.issue("client-1", elevate_purpose(), 0).unwrap();
        let bad = [0u8; SIGNATURE_LENGTH];
        assert_eq!(
            store.verify_and_consume("client-1", &nonce, &bad, &registry, 1),
            Err(ElevationError::BadSignature)
        );
        // The nonce is gone, so even a correct signature now fails.
        assert_eq!(store.pending_count(), 0);
    }

    #[test]
    fn a_signature_for_one_server_does_not_authorise_another() {
        let (mut store, registry, signer) = setup();
        let nonce = store.issue("client-1", elevate_purpose(), 0).unwrap();
        // Sign a DIFFERENT purpose (another server) with the same nonce.
        let other = Purpose::Elevate {
            server_id: "files".to_string(),
            mode: RequestedMode::Duration { ttl_secs: 300 },
        };
        let sig = signer.sign(&nonce, "client-1", &other);
        assert_eq!(
            store.verify_and_consume("client-1", &nonce, &sig, &registry, 1),
            Err(ElevationError::BadSignature)
        );
    }

    #[test]
    fn an_expired_nonce_is_rejected() {
        let (mut store, registry, signer) = setup();
        let nonce = store.issue("client-1", elevate_purpose(), 0).unwrap();
        let sig = signer.sign(&nonce, "client-1", &elevate_purpose());
        let too_late = NONCE_TTL_SECS + 1;
        assert_eq!(
            store.verify_and_consume("client-1", &nonce, &sig, &registry, too_late),
            Err(ElevationError::NonceExpired)
        );
    }

    #[test]
    fn an_unregistered_client_cannot_elevate() {
        let (mut store, _registry, signer) = setup();
        let empty = ClientRegistry::new();
        assert!(empty.is_empty());
        let nonce = store.issue("client-1", elevate_purpose(), 0).unwrap();
        let sig = signer.sign(&nonce, "client-1", &elevate_purpose());
        assert_eq!(
            store.verify_and_consume("client-1", &nonce, &sig, &empty, 1),
            Err(ElevationError::UnknownClient)
        );
    }

    #[test]
    fn a_signature_from_the_wrong_key_is_rejected() {
        let (mut store, registry, _signer) = setup();
        let attacker = TestSigner::new(99); // not registered
        let nonce = store.issue("client-1", elevate_purpose(), 0).unwrap();
        let sig = attacker.sign(&nonce, "client-1", &elevate_purpose());
        assert_eq!(
            store.verify_and_consume("client-1", &nonce, &sig, &registry, 1),
            Err(ElevationError::BadSignature)
        );
    }

    #[test]
    fn confirm_purpose_round_trips_and_binds_the_tool() {
        let (mut store, registry, signer) = setup();
        let purpose = Purpose::Confirm {
            server_id: "mail".to_string(),
            tool: "send_message".to_string(),
        };
        let nonce = store.issue("client-1", purpose.clone(), 0).unwrap();
        let sig = signer.sign(&nonce, "client-1", &purpose);
        let verified = store
            .verify_and_consume("client-1", &nonce, &sig, &registry, 1)
            .unwrap();
        assert_eq!(
            verified,
            Verified::Confirm {
                server_id: "mail".to_string(),
                tool: "send_message".to_string()
            }
        );
    }

    #[test]
    fn nonce_hex_round_trips() {
        let n = Nonce::generate().unwrap();
        assert_eq!(Nonce::from_hex(&n.to_hex()), Some(n));
        assert_eq!(Nonce::from_hex("zz"), None);
    }
}
