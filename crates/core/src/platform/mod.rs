//! Platform-abstraction trait seams.
//!
//! `docs/DESIGN.md` requires these defined now, implemented for macOS only in
//! v1, so that Linux and Windows are additive ports rather than rewrites. Each
//! trait documents its intended per-platform implementation. The signed-nonce
//! presence assertion (see [`PresenceProvider`]) is the PRIMARY, portable
//! presence primitive; platform bonuses like macOS peer code-signature
//! verification ([`PeerIdentityVerifier`]) are layers on top, never the sole
//! gate.
//!
//! In Slice 0 every method is a stub returning
//! [`PlatformError::Unsupported`](crate::PlatformError::Unsupported). That is a
//! fail-closed default: an unimplemented provider denies. Real implementations
//! arrive in the security-reviewed slices that need them.

use crate::error::PlatformError;
use crate::exec::ExecutionContext;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{
    MacosPeerIdentityVerifier, MacosPresenceProvider, MacosProcessIsolator, MacosProcessSupervisor,
    MacosSecureKeyStore,
};

/// Proof that a present human authorised a specific request, produced by
/// signing a broker-issued challenge with a presence-unlocked key.
///
/// In Slice 0 this is an opaque byte container. Slice 5 introduces the typed
/// challenge/assertion protocol around it (fresh single-use nonce, bound to
/// server + tools + expiry). The signature here is verified against a
/// registered public key; presence (Touch ID / passcode) is what unlocks the
/// signing key, and is never itself treated as a bearer token.
#[derive(Clone, PartialEq, Eq)]
pub struct PresenceAssertion {
    /// Detached signature over the challenge the broker issued.
    pub signature: Vec<u8>,
    /// Identifier of the signing key, so the broker selects the right
    /// registered public key to verify against.
    pub key_id: String,
}

// Hand-written so the signature bytes are never rendered in logs or panics.
impl std::fmt::Debug for PresenceAssertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresenceAssertion")
            .field("key_id", &self.key_id)
            .field("signature", &"<redacted>")
            .finish()
    }
}

/// Produces a presence-gated [`PresenceAssertion`] by unlocking a per-client
/// signing key and signing a challenge.
///
/// * macOS: LocalAuthentication unlocking a Keychain key gated
///   `.biometryCurrentSet` (Touch ID / passcode).
/// * Linux (future): FIDO2 hardware token / PAM.
/// * Windows (future): Windows Hello.
pub trait PresenceProvider {
    /// Prompt for presence, unlock the signing key identified by `key_id`, and
    /// sign `challenge`. Returns [`PlatformError::PresenceDenied`] if the human
    /// declines or the check fails.
    fn assert_presence(
        &self,
        key_id: &str,
        challenge: &[u8],
    ) -> Result<PresenceAssertion, PlatformError>;
}

/// Stores and uses secret material (scoped child credentials, per-client
/// signing keys) without exposing raw key bytes to the broker process where it
/// can be avoided.
///
/// * macOS: Keychain / Secure Enclave.
/// * Linux (future): Secret Service / TPM.
/// * Windows (future): DPAPI / TPM.
///
/// In Slice 5 the broker wires its presence/elevation path to this trait — and
/// to a test double — *not* to a real Keychain item holding a real secret.
pub trait SecureKeyStore {
    /// Fetch a stored secret by its logical name, for scoped delivery to a
    /// child. Returns [`PlatformError::KeyNotFound`] if absent. The returned
    /// bytes are the caller's responsibility to handle carefully and drop
    /// promptly; a zeroizing wrapper arrives with the real implementation.
    fn get_secret(&self, name: &str) -> Result<Vec<u8>, PlatformError>;
}

/// Verifies the identity of a peer connecting on the local control channel.
///
/// This is a Mac-only *bonus* layer (DESIGN.md): it strengthens local control,
/// but the portable, primary gate is always the signed-nonce assertion.
///
/// * macOS: code-signature verification over the Unix domain socket (reject any
///   peer not matching a registered, signed client identity).
/// * Linux (future): `SO_PEERCRED` uid/pid only — no code identity.
/// * Windows (future): named-pipe SID.
pub trait PeerIdentityVerifier {
    /// Verify the peer behind `connection_fd` is a registered, trusted client.
    /// Returns [`PlatformError::PeerRejected`] otherwise.
    fn verify_peer(&self, connection_fd: std::os::fd::RawFd) -> Result<(), PlatformError>;
}

/// Integrates the broker daemon with the platform service supervisor that keeps
/// it alive (and thus enforces the "restart comes up cold and read-only"
/// invariant).
///
/// * macOS: launchd (KeepAlive).
/// * Linux (future): systemd.
/// * Windows (future): Service Control Manager.
pub trait ProcessSupervisor {
    /// Whether the broker is currently registered with the platform supervisor.
    fn is_installed(&self) -> Result<bool, PlatformError>;
}

/// The v2 sandboxing seam: applies a child's [`SandboxProfile`] when spawning
/// it under a given [`ExecutionContext`].
///
/// v1 only ever spawns with [`SandboxProfile::None`](crate::exec::SandboxProfile::None);
/// this trait exists so v2 per-child isolation slots in without changing the
/// spawn path.
///
/// * macOS (future): Seatbelt.
/// * Linux (future): namespaces / seccomp.
/// * Windows (future): AppContainer.
pub trait ProcessIsolator {
    /// Prepare process-isolation settings for a child described by `ctx`. In v1
    /// this is a no-op for [`SandboxProfile::None`](crate::exec::SandboxProfile::None)
    /// and unsupported otherwise.
    fn prepare(&self, ctx: &ExecutionContext) -> Result<(), PlatformError>;
}
