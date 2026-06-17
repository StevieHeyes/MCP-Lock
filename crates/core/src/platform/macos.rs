//! macOS implementations of the platform-abstraction traits.
//!
//! In Slice 0 these are honest stubs: each returns
//! [`PlatformError::Unsupported`] so the system fails closed until the relevant
//! security-reviewed slice implements it. They exist now so the broker and CLI
//! can be wired against concrete types, and so the macOS-only `cfg` boundary is
//! established from the start.
//!
//! Where each will eventually bind:
//! * [`MacosPresenceProvider`] -> LocalAuthentication + Keychain (Slice 5)
//! * [`MacosSecureKeyStore`]   -> Keychain / Secure Enclave (Slice 5)
//! * [`MacosPeerIdentityVerifier`] -> code-signature over UDS (Slice 5)
//! * [`MacosProcessSupervisor`] -> launchd (Slice 3+)
//! * [`MacosProcessIsolator`]  -> Seatbelt (v2)

use crate::error::PlatformError;
use crate::exec::{ExecutionContext, SandboxProfile};
use crate::platform::{
    PeerIdentityVerifier, PresenceAssertion, PresenceProvider, ProcessIsolator, ProcessSupervisor,
    SecureKeyStore,
};

/// macOS presence provider (LocalAuthentication). Stub in Slice 0.
#[derive(Debug, Default, Clone)]
pub struct MacosPresenceProvider;

impl PresenceProvider for MacosPresenceProvider {
    fn assert_presence(
        &self,
        _key_id: &str,
        _challenge: &[u8],
    ) -> Result<PresenceAssertion, PlatformError> {
        Err(PlatformError::unsupported(
            "macos presence (LocalAuthentication)",
        ))
    }
}

/// macOS secure key store (Keychain / Secure Enclave). Stub in Slice 0.
#[derive(Debug, Default, Clone)]
pub struct MacosSecureKeyStore;

impl SecureKeyStore for MacosSecureKeyStore {
    fn get_secret(&self, _name: &str) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::unsupported("macos key store (Keychain)"))
    }
}

/// macOS peer-identity verifier (code signature over UDS). Stub in Slice 0.
#[derive(Debug, Default, Clone)]
pub struct MacosPeerIdentityVerifier;

impl PeerIdentityVerifier for MacosPeerIdentityVerifier {
    fn verify_peer(&self, _connection_fd: std::os::fd::RawFd) -> Result<(), PlatformError> {
        Err(PlatformError::unsupported(
            "macos peer code-signature verification",
        ))
    }
}

/// macOS process supervisor (launchd). Stub in Slice 0.
#[derive(Debug, Default, Clone)]
pub struct MacosProcessSupervisor;

impl ProcessSupervisor for MacosProcessSupervisor {
    fn is_installed(&self) -> Result<bool, PlatformError> {
        Err(PlatformError::unsupported(
            "macos process supervisor (launchd)",
        ))
    }
}

/// macOS process isolator (Seatbelt). v2 seam; no-op for the v1 unsandboxed
/// profile so the v1 spawn path can call it unconditionally.
#[derive(Debug, Default, Clone)]
pub struct MacosProcessIsolator;

impl ProcessIsolator for MacosProcessIsolator {
    fn prepare(&self, ctx: &ExecutionContext) -> Result<(), PlatformError> {
        match ctx.sandbox {
            // v1 runs first-party servers with no sandbox; nothing to prepare.
            SandboxProfile::None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::ExecutionContext;

    #[test]
    fn presence_stub_fails_closed() {
        let p = MacosPresenceProvider;
        assert!(p.assert_presence("client-1", b"challenge").is_err());
    }

    #[test]
    fn key_store_stub_fails_closed() {
        let k = MacosSecureKeyStore;
        assert!(k.get_secret("mail.imap_password").is_err());
    }

    #[test]
    fn peer_verifier_stub_fails_closed() {
        let v = MacosPeerIdentityVerifier;
        assert!(v.verify_peer(-1).is_err());
    }

    #[test]
    fn isolator_is_noop_for_unsandboxed_v1_context() {
        let iso = MacosProcessIsolator;
        let ctx = ExecutionContext::first_party(Vec::new());
        assert!(iso.prepare(&ctx).is_ok());
    }
}
