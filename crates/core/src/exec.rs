//! The execution-context seam for spawning child MCP servers.
//!
//! Per `docs/DESIGN.md` ("Sandboxing seam"), the child-spawning path MUST
//! accept an injectable execution context describing the identity, sandbox
//! profile, and scoped credentials a child runs with. In v1 the broker always
//! constructs [`ExecutionContext::first_party`]: broker identity, no sandbox,
//! and the specific credentials that child is entitled to. In v2, per-child
//! isolation and per-child scoped credentials slot in *here* — by handing the
//! spawn path a different context — without the spawn path itself changing.
//!
//! Nothing in this module spawns a process; it only describes *how* one should
//! be spawned. The actual spawn/supervision lives behind
//! [`crate::platform::ProcessSupervisor`] and arrives in a later slice.

/// Which OS identity a child server runs as.
///
/// v1 has exactly one variant. It exists as an enum so that v2 can add
/// per-child identities (each child its own restricted account) additively.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcessIdentity {
    /// The broker's own dedicated service account (the `mcp-lock` account).
    /// This is the only identity v1 uses.
    BrokerServiceAccount,
}

/// The sandbox applied to a child server.
///
/// v1 applies no sandbox (first-party, trusted servers only — see
/// `SECURITY.md`). The enum is the v2 seam: macOS Seatbelt, Linux
/// namespaces/seccomp, and Windows AppContainer profiles attach here.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SandboxProfile {
    /// No sandbox. The child runs with the broker's identity and reach.
    /// Valid in v1 *only* because v1 runs first-party servers exclusively.
    None,
}

/// A single credential a child is entitled to, named by its logical handle in
/// the [`crate::platform::SecureKeyStore`].
///
/// Credentials are scoped per child: the mail server is granted the IMAP
/// password and nothing else. This type carries only the *name* of a secret,
/// never the secret material — resolution happens through the key store at
/// spawn time so secrets are never pooled where any child could reach them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialGrant {
    /// Logical name of the secret in the key store (e.g. `"mail.imap_password"`).
    pub key_name: String,
    /// Environment variable the child expects the secret to be delivered in
    /// (e.g. `"IMAP_PASSWORD"`). The spawn path reads `key_name` from the key
    /// store and injects it as this variable into the child only.
    pub env_var: String,
}

/// The full context a child MCP server is spawned with.
///
/// This is the single argument that future per-child isolation hangs off. The
/// spawn path takes `&ExecutionContext`; changing isolation means changing the
/// context passed in, not the spawn path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionContext {
    /// The OS identity the child runs as.
    pub identity: ProcessIdentity,
    /// The sandbox profile applied to the child.
    pub sandbox: SandboxProfile,
    /// The credentials this child — and only this child — is granted.
    pub scoped_credentials: Vec<CredentialGrant>,
}

impl ExecutionContext {
    /// The v1 execution context: first-party server, broker identity, no
    /// sandbox, granted exactly the listed credentials.
    ///
    /// `scoped_credentials` is explicit (not defaulted to empty) so that every
    /// caller has to state, at the spawn site, precisely which secrets a child
    /// receives. A child that needs nothing passes an empty vec deliberately.
    pub fn first_party(scoped_credentials: Vec<CredentialGrant>) -> Self {
        ExecutionContext {
            identity: ProcessIdentity::BrokerServiceAccount,
            sandbox: SandboxProfile::None,
            scoped_credentials,
        }
    }

    /// Whether this context applies any sandbox. Always `false` in v1; present
    /// so callers and tests can assert the v1 invariant explicitly.
    pub fn is_sandboxed(&self) -> bool {
        !matches!(self.sandbox, SandboxProfile::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_party_is_broker_identity_and_unsandboxed() {
        let ctx = ExecutionContext::first_party(Vec::new());
        assert_eq!(ctx.identity, ProcessIdentity::BrokerServiceAccount);
        assert!(!ctx.is_sandboxed());
        assert!(ctx.scoped_credentials.is_empty());
    }

    #[test]
    fn credentials_are_scoped_to_the_child_that_is_granted_them() {
        let ctx = ExecutionContext::first_party(vec![CredentialGrant {
            key_name: "mail.imap_password".to_string(),
            env_var: "IMAP_PASSWORD".to_string(),
        }]);
        assert_eq!(ctx.scoped_credentials.len(), 1);
        assert_eq!(ctx.scoped_credentials[0].env_var, "IMAP_PASSWORD");
    }
}
