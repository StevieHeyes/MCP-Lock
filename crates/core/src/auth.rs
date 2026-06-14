//! The MCP-endpoint credential-validation seam.
//!
//! Per `docs/DESIGN.md`, the MCP endpoint authenticates the AI client with a
//! bearer token in v1, but validation MUST be a *pluggable seam* so OAuth 2.1 +
//! PKCE can drop in for v2 **without touching the endpoint**. The endpoint
//! depends only on the [`CredentialValidator`] trait and on [`ValidatedClient`];
//! it never compares tokens itself.
//!
//! This is security-core code: plain, synchronous, dependency-free, and small
//! enough to audit in one sitting. Two properties are deliberate:
//!
//! * **Unforgeable proof of validation.** A [`ValidatedClient`] cannot be
//!   constructed outside this module, so a function that receives one *knows* a
//!   validator approved the request — the type is the proof.
//! * **Ship closed.** [`StaticBearerValidator::new`] returns `None` for an empty
//!   token, so a deployment with no configured token cannot accidentally accept
//!   one. There is no baked-in default token.

use std::fmt;

/// Proof that a request presented a credential a [`CredentialValidator`]
/// accepted.
///
/// It carries only the identity the validator assigned, never the secret. It can
/// be constructed only inside this module (the field is private and there is no
/// public constructor), so holding one is itself the proof of validation.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedClient {
    client_id: String,
}

impl ValidatedClient {
    /// The identity the validator assigned to this client.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

// Hand-written so a ValidatedClient never renders anything secret-looking.
impl fmt::Debug for ValidatedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedClient")
            .field("client_id", &self.client_id)
            .finish()
    }
}

/// Why a credential was not accepted. Intentionally coarse: the endpoint should
/// return the same `401` either way and not reveal which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// No credential was presented.
    Missing,
    /// A credential was presented but did not validate.
    Invalid,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Missing => write!(f, "no credential presented"),
            AuthError::Invalid => write!(f, "credential rejected"),
        }
    }
}

impl std::error::Error for AuthError {}

/// The pluggable validation seam for the MCP endpoint's client credential.
///
/// v1 supplies [`StaticBearerValidator`]; v2 supplies an OAuth 2.1 validator.
/// The endpoint is generic over this trait and so is unaffected by the swap.
pub trait CredentialValidator: Send + Sync {
    /// Validate the credential presented by a client (the raw bearer token, if
    /// any). Returns a [`ValidatedClient`] on success.
    fn validate(&self, presented_token: Option<&str>) -> Result<ValidatedClient, AuthError>;
}

/// A v1 validator that accepts a single configured bearer token.
///
/// The token is compared in constant time with respect to its contents. Token
/// *length* is not hidden, which is an accepted, standard trade-off for bearer
/// comparison.
pub struct StaticBearerValidator {
    expected: Vec<u8>,
    client_id: String,
}

// Hand-written so the expected token bytes are never rendered in logs or panics.
impl fmt::Debug for StaticBearerValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticBearerValidator")
            .field("client_id", &self.client_id)
            .field("expected", &"<redacted>")
            .finish()
    }
}

impl StaticBearerValidator {
    /// Create a validator for `token`, assigning accepted requests the identity
    /// `client_id`.
    ///
    /// Returns `None` if `token` is empty: a deployment must configure a real
    /// token, and an empty one would mean "accept the empty string", which is
    /// exactly the ship-closed footgun this guards against.
    pub fn new(token: &str, client_id: impl Into<String>) -> Option<Self> {
        if token.is_empty() {
            return None;
        }
        Some(StaticBearerValidator {
            expected: token.as_bytes().to_vec(),
            client_id: client_id.into(),
        })
    }
}

impl CredentialValidator for StaticBearerValidator {
    fn validate(&self, presented_token: Option<&str>) -> Result<ValidatedClient, AuthError> {
        let presented = presented_token.ok_or(AuthError::Missing)?;
        if presented.is_empty() {
            return Err(AuthError::Missing);
        }
        if constant_time_eq(presented.as_bytes(), &self.expected) {
            Ok(ValidatedClient {
                client_id: self.client_id.clone(),
            })
        } else {
            Err(AuthError::Invalid)
        }
    }
}

/// Constant-time byte-slice equality for equal-length inputs.
///
/// Unequal lengths return early (length is not treated as secret); equal-length
/// inputs are compared without a data-dependent branch or early exit, so the
/// comparison time does not reveal how many leading bytes matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_configured_token() {
        let v = StaticBearerValidator::new("s3cr3t-placeholder", "claude-client").unwrap();
        let client = v.validate(Some("s3cr3t-placeholder")).unwrap();
        assert_eq!(client.client_id(), "claude-client");
    }

    #[test]
    fn rejects_a_wrong_token() {
        let v = StaticBearerValidator::new("s3cr3t-placeholder", "c").unwrap();
        assert_eq!(v.validate(Some("wrong")), Err(AuthError::Invalid));
        assert_eq!(
            v.validate(Some("s3cr3t-placeholde")),
            Err(AuthError::Invalid)
        );
        assert_eq!(
            v.validate(Some("s3cr3t-placeholder-extra")),
            Err(AuthError::Invalid)
        );
    }

    #[test]
    fn rejects_missing_or_empty_credential() {
        let v = StaticBearerValidator::new("s3cr3t-placeholder", "c").unwrap();
        assert_eq!(v.validate(None), Err(AuthError::Missing));
        assert_eq!(v.validate(Some("")), Err(AuthError::Missing));
    }

    #[test]
    fn ships_closed_on_empty_configured_token() {
        // No token configured => no validator => endpoint cannot accept anyone.
        assert!(StaticBearerValidator::new("", "c").is_none());
    }

    #[test]
    fn debug_does_not_leak_the_token() {
        let v = StaticBearerValidator::new("top-secret-placeholder", "c").unwrap();
        let client = v.validate(Some("top-secret-placeholder")).unwrap();
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("top-secret-placeholder"));
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn trait_object_is_usable_as_a_seam() {
        // The endpoint will hold a `Box<dyn CredentialValidator>`; prove it works.
        let v: Box<dyn CredentialValidator> =
            Box::new(StaticBearerValidator::new("tok-placeholder", "c").unwrap());
        assert!(v.validate(Some("tok-placeholder")).is_ok());
        assert!(v.validate(Some("nope")).is_err());
    }
}
