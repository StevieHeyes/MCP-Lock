//! Error type for the platform-abstraction layer.
//!
//! Deliberately hand-written rather than derived via a macro crate: the
//! security core is kept dependency-light so it can be audited on day one. This
//! is a small, closed enum; a derive dependency would not earn its place here.

use std::error::Error;
use std::fmt;

/// An error from a platform-abstraction operation (presence, key store, peer
/// identity, supervision, isolation).
///
/// The variants are intentionally coarse. The point in Slice 0 is that callers
/// can already program against a stable error surface; richer, security-core
/// error detail arrives with the slices that implement each provider.
#[derive(Debug)]
#[non_exhaustive]
pub enum PlatformError {
    /// The requested capability is not implemented on this platform/build.
    ///
    /// In v1 the macOS providers are stubs that return this until their slice
    /// lands. It is a fail-closed default: an unimplemented provider denies,
    /// it never silently succeeds.
    Unsupported {
        /// Human-readable name of the capability that is unavailable.
        capability: &'static str,
    },
    /// The operator (or platform) declined or failed a presence check.
    PresenceDenied,
    /// A key or secret was requested that the key store does not hold.
    KeyNotFound {
        /// Logical name of the missing key/secret. Never the secret itself.
        name: String,
    },
    /// The peer on a control-channel connection could not be verified as a
    /// registered, trusted identity.
    PeerRejected,
    /// An underlying OS operation failed.
    Os {
        /// What was being attempted when the OS call failed.
        context: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformError::Unsupported { capability } => {
                write!(f, "capability not supported on this platform: {capability}")
            }
            PlatformError::PresenceDenied => write!(f, "presence check denied or failed"),
            PlatformError::KeyNotFound { name } => write!(f, "key not found: {name}"),
            PlatformError::PeerRejected => write!(f, "peer identity rejected"),
            PlatformError::Os { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl Error for PlatformError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PlatformError::Os { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl PlatformError {
    /// Convenience constructor for the "not implemented yet on this platform"
    /// case used by the v1 stubs.
    pub fn unsupported(capability: &'static str) -> Self {
        PlatformError::Unsupported { capability }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_names_the_capability() {
        let err = PlatformError::unsupported("presence");
        assert!(err.to_string().contains("presence"));
    }

    #[test]
    fn os_error_exposes_its_source() {
        let err = PlatformError::Os {
            context: "spawn child",
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "boom"),
        };
        assert!(err.source().is_some());
    }
}
