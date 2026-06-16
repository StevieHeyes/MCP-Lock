//! The mail domain types and the read-only [`MailStore`] trait.
//!
//! The trait is the seam between the MCP tool layer (which is fully tested) and
//! a backend (the real IMAP client, or the in-memory [`crate::fake`] fixture).
//!
//! **Read-only by construction.** This trait exposes only retrieval operations:
//! there is no method to send, move, flag, or delete a message. That is the
//! whole point of the server — it is the first concrete read-only server in the
//! MCP-Lock design. The IMAP backend additionally opens mailboxes with `EXAMINE`
//! (read-only), so even the protocol-level session cannot mutate state.

use std::error::Error;
use std::fmt;

/// A short summary of a message, as returned by listing and searching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSummary {
    /// IMAP UID, stable within a mailbox. Used to fetch the full message.
    pub uid: u32,
    /// Decoded `Subject`, or an empty string if absent.
    pub subject: String,
    /// Decoded `From`, or an empty string if absent.
    pub from: String,
    /// `Date` as reported by the server (RFC 5322 form), or empty.
    pub date: String,
    /// Whether the message carries the `\Seen` flag.
    pub seen: bool,
}

/// A full message, as returned by [`MailStore::fetch_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// IMAP UID.
    pub uid: u32,
    /// Decoded `Subject`, or empty.
    pub subject: String,
    /// Decoded `From`, or empty.
    pub from: String,
    /// Decoded `To`, or empty.
    pub to: String,
    /// `Date` as reported by the server, or empty.
    pub date: String,
    /// Best-effort plain-text body. Backends extract a readable text rendering;
    /// they do not execute or interpret message content.
    pub body_text: String,
}

/// Errors a [`MailStore`] operation can return.
#[derive(Debug)]
#[non_exhaustive]
pub enum MailError {
    /// The requested mailbox does not exist or could not be opened read-only.
    MailboxUnavailable {
        /// Name of the mailbox that could not be opened.
        mailbox: String,
    },
    /// No message with the given UID exists in the mailbox.
    MessageNotFound {
        /// The UID that was requested.
        uid: u32,
    },
    /// The search query was not understood by the backend.
    ///
    /// Reserved for future query-validation. The current backends do not
    /// construct it: the IMAP backend sanitises free text into an always-valid
    /// `TEXT "..."` criterion (so the server never rejects it as malformed) and
    /// reports any `SEARCH` failure as a transport-level [`MailError::Backend`],
    /// which cannot be cleanly distinguished from a bad criterion. It is part of
    /// the public, `#[non_exhaustive]` error surface for richer query grammars.
    InvalidQuery {
        /// Human-readable reason. Never contains credentials.
        reason: String,
    },
    /// The backend (network, IMAP server, TLS) failed. The message is safe to
    /// surface; backends must not place credentials in it.
    Backend {
        /// Human-readable description of what failed.
        message: String,
    },
}

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MailError::MailboxUnavailable { mailbox } => {
                write!(f, "mailbox unavailable: {mailbox}")
            }
            MailError::MessageNotFound { uid } => write!(f, "message not found: uid {uid}"),
            MailError::InvalidQuery { reason } => write!(f, "invalid search query: {reason}"),
            MailError::Backend { message } => write!(f, "mail backend error: {message}"),
        }
    }
}

impl Error for MailError {}

/// A read-only view over a mail account.
///
/// Implementors: the real IMAP client ([`crate::imap_backend`]) and the
/// in-memory test fixture ([`crate::fake`]). The MCP tool layer depends only on
/// this trait, so the entire tool surface is exercised in tests against the
/// fixture without any network or credentials.
pub trait MailStore {
    /// List up to `limit` of the most recent messages in `mailbox`, newest
    /// first.
    fn list_messages(&self, mailbox: &str, limit: usize) -> Result<Vec<MessageSummary>, MailError>;

    /// Search `mailbox` and return up to `limit` matching message summaries,
    /// newest first. The query grammar is backend-defined; the IMAP backend maps
    /// it to an IMAP `SEARCH`.
    fn search(
        &self,
        mailbox: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MessageSummary>, MailError>;

    /// Fetch the full message with `uid` from `mailbox`.
    fn fetch_message(&self, mailbox: &str, uid: u32) -> Result<Message, MailError>;
}
