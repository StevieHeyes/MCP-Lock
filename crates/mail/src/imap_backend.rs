//! The real IMAP-backed [`MailStore`].
//!
//! Read-only by construction:
//! * mailboxes are opened with `EXAMINE` (read-only), never `SELECT`, so the
//!   session cannot set flags or expunge;
//! * fetches use `BODY.PEEK[...]`, which does not set `\Seen`.
//!
//! Each operation opens a fresh TLS connection, logs in, does its work, and logs
//! out. That trades a little latency for simplicity and robustness (no
//! long-lived connection to time out or to share across calls); connection
//! reuse is a possible later optimisation.
//!
//! This backend is exercised manually against a real account; it is not part of
//! the CI test suite (which uses the in-memory [`crate::fake`] fixture and never
//! touches the network or any credential). The pure helpers below — search-query
//! sanitisation and address formatting — are unit-tested.

use imap::types::{Fetch, Flag};
use imap::Session;
use mail_parser::{Addr, Address, MessageParser};
use native_tls::{TlsConnector, TlsStream};
use std::net::TcpStream;

use crate::config::ImapConfig;
use crate::mailstore::{MailError, MailStore, Message, MessageSummary};

type ImapSession = Session<TlsStream<TcpStream>>;

/// IMAP-backed mail store. Holds connection settings (including the password,
/// which is redacted from `Debug` via [`ImapConfig`]).
#[derive(Debug)]
pub struct ImapBackend {
    config: ImapConfig,
}

impl ImapBackend {
    /// Create a backend from resolved configuration.
    pub fn new(config: ImapConfig) -> Self {
        ImapBackend { config }
    }

    /// Open a fresh TLS connection and log in.
    fn connect(&self) -> Result<ImapSession, MailError> {
        let tls = TlsConnector::builder().build().map_err(backend_err)?;
        let client = imap::connect(
            (self.config.host.as_str(), self.config.port),
            &self.config.host,
            &tls,
        )
        .map_err(backend_err)?;
        // On failure imap returns (error, client); keep only the error so the
        // client (and any buffered bytes) is dropped, and never surface
        // credentials.
        client
            .login(&self.config.username, &self.config.password)
            .map_err(|(e, _client)| backend_err(e))
    }

    /// Open `mailbox` read-only, run `op`, then log out regardless of outcome.
    fn with_mailbox<T>(
        &self,
        mailbox: &str,
        op: impl FnOnce(&mut ImapSession) -> Result<T, MailError>,
    ) -> Result<T, MailError> {
        let mut session = self.connect()?;
        // EXAMINE = read-only open. A failure here is treated as the mailbox
        // being unavailable.
        if session.examine(mailbox).is_err() {
            let _ = session.logout();
            return Err(MailError::MailboxUnavailable {
                mailbox: mailbox.to_string(),
            });
        }
        let result = op(&mut session);
        let _ = session.logout();
        result
    }

    /// Fetch summaries for a set of UIDs (newest first).
    fn fetch_summaries(
        session: &mut ImapSession,
        uids: &[u32],
    ) -> Result<Vec<MessageSummary>, MailError> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let set = uids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let fetches = session
            .uid_fetch(&set, "(UID FLAGS BODY.PEEK[HEADER])")
            .map_err(backend_err)?;
        let mut summaries: Vec<MessageSummary> =
            fetches.iter().filter_map(summary_from_fetch).collect();
        // The server may return fetches in any order; sort newest-first by UID.
        summaries.sort_unstable_by_key(|s| std::cmp::Reverse(s.uid));
        Ok(summaries)
    }
}

impl MailStore for ImapBackend {
    fn list_messages(&self, mailbox: &str, limit: usize) -> Result<Vec<MessageSummary>, MailError> {
        self.with_mailbox(mailbox, |session| {
            let mut uids: Vec<u32> = session
                .uid_search("ALL")
                .map_err(backend_err)?
                .into_iter()
                .collect();
            uids.sort_unstable();
            uids.reverse(); // newest (highest UID) first
            uids.truncate(limit);
            Self::fetch_summaries(session, &uids)
        })
    }

    fn search(&self, mailbox: &str, query: &str) -> Result<Vec<MessageSummary>, MailError> {
        let criterion = build_text_search(query);
        self.with_mailbox(mailbox, |session| {
            let mut uids: Vec<u32> = session
                .uid_search(&criterion)
                .map_err(backend_err)?
                .into_iter()
                .collect();
            uids.sort_unstable();
            uids.reverse();
            Self::fetch_summaries(session, &uids)
        })
    }

    fn fetch_message(&self, mailbox: &str, uid: u32) -> Result<Message, MailError> {
        self.with_mailbox(mailbox, |session| {
            let fetches = session
                .uid_fetch(uid.to_string(), "(UID FLAGS BODY.PEEK[])")
                .map_err(backend_err)?;
            let fetch = fetches
                .iter()
                .next()
                .ok_or(MailError::MessageNotFound { uid })?;
            Ok(message_from_fetch(uid, fetch))
        })
    }
}

// --- pure helpers (unit-tested) --------------------------------------------

/// Build an IMAP `SEARCH` criterion from free-text, safely quoted.
///
/// The text is embedded in an IMAP quoted string. CR/LF are stripped (illegal in
/// a quoted string and the vector for command injection), and `"` / `\` are
/// escaped. `SEARCH` is itself read-only, but quoting correctly is still the
/// right hygiene.
fn build_text_search(query: &str) -> String {
    let mut q = String::with_capacity(query.len());
    for ch in query.chars() {
        match ch {
            '\r' | '\n' => {} // strip
            '"' => q.push_str("\\\""),
            '\\' => q.push_str("\\\\"),
            c => q.push(c),
        }
    }
    format!("TEXT \"{q}\"")
}

/// Render an optional parsed address into `Name <addr>` form, comma-joined.
fn format_address(addr: Option<&Address<'_>>) -> String {
    let mut out: Vec<String> = Vec::new();
    match addr {
        Some(Address::List(addrs)) => {
            for a in addrs {
                push_addr(&mut out, a);
            }
        }
        Some(Address::Group(groups)) => {
            for g in groups {
                for a in &g.addresses {
                    push_addr(&mut out, a);
                }
            }
        }
        None => {}
    }
    out.join(", ")
}

fn push_addr(out: &mut Vec<String>, a: &Addr<'_>) {
    match (a.name.as_deref(), a.address.as_deref()) {
        (Some(name), Some(email)) => out.push(format!("{name} <{email}>")),
        (None, Some(email)) => out.push(email.to_string()),
        (Some(name), None) => out.push(name.to_string()),
        (None, None) => {}
    }
}

// --- fetch -> domain conversions -------------------------------------------

fn summary_from_fetch(fetch: &Fetch) -> Option<MessageSummary> {
    let uid = fetch.uid?;
    let seen = fetch.flags().iter().any(|f| matches!(f, Flag::Seen));
    let header_bytes = fetch.header().unwrap_or(&[]);
    let parsed = MessageParser::default().parse(header_bytes);
    let (subject, from, date) = match parsed {
        Some(m) => (
            m.subject().unwrap_or("").to_string(),
            format_address(m.from()),
            m.date().map(|d| d.to_rfc3339()).unwrap_or_default(),
        ),
        None => (String::new(), String::new(), String::new()),
    };
    Some(MessageSummary {
        uid,
        subject,
        from,
        date,
        seen,
    })
}

fn message_from_fetch(uid: u32, fetch: &Fetch) -> Message {
    let body_bytes = fetch.body().or_else(|| fetch.text()).unwrap_or(&[]);
    match MessageParser::default().parse(body_bytes) {
        Some(m) => Message {
            uid,
            subject: m.subject().unwrap_or("").to_string(),
            from: format_address(m.from()),
            to: format_address(m.to()),
            date: m.date().map(|d| d.to_rfc3339()).unwrap_or_default(),
            body_text: m.body_text(0).map(|c| c.into_owned()).unwrap_or_default(),
        },
        None => Message {
            uid,
            subject: String::new(),
            from: String::new(),
            to: String::new(),
            date: String::new(),
            body_text: String::from_utf8_lossy(body_bytes).into_owned(),
        },
    }
}

fn backend_err(e: impl std::fmt::Display) -> MailError {
    MailError::Backend {
        message: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_query_is_quoted_and_crlf_stripped() {
        assert_eq!(build_text_search("hello"), "TEXT \"hello\"");
        // Quote and backslash are escaped; CR/LF removed so no second command
        // can be injected.
        assert_eq!(
            build_text_search("a\"b\\c\r\nLOGOUT"),
            "TEXT \"a\\\"b\\\\cLOGOUT\""
        );
    }

    #[test]
    fn address_formatting_handles_name_and_bare_forms() {
        let list = Address::List(vec![
            Addr {
                name: Some("Alice".into()),
                address: Some("alice@example.test".into()),
            },
            Addr {
                name: None,
                address: Some("bob@example.test".into()),
            },
        ]);
        assert_eq!(
            format_address(Some(&list)),
            "Alice <alice@example.test>, bob@example.test"
        );
        assert_eq!(format_address(None), "");
    }
}
