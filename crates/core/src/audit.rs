//! The audit log: an append-only record of every elevation and every write-tool
//! invocation. This is the tape for incident review (DESIGN: "Audit").
//!
//! Entries are JSON lines, each with a wall-clock timestamp, appended to a file
//! (and kept in a bounded in-memory ring for quick `recent()` access). The file
//! is opened in append mode and each record is flushed, so a crash loses at most
//! the in-flight line. Append-only is a convention here, not a kernel guarantee;
//! tamper-evidence (e.g. hash chaining) is a possible future hardening.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// How many recent entries to keep in memory.
const RECENT_CAP: usize = 500;

/// A security-relevant event worth recording.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A write elevation was granted.
    ElevationGranted {
        /// Server elevated.
        server_id: String,
        /// Client that authorised it.
        client_id: String,
        /// `"duration"` or `"until_revoked"`.
        mode: String,
    },
    /// An elevation was explicitly revoked.
    ElevationRevoked {
        /// Server.
        server_id: String,
        /// Why (e.g. "operator", "fault").
        reason: String,
    },
    /// A destructive (`confirm`) action was approved by per-action presence.
    ConfirmApproved {
        /// Server.
        server_id: String,
        /// Tool approved.
        tool: String,
    },
    /// A write-class tool was invoked.
    WriteToolInvoked {
        /// Server.
        server_id: String,
        /// Tool name.
        tool: String,
    },
    /// An elevation or confirmation attempt was rejected. These are the
    /// high-signal events for incident review — a forged signature, an unknown
    /// client, an expired nonce, or a replay — so the tape must record them, not
    /// only the successes. The `reason` is the coarse, attacker-safe
    /// `ElevationError` text (no signature/nonce material). The broker records
    /// this on every failed verification (wired where verification is invoked).
    ElevationDenied {
        /// Server the attempt targeted.
        server_id: String,
        /// Client that attempted it (as presented; unverified).
        client_id: String,
        /// Coarse reason (e.g. "bad signature", "unknown or used nonce").
        reason: String,
    },
}

/// An append-only audit sink: a file plus an in-memory ring of recent lines.
pub struct AuditLog {
    file: Option<Mutex<std::fs::File>>,
    recent: Mutex<VecDeque<String>>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("file_backed", &self.file.is_some())
            .finish()
    }
}

impl AuditLog {
    /// An in-memory-only audit log (used in tests).
    pub fn in_memory() -> Self {
        AuditLog {
            file: None,
            recent: Mutex::new(VecDeque::new()),
        }
    }

    /// Append-only audit log backed by the file at `path` (created if missing).
    pub fn to_file(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(AuditLog {
            file: Some(Mutex::new(file)),
            recent: Mutex::new(VecDeque::new()),
        })
    }

    /// Record an event. Best-effort durability: the file write is flushed; a
    /// failed write is dropped rather than panicking (the broker must not crash
    /// because the audit disk is full — though that is itself worth alerting on).
    pub fn record(&self, event: AuditEvent) {
        let line = serialize_line(&event);
        if let Some(file) = &self.file {
            if let Ok(mut f) = file.lock() {
                let _ = f.write_all(line.as_bytes());
                let _ = f.write_all(b"\n");
                let _ = f.flush();
            }
        }
        if let Ok(mut recent) = self.recent.lock() {
            recent.push_back(line);
            while recent.len() > RECENT_CAP {
                recent.pop_front();
            }
        }
    }

    /// The most recent up-to-`limit` entries, oldest first.
    pub fn recent(&self, limit: usize) -> Vec<String> {
        let recent = match self.recent.lock() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let n = limit.min(recent.len());
        recent.iter().skip(recent.len() - n).cloned().collect()
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn serialize_line(event: &AuditEvent) -> String {
    #[derive(Serialize)]
    struct Entry<'a> {
        ts: u64,
        #[serde(flatten)]
        event: &'a AuditEvent,
    }
    serde_json::to_string(&Entry {
        ts: unix_now(),
        event,
    })
    .unwrap_or_else(|_| "{\"ts\":0,\"event\":\"serialize_error\"}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_appear_in_recent_in_order() {
        let log = AuditLog::in_memory();
        log.record(AuditEvent::ElevationGranted {
            server_id: "mail".into(),
            client_id: "client-1".into(),
            mode: "duration".into(),
        });
        log.record(AuditEvent::WriteToolInvoked {
            server_id: "mail".into(),
            tool: "send_message".into(),
        });
        let recent = log.recent(10);
        assert_eq!(recent.len(), 2);
        assert!(recent[0].contains("elevation_granted"));
        assert!(recent[0].contains("\"ts\":"));
        assert!(recent[1].contains("write_tool_invoked"));
        assert!(recent[1].contains("send_message"));
    }

    #[test]
    fn file_backed_log_persists_lines() {
        let path = std::env::temp_dir().join(format!("mcp-lock-audit-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let log = AuditLog::to_file(&path).unwrap();
            log.record(AuditEvent::ConfirmApproved {
                server_id: "mail".into(),
                tool: "delete_message".into(),
            });
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("confirm_approved"));
        assert!(contents.contains("delete_message"));
        assert_eq!(contents.lines().count(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn records_denied_attempts_for_incident_review() {
        let log = AuditLog::in_memory();
        log.record(AuditEvent::ElevationDenied {
            server_id: "mail".into(),
            client_id: "attacker".into(),
            reason: "bad signature".into(),
        });
        let recent = log.recent(10);
        assert_eq!(recent.len(), 1);
        assert!(recent[0].contains("elevation_denied"));
        assert!(recent[0].contains("bad signature"));
        assert!(recent[0].contains("attacker"));
    }

    #[test]
    fn recent_respects_limit() {
        let log = AuditLog::in_memory();
        for _ in 0..5 {
            log.record(AuditEvent::ElevationRevoked {
                server_id: "mail".into(),
                reason: "operator".into(),
            });
        }
        assert_eq!(log.recent(2).len(), 2);
        assert_eq!(log.recent(100).len(), 5);
    }
}
