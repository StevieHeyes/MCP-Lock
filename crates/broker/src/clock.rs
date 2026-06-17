//! A single monotonic clock shared by the broker's handlers.
//!
//! The MCP handler and the control handler both read and write time-stamped
//! state in the shared aggregator — an elevation's `granted_at`/expiry and a
//! per-action confirmation's `approved_at` are written by the control handler
//! and then read (for expiry) by the MCP handler. They MUST therefore measure
//! "now" from the same epoch. Two independent `Instant::now()` bases (one per
//! handler, created at slightly different moments) would drift by the
//! handler-setup delay and corrupt those decisions: a confirmation could be born
//! already-aged against the reader's clock, or an elevation could expire early
//! or late. One shared `Clock` keeps the timeline coherent.
//!
//! `Instant` is `Copy`, so a cloned `Clock` carries the *same* base instant —
//! every clone reports the same `now()`. Construct one in `serve()` and hand a
//! clone to each handler.

use std::time::Instant;

use mcp_lock_core::policy::Timestamp;

/// A monotonic clock measuring seconds since a shared base instant.
#[derive(Debug, Clone)]
pub struct Clock {
    base: Instant,
}

impl Clock {
    /// A clock whose epoch is now.
    pub fn new() -> Self {
        Clock {
            base: Instant::now(),
        }
    }

    /// Seconds elapsed since the clock's base instant.
    pub fn now(&self) -> Timestamp {
        self.base.elapsed().as_secs()
    }
}

impl Default for Clock {
    fn default() -> Self {
        Clock::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_the_same_epoch() {
        // The whole point: a cloned clock measures from the same base, so two
        // handlers holding clones agree on "now". (Instant is Copy.)
        let a = Clock::new();
        let b = a.clone();
        // Both read from the same base instant, so their readings match.
        assert_eq!(a.now(), b.now());
    }
}
