//! MCP-Lock core.
//!
//! This crate holds the parts of MCP-Lock that the rest of the system is built
//! around but that are themselves free of transport, async, and (beyond thin
//! stubs) platform code:
//!
//! * the **platform-abstraction traits** ([`platform`]) — presence, key
//!   storage, peer identity, process supervision, and the v2 isolation seam —
//!   defined once here so other OSes are an additive concern, never a rewrite;
//! * the **execution-context seam** ([`exec`]) — the injectable context every
//!   child server is spawned with, so per-child isolation and scoped
//!   credentials slot into v2 without touching the spawn path.
//!
//! Per `docs/DESIGN.md`, the security core (credential handling, presence/nonce
//! verification, token validation, the exposure/classification gate, and the
//! fail-closed logic) belongs in this crate and must stay plain, synchronous,
//! and lifetime-light so it can be audited without deep Rust fluency.
//!
//! The exposure/classification gate and the fail-closed state machine landed in
//! Slice 2:
//! * [`manifest`] — the operator-authoritative manifest, its integrity hash, and
//!   the hint-as-prefill helper.
//! * [`policy`] — classification (default-deny), elevation with expiry, and the
//!   exposure-resolution gate.
//! * [`broker`] — the in-memory, no-persistence broker state and its fail-closed
//!   transitions.
//!
//! Token validation landed in Slice 3a:
//! * [`auth`] — the pluggable credential-validation seam (`CredentialValidator`,
//!   the unforgeable `ValidatedClient`, and the ship-closed static bearer
//!   validator).
//!
//! Presence/nonce verification and the audit tape landed in Slice 5:
//! * [`elevation`] — single-use nonces, the canonical signed challenge, Ed25519
//!   verification (no replay, binding, freshness, ship-closed), and the client
//!   registry.
//! * [`audit`] — the append-only record of elevations and write-tool invocations.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod audit;
pub mod auth;
pub mod broker;
pub mod elevation;
pub mod error;
pub mod exec;
pub mod manifest;
pub mod platform;
pub mod policy;

pub use error::PlatformError;
