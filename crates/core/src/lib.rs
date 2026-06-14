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
//! Credential handling, presence/nonce verification, and token validation arrive
//! in the later security-reviewed slices that fill the remaining seams.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod broker;
pub mod error;
pub mod exec;
pub mod manifest;
pub mod platform;
pub mod policy;

pub use error::PlatformError;
