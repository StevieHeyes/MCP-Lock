//! MCP-Lock read-only IMAP mail MCP server.
//!
//! A standalone stdio [MCP](https://modelcontextprotocol.io) server exposing
//! three read-only tools — `search`, `list_messages`, `fetch_message` — over an
//! IMAP account. It runs directly against an MCP client without the broker, and
//! is also the first concrete server the broker will supervise.
//!
//! Layering:
//! * [`mailstore`] — domain types and the read-only `MailStore` trait (the seam).
//! * [`fake`] — in-memory fixture implementing `MailStore` (tests + demo mode).
//! * [`imap_backend`] — the real IMAP-backed `MailStore`.
//! * [`jsonrpc`] / [`server`] — the MCP stdio protocol and dispatch loop.
//! * [`tools`] — the three tool definitions and their handlers.
//! * [`config`] — environment-sourced IMAP configuration.
//!
//! Every layer except [`imap_backend`] is exercised by tests with no network and
//! no credentials.

pub mod config;
pub mod fake;
pub mod imap_backend;
pub mod jsonrpc;
pub mod mailstore;
pub mod server;
pub mod tools;
