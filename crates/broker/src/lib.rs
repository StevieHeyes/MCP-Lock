//! MCP-Lock broker library.
//!
//! The broker is the parent process of every supervised MCP server and presents
//! a single, fail-closed, default-read-only view of their tools. This crate
//! holds the mediation logic:
//!
//! * [`mcp_client`] — a synchronous stdio MCP client for talking to a child
//!   server (the broker is the parent), behind the [`mcp_client::McpChild`]
//!   seam so the aggregator is testable without subprocesses.
//! * [`aggregator`] — combines children with the security-core exposure gate
//!   (`mcp_lock_core::broker`/`policy`): discovers each child's tools, classifies
//!   them (operator-authoritative, default-deny), exposes only what policy
//!   currently allows, and routes calls — re-checking the gate at call time.
//!
//! The upward MCP endpoint (HTTP/SSE + the bearer-token seam) is wired on top of
//! this in Slice 3c. Everything here is synchronous; transport/async complexity
//! stays at the edge.

pub mod aggregator;
pub mod mcp_client;
