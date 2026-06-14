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
//! * [`handler`] — [`handler::BrokerMcpHandler`] implements the transport
//!   crate's `McpHandler`, answering MCP requests from the aggregator. The HTTP
//!   endpoint itself (bearer-auth'd, in `mcp-lock-transport`) calls into it.
//!
//! Everything here is synchronous; transport/async complexity stays at the edge.

pub mod aggregator;
#[cfg(unix)]
pub mod control_handler;
pub mod handler;
pub mod mcp_client;
