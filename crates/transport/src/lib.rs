//! MCP-Lock transport seams.
//!
//! `docs/DESIGN.md` defines two distinct channels, deliberately kept apart
//! because they grant different authority:
//!
//! 1. **Control channel** (control clients -> broker): carries privileged
//!    actions, including elevation. Strong auth. Local is a Unix domain socket
//!    owned by the service account with peer verification; remote is mutual TLS
//!    bound to a private interface. Implemented in Slice 5.
//! 2. **MCP endpoint** (Claude client -> broker): in the default un-elevated
//!    state can invoke only READ tools. v1 authenticates it with a bearer token
//!    in the client's MCP config; validation is a *pluggable seam* so OAuth 2.1
//!    with PKCE drops in for v2 without touching the endpoint. Implemented in
//!    Slice 3.
//!
//! This crate exists to keep async, TLS, and IO complexity at the edges, around
//! the synchronous security core in `mcp-lock-core`. Slice 0 establishes only
//! the crate boundary and the transport-agnostic framing seam below; the
//! channels themselves, and all authentication, land in later slices.
//!
//! Note on layering: credential/token *validation* is security-core policy and
//! lives behind a seam in `mcp-lock-core`, not here. This crate moves bytes and
//! authenticates with that seam; it does not decide who is allowed to do what
//! with a tool — that is the broker/aggregator over the security core.
//!
//! The upward MCP endpoint (Slice 3c) is in [`endpoint`]: a synchronous,
//! bearer-authenticated HTTP server that delegates every request to an
//! [`endpoint::McpHandler`] the broker implements.

pub mod endpoint;

/// A transport that carries length-delimited message frames in both directions.
///
/// Both channels reduce to this once authentication and routing are stripped
/// away: the control channel frames control-API messages over a UDS/TLS stream,
/// and the MCP endpoint frames JSON-RPC messages to and from child stdio
/// servers. Defining it here lets the broker depend on the capability rather
/// than on a concrete socket type.
///
/// This is pure plumbing — it makes no security decisions. It is intentionally
/// synchronous and byte-oriented in Slice 0; an async variant for the network
/// edges arrives with the slice that needs it.
pub trait FramedTransport {
    /// The error type produced by send/receive operations.
    type Error: std::error::Error;

    /// Send one complete message frame.
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), Self::Error>;

    /// Receive the next complete message frame, or `Ok(None)` at end of stream.
    fn recv_frame(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;
}
