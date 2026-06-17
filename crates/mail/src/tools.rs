//! The three read-only MCP tools and their dispatch: `search`,
//! `list_messages`, and `fetch_message`.
//!
//! Two distinct failure modes are kept separate, matching MCP semantics:
//!
//! * **Protocol-level** problems (the `arguments` object is missing or
//!   malformed) return [`ToolError::InvalidParams`], which the server turns into
//!   a JSON-RPC error. The model cannot recover from these by itself.
//! * **Tool-level** problems (mailbox missing, UID not found, backend error)
//!   return a normal tool *result* with `isError: true`, so the model sees the
//!   failure as content and can adjust. This is the MCP-recommended shape.

use serde_json::{json, Value};

use crate::mailstore::{MailError, MailStore, Message, MessageSummary};

/// Default number of messages `list_messages` returns when no limit is given.
const DEFAULT_LIST_LIMIT: usize = 25;
/// Upper bound on how many messages a single call may return, so a model cannot
/// pull an entire mailbox in one request.
const MAX_LIST_LIMIT: usize = 200;

/// A protocol-level argument error. Mapped to a JSON-RPC `INVALID_PARAMS`.
#[derive(Debug)]
pub struct ToolError {
    /// Human-readable reason. Never contains credentials.
    pub message: String,
}

impl ToolError {
    fn new(message: impl Into<String>) -> Self {
        ToolError {
            message: message.into(),
        }
    }
}

/// The MCP `tools/list` payload: the definitions of every tool this server
/// exposes. All three are read-only; the server advertises nothing that mutates
/// mail.
pub fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "search",
            "description": "Search a mailbox and return matching message summaries (newest first). Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search text. Matches subject, sender, and body as supported by the mail server."
                    },
                    "mailbox": {
                        "type": "string",
                        "description": "Mailbox to search. Defaults to the configured default mailbox (usually INBOX)."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_LIST_LIMIT,
                        "description": "Maximum number of matches to return. Defaults to 200."
                    }
                },
                "required": ["query"]
            }
        }),
        json!({
            "name": "list_messages",
            "description": "List the most recent messages in a mailbox (newest first). Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "mailbox": {
                        "type": "string",
                        "description": "Mailbox to list. Defaults to the configured default mailbox (usually INBOX)."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_LIST_LIMIT,
                        "description": "Maximum number of messages to return. Defaults to 25."
                    }
                },
                "required": []
            }
        }),
        json!({
            "name": "fetch_message",
            "description": "Fetch one full message by UID, including a plain-text body. Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "uid": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "IMAP UID of the message, as returned by search or list_messages."
                    },
                    "mailbox": {
                        "type": "string",
                        "description": "Mailbox the message is in. Defaults to the configured default mailbox (usually INBOX)."
                    }
                },
                "required": ["uid"]
            }
        }),
    ]
}

/// Dispatch a `tools/call` to the named tool.
///
/// `arguments` is the raw `arguments` object from the request (or `None`).
/// `default_mailbox` is used whenever a call omits an explicit mailbox.
///
/// Returns the `tools/call` *result* `Value` on success (which itself may carry
/// `isError: true` for tool-level failures), or [`ToolError`] for malformed
/// parameters that the caller maps to a JSON-RPC error.
pub fn call<S: MailStore>(
    store: &S,
    name: &str,
    arguments: Option<&Value>,
    default_mailbox: &str,
) -> Result<Value, ToolError> {
    match name {
        "search" => call_search(store, arguments, default_mailbox),
        "list_messages" => call_list(store, arguments, default_mailbox),
        "fetch_message" => call_fetch(store, arguments, default_mailbox),
        other => Ok(error_text(format!(
            "unknown tool '{other}'; available tools: search, list_messages, fetch_message"
        ))),
    }
}

fn call_search<S: MailStore>(
    store: &S,
    arguments: Option<&Value>,
    default_mailbox: &str,
) -> Result<Value, ToolError> {
    let args = require_object(arguments)?;
    let query = require_string(args, "query")?;
    let mailbox = optional_mailbox(args, default_mailbox)?;
    // Search has no narrowing default the way `list_messages` does; an absent
    // limit means "as many as allowed", i.e. the hard cap.
    let limit = optional_limit(args, MAX_LIST_LIMIT)?;
    Ok(summaries_to_result(store.search(&mailbox, &query, limit)))
}

fn call_list<S: MailStore>(
    store: &S,
    arguments: Option<&Value>,
    default_mailbox: &str,
) -> Result<Value, ToolError> {
    // `arguments` may be omitted entirely for list_messages (no required args).
    let empty = json!({});
    let args = arguments.unwrap_or(&empty);
    let args = args
        .as_object()
        .ok_or_else(|| ToolError::new("`arguments` must be an object"))?;
    let mailbox = optional_mailbox(args, default_mailbox)?;
    let limit = optional_limit(args, DEFAULT_LIST_LIMIT)?;
    Ok(summaries_to_result(store.list_messages(&mailbox, limit)))
}

fn call_fetch<S: MailStore>(
    store: &S,
    arguments: Option<&Value>,
    default_mailbox: &str,
) -> Result<Value, ToolError> {
    let args = require_object(arguments)?;
    let uid = require_uid(args, "uid")?;
    let mailbox = optional_mailbox(args, default_mailbox)?;
    match store.fetch_message(&mailbox, uid) {
        Ok(message) => Ok(message_to_result(&message)),
        Err(e) => Ok(mail_error_to_result(e)),
    }
}

// --- argument helpers -------------------------------------------------------

fn require_object(arguments: Option<&Value>) -> Result<&serde_json::Map<String, Value>, ToolError> {
    arguments
        .and_then(Value::as_object)
        .ok_or_else(|| ToolError::new("`arguments` must be an object"))
}

fn require_string(args: &serde_json::Map<String, Value>, key: &str) -> Result<String, ToolError> {
    match args.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        Some(Value::String(_)) => Err(ToolError::new(format!("`{key}` must not be empty"))),
        Some(_) => Err(ToolError::new(format!("`{key}` must be a string"))),
        None => Err(ToolError::new(format!("missing required argument `{key}`"))),
    }
}

fn require_uid(args: &serde_json::Map<String, Value>, key: &str) -> Result<u32, ToolError> {
    match args.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .filter(|v| *v >= 1 && *v <= u64::from(u32::MAX))
            .map(|v| v as u32)
            .ok_or_else(|| ToolError::new(format!("`{key}` must be a positive integer UID"))),
        Some(_) => Err(ToolError::new(format!("`{key}` must be an integer"))),
        None => Err(ToolError::new(format!("missing required argument `{key}`"))),
    }
}

fn optional_mailbox(
    args: &serde_json::Map<String, Value>,
    default_mailbox: &str,
) -> Result<String, ToolError> {
    match args.get("mailbox") {
        None | Some(Value::Null) => Ok(default_mailbox.to_string()),
        Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        Some(Value::String(_)) => Err(ToolError::new("`mailbox` must not be empty")),
        Some(_) => Err(ToolError::new("`mailbox` must be a string")),
    }
}

fn optional_limit(
    args: &serde_json::Map<String, Value>,
    default: usize,
) -> Result<usize, ToolError> {
    match args.get("limit") {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Number(n)) => {
            let v = n
                .as_u64()
                .ok_or_else(|| ToolError::new("`limit` must be a positive integer"))?;
            if v == 0 {
                return Err(ToolError::new("`limit` must be at least 1"));
            }
            Ok((v as usize).min(MAX_LIST_LIMIT))
        }
        Some(_) => Err(ToolError::new("`limit` must be an integer")),
    }
}

// --- result formatting ------------------------------------------------------

fn summaries_to_result(result: Result<Vec<MessageSummary>, MailError>) -> Value {
    match result {
        Ok(summaries) => {
            let items: Vec<Value> = summaries
                .iter()
                .map(|s| {
                    json!({
                        "uid": s.uid,
                        "subject": s.subject,
                        "from": s.from,
                        "date": s.date,
                        "seen": s.seen,
                    })
                })
                .collect();
            let text = serde_json::to_string_pretty(&json!({
                "count": items.len(),
                "messages": items,
            }))
            .unwrap_or_else(|_| "{}".to_string());
            ok_text(text)
        }
        Err(e) => mail_error_to_result(e),
    }
}

fn message_to_result(message: &Message) -> Value {
    let text = serde_json::to_string_pretty(&json!({
        "uid": message.uid,
        "subject": message.subject,
        "from": message.from,
        "to": message.to,
        "date": message.date,
        "body_text": message.body_text,
    }))
    .unwrap_or_else(|_| "{}".to_string());
    ok_text(text)
}

fn mail_error_to_result(e: MailError) -> Value {
    error_text(e.to_string())
}

fn ok_text(text: String) -> Value {
    json!({ "content": [ { "type": "text", "text": text } ], "isError": false })
}

fn error_text(text: String) -> Value {
    json!({ "content": [ { "type": "text", "text": text } ], "isError": true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeMailStore;
    use crate::mailstore::Message;

    /// Parse the `count` field out of a successful summaries result.
    fn result_count(result: &Value) -> u64 {
        assert_eq!(result["isError"], json!(false), "expected a success result");
        let text = result["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        parsed["count"].as_u64().unwrap()
    }

    /// A store whose INBOX holds `n` messages with UIDs `1..=n`, all matching the
    /// search needle "match".
    fn store_with(n: u32) -> FakeMailStore {
        let mut store = FakeMailStore::new();
        for uid in 1..=n {
            store.add_message(
                "INBOX",
                Message {
                    uid,
                    subject: "match".to_string(),
                    from: "a@example.test".to_string(),
                    to: "b@example.test".to_string(),
                    date: String::new(),
                    body_text: "match".to_string(),
                },
                false,
            );
        }
        store
    }

    #[test]
    fn list_limit_over_max_is_clamped_to_max() {
        let store = store_with((MAX_LIST_LIMIT as u32) + 50);
        let args = json!({ "limit": MAX_LIST_LIMIT + 50 });
        let result = call(&store, "list_messages", Some(&args), "INBOX").unwrap();
        assert_eq!(result_count(&result), MAX_LIST_LIMIT as u64);
    }

    #[test]
    fn list_limit_zero_is_rejected() {
        let store = FakeMailStore::demo();
        let args = json!({ "limit": 0 });
        let err = call(&store, "list_messages", Some(&args), "INBOX").unwrap_err();
        assert!(err.message.contains("at least 1"), "got: {}", err.message);
    }

    #[test]
    fn search_limit_over_max_is_clamped_to_max() {
        let store = store_with((MAX_LIST_LIMIT as u32) + 50);
        let args = json!({ "query": "match", "limit": MAX_LIST_LIMIT + 50 });
        let result = call(&store, "search", Some(&args), "INBOX").unwrap();
        assert_eq!(result_count(&result), MAX_LIST_LIMIT as u64);
    }

    #[test]
    fn search_caps_results_at_max_when_limit_absent() {
        // More matches than the hard cap, no explicit limit: must truncate to
        // MAX_LIST_LIMIT, not return the whole mailbox.
        let store = store_with((MAX_LIST_LIMIT as u32) + 50);
        let args = json!({ "query": "match" });
        let result = call(&store, "search", Some(&args), "INBOX").unwrap();
        assert_eq!(result_count(&result), MAX_LIST_LIMIT as u64);
    }

    #[test]
    fn require_uid_rejects_zero_negative_and_overflow() {
        let store = FakeMailStore::demo();
        // uid 0 (below minimum)
        let zero = json!({ "uid": 0 });
        assert!(call(&store, "fetch_message", Some(&zero), "INBOX").is_err());
        // negative uid
        let neg = json!({ "uid": -1 });
        assert!(call(&store, "fetch_message", Some(&neg), "INBOX").is_err());
        // overflow beyond u32::MAX
        let over = json!({ "uid": (u64::from(u32::MAX)) + 1 });
        assert!(call(&store, "fetch_message", Some(&over), "INBOX").is_err());
        // a valid in-range uid is accepted (no InvalidParams error)
        let ok = json!({ "uid": 1 });
        assert!(call(&store, "fetch_message", Some(&ok), "INBOX").is_ok());
    }

    #[test]
    fn require_uid_accepts_u32_max_boundary() {
        let store = FakeMailStore::demo();
        let max = json!({ "uid": u32::MAX });
        // In range, so it is a valid param; the message simply is not found,
        // which surfaces as a tool-level result, not an InvalidParams error.
        assert!(call(&store, "fetch_message", Some(&max), "INBOX").is_ok());
    }
}
