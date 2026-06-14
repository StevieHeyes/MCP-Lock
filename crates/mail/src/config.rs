//! Configuration for the real IMAP backend, read from the environment.
//!
//! Credentials come from environment variables only. The server never prompts
//! for a password and never writes one anywhere. In the broker deployment
//! (Slice 3+) the broker injects the scoped credential into the child's
//! environment; a Keychain-backed source is a documented follow-up
//! (see `docs/DESIGN.md`, "Sandboxing seam" / `SecureKeyStore`).

use std::fmt;

/// Environment variable names this server reads.
pub mod env_vars {
    /// IMAP server hostname. Required.
    pub const HOST: &str = "MAIL_IMAP_HOST";
    /// IMAP server port. Optional; defaults to 993 (implicit TLS).
    pub const PORT: &str = "MAIL_IMAP_PORT";
    /// IMAP username. Required.
    pub const USERNAME: &str = "MAIL_IMAP_USERNAME";
    /// IMAP password / app password. Required. Never logged.
    pub const PASSWORD: &str = "MAIL_IMAP_PASSWORD";
    /// Default mailbox when a tool call omits one. Optional; defaults to INBOX.
    pub const DEFAULT_MAILBOX: &str = "MAIL_DEFAULT_MAILBOX";
}

/// Default IMAPS port (implicit TLS).
const DEFAULT_PORT: u16 = 993;
/// Default mailbox.
const DEFAULT_MAILBOX: &str = "INBOX";

/// Resolved IMAP connection settings.
pub struct ImapConfig {
    /// IMAP server hostname.
    pub host: String,
    /// IMAP server port (993 by default).
    pub port: u16,
    /// IMAP username.
    pub username: String,
    /// IMAP password. Held only in memory; redacted from `Debug`.
    pub password: String,
    /// Default mailbox for tool calls that omit one.
    pub default_mailbox: String,
}

// Hand-written so the password can never reach a log line or panic message.
impl fmt::Debug for ImapConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImapConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("default_mailbox", &self.default_mailbox)
            .finish()
    }
}

/// Why configuration could not be loaded.
#[derive(Debug)]
pub enum ConfigError {
    /// One or more required variables were absent.
    MissingVars {
        /// Names of the missing variables.
        names: Vec<&'static str>,
    },
    /// A variable was present but malformed (e.g. a non-numeric port).
    InvalidValue {
        /// The variable name.
        name: &'static str,
        /// What was wrong. Never contains a secret value.
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::MissingVars { names } => {
                write!(
                    f,
                    "missing required environment variables: {}",
                    names.join(", ")
                )
            }
            ConfigError::InvalidValue { name, reason } => {
                write!(f, "invalid value for {name}: {reason}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl ImapConfig {
    /// Build a config from the process environment, using a provided lookup so
    /// the logic is unit-testable without mutating global process state.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut missing = Vec::new();

        let host = lookup(env_vars::HOST);
        let username = lookup(env_vars::USERNAME);
        let password = lookup(env_vars::PASSWORD);

        if host.as_deref().unwrap_or("").is_empty() {
            missing.push(env_vars::HOST);
        }
        if username.as_deref().unwrap_or("").is_empty() {
            missing.push(env_vars::USERNAME);
        }
        if password.as_deref().unwrap_or("").is_empty() {
            missing.push(env_vars::PASSWORD);
        }
        if !missing.is_empty() {
            return Err(ConfigError::MissingVars { names: missing });
        }

        let port = match lookup(env_vars::PORT) {
            None => DEFAULT_PORT,
            Some(s) if s.is_empty() => DEFAULT_PORT,
            Some(s) => s.parse::<u16>().map_err(|_| ConfigError::InvalidValue {
                name: env_vars::PORT,
                reason: "must be a port number in 1..=65535".to_string(),
            })?,
        };

        let default_mailbox = match lookup(env_vars::DEFAULT_MAILBOX) {
            Some(s) if !s.is_empty() => s,
            _ => DEFAULT_MAILBOX.to_string(),
        };

        Ok(ImapConfig {
            // unwrap: presence was checked above.
            host: host.unwrap(),
            port,
            username: username.unwrap(),
            password: password.unwrap(),
            default_mailbox,
        })
    }

    /// Build a config from the real process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup_from(map: &HashMap<&'static str, &'static str>) -> impl Fn(&str) -> Option<String> {
        let owned: HashMap<String, String> = map
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k: &str| owned.get(k).cloned()
    }

    #[test]
    fn missing_required_vars_are_all_reported() {
        let cfg = ImapConfig::from_lookup(lookup_from(&HashMap::new()));
        match cfg {
            Err(ConfigError::MissingVars { names }) => {
                assert!(names.contains(&env_vars::HOST));
                assert!(names.contains(&env_vars::USERNAME));
                assert!(names.contains(&env_vars::PASSWORD));
            }
            other => panic!("expected MissingVars, got {other:?}"),
        }
    }

    #[test]
    fn defaults_apply_for_port_and_mailbox() {
        let mut m = HashMap::new();
        m.insert(env_vars::HOST, "imap.example.test");
        m.insert(env_vars::USERNAME, "user");
        m.insert(env_vars::PASSWORD, "placeholder-not-a-real-secret");
        let cfg = ImapConfig::from_lookup(lookup_from(&m)).unwrap();
        assert_eq!(cfg.port, 993);
        assert_eq!(cfg.default_mailbox, "INBOX");
    }

    #[test]
    fn invalid_port_is_rejected() {
        let mut m = HashMap::new();
        m.insert(env_vars::HOST, "imap.example.test");
        m.insert(env_vars::USERNAME, "user");
        m.insert(env_vars::PASSWORD, "placeholder-not-a-real-secret");
        m.insert(env_vars::PORT, "not-a-number");
        assert!(matches!(
            ImapConfig::from_lookup(lookup_from(&m)),
            Err(ConfigError::InvalidValue { .. })
        ));
    }

    #[test]
    fn debug_redacts_password() {
        let mut m = HashMap::new();
        m.insert(env_vars::HOST, "imap.example.test");
        m.insert(env_vars::USERNAME, "user");
        m.insert(env_vars::PASSWORD, "super-secret-placeholder");
        let cfg = ImapConfig::from_lookup(lookup_from(&m)).unwrap();
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("super-secret-placeholder"));
        assert!(rendered.contains("<redacted>"));
    }
}
