//! Process-wide structured logging setup.
//!
//! Library crates emit events through `tracing`; only application entry points should call
//! [`init`]. Sensitive protocol values must never be attached to tracing fields.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use thiserror::Error;

/// Output representation selected by an application entry point.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LogFormat {
    /// Human-readable single-line output for interactive use.
    #[default]
    Compact,
    /// Structured output for service managers and log collectors.
    Json,
}

/// Logger initialization parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoggerConfig {
    /// Fallback filter used when the configured environment variable is absent.
    pub default_filter: String,
    /// Environment variable containing a `tracing-subscriber` filter expression.
    pub filter_env: String,
    pub format: LogFormat,
    pub ansi: bool,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            default_filter: "info".to_owned(),
            filter_env: "HERMES_LOG".to_owned(),
            format: LogFormat::Compact,
            ansi: true,
        }
    }
}

/// Installs the global tracing subscriber.
pub fn init(config: &LoggerConfig) -> Result<(), LoggerError> {
    let filter = EnvFilter::try_from_env(&config.filter_env)
        .or_else(|_| EnvFilter::try_new(&config.default_filter))
        .map_err(LoggerError::InvalidFilter)?;

    match config.format {
        LogFormat::Compact => tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().compact().with_ansi(config.ansi))
            .try_init()
            .map_err(LoggerError::Install),
        LogFormat::Json => tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json().with_ansi(false))
            .try_init()
            .map_err(LoggerError::Install),
    }
}

#[derive(Debug, Error)]
pub enum LoggerError {
    #[error("invalid logger filter: {0}")]
    InvalidFilter(#[source] tracing_subscriber::filter::ParseError),
    #[error("global logger is already installed: {0}")]
    Install(#[source] tracing_subscriber::util::TryInitError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logger_defaults_are_safe_for_interactive_use() {
        let config = LoggerConfig::default();
        assert_eq!(config.default_filter, "info");
        assert_eq!(config.filter_env, "HERMES_LOG");
        assert_eq!(config.format, LogFormat::Compact);
    }
}
