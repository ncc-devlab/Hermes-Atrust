//! Process-wide structured logging setup.
//!
//! Library crates emit events through `tracing`; only application entry points should call
//! [`init`]. Sensitive protocol values must never be attached to tracing fields.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use thiserror::Error;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

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
    /// Optional file path; when set, logs are tee'd to stderr and appended to this file.
    pub log_file: Option<PathBuf>,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            default_filter: "info".to_owned(),
            filter_env: "HERMES_LOG".to_owned(),
            format: LogFormat::Compact,
            ansi: true,
            log_file: None,
        }
    }
}

/// Installs the global tracing subscriber.
pub fn init(config: &LoggerConfig) -> Result<(), LoggerError> {
    let filter = EnvFilter::try_from_env(&config.filter_env)
        .or_else(|_| EnvFilter::try_new(&config.default_filter))
        .map_err(LoggerError::InvalidFilter)?;

    let file_writer = match config.log_file.as_deref() {
        Some(path) => Some(open_log_file(path)?),
        None => None,
    };

    match (config.format, file_writer) {
        (LogFormat::Compact, None) => tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().compact().with_ansi(config.ansi))
            .try_init()
            .map_err(LoggerError::Install),
        (LogFormat::Json, None) => tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json().with_ansi(false))
            .try_init()
            .map_err(LoggerError::Install),
        (LogFormat::Compact, Some(file)) => {
            let tee = TeeMakeWriter::new(file);
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .compact()
                        .with_ansi(config.ansi)
                        .with_writer(tee),
                )
                .try_init()
                .map_err(LoggerError::Install)
        }
        (LogFormat::Json, Some(file)) => {
            let tee = TeeMakeWriter::new(file);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_ansi(false).with_writer(tee))
                .try_init()
                .map_err(LoggerError::Install)
        }
    }
}

fn open_log_file(path: &Path) -> Result<SharedFileWriter, LoggerError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|source| LoggerError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| LoggerError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(SharedFileWriter::new(file))
}

#[derive(Clone, Debug)]
struct SharedFileWriter {
    inner: Arc<Mutex<std::fs::File>>,
}

impl SharedFileWriter {
    fn new(file: std::fs::File) -> Self {
        Self {
            inner: Arc::new(Mutex::new(file)),
        }
    }
}

impl Write for SharedFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?
            .flush()
    }
}

/// Writes each log line to stderr and an optional append-only file.
#[derive(Clone, Debug)]
struct TeeMakeWriter {
    file: SharedFileWriter,
}

impl TeeMakeWriter {
    fn new(file: SharedFileWriter) -> Self {
        Self { file }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TeeMakeWriter {
    type Writer = TeeWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TeeWriter {
            stderr: io::stderr(),
            file: self.file.clone(),
        }
    }
}

struct TeeWriter {
    stderr: io::Stderr,
    file: SharedFileWriter,
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _ = self.stderr.write_all(buf);
        self.file.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let _ = self.stderr.flush();
        self.file.flush()
    }
}

#[derive(Debug, Error)]
pub enum LoggerError {
    #[error("invalid logger filter: {0}")]
    InvalidFilter(#[source] tracing_subscriber::filter::ParseError),
    #[error("global logger is already installed: {0}")]
    Install(#[source] tracing_subscriber::util::TryInitError),
    #[error("failed to open log file {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
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
        assert!(config.log_file.is_none());
    }
}
