use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use atrust_auth::{AuthClient, AuthConfigOptions, PasswordCredentials};
use clap::{Parser, Subcommand};
use hermes_logging::{LogFormat, LoggerConfig};
use hermes_model::{DeviceId, GatewayEndpoint, SecretString};
use hermes_transport::{ReqwestTransport, ReqwestTransportConfig, TlsPolicy};
use rand::Rng as _;
use tracing::{error, info, warn};

mod browser;

use browser::{BrowserKind, WebDriverBrowser};

#[derive(Debug, Parser)]
#[command(
    about = "aTrust protocol probe for auth discovery and controlled interactive login",
    version
)]
struct Cli {
    #[arg(long)]
    host: String,
    #[arg(long, default_value_t = 443)]
    port: u16,
    /// Disable peer certificate verification for incompatible private gateways.
    #[arg(long)]
    insecure_tls: bool,
    #[arg(long)]
    json_logs: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Fetch authentication methods without logging in.
    AuthConfig {
        #[arg(long)]
        modified: bool,
        #[arg(long)]
        need_ticket: bool,
    },
    /// Perform one local password authentication attempt using environment credentials.
    Password {
        #[arg(long, default_value = "local")]
        login_domain: String,
    },
    /// Show the server-provided CAS entry point without opening a browser.
    CasStart {
        #[arg(long)]
        login_domain: String,
    },
    /// Complete interactive CAS login in a WebDriver browser session.
    CasLogin {
        #[arg(long)]
        login_domain: String,
        #[arg(long, default_value = "http://127.0.0.1:9515")]
        webdriver_url: String,
        /// Browser engine used for interactive login: chrome or firefox.
        #[arg(long, default_value = "chrome")]
        browser: String,
        #[arg(long, default_value_t = 300)]
        timeout_seconds: u64,
        #[arg(long)]
        keep_browser_open: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let logger = LoggerConfig {
        format: if cli.json_logs {
            LogFormat::Json
        } else {
            LogFormat::Compact
        },
        ..LoggerConfig::default()
    };
    if let Err(error) = hermes_logging::init(&logger) {
        eprintln!("failed to initialize logger: {error}");
        return ExitCode::FAILURE;
    }

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(event = "probe.failed", error = %error);
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = GatewayEndpoint::new(cli.host, cli.port)?;
    let tls_policy = if cli.insecure_tls {
        TlsPolicy::DangerousAcceptInvalidCertificates
    } else {
        TlsPolicy::Verify
    };
    let transport = Arc::new(ReqwestTransport::new(&ReqwestTransportConfig {
        tls_policy,
        ..ReqwestTransportConfig::default()
    })?);
    let client = AuthClient::new(endpoint, transport);

    match cli.command {
        Command::AuthConfig {
            modified,
            need_ticket,
        } => {
            let configuration = client
                .auth_config(AuthConfigOptions {
                    modified,
                    need_ticket,
                })
                .await?;
            info!(
                event = "probe.auth_config",
                login_state = ?configuration.login_state,
                auth_method_count = configuration.methods.len()
            );
            for method in configuration.methods {
                info!(
                    event = "probe.auth_method",
                    login_domain = method.login_domain,
                    auth_type = method.auth_type,
                    auth_name = method.auth_name
                );
            }
        }
        Command::Password { login_domain } => {
            let username = env::var("HERMES_ATRUST_USERNAME")?;
            let password = SecretString::new(env::var("HERMES_ATRUST_PASSWORD")?)?;
            let credentials = PasswordCredentials::new(username, password, login_domain)?;
            let device_id = DeviceId::new(random_hex(32))?;
            let configuration = client
                .auth_config(AuthConfigOptions {
                    modified: false,
                    need_ticket: true,
                })
                .await?;
            let outcome = client
                .authenticate_password(&configuration, &credentials, &device_id, None)
                .await?;
            info!(
                event = "probe.password_primary_complete",
                captcha_required = outcome.captcha_required,
                ticket_received = outcome.ticket.is_some()
            );
        }
        Command::CasStart { login_domain } => {
            let configuration = client
                .auth_config(AuthConfigOptions {
                    modified: false,
                    need_ticket: true,
                })
                .await?;
            let challenge = client.prepare_cas(&configuration, &login_domain)?;
            info!(
                event = "probe.cas_challenge",
                login_domain = challenge.login_domain(),
                login_url = %challenge.login_url
            );
        }
        Command::CasLogin {
            login_domain,
            webdriver_url,
            browser,
            timeout_seconds,
            keep_browser_open,
        } => {
            let configuration = client
                .auth_config(AuthConfigOptions {
                    modified: false,
                    need_ticket: true,
                })
                .await?;
            // configuration is only used to discover the CAS entry; intermediate aTrust
            // multi-step pages must finish in the browser before any credential harvest.
            let challenge = client.prepare_cas(&configuration, &login_domain)?;
            let kind = match browser.as_str() {
                "chrome" => BrowserKind::Chrome,
                "firefox" => BrowserKind::Firefox,
                other => {
                    return Err(
                        format!("unsupported browser `{other}`; use chrome or firefox").into(),
                    );
                }
            };
            let browser = WebDriverBrowser::connect(&webdriver_url, kind).await?;
            info!(
                event = "probe.cas_browser_waiting",
                note = "waiting for final portal entry after IDS and aTrust multi-step pages"
            );
            let exchange = match browser
                .complete_cas(challenge, std::time::Duration::from_secs(timeout_seconds))
                .await
            {
                Ok(exchange) => exchange,
                Err(error) => {
                    if !keep_browser_open && let Err(close_error) = browser.close().await {
                        warn!(event = "probe.cas_browser_close_failed", error = %close_error);
                    }
                    return Err(Box::new(error));
                }
            };
            info!(
                event = "probe.cas_completion_harvested",
                portal_ticket_received = true
            );
            drop(exchange);
            if !keep_browser_open {
                browser.close().await?;
            }
        }
    }
    Ok(())
}

fn random_hex(length: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| HEX[rng.random_range(0..HEX.len())] as char)
        .collect()
}
