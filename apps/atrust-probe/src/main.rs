use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use atrust_auth::{AuthClient, AuthConfigOptions, PasswordCredentials, SessionProgress};
use clap::{Parser, Subcommand};
use hermes_logging::{LogFormat, LoggerConfig};
use hermes_model::{DeviceId, GatewayEndpoint, SecretString};
use hermes_transport::{HttpTransport, ReqwestTransport, ReqwestTransportConfig, TlsPolicy};
use rand::Rng as _;
use tracing::{error, info, warn};
use url::Url;

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
        /// Maximum wait while observing the browser. Harvest starts only after you close it.
        #[arg(long, default_value_t = 1800)]
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
    let client = AuthClient::new(endpoint.clone(), transport.clone());

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
                note = "finish IDS + aTrust MFA fully, then manually close the probe browser to harvest"
            );
            let login = match browser
                .complete_cas(challenge, std::time::Duration::from_secs(timeout_seconds))
                .await
            {
                Ok(login) => login,
                Err(error) => {
                    // Browser may already be closed by the user; ignore close failures.
                    let _ = browser.close().await;
                    return Err(Box::new(error));
                }
            };
            info!(
                event = "probe.cas_completion_harvested",
                portal_ticket_received = login.exchange.is_some(),
                portal_hits = login.portal_hits,
                final_path = login.final_path.as_deref().unwrap_or(""),
                gateway_cookie_count = login.gateway_cookies.len(),
                gateway_cookie_names = ?login
                    .gateway_cookies
                    .iter()
                    .map(|cookie| cookie.name.as_str())
                    .collect::<Vec<_>>()
            );
            let origin = Url::parse(&format!("https://{}/", gateway_authority(&endpoint)))?;
            let sid_present = login
                .gateway_cookies
                .iter()
                .any(|cookie| cookie.name.eq_ignore_ascii_case("sid"));
            if login.gateway_cookies.is_empty() {
                warn!(event = "probe.gateway_cookies_missing");
            } else {
                transport.import_gateway_cookies(&origin, &login.gateway_cookies)?;
            }
            // Refresh authConfig after browser login so csrf/login state match the session.
            let configuration = client
                .auth_config(AuthConfigOptions {
                    modified: true,
                    need_ticket: false,
                })
                .await?;
            info!(
                event = "probe.post_login_auth_config",
                login_state = ?configuration.login_state,
                csrf_present = !configuration.csrf_token.is_empty()
            );
            // Portal ticket is single-use and was already opened by the browser via continueRequest.
            // Prefer cookie-backed control-plane checks; only fall back to reportEnv if needed.
            let progress = match client.online_info(&configuration).await {
                Ok(username) => SessionProgress::Established {
                    username: Some(username),
                    sid_present,
                },
                Err(online_error) => {
                    warn!(event = "probe.online_info_failed", error = %online_error);
                    let step = match client.auth_check(&configuration).await {
                        Ok(step) => {
                            info!(
                                event = "probe.auth_check",
                                service = %step.service,
                                complete = step.is_complete()
                            );
                            Some(step)
                        }
                        Err(error) => {
                            warn!(event = "probe.auth_check_failed", error = %error);
                            None
                        }
                    };
                    if let Some(step) = step.filter(|step| !step.is_complete()) {
                        SessionProgress::InteractionRequired {
                            service: step.service,
                            auth_id: step.auth_id,
                        }
                    } else if let Some(exchange) = login.exchange.as_ref() {
                        let device_id = DeviceId::new(random_hex(32))?;
                        match client
                            .establish_session_from_portal(&configuration, exchange, &device_id)
                            .await
                        {
                            Ok(progress) => progress,
                            Err(error) => {
                                if !keep_browser_open
                                    && let Err(close_error) = browser.close().await
                                {
                                    warn!(
                                        event = "probe.cas_browser_close_failed",
                                        error = %close_error
                                    );
                                }
                                return Err(format!(
                                    "cookie session failed ({online_error}); portal reportEnv failed ({error})"
                                )
                                .into());
                            }
                        }
                    } else {
                        if !keep_browser_open && let Err(close_error) = browser.close().await {
                            warn!(event = "probe.cas_browser_close_failed", error = %close_error);
                        }
                        return Err(format!(
                            "cookie session failed ({online_error}); no post-MFA portal ticket available"
                        )
                        .into());
                    }
                }
            };
            match progress {
                SessionProgress::Established {
                    username,
                    sid_present,
                } => info!(
                    event = "probe.session_established",
                    username_present = username.is_some(),
                    sid_present
                ),
                SessionProgress::InteractionRequired { service, auth_id } => info!(
                    event = "probe.session_interaction_required",
                    service,
                    auth_id_present = auth_id.is_some()
                ),
            }
            // Session is usually already gone after the user closed the window.
            let _ = browser.close().await;
            let _ = keep_browser_open;
        }
    }
    Ok(())
}

fn gateway_authority(endpoint: &GatewayEndpoint) -> String {
    if endpoint.port() == 443 {
        let host = endpoint.host();
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host.to_owned()
        }
    } else {
        endpoint.to_string()
    }
}

fn random_hex(length: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| HEX[rng.random_range(0..HEX.len())] as char)
        .collect()
}
