use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use std::time::Duration;

use atrust_auth::{
    AuthClient, AuthConfigOptions, PasswordCredentials, SessionMaterial, SessionProgress,
    extract_sid_from_cookies,
};
use clap::{Parser, Subcommand};
use hermes_logging::{LogFormat, LoggerConfig};
use hermes_model::{DeviceId, GatewayEndpoint, SecretString};
use hermes_transport::{
    HttpTransport, ReqwestTransport, ReqwestTransportConfig, TlsPolicy, probe_node_tls,
};
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
    /// Fetch clientResource after an interactive session exists in this process.
    ///
    /// Run immediately after cas-login in the same process is not required; this command
    /// only uses the cookie jar of the current probe process. Prefer chaining after
    /// cas-login once session harvest lands, or import cookies via a future session store.
    ClientResource,
    /// TLS-only smoke probe of data-plane nodes (no init frame / tunnel).
    ///
    /// Without `--address`, loads `clientResource` from the current process cookie jar
    /// (typically after `cas-login` in the same process once a session store exists).
    NodeProbe {
        /// Probe every primary node (first endpoint of each group). Ignored with `--address`.
        #[arg(long, default_value_t = true)]
        primary: bool,
        /// Restrict to a single node group id when set.
        #[arg(long)]
        group: Option<String>,
        /// Direct `host:port` TLS probe without loading resources (Phase B smoke).
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value_t = 5)]
        timeout_seconds: u64,
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
                } => {
                    info!(
                        event = "probe.session_established",
                        username_present = username.is_some(),
                        sid_present
                    );
                    match build_session_material(&login.gateway_cookies, username.as_deref()) {
                        Ok(material) => {
                            let fields = material.log_fields();
                            info!(
                                event = "probe.session_material",
                                sid_present = fields.sid_present,
                                device_id_present = fields.device_id_present,
                                connection_id_present = fields.connection_id_present,
                                sign_key_present = fields.sign_key_present,
                                username_present = fields.username_present,
                                sign_key_provisional = fields.sign_key_provisional,
                                sid_cookie_name = fields.sid_cookie_name,
                                sid_sig_present = fields.sid_sig_present
                            );
                            let _ = material;
                        }
                        Err(error) => {
                            warn!(event = "probe.session_material_failed", error = %error)
                        }
                    }
                    match client.client_resource(&configuration).await {
                        Ok(resources) => log_client_resources(&endpoint, &resources),
                        Err(error) => warn!(event = "probe.client_resource_failed", error = %error),
                    }
                }
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
        Command::ClientResource => {
            let configuration = client
                .auth_config(AuthConfigOptions {
                    modified: true,
                    need_ticket: false,
                })
                .await?;
            info!(
                event = "probe.pre_resource_auth_config",
                login_state = ?configuration.login_state,
                csrf_present = !configuration.csrf_token.is_empty()
            );
            let resources = client.client_resource(&configuration).await?;
            log_client_resources(&endpoint, &resources);
        }
        Command::NodeProbe {
            primary,
            group,
            address,
            timeout_seconds,
        } => {
            let connect_timeout = Duration::from_secs(timeout_seconds.max(1));
            let candidates: Vec<(String, atrust_auth::ResolvedNodeEndpoint)> =
                if let Some(address) = address {
                    let (host, port) = parse_host_port(&address)?;
                    vec![(
                        String::new(),
                        atrust_auth::ResolvedNodeEndpoint {
                            host,
                            port,
                            address_type: "manual".to_owned(),
                            from_sdpc_placeholder: false,
                        },
                    )]
                } else {
                    let configuration = client
                        .auth_config(AuthConfigOptions {
                            modified: true,
                            need_ticket: false,
                        })
                        .await?;
                    info!(
                        event = "probe.pre_node_probe_auth_config",
                        login_state = ?configuration.login_state,
                        csrf_present = !configuration.csrf_token.is_empty()
                    );
                    let resources = client.client_resource(&configuration).await?;
                    log_client_resources(&endpoint, &resources);
                    let resolved = resources.resolve_node_groups(&endpoint);
                    if let Some(group_id) = group.as_deref() {
                        resolved
                            .into_iter()
                            .filter(|item| item.id == group_id)
                            .flat_map(|item| {
                                let id = item.id.clone();
                                item.endpoints
                                    .into_iter()
                                    .map(move |endpoint| (id.clone(), endpoint))
                            })
                            .collect()
                    } else if primary {
                        resources.primary_nodes(&endpoint)
                    } else {
                        resolved
                            .into_iter()
                            .flat_map(|item| {
                                let id = item.id.clone();
                                item.endpoints
                                    .into_iter()
                                    .map(move |endpoint| (id.clone(), endpoint))
                            })
                            .collect()
                    }
                };
            if candidates.is_empty() {
                warn!(event = "probe.node_probe_no_candidates");
                return Ok(());
            }
            for (group_id, node) in candidates {
                let result =
                    probe_node_tls(&node.host, node.port, tls_policy, connect_timeout).await;
                info!(
                    event = "probe.node_tls",
                    group_id_present = !group_id.is_empty(),
                    host_present = !node.host.is_empty(),
                    port = node.port,
                    from_sdpc_placeholder = node.from_sdpc_placeholder,
                    outcome = %result.outcome,
                    success = result.success(),
                    elapsed_ms = result.elapsed.as_millis()
                );
            }
        }
    }
    Ok(())
}

fn build_session_material(
    cookies: &[hermes_transport::GatewayCookie],
    username: Option<&str>,
) -> Result<SessionMaterial, atrust_auth::MaterialError> {
    let source = extract_sid_from_cookies(cookies)?;
    let device_id =
        DeviceId::new(random_hex(32)).map_err(atrust_auth::MaterialError::Identifier)?;
    SessionMaterial::from_cookie_sid(
        &source.value,
        source.cookie_name,
        source.sid_sig_present,
        device_id,
        username.map(str::to_owned),
        None,
    )
}

fn parse_host_port(value: &str) -> Result<(String, u16), Box<dyn std::error::Error>> {
    let value = value.trim();
    if value.is_empty() {
        return Err("address must not be empty".into());
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or("IPv6 address must be bracketed as [host]:port")?;
        let port = after
            .strip_prefix(':')
            .ok_or("IPv6 address must include :port")?
            .parse::<u16>()?;
        if port == 0 {
            return Err("port must not be zero".into());
        }
        return Ok((host.to_owned(), port));
    }
    let (host, port) = value.rsplit_once(':').ok_or("address must be host:port")?;
    if host.is_empty() {
        return Err("host must not be empty".into());
    }
    let port = port.parse::<u16>()?;
    if port == 0 {
        return Err("port must not be zero".into());
    }
    Ok((host.to_owned(), port))
}

fn log_client_resources(endpoint: &GatewayEndpoint, resources: &atrust_auth::ClientResources) {
    info!(
        event = "probe.client_resource",
        ip_resource_count = resources.ip_resources.len(),
        domain_resource_count = resources.domain_resources.len(),
        node_group_count = resources.node_groups.len(),
        major_node_group_present = resources.major_node_group_id.is_some(),
        dns_primary_present = resources.dns.primary.is_some(),
        dns_secondary_present = resources.dns.secondary.is_some()
    );
    let resolved = resources.resolve_node_groups(endpoint);
    let mut total_endpoints = 0usize;
    let mut sdpc_placeholders = 0usize;
    for group in &resolved {
        total_endpoints += group.endpoints.len();
        sdpc_placeholders += group
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.from_sdpc_placeholder)
            .count();
        info!(
            event = "probe.node_group_resolved",
            node_group_id_present = !group.id.is_empty(),
            endpoint_count = group.endpoints.len(),
            is_major = resources
                .major_node_group_id
                .as_deref()
                .is_some_and(|major| major == group.id)
        );
    }
    let primaries = resources.primary_nodes(endpoint);
    info!(
        event = "probe.nodes_summary",
        resolved_group_count = resolved.len(),
        resolved_endpoint_count = total_endpoints,
        primary_node_count = primaries.len(),
        sdpc_placeholder_count = sdpc_placeholders
    );
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
