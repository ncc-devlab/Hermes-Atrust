use std::env;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use atrust_auth::{
    AuthClient, AuthConfigOptions, AuthConfiguration, LoginMethod, PasswordCredentials,
    SessionMaterial, SessionProgress, StoredSession, extract_sid_from_cookies,
};
use atrust_browser::{BrowserKind, WebDriverBrowser, append_trace_event};
use atrust_tcp::{DialTcpRequest, TunnelTarget, dial_tcp};
use clap::{Parser, Subcommand};
use hermes_logging::{LogFormat, LoggerConfig};
use hermes_model::{DeviceId, GatewayEndpoint, SecretString};
use hermes_transport::{
    HttpTransport, ReqwestTransport, ReqwestTransportConfig, TlsPolicy, probe_node_tls,
};
use rand::Rng as _;
use serde_json::json;
use tracing::{error, info, warn};
use url::Url;

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
    /// Append probe logs to this file (also still printed to stderr).
    #[arg(long)]
    log_file: Option<PathBuf>,
    /// Append a full-fidelity browser/control-plane trace as JSONL.
    ///
    /// The trace is deliberately NOT redacted: cookies, SID, SignKey, request
    /// bodies (including the CAS credential POST) and full URLs are written
    /// verbatim so a line can be diffed against a packet capture. The file is
    /// created 0600 — treat it as credential material and never attach it to a
    /// report. Diagnostic logs stay separate and default to `warn`.
    #[arg(long)]
    browser_trace_file: Option<PathBuf>,
    /// Whole-request HTTP timeout in seconds for gateway API calls.
    #[arg(long, default_value_t = 120)]
    http_timeout_seconds: u64,
    /// Maximum response body size for gateway API calls (bytes).
    #[arg(long, default_value_t = 32 * 1024 * 1024)]
    max_response_body: usize,
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
        /// Persist the resulting session so later subcommands can reuse it.
        /// The file holds live cookies, the SID, and the SignKey; it is forced to 0600.
        #[arg(long)]
        session_file: Option<PathBuf>,
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
        /// Phase B: after harvest + clientResource, TLS-smoke every advertised data-plane
        /// endpoint in this same process (no init frame, no tunnel). Off by default.
        #[arg(long)]
        probe_nodes: bool,
        /// Per-node TLS connect timeout (seconds) used by `--probe-nodes`.
        #[arg(long, default_value_t = 5)]
        node_connect_timeout_seconds: u64,
        /// Export a one-shot zju-connect client_data JSON after onlineInfo succeeds.
        /// The file contains live gateway cookies and is forced to mode 0600.
        #[arg(long)]
        zju_client_data_file: Option<PathBuf>,
        /// Persist the harvested session so `tcp-dial`, `node-probe`, and
        /// `client-resource` can reuse this CAS login in a later process instead
        /// of repeating IDS + slider + SMS. Forced to 0600; holds live cookies,
        /// the SID, the DeviceID/ConnectionID pair, and the SignKey.
        #[arg(long)]
        session_file: Option<PathBuf>,
        /// Perform one SID-only Get-IP exchange against this explicit `host:port` node.
        /// No L3 packet forwarding, TUN, DNS, routes, or retries are started.
        #[arg(long)]
        get_ip_node: Option<String>,
        #[arg(long, default_value_t = 8)]
        get_ip_timeout_seconds: u64,
    },
    /// Fetch clientResource for an existing session.
    ///
    /// Uses `--session-file` when given, otherwise the cookie jar of the current
    /// probe process (i.e. chained after `cas-login` in the same invocation).
    ClientResource {
        /// Session saved earlier by `cas-login --session-file` or `password --session-file`.
        #[arg(long)]
        session_file: Option<PathBuf>,
    },
    /// TLS-only smoke probe of data-plane nodes (no init frame / tunnel).
    ///
    /// Without `--address`, loads `clientResource` from `--session-file` when given,
    /// otherwise from the current process cookie jar.
    NodeProbe {
        /// Probe only the first endpoint of each group. By default every endpoint is probed.
        /// Ignored with `--address` or `--group`.
        #[arg(long)]
        primary: bool,
        /// Restrict to a single node group id when set.
        #[arg(long)]
        group: Option<String>,
        /// Direct `host:port` TLS probe without loading resources (Phase B smoke).
        #[arg(long)]
        address: Option<String>,
        /// Session saved earlier by `cas-login --session-file` or `password --session-file`.
        #[arg(long)]
        session_file: Option<PathBuf>,
        #[arg(long, default_value_t = 5)]
        timeout_seconds: u64,
    },
    /// Phase C: establish a session, then dial one TCP tunnel and complete the aTrust handshake.
    ///
    /// The login method matches the authentication stage: pass `--session-file` to reuse a
    /// session already established by `cas-login` (the only workable path on a gateway that
    /// requires CAS + MFA), or omit it to run one local password login from
    /// `HERMES_ATRUST_USERNAME` / `HERMES_ATRUST_PASSWORD`.
    /// This is a live data-plane action; it dials only the node you point it at and
    /// completes exactly one handshake to `--target`. Never auto-retries credentials.
    TcpDial {
        /// Login domain for the password path. Ignored with `--session-file`.
        #[arg(long, default_value = "local")]
        login_domain: String,
        /// Reuse a session saved by `cas-login --session-file` instead of logging in.
        #[arg(long)]
        session_file: Option<PathBuf>,
        /// Data-plane node `host:port`. Overrides the address advertised in clientResource
        /// (which is often a server-side loopback). Point this at the reachable node.
        #[arg(long)]
        node: Option<String>,
        /// Server-side destination the tunnel connects to, as `host:port`.
        #[arg(long)]
        target: String,
        /// appId carried in the init JSON (matches a clientResource app on strict gateways).
        #[arg(long, default_value = "app-lab")]
        app_id: String,
        /// After the handshake, send a minimal `GET / HTTP/1.0` and read one app frame.
        #[arg(long)]
        send_http: bool,
        #[arg(long, default_value_t = 8)]
        connect_timeout_seconds: u64,
        #[arg(long, default_value_t = 8)]
        handshake_timeout_seconds: u64,
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
        // Distribution builds default to warning-only; HERMES_LOG opts into diagnostics.
        default_filter: "warn".to_owned(),
        log_file: cli.log_file.clone(),
        ..LoggerConfig::default()
    };
    if let Err(error) = hermes_logging::init(&logger) {
        eprintln!("failed to initialize logger: {error}");
        return ExitCode::FAILURE;
    }
    // Warn level so this is visible under the distribution default filter: the
    // trace records live credentials verbatim and the operator must know.
    if let Some(path) = cli.browser_trace_file.as_deref() {
        warn!(
            event = "probe.trace_contains_credentials",
            path = %path.display(),
            note = "trace records cookies, SID, SignKey, and credential request bodies verbatim (file mode 0600)"
        );
    }
    info!(
        event = "probe.logger_ready",
        log_file = cli
            .log_file
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        http_timeout_seconds = cli.http_timeout_seconds,
        max_response_body = cli.max_response_body
    );

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(
                event = "probe.failed",
                error = %error,
                error_debug = ?error
            );
            let mut source = error.source();
            let mut depth = 0u32;
            while let Some(cause) = source {
                error!(
                    event = "probe.failed_cause",
                    depth,
                    cause = %cause,
                    cause_debug = ?cause
                );
                source = cause.source();
                depth += 1;
            }
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
    let http_timeout = Duration::from_secs(cli.http_timeout_seconds.max(1));
    let max_response_body = cli.max_response_body.max(1);
    let transport = Arc::new(ReqwestTransport::new(&ReqwestTransportConfig {
        tls_policy,
        timeout: http_timeout,
        max_response_body,
    })?);
    info!(
        event = "probe.transport_ready",
        timeout_ms = http_timeout.as_millis(),
        max_response_body
    );
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
        Command::Password {
            login_domain,
            session_file,
        } => {
            let session =
                password_session(&client, transport.as_ref(), &endpoint, login_domain.clone())
                    .await?;
            log_session_material(&session.material);
            append_probe_trace(
                cli.browser_trace_file.as_deref(),
                "session_material_assembled",
                session_material_trace(&session.material),
            )?;
            if let Some(path) = session_file.as_deref() {
                save_session_file(
                    path,
                    &endpoint,
                    LoginMethod::Password,
                    Some(login_domain),
                    &session.cookies,
                    &session.material,
                )?;
            }
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
            probe_nodes,
            node_connect_timeout_seconds,
            zju_client_data_file,
            session_file,
            get_ip_node,
            get_ip_timeout_seconds,
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
                .complete_cas(
                    challenge,
                    std::time::Duration::from_secs(timeout_seconds),
                    cli.browser_trace_file.as_deref(),
                )
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
            append_probe_trace(
                cli.browser_trace_file.as_deref(),
                "auth_config_checked",
                json!({
                    "login_state": format!("{:?}", configuration.login_state),
                    "csrf_present": !configuration.csrf_token.is_empty(),
                }),
            )?;
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
                    append_probe_trace(
                        cli.browser_trace_file.as_deref(),
                        "online_info_succeeded",
                        json!({
                            "username_present": username.is_some(),
                            "sid_present": sid_present,
                        }),
                    )?;
                    if let Some(path) = zju_client_data_file.as_deref() {
                        write_zju_client_data(path, &endpoint, &login.gateway_cookies)?;
                        info!(
                            event = "probe.zju_client_data_exported",
                            cookie_count = login.gateway_cookies.len()
                        );
                    }
                    match build_session_material(&login.gateway_cookies, username.as_deref()) {
                        Ok(material) => {
                            log_session_material(&material);
                            append_probe_trace(
                                cli.browser_trace_file.as_deref(),
                                "session_material_assembled",
                                session_material_trace(&material),
                            )?;
                            if let Some(path) = session_file.as_deref() {
                                // Persist the live jar, not just the harvested cookie list:
                                // the gateway may have set further cookies during onlineInfo
                                // and clientResource after the browser import.
                                save_session_file(
                                    path,
                                    &endpoint,
                                    LoginMethod::Cas,
                                    Some(login_domain.clone()),
                                    &transport.session_cookies(&origin),
                                    &material,
                                )?;
                            }
                            if let Some(node) = get_ip_node.as_deref() {
                                let (node_host, node_port) = parse_host_port(node)?;
                                match atrust_l3::get_ipv4(atrust_l3::GetIpv4Request {
                                    node_host: &node_host,
                                    node_port,
                                    tls_policy,
                                    sid: &material.sid,
                                    timeout: Duration::from_secs(get_ip_timeout_seconds.max(1)),
                                })
                                .await
                                {
                                    Ok(address) => {
                                        info!(
                                            event = "probe.get_ip.succeeded",
                                            node_port,
                                            address_family = "ipv4",
                                            private = address.is_private()
                                        );
                                        append_probe_trace(
                                            cli.browser_trace_file.as_deref(),
                                            "get_ip_succeeded",
                                            json!({
                                                "node_port": node_port,
                                                "address_family": "ipv4",
                                                "private": address.is_private(),
                                            }),
                                        )?;
                                    }
                                    Err(error) => {
                                        append_probe_trace(
                                            cli.browser_trace_file.as_deref(),
                                            "get_ip_failed",
                                            json!({
                                                "node_port": node_port,
                                                "error": error.to_string(),
                                            }),
                                        )?;
                                        return Err(error.into());
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            warn!(event = "probe.session_material_failed", error = %error)
                        }
                    }
                    match client.client_resource(&configuration).await {
                        Ok(resources) => {
                            append_probe_trace(
                                cli.browser_trace_file.as_deref(),
                                "client_resource_succeeded",
                                json!({
                                    "ip_resource_count": resources.ip_resources.len(),
                                    "domain_resource_count": resources.domain_resources.len(),
                                    "node_group_count": resources.node_groups.len(),
                                }),
                            )?;
                            log_client_resources(&endpoint, &resources);
                            // Phase B: TLS-only reachability smoke of every resolved endpoint,
                            // in-process where the harvested cookie jar exists. No init frame.
                            if probe_nodes {
                                let candidates = resources.all_nodes(&endpoint);
                                let connect_timeout =
                                    Duration::from_secs(node_connect_timeout_seconds.max(1));
                                probe_nodes_tls(
                                    &candidates,
                                    tls_policy,
                                    connect_timeout,
                                    cli.browser_trace_file.as_deref(),
                                )
                                .await?;
                            }
                        }
                        Err(error) => {
                            warn!(
                                event = "probe.client_resource_failed",
                                error = %error,
                                error_debug = ?error
                            );
                            let mut source = std::error::Error::source(&error);
                            let mut depth = 0u32;
                            while let Some(cause) = source {
                                warn!(
                                    event = "probe.client_resource_failed_cause",
                                    depth,
                                    cause = %cause,
                                    cause_debug = ?cause
                                );
                                source = cause.source();
                                depth += 1;
                            }
                        }
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
        Command::ClientResource { session_file } => {
            if let Some(path) = session_file.as_deref() {
                import_session_file(transport.as_ref(), &endpoint, path)?;
            }
            let configuration = client
                .auth_config(AuthConfigOptions {
                    modified: true,
                    need_ticket: false,
                })
                .await?;
            info!(
                event = "probe.pre_resource_auth_config",
                login_state = ?configuration.login_state,
                csrf_present = !configuration.csrf_token.is_empty(),
                http_timeout_seconds = cli.http_timeout_seconds,
                max_response_body = cli.max_response_body
            );
            let resources = client.client_resource(&configuration).await?;
            log_client_resources(&endpoint, &resources);
        }
        Command::NodeProbe {
            primary,
            group,
            address,
            session_file,
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
                    if let Some(path) = session_file.as_deref() {
                        import_session_file(transport.as_ref(), &endpoint, path)?;
                    }
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
                        resources.all_nodes(&endpoint)
                    }
                };
            probe_nodes_tls(
                &candidates,
                tls_policy,
                connect_timeout,
                cli.browser_trace_file.as_deref(),
            )
            .await?;
        }
        Command::TcpDial {
            login_domain,
            session_file,
            node,
            target,
            app_id,
            send_http,
            connect_timeout_seconds,
            handshake_timeout_seconds,
        } => {
            // 1. Establish the session the same way the authentication stage did.
            // A gateway behind CAS + MFA cannot be entered by password login at all,
            // so the stored-session path is the only usable one there.
            let session = match session_file.as_deref() {
                Some(path) => restore_session(&client, transport.as_ref(), &endpoint, path).await?,
                None => {
                    password_session(&client, transport.as_ref(), &endpoint, login_domain).await?
                }
            };
            info!(
                event = "probe.tcp_dial.session_ready",
                login_method = session.login_method.as_str()
            );
            let EstablishedSession {
                configuration,
                material,
                ..
            } = session;
            log_session_material(&material);
            append_probe_trace(
                cli.browser_trace_file.as_deref(),
                "session_material_assembled",
                session_material_trace(&material),
            )?;

            // 2. clientResource confirms authorization and can supply the node address.
            let resources = match client.client_resource(&configuration).await {
                Ok(resources) => {
                    log_client_resources(&endpoint, &resources);
                    Some(resources)
                }
                Err(error) => {
                    warn!(event = "probe.tcp_dial.client_resource_failed", error = %error);
                    None
                }
            };

            // 5. Resolve the node to dial: explicit override wins over advertised primary.
            let (node_host, node_port) = if let Some(node) = node {
                parse_host_port(&node)?
            } else {
                let primary = resources
                    .as_ref()
                    .and_then(|resources| resources.primary_nodes(&endpoint).into_iter().next());
                match primary {
                    Some((_, endpoint)) => (endpoint.host, endpoint.port),
                    None => {
                        return Err(
                            "no --node override and no primary node could be resolved".into()
                        );
                    }
                }
            };

            // 6. Build the server-side destination frame target.
            let (target_host, target_port) = parse_host_port(&target)?;
            let tunnel_target = build_tunnel_target(&target_host, target_port, &app_id);

            // 7. Dial + complete the aTrust TCP handshake.
            info!(
                event = "probe.tcp_dial.begin",
                node_port,
                target_port,
                app_id_present = !app_id.is_empty(),
                send_http
            );
            let request = DialTcpRequest {
                node_host: &node_host,
                node_port,
                tls_policy,
                sid: &material.sid,
                device_id: &material.device_id,
                connection_id: &material.connection_id,
                sign_key: &material.sign_key,
                username: material.username.as_deref().unwrap_or_default(),
                target: tunnel_target,
                process: None,
                lang: "en-US",
                connect_timeout: Duration::from_secs(connect_timeout_seconds.max(1)),
                handshake_timeout: Duration::from_secs(handshake_timeout_seconds.max(1)),
            };
            let mut tunnel = dial_tcp(request).await?;
            info!(
                event = "probe.tcp_dial.handshake_ok",
                node_port, target_port
            );

            // 8. Optional application-layer round trip through the established tunnel.
            if send_http {
                let http_request = format!(
                    "GET / HTTP/1.0\r\nHost: {target_host}\r\nUser-Agent: hermes-probe\r\nConnection: close\r\n\r\n"
                );
                tunnel.write_app(http_request.as_bytes()).await?;
                match tunnel.read_app().await? {
                    Some(data) => info!(
                        event = "probe.tcp_dial.app_response",
                        bytes = data.len(),
                        looks_like_http = data.starts_with(b"HTTP/")
                    ),
                    None => info!(event = "probe.tcp_dial.app_closed_by_peer"),
                }
            }

            tunnel.close().await?;
            info!(event = "probe.tcp_dial.closed");
        }
    }
    Ok(())
}

/// Builds a data-plane destination: raw IPv4 target when `host` parses as an IPv4
/// literal, otherwise a domain target (handshake sends the domain bytes verbatim).
fn build_tunnel_target(host: &str, port: u16, app_id: &str) -> TunnelTarget {
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => TunnelTarget::Ipv4 {
            ip,
            port,
            app_id: app_id.to_owned(),
        },
        Err(_) => TunnelTarget::Domain {
            host: host.to_owned(),
            port,
            app_id: app_id.to_owned(),
            resolved: None,
        },
    }
}

/// A control-plane session ready for data-plane use, however it was established.
struct EstablishedSession {
    configuration: AuthConfiguration,
    material: SessionMaterial,
    /// Gateway-scoped jar contents at the time the session became usable.
    cookies: Vec<hermes_transport::GatewayCookie>,
    login_method: LoginMethod,
}

/// Runs one local password login and assembles data-plane material from the
/// server-set SID. Never auto-solves a captcha and never retries credentials.
async fn password_session(
    client: &AuthClient,
    transport: &ReqwestTransport,
    endpoint: &GatewayEndpoint,
    login_domain: String,
) -> Result<EstablishedSession, Box<dyn std::error::Error>> {
    let username_env = env::var("HERMES_ATRUST_USERNAME")?;
    let password = SecretString::new(env::var("HERMES_ATRUST_PASSWORD")?)?;
    let credentials = PasswordCredentials::new(username_env, password, login_domain)?;
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
    if outcome.captcha_required {
        return Err("server requires a graphical captcha; aborting without auto-solve".into());
    }
    info!(
        event = "probe.password_primary_complete",
        captcha_required = outcome.captcha_required,
        ticket_received = outcome.ticket.is_some()
    );

    // Refresh authConfig for the logged-in csrf and confirm the session by cookie.
    let configuration = client
        .auth_config(AuthConfigOptions {
            modified: true,
            need_ticket: false,
        })
        .await?;
    let username = client.online_info(&configuration).await.ok();
    info!(
        event = "probe.password_session.online_info",
        username_present = username.is_some()
    );

    let origin = gateway_origin(endpoint)?;
    let sid_value = transport
        .session_cookie_value(&origin, "sid")
        .ok_or("no sid cookie present after password login")?;
    let sid_secret = SecretString::new(sid_value)?;
    let material =
        SessionMaterial::from_cookie_sid(&sid_secret, "sid", false, device_id, username, None)?;
    Ok(EstablishedSession {
        configuration,
        material,
        cookies: transport.session_cookies(&origin),
        login_method: LoginMethod::Password,
    })
}

/// Restores a session persisted by an earlier login, so a CAS + MFA session
/// harvested in one process can drive the data plane in another.
///
/// The stored DeviceID / ConnectionID / SignKey are reused verbatim: a gateway
/// that binds any of them to the session would reject freshly generated ones.
async fn restore_session(
    client: &AuthClient,
    transport: &ReqwestTransport,
    endpoint: &GatewayEndpoint,
    path: &Path,
) -> Result<EstablishedSession, Box<dyn std::error::Error>> {
    let stored = import_session_file(transport, endpoint, path)?;
    let configuration = client
        .auth_config(AuthConfigOptions {
            modified: true,
            need_ticket: false,
        })
        .await?;
    info!(
        event = "probe.session_file_auth_config",
        login_state = ?configuration.login_state,
        csrf_present = !configuration.csrf_token.is_empty()
    );
    // onlineInfo is the cheapest proof the restored cookies are still live; a
    // stale session must fail here rather than during the data-plane handshake.
    let username = client.online_info(&configuration).await?;
    info!(
        event = "probe.session_file_online_info",
        username_present = !username.is_empty()
    );
    let material = stored.to_material()?;
    let origin = gateway_origin(endpoint)?;
    Ok(EstablishedSession {
        configuration,
        material,
        cookies: transport.session_cookies(&origin),
        login_method: stored.login_method,
    })
}

/// Loads a stored session and imports its cookies into the process jar.
fn import_session_file(
    transport: &ReqwestTransport,
    endpoint: &GatewayEndpoint,
    path: &Path,
) -> Result<StoredSession, Box<dyn std::error::Error>> {
    let stored = StoredSession::load(path)?;
    stored.ensure_gateway(endpoint)?;
    let cookies = stored.gateway_cookies();
    let origin = gateway_origin(endpoint)?;
    transport.import_gateway_cookies(&origin, &cookies)?;
    info!(
        event = "probe.session_file_loaded",
        login_method = stored.login_method.as_str(),
        login_domain = stored.login_domain.as_deref().unwrap_or(""),
        cookie_count = cookies.len(),
        saved_unix_ms = stored.saved_unix_ms as u64,
        sign_key_provisional = stored.sign_key_provisional,
        path = %path.display()
    );
    Ok(stored)
}

fn save_session_file(
    path: &Path,
    endpoint: &GatewayEndpoint,
    login_method: LoginMethod,
    login_domain: Option<String>,
    cookies: &[hermes_transport::GatewayCookie],
    material: &SessionMaterial,
) -> Result<(), Box<dyn std::error::Error>> {
    let stored = StoredSession::capture(endpoint, login_method, login_domain, cookies, material);
    stored.save(path)?;
    info!(
        event = "probe.session_file_saved",
        login_method = login_method.as_str(),
        cookie_count = cookies.len(),
        path = %path.display()
    );
    Ok(())
}

fn gateway_origin(endpoint: &GatewayEndpoint) -> Result<Url, url::ParseError> {
    Url::parse(&format!("https://{}/", gateway_authority(endpoint)))
}

/// Presence-only session summary for the log stream, which is not owner-only.
fn log_session_material(material: &SessionMaterial) {
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
}

/// Full session material for the trace file. Unlike the log stream this records
/// raw values: the SID, DeviceID, ConnectionID, and SignKey are exactly what the
/// init JSON carries, and comparing them against a capture is the whole point of
/// the trace. The trace file is 0600; see `--browser-trace-file`.
fn session_material_trace(material: &SessionMaterial) -> serde_json::Value {
    let fields = material.log_fields();
    json!({
        "sid": material.sid.as_str(),
        "device_id": material.device_id.as_str(),
        "connection_id": material.connection_id.as_str(),
        "sign_key_hex": material.sign_key.to_hex_lower(),
        "username": material.username,
        "sid_cookie_name": fields.sid_cookie_name,
        "sid_sig_present": fields.sid_sig_present,
        "sign_key_provisional": fields.sign_key_provisional,
    })
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

/// Phase B: TLS-only reachability smoke of data-plane nodes. Connects TCP and
/// completes the TLS handshake to each candidate, then closes. It never sends an
/// init frame, opens a tunnel, or uses any session material (SID / SignKey), so
/// it is safe to run before the data-plane protocol is confirmed. Node addresses
/// are intentionally logged because this command is an explicit diagnostic probe.
async fn probe_nodes_tls(
    candidates: &[(String, atrust_auth::ResolvedNodeEndpoint)],
    tls_policy: TlsPolicy,
    connect_timeout: Duration,
    trace_file: Option<&Path>,
) -> Result<NodeProbeSummary, Box<dyn std::error::Error>> {
    if candidates.is_empty() {
        warn!(event = "probe.node_probe_no_candidates");
        return Ok(NodeProbeSummary::default());
    }
    let mut attempted = 0usize;
    let mut succeeded = 0usize;
    for (group_id, node) in candidates {
        let result = probe_node_tls(&node.host, node.port, tls_policy, connect_timeout).await;
        attempted += 1;
        if result.success() {
            succeeded += 1;
        }
        let elapsed_ms = u64::try_from(result.elapsed.as_millis()).unwrap_or(u64::MAX);
        info!(
            event = "probe.node_tls",
            group_id = %group_id,
            host = %node.host,
            address = %node.socket_display(),
            port = node.port,
            from_sdpc_placeholder = node.from_sdpc_placeholder,
            outcome = %result.outcome,
            success = result.success(),
            elapsed_ms
        );
        append_probe_trace(
            trace_file,
            "node_tls_probed",
            json!({
                "group_id": group_id,
                "host": node.host,
                "address": node.socket_display(),
                "port": node.port,
                "from_sdpc_placeholder": node.from_sdpc_placeholder,
                "outcome": result.outcome.to_string(),
                "success": result.success(),
                "elapsed_ms": elapsed_ms,
            }),
        )?;
    }
    info!(
        event = "probe.node_tls_summary",
        attempted,
        succeeded,
        failed = attempted - succeeded
    );
    append_probe_trace(
        trace_file,
        "node_tls_summary",
        json!({
            "attempted": attempted,
            "succeeded": succeeded,
            "failed": attempted - succeeded,
        }),
    )?;
    Ok(NodeProbeSummary {
        attempted,
        succeeded,
    })
}

/// Aggregate result of a Phase B TLS-only smoke pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NodeProbeSummary {
    attempted: usize,
    succeeded: usize,
}

fn append_probe_trace(
    path: Option<&Path>,
    kind: &str,
    data: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(path) = path {
        append_trace_event(path, kind, data)?;
    }
    Ok(())
}

fn write_zju_client_data(
    path: &Path,
    endpoint: &GatewayEndpoint,
    cookies: &[hermes_transport::GatewayCookie],
) -> Result<(), Box<dyn std::error::Error>> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let mut writer = BufWriter::new(file);
    let host = gateway_authority(endpoint);
    let value = json!({
        "cookies": cookies.iter().map(|cookie| json!({
            "host": host,
            "scheme": "https",
            "name": cookie.name,
            "value": cookie.value,
        })).collect::<Vec<_>>(),
        "device_id": "",
    });
    serde_json::to_writer(&mut writer, &value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn manual_node(host: String, port: u16) -> (String, atrust_auth::ResolvedNodeEndpoint) {
        (
            "major".to_owned(),
            atrust_auth::ResolvedNodeEndpoint {
                host,
                port,
                address_type: "manual".to_owned(),
                from_sdpc_placeholder: false,
            },
        )
    }

    #[tokio::test]
    async fn phase_b_empty_candidates_is_ok_and_zero() {
        let summary = probe_nodes_tls(&[], TlsPolicy::Verify, Duration::from_secs(1), None)
            .await
            .unwrap();
        assert_eq!(summary, NodeProbeSummary::default());
    }

    #[tokio::test]
    async fn phase_b_plain_tcp_peer_counts_as_failure_never_success() {
        // A plain-TCP listener speaks no TLS: the TCP connect half succeeds but the
        // TLS handshake must fail, so Phase B counts it attempted-but-not-succeeded.
        // This never sends an init frame and needs no session material.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept once and drop, giving the client an immediate TLS read EOF.
            let _ = listener.accept().await;
        });
        let candidates = vec![manual_node(addr.ip().to_string(), addr.port())];
        let summary = probe_nodes_tls(&candidates, TlsPolicy::Verify, Duration::from_secs(3), None)
            .await
            .unwrap();
        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.succeeded, 0);
    }

    #[test]
    fn zju_client_data_export_is_compatible_and_private() {
        let path = std::env::temp_dir().join(format!(
            "hermes-zju-client-data-{}-{}.json",
            std::process::id(),
            random_hex(8)
        ));
        let endpoint = GatewayEndpoint::new("gateway.test", 443).unwrap();
        let cookies = vec![hermes_transport::GatewayCookie {
            name: "sid".to_owned(),
            value: "secret-session".to_owned(),
            domain: Some("gateway.test".to_owned()),
            path: Some("/".to_owned()),
            secure: true,
            http_only: true,
        }];

        write_zju_client_data(&path, &endpoint, &cookies).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["device_id"], "");
        assert_eq!(value["cookies"][0]["host"], "gateway.test");
        assert_eq!(value["cookies"][0]["scheme"], "https");
        assert_eq!(value["cookies"][0]["name"], "sid");
        assert_eq!(value["cookies"][0]["value"], "secret-session");
        std::fs::remove_file(path).unwrap();
    }
}
