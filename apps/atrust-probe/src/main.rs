use std::env;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use atrust_auth::{
    AuthClient, AuthConfigOptions, AuthConfiguration, FlowProtocol, LoginMethod,
    PasswordCredentials, SessionMaterial, SessionProgress, StoredSession, UnadvertisedNode,
    extract_sid_from_cookies, select_node,
};
use atrust_browser::{BrowserKind, WebDriverBrowser, append_trace_event};
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
        /// Save the raw response body so resource matching can be replayed offline
        /// with `resource-match --resource-file`. Server policy, not credentials.
        #[arg(long)]
        save_body: Option<PathBuf>,
    },
    /// Ask the resource matcher which app / node group carries a destination.
    ///
    /// Pure lookup against `clientResource`: no dial, no init frame, no tunnel.
    /// An unmatched destination is exactly what the data plane must refuse to
    /// send, so `matched=false` is a valid, expected result.
    ///
    /// With `--resource-file` this runs fully offline against a saved body.
    ResourceMatch {
        /// Destination as `host:port`; an IPv4 literal uses the IP table, a name
        /// uses the domain table (names are not resolved locally first).
        #[arg(long)]
        target: String,
        /// Flow protocol: tcp, udp, or icmp. ICMP ignores the port.
        #[arg(long, default_value = "tcp")]
        protocol: String,
        /// Match against a `clientResource` body saved by `client-resource --save-body`,
        /// with no session and no network. Takes precedence over `--session-file`.
        #[arg(long)]
        resource_file: Option<PathBuf>,
        /// Session saved earlier by `cas-login --session-file` or `password --session-file`.
        #[arg(long)]
        session_file: Option<PathBuf>,
        /// Also list every lower-ranked candidate, to inspect an ambiguous table.
        #[arg(long)]
        show_all: bool,
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
    /// This is a live data-plane action. It automatically matches the target to
    /// one appId/node group and may retry one transient establishment failure.
    /// Credentials and application data are never replayed.
    TcpDial {
        /// Login domain for the password path. Ignored with `--session-file`.
        #[arg(long, default_value = "local")]
        login_domain: String,
        /// Reuse a session saved by `cas-login --session-file` instead of logging in.
        #[arg(long)]
        session_file: Option<PathBuf>,
        /// Data-plane node `host:port`. Must be one of the endpoints advertised in
        /// clientResource unless `--allow-unadvertised-node` is set. Without it,
        /// every advertised endpoint is probed and the lowest-latency one wins.
        #[arg(long)]
        node: Option<String>,
        /// Permit a `--node` that the gateway never advertised.
        ///
        /// Selection is fail-closed by default: an address the server did not
        /// offer is either a stale note or a misdirection. Use this only while
        /// the advertised list is itself under investigation.
        #[arg(long)]
        allow_unadvertised_node: bool,
        /// Server-side destination the tunnel connects to, as `host:port`.
        #[arg(long)]
        target: String,
        /// Optional assertion for the automatically matched appId. A mismatch is
        /// rejected; this never overrides server policy.
        #[arg(long)]
        app_id: Option<String>,
        /// After the handshake, send a minimal `GET / HTTP/1.0` and read one app frame.
        #[arg(long)]
        send_http: bool,
        #[arg(long, default_value_t = atrust_tcp::TCP_DIAL_TIMEOUT.as_secs())]
        connect_timeout_seconds: u64,
        #[arg(long, default_value_t = atrust_tcp::TCP_DIAL_TIMEOUT.as_secs())]
        handshake_timeout_seconds: u64,
    },
    /// Phase D: one SID-only Get-IP exchange against a node, then disconnect.
    ///
    /// Unlike `cas-login --get-ip-node`, this reuses a stored session, so a
    /// Get-IP rerun costs one TLS connection instead of a full IDS + slider +
    /// SMS login. Starts no L3 session, TUN, DNS, or routes.
    GetIp {
        /// Login domain for the password path. Ignored with `--session-file`.
        #[arg(long, default_value = "local")]
        login_domain: String,
        /// Reuse a session saved by `cas-login --session-file`.
        #[arg(long)]
        session_file: Option<PathBuf>,
        /// Data-plane node `host:port`. Without it, every advertised endpoint is
        /// probed and the lowest-latency one wins.
        #[arg(long)]
        node: Option<String>,
        /// Permit a `--node` that the gateway never advertised.
        ///
        /// Selection is fail-closed by default: an address the server did not
        /// offer is either a stale note or a misdirection. Use this only while
        /// the advertised list is itself under investigation.
        #[arg(long)]
        allow_unadvertised_node: bool,
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,
    },
    /// Phase D milestone: one L3 session — Get-IP, one flow authorization, and
    /// one hand-built IP packet round trip.
    ///
    /// Deliberately stops there: no TUN, no DNS, no route changes. The packet is
    /// constructed in-process so a failure stays inside the protocol rather than
    /// spreading into the kernel routing table.
    L3Session {
        /// Login domain for the password path. Ignored with `--session-file`.
        #[arg(long, default_value = "local")]
        login_domain: String,
        /// Reuse a session saved by `cas-login --session-file`.
        #[arg(long)]
        session_file: Option<PathBuf>,
        /// Data-plane node `host:port`. Without it, every advertised endpoint is
        /// probed and the lowest-latency one wins.
        #[arg(long)]
        node: Option<String>,
        /// Permit a `--node` that the gateway never advertised.
        ///
        /// Selection is fail-closed by default: an address the server did not
        /// offer is either a stale note or a misdirection. Use this only while
        /// the advertised list is itself under investigation.
        #[arg(long)]
        allow_unadvertised_node: bool,
        /// Destination `host:port` for the authorized flow. Must be an IPv4
        /// literal: L3 carries packets, and resolving a name here would invent a
        /// destination the resource table never authorized.
        #[arg(long)]
        target: String,
        /// Optional assertion for the automatically matched appId. A mismatch is
        /// rejected; this never overrides the matched node group.
        #[arg(long)]
        app_id: Option<String>,
        /// Source port for the synthetic flow.
        #[arg(long, default_value_t = 40000)]
        src_port: u16,
        /// Packet to send after authorization.
        #[arg(long, value_enum, default_value_t = L3Probe::IcmpEcho)]
        probe: L3Probe,
        /// UDP application payload bytes, excluding the IPv4 and UDP headers.
        /// Valid only with `--probe udp`.
        #[arg(long, value_parser = clap::value_parser!(u16).range(0..=65507))]
        payload_bytes: Option<u16>,
        /// Skip the packet round trip and stop after authorization.
        #[arg(long)]
        auth_only: bool,
        /// Budget for TCP + TLS + Get-IP. Live Xidian TLS connect alone has been
        /// measured at ~6.3s, so keep this well above the 8s auth timeout.
        #[arg(long, default_value_t = 20)]
        connect_timeout_seconds: u64,
        /// How long to wait for one inbound packet after sending.
        #[arg(long, default_value_t = 10)]
        reply_timeout_seconds: u64,
        /// Refresh clientResource in the background while this L3 owner is alive.
        #[arg(long, default_value_t = 60)]
        resource_refresh_seconds: u64,
    },
}

/// Which hand-built packet `l3-session` sends.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum L3Probe {
    /// ICMP echo request. Round trips against any peer that answers ping, and
    /// needs no listening service at the destination.
    IcmpEcho,
    /// TCP SYN. Proves the five-tuple path but needs a listener to answer.
    TcpSyn,
    /// UDP datagram with a deterministic payload. E6 requires an authorized
    /// echo service so the returned bytes can be checked exactly.
    Udp,
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
    let client = Arc::new(AuthClient::new(endpoint.clone(), transport.clone()));

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
                                    Ok(response) => {
                                        report_get_ip(
                                            &response,
                                            node_port,
                                            cli.browser_trace_file.as_deref(),
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
        Command::ClientResource {
            session_file,
            save_body,
        } => {
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
            let body = client.client_resource_body(&configuration).await?;
            let resources = atrust_auth::ClientResources::from_json_bytes(&body)?;
            log_client_resources(&endpoint, &resources);
            if let Some(path) = save_body.as_deref() {
                std::fs::write(path, &body)?;
                info!(
                    event = "probe.client_resource_body_saved",
                    bytes = body.len(),
                    path = %path.display()
                );
            }
        }
        Command::ResourceMatch {
            target,
            protocol,
            resource_file,
            session_file,
            show_all,
        } => {
            let protocol = FlowProtocol::parse(&protocol)
                .ok_or("unsupported --protocol; use tcp, udp, or icmp")?;
            let (host, port) = parse_host_port(&target)?;
            let resources = if let Some(path) = resource_file.as_deref() {
                // Fully offline: no session, no gateway request.
                let body = std::fs::read(path)?;
                info!(
                    event = "probe.resource_file_loaded",
                    bytes = body.len(),
                    path = %path.display()
                );
                atrust_auth::ClientResources::from_json_bytes(&body)?
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
                client.client_resource(&configuration).await?
            };
            log_client_resources(&endpoint, &resources);
            report_resource_match(
                &resources,
                &endpoint,
                &host,
                port,
                protocol,
                show_all,
                cli.browser_trace_file.as_deref(),
            )?;
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
            // Then rank them the way the data-plane commands will. Reported even
            // when nothing is reachable, because "which endpoint would have been
            // chosen, and what did the others cost" is the question E1 asks.
            match select_node(
                &candidates,
                None,
                UnadvertisedNode::Reject,
                tls_policy,
                connect_timeout,
            )
            .await
            {
                Ok(selection) => {
                    report_node_selection(&selection, cli.browser_trace_file.as_deref())?;
                }
                Err(error) => {
                    warn!(event = "probe.node_select.failed", error = %error);
                }
            }
        }
        Command::TcpDial {
            login_domain,
            session_file,
            node,
            allow_unadvertised_node,
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

            // Resource match, node selection and the dial itself now belong to
            // the runtime. This arm keeps only the diagnostic parts: reporting
            // which resource authorized the target, measuring endpoint latency,
            // and the optional application round trip.
            let resources = client.client_resource(&configuration).await?;
            log_client_resources(&endpoint, &resources);
            let (target_host, target_port) = parse_host_port(&target)?;
            report_resource_match(
                &resources,
                &endpoint,
                &target_host,
                target_port,
                FlowProtocol::Tcp,
                false,
                cli.browser_trace_file.as_deref(),
            )?;
            let node_group_id = resources
                .routing_index()
                .match_destination(&target_host, target_port, FlowProtocol::Tcp)
                .map(|destination| destination.node_group_id().to_owned())
                .ok_or_else(|| {
                    format!(
                        "resource table does not authorize TCP target {target_host}:{target_port}"
                    )
                })?;

            let nodes = select_data_nodes(
                &resources,
                &endpoint,
                Some(&node_group_id),
                NodeChoice {
                    node: node.as_deref(),
                    allow_unadvertised: allow_unadvertised_node,
                    tls_policy,
                    connect_timeout: Duration::from_secs(connect_timeout_seconds.max(1)),
                    trace_file: cli.browser_trace_file.as_deref(),
                },
            )
            .await?;
            let endpoint_override = nodes
                .into_iter()
                .map(|node| atrust_client::L3NodeEndpoint::new(node.host, node.port))
                .collect::<Vec<_>>();

            let runtime = atrust_client::AtrustClient::start(
                Arc::clone(&client),
                configuration,
                material,
                atrust_client::AtrustClientConfig::new(endpoint.clone(), tls_policy)
                    .with_connect_timeout(Duration::from_secs(connect_timeout_seconds.max(1)))
                    .with_tcp_handshake_timeout(Duration::from_secs(
                        handshake_timeout_seconds.max(1),
                    ))
                    .with_endpoint_override(Some(endpoint_override)),
            )
            .await?;
            let events = report_events(runtime.events());

            if let Some(asserted) = app_id.as_deref() {
                let matched = runtime
                    .route(&target_host, target_port, FlowProtocol::Tcp)
                    .await
                    .ok_or_else(|| {
                        format!(
                            "resource table does not authorize TCP target {target_host}:{target_port}"
                        )
                    })?;
                if asserted != matched.app_id {
                    runtime.shutdown().await;
                    events.stop().await;
                    return Err(format!(
                        "--app-id {asserted} does not match resource appId {}",
                        matched.app_id
                    )
                    .into());
                }
            }

            info!(event = "probe.tcp_dial.begin", target_port, send_http);
            let dialed = match runtime.dial_tcp(&target_host, target_port).await {
                Ok(dialed) => dialed,
                Err(error) => {
                    runtime.shutdown().await;
                    events.stop().await;
                    return Err(error.into());
                }
            };
            let mut tunnel = dialed.tunnel;
            info!(
                event = "probe.tcp_dial.handshake_ok",
                node_port = dialed.node_port,
                target_port
            );

            // Optional application-layer round trip through the established tunnel.
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

            runtime.shutdown().await;
            events.stop().await;
            tunnel.close().await?;
            info!(event = "probe.tcp_dial.closed");
        }

        Command::GetIp {
            login_domain,
            session_file,
            node,
            allow_unadvertised_node,
            timeout_seconds,
        } => {
            let session = match session_file.as_deref() {
                Some(path) => restore_session(&client, transport.as_ref(), &endpoint, path).await?,
                None => {
                    password_session(&client, transport.as_ref(), &endpoint, login_domain).await?
                }
            };
            let (node_host, node_port) = resolve_data_node(
                &client,
                &session.configuration,
                &endpoint,
                None,
                NodeChoice {
                    node: node.as_deref(),
                    allow_unadvertised: allow_unadvertised_node,
                    tls_policy,
                    connect_timeout: Duration::from_secs(timeout_seconds.max(1)),
                    trace_file: cli.browser_trace_file.as_deref(),
                },
            )
            .await?;
            info!(
                event = "probe.get_ip.begin",
                node_port,
                login_method = session.login_method.as_str()
            );
            match atrust_l3::get_ipv4(atrust_l3::GetIpv4Request {
                node_host: &node_host,
                node_port,
                tls_policy,
                sid: &session.material.sid,
                timeout: Duration::from_secs(timeout_seconds.max(1)),
            })
            .await
            {
                Ok(response) => {
                    report_get_ip(&response, node_port, cli.browser_trace_file.as_deref())?;
                }
                Err(error) => {
                    append_probe_trace(
                        cli.browser_trace_file.as_deref(),
                        "get_ip_failed",
                        json!({ "node_port": node_port, "error": error.to_string() }),
                    )?;
                    return Err(error.into());
                }
            }
        }

        Command::L3Session {
            login_domain,
            session_file,
            node,
            allow_unadvertised_node,
            target,
            app_id,
            src_port,
            probe,
            payload_bytes,
            auth_only,
            connect_timeout_seconds,
            reply_timeout_seconds,
            resource_refresh_seconds,
        } => {
            // Everything below is assembly the runtime owns: this arm only
            // supplies diagnostics-specific choices (which node, which probe
            // packet) and reports what came back.
            let payload_bytes = match (probe, payload_bytes) {
                (L3Probe::Udp, Some(bytes)) => usize::from(bytes),
                (L3Probe::Udp, None) => 32,
                (_, Some(_)) => {
                    return Err("--payload-bytes is valid only with --probe udp".into());
                }
                (_, None) => 0,
            };
            let session = match session_file.as_deref() {
                Some(path) => restore_session(&client, transport.as_ref(), &endpoint, path).await?,
                None => {
                    password_session(&client, transport.as_ref(), &endpoint, login_domain).await?
                }
            };
            let EstablishedSession {
                configuration,
                material,
                ..
            } = session;
            log_session_material(&material);

            // L3 carries IP packets, so the destination must already be an
            // address. Resolving a name here would authorize a five-tuple the
            // server's domain resource never covered.
            let (target_host, target_port) = parse_host_port(&target)?;
            let target_ip: std::net::Ipv4Addr = target_host.parse().map_err(|_| {
                format!("--target must be an IPv4 literal for L3, got {target_host}")
            })?;
            let flow_protocol = match probe {
                L3Probe::IcmpEcho => FlowProtocol::Icmp,
                L3Probe::TcpSyn => FlowProtocol::Tcp,
                L3Probe::Udp => FlowProtocol::Udp,
            };
            // Node choice stays here: the probe measures reachability and
            // reports it, then hands the runtime an ordered candidate list.
            // The advertised order is not preference order (Xidian lists the
            // unreachable internal address first), so this ordering matters.
            let resources = client.client_resource(&configuration).await?;
            log_client_resources(&endpoint, &resources);
            report_resource_match(
                &resources,
                &endpoint,
                &target_host,
                target_port,
                flow_protocol,
                false,
                cli.browser_trace_file.as_deref(),
            )?;
            let node_group_id = resources
                .routing_index()
                .match_destination(&target_host, target_port, flow_protocol)
                .map(|destination| destination.node_group_id().to_owned())
                .ok_or_else(|| {
                    format!(
                        "resource table does not authorize {} target {target_host}:{target_port}",
                        flow_protocol.as_str()
                    )
                })?;
            let nodes = select_data_nodes(
                &resources,
                &endpoint,
                Some(&node_group_id),
                NodeChoice {
                    node: node.as_deref(),
                    allow_unadvertised: allow_unadvertised_node,
                    tls_policy,
                    connect_timeout: Duration::from_secs(connect_timeout_seconds.max(1)),
                    trace_file: cli.browser_trace_file.as_deref(),
                },
            )
            .await?;
            let node_port = nodes.first().expect("selection always returns a node").port;
            let endpoint_override = nodes
                .into_iter()
                .map(|node| atrust_client::L3NodeEndpoint::new(node.host, node.port))
                .collect::<Vec<_>>();

            let runtime = atrust_client::AtrustClient::start(
                Arc::clone(&client),
                configuration,
                material,
                atrust_client::AtrustClientConfig::new(endpoint.clone(), tls_policy)
                    .with_connect_timeout(Duration::from_secs(connect_timeout_seconds.max(1)))
                    .with_resource_refresh_interval(Duration::from_secs(
                        resource_refresh_seconds.max(1),
                    ))
                    .with_endpoint_override(Some(endpoint_override)),
            )
            .await?;
            // Subscribed before the first packet, so the establish and any VIP
            // change are on the stream rather than only in the log.
            let events = report_events(runtime.events());

            let route = runtime
                .route(&target_host, target_port, flow_protocol)
                .await
                .ok_or_else(|| {
                    format!(
                        "resource table does not authorize {} target {target_host}:{target_port}",
                        flow_protocol.as_str()
                    )
                })?;
            if let Some(asserted) = app_id.as_deref()
                && asserted != route.app_id
            {
                runtime.shutdown().await;
                return Err(format!(
                    "--app-id {asserted} does not match resource appId {}",
                    route.app_id
                )
                .into());
            }

            info!(
                event = "probe.l3_session.begin",
                node_port,
                target_port,
                protocol = flow_protocol.as_str(),
                app_id_present = !route.app_id.is_empty(),
                node_group_id = %route.node_group_id
            );

            // Ctrl-C must reach `shutdown`, not abort the process: an aborted
            // run leaves the node connection open and the gateway holding a
            // session it can only time out on its own.
            let outcome = tokio::select! {
                result = run_l3_probe(
                    &runtime,
                    probe,
                    target_ip,
                    target_port,
                    src_port,
                    payload_bytes,
                    auth_only,
                    reply_timeout_seconds,
                    node_port,
                    cli.browser_trace_file.as_deref(),
                ) => result,
                signal = tokio::signal::ctrl_c() => {
                    warn!(event = "probe.l3_session.interrupted");
                    signal.map_err(Into::into)
                }
            };

            runtime.shutdown().await;
            events.stop().await;
            info!(event = "probe.l3_session.closed");
            outcome?;
        }
    }
    Ok(())
}

/// Mirrors the runtime event stream into the log for a diagnostic run.
///
/// The runtime publishes state changes whether or not anyone listens; this
/// turns them into log lines so a probe run records the VIP change, reconnect
/// or protocol finding that a bare error return would have hidden.
struct EventReporter {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl EventReporter {
    async fn stop(mut self) {
        let _ = self.stop.send(true);
        let _ = (&mut self.task).await;
    }
}

fn report_events(mut stream: atrust_client::EventStream) -> EventReporter {
    let (stop, mut stop_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                delivery = stream.recv() => {
                    let Some(delivery) = delivery else { break };
                    match delivery {
                        atrust_client::EventDelivery::Event(event) => info!(
                            event = "probe.runtime_event",
                            kind = event.kind(),
                            severity = ?event.severity(),
                            detail = ?event
                        ),
                        // Losing an event is itself worth a line: a skipped VIP
                        // change would leave any consumer out of sync.
                        atrust_client::EventDelivery::Lagged { skipped } => warn!(
                            event = "probe.runtime_event_lagged",
                            skipped
                        ),
                    }
                }
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });
    EventReporter { stop, task }
}

/// Brings the node group up, sends one hand-built packet, and reports the reply.
///
/// The VIP has to be known before the packet is built: it is the source address
/// the gateway authorized, and a packet carrying anything else is rejected by
/// the runtime rather than sent.
#[allow(clippy::too_many_arguments)]
async fn run_l3_probe(
    runtime: &atrust_client::AtrustClient,
    probe: L3Probe,
    target_ip: std::net::Ipv4Addr,
    target_port: u16,
    src_port: u16,
    payload_bytes: usize,
    auth_only: bool,
    reply_timeout_seconds: u64,
    node_port: u16,
    trace_file: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let route = runtime
        .route(
            &target_ip.to_string(),
            target_port,
            match probe {
                L3Probe::IcmpEcho => FlowProtocol::Icmp,
                L3Probe::TcpSyn => FlowProtocol::Tcp,
                L3Probe::Udp => FlowProtocol::Udp,
            },
        )
        .await
        .ok_or("resource table does not authorize the target")?;

    let session = runtime.connect_node_group(&route.node_group_id).await?;
    report_get_ip(session.get_ip(), node_port, trace_file)?;
    let vip = session.vip();

    let packet = match probe {
        L3Probe::IcmpEcho => build_icmp_echo(vip, target_ip),
        L3Probe::TcpSyn => build_tcp_syn(vip, src_port, target_ip, target_port),
        L3Probe::Udp => build_udp_probe(vip, src_port, target_ip, target_port, payload_bytes),
    };

    let sent = if auth_only {
        runtime.authorize_ipv4(&packet).await
    } else {
        runtime.send_ipv4(&packet).await
    };
    let sent = match sent {
        Ok(sent) => sent,
        Err(error) => {
            append_probe_trace(
                trace_file,
                "l3_flow_auth_failed",
                json!({
                    "target": format!("{target_ip}:{target_port}"),
                    "app_id": route.app_id.as_str(),
                    "error": error.to_string(),
                }),
            )?;
            return Err(error.into());
        }
    };

    info!(
        event = "probe.l3_session.flow_authorized",
        flow = %sent.flow.flow_key(),
        connect_token_present = sent.connect_token_len > 0,
        connect_token_len = sent.connect_token_len
    );
    append_probe_trace(
        trace_file,
        "l3_flow_authorized",
        json!({
            "flow": sent.flow.flow_key().as_str(),
            "app_id": sent.app_id.as_str(),
            "node_group_id": sent.node_group_id.as_str(),
            "connect_token_len": sent.connect_token_len,
        }),
    )?;

    if auth_only {
        return Ok(());
    }

    info!(
        event = "probe.l3_session.packet_sent",
        bytes = packet.len(),
        probe = ?probe
    );
    match tokio::time::timeout(
        Duration::from_secs(reply_timeout_seconds.max(1)),
        sent.session.recv_packet(),
    )
    .await
    {
        Ok(Some(reply)) => {
            if matches!(probe, L3Probe::Udp) {
                validate_udp_echo(
                    &reply,
                    target_ip,
                    target_port,
                    vip,
                    src_port,
                    &udp_probe_payload(payload_bytes),
                )
                .map_err(|error| format!("UDP echo validation failed: {error}"))?;
            }
            let parsed = atrust_client::parse_ipv4_flow(&reply).ok();
            info!(
                event = "probe.l3_session.packet_received",
                bytes = reply.len(),
                parsed_as_ipv4 = parsed.is_some(),
                protocol = parsed
                    .as_ref()
                    .map(|flow| flow.protocol.scheme())
                    .unwrap_or("<unparsed>")
            );
        }
        Ok(None) if matches!(probe, L3Probe::Udp) => {
            return Err("L3 session closed before the UDP echo reply".into());
        }
        Ok(None) => warn!(event = "probe.l3_session.closed_before_reply"),
        Err(_) if matches!(probe, L3Probe::Udp) => {
            return Err(format!("UDP echo timed out after {reply_timeout_seconds}s").into());
        }
        Err(_) => warn!(
            event = "probe.l3_session.reply_timeout",
            seconds = reply_timeout_seconds
        ),
    }
    Ok(())
}

/// Resolves the data-plane node: explicit override wins, otherwise the first
/// advertised primary. Gateways commonly advertise a server-side loopback, so
/// the override is the normal case during bring-up.
async fn resolve_data_node(
    client: &AuthClient,
    configuration: &AuthConfiguration,
    endpoint: &GatewayEndpoint,
    node_group_id: Option<&str>,
    request: NodeChoice<'_>,
) -> Result<(String, u16), Box<dyn std::error::Error>> {
    let resources = client.client_resource(configuration).await?;
    select_data_node(&resources, endpoint, node_group_id, request).await
}

/// What the caller asked for, and what it costs to probe.
#[derive(Clone, Copy)]
struct NodeChoice<'a> {
    node: Option<&'a str>,
    allow_unadvertised: bool,
    tls_policy: TlsPolicy,
    connect_timeout: Duration,
    trace_file: Option<&'a Path>,
}

/// Probes every advertised endpoint and returns the one to dial.
///
/// Selection never silently substitutes: an explicit `--node` that is absent
/// from the advertised list, or present but unreachable, is an error. A quiet
/// fallback would make every later measurement unattributable — the operator
/// would believe they tested one node while having tested another.
async fn select_data_node(
    resources: &atrust_auth::ClientResources,
    endpoint: &GatewayEndpoint,
    node_group_id: Option<&str>,
    request: NodeChoice<'_>,
) -> Result<(String, u16), Box<dyn std::error::Error>> {
    let nodes = select_data_nodes(resources, endpoint, node_group_id, request).await?;
    let chosen = nodes.first().expect("selection always returns a node");
    Ok((chosen.host.clone(), chosen.port))
}

/// Returns all reachable endpoints in failover order. An explicit node remains
/// pinned and therefore yields exactly one candidate.
async fn select_data_nodes(
    resources: &atrust_auth::ClientResources,
    endpoint: &GatewayEndpoint,
    node_group_id: Option<&str>,
    request: NodeChoice<'_>,
) -> Result<Vec<atrust_auth::ResolvedNodeEndpoint>, Box<dyn std::error::Error>> {
    let candidates = match node_group_id {
        Some(group_id) => resources
            .node_group_endpoints(group_id, endpoint)
            .into_iter()
            .map(|node| (group_id.to_owned(), node))
            .collect(),
        None => resources.all_nodes(endpoint),
    };
    let unadvertised = if request.allow_unadvertised && node_group_id.is_none() {
        UnadvertisedNode::Allow
    } else {
        UnadvertisedNode::Reject
    };
    let selection = select_node(
        &candidates,
        request.node,
        unadvertised,
        request.tls_policy,
        request.connect_timeout,
    )
    .await?;
    report_node_selection(&selection, request.trace_file)?;
    Ok(selection.failover_endpoints())
}

/// Logs the full latency ranking, not just the winner: the alternatives are the
/// evidence for why this endpoint was picked.
fn report_node_selection(
    selection: &atrust_auth::NodeSelection,
    trace_file: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    for (rank, measurement) in selection.ranked.iter().enumerate() {
        info!(
            event = "probe.node_select.candidate",
            rank,
            group_id = %measurement.group_id,
            address = %measurement.address(),
            from_sdpc_placeholder = measurement.endpoint.from_sdpc_placeholder,
            outcome = %measurement.outcome,
            reachable = measurement.reachable(),
            elapsed_ms = u64::try_from(measurement.elapsed.as_millis()).unwrap_or(u64::MAX)
        );
    }
    info!(
        event = "probe.node_select.chosen",
        address = %selection.chosen.address(),
        group_id = %selection.chosen.group_id,
        source = selection.source.as_str(),
        elapsed_ms = u64::try_from(selection.chosen.elapsed.as_millis()).unwrap_or(u64::MAX),
        candidates = selection.ranked.len()
    );
    append_probe_trace(
        trace_file,
        "node_selected",
        json!({
            "chosen": selection.chosen.address(),
            "source": selection.source.as_str(),
            "candidates": selection
                .ranked
                .iter()
                .map(|measurement| json!({
                    "group_id": measurement.group_id,
                    "address": measurement.address(),
                    "outcome": measurement.outcome.to_string(),
                    "reachable": measurement.reachable(),
                    "elapsed_ms": u64::try_from(measurement.elapsed.as_millis()).unwrap_or(u64::MAX),
                }))
                .collect::<Vec<_>>(),
        }),
    )?;
    Ok(())
}

/// Logs and traces a Get-IP outcome.
///
/// The VIP is session-scoped, not a credential, and the `53 00` status body is
/// the one place a mask or second-VIP hint could appear — it is recorded verbatim
/// so a live Xidian run can be compared against a capture.
fn report_get_ip(
    response: &atrust_l3::GetIpv4Response,
    node_port: u16,
    trace_file: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        event = "probe.get_ip.succeeded",
        node_port,
        address_family = "ipv4",
        vip = %response.address,
        private = response.address.is_private(),
        address_type = response.address_type,
        vip_data_len = response.vip_data.len(),
        status_bodies = response.status_bodies.len(),
        status_text = %response.status_text()
    );
    append_probe_trace(
        trace_file,
        "get_ip_succeeded",
        json!({
            "node_port": node_port,
            "address_family": "ipv4",
            "vip": response.address.to_string(),
            "private": response.address.is_private(),
            "address_type": response.address_type,
            // Raw body: for addrType 5 this carries the IPv6 VIP, and the bytes
            // trailing an IPv4 VIP are still unexplained. Keep them verbatim.
            "vip_data_hex": response
                .vip_data
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "status_bodies": response
                .status_bodies
                .iter()
                .map(|body| String::from_utf8_lossy(body).into_owned())
                .collect::<Vec<_>>(),
        }),
    )?;
    Ok(())
}

/// Builds an ICMP echo request from `src` to `dst`.
fn build_icmp_echo(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr) -> Vec<u8> {
    let mut icmp = vec![
        8, 0, // echo request, code 0
        0, 0, // checksum placeholder
        0x13, 0x37, // identifier
        0x00, 0x01, // sequence
    ];
    icmp.extend_from_slice(b"hermes-l3-probe");
    let checksum = ones_complement_sum(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    ipv4_packet(src, dst, 1, &icmp)
}

/// Builds a bare TCP SYN from `src:src_port` to `dst:dst_port`.
fn build_tcp_syn(
    src: std::net::Ipv4Addr,
    src_port: u16,
    dst: std::net::Ipv4Addr,
    dst_port: u16,
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&0x1234_5678_u32.to_be_bytes()); // sequence
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
    tcp.push(5 << 4); // data offset 5 words, no flags in low nibble
    tcp.push(0x02); // SYN
    tcp.extend_from_slice(&64240u16.to_be_bytes()); // window
    tcp.extend_from_slice(&[0, 0]); // checksum placeholder
    tcp.extend_from_slice(&[0, 0]); // urgent pointer

    // TCP checksum covers a pseudo-header of the IP addresses, protocol and length.
    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&tcp);
    let checksum = ones_complement_sum(&pseudo);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

    ipv4_packet(src, dst, 6, &tcp)
}

fn udp_probe_payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(17))
        .collect()
}

/// Builds one UDP datagram whose payload can be reproduced for echo validation.
fn build_udp_probe(
    src: std::net::Ipv4Addr,
    src_port: u16,
    dst: std::net::Ipv4Addr,
    dst_port: u16,
    payload_bytes: usize,
) -> Vec<u8> {
    debug_assert!(payload_bytes <= 65_507);
    let payload = udp_probe_payload(payload_bytes);
    let udp_len = u16::try_from(8 + payload.len()).expect("validated UDP payload length");
    let mut udp = Vec::with_capacity(usize::from(udp_len));
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&payload);

    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let checksum = match ones_complement_sum(&pseudo) {
        0 => u16::MAX,
        checksum => checksum,
    };
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    ipv4_packet(src, dst, 17, &udp)
}

fn validate_udp_echo(
    packet: &[u8],
    expected_src: std::net::Ipv4Addr,
    expected_src_port: u16,
    expected_dst: std::net::Ipv4Addr,
    expected_dst_port: u16,
    expected_payload: &[u8],
) -> Result<(), String> {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return Err("reply is not a complete IPv4 UDP packet".to_owned());
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len + 8 > packet.len() {
        return Err("reply has an invalid IPv4 header length".to_owned());
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len != packet.len() {
        return Err(format!(
            "IPv4 length says {total_len} bytes but received {}",
            packet.len()
        ));
    }
    if ones_complement_sum(&packet[..header_len]) != 0 {
        return Err("invalid IPv4 header checksum".to_owned());
    }
    if packet[9] != 17 {
        return Err(format!("expected UDP protocol 17, got {}", packet[9]));
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return Err("fragmented UDP replies are not supported".to_owned());
    }
    let src = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if src != expected_src || dst != expected_dst {
        return Err(format!("unexpected addresses {src} -> {dst}"));
    }

    let udp = &packet[header_len..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if src_port != expected_src_port || dst_port != expected_dst_port {
        return Err(format!("unexpected UDP ports {src_port} -> {dst_port}"));
    }
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len != udp.len() || udp_len < 8 {
        return Err(format!(
            "UDP length says {udp_len} bytes but received {}",
            udp.len()
        ));
    }
    if udp[8..] != *expected_payload {
        return Err(format!(
            "UDP payload mismatch: expected {} bytes, received {}",
            expected_payload.len(),
            udp.len() - 8
        ));
    }
    let checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if checksum != 0 {
        let mut pseudo = Vec::with_capacity(12 + udp.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(udp);
        if ones_complement_sum(&pseudo) != 0 {
            return Err("invalid UDP checksum".to_owned());
        }
    }
    Ok(())
}

/// Wraps `payload` in an IPv4 header with a valid header checksum.
fn ipv4_packet(
    src: std::net::Ipv4Addr,
    dst: std::net::Ipv4Addr,
    protocol: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = (20 + payload.len()) as u16;
    let mut header = vec![
        0x45, // version 4, IHL 5
        0x00, // DSCP / ECN
    ];
    header.extend_from_slice(&total_len.to_be_bytes());
    header.extend_from_slice(&0xbeef_u16.to_be_bytes()); // identification
    header.extend_from_slice(&[0x40, 0x00]); // don't fragment
    header.push(64); // TTL
    header.push(protocol);
    header.extend_from_slice(&[0, 0]); // checksum placeholder
    header.extend_from_slice(&src.octets());
    header.extend_from_slice(&dst.octets());
    let checksum = ones_complement_sum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());

    header.extend_from_slice(payload);
    header
}

/// Internet checksum (RFC 1071): one's complement of the one's complement sum.
fn ones_complement_sum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds a data-plane destination: raw IPv4 target when `host` parses as an IPv4
/// literal, otherwise a domain target (handshake sends the domain bytes verbatim).
/// Reports which resource authorizes a destination, and therefore which `appId`
/// and node group would carry it. Pure lookup: it never dials, sends an init
/// frame, or opens a tunnel, and `matched=false` is a valid result — that is
/// exactly the case the data plane must refuse to send.
///
/// Resource identifiers (`appId`, `nodeGroupId`, node addresses) are server
/// policy metadata, not session secrets, and this command is useless without
/// them, so they are logged in full.
#[allow(clippy::too_many_arguments)]
fn report_resource_match(
    resources: &atrust_auth::ClientResources,
    gateway: &GatewayEndpoint,
    host: &str,
    port: u16,
    protocol: FlowProtocol,
    show_all: bool,
    trace_file: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let index = resources.routing_index();
    let matched = index.match_destination(host, port, protocol);
    match matched {
        Some(destination) => {
            let (port_min, port_max) = destination.port_range();
            let endpoints = resources.node_group_endpoints(destination.node_group_id(), gateway);
            info!(
                event = "probe.resource_match",
                matched = true,
                target_host = %host,
                target_port = port,
                flow_protocol = protocol.as_str(),
                match_kind = destination.kind(),
                app_id = %destination.app_id(),
                node_group_id = %destination.node_group_id(),
                resource_protocol = destination.protocol().as_str(),
                resource_port_min = port_min,
                resource_port_max = port_max,
                node_endpoint_count = endpoints.len()
            );
            for endpoint in &endpoints {
                info!(
                    event = "probe.resource_match_node",
                    node_group_id = %destination.node_group_id(),
                    address = %endpoint.socket_display(),
                    from_sdpc_placeholder = endpoint.from_sdpc_placeholder
                );
            }
            append_probe_trace(
                trace_file,
                "resource_matched",
                json!({
                    "target_host": host,
                    "target_port": port,
                    "flow_protocol": protocol.as_str(),
                    "match_kind": destination.kind(),
                    "app_id": destination.app_id(),
                    "node_group_id": destination.node_group_id(),
                    "resource_protocol": destination.protocol().as_str(),
                    "resource_port_min": port_min,
                    "resource_port_max": port_max,
                    "node_endpoints": endpoints
                        .iter()
                        .map(|endpoint| endpoint.socket_display())
                        .collect::<Vec<_>>(),
                }),
            )?;
        }
        None => {
            warn!(
                event = "probe.resource_match",
                matched = false,
                target_host = %host,
                target_port = port,
                flow_protocol = protocol.as_str(),
                ip_resource_count = index.ip_len(),
                domain_resource_count = index.domain_len(),
                note = "no resource authorizes this destination; the data plane must not send it"
            );
            append_probe_trace(
                trace_file,
                "resource_unmatched",
                json!({
                    "target_host": host,
                    "target_port": port,
                    "flow_protocol": protocol.as_str(),
                }),
            )?;
        }
    }

    if show_all {
        // Lower-ranked candidates expose an ambiguous table: the gateway's own
        // precedence rule is unconfirmed, so the full list is the evidence.
        let candidates: Vec<(String, String, &'static str)> =
            match host.parse::<std::net::Ipv4Addr>() {
                Ok(destination) => index
                    .match_ip_all(atrust_auth::FlowKey {
                        destination,
                        port,
                        protocol,
                    })
                    .into_iter()
                    .map(|resource| {
                        (
                            resource.app_id.clone(),
                            resource.node_group_id.clone(),
                            "ip",
                        )
                    })
                    .collect(),
                Err(_) => index
                    .match_domain_all(atrust_auth::DomainFlow {
                        host,
                        port,
                        protocol,
                    })
                    .into_iter()
                    .map(|resource| {
                        (
                            resource.app_id.clone(),
                            resource.node_group_id.clone(),
                            "domain",
                        )
                    })
                    .collect(),
            };
        for (rank, (app_id, node_group_id, kind)) in candidates.iter().enumerate() {
            info!(
                event = "probe.resource_match_candidate",
                rank,
                match_kind = kind,
                app_id = %app_id,
                node_group_id = %node_group_id
            );
        }
        info!(
            event = "probe.resource_match_candidates",
            candidate_count = candidates.len()
        );
    }
    Ok(())
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

    #[test]
    fn udp_probe_has_valid_lengths_checksums_and_payload() {
        let src = "10.210.29.48".parse().unwrap();
        let dst = "202.117.112.71".parse().unwrap();
        let packet = build_udp_probe(src, 40_000, dst, 7, 1_372);

        assert_eq!(packet.len(), 1_400);
        assert_eq!(packet[9], 17);
        assert_eq!(ones_complement_sum(&packet[..20]), 0);
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 1_400);
        assert_eq!(u16::from_be_bytes([packet[24], packet[25]]), 1_380);
        assert_eq!(&packet[28..], udp_probe_payload(1_372));
    }

    #[test]
    fn udp_echo_validation_accepts_exact_echo_and_rejects_corruption() {
        let vip = "10.210.29.48".parse().unwrap();
        let target = "202.117.112.71".parse().unwrap();
        let payload = udp_probe_payload(33);
        let mut reply = build_udp_probe(target, 7, vip, 40_000, payload.len());

        validate_udp_echo(&reply, target, 7, vip, 40_000, &payload).unwrap();
        *reply.last_mut().unwrap() ^= 1;
        assert!(
            validate_udp_echo(&reply, target, 7, vip, 40_000, &payload)
                .unwrap_err()
                .contains("payload mismatch")
        );
    }

    #[test]
    fn udp_probe_supports_ipv4_maximum_payload() {
        let packet = build_udp_probe(
            "192.0.2.1".parse().unwrap(),
            1,
            "198.51.100.2".parse().unwrap(),
            2,
            65_507,
        );
        assert_eq!(packet.len(), usize::from(u16::MAX));
    }

    #[test]
    fn cli_accepts_udp_payload_size_and_rejects_oversize() {
        let valid = Cli::try_parse_from([
            "atrust-probe",
            "--host",
            "gateway.test",
            "l3-session",
            "--target",
            "192.0.2.1:7",
            "--probe",
            "udp",
            "--payload-bytes",
            "1372",
        ]);
        assert!(valid.is_ok());

        let oversized = Cli::try_parse_from([
            "atrust-probe",
            "--host",
            "gateway.test",
            "l3-session",
            "--target",
            "192.0.2.1:7",
            "--probe",
            "udp",
            "--payload-bytes",
            "65508",
        ]);
        assert!(oversized.is_err());
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
