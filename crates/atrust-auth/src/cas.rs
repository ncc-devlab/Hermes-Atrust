use hermes_model::{GatewayEndpoint, SecretString};
use thiserror::Error;
use url::Url;

const MAX_CALLBACK_URL_LENGTH: usize = 16 * 1024;
const MAX_SERVICE_TICKET_LENGTH: usize = 8 * 1024;
const MAX_PORTAL_URL_LENGTH: usize = 16 * 1024;
pub const PORTAL_COMPLETION_PATH: &str = "/portal/shortcut.html";

/// Server-provided web login entry point plus strict aTrust callback validation rules.
#[derive(Debug, Eq, PartialEq)]
pub struct CasChallenge {
    pub login_url: Url,
    login_domain: String,
    callback_url: Url,
    portal_url: Url,
}

impl CasChallenge {
    pub(crate) fn new(
        endpoint: &GatewayEndpoint,
        login_domain: String,
        login_url: &str,
    ) -> Result<Self, CasError> {
        if login_url.is_empty() {
            return Err(CasError::MissingLoginUrl);
        }
        let base_url = Url::parse(&format!("https://{}/", auth_authority(endpoint)))
            .map_err(CasError::InvalidGatewayUrl)?;
        let login_url = base_url
            .join(login_url)
            .map_err(CasError::InvalidLoginUrl)?;
        if login_url.scheme() != "https" {
            return Err(CasError::InsecureLoginUrl);
        }
        let callback_url = base_url
            .join("/passport/v1/auth/cas")
            .map_err(CasError::InvalidGatewayUrl)?;
        let portal_url = base_url
            .join(PORTAL_COMPLETION_PATH)
            .map_err(CasError::InvalidGatewayUrl)?;
        Ok(Self {
            login_url,
            login_domain,
            callback_url,
            portal_url,
        })
    }

    pub fn login_domain(&self) -> &str {
        &self.login_domain
    }

    pub fn callback_url(&self) -> &Url {
        &self.callback_url
    }

    pub fn portal_url(&self) -> &Url {
        &self.portal_url
    }

    /// Intermediate IDS/aTrust CAS callbacks must stay in the browser so multi-step
    /// aTrust challenges can complete before any client-side credential harvest.
    pub fn is_callback_target(&self, callback: &Url) -> bool {
        callback.scheme() == "https"
            && callback.authority() == self.callback_url.authority()
            && callback.path() == "/passport/v1/auth/cas"
    }

    /// Final gateway page that means the browser login flow has actually entered aTrust.
    pub fn is_completion_target(&self, url: &Url) -> bool {
        url.scheme() == "https"
            && url.authority() == self.portal_url.authority()
            && url.path() == PORTAL_COMPLETION_PATH
    }

    /// Converts an untrusted browser callback into a single-use aTrust credential.
    pub fn finish(self, callback: &Url) -> Result<CasCallbackCredential, CasError> {
        if callback.as_str().len() > MAX_CALLBACK_URL_LENGTH {
            return Err(CasError::CallbackTooLong);
        }
        if callback.scheme() != "https" {
            return Err(CasError::InvalidCallbackScheme);
        }
        if callback.authority() != self.callback_url.authority() {
            return Err(CasError::InvalidCallbackAuthority);
        }
        if callback.path() != "/passport/v1/auth/cas" {
            return Err(CasError::InvalidCallbackPath);
        }
        if callback.fragment().is_some()
            || !callback.username().is_empty()
            || callback.password().is_some()
        {
            return Err(CasError::InvalidCallbackUrl);
        }

        let tickets: Vec<_> = callback
            .query_pairs()
            .filter(|(name, _)| name == "ticket")
            .map(|(_, value)| value.into_owned())
            .collect();
        if tickets.len() != 1 {
            return Err(CasError::InvalidTicketCount);
        }
        let domains: Vec<_> = callback
            .query_pairs()
            .filter(|(name, _)| name == "sfDomain")
            .map(|(_, value)| value.into_owned())
            .collect();
        if domains.len() != 1 || domains[0] != self.login_domain {
            return Err(CasError::LoginDomainMismatch);
        }
        let service_ticket = SecretString::new(
            tickets
                .into_iter()
                .next()
                .expect("ticket count was checked"),
        )
        .map_err(|_| CasError::MissingTicket)?;
        if service_ticket.expose().len() > MAX_SERVICE_TICKET_LENGTH {
            return Err(CasError::TicketTooLong);
        }
        Ok(CasCallbackCredential {
            service_ticket,
            login_domain: self.login_domain,
            callback_authority: self.callback_url.authority().to_owned(),
        })
    }

    /// Harvests the aTrust portal ticket only after the browser has entered the final page.
    pub fn finish_completion(self, completion: &Url) -> Result<CasExchange, CasError> {
        parse_portal_ticket(completion, self.portal_url.authority())
            .map(|portal_ticket| CasExchange { portal_ticket })
    }
}

/// Strictly validates a same-gateway portal redirect and extracts its ticket.
pub fn parse_portal_ticket(
    location: &Url,
    expected_authority: &str,
) -> Result<SecretString, CasError> {
    if location.as_str().len() > MAX_PORTAL_URL_LENGTH {
        return Err(CasError::PortalUrlTooLong);
    }
    if location.scheme() != "https" {
        return Err(CasError::InvalidPortalScheme);
    }
    if location.authority() != expected_authority {
        return Err(CasError::InvalidPortalAuthority);
    }
    if location.path() != PORTAL_COMPLETION_PATH {
        return Err(CasError::InvalidPortalPath);
    }
    if location.fragment().is_some()
        || !location.username().is_empty()
        || location.password().is_some()
    {
        return Err(CasError::InvalidPortalUrl);
    }
    let data: Vec<_> = location
        .query_pairs()
        .filter(|(name, _)| name == "data")
        .map(|(_, value)| value.into_owned())
        .collect();
    if data.len() != 1 {
        return Err(CasError::MissingPortalTicket);
    }
    #[derive(serde::Deserialize)]
    struct PortalData {
        ticket: String,
    }
    let portal: PortalData =
        serde_json::from_str(&data[0]).map_err(|_| CasError::InvalidPortalData)?;
    SecretString::new(portal.ticket).map_err(|_| CasError::MissingPortalTicket)
}

/// Credential returned by any web UI after a strictly validated aTrust callback.
///
/// School-specific cookies and form state intentionally never cross this boundary.
pub struct CasCallbackCredential {
    pub(crate) service_ticket: SecretString,
    pub(crate) login_domain: String,
    pub(crate) callback_authority: String,
}

impl std::fmt::Debug for CasCallbackCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CasCallbackCredential")
            .field("service_ticket", &"[REDACTED]")
            .field("login_domain", &self.login_domain)
            .field("callback_authority", &self.callback_authority)
            .finish()
    }
}

/// aTrust-owned ticket obtained after consuming an external CAS service ticket.
#[derive(Debug)]
pub struct CasExchange {
    pub portal_ticket: SecretString,
}

fn auth_authority(endpoint: &GatewayEndpoint) -> String {
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

#[derive(Debug, Error)]
pub enum CasError {
    #[error("server did not provide a CAS login URL")]
    MissingLoginUrl,
    #[error("server provided an invalid CAS login URL: {0}")]
    InvalidLoginUrl(#[source] url::ParseError),
    #[error("configured gateway cannot form a valid CAS URL: {0}")]
    InvalidGatewayUrl(#[source] url::ParseError),
    #[error("server-provided CAS login URL must use HTTPS")]
    InsecureLoginUrl,
    #[error("CAS callback must use HTTPS")]
    InvalidCallbackScheme,
    #[error("CAS callback authority does not match the configured gateway")]
    InvalidCallbackAuthority,
    #[error("CAS callback path is invalid")]
    InvalidCallbackPath,
    #[error("CAS callback URL contains forbidden components")]
    InvalidCallbackUrl,
    #[error("CAS callback URL exceeds the accepted length")]
    CallbackTooLong,
    #[error("CAS callback must contain exactly one ticket")]
    InvalidTicketCount,
    #[error("CAS service ticket exceeds the accepted length")]
    TicketTooLong,
    #[error("CAS callback login domain does not match the selected login method")]
    LoginDomainMismatch,
    #[error("CAS callback does not contain a ticket")]
    MissingTicket,
    #[error("requested CAS login domain is unavailable")]
    LoginDomainUnavailable,
    #[error("portal completion must use HTTPS")]
    InvalidPortalScheme,
    #[error("portal completion authority does not match the configured gateway")]
    InvalidPortalAuthority,
    #[error("portal completion path is invalid")]
    InvalidPortalPath,
    #[error("portal completion URL contains forbidden components")]
    InvalidPortalUrl,
    #[error("portal completion URL exceeds the accepted length")]
    PortalUrlTooLong,
    #[error("portal completion contains invalid ticket data")]
    InvalidPortalData,
    #[error("portal completion does not contain exactly one non-empty ticket")]
    MissingPortalTicket,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_callback_without_exposing_ticket() {
        let endpoint = GatewayEndpoint::new("atrust.example.edu", 443).unwrap();
        let challenge = CasChallenge::new(
            &endpoint,
            "cas-domain".to_owned(),
            "https://sso.example.edu/login",
        )
        .unwrap();
        let callback = Url::parse(
            "https://atrust.example.edu/passport/v1/auth/cas?sfDomain=cas-domain&ticket=secret-ticket",
        )
        .unwrap();
        let credential = challenge.finish(&callback).unwrap();
        assert_eq!(credential.service_ticket.expose(), "secret-ticket");
        assert!(!format!("{credential:?}").contains("secret-ticket"));
    }

    #[test]
    fn rejects_callback_from_another_gateway() {
        let endpoint = GatewayEndpoint::new("atrust.example.edu", 443).unwrap();
        let challenge = CasChallenge::new(
            &endpoint,
            "cas-domain".to_owned(),
            "https://sso.example.edu/login",
        )
        .unwrap();
        let callback =
            Url::parse("https://attacker.example/passport/v1/auth/cas?ticket=secret").unwrap();
        assert!(matches!(
            challenge.finish(&callback),
            Err(CasError::InvalidCallbackAuthority)
        ));
    }

    #[test]
    fn rejects_duplicate_ticket_and_mismatched_domain() {
        let endpoint = GatewayEndpoint::new("atrust.example.edu", 443).unwrap();
        let duplicate = Url::parse("https://atrust.example.edu/passport/v1/auth/cas?sfDomain=cas-domain&ticket=one&ticket=two").unwrap();
        assert!(matches!(
            CasChallenge::new(
                &endpoint,
                "cas-domain".to_owned(),
                "https://sso.example/login"
            )
            .unwrap()
            .finish(&duplicate),
            Err(CasError::InvalidTicketCount)
        ));

        let mismatch =
            Url::parse("https://atrust.example.edu/passport/v1/auth/cas?sfDomain=other&ticket=one")
                .unwrap();
        assert!(matches!(
            CasChallenge::new(
                &endpoint,
                "cas-domain".to_owned(),
                "https://sso.example/login"
            )
            .unwrap()
            .finish(&mismatch),
            Err(CasError::LoginDomainMismatch)
        ));
    }

    #[test]
    fn resolves_relative_login_url_against_configured_gateway() {
        let endpoint = GatewayEndpoint::new("atrust.example.edu", 443).unwrap();
        let challenge = CasChallenge::new(
            &endpoint,
            "cas-domain".to_owned(),
            "/passport/v1/auth/cas/start",
        )
        .unwrap();
        assert_eq!(
            challenge.login_url.as_str(),
            "https://atrust.example.edu/passport/v1/auth/cas/start"
        );
    }

    #[test]
    fn rejects_insecure_login_url_and_supports_ipv6_gateway() {
        let endpoint = GatewayEndpoint::new("atrust.example.edu", 443).unwrap();
        assert!(matches!(
            CasChallenge::new(&endpoint, "cas".to_owned(), "http://ids.example/login"),
            Err(CasError::InsecureLoginUrl)
        ));

        let ipv6 = GatewayEndpoint::new("2001:db8::1", 443).unwrap();
        let challenge =
            CasChallenge::new(&ipv6, "cas".to_owned(), "https://ids.example/login").unwrap();
        assert_eq!(
            challenge.callback_url().as_str(),
            "https://[2001:db8::1]/passport/v1/auth/cas"
        );
    }

    #[test]
    fn harvests_portal_ticket_only_from_final_completion_url() {
        let endpoint = GatewayEndpoint::new("atrust.example.edu", 443).unwrap();
        let challenge = CasChallenge::new(
            &endpoint,
            "cas-domain".to_owned(),
            "https://sso.example.edu/login",
        )
        .unwrap();
        let intermediate = Url::parse(
            "https://atrust.example.edu/passport/v1/auth/cas?sfDomain=cas-domain&ticket=service",
        )
        .unwrap();
        assert!(challenge.is_callback_target(&intermediate));
        assert!(!challenge.is_completion_target(&intermediate));

        let completion = Url::parse(
            "https://atrust.example.edu/portal/shortcut.html?data=%7B%22ticket%22%3A%22portal-secret%22%7D",
        )
        .unwrap();
        assert!(challenge.is_completion_target(&completion));
        let exchange = challenge.finish_completion(&completion).unwrap();
        assert_eq!(exchange.portal_ticket.expose(), "portal-secret");
        assert!(!format!("{exchange:?}").contains("portal-secret"));
    }
}
