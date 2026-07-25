use hermes_model::{GatewayEndpoint, SecretString};
use thiserror::Error;
use url::Url;

/// Server-provided CAS entry point plus strict callback validation rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CasChallenge {
    pub login_url: Url,
    login_domain: String,
    callback_authority: String,
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
            .expect("validated gateway endpoint always forms a URL");
        let login_url = base_url
            .join(login_url)
            .map_err(CasError::InvalidLoginUrl)?;
        Ok(Self {
            login_url,
            login_domain,
            callback_authority: auth_authority(endpoint),
        })
    }

    pub fn login_domain(&self) -> &str {
        &self.login_domain
    }

    /// Validates a callback captured by a separately configured browser or UI provider.
    pub fn validate_callback(&self, callback: &Url) -> Result<SecretString, CasError> {
        if callback.scheme() != "https" {
            return Err(CasError::InvalidCallbackScheme);
        }
        if callback.authority() != self.callback_authority {
            return Err(CasError::InvalidCallbackAuthority);
        }
        if callback.path() != "/passport/v1/auth/cas" {
            return Err(CasError::InvalidCallbackPath);
        }
        let ticket = callback
            .query_pairs()
            .find(|(name, _)| name == "ticket")
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty())
            .ok_or(CasError::MissingTicket)?;
        SecretString::new(ticket).map_err(|_| CasError::MissingTicket)
    }
}

fn auth_authority(endpoint: &GatewayEndpoint) -> String {
    if endpoint.port() == 443 {
        endpoint.host().to_owned()
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
    #[error("CAS callback must use HTTPS")]
    InvalidCallbackScheme,
    #[error("CAS callback authority does not match the configured gateway")]
    InvalidCallbackAuthority,
    #[error("CAS callback path is invalid")]
    InvalidCallbackPath,
    #[error("CAS callback does not contain a ticket")]
    MissingTicket,
    #[error("requested CAS login domain is unavailable")]
    LoginDomainUnavailable,
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
        let callback =
            Url::parse("https://atrust.example.edu/passport/v1/auth/cas?ticket=secret-ticket")
                .unwrap();
        let ticket = challenge.validate_callback(&callback).unwrap();
        assert_eq!(ticket.expose(), "secret-ticket");
        assert!(!format!("{ticket:?}").contains("secret-ticket"));
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
            challenge.validate_callback(&callback),
            Err(CasError::InvalidCallbackAuthority)
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
}
