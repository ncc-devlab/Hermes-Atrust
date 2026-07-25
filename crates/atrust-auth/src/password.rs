use atrust_protocol::to_wire_json;
use hermes_model::SecretString;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::rand_core::OsRng;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::AuthConfiguration;

/// User input for one local password authentication attempt.
#[derive(Debug)]
pub struct PasswordCredentials {
    pub username: String,
    pub password: SecretString,
    pub login_domain: String,
}

impl PasswordCredentials {
    pub fn new(
        username: impl Into<String>,
        password: SecretString,
        login_domain: impl Into<String>,
    ) -> Result<Self, PasswordError> {
        let username = username.into();
        let login_domain = login_domain.into();
        if username.is_empty() {
            return Err(PasswordError::EmptyUsername);
        }
        if login_domain.is_empty() {
            return Err(PasswordError::EmptyLoginDomain);
        }
        Ok(Self {
            username,
            password,
            login_domain,
        })
    }
}

/// Result of the primary password step. Follow-up authentication is handled separately.
#[derive(Debug)]
pub struct PasswordAuthOutcome {
    pub ticket: Option<SecretString>,
    pub captcha_required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasswordRequest<'a> {
    username: String,
    password: String,
    remember_pwd: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    graph_check_code: Option<&'a str>,
}

impl<'a> PasswordRequest<'a> {
    pub(crate) fn build(
        configuration: &AuthConfiguration,
        credentials: &PasswordCredentials,
        graph_check_code: Option<&'a str>,
    ) -> Result<Vec<u8>, PasswordError> {
        let modulus = BigUint::parse_bytes(configuration.public_key.as_bytes(), 16)
            .ok_or(PasswordError::InvalidPublicKey)?;
        let exponent = configuration
            .public_key_exponent
            .parse::<u64>()
            .map(BigUint::from)
            .map_err(|_| PasswordError::InvalidPublicKeyExponent)?;
        let public_key =
            RsaPublicKey::new(modulus, exponent).map_err(PasswordError::InvalidRsaKey)?;
        let plaintext = format!(
            "{}_{}",
            credentials.password.expose(),
            configuration.anti_replay_random
        );
        let encrypted = public_key
            .encrypt(&mut OsRng, Pkcs1v15Encrypt, plaintext.as_bytes())
            .map_err(PasswordError::Encrypt)?;
        let request = Self {
            username: format!("{}@{}", credentials.username, credentials.login_domain),
            password: hex::encode(encrypted),
            remember_pwd: "0",
            graph_check_code,
        };
        to_wire_json(&request).map_err(PasswordError::Serialize)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct PasswordEnvelope {
    pub code: i64,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub data: PasswordResponseData,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasswordResponseData {
    #[serde(default)]
    pub ticket: String,
    #[serde(default)]
    pub graph_check_code_enable: i64,
}

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("username must not be empty")]
    EmptyUsername,
    #[error("login domain must not be empty")]
    EmptyLoginDomain,
    #[error("server provided an invalid RSA modulus")]
    InvalidPublicKey,
    #[error("server provided an invalid RSA exponent")]
    InvalidPublicKeyExponent,
    #[error("server provided an unusable RSA public key: {0}")]
    InvalidRsaKey(#[source] rsa::Error),
    #[error("failed to encrypt password: {0}")]
    Encrypt(#[source] rsa::Error),
    #[error("failed to serialize password request: {0}")]
    Serialize(#[source] atrust_protocol::ProtocolJsonError),
}
