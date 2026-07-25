use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthConfigOptions {
    pub modified: bool,
    pub need_ticket: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthConfiguration {
    pub login_state: LoginState,
    pub methods: Vec<AuthInfo>,
    pub csrf_token: String,
    pub public_key: String,
    pub public_key_exponent: String,
    pub anti_replay_random: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginState {
    LoggedOut,
    LoggedIn,
    Unknown(i64),
}

impl From<i64> for LoginState {
    fn from(value: i64) -> Self {
        match value {
            0 => Self::LoggedOut,
            1 => Self::LoggedIn,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthInfo {
    pub login_domain: String,
    pub auth_type: String,
    pub auth_name: String,
    pub login_url: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthConfigEnvelope {
    pub data: AuthConfigData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthConfigData {
    #[serde(default)]
    pub auth_server_info_list: Vec<AuthInfo>,
    pub is_login: i64,
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub security: SecurityData,
    #[serde(default)]
    pub pub_key: String,
    #[serde(default)]
    pub pub_key_exp: String,
    #[serde(default)]
    pub anti_replay_rand: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecurityData {
    #[serde(default)]
    pub csrf_token: String,
}

impl From<AuthConfigData> for AuthConfiguration {
    fn from(data: AuthConfigData) -> Self {
        let csrf_token = if data.csrf_token.is_empty() {
            data.security.csrf_token
        } else {
            data.csrf_token
        };
        Self {
            login_state: data.is_login.into(),
            methods: data.auth_server_info_list,
            csrf_token,
            public_key: data.pub_key,
            public_key_exponent: data.pub_key_exp,
            anti_replay_random: data.anti_replay_rand,
        }
    }
}
