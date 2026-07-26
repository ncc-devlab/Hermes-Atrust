use hermes_model::{DeviceId, SecretString};
use serde::{Deserialize, Serialize};

/// Progress after consuming a portal ticket and running the first control-plane steps.
#[derive(Debug)]
pub enum SessionProgress {
    /// Gateway accepted the portal ticket and no further aTrust auth services were requested.
    Established {
        username: Option<String>,
        sid_present: bool,
    },
    /// Gateway requires another aTrust-layer interaction that must stay manual.
    InteractionRequired {
        service: String,
        auth_id: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
pub(crate) struct BusinessEnvelope<T> {
    pub code: i64,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub data: T,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthStepData {
    #[serde(default)]
    pub next_service: String,
    #[serde(default)]
    pub next_service_list: Vec<AuthServiceInfo>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthServiceInfo {
    #[serde(default)]
    pub auth_id: String,
    #[serde(default)]
    pub auth_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthStep {
    pub service: String,
    pub auth_id: Option<String>,
}

impl AuthStep {
    pub(crate) fn from_data(data: AuthStepData) -> Self {
        let mut service = data.next_service;
        let mut auth_id = None;
        let selected = data
            .next_service_list
            .iter()
            .find(|item| !service.is_empty() && item.auth_type == service)
            .or_else(|| data.next_service_list.first());
        if let Some(item) = selected {
            if !item.auth_id.is_empty() {
                auth_id = Some(item.auth_id.clone());
            }
            if service.is_empty() {
                service = item.auth_type.clone();
            }
        }
        if service.is_empty() && auth_id.is_some() {
            service = "auth/sms".to_owned();
        }
        Self { service, auth_id }
    }

    pub fn is_complete(&self) -> bool {
        self.service.is_empty()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReportEnvRequest<'a> {
    ticket: &'a str,
    device_id: &'a str,
    env: ReportEnvBody<'a>,
}

#[derive(Serialize)]
struct ReportEnvBody<'a> {
    endpoint: ReportEnvEndpoint<'a>,
}

#[derive(Serialize)]
struct ReportEnvEndpoint<'a> {
    device_id: &'a str,
    device: ReportEnvDevice,
}

#[derive(Serialize)]
struct ReportEnvDevice {
    #[serde(rename = "type")]
    device_type: &'static str,
}

impl<'a> ReportEnvRequest<'a> {
    pub(crate) fn new(ticket: &'a SecretString, device_id: &'a DeviceId) -> Self {
        Self {
            ticket: ticket.expose(),
            device_id: device_id.as_str(),
            env: ReportEnvBody {
                endpoint: ReportEnvEndpoint {
                    device_id: device_id.as_str(),
                    device: ReportEnvDevice {
                        device_type: "browser",
                    },
                },
            },
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OnlineInfoData {
    #[serde(default)]
    pub username: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_next_service_means_auth_complete() {
        let step = AuthStep::from_data(AuthStepData::default());
        assert!(step.is_complete());
    }

    #[test]
    fn selects_matching_service_and_auth_id() {
        let step = AuthStep::from_data(AuthStepData {
            next_service: "auth/sms".to_owned(),
            next_service_list: vec![AuthServiceInfo {
                auth_id: "sms-1".to_owned(),
                auth_type: "auth/sms".to_owned(),
            }],
        });
        assert_eq!(step.service, "auth/sms");
        assert_eq!(step.auth_id.as_deref(), Some("sms-1"));
    }
}
