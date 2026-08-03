use std::sync::Arc;
use std::time::Duration;

use hermes_model::SessionId;
use hermes_transport::TlsPolicy;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::warn;

use crate::{
    Ipv4Flow, L3_AUTH_TIMEOUT_RETRIES, L3_CLOSED_RETRIES, L3_HEARTBEAT_INTERVAL, L3AuthContext,
    L3Session, L3SessionConfig, L3SessionError,
};

/// Owned inputs for a reconnectable L3 connection to one selected node group.
#[derive(Clone, Debug)]
pub struct L3SessionManagerConfig {
    pub node_host: String,
    pub node_port: u16,
    pub node_group_id: String,
    pub tls_policy: TlsPolicy,
    pub sid: SessionId,
    pub connect_timeout: Duration,
    pub heartbeat_interval: Duration,
}

impl L3SessionManagerConfig {
    pub fn with_default_heartbeat(
        node_host: String,
        node_port: u16,
        node_group_id: String,
        tls_policy: TlsPolicy,
        sid: SessionId,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            node_host,
            node_port,
            node_group_id,
            tls_policy,
            sid,
            connect_timeout,
            heartbeat_interval: L3_HEARTBEAT_INTERVAL,
        }
    }
}

/// Authorization result tied to the exact session that issued the token.
#[derive(Debug)]
pub struct AuthorizedL3Flow {
    session: Arc<L3Session>,
    connect_token: String,
}

impl AuthorizedL3Flow {
    pub fn session(&self) -> &Arc<L3Session> {
        &self.session
    }

    pub fn connect_token(&self) -> &str {
        &self.connect_token
    }
}

/// Reconnect owner for one selected node group. It operates on raw IPv4 flows
/// and deliberately has no dependency on TUN, DNS, or system routes.
#[derive(Debug)]
pub struct L3SessionManager {
    config: L3SessionManagerConfig,
    current: Mutex<Option<Arc<L3Session>>>,
}

impl L3SessionManager {
    pub fn new(config: L3SessionManagerConfig) -> Self {
        Self {
            config,
            current: Mutex::new(None),
        }
    }

    /// Returns the live session, establishing Get-IP lazily when absent/closed.
    pub async fn session(&self) -> Result<Arc<L3Session>, L3SessionManagerError> {
        let mut current = self.current.lock().await;
        if let Some(session) = current.as_ref()
            && !session.is_closed()
        {
            return Ok(Arc::clone(session));
        }
        if let Some(closed) = current.take() {
            closed.close().await;
        }
        let session = Arc::new(
            L3Session::establish(L3SessionConfig {
                node_host: &self.config.node_host,
                node_port: self.config.node_port,
                tls_policy: self.config.tls_policy,
                sid: &self.config.sid,
                connect_timeout: self.config.connect_timeout,
                heartbeat_interval: self.config.heartbeat_interval,
            })
            .await?,
        );
        *current = Some(Arc::clone(&session));
        Ok(session)
    }

    /// Authorizes a flow, reconnecting on closed sessions and once after auth
    /// timeout. Explicit server policy failures are returned without retry.
    pub async fn authorize_flow(
        &self,
        ctx: &L3AuthContext<'_>,
        app_id: &str,
        flow: &Ipv4Flow,
    ) -> Result<AuthorizedL3Flow, L3SessionManagerError> {
        let mut budget = RetryBudget::default();
        self.authorize_with_budget(ctx, app_id, flow, &mut budget)
            .await
    }

    /// Authorizes and flushes one packet. A write-side disconnect reconnects,
    /// reauthorizes, and retries under the same bounded policy.
    pub async fn authorize_and_send(
        &self,
        ctx: &L3AuthContext<'_>,
        app_id: &str,
        flow: &Ipv4Flow,
        packet: &[u8],
    ) -> Result<AuthorizedL3Flow, L3SessionManagerError> {
        let mut budget = RetryBudget::default();
        loop {
            let authorized = self
                .authorize_with_budget(ctx, app_id, flow, &mut budget)
                .await?;
            match authorized
                .session
                .send_packet(&authorized.connect_token, packet)
                .await
            {
                Ok(()) => return Ok(authorized),
                Err(error) if budget.consume(&error) => {
                    self.invalidate(&authorized.session).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn authorize_with_budget(
        &self,
        ctx: &L3AuthContext<'_>,
        app_id: &str,
        flow: &Ipv4Flow,
        budget: &mut RetryBudget,
    ) -> Result<AuthorizedL3Flow, L3SessionManagerError> {
        loop {
            let session = self.session().await?;
            if session.vip() != flow.src_addr {
                return Err(L3SessionManagerError::VipChanged {
                    packet_source: flow.src_addr,
                    session_vip: session.vip(),
                });
            }
            match session
                .authorize_flow(ctx, app_id, &self.config.node_group_id, flow)
                .await
            {
                Ok(connect_token) => {
                    return Ok(AuthorizedL3Flow {
                        session,
                        connect_token,
                    });
                }
                Err(error) if budget.consume(&error) => self.invalidate(&session).await,
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn invalidate(&self, failed: &Arc<L3Session>) {
        let removed = {
            let mut current = self.current.lock().await;
            if current
                .as_ref()
                .is_some_and(|session| Arc::ptr_eq(session, failed))
            {
                current.take()
            } else {
                None
            }
        };
        if let Some(session) = removed {
            session.close().await;
        }
    }

    pub async fn close(&self) {
        if let Some(session) = self.current.lock().await.take() {
            session.close().await;
        }
    }
}

#[derive(Debug)]
struct RetryBudget {
    closed: usize,
    auth_timeout: usize,
}

impl Default for RetryBudget {
    fn default() -> Self {
        Self {
            closed: L3_CLOSED_RETRIES,
            auth_timeout: L3_AUTH_TIMEOUT_RETRIES,
        }
    }
}

impl RetryBudget {
    fn consume(&mut self, error: &L3SessionError) -> bool {
        let (remaining, reason) = match error {
            L3SessionError::Closed if self.closed > 0 => (&mut self.closed, "closed"),
            L3SessionError::AuthTimeout { .. } if self.auth_timeout > 0 => {
                (&mut self.auth_timeout, "auth_timeout")
            }
            _ => return false,
        };
        *remaining -= 1;
        warn!(
            event = "atrust_l3.manager.reconnect",
            reason,
            remaining_retries = *remaining
        );
        true
    }
}

#[derive(Debug, Error)]
pub enum L3SessionManagerError {
    #[error(transparent)]
    Session(#[from] L3SessionError),
    #[error("L3 reconnect changed VIP from packet source {packet_source} to {session_vip}")]
    VipChanged {
        packet_source: std::net::Ipv4Addr,
        session_vip: std::net::Ipv4Addr,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowAuthError;

    #[test]
    fn retry_budget_matches_zju_connect_boundaries() {
        let mut budget = RetryBudget::default();
        for _ in 0..L3_CLOSED_RETRIES {
            assert!(budget.consume(&L3SessionError::Closed));
        }
        assert!(!budget.consume(&L3SessionError::Closed));

        assert!(budget.consume(&L3SessionError::AuthTimeout {
            flow: "flow".to_owned(),
        }));
        assert!(!budget.consume(&L3SessionError::AuthTimeout {
            flow: "flow".to_owned(),
        }));
    }

    #[test]
    fn policy_rejection_is_never_retried() {
        let mut budget = RetryBudget::default();
        assert!(
            !budget.consume(&L3SessionError::FlowAuth(FlowAuthError::AuthFailed(
                "denied".to_owned()
            )))
        );
    }
}
