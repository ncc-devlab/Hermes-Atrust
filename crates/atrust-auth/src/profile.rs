/// Audited HTTP compatibility values for a known aTrust client profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthProtocolProfile {
    pub user_agent: &'static str,
    pub client_type: &'static str,
    pub platform: &'static str,
    pub language: &'static str,
}

impl Default for AuthProtocolProfile {
    fn default() -> Self {
        Self {
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.4.10.50 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType",
            client_type: "SDPClient",
            platform: "Linux",
            language: "en-US",
        }
    }
}
