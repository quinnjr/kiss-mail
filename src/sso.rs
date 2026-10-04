//! SSO (Single Sign-On) integration module.
//!
//! Provides OIDC/OAuth2 authentication for SSO providers:
//! - 1Password
//! - Google Workspace
//! - Microsoft Entra ID (Azure AD)
//! - Okta
//! - Auth0
//! - Keycloak
//! - Any OIDC-compliant provider
//!
//! For email clients that don't support OAuth2, app passwords can be generated.

use crate::config::env_nonempty;
use chrono::{DateTime, Duration, Utc};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Well-known OIDC provider configurations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SsoProvider {
    /// 1Password Business/Enterprise
    OnePassword,
    /// Google Workspace
    Google,
    /// Microsoft Entra ID (Azure AD)
    Microsoft,
    /// Okta
    Okta,
    /// Auth0
    Auth0,
    /// Keycloak
    Keycloak,
    /// Generic OIDC provider
    Generic,
}

impl SsoProvider {
    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::OnePassword => "1Password",
            Self::Google => "Google",
            Self::Microsoft => "Microsoft",
            Self::Okta => "Okta",
            Self::Auth0 => "Auth0",
            Self::Keycloak => "Keycloak",
            Self::Generic => "OIDC",
        }
    }
}

/// SSO configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfig {
    /// SSO enabled
    pub enabled: bool,
    /// SSO provider type
    pub provider: SsoProvider,
    /// OAuth2 Client ID
    pub client_id: String,
    /// OAuth2 Client Secret
    pub client_secret: String,
    /// Authorization endpoint URL
    pub auth_url: String,
    /// Token endpoint URL
    pub token_url: String,
    /// UserInfo endpoint URL (optional)
    pub userinfo_url: Option<String>,
    /// OIDC issuer URL (for discovery)
    pub issuer_url: Option<String>,
    /// Redirect URI for OAuth2 callback
    pub redirect_uri: String,
    /// Required scopes
    pub scopes: Vec<String>,
    /// Map OIDC claims to username
    pub username_claim: String,
    /// Map OIDC claims to email
    pub email_claim: String,
    /// Map OIDC claims to display name
    pub name_claim: String,
    /// Allow app passwords for mail clients
    pub allow_app_passwords: bool,
    /// App password length
    pub app_password_length: usize,
    /// Email domains accepted for SSO identities (`user@domain` -> `user`).
    /// Required: an empty list disables SSO login (see `validate`).
    /// Matched exactly unless `allow_subdomains` is set; parents are never
    /// accepted. Read from `SSO_ALLOWED_DOMAIN` (comma-separated), falling
    /// back to `KISS_MAIL_DOMAIN`.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Also accept subdomains of an allowed domain
    /// (`SSO_ALLOW_SUBDOMAINS=true`; default `false`).
    #[serde(default)]
    pub allow_subdomains: bool,
    /// Microsoft Entra tenant the provider is pinned to
    /// (`MICROSOFT_TENANT_ID`). Required for the Microsoft provider: the
    /// multi-tenant authorities (`common`, `organizations`, `consumers`) are
    /// refused by `validate`.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

impl Default for SsoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: SsoProvider::Generic,
            client_id: String::new(),
            client_secret: String::new(),
            auth_url: String::new(),
            token_url: String::new(),
            userinfo_url: None,
            issuer_url: None,
            redirect_uri: "http://localhost:8080/callback".to_string(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            username_claim: "preferred_username".to_string(),
            email_claim: "email".to_string(),
            name_claim: "name".to_string(),
            allow_app_passwords: true,
            app_password_length: 24,
            allowed_domains: Vec::new(),
            allow_subdomains: false,
            tenant_id: None,
        }
    }
}

impl SsoConfig {
    /// Create config from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Check for provider-specific env vars first
        if let Ok(client_id) = std::env::var("ONEPASSWORD_CLIENT_ID") {
            config.provider = SsoProvider::OnePassword;
            config.client_id = client_id;
            config.enabled = true;
            if let Ok(secret) = std::env::var("ONEPASSWORD_CLIENT_SECRET") {
                config.client_secret = secret;
            }
            // 1Password uses their own SSO endpoints
            config.auth_url = std::env::var("ONEPASSWORD_AUTH_URL")
                .unwrap_or_else(|_| "https://app.1password.com/oauth/authorize".to_string());
            config.token_url = std::env::var("ONEPASSWORD_TOKEN_URL")
                .unwrap_or_else(|_| "https://app.1password.com/oauth/token".to_string());
            // No well-known UserInfo endpoint: must be configured explicitly
            // (ONEPASSWORD_USERINFO_URL or SSO_USERINFO_URL), otherwise the
            // provider is disabled by `validate()` below.
            config.userinfo_url = std::env::var("ONEPASSWORD_USERINFO_URL")
                .ok()
                .filter(|s| !s.trim().is_empty());
        } else if let Ok(client_id) = std::env::var("GOOGLE_CLIENT_ID") {
            config.provider = SsoProvider::Google;
            config.client_id = client_id;
            config.enabled = true;
            if let Ok(secret) = std::env::var("GOOGLE_CLIENT_SECRET") {
                config.client_secret = secret;
            }
            config.auth_url = "https://accounts.google.com/o/oauth2/v2/auth".to_string();
            config.token_url = "https://oauth2.googleapis.com/token".to_string();
            config.userinfo_url =
                Some("https://openidconnect.googleapis.com/v1/userinfo".to_string());
        } else if let Ok(client_id) = std::env::var("MICROSOFT_CLIENT_ID") {
            config.provider = SsoProvider::Microsoft;
            config.client_id = client_id;
            config.enabled = true;
            if let Ok(secret) = std::env::var("MICROSOFT_CLIENT_SECRET") {
                config.client_secret = secret;
            }
            // No default tenant: `validate()` disables the provider unless a
            // specific tenant is configured (see `MULTI_TENANT_AUTHORITIES`).
            config.tenant_id = env_nonempty("MICROSOFT_TENANT_ID").map(|t| t.trim().to_string());
            let tenant = config
                .tenant_id
                .clone()
                .unwrap_or_else(|| "common".to_string());
            config.auth_url = format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                tenant
            );
            config.token_url = format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                tenant
            );
            config.userinfo_url = Some("https://graph.microsoft.com/oidc/userinfo".to_string());
        } else if let Ok(client_id) = std::env::var("OKTA_CLIENT_ID") {
            config.provider = SsoProvider::Okta;
            config.client_id = client_id;
            config.enabled = true;
            if let Ok(secret) = std::env::var("OKTA_CLIENT_SECRET") {
                config.client_secret = secret;
            }
            if let Some(domain) = env_nonempty("OKTA_DOMAIN") {
                config.auth_url = format!("https://{}/oauth2/default/v1/authorize", domain);
                config.token_url = format!("https://{}/oauth2/default/v1/token", domain);
                config.userinfo_url =
                    Some(format!("https://{}/oauth2/default/v1/userinfo", domain));
            }
        } else if let Ok(client_id) = std::env::var("AUTH0_CLIENT_ID") {
            config.provider = SsoProvider::Auth0;
            config.client_id = client_id;
            config.enabled = true;
            if let Ok(secret) = std::env::var("AUTH0_CLIENT_SECRET") {
                config.client_secret = secret;
            }
            if let Some(domain) = env_nonempty("AUTH0_DOMAIN") {
                config.auth_url = format!("https://{}/authorize", domain);
                config.token_url = format!("https://{}/oauth/token", domain);
                config.userinfo_url = Some(format!("https://{}/userinfo", domain));
            }
        }

        // Generic OIDC overrides
        if let Ok(client_id) = std::env::var("SSO_CLIENT_ID") {
            config.client_id = client_id;
            config.enabled = true;
        }
        if let Ok(secret) = std::env::var("SSO_CLIENT_SECRET") {
            config.client_secret = secret;
        }
        if let Ok(url) = std::env::var("SSO_AUTH_URL") {
            config.auth_url = url;
        }
        if let Ok(url) = std::env::var("SSO_TOKEN_URL") {
            config.token_url = url;
        }
        if let Ok(url) = std::env::var("SSO_USERINFO_URL") {
            config.userinfo_url = Some(url);
        }
        if let Ok(url) = std::env::var("SSO_ISSUER_URL") {
            config.issuer_url = Some(url);
        }
        if let Ok(uri) = std::env::var("SSO_REDIRECT_URI") {
            config.redirect_uri = uri;
        }
        if let Ok(claim) = std::env::var("SSO_USERNAME_CLAIM") {
            config.username_claim = claim;
        }
        if let Ok(claim) = std::env::var("SSO_EMAIL_CLAIM") {
            config.email_claim = claim;
        }

        let domains =
            env_nonempty("SSO_ALLOWED_DOMAIN").or_else(|| env_nonempty("KISS_MAIL_DOMAIN"));
        if let Some(domains) = domains {
            config.allowed_domains = domains
                .split(',')
                .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect();
        }

        config.allow_subdomains = crate::config::env_bool("SSO_ALLOW_SUBDOMAINS", false);

        config.validate();
        config
    }

    /// Disable the provider (with a warning) if required endpoints are
    /// missing, instead of running with empty URLs.
    fn validate(&mut self) {
        if !self.enabled {
            return;
        }
        let mut missing = Vec::new();
        if self.auth_url.trim().is_empty() {
            missing.push("authorization URL");
        }
        if self.token_url.trim().is_empty() {
            missing.push("token URL");
        }
        if self
            .userinfo_url
            .as_deref()
            .is_none_or(|u| u.trim().is_empty())
        {
            missing.push("UserInfo URL");
        }
        if self.allowed_domains.is_empty() {
            tracing::warn!(
                "SSO provider {} disabled: SSO_ALLOWED_DOMAIN or KISS_MAIL_DOMAIN is required \
                 to map SSO identities to local users",
                self.provider.display_name()
            );
            self.enabled = false;
            return;
        }
        if self.provider == SsoProvider::Microsoft {
            let tenant = self.tenant_id.as_deref().map(str::trim).unwrap_or("");
            if tenant.is_empty()
                || MULTI_TENANT_AUTHORITIES
                    .iter()
                    .any(|t| tenant.eq_ignore_ascii_case(t))
            {
                tracing::warn!(
                    "SSO provider Microsoft disabled: MICROSOFT_TENANT_ID must name a specific \
                     tenant; the multi-tenant authorities (common, organizations, consumers) \
                     would accept identities from any tenant"
                );
                self.enabled = false;
                return;
            }
        }
        if missing.is_empty() {
            return;
        }
        let hint = match self.provider {
            SsoProvider::Okta => " (set OKTA_DOMAIN)",
            SsoProvider::Auth0 => " (set AUTH0_DOMAIN)",
            SsoProvider::OnePassword => " (set ONEPASSWORD_USERINFO_URL or SSO_USERINFO_URL)",
            _ => " (set SSO_AUTH_URL / SSO_TOKEN_URL / SSO_USERINFO_URL)",
        };
        tracing::warn!(
            "SSO provider {} disabled: missing {}{}",
            self.provider.display_name(),
            missing.join(", "),
            hint
        );
        self.enabled = false;
    }

    /// Whether `domain` is acceptable for username mapping.
    ///
    /// Matches an allowed domain exactly. Only with `allow_subdomains` is a
    /// subdomain of an allowed one accepted too (`allowed = example.com`
    /// accepts `user@mail.example.com`). A parent of an allowed domain is
    /// never accepted. An empty allow-list accepts nothing.
    fn domain_allowed(&self, domain: &str) -> bool {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return false;
        }
        self.allowed_domains.iter().any(|a| {
            let a = a.trim().trim_end_matches('.').to_ascii_lowercase();
            !a.is_empty()
                && (domain == a || (self.allow_subdomains && domain.ends_with(&format!(".{}", a))))
        })
    }

    /// Map provider claims to a local identity.
    ///
    /// Rules:
    /// - `sub` must be present (it is bound to the local account on first login).
    /// - The address is taken from the configured email claim; if that claim is
    ///   absent, the configured username claim is used only when it is an
    ///   address (`local@domain`). A free-form username without `@` is rejected.
    /// - The address's domain must pass `domain_allowed`; the local username is
    ///   the canonicalised local part.
    /// - The address must be verified: `email_verified` must be `true` (a
    ///   boolean, or the string `"true"`). A missing claim is rejected, so a
    ///   provider that lets users set an arbitrary unverified email cannot be
    ///   used to take over a local account ("nOAuth").
    /// - Microsoft Entra ID is the exception: it does not send
    ///   `email_verified`. The provider is pinned to one tenant (`validate`
    ///   refuses the multi-tenant authorities), the `tid` claim, when present,
    ///   must equal that tenant, and only then is the address treated as
    ///   verified, i.e. trust rests on the tenant's administrators controlling
    ///   the `email` attribute of their accounts. An explicit
    ///   `email_verified: false` is still rejected.
    fn identity_from_claims(
        &self,
        claims: HashMap<String, serde_json::Value>,
    ) -> Result<SsoUserInfo, String> {
        let claim_str = |name: &str| {
            claims
                .get(name)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };

        let sub = claim_str("sub").ok_or_else(|| "SSO provider returned no subject".to_string())?;

        let email_claim = claim_str(&self.config_email_claim());
        let address = match email_claim {
            Some(e) => e,
            None => match claim_str(&self.username_claim) {
                Some(u) if u.contains('@') => u,
                Some(_) => {
                    return Err(
                        "SSO identity has no email address; free-form usernames are not accepted"
                            .to_string(),
                    );
                }
                None => return Err("SSO provider returned no email address".to_string()),
            },
        };

        let email_verified = match claims.get("email_verified") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::Bool(b)) => Some(*b),
            // Some providers (e.g. Cognito) send the flag as a string.
            Some(serde_json::Value::String(s)) => Some(s.eq_ignore_ascii_case("true")),
            Some(_) => Some(false),
        };
        let email_verified = match email_verified {
            Some(true) => true,
            Some(false) => return Err("SSO email address is not verified".to_string()),
            None if self.provider == SsoProvider::Microsoft => {
                self.microsoft_tenant_matches(claim_str("tid").as_deref())?
            }
            None => {
                return Err(
                    "SSO email address is not verified (no email_verified claim)".to_string(),
                );
            }
        };
        if !email_verified {
            return Err("SSO email address is not verified".to_string());
        }

        let (local, domain) = address
            .rsplit_once('@')
            .ok_or_else(|| "SSO email address is malformed".to_string())?;
        if !self.domain_allowed(domain) {
            tracing::warn!("SSO login rejected: email domain '{}' not allowed", domain);
            return Err(format!("Email domain '{}' is not allowed", domain));
        }
        let username = crate::users::canonical_username(local);
        if username.is_empty() || username.contains('@') {
            return Err("SSO provider returned no usable username".to_string());
        }

        let name = claim_str(&self.name_claim);

        Ok(SsoUserInfo {
            sub,
            username,
            email: Some(address),
            name,
            email_verified: Some(true),
            claims,
        })
    }

    /// Microsoft only (no `email_verified` claim): the address counts as
    /// verified when the provider is pinned to a specific tenant and the
    /// token's `tid`, when present, is that tenant. A `tid` from another
    /// tenant is rejected.
    fn microsoft_tenant_matches(&self, tid: Option<&str>) -> Result<bool, String> {
        let Some(tenant) = self
            .tenant_id
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .filter(|t| {
                !MULTI_TENANT_AUTHORITIES
                    .iter()
                    .any(|m| t.eq_ignore_ascii_case(m))
            })
        else {
            return Err("SSO email address is not verified (no tenant configured)".to_string());
        };
        match tid {
            Some(tid) if !tid.eq_ignore_ascii_case(tenant) => {
                tracing::warn!(
                    "SSO login rejected: token tenant does not match the configured tenant"
                );
                Err("SSO identity belongs to a different tenant".to_string())
            }
            _ => Ok(true),
        }
    }

    fn config_email_claim(&self) -> String {
        if self.email_claim.trim().is_empty() {
            "email".to_string()
        } else {
            self.email_claim.clone()
        }
    }

    /// Create preset for 1Password.
    ///
    /// 1Password has no well-known UserInfo endpoint; set `userinfo_url`
    /// before use or SSO logins will fail.
    #[cfg(test)]
    pub fn onepassword(client_id: &str, client_secret: &str) -> Self {
        Self {
            enabled: true,
            provider: SsoProvider::OnePassword,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://app.1password.com/oauth/authorize".to_string(),
            token_url: "https://app.1password.com/oauth/token".to_string(),
            ..Default::default()
        }
    }

    /// Create preset for Google
    #[cfg(test)]
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            enabled: true,
            provider: SsoProvider::Google,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_url: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
            ..Default::default()
        }
    }

    /// Create preset for Microsoft
    #[cfg(test)]
    pub fn microsoft(client_id: &str, client_secret: &str, tenant_id: &str) -> Self {
        Self {
            enabled: true,
            provider: SsoProvider::Microsoft,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                tenant_id
            ),
            token_url: format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                tenant_id
            ),
            userinfo_url: Some("https://graph.microsoft.com/oidc/userinfo".to_string()),
            tenant_id: Some(tenant_id.to_string()),
            ..Default::default()
        }
    }
}

/// Entra ID authorities that accept accounts from any tenant. Refused: with
/// them, any tenant's administrator (or any personal account) could assert an
/// email address in an allowed domain.
const MULTI_TENANT_AUTHORITIES: &[&str] = &["common", "organizations", "consumers"];

/// SSO user info from OIDC provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoUserInfo {
    /// Subject (unique user ID from provider)
    pub sub: String,
    /// Username (from configured claim)
    pub username: String,
    /// Email address
    pub email: Option<String>,
    /// Display name
    pub name: Option<String>,
    /// Email verified flag
    pub email_verified: Option<bool>,
    /// Raw claims from provider
    pub claims: HashMap<String, serde_json::Value>,
}

/// App password for mail clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPassword {
    /// Unique ID
    pub id: String,
    /// Hashed password
    pub password_hash: String,
    /// Display name/label
    pub label: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
    /// Expires at (optional)
    pub expires_at: Option<DateTime<Utc>>,
    /// Allowed protocols (empty = all)
    pub allowed_protocols: Vec<String>,
}

/// Pending authorization state
#[derive(Debug, Clone)]
pub struct PendingAuth {
    /// PKCE verifier
    pub pkce_verifier: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// OAuth2 token response
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// User's SSO data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserSsoData {
    /// SSO provider subject ID. Together with `provider` this is the bound
    /// identity: bindings are keyed on (provider, sub).
    pub provider_sub: Option<String>,
    /// SSO provider (display name). `None` with a `provider_sub` is a legacy
    /// binding (see `SsoManager::bind_identity`).
    pub provider: Option<String>,
    /// App passwords
    pub app_passwords: Vec<AppPassword>,
    /// Last SSO login
    pub last_sso_login: Option<DateTime<Utc>>,
}

/// SSO Manager
#[derive(Debug)]
pub struct SsoManager {
    /// Configuration
    config: SsoConfig,
    /// HTTP client (with timeouts). `None` if it could not be built, in
    /// which case SSO is disabled.
    http_client: Option<HttpClient>,
    /// Pending authorizations (CSRF token -> state)
    pending_auth: Arc<RwLock<HashMap<String, PendingAuth>>>,
    /// User SSO data
    user_data: Arc<RwLock<HashMap<String, UserSsoData>>>,
    /// Data directory
    data_dir: PathBuf,
    /// Serializes snapshot+write of sso_data.json so saves land in order.
    save_lock: tokio::sync::Mutex<()>,
    /// `last_used` updates not yet persisted.
    last_used_dirty: std::sync::atomic::AtomicBool,
    /// When `last_used` updates were last persisted (debounce).
    last_used_saved: std::sync::Mutex<Option<std::time::Instant>>,
}

/// Minimum interval between saves triggered only by `last_used` updates.
const LAST_USED_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// Connect timeout for requests to the identity provider.
const HTTP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Total timeout for requests to the identity provider.
const HTTP_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Build the IdP HTTP client. Never falls back to a client without
/// timeouts: on failure SSO is disabled instead (see `SsoManager::new`).
fn build_http_client() -> Option<HttpClient> {
    match HttpClient::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_TOTAL_TIMEOUT)
        .build()
    {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::error!(
                "Failed to build SSO HTTP client with timeouts: {}; SSO login disabled",
                e
            );
            None
        }
    }
}

/// At most this many (most recent, non-expired) app passwords are tried per
/// login, bounding the Argon2 work one request can cause.
const MAX_APP_PASSWORD_CANDIDATES: usize = 20;

impl SsoManager {
    /// Create a new SSO manager
    pub fn new(mut config: SsoConfig, data_dir: PathBuf) -> Self {
        let http_client = build_http_client();
        if http_client.is_none() {
            config.enabled = false;
        }
        Self {
            config,
            http_client,
            pending_auth: Arc::new(RwLock::new(HashMap::new())),
            user_data: Arc::new(RwLock::new(HashMap::new())),
            data_dir,
            save_lock: tokio::sync::Mutex::new(()),
            last_used_dirty: std::sync::atomic::AtomicBool::new(false),
            last_used_saved: std::sync::Mutex::new(None),
        }
    }

    /// Create from environment
    pub fn from_env(data_dir: PathBuf) -> Self {
        Self::new(SsoConfig::from_env(), data_dir)
    }

    /// Check if SSO is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.client_id.is_empty() && self.http_client.is_some()
    }

    fn http(&self) -> Result<&HttpClient, String> {
        self.http_client
            .as_ref()
            .ok_or_else(|| "SSO is not enabled".to_string())
    }

    fn provider_name(&self) -> &'static str {
        self.config.provider.display_name()
    }

    /// Get SSO status
    pub fn status(&self) -> SsoStatus {
        SsoStatus {
            enabled: self.is_enabled(),
            provider: self.config.provider.clone(),
            provider_name: self.config.provider.display_name().to_string(),
            allow_app_passwords: self.config.allow_app_passwords,
        }
    }

    /// Load user SSO data from disk. Keys are canonicalised.
    pub async fn load(&self) -> Result<(), std::io::Error> {
        let path = self.data_dir.join("sso_data.json");
        let Some(raw) = crate::storage::read_json::<HashMap<String, UserSsoData>>(&path).await?
        else {
            return Ok(());
        };

        let mut user_data: HashMap<String, UserSsoData> = HashMap::new();
        for (key, value) in raw {
            match user_data.entry(crate::users::canonical_username(&key)) {
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(value);
                }
                std::collections::hash_map::Entry::Occupied(o) => {
                    let existing = o.into_mut();
                    existing.app_passwords.extend(value.app_passwords);
                    if existing.provider_sub.is_none() {
                        existing.provider_sub = value.provider_sub;
                        existing.provider = value.provider;
                    } else if value.provider_sub.is_some()
                        && (value.provider_sub != existing.provider_sub
                            || value.provider != existing.provider)
                    {
                        tracing::warn!(
                            "sso_data.json: entry '{}' canonicalises to an existing user with a \
                             different SSO identity binding; dropping the binding from '{}'",
                            key,
                            key
                        );
                    }
                    existing.last_sso_login = existing.last_sso_login.max(value.last_sso_login);
                }
            }
        }

        *self.user_data.write().await = user_data;
        Ok(())
    }

    /// Save user SSO data to disk (atomic, 0600, fsync'd).
    ///
    /// Persists everything in memory, including pending `last_used` updates.
    pub async fn save(&self) -> Result<(), std::io::Error> {
        let guard = self.save_lock.lock().await;
        self.save_locked(&guard).await
    }

    /// Snapshot and write `sso_data.json`. The caller must hold `save_lock`
    /// (proved by the guard), so a mutation + save + rollback sequence done
    /// under the same guard can never be interleaved with another save.
    async fn save_locked(
        &self,
        _guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> Result<(), std::io::Error> {
        tokio::fs::create_dir_all(&self.data_dir).await?;
        let path = self.data_dir.join("sso_data.json");

        let was_dirty = self
            .last_used_dirty
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        let restore_dirty = || {
            if was_dirty {
                self.last_used_dirty
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        };
        let data = match serde_json::to_vec_pretty(&*self.user_data.read().await) {
            Ok(d) => d,
            Err(e) => {
                restore_dirty();
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
            }
        };

        let result = crate::storage::write_atomic(&path, data).await;
        match &result {
            Ok(()) => {
                if let Ok(mut t) = self.last_used_saved.lock() {
                    *t = Some(std::time::Instant::now());
                }
            }
            Err(_) => restore_dirty(),
        }
        result
    }

    /// Persist pending `last_used` updates, if any (call on shutdown).
    pub async fn flush(&self) -> Result<(), std::io::Error> {
        if self
            .last_used_dirty
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            self.save().await
        } else {
            Ok(())
        }
    }

    /// Start OAuth2 authorization flow
    pub async fn start_auth(&self) -> Result<(String, String), String> {
        if !self.is_enabled() {
            return Err("SSO is not enabled".to_string());
        }

        // Generate CSRF state and PKCE verifier
        let state = generate_random_string(32);
        let pkce_verifier = generate_random_string(64);
        let pkce_challenge = generate_pkce_challenge(&pkce_verifier);

        // Build authorization URL
        let scopes = self.config.scopes.join(" ");
        let auth_url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            self.config.auth_url,
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.redirect_uri),
            urlencoding::encode(&scopes),
            urlencoding::encode(&state),
            urlencoding::encode(&pkce_challenge),
        );

        // Store pending auth state
        let pending = PendingAuth {
            pkce_verifier,
            created_at: Utc::now(),
        };

        self.pending_auth
            .write()
            .await
            .insert(state.clone(), pending);

        // Clean up old pending auths (older than 10 minutes)
        self.cleanup_pending_auth().await;

        Ok((auth_url, state))
    }

    /// Complete OAuth2 authorization flow
    pub async fn complete_auth(&self, code: &str, state: &str) -> Result<SsoUserInfo, String> {
        if !self.is_enabled() {
            return Err("SSO is not enabled".to_string());
        }

        // Verify CSRF state. The pending entry is only consumed after the
        // token exchange succeeds, so a transient provider failure can be
        // retried within the 10-minute window.
        let pending = self
            .pending_auth
            .read()
            .await
            .get(state)
            .cloned()
            .ok_or_else(|| "Invalid or expired authorization state".to_string())?;

        // Check if expired (10 minute window)
        if Utc::now() - pending.created_at > Duration::minutes(10) {
            self.pending_auth.write().await.remove(state);
            return Err("Authorization expired".to_string());
        }

        // Exchange code for token
        let token_response = self
            .http()?
            .post(&self.config.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.config.redirect_uri),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
                ("code_verifier", &pending.pkce_verifier),
            ])
            .send()
            .await
            .map_err(|e| format!("Token request failed: {}", e))?;

        if !token_response.status().is_success() {
            let error_text = token_response.text().await.unwrap_or_default();
            return Err(format!("Token exchange failed: {}", error_text));
        }

        let token_data: TokenResponse = token_response
            .json()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

        // Token exchange succeeded: consume the state (single use). If a
        // concurrent callback already consumed it, fail this one.
        if self.pending_auth.write().await.remove(state).is_none() {
            return Err("Authorization state already used".to_string());
        }

        // Get user info. The caller must then call `bind_identity` before
        // treating the user as logged in.
        let user_info = self.fetch_user_info(&token_data.access_token).await?;

        tracing::info!("SSO authentication successful for {}", user_info.username);
        Ok(user_info)
    }

    /// Enforce or record the (provider, sub) binding for an identity
    /// returned by `complete_auth`, and record the login time.
    ///
    /// - Account bound to (provider, sub): must match exactly.
    /// - Legacy binding (sub without provider): enforced when the sub
    ///   matches (the provider is then recorded); otherwise it cannot be
    ///   attributed to this provider, so it is treated as unbound (warning).
    /// - Unbound: bound now only if `allow_first_bind`; the caller passes
    ///   `false` for accounts that must be linked explicitly (admins).
    ///
    /// A new binding is persisted before success is returned; if it cannot
    /// be saved it is rolled back and the login fails.
    pub async fn bind_identity(
        &self,
        info: &SsoUserInfo,
        allow_first_bind: bool,
    ) -> Result<(), String> {
        let username = crate::users::canonical_username(&info.username);
        let provider = self.provider_name();
        if username.is_empty() || info.sub.trim().is_empty() {
            return Err("SSO identity is incomplete".to_string());
        }

        let guard = self.save_lock.lock().await;
        let mut data = self.user_data.write().await;
        let previous = data.get(&username).cloned();
        let user_data = data.entry(username.clone()).or_default();
        let bound = match (&user_data.provider, &user_data.provider_sub) {
            (Some(p), Some(sub)) => {
                if p != provider || *sub != info.sub {
                    drop(data);
                    tracing::warn!(
                        "SSO login for '{}' rejected: identity does not match the bound identity",
                        username
                    );
                    return Err(
                        "SSO identity does not match the account's bound identity".to_string()
                    );
                }
                true
            }
            (None, Some(sub)) if *sub == info.sub => {
                // Legacy binding confirmed by this provider: record it.
                user_data.provider = Some(provider.to_string());
                false
            }
            (None, Some(_)) => {
                tracing::warn!(
                    "SSO account '{}' has a legacy identity binding without a provider; \
                     treating it as unbound for provider {}",
                    username,
                    provider
                );
                false
            }
            (_, None) => false,
        };
        let first_binding = !bound;
        if first_binding && user_data.provider_sub.as_deref() != Some(info.sub.as_str()) {
            if !allow_first_bind {
                // Restore exactly what was there (entry() may have created it).
                match &previous {
                    Some(p) => *user_data = p.clone(),
                    None => {
                        data.remove(&username);
                    }
                }
                drop(data);
                tracing::warn!(
                    "SSO login for '{}' rejected: account has no SSO identity bound and \
                     automatic binding is not allowed for it",
                    username
                );
                return Err(
                    "This account must be linked to an SSO identity by an administrator"
                        .to_string(),
                );
            }
            user_data.provider_sub = Some(info.sub.clone());
            user_data.provider = Some(provider.to_string());
            tracing::info!("Bound SSO identity ({}) to '{}'", provider, username);
        }
        user_data.last_sso_login = Some(Utc::now());
        drop(data);

        if let Err(e) = self.save_locked(&guard).await {
            if first_binding {
                // The binding is security-relevant: do not keep it only in
                // memory, and do not let the login proceed unbound.
                self.restore_user(&username, previous).await;
                tracing::error!(
                    "Failed to persist SSO identity binding for {}: {}",
                    username,
                    e
                );
                return Err(format!("Failed to persist SSO login data: {}", e));
            }
            tracing::warn!("Failed to persist SSO login data: {}", e);
        }
        Ok(())
    }

    /// Put a user's entry back to `previous` (rollback after a failed save).
    async fn restore_user(&self, username: &str, previous: Option<UserSsoData>) {
        let mut data = self.user_data.write().await;
        match previous {
            Some(p) => {
                data.insert(username.to_string(), p);
            }
            None => {
                data.remove(username);
            }
        }
    }

    /// Bind `user` to (provider, sub), replacing any existing binding
    /// (administrative link). Persisted; rolled back on failure.
    pub async fn link_identity(&self, user: &str, provider: &str, sub: &str) -> Result<(), String> {
        let username = crate::users::canonical_username(user);
        let (provider, sub) = (provider.trim(), sub.trim());
        if username.is_empty() || provider.is_empty() || sub.is_empty() {
            return Err("User, provider and subject are required".to_string());
        }
        let guard = self.save_lock.lock().await;
        let mut data = self.user_data.write().await;
        let previous = data.get(&username).cloned();
        let entry = data.entry(username.clone()).or_default();
        entry.provider = Some(provider.to_string());
        entry.provider_sub = Some(sub.to_string());
        drop(data);
        if let Err(e) = self.save_locked(&guard).await {
            self.restore_user(&username, previous).await;
            tracing::error!("Failed to save SSO identity link for {}: {}", username, e);
            return Err(format!("Failed to save SSO identity link: {}", e));
        }
        tracing::info!("Linked SSO identity ({}) to '{}'", provider, username);
        Ok(())
    }

    /// Remove `user`'s identity binding (app passwords are kept).
    /// `Ok(false)` = there was no binding. Persisted; rolled back on failure.
    pub async fn unlink_identity(&self, user: &str) -> Result<bool, String> {
        let username = crate::users::canonical_username(user);
        let guard = self.save_lock.lock().await;
        let mut data = self.user_data.write().await;
        let Some(entry) = data.get_mut(&username) else {
            return Ok(false);
        };
        if entry.provider_sub.is_none() && entry.provider.is_none() {
            return Ok(false);
        }
        let previous = entry.clone();
        entry.provider_sub = None;
        entry.provider = None;
        drop(data);
        if let Err(e) = self.save_locked(&guard).await {
            self.restore_user(&username, Some(previous)).await;
            tracing::error!("Failed to save SSO identity unlink for {}: {}", username, e);
            return Err(format!("Failed to save SSO identity unlink: {}", e));
        }
        tracing::info!("Unlinked SSO identity from '{}'", username);
        Ok(true)
    }

    /// Fetch user info from provider
    async fn fetch_user_info(&self, access_token: &str) -> Result<SsoUserInfo, String> {
        let userinfo_url = self
            .config
            .userinfo_url
            .as_ref()
            .ok_or_else(|| "UserInfo endpoint not configured".to_string())?;

        let response = self
            .http()?
            .get(userinfo_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| format!("UserInfo request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("UserInfo request failed: {}", response.status()));
        }

        let claims: HashMap<String, serde_json::Value> = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse UserInfo: {}", e))?;

        self.config.identity_from_claims(claims)
    }

    /// Test helper: restrict every app password of `username` to `protocols`.
    #[cfg(test)]
    pub(crate) async fn set_allowed_protocols_for_test(&self, username: &str, protocols: &[&str]) {
        let mut data = self.user_data.write().await;
        for ap in &mut data.entry(username.to_string()).or_default().app_passwords {
            ap.allowed_protocols = protocols.iter().map(|p| p.to_string()).collect();
        }
    }

    /// Generate an app password for a user
    pub async fn generate_app_password(
        &self,
        username: &str,
        label: &str,
        expires_days: Option<u32>,
    ) -> Result<String, String> {
        if !self.config.allow_app_passwords {
            return Err("App passwords are not enabled".to_string());
        }

        // Generate random password
        let password = generate_app_password(self.config.app_password_length);
        let password_hash = {
            let password = password.clone();
            let _permit = crate::users::argon2_permit().await;
            tokio::task::spawn_blocking(move || hash_app_password(&password))
                .await
                .map_err(|e| format!("App password hashing task failed: {}", e))??
        };

        let app_password = AppPassword {
            id: uuid::Uuid::new_v4().to_string(),
            password_hash,
            label: label.to_string(),
            created_at: Utc::now(),
            last_used: None,
            expires_at: expires_days.map(|d| Utc::now() + Duration::days(d as i64)),
            allowed_protocols: vec![],
        };

        // Store app password (mutation, save and rollback all under save_lock)
        let username = crate::users::canonical_username(username);
        let username = username.as_str();
        let id = app_password.id.clone();
        let guard = self.save_lock.lock().await;
        let mut data = self.user_data.write().await;
        let user_data = data.entry(username.to_string()).or_default();
        user_data.app_passwords.push(app_password);
        drop(data);

        if let Err(e) = self.save_locked(&guard).await {
            // Roll back the in-memory change so state matches disk.
            let mut data = self.user_data.write().await;
            if let Some(user_data) = data.get_mut(username) {
                user_data.app_passwords.retain(|ap| ap.id != id);
                if user_data.app_passwords.is_empty()
                    && user_data.provider_sub.is_none()
                    && user_data.last_sso_login.is_none()
                {
                    data.remove(username);
                }
            }
            drop(data);
            tracing::error!("Failed to save app password for {}: {}", username, e);
            return Err(format!("Failed to save app password: {}", e));
        }

        tracing::info!("Generated app password '{}' for {}", label, username);
        Ok(password)
    }

    /// Verify an app password.
    ///
    /// Only the `MAX_APP_PASSWORD_CANDIDATES` most recently created,
    /// non-expired app passwords allowed for `protocol` are tried. Argon2
    /// verification runs on a blocking thread, under the shared Argon2
    /// permit and without holding the user-data lock. `last_used` is updated
    /// in memory immediately but only persisted at most every 5 minutes (or
    /// by any other save / `flush`).
    ///
    /// `Ok(false)` = no match; `Err` = internal failure (never treat it as a
    /// wrong password).
    pub async fn verify_app_password(
        &self,
        username: &str,
        password: &str,
        protocol: &str,
    ) -> Result<bool, String> {
        if password.is_empty() {
            return Ok(false);
        }
        let username = crate::users::canonical_username(username);
        let username = username.as_str();

        // Snapshot candidate hashes under a short read lock.
        let now = Utc::now();
        let candidates: Vec<(String, String)> = {
            let data = self.user_data.read().await;
            let Some(user_data) = data.get(username) else {
                return Ok(false);
            };
            let mut usable: Vec<&AppPassword> = user_data
                .app_passwords
                .iter()
                .filter(|ap| ap.expires_at.is_none_or(|exp| now <= exp))
                .filter(|ap| {
                    ap.allowed_protocols.is_empty()
                        || ap.allowed_protocols.iter().any(|p| p == protocol)
                })
                .collect();
            usable.sort_by_key(|ap| std::cmp::Reverse(ap.created_at));
            usable
                .into_iter()
                .take(MAX_APP_PASSWORD_CANDIDATES)
                .map(|ap| (ap.id.clone(), ap.password_hash.clone()))
                .collect()
        };
        if candidates.is_empty() {
            return Ok(false);
        }

        let password = password.to_string();
        let matched = {
            let _permit = crate::users::argon2_permit().await;
            tokio::task::spawn_blocking(move || {
                candidates
                    .into_iter()
                    .find(|(_, hash)| verify_app_password(&password, hash))
                    .map(|(id, _)| id)
            })
            .await
            .map_err(|e| {
                tracing::error!("App password verification task failed: {}", e);
                format!("App password verification failed: {}", e)
            })?
        };

        let Some(id) = matched else {
            return Ok(false);
        };

        // Short write lock to record last use (entry may have been revoked meanwhile).
        {
            let mut data = self.user_data.write().await;
            let Some(app_pw) = data
                .get_mut(username)
                .and_then(|u| u.app_passwords.iter_mut().find(|ap| ap.id == id))
            else {
                return Ok(false);
            };
            app_pw.last_used = Some(Utc::now());
        }
        self.last_used_dirty
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let due = self
            .last_used_saved
            .lock()
            .map(|t| t.is_none_or(|t| t.elapsed() >= LAST_USED_SAVE_INTERVAL))
            .unwrap_or(true);
        if due && let Err(e) = self.save().await {
            tracing::warn!("Failed to persist app password last_used: {}", e);
        }

        Ok(true)
    }

    /// List app passwords for a user
    pub async fn list_app_passwords(&self, username: &str) -> Vec<AppPasswordInfo> {
        let username = crate::users::canonical_username(username);
        let data = self.user_data.read().await;

        data.get(&username)
            .map(|user_data| {
                user_data
                    .app_passwords
                    .iter()
                    .map(|ap| AppPasswordInfo {
                        id: ap.id.clone(),
                        label: ap.label.clone(),
                        created_at: ap.created_at,
                        last_used: ap.last_used,
                        expires_at: ap.expires_at,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Revoke an app password.
    ///
    /// `Ok(true)` = revoked and persisted, `Ok(false)` = not found,
    /// `Err` = the change could not be persisted (it is rolled back).
    pub async fn revoke_app_password(
        &self,
        username: &str,
        password_id: &str,
    ) -> Result<bool, String> {
        let username = crate::users::canonical_username(username);
        let guard = self.save_lock.lock().await;
        let mut data = self.user_data.write().await;

        let Some(user_data) = data.get_mut(&username) else {
            return Ok(false);
        };
        let Some(pos) = user_data
            .app_passwords
            .iter()
            .position(|ap| ap.id == password_id)
        else {
            return Ok(false);
        };
        let removed = user_data.app_passwords.remove(pos);
        drop(data);

        if let Err(e) = self.save_locked(&guard).await {
            // Roll back: restore the revoked entry (still under save_lock, so
            // no other save can have persisted the removal meanwhile).
            let mut data = self.user_data.write().await;
            let user_data = data.entry(username.clone()).or_default();
            let pos = pos.min(user_data.app_passwords.len());
            user_data.app_passwords.insert(pos, removed);
            drop(data);
            tracing::error!(
                "Failed to save revocation of app password {} for {}: {}",
                password_id,
                username,
                e
            );
            return Err(format!("Failed to save app password revocation: {}", e));
        }

        Ok(true)
    }

    /// Revoke every app password of `user`; returns how many were revoked.
    /// Persisted atomically; rolled back (and `Err`) if the save fails.
    pub async fn revoke_all_app_passwords(&self, user: &str) -> Result<usize, String> {
        let username = crate::users::canonical_username(user);
        let guard = self.save_lock.lock().await;
        let mut data = self.user_data.write().await;
        let Some(entry) = data.get_mut(&username) else {
            return Ok(0);
        };
        if entry.app_passwords.is_empty() {
            return Ok(0);
        }
        let removed = std::mem::take(&mut entry.app_passwords);
        let count = removed.len();
        drop(data);
        if let Err(e) = self.save_locked(&guard).await {
            let mut data = self.user_data.write().await;
            let entry = data.entry(username.clone()).or_default();
            // Still under save_lock, so no save can have persisted the
            // removal; `last_used` updates cannot touch the taken entries.
            entry.app_passwords = removed;
            drop(data);
            tracing::error!(
                "Failed to save revocation of all app passwords for {}: {}",
                username,
                e
            );
            return Err(format!("Failed to save app password revocation: {}", e));
        }
        tracing::info!("Revoked {} app password(s) for {}", count, username);
        Ok(count)
    }

    /// Remove all SSO data (app passwords, identity binding) for a user,
    /// e.g. when the local account is deleted. Missing user is not an error.
    pub async fn remove_user(&self, username: &str) -> Result<(), String> {
        let username = crate::users::canonical_username(username);
        let guard = self.save_lock.lock().await;
        let Some(removed) = self.user_data.write().await.remove(&username) else {
            return Ok(());
        };

        if let Err(e) = self.save_locked(&guard).await {
            self.user_data
                .write()
                .await
                .insert(username.clone(), removed);
            tracing::error!("Failed to save SSO data removal for {}: {}", username, e);
            return Err(format!("Failed to save SSO data removal: {}", e));
        }
        tracing::info!("Removed SSO data for {}", username);
        Ok(())
    }

    /// Clean up expired pending authorizations
    async fn cleanup_pending_auth(&self) {
        let cutoff = Utc::now() - Duration::minutes(10);
        let mut pending = self.pending_auth.write().await;
        pending.retain(|_, v| v.created_at > cutoff);
    }

    /// Get user's SSO data
    #[cfg(test)]
    pub async fn get_user_data(&self, username: &str) -> Option<UserSsoData> {
        let username = crate::users::canonical_username(username);
        self.user_data.read().await.get(&username).cloned()
    }
}

/// App password info (without sensitive data)
#[derive(Debug, Clone, Serialize)]
pub struct AppPasswordInfo {
    pub id: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// SSO status
#[derive(Debug, Clone, serde::Serialize)]
pub struct SsoStatus {
    pub enabled: bool,
    pub provider: SsoProvider,
    pub provider_name: String,
    pub allow_app_passwords: bool,
}

/// Generate a random string of specified length
fn generate_random_string(length: usize) -> String {
    use rand::RngExt;
    let mut rng = rand::rng();

    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();

    (0..length)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect()
}

/// Generate PKCE code challenge from verifier
fn generate_pkce_challenge(verifier: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();

    // Base64 URL-safe encoding without padding
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Generate a random app password
fn generate_app_password(length: usize) -> String {
    use rand::RngExt;
    let mut rng = rand::rng();

    // Use a character set that's easy to type and unambiguous
    let chars: Vec<char> = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
        .chars()
        .collect();

    // Format as xxxx-xxxx-xxxx-xxxx for readability
    let raw: String = (0..length)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect();

    // Insert dashes every 4 characters
    raw.chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i > 0 && i % 4 == 0 {
                vec!['-', c]
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Hash an app password using Argon2
fn hash_app_password(password: &str) -> Result<String, String> {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

    // Use password_hash's own RNG to avoid version conflicts
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Failed to hash password: {}", e))
}

/// Verify an app password
fn verify_app_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordVerifier, password_hash::PasswordHash};

    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = SsoConfig::default();
        assert!(!config.enabled);
        assert!(config.allow_app_passwords);
        assert_eq!(config.username_claim, "preferred_username");
    }

    #[test]
    fn test_app_password_generation() {
        let password = generate_app_password(24);
        // 24 chars + 5 dashes = 29 total
        assert_eq!(password.len(), 29);
        assert!(password.contains('-'));
    }

    #[test]
    fn test_app_password_hash_verify() {
        let password = "test-pass-word-1234";
        let hash = hash_app_password(password).unwrap();

        assert!(verify_app_password(password, &hash));
        assert!(!verify_app_password("wrong-password", &hash));
    }

    #[test]
    fn test_provider_presets() {
        let google = SsoConfig::google("client_id", "secret");
        assert_eq!(google.provider, SsoProvider::Google);
        assert!(google.auth_url.contains("google"));

        let microsoft = SsoConfig::microsoft("client_id", "secret", "tenant");
        assert_eq!(microsoft.provider, SsoProvider::Microsoft);
        assert!(microsoft.auth_url.contains("microsoftonline"));
    }

    #[tokio::test]
    async fn test_app_password_lifecycle_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SsoManager::new(SsoConfig::default(), dir.path().to_path_buf());
        let pw = manager
            .generate_app_password("alice", "phone", None)
            .await
            .unwrap();
        assert!(
            manager
                .verify_app_password("alice", &pw, "imap")
                .await
                .unwrap()
        );
        assert!(
            !manager
                .verify_app_password("alice", "nope", "imap")
                .await
                .unwrap()
        );
        assert!(
            !manager
                .verify_app_password("alice", "", "imap")
                .await
                .unwrap()
        );
        assert!(
            !manager
                .verify_app_password("bob", &pw, "imap")
                .await
                .unwrap()
        );

        // Persisted
        let reloaded = SsoManager::new(SsoConfig::default(), dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        let list = reloaded.list_app_passwords("alice").await;
        assert_eq!(list.len(), 1);

        assert_eq!(
            manager.revoke_app_password("alice", &list[0].id).await,
            Ok(true)
        );
        assert!(
            !manager
                .verify_app_password("alice", &pw, "imap")
                .await
                .unwrap()
        );
        assert_eq!(
            manager.revoke_app_password("alice", &list[0].id).await,
            Ok(false)
        );
    }

    #[tokio::test]
    async fn test_app_password_save_failure_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        // data_dir is a regular file -> create_dir_all fails -> save fails
        let file_path = dir.path().join("not_a_dir");
        std::fs::write(&file_path, b"x").unwrap();
        let manager = SsoManager::new(SsoConfig::default(), file_path);
        assert!(
            manager
                .generate_app_password("alice", "x", None)
                .await
                .is_err()
        );
        assert!(manager.list_app_passwords("alice").await.is_empty());

        // Revoke rollback: insert directly, then fail to save.
        let hash = hash_app_password("abcd").unwrap();
        manager.user_data.write().await.insert(
            "alice".to_string(),
            UserSsoData {
                app_passwords: vec![AppPassword {
                    id: "id1".to_string(),
                    password_hash: hash,
                    label: "l".to_string(),
                    created_at: Utc::now(),
                    last_used: None,
                    expires_at: None,
                    allowed_protocols: vec![],
                }],
                ..Default::default()
            },
        );
        assert!(manager.revoke_app_password("alice", "id1").await.is_err());
        assert_eq!(manager.list_app_passwords("alice").await.len(), 1);
    }

    #[test]
    fn test_validate_disables_incomplete_providers() {
        let mut okta = SsoConfig {
            enabled: true,
            provider: SsoProvider::Okta,
            client_id: "id".to_string(),
            ..Default::default()
        };
        okta.validate();
        assert!(!okta.enabled);

        let mut op = SsoConfig::onepassword("id", "secret");
        op.validate();
        assert!(
            !op.enabled,
            "1Password without userinfo_url must be disabled"
        );

        let mut google = SsoConfig::google("id", "secret");
        google.allowed_domains = vec!["example.com".to_string()];
        google.validate();
        assert!(google.enabled);
    }

    #[test]
    fn validate_disables_without_allowed_domains() {
        let mut google = SsoConfig::google("id", "secret");
        assert!(google.allowed_domains.is_empty());
        google.validate();
        assert!(!google.enabled);
    }

    #[test]
    fn test_domain_allowed() {
        let mut c = SsoConfig::default();
        // Empty allow-list accepts nothing.
        assert!(!c.domain_allowed("anything.org"));

        c.allowed_domains = vec!["example.com".to_string()];
        assert!(c.domain_allowed("example.com"));
        assert!(c.domain_allowed("EXAMPLE.com"));
        // Subdomains are only accepted with allow_subdomains (see
        // subdomain_rejected_by_default_and_allowed_with_flag).
        c.allow_subdomains = true;
        assert!(c.domain_allowed("mail.example.com"));
        assert!(!c.domain_allowed("evil.com"));
        assert!(!c.domain_allowed("ample.com"));
        assert!(!c.domain_allowed("notexample.com"));
        assert!(!c.domain_allowed("example.com.evil.com"));
        assert!(!c.domain_allowed(""));

        // A parent of an allowed domain is never accepted.
        c.allowed_domains = vec!["mail.example.com".to_string()];
        assert!(!c.domain_allowed("example.com"));
        assert!(c.domain_allowed("mail.example.com"));
    }

    fn sso_config() -> SsoConfig {
        SsoConfig {
            allowed_domains: vec!["example.com".to_string()],
            ..SsoConfig::google("id", "secret")
        }
    }

    fn claims(v: serde_json::Value) -> HashMap<String, serde_json::Value> {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn identity_username_from_email_local_part() {
        let c = sso_config();
        let info = c
            .identity_from_claims(claims(serde_json::json!({
                "sub": "s1",
                "preferred_username": "root",
                "email": "Alice@Example.com",
                "email_verified": true,
            })))
            .unwrap();
        // preferred_username is ignored; the email local part wins.
        assert_eq!(info.username, "alice");
        assert_eq!(info.sub, "s1");
    }

    #[test]
    fn identity_rejects_unverified_email() {
        let c = sso_config();
        let r = c.identity_from_claims(claims(serde_json::json!({
            "sub": "s1", "email": "alice@example.com", "email_verified": false,
        })));
        assert!(r.is_err());
        let r = c.identity_from_claims(claims(serde_json::json!({
            "sub": "s1", "email": "alice@example.com", "email_verified": "false",
        })));
        assert!(r.is_err());
    }

    #[test]
    fn email_verified_missing_rejected() {
        let c = sso_config();
        // From the email claim without the flag: rejected (nOAuth).
        let r = c.identity_from_claims(claims(serde_json::json!({
            "sub": "s1", "email": "alice@example.com",
        })));
        assert!(r.is_err());
        // Non-boolean junk is not "verified".
        let r = c.identity_from_claims(claims(serde_json::json!({
            "sub": "s1", "email": "alice@example.com", "email_verified": 1,
        })));
        assert!(r.is_err());
        // String "true" (Cognito style) is accepted.
        assert!(
            c.identity_from_claims(claims(serde_json::json!({
                "sub": "s1", "email": "alice@example.com", "email_verified": "TRUE",
            })))
            .is_ok()
        );
        // From the username claim (no email claim): rejected without the flag...
        let r = c.identity_from_claims(claims(serde_json::json!({
            "sub": "s1", "preferred_username": "alice@example.com",
        })));
        assert!(r.is_err());
        // ...and accepted when explicitly verified.
        let info = c
            .identity_from_claims(claims(serde_json::json!({
                "sub": "s1", "preferred_username": "alice@example.com", "email_verified": true,
            })))
            .unwrap();
        assert_eq!(info.username, "alice");
    }

    #[test]
    fn identity_rejects_free_form_username() {
        let c = sso_config();
        let r = c.identity_from_claims(claims(serde_json::json!({
            "sub": "s1", "preferred_username": "admin", "email_verified": true,
        })));
        assert!(r.is_err());
        // Nothing at all -> rejected, never falls back to `sub`.
        let r = c.identity_from_claims(claims(serde_json::json!({ "sub": "admin" })));
        assert!(r.is_err());
    }

    #[test]
    fn identity_rejects_foreign_and_parent_domains() {
        let mut c = sso_config();
        let r = c.identity_from_claims(claims(serde_json::json!({
            "sub": "s1", "email": "admin@evil.com", "email_verified": true,
        })));
        assert!(r.is_err());
        c.allowed_domains = vec!["mail.example.com".to_string()];
        let r = c.identity_from_claims(claims(serde_json::json!({
            "sub": "s1", "email": "admin@example.com", "email_verified": true,
        })));
        assert!(r.is_err());
        c.allowed_domains.clear();
        let r = c.identity_from_claims(claims(serde_json::json!({
            "sub": "s1", "email": "admin@example.com", "email_verified": true,
        })));
        assert!(r.is_err(), "empty allow-list must reject");
    }

    #[test]
    fn identity_requires_sub() {
        let c = sso_config();
        let r = c.identity_from_claims(claims(serde_json::json!({
            "email": "alice@example.com", "email_verified": true,
        })));
        assert!(r.is_err());
    }

    fn user_info(username: &str, sub: &str) -> SsoUserInfo {
        SsoUserInfo {
            sub: sub.to_string(),
            username: username.to_string(),
            email: Some(format!("{}@example.com", username)),
            name: None,
            email_verified: Some(true),
            claims: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn provider_sub_bound_on_first_login_and_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SsoManager::new(sso_config(), dir.path().to_path_buf());
        manager
            .bind_identity(&user_info("alice", "sub-1"), true)
            .await
            .unwrap();
        assert_eq!(
            manager
                .get_user_data("alice")
                .await
                .unwrap()
                .provider_sub
                .as_deref(),
            Some("sub-1")
        );
        // Same subject again: fine.
        manager
            .bind_identity(&user_info("alice", "sub-1"), true)
            .await
            .unwrap();
        // Different subject claiming the same local user: rejected.
        assert!(
            manager
                .bind_identity(&user_info("alice", "sub-2"), true)
                .await
                .is_err()
        );

        // Binding persisted.
        let reloaded = SsoManager::new(sso_config(), dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        assert!(
            reloaded
                .bind_identity(&user_info("alice", "sub-2"), true)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn app_password_usernames_are_canonicalised() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SsoManager::new(SsoConfig::default(), dir.path().to_path_buf());
        let pw = manager
            .generate_app_password(" Alice ", "phone", None)
            .await
            .unwrap();
        assert!(
            manager
                .verify_app_password("alice", &pw, "imap")
                .await
                .unwrap()
        );
        assert!(
            manager
                .verify_app_password("ALICE", &pw, "imap")
                .await
                .unwrap()
        );
        let list = manager.list_app_passwords("aLiCe").await;
        assert_eq!(list.len(), 1);
        assert_eq!(
            manager.revoke_app_password("ALICE", &list[0].id).await,
            Ok(true)
        );
        assert!(manager.list_app_passwords("alice").await.is_empty());
    }

    #[tokio::test]
    async fn remove_user_drops_all_sso_data() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SsoManager::new(SsoConfig::default(), dir.path().to_path_buf());
        let pw = manager
            .generate_app_password("alice", "a", None)
            .await
            .unwrap();
        manager
            .generate_app_password("alice", "b", None)
            .await
            .unwrap();
        manager.remove_user("ALICE").await.unwrap();
        assert!(
            !manager
                .verify_app_password("alice", &pw, "imap")
                .await
                .unwrap()
        );
        assert!(manager.get_user_data("alice").await.is_none());
        // Missing user is not an error.
        manager.remove_user("nobody").await.unwrap();

        let reloaded = SsoManager::new(SsoConfig::default(), dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        assert!(reloaded.list_app_passwords("alice").await.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sso_data_written_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let manager = SsoManager::new(SsoConfig::default(), dir.path().to_path_buf());
        manager
            .generate_app_password("alice", "a", None)
            .await
            .unwrap();
        let mode = std::fs::metadata(dir.path().join("sso_data.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn test_app_password_charset() {
        let pw = generate_app_password(24);
        let charset = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789-";
        assert!(pw.chars().all(|c| charset.contains(c)));
    }

    #[tokio::test]
    async fn test_disabled_sso() {
        let dir = tempfile::tempdir().unwrap();
        let manager = SsoManager::new(SsoConfig::default(), dir.path().to_path_buf());
        assert!(!manager.is_enabled());

        let result = manager.start_auth().await;
        assert!(result.is_err());
    }

    // ---- stub IdP -------------------------------------------------------

    /// Minimal OAuth2 IdP: `POST /token` succeeds for code `good` (500 for
    /// anything else) and `GET /userinfo` returns the configured claims.
    struct StubIdp {
        base: String,
        claims: Arc<std::sync::Mutex<serde_json::Value>>,
        token_calls: Arc<std::sync::atomic::AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for StubIdp {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn stub_idp(claims: serde_json::Value) -> StubIdp {
        use axum::{
            Form, Json, Router,
            http::StatusCode,
            response::IntoResponse,
            routing::{get, post},
        };
        let claims = Arc::new(std::sync::Mutex::new(claims));
        let token_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = token_calls.clone();
        let c = claims.clone();
        let app = Router::new()
            .route(
                "/token",
                post(move |Form(f): Form<HashMap<String, String>>| {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if f.get("code").map(String::as_str) == Some("good")
                            && f.get("code_verifier").is_some_and(|v| !v.is_empty())
                        {
                            Json(serde_json::json!({
                                "access_token": "tok",
                                "token_type": "Bearer",
                                "expires_in": 3600,
                            }))
                            .into_response()
                        } else {
                            (StatusCode::INTERNAL_SERVER_ERROR, "nope").into_response()
                        }
                    }
                }),
            )
            .route(
                "/userinfo",
                get(move || {
                    let c = c.clone();
                    async move { Json(c.lock().unwrap().clone()) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        StubIdp {
            base: format!("http://{}", addr),
            claims,
            token_calls,
            task,
        }
    }

    fn stub_config(idp: &StubIdp) -> SsoConfig {
        SsoConfig {
            enabled: true,
            client_id: "cid".to_string(),
            client_secret: "secret".to_string(),
            auth_url: format!("{}/authorize", idp.base),
            token_url: format!("{}/token", idp.base),
            userinfo_url: Some(format!("{}/userinfo", idp.base)),
            allowed_domains: vec!["example.com".to_string()],
            ..Default::default()
        }
    }

    fn alice_claims() -> serde_json::Value {
        serde_json::json!({
            "sub": "sub-alice", "email": "alice@example.com", "email_verified": true,
        })
    }

    #[tokio::test]
    async fn complete_auth_unknown_state_is_rejected() {
        let idp = stub_idp(alice_claims()).await;
        let dir = tempfile::tempdir().unwrap();
        let m = SsoManager::new(stub_config(&idp), dir.path().to_path_buf());
        assert!(m.complete_auth("good", "no-such-state").await.is_err());
        assert_eq!(
            idp.token_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no token request for an unknown state"
        );
    }

    #[tokio::test]
    async fn complete_auth_expired_state_is_removed() {
        let idp = stub_idp(alice_claims()).await;
        let dir = tempfile::tempdir().unwrap();
        let m = SsoManager::new(stub_config(&idp), dir.path().to_path_buf());
        let (_, state) = m.start_auth().await.unwrap();
        m.pending_auth
            .write()
            .await
            .get_mut(&state)
            .unwrap()
            .created_at = Utc::now() - Duration::minutes(11);
        assert!(m.complete_auth("good", &state).await.is_err());
        assert!(!m.pending_auth.read().await.contains_key(&state));
        assert_eq!(idp.token_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn complete_auth_token_failure_keeps_state_for_retry() {
        let idp = stub_idp(alice_claims()).await;
        let dir = tempfile::tempdir().unwrap();
        let m = SsoManager::new(stub_config(&idp), dir.path().to_path_buf());
        let (_, state) = m.start_auth().await.unwrap();
        assert!(m.complete_auth("bad", &state).await.is_err());
        assert!(m.pending_auth.read().await.contains_key(&state));
        let info = m.complete_auth("good", &state).await.unwrap();
        assert_eq!(info.username, "alice");
        assert_eq!(info.sub, "sub-alice");
    }

    #[tokio::test]
    async fn complete_auth_state_is_single_use() {
        let idp = stub_idp(alice_claims()).await;
        let dir = tempfile::tempdir().unwrap();
        let m = SsoManager::new(stub_config(&idp), dir.path().to_path_buf());
        let (_, state) = m.start_auth().await.unwrap();
        m.complete_auth("good", &state).await.unwrap();
        assert!(m.complete_auth("good", &state).await.is_err());
    }

    #[tokio::test]
    async fn complete_auth_does_not_bind() {
        let idp = stub_idp(alice_claims()).await;
        let dir = tempfile::tempdir().unwrap();
        let m = SsoManager::new(stub_config(&idp), dir.path().to_path_buf());
        let (_, state) = m.start_auth().await.unwrap();
        let info = m.complete_auth("good", &state).await.unwrap();
        assert!(m.get_user_data("alice").await.is_none());
        assert!(!dir.path().join("sso_data.json").exists());
        m.bind_identity(&info, true).await.unwrap();
        let d = m.get_user_data("alice").await.unwrap();
        assert_eq!(d.provider_sub.as_deref(), Some("sub-alice"));
        assert_eq!(d.provider.as_deref(), Some("OIDC"));
        assert!(d.last_sso_login.is_some());
    }

    #[tokio::test]
    async fn complete_auth_rejects_unverified_identity_from_idp() {
        let idp = stub_idp(serde_json::json!({
            "sub": "attacker", "email": "admin@example.com",
        }))
        .await;
        let dir = tempfile::tempdir().unwrap();
        let m = SsoManager::new(stub_config(&idp), dir.path().to_path_buf());
        let (_, state) = m.start_auth().await.unwrap();
        assert!(m.complete_auth("good", &state).await.is_err());
        // Verified now: accepted.
        *idp.claims.lock().unwrap() = alice_claims();
        let (_, state) = m.start_auth().await.unwrap();
        assert!(m.complete_auth("good", &state).await.is_ok());
    }

    #[tokio::test]
    async fn bind_identity_first_bind_allowed_and_denied() {
        let dir = tempfile::tempdir().unwrap();
        let m = SsoManager::new(sso_config(), dir.path().to_path_buf());
        // Denied: nothing recorded at all.
        assert!(
            m.bind_identity(&user_info("root", "s-r"), false)
                .await
                .is_err()
        );
        assert!(m.get_user_data("root").await.is_none());
        // Denied with existing (unbound) data: the data is left untouched.
        m.generate_app_password("bob", "x", None).await.unwrap();
        assert!(
            m.bind_identity(&user_info("bob", "s-b"), false)
                .await
                .is_err()
        );
        let bob = m.get_user_data("bob").await.unwrap();
        assert!(bob.provider_sub.is_none());
        assert!(bob.last_sso_login.is_none());
        assert_eq!(bob.app_passwords.len(), 1);
        // Allowed.
        m.bind_identity(&user_info("bob", "s-b"), true)
            .await
            .unwrap();
        // Once bound, a matching identity passes even with allow_first_bind=false.
        m.bind_identity(&user_info("bob", "s-b"), false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn bind_identity_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let m = SsoManager::new(sso_config(), dir.path().to_path_buf());
        m.bind_identity(&user_info("alice", "s1"), true)
            .await
            .unwrap();
        assert!(
            m.bind_identity(&user_info("alice", "s2"), true)
                .await
                .is_err()
        );
        // Same sub but bound to another provider: rejected.
        m.link_identity("carol", "Okta", "s1").await.unwrap();
        assert!(
            m.bind_identity(&user_info("carol", "s1"), true)
                .await
                .is_err()
        );
        // Unlink then rebind.
        assert_eq!(m.unlink_identity("carol").await, Ok(true));
        assert_eq!(m.unlink_identity("carol").await, Ok(false));
        m.bind_identity(&user_info("carol", "s1"), true)
            .await
            .unwrap();
        // link_identity replaces a binding and persists it.
        m.link_identity("alice", "Google", "s9").await.unwrap();
        let reloaded = SsoManager::new(sso_config(), dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        reloaded
            .bind_identity(&user_info("alice", "s9"), false)
            .await
            .unwrap();
        assert!(
            reloaded
                .bind_identity(&user_info("alice", "s1"), true)
                .await
                .is_err()
        );
        assert!(m.link_identity("alice", "", "s").await.is_err());
    }

    #[tokio::test]
    async fn bind_identity_legacy_binding_without_provider() {
        let dir = tempfile::tempdir().unwrap();
        let m = SsoManager::new(sso_config(), dir.path().to_path_buf());
        let legacy = |sub: &str| UserSsoData {
            provider_sub: Some(sub.to_string()),
            provider: None,
            ..Default::default()
        };
        // Same sub: accepted and the provider recorded (then enforced).
        m.user_data
            .write()
            .await
            .insert("alice".to_string(), legacy("s1"));
        m.bind_identity(&user_info("alice", "s1"), false)
            .await
            .unwrap();
        let d = m.get_user_data("alice").await.unwrap();
        assert_eq!(d.provider.as_deref(), Some("Google"));
        assert!(
            m.bind_identity(&user_info("alice", "s2"), true)
                .await
                .is_err()
        );

        // Different sub (e.g. a binding made by another provider): treated
        // as unbound, so it follows the first-bind rule.
        m.user_data
            .write()
            .await
            .insert("bob".to_string(), legacy("other"));
        assert!(
            m.bind_identity(&user_info("bob", "s3"), false)
                .await
                .is_err()
        );
        assert_eq!(
            m.get_user_data("bob")
                .await
                .unwrap()
                .provider_sub
                .as_deref(),
            Some("other")
        );
        m.bind_identity(&user_info("bob", "s3"), true)
            .await
            .unwrap();
        let d = m.get_user_data("bob").await.unwrap();
        assert_eq!(d.provider_sub.as_deref(), Some("s3"));
        assert_eq!(d.provider.as_deref(), Some("Google"));
    }

    #[tokio::test]
    async fn first_binding_save_failure_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("not_a_dir");
        std::fs::write(&file_path, b"x").unwrap();
        let m = SsoManager::new(sso_config(), file_path);
        assert!(
            m.bind_identity(&user_info("alice", "s1"), true)
                .await
                .is_err()
        );
        assert!(m.get_user_data("alice").await.is_none());
        // Link / unlink roll back too.
        assert!(m.link_identity("alice", "Google", "s1").await.is_err());
        assert!(m.get_user_data("alice").await.is_none());
        m.user_data.write().await.insert(
            "bob".to_string(),
            UserSsoData {
                provider_sub: Some("s".to_string()),
                provider: Some("Google".to_string()),
                ..Default::default()
            },
        );
        assert!(m.unlink_identity("bob").await.is_err());
        assert_eq!(
            m.get_user_data("bob")
                .await
                .unwrap()
                .provider_sub
                .as_deref(),
            Some("s")
        );
    }

    #[test]
    fn microsoft_common_tenant_disabled() {
        for tenant in ["common", "organizations", "Consumers", ""] {
            let mut c = SsoConfig {
                allowed_domains: vec!["example.com".to_string()],
                ..SsoConfig::microsoft("id", "secret", tenant)
            };
            c.validate();
            assert!(!c.enabled, "tenant '{}' must be refused", tenant);
        }
        let mut c = SsoConfig {
            allowed_domains: vec!["example.com".to_string()],
            tenant_id: None,
            ..SsoConfig::microsoft("id", "secret", "x")
        };
        c.validate();
        assert!(!c.enabled, "no tenant must be refused");

        let mut c = SsoConfig {
            allowed_domains: vec!["example.com".to_string()],
            ..SsoConfig::microsoft("id", "secret", "tenant-1")
        };
        c.validate();
        assert!(c.enabled);
    }

    #[test]
    fn microsoft_email_verified_via_tenant() {
        let c = SsoConfig {
            allowed_domains: vec!["example.com".to_string()],
            ..SsoConfig::microsoft("id", "secret", "tenant-1")
        };
        // No email_verified, matching tid: verified.
        let info = c
            .identity_from_claims(claims(serde_json::json!({
                "sub": "s", "email": "alice@example.com", "tid": "TENANT-1",
            })))
            .unwrap();
        assert_eq!(info.email_verified, Some(true));
        // No tid (Graph UserInfo): the pinned tenant suffices.
        assert!(
            c.identity_from_claims(claims(serde_json::json!({
                "sub": "s", "email": "alice@example.com",
            })))
            .is_ok()
        );
        // Foreign tenant: rejected.
        assert!(
            c.identity_from_claims(claims(serde_json::json!({
                "sub": "s", "email": "alice@example.com", "tid": "tenant-2",
            })))
            .is_err()
        );
        // Explicitly unverified: rejected.
        assert!(
            c.identity_from_claims(claims(serde_json::json!({
                "sub": "s", "email": "alice@example.com", "email_verified": false,
            })))
            .is_err()
        );
        // Multi-tenant config never treats the address as verified.
        let c = SsoConfig {
            allowed_domains: vec!["example.com".to_string()],
            ..SsoConfig::microsoft("id", "secret", "common")
        };
        assert!(
            c.identity_from_claims(claims(serde_json::json!({
                "sub": "s", "email": "alice@example.com",
            })))
            .is_err()
        );
    }

    #[test]
    fn subdomain_rejected_by_default_and_allowed_with_flag() {
        let mut c = sso_config();
        let sub = claims(serde_json::json!({
            "sub": "s", "email": "alice@mail.example.com", "email_verified": true,
        }));
        assert!(!c.allow_subdomains);
        assert!(!c.domain_allowed("mail.example.com"));
        assert!(c.identity_from_claims(sub.clone()).is_err());
        c.allow_subdomains = true;
        assert!(c.domain_allowed("mail.example.com"));
        assert!(!c.domain_allowed("notexample.com"));
        assert_eq!(c.identity_from_claims(sub).unwrap().username, "alice");
    }

    #[tokio::test]
    async fn revoke_all_app_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let m = SsoManager::new(SsoConfig::default(), dir.path().to_path_buf());
        assert_eq!(m.revoke_all_app_passwords("alice").await, Ok(0));
        let a = m.generate_app_password("alice", "a", None).await.unwrap();
        m.generate_app_password("alice", "b", None).await.unwrap();
        m.bind_identity(&user_info("alice", "s1"), true)
            .await
            .unwrap();
        assert_eq!(m.revoke_all_app_passwords("ALICE").await, Ok(2));
        assert!(!m.verify_app_password("alice", &a, "imap").await.unwrap());
        // The identity binding is kept.
        assert_eq!(
            m.get_user_data("alice")
                .await
                .unwrap()
                .provider_sub
                .as_deref(),
            Some("s1")
        );
        assert_eq!(m.revoke_all_app_passwords("alice").await, Ok(0));
        let reloaded = SsoManager::new(SsoConfig::default(), dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        assert!(reloaded.list_app_passwords("alice").await.is_empty());
    }

    #[tokio::test]
    async fn revoke_all_app_passwords_save_failure_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("not_a_dir");
        std::fs::write(&file_path, b"x").unwrap();
        let m = SsoManager::new(SsoConfig::default(), file_path);
        m.user_data.write().await.insert(
            "alice".to_string(),
            UserSsoData {
                app_passwords: vec![AppPassword {
                    id: "id1".to_string(),
                    password_hash: hash_app_password("abcd").unwrap(),
                    label: "l".to_string(),
                    created_at: Utc::now(),
                    last_used: None,
                    expires_at: None,
                    allowed_protocols: vec![],
                }],
                ..Default::default()
            },
        );
        assert!(m.revoke_all_app_passwords("alice").await.is_err());
        assert_eq!(m.list_app_passwords("alice").await.len(), 1);
    }

    #[tokio::test]
    async fn verify_app_password_checks_only_recent_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let m = SsoManager::new(SsoConfig::default(), dir.path().to_path_buf());
        let oldest = m.generate_app_password("alice", "old", None).await.unwrap();
        // Push MAX newer entries (cheap fake hashes; they never match).
        {
            let mut data = m.user_data.write().await;
            let entry = data.get_mut("alice").unwrap();
            entry.app_passwords[0].created_at = Utc::now() - Duration::days(1);
            for i in 0..MAX_APP_PASSWORD_CANDIDATES {
                entry.app_passwords.push(AppPassword {
                    id: format!("n{}", i),
                    password_hash: "not-a-phc-string".to_string(),
                    label: "n".to_string(),
                    created_at: Utc::now(),
                    last_used: None,
                    expires_at: None,
                    allowed_protocols: vec![],
                });
            }
        }
        assert!(
            !m.verify_app_password("alice", &oldest, "imap")
                .await
                .unwrap()
        );
        // An expired newer entry does not count towards the limit.
        {
            let mut data = m.user_data.write().await;
            let entry = data.get_mut("alice").unwrap();
            entry.app_passwords[1].expires_at = Some(Utc::now() - Duration::days(1));
        }
        assert!(
            m.verify_app_password("alice", &oldest, "imap")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn load_merge_of_conflicting_bindings_keeps_one() {
        let dir = tempfile::tempdir().unwrap();
        let raw = serde_json::json!({
            "alice": {"provider_sub": "s1", "provider": "Google", "app_passwords": [], "last_sso_login": null},
            "ALICE": {"provider_sub": "s2", "provider": "Google", "app_passwords": [], "last_sso_login": null},
        });
        std::fs::write(
            dir.path().join("sso_data.json"),
            serde_json::to_vec(&raw).unwrap(),
        )
        .unwrap();
        let m = SsoManager::new(sso_config(), dir.path().to_path_buf());
        m.load().await.unwrap();
        let d = m.get_user_data("alice").await.unwrap();
        assert!(matches!(d.provider_sub.as_deref(), Some("s1") | Some("s2")));
    }
}
