//! LDAP integration module.
//!
//! Provides LDAP authentication and directory services:
//! - User authentication via LDAP bind
//! - User directory lookups
//! - Fallback to local authentication when LDAP unavailable

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry, dn_escape, ldap_escape};
use std::time::Duration;
use tokio::time::Instant;

/// LDAP configuration
#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// LDAP server URL (e.g., "ldap://localhost:389" or "ldaps://ldap.example.com:636")
    pub url: String,
    /// Base DN for searches (e.g., "dc=example,dc=com")
    pub base_dn: String,
    /// Bind DN for directory searches (optional, for anonymous bind leave empty)
    pub bind_dn: Option<String>,
    /// Bind password
    pub bind_password: Option<String>,
    /// User search filter template (use {username} as placeholder)
    /// e.g., "(&(objectClass=person)(uid={username}))"
    pub user_filter: String,
    /// User DN template for direct bind (use {username} as placeholder;
    /// the username is RFC 4514-escaped). Defaults to `None` (search-then-bind)
    /// unless `LDAP_USER_DN_TEMPLATE` is set.
    /// e.g., "uid={username},ou=users,dc=example,dc=com"
    pub user_dn_template: Option<String>,
    /// Attribute containing the username
    pub username_attr: String,
    /// Attribute containing the email
    pub email_attr: String,
    /// Attribute containing the display name
    pub display_name_attr: String,
    /// Per-operation (connect/bind/search) timeout in seconds; minimum 1.
    /// One authentication may take up to 6x this in total.
    pub timeout_seconds: u64,
    /// Enable TLS/SSL
    pub use_tls: bool,
    /// Enable StartTLS
    pub use_starttls: bool,
    /// Whether LDAP is enabled
    pub enabled: bool,
    /// Fallback to local auth if LDAP fails
    pub fallback_to_local: bool,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            url: "ldap://localhost:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: None,
            bind_password: None,
            user_filter: "(&(objectClass=inetOrgPerson)(uid={username}))".to_string(),
            // No default template: when unset, authentication uses
            // search-then-bind with `user_filter`.
            user_dn_template: None,
            username_attr: "uid".to_string(),
            email_attr: "mail".to_string(),
            display_name_attr: "cn".to_string(),
            timeout_seconds: 10,
            use_tls: false,
            use_starttls: false,
            enabled: false,
            fallback_to_local: true,
        }
    }
}

impl LdapConfig {
    /// Create config from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(url) = std::env::var("LDAP_URL") {
            config.url = url;
            config.enabled = true;
        }

        if let Ok(base_dn) = std::env::var("LDAP_BASE_DN") {
            config.base_dn = base_dn;
        }

        if let Ok(bind_dn) = std::env::var("LDAP_BIND_DN") {
            config.bind_dn = Some(bind_dn);
        }

        if let Ok(bind_password) = std::env::var("LDAP_BIND_PASSWORD") {
            config.bind_password = Some(bind_password);
        }

        if let Ok(user_filter) = std::env::var("LDAP_USER_FILTER") {
            config.user_filter = user_filter;
        }

        if let Ok(user_dn_template) = std::env::var("LDAP_USER_DN_TEMPLATE") {
            if !user_dn_template.trim().is_empty() {
                config.user_dn_template = Some(user_dn_template);
            }
        }

        if let Ok(username_attr) = std::env::var("LDAP_USERNAME_ATTR") {
            config.username_attr = username_attr;
        }

        if let Ok(email_attr) = std::env::var("LDAP_EMAIL_ATTR") {
            config.email_attr = email_attr;
        }

        if let Ok(display_name_attr) = std::env::var("LDAP_DISPLAY_NAME_ATTR") {
            config.display_name_attr = display_name_attr;
        }

        config.use_tls = crate::config::env_bool("LDAP_USE_TLS", config.use_tls);
        config.use_starttls = crate::config::env_bool("LDAP_USE_STARTTLS", config.use_starttls);
        config.fallback_to_local =
            crate::config::env_bool("LDAP_FALLBACK_LOCAL", config.fallback_to_local);

        if let Ok(timeout) = std::env::var("LDAP_TIMEOUT") {
            config.timeout_seconds = parse_timeout(&timeout, config.timeout_seconds);
        }

        config
    }
}

/// Parse `LDAP_TIMEOUT` (whole seconds, minimum 1). Invalid values keep
/// `default` and log a warning; 0 is raised to 1 with a warning.
fn parse_timeout(value: &str, default: u64) -> u64 {
    match value.trim().parse::<u64>() {
        Ok(0) => {
            tracing::warn!("LDAP_TIMEOUT=0 is below the minimum of 1 second; using 1");
            1
        }
        Ok(secs) => secs,
        Err(_) => {
            tracing::warn!(
                "Ignoring invalid LDAP_TIMEOUT '{}' (whole seconds, minimum 1); using {}",
                value,
                default
            );
            default
        }
    }
}

/// LDAP user information
#[derive(Debug, Clone)]
pub struct LdapUser {
    /// Distinguished Name
    pub dn: String,
    /// Username
    pub username: String,
    /// Email address
    pub email: Option<String>,
    /// Display name
    pub display_name: Option<String>,
}

/// LDAP authentication result
#[derive(Debug, Clone)]
pub enum LdapAuthResult {
    /// Successfully authenticated
    Success(LdapUser),
    /// Invalid credentials
    InvalidCredentials,
    /// User not found
    UserNotFound,
    /// LDAP error (connection, timeout, etc.)
    Error(String),
    /// LDAP not enabled, use local auth
    NotEnabled,
}

/// LDAP client for authentication and directory services
#[derive(Debug)]
pub struct LdapClient {
    /// LDAP configuration
    config: LdapConfig,
    /// URL actually used to connect (may differ from `config.url` when
    /// `use_tls` forces an `ldap://` URL to `ldaps://`).
    effective_url: String,
    /// Whether StartTLS is actually requested on connect.
    effective_starttls: bool,
}

/// Resolve the URL and StartTLS flag actually used for connecting.
///
/// - `ldaps://` URLs always use implicit TLS (StartTLS ignored).
/// - `use_tls` with an `ldap://` URL rewrites the scheme to `ldaps://`
///   (and an explicit `:389` port to `:636`), logging a warning.
/// - `use_starttls` with an `ldap://` URL enables StartTLS.
fn resolve_connection(config: &LdapConfig) -> (String, bool) {
    let url = config.url.trim().to_string();
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("ldaps://") {
        if config.use_starttls {
            tracing::warn!("LDAP_USE_STARTTLS ignored: URL already uses ldaps:// (implicit TLS)");
        }
        return (url, false);
    }
    if lower.starts_with("ldap://") {
        if config.use_tls {
            let rest = &url["ldap://".len()..];
            let (hostport, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, ""),
            };
            let hostport = match hostport.strip_suffix(":389") {
                Some(h) => format!("{}:636", h),
                None => hostport.to_string(),
            };
            let new_url = format!("ldaps://{}{}", hostport, path);
            tracing::warn!(
                "LDAP_USE_TLS is set but LDAP_URL uses ldap://; connecting with implicit TLS to {}",
                new_url
            );
            if config.use_starttls {
                tracing::warn!("LDAP_USE_STARTTLS ignored because LDAP_USE_TLS takes precedence");
            }
            return (new_url, false);
        }
        return (url, config.use_starttls);
    }
    // Unknown scheme (e.g. ldapi://): pass through, let ldap3 report errors.
    (url, config.use_starttls)
}

impl LdapClient {
    /// Create a new LDAP client
    pub fn new(config: LdapConfig) -> Self {
        let (effective_url, effective_starttls) = if config.enabled {
            resolve_connection(&config)
        } else {
            (config.url.clone(), config.use_starttls)
        };
        Self {
            config,
            effective_url,
            effective_starttls,
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Self {
        Self::new(LdapConfig::from_env())
    }

    /// Check if LDAP is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if fallback to local auth is enabled
    pub fn fallback_enabled(&self) -> bool {
        self.config.fallback_to_local
    }

    /// Get LDAP status (reflects the connection mode actually used).
    pub fn status(&self) -> LdapStatus {
        let use_tls = self
            .effective_url
            .to_ascii_lowercase()
            .starts_with("ldaps://");
        LdapStatus {
            enabled: self.config.enabled,
            url: self.effective_url.clone(),
            base_dn: self.config.base_dn.clone(),
            use_tls,
            use_starttls: !use_tls && self.effective_starttls,
            fallback_to_local: self.config.fallback_to_local,
        }
    }

    /// Per-operation timeout (bind/search/unbind) and connect timeout.
    fn op_timeout(&self) -> Duration {
        Duration::from_secs(self.config.timeout_seconds.max(1))
    }

    /// Overall budget for one call (`authenticate`: connect + binds +
    /// searches, across the direct-bind and search-then-bind phases).
    /// Backstop for the per-operation timeouts, since ldap3 resets a
    /// search's timer on every reply.
    fn overall_timeout(&self) -> Duration {
        self.op_timeout() * 6
    }

    /// A fresh deadline for one call.
    fn deadline(&self) -> Instant {
        Instant::now() + self.overall_timeout()
    }

    /// Run `fut` until `deadline`, mapping expiry to an error.
    async fn until<T>(
        &self,
        deadline: Instant,
        what: &str,
        fut: impl std::future::Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        match tokio::time::timeout_at(deadline, fut).await {
            Ok(r) => r,
            Err(_) => Err(format!(
                "LDAP {} timed out after {}s",
                what,
                self.overall_timeout().as_secs()
            )),
        }
    }

    /// Unbind in the background (bounded by the operation timeout; errors
    /// ignored), so a slow unbind never delays or changes a result that is
    /// already known.
    fn spawn_unbind(&self, mut ldap: Ldap) {
        let timeout = self.op_timeout();
        tokio::spawn(async move {
            let _ = ldap.with_timeout(timeout).unbind().await;
        });
    }

    /// Connect to LDAP server (one connection per call; no pooling).
    async fn connect(&self) -> Result<Ldap, String> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.op_timeout())
            .set_starttls(self.effective_starttls);

        let (conn, ldap) = LdapConnAsync::with_settings(settings, &self.effective_url)
            .await
            .map_err(|e| format!("LDAP connection failed: {}", e))?;

        // Drive the connection in background
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                tracing::error!("LDAP connection error: {}", e);
            }
        });

        Ok(ldap)
    }

    /// Bind with service account (for searches)
    async fn bind_service(&self, ldap: &mut Ldap) -> Result<(), String> {
        if let (Some(bind_dn), Some(bind_password)) =
            (&self.config.bind_dn, &self.config.bind_password)
        {
            ldap.with_timeout(self.op_timeout())
                .simple_bind(bind_dn, bind_password)
                .await
                .map_err(|e| format!("LDAP bind failed: {}", e))?
                .success()
                .map_err(|e| format!("LDAP bind rejected: {}", e))?;
        }
        Ok(())
    }

    /// Attributes requested for user entries.
    fn user_attrs(&self) -> Vec<&str> {
        vec![
            &self.config.username_attr as &str,
            &self.config.email_attr,
            &self.config.display_name_attr,
        ]
    }

    /// Build the user search filter with the username safely escaped.
    fn user_filter_for(&self, username: &str) -> String {
        self.config
            .user_filter
            .replace("{username}", &ldap_escape(username))
    }

    /// Search for a single user entry on an already-bound connection.
    async fn search_user_entry(
        &self,
        ldap: &mut Ldap,
        username: &str,
    ) -> Result<Option<SearchEntry>, String> {
        let filter = self.user_filter_for(username);
        let (rs, _) = ldap
            .with_timeout(self.op_timeout())
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &filter,
                self.user_attrs(),
            )
            .await
            .map_err(|e| format!("LDAP search failed: {}", e))?
            .success()
            .map_err(|e| format!("LDAP search error: {}", e))?;
        Ok(rs.into_iter().next().map(SearchEntry::construct))
    }

    /// Minimal user record when the directory entry cannot be read.
    fn minimal_user(user_dn: String, username: &str) -> LdapUser {
        LdapUser {
            dn: user_dn,
            username: username.to_string(),
            email: None,
            display_name: None,
        }
    }

    /// Authenticate a user with username and password
    pub async fn authenticate(&self, username: &str, password: &str) -> LdapAuthResult {
        if !self.config.enabled {
            return LdapAuthResult::NotEnabled;
        }

        // An empty password would be an "unauthenticated bind" (RFC 4513 5.1.2),
        // which many servers report as success. Never send one.
        if password.is_empty() || username.is_empty() {
            return LdapAuthResult::InvalidCredentials;
        }

        // One deadline covers every phase of this call.
        let deadline = self.deadline();

        // Try direct bind first if user_dn_template is set
        if let Some(ref template) = self.config.user_dn_template {
            let user_dn = template.replace("{username}", &dn_escape(username));
            match self
                .until(
                    deadline,
                    "bind",
                    self.direct_bind_and_lookup(&user_dn, username, password),
                )
                .await
            {
                Ok(Some(user)) => return LdapAuthResult::Success(user),
                Ok(None) => {
                    // Invalid credentials / no such object for the templated DN.
                    // Fall through to search-then-bind, which may locate the
                    // user elsewhere in the tree. If that search itself fails
                    // (e.g. anonymous search denied), the direct bind's answer
                    // stands.
                    return match self
                        .until(
                            deadline,
                            "search-then-bind",
                            self.search_and_bind_authenticate(username, password),
                        )
                        .await
                    {
                        Ok(Some(user)) => LdapAuthResult::Success(user),
                        Ok(None) => LdapAuthResult::InvalidCredentials,
                        Err(e) => {
                            tracing::debug!("LDAP search-then-bind fallback failed: {}", e);
                            LdapAuthResult::InvalidCredentials
                        }
                    };
                }
                Err(e) => return LdapAuthResult::Error(e),
            }
        }

        // Search-then-bind approach
        match self
            .until(
                deadline,
                "search-then-bind",
                self.search_and_bind_authenticate(username, password),
            )
            .await
        {
            Ok(Some(user)) => LdapAuthResult::Success(user),
            Ok(None) => LdapAuthResult::InvalidCredentials,
            Err(e) => {
                if e.contains("not found") {
                    LdapAuthResult::UserNotFound
                } else {
                    LdapAuthResult::Error(e)
                }
            }
        }
    }

    /// Bind as `user_dn` and, on success, look up the user's entry over the
    /// same connection. Returns `Ok(None)` for invalidCredentials (49) or
    /// noSuchObject (32).
    async fn direct_bind_and_lookup(
        &self,
        user_dn: &str,
        username: &str,
        password: &str,
    ) -> Result<Option<LdapUser>, String> {
        let mut ldap = self.connect().await?;

        let result = ldap
            .with_timeout(self.op_timeout())
            .simple_bind(user_dn, password)
            .await
            .map_err(|e| format!("LDAP bind error: {}", e))?;

        match result.rc {
            0 => {}
            32 | 49 => {
                self.spawn_unbind(ldap);
                return Ok(None);
            }
            _ => {
                self.spawn_unbind(ldap);
                return Err(format!(
                    "LDAP bind failed with code {}: {}",
                    result.rc, result.text
                ));
            }
        }

        // Authenticated. Look up details on the same (user-bound) connection.
        let user = match self.search_user_entry(&mut ldap, username).await {
            Ok(Some(entry)) => self.entry_to_user(entry),
            Ok(None) => Self::minimal_user(user_dn.to_string(), username),
            Err(e) => {
                tracing::warn!("LDAP user lookup failed after auth: {}", e);
                Self::minimal_user(user_dn.to_string(), username)
            }
        };
        self.spawn_unbind(ldap);
        Ok(Some(user))
    }

    /// Search for user (as the service account), then bind with their DN on
    /// the same connection.
    async fn search_and_bind_authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<LdapUser>, String> {
        let mut ldap = self.connect().await?;
        self.bind_service(&mut ldap).await?;

        let entry = match self.search_user_entry(&mut ldap, username).await? {
            Some(entry) => entry,
            None => {
                self.spawn_unbind(ldap);
                return Err(format!("User '{}' not found in LDAP", username));
            }
        };

        // Now bind as the user to verify password
        let result = ldap
            .with_timeout(self.op_timeout())
            .simple_bind(&entry.dn, password)
            .await
            .map_err(|e| format!("LDAP bind error: {}", e));
        self.spawn_unbind(ldap);
        let result = result?;

        match result.rc {
            0 => Ok(Some(self.entry_to_user(entry))),
            49 => Ok(None),
            _ => Err(format!(
                "LDAP bind failed with code {}: {}",
                result.rc, result.text
            )),
        }
    }

    /// Get user information by username
    pub async fn get_user(&self, username: &str) -> Result<Option<LdapUser>, String> {
        if !self.config.enabled {
            return Ok(None);
        }

        self.until(self.deadline(), "user lookup", async {
            let mut ldap = self.connect().await?;
            self.bind_service(&mut ldap).await?;
            let entry = self.search_user_entry(&mut ldap, username).await;
            self.spawn_unbind(ldap);
            Ok(entry?.map(|e| self.entry_to_user(e)))
        })
        .await
    }

    /// Convert LDAP entry to LdapUser
    fn entry_to_user(&self, entry: SearchEntry) -> LdapUser {
        let username = entry
            .attrs
            .get(&self.config.username_attr)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let email = entry
            .attrs
            .get(&self.config.email_attr)
            .and_then(|v| v.first())
            .cloned();

        let display_name = entry
            .attrs
            .get(&self.config.display_name_attr)
            .and_then(|v| v.first())
            .cloned();

        LdapUser {
            dn: entry.dn,
            username,
            email,
            display_name,
        }
    }

    /// Test LDAP connection
    pub async fn test_connection(&self) -> Result<String, String> {
        if !self.config.enabled {
            return Err("LDAP is not enabled".to_string());
        }
        self.until(
            self.deadline(),
            "connection test",
            self.test_connection_inner(),
        )
        .await
    }

    async fn test_connection_inner(&self) -> Result<String, String> {
        let mut ldap = self.connect().await?;
        self.bind_service(&mut ldap).await?;

        // Try to get root DSE
        let result = ldap
            .with_timeout(self.op_timeout())
            .search(
                "",
                Scope::Base,
                "(objectClass=*)",
                vec!["namingContexts", "supportedLDAPVersion"],
            )
            .await;
        self.spawn_unbind(ldap);
        let (rs, _) = result
            .map_err(|e| format!("LDAP search failed: {}", e))?
            .success()
            .map_err(|e| format!("LDAP search error: {}", e))?;

        if let Some(entry) = rs.into_iter().next() {
            let se = SearchEntry::construct(entry);
            let versions = se
                .attrs
                .get("supportedLDAPVersion")
                .map(|v| v.join(", "))
                .unwrap_or_else(|| "unknown".to_string());
            Ok(format!("Connected to LDAP server (versions: {})", versions))
        } else {
            Ok("Connected to LDAP server".to_string())
        }
    }
}

/// LDAP status information
#[derive(Debug, Clone, serde::Serialize)]
pub struct LdapStatus {
    pub enabled: bool,
    pub url: String,
    pub base_dn: String,
    pub use_tls: bool,
    pub use_starttls: bool,
    pub fallback_to_local: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = LdapConfig::default();
        assert!(!config.enabled);
        assert!(config.fallback_to_local);
        assert_eq!(config.username_attr, "uid");
        assert_eq!(config.email_attr, "mail");
    }

    #[test]
    fn test_user_filter_replacement() {
        let config = LdapConfig::default();
        let filter = config.user_filter.replace("{username}", "testuser");
        assert!(filter.contains("testuser"));
        assert!(!filter.contains("{username}"));
    }

    #[test]
    fn test_user_dn_template_default_none() {
        let config = LdapConfig::default();
        assert!(config.user_dn_template.is_none());
    }

    #[test]
    fn test_dn_escape_in_template() {
        // ldap3::dn_escape uses RFC 4514 hex escapes.
        assert_eq!(dn_escape("alice"), "alice");
        assert_eq!(
            dn_escape("a,b+c\"d\\e<f>g;h=i"),
            "a\\2cb\\2bc\\22d\\5ce\\3cf\\3eg\\3bh\\3di"
        );
        assert_eq!(dn_escape("#lead"), "\\23lead");
        assert_eq!(dn_escape("mid#dle"), "mid#dle");
        assert_eq!(dn_escape(" x "), "\\20x\\20");
        assert_eq!(dn_escape("a\0b"), "a\\00b");
        assert_eq!(dn_escape("ünï"), "ünï");
        let template = "uid={username},ou=users,dc=example,dc=com";
        let dn = template.replace("{username}", &dn_escape("x,ou=admins"));
        assert_eq!(dn, "uid=x\\2cou\\3dadmins,ou=users,dc=example,dc=com");
    }

    #[test]
    fn test_filter_escaping() {
        let client = LdapClient::new(LdapConfig::default());
        let f = client.user_filter_for("*)(uid=*");
        assert_eq!(
            f,
            "(&(objectClass=inetOrgPerson)(uid=\\2a\\29\\28uid=\\2a))"
        );
        // Backslash and NUL are escaped too.
        let f = client.user_filter_for("a\\b\0c");
        assert_eq!(f, "(&(objectClass=inetOrgPerson)(uid=a\\5cb\\00c))");
    }

    #[tokio::test]
    async fn test_unresponsive_server_times_out_as_error() {
        // A server that accepts connections but never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });

        let client = LdapClient::new(LdapConfig {
            enabled: true,
            url: format!("ldap://{}", addr),
            user_dn_template: Some("uid={username},dc=example,dc=com".to_string()),
            timeout_seconds: 1,
            ..LdapConfig::default()
        });
        let started = std::time::Instant::now();
        let result = client.authenticate("alice", "pw").await;
        assert!(
            matches!(result, LdapAuthResult::Error(_)),
            "timeout must map to Error so local fallback runs: {:?}",
            result
        );
        // One overall budget (6 x 1s) for both phases, not one per phase.
        assert!(started.elapsed() < Duration::from_secs(8));
        match result {
            LdapAuthResult::Error(e) => assert!(!e.is_empty()),
            other => panic!("expected Error, got {:?}", other),
        }
        accept.abort();
    }

    #[test]
    fn test_parse_timeout() {
        assert_eq!(parse_timeout("5", 10), 5);
        assert_eq!(parse_timeout(" 7 ", 10), 7);
        assert_eq!(parse_timeout("0", 10), 1);
        assert_eq!(parse_timeout("abc", 10), 10);
        assert_eq!(parse_timeout("-3", 10), 10);
    }

    #[tokio::test]
    async fn test_empty_password_rejected() {
        let config = LdapConfig {
            enabled: true,
            // Unroutable: if a bind were attempted this would be an Error.
            url: "ldap://127.0.0.1:1".to_string(),
            user_dn_template: Some("uid={username},dc=example,dc=com".to_string()),
            ..LdapConfig::default()
        };
        let client = LdapClient::new(config);
        assert!(matches!(
            client.authenticate("alice", "").await,
            LdapAuthResult::InvalidCredentials
        ));
        assert!(matches!(
            client.authenticate("", "pw").await,
            LdapAuthResult::InvalidCredentials
        ));
    }

    #[test]
    fn test_resolve_connection_modes() {
        let mut c = LdapConfig {
            enabled: true,
            url: "ldap://host:389".to_string(),
            ..LdapConfig::default()
        };
        assert_eq!(
            resolve_connection(&c),
            ("ldap://host:389".to_string(), false)
        );
        c.use_starttls = true;
        assert_eq!(
            resolve_connection(&c),
            ("ldap://host:389".to_string(), true)
        );
        c.use_tls = true;
        assert_eq!(
            resolve_connection(&c),
            ("ldaps://host:636".to_string(), false)
        );
        c.url = "ldaps://host".to_string();
        assert_eq!(resolve_connection(&c), ("ldaps://host".to_string(), false));

        let client = LdapClient::new(LdapConfig {
            enabled: true,
            url: "ldap://h".to_string(),
            use_tls: true,
            ..LdapConfig::default()
        });
        let st = client.status();
        assert!(st.use_tls);
        assert!(!st.use_starttls);
        assert_eq!(st.url, "ldaps://h");
    }

    #[tokio::test]
    async fn test_disabled_ldap() {
        let client = LdapClient::new(LdapConfig::default());
        assert!(!client.is_enabled());

        let result = client.authenticate("user", "pass").await;
        assert!(matches!(result, LdapAuthResult::NotEnabled));
    }
}
