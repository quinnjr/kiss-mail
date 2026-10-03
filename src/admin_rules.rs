//! Admin rules shared by the admin API (axum) and the admin web (actix).
//!
//! Framework-free: session/token storage, the permission rules for creating
//! and updating accounts, the single implementation of a user update, the
//! cleanup after a user is deleted (plus a purge of orphaned data), and the
//! client IP resolution behind trusted reverse proxies.

use chrono::{DateTime, Utc};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::crypto::CryptoManager;
use crate::groups::GroupManager;
use crate::sso::SsoManager;
use crate::storage::Storage;
use crate::users::{
    AccountStatus, PasswordChangeFailure, UserAccount, UserManager, UserRole, canonical_username,
};

// ============================================================================
// Sessions and tokens
// ============================================================================

#[derive(Debug, Clone)]
struct SessionEntry<V> {
    value: V,
    expires_at: Instant,
}

impl<V> SessionEntry<V> {
    fn is_expired_at(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// In-memory map of random token -> session value with expiry.
///
/// Used for web admin sessions and admin API session tokens.
#[derive(Debug, Clone)]
pub struct SessionStore<V: Clone> {
    inner: Arc<RwLock<HashMap<String, SessionEntry<V>>>>,
}

impl<V: Clone> Default for SessionStore<V> {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<V: Clone> SessionStore<V> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a session lasting `ttl`; returns the token.
    pub async fn create(&self, value: V, ttl: Duration) -> String {
        self.create_expiring_at(value, Instant::now() + ttl).await
    }

    /// Create a session that expires at `expires_at` (expired sessions are
    /// purged first); returns the token.
    pub async fn create_expiring_at(&self, value: V, expires_at: Instant) -> String {
        let token = generate_session_token();
        let mut map = self.inner.write().await;
        let now = Instant::now();
        map.retain(|_, s| !s.is_expired_at(now));
        map.insert(token.clone(), SessionEntry { value, expires_at });
        token
    }

    /// Look up a token; an expired session is removed and yields `None`.
    pub async fn lookup(&self, token: &str) -> Option<V> {
        let entry = self.inner.read().await.get(token).cloned()?;
        if entry.is_expired_at(Instant::now()) {
            self.remove(token).await;
            return None;
        }
        Some(entry.value)
    }

    /// Remove a session.
    pub async fn remove(&self, token: &str) {
        self.inner.write().await.remove(token);
    }

    /// Drop every expired session.
    pub async fn purge_expired(&self) {
        let now = Instant::now();
        self.inner
            .write()
            .await
            .retain(|_, s| !s.is_expired_at(now));
    }

    /// Whether a token is stored (expired or not).
    #[cfg(test)]
    pub async fn contains(&self, token: &str) -> bool {
        self.inner.read().await.contains_key(token)
    }
}

/// 32 random bytes, hex-encoded.
pub(crate) fn generate_session_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Whether a session issued when the account's password was last changed at
/// `issued_for` is still valid for `user`: the password has not changed
/// since, and no password change is pending.
pub(crate) fn session_is_current(issued_for: DateTime<Utc>, user: &UserAccount) -> bool {
    user.password_changed_at <= issued_for && !user.password_change_required
}

// ============================================================================
// Permission rules
// ============================================================================

/// Only a super administrator may create accounts with a role above `User`.
pub(crate) fn check_create_role(actor: &UserAccount, role: UserRole) -> Result<(), String> {
    if role != UserRole::User && actor.role != UserRole::SuperAdmin {
        return Err("Only super administrators can create administrator accounts".to_string());
    }
    Ok(())
}

/// The changes an admin user update would apply (only real changes).
#[derive(Default)]
pub(crate) struct PlannedUserUpdate {
    /// New password (admin reset).
    pub password: Option<String>,
    /// New display name (`Some(None)` clears it).
    pub display_name: Option<Option<String>>,
    pub role: Option<UserRole>,
    pub status: Option<AccountStatus>,
}

impl PlannedUserUpdate {
    fn is_empty(&self) -> bool {
        self.password.is_none()
            && self.display_name.is_none()
            && self.role.is_none()
            && self.status.is_none()
    }

    /// Plan a display name change when the submitted name (trimmed; empty
    /// means "no display name") differs from `current`.
    pub(crate) fn set_display_name(&mut self, submitted: &str, current: &Option<String>) {
        let name = Some(submitted.trim().to_string()).filter(|n| !n.is_empty());
        self.display_name = (name != *current).then_some(name);
    }
}

/// Check every permission an admin update needs before anything is applied.
/// Mirrors the rules enforced by `UserManager` (role changes need a super
/// admin and never apply to yourself; super admins can only be modified by
/// super admins).
pub(crate) fn check_update_permissions(
    actor: &UserAccount,
    target: &UserAccount,
    plan: &PlannedUserUpdate,
) -> Result<(), String> {
    if plan.is_empty() {
        return Ok(());
    }
    if actor.role == UserRole::User {
        return Err("Only administrators can modify users".to_string());
    }
    if target.role == UserRole::SuperAdmin && actor.role != UserRole::SuperAdmin {
        return Err("Only super administrators can modify super administrators".to_string());
    }
    if plan.role.is_some() {
        if actor.role != UserRole::SuperAdmin {
            return Err("Only super administrators can change user roles".to_string());
        }
        if canonical_username(&actor.username) == canonical_username(&target.username) {
            return Err("Cannot change your own role".to_string());
        }
    }
    Ok(())
}

/// What [`apply_user_update`] did.
#[derive(Debug, Default)]
pub(crate) struct UpdateReport {
    /// One message per step that failed (`"<Field>: <error>"`).
    pub errors: Vec<String>,
    /// App passwords revoked because the password was reset.
    pub revoked_app_passwords: usize,
}

/// Apply a (permission-checked) plan to `target`, in a fixed order:
/// password, display name, role, status. Each step is attempted even if an
/// earlier one failed. A successful password reset also revokes all of the
/// user's app passwords (an admin reset means the old credentials must stop
/// working).
pub(crate) async fn apply_user_update(
    user_manager: &UserManager,
    sso: &SsoManager,
    actor: &UserAccount,
    target: &UserAccount,
    plan: &PlannedUserUpdate,
) -> UpdateReport {
    let mut report = UpdateReport::default();
    let user = target.username.as_str();

    if let Some(password) = &plan.password {
        match user_manager
            .admin_reset_password(user, password, actor, false)
            .await
        {
            Ok(()) => match sso.revoke_all_app_passwords(user).await {
                Ok(n) => {
                    if n > 0 {
                        tracing::info!(
                            "Revoked {} app password(s) of {} after an admin password reset",
                            n,
                            user
                        );
                    }
                    report.revoked_app_passwords = n;
                }
                Err(e) => report
                    .errors
                    .push(format!("App passwords: could not revoke: {}", e)),
            },
            Err(e) => report.errors.push(format!("Password: {}", e)),
        }
    }

    if let Some(name) = &plan.display_name {
        let name = name.clone();
        if let Err(e) = user_manager
            .update_user(user, |u| u.settings.display_name = name)
            .await
        {
            report.errors.push(format!("Display name: {}", e));
        }
    }

    if let Some(role) = plan.role {
        if let Err(e) = user_manager.set_role(user, role, actor).await {
            report.errors.push(format!("Role: {}", e));
        }
    }

    if let Some(status) = plan.status {
        if let Err(e) = user_manager.set_status(user, status, actor).await {
            report.errors.push(format!("Status: {}", e));
        }
    }

    report
}

/// HTTP status for a failed self-service password change (shared by the web
/// page and the API so both map failures the same way).
pub(crate) fn password_change_status(failure: &PasswordChangeFailure) -> u16 {
    match failure {
        PasswordChangeFailure::Weak(_) => 400,
        PasswordChangeFailure::BadCredentials => 401,
        PasswordChangeFailure::ExternallyManaged => 403,
        PasswordChangeFailure::Locked => 429,
        PasswordChangeFailure::Storage(_) => 500,
    }
}

/// User-facing message for a failed password change. Storage failures are
/// logged and reported generically.
pub(crate) fn password_change_message(username: &str, failure: &PasswordChangeFailure) -> String {
    match failure {
        PasswordChangeFailure::Storage(e) => {
            tracing::error!("Password change for {} failed: {}", username, e);
            "Could not change the password (see server log)".to_string()
        }
        other => other.user_message(),
    }
}

// ============================================================================
// Deleted users and orphaned data
// ============================================================================

/// After a user was deleted, remove their mailbox, SSO data, encryption keys
/// and group memberships (groups they owned pass to another administrator,
/// see [`GroupManager::remove_user_everywhere`]). Returns a description of
/// each cleanup step that failed (also logged).
///
/// Every step is idempotent, so this is safe to re-run after a partial
/// failure. It refuses to touch anything while an account of that name
/// exists.
pub(crate) async fn cleanup_deleted_user(
    user_manager: &UserManager,
    storage: &Storage,
    sso: &SsoManager,
    crypto: Option<&CryptoManager>,
    groups: &GroupManager,
    username: &str,
) -> Vec<String> {
    let username = canonical_username(username);
    if user_manager.user_exists(&username).await {
        tracing::warn!("Not cleaning up data of {}: the account exists", username);
        return vec![format!("account {} exists; nothing was removed", username)];
    }

    let mut failures = Vec::new();
    let mut fail = |what: &str, e: &dyn std::fmt::Display| {
        tracing::warn!(
            "Could not remove {} of deleted user {}: {}",
            what,
            username,
            e
        );
        failures.push(format!("removing {} failed: {}", what, e));
    };
    if let Err(e) = storage.remove_mailbox(&username).await {
        fail("mailbox", &e);
    }
    if let Err(e) = sso.remove_user(&username).await {
        fail("SSO data", &e);
    }
    if let Some(crypto) = crypto {
        if let Err(e) = crypto.delete_keys(&username).await {
            fail("encryption keys", &e);
        }
    }
    if let Err(e) = groups.remove_user_everywhere(&username).await {
        fail("group memberships", &e);
    }
    failures
}

/// What [`purge_orphans`] did.
#[derive(Debug, Default)]
pub(crate) struct PurgeReport {
    /// Users (canonical names, sorted) whose leftover data was cleaned up.
    pub purged: Vec<String>,
    /// One message per failed cleanup step.
    pub failures: Vec<String>,
}

/// Usernames (canonical) that are keys of the JSON object in `path`.
/// A missing file yields nothing; an unreadable one is a failure.
async fn json_keys(path: &Path, failures: &mut Vec<String>) -> Vec<String> {
    match crate::storage::read_json::<HashMap<String, serde::de::IgnoredAny>>(path).await {
        Ok(Some(map)) => map.keys().map(|k| canonical_username(k)).collect(),
        Ok(None) => Vec::new(),
        Err(e) => {
            failures.push(format!("reading {} failed: {}", path.display(), e));
            Vec::new()
        }
    }
}

/// Remove data left behind by users that no longer exist: mailboxes
/// (`mailboxes.json`), SSO data (`sso_data.json`), encryption keys
/// (`keys.json`) and group memberships/ownership. Each orphaned name gets
/// the same idempotent [`cleanup_deleted_user`] as an interactive delete.
///
/// Names are taken from the persisted files in `data_dir` and from the
/// loaded groups, so call this after everything has been loaded.
pub(crate) async fn purge_orphans(
    data_dir: &Path,
    user_manager: &UserManager,
    storage: &Storage,
    sso: &SsoManager,
    crypto: Option<&CryptoManager>,
    groups: &GroupManager,
) -> PurgeReport {
    let mut report = PurgeReport::default();

    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for file in ["mailboxes.json", "sso_data.json", "keys.json"] {
        candidates.extend(json_keys(&data_dir.join(file), &mut report.failures).await);
    }
    candidates.extend(groups.validate_members().await.into_iter().map(|(_, u)| u));
    // Without a user manager attached validate_members reports nothing, so
    // also look at every group directly.
    for g in groups.list().await {
        candidates.extend(g.members);
        candidates.extend(g.managers);
        candidates.insert(g.owner);
    }

    for name in candidates {
        if name.is_empty() || user_manager.user_exists(&name).await {
            continue;
        }
        let failures =
            cleanup_deleted_user(user_manager, storage, sso, crypto, groups, &name).await;
        report.purged.push(name.clone());
        report
            .failures
            .extend(failures.into_iter().map(|f| format!("{}: {}", name, f)));
    }
    if !report.purged.is_empty() {
        tracing::info!(
            "Purged leftover data of {} deleted user(s): {}",
            report.purged.len(),
            report.purged.join(", ")
        );
    }
    report
}

// ============================================================================
// Client IP behind trusted proxies
// ============================================================================

/// Trusted proxies when `KISS_MAIL_TRUSTED_PROXIES` is unset.
const DEFAULT_TRUSTED_PROXIES: &str = "127.0.0.1/32,::1/128";

/// An IP network (`addr/prefix`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `a.b.c.d/n`, `x::y/n` or a bare address (full-length prefix).
    fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim().parse::<u8>().ok()?)),
            None => (s, None),
        };
        let addr = addr.parse::<IpAddr>().ok()?.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Self { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// Parse a comma-separated CIDR list; invalid entries are logged and skipped.
fn parse_cidrs(list: &str) -> Vec<Cidr> {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let parsed = Cidr::parse(s);
            if parsed.is_none() {
                tracing::warn!("KISS_MAIL_TRUSTED_PROXIES: ignoring invalid entry '{}'", s);
            }
            parsed
        })
        .collect()
}

static TRUSTED_PROXIES: LazyLock<Vec<Cidr>> = LazyLock::new(|| {
    parse_cidrs(
        &crate::config::env_nonempty("KISS_MAIL_TRUSTED_PROXIES")
            .unwrap_or_else(|| DEFAULT_TRUSTED_PROXIES.to_string()),
    )
});

/// The client's IP address for logging, throttling and IP allow-lists.
///
/// `peer` is the TCP peer. Only when it is a trusted proxy
/// (`KISS_MAIL_TRUSTED_PROXIES`, comma-separated CIDRs; default
/// `127.0.0.1/32,::1/128`) are forwarding headers believed: `X-Real-IP`
/// first, else the rightmost `X-Forwarded-For` entry that is not itself a
/// trusted proxy. Otherwise the peer address is used ("unknown" if none).
pub(crate) fn client_ip(
    peer: Option<IpAddr>,
    x_real_ip: Option<&str>,
    xff: Option<&str>,
) -> String {
    client_ip_with(&TRUSTED_PROXIES, peer, x_real_ip, xff)
}

fn client_ip_with(
    trusted: &[Cidr],
    peer: Option<IpAddr>,
    x_real_ip: Option<&str>,
    xff: Option<&str>,
) -> String {
    let Some(peer) = peer.map(|p| p.to_canonical()) else {
        return "unknown".to_string();
    };
    let is_trusted = |ip: IpAddr| trusted.iter().any(|c| c.contains(ip));
    if !is_trusted(peer) {
        return peer.to_string();
    }
    let parse = |s: &str| s.trim().parse::<IpAddr>().ok().map(|ip| ip.to_canonical());
    if let Some(ip) = x_real_ip.and_then(parse) {
        return ip.to_string();
    }
    if let Some(xff) = xff {
        for entry in xff.rsplit(',') {
            match parse(entry) {
                Some(ip) if is_trusted(ip) => continue,
                Some(ip) => return ip.to_string(),
                // A malformed hop: stop trusting anything further left.
                None => break,
            }
        }
    }
    peer.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sso::SsoConfig;
    use tempfile::tempdir;

    #[tokio::test]
    async fn session_store_lookup_remove_and_expiry() {
        let store = SessionStore::new();
        let token = store
            .create("admin".to_string(), Duration::from_secs(60))
            .await;
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(store.lookup(&token).await.as_deref(), Some("admin"));
        // A raw username is not a valid session token.
        assert!(store.lookup("admin").await.is_none());
        store.remove(&token).await;
        assert!(store.lookup(&token).await.is_none());

        let expired = store
            .create_expiring_at("admin".to_string(), Instant::now())
            .await;
        assert!(store.lookup(&expired).await.is_none());
        assert!(!store.contains(&expired).await);
        let stale = store
            .create_expiring_at("old".to_string(), Instant::now())
            .await;
        let fresh = store
            .create("new".to_string(), Duration::from_secs(60))
            .await;
        store.purge_expired().await;
        assert!(!store.contains(&stale).await);
        assert!(store.contains(&fresh).await);
        assert_ne!(generate_session_token(), generate_session_token());
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn cidr_parse_and_contains() {
        let c = Cidr::parse("172.16.0.0/12").unwrap();
        assert!(c.contains("172.31.255.1".parse().unwrap()));
        assert!(!c.contains("172.32.0.1".parse().unwrap()));
        // IPv4-mapped IPv6 peers match IPv4 networks.
        assert!(c.contains("::ffff:172.16.0.5".parse().unwrap()));
        let c = Cidr::parse("fd00::/8").unwrap();
        assert!(c.contains("fd12::1".parse().unwrap()));
        assert!(!c.contains("fe80::1".parse().unwrap()));
        assert_eq!(Cidr::parse("10.0.0.1"), Cidr::parse("10.0.0.1/32"));
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("nonsense").is_none());
        assert_eq!(parse_cidrs("127.0.0.1/32, bad, ::1/128").len(), 2);
    }

    #[test]
    fn trusted_peer_uses_x_real_ip() {
        let trusted = parse_cidrs(DEFAULT_TRUSTED_PROXIES);
        assert_eq!(
            client_ip_with(
                &trusted,
                ip("127.0.0.1"),
                Some(" 203.0.113.7 "),
                Some("1.1.1.1")
            ),
            "203.0.113.7"
        );
        assert_eq!(
            client_ip_with(&trusted, ip("::1"), Some("2001:db8::5"), None),
            "2001:db8::5"
        );
        // A garbage X-Real-IP falls through to X-Forwarded-For, then the peer.
        assert_eq!(
            client_ip_with(
                &trusted,
                ip("127.0.0.1"),
                Some("junk"),
                Some("198.51.100.2")
            ),
            "198.51.100.2"
        );
        assert_eq!(
            client_ip_with(&trusted, ip("127.0.0.1"), None, None),
            "127.0.0.1"
        );
    }

    #[test]
    fn untrusted_peer_ignores_headers() {
        let trusted = parse_cidrs(DEFAULT_TRUSTED_PROXIES);
        assert_eq!(
            client_ip_with(
                &trusted,
                ip("198.51.100.9"),
                Some("10.0.0.1"),
                Some("10.0.0.2")
            ),
            "198.51.100.9"
        );
        assert_eq!(
            client_ip_with(&trusted, ip("::ffff:198.51.100.9"), Some("10.0.0.1"), None),
            "198.51.100.9"
        );
        assert_eq!(
            client_ip_with(&trusted, None, Some("10.0.0.1"), None),
            "unknown"
        );
    }

    #[test]
    fn rightmost_untrusted_xff_entry_wins() {
        let trusted = parse_cidrs("127.0.0.1/32,10.0.0.0/8");
        // client (spoofable) , real client , inner proxy
        assert_eq!(
            client_ip_with(
                &trusted,
                ip("127.0.0.1"),
                None,
                Some("6.6.6.6, 203.0.113.50, 10.1.2.3")
            ),
            "203.0.113.50"
        );
        // Only trusted hops: the peer.
        assert_eq!(
            client_ip_with(&trusted, ip("127.0.0.1"), None, Some("10.0.0.1, 10.0.0.2")),
            "127.0.0.1"
        );
        // A malformed hop stops the walk.
        assert_eq!(
            client_ip_with(
                &trusted,
                ip("127.0.0.1"),
                None,
                Some("6.6.6.6, junk, 10.0.0.1")
            ),
            "127.0.0.1"
        );
    }

    #[test]
    fn display_name_plan_trims_and_detects_changes() {
        let mut plan = PlannedUserUpdate::default();
        plan.set_display_name("  Bob  ", &Some("Bob".into()));
        assert!(plan.display_name.is_none());
        plan.set_display_name("   ", &Some("Bob".into()));
        assert_eq!(plan.display_name, Some(None));
        plan.set_display_name("", &None);
        assert!(plan.display_name.is_none());
        plan.set_display_name(" Robert ", &None);
        assert_eq!(plan.display_name, Some(Some("Robert".into())));
    }

    struct Env {
        _dir: tempfile::TempDir,
        data: std::path::PathBuf,
        users: Arc<UserManager>,
        storage: Storage,
        sso: SsoManager,
        crypto: CryptoManager,
        groups: GroupManager,
    }

    fn env() -> Env {
        let dir = tempdir().unwrap();
        let data = dir.path().to_path_buf();
        let users = Arc::new(UserManager::new("example.com".into(), data.clone()));
        let groups = GroupManager::new(data.clone());
        groups.attach_user_manager(Arc::clone(&users));
        Env {
            storage: Storage::new(data.clone(), Arc::clone(&users)),
            sso: SsoManager::new(SsoConfig::default(), data.clone()),
            crypto: CryptoManager::with_enabled(data.clone(), true),
            groups,
            users,
            data,
            _dir: dir,
        }
    }

    #[tokio::test]
    async fn apply_user_update_resets_password_and_revokes_app_passwords() {
        let e = env();
        let root = e
            .users
            .create_user("root", "password123", Some(UserRole::SuperAdmin))
            .await
            .unwrap();
        let bob = e
            .users
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        e.sso
            .generate_app_password("bob", "phone", None)
            .await
            .unwrap();
        e.sso
            .generate_app_password("bob", "laptop", None)
            .await
            .unwrap();

        let mut plan = PlannedUserUpdate {
            password: Some("new-password-1".into()),
            role: Some(UserRole::Admin),
            ..Default::default()
        };
        plan.set_display_name(" Bob B ", &bob.settings.display_name);
        check_update_permissions(&root, &bob, &plan).unwrap();
        let report = apply_user_update(&e.users, &e.sso, &root, &bob, &plan).await;
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.revoked_app_passwords, 2);
        assert!(e.sso.list_app_passwords("bob").await.is_empty());
        let bob = e.users.get_user("bob").await.unwrap();
        assert!(bob.verify_password("new-password-1"));
        assert_eq!(bob.settings.display_name.as_deref(), Some("Bob B"));
        assert_eq!(bob.role, UserRole::Admin);

        // A weak password fails that step only; later steps still run.
        let plan = PlannedUserUpdate {
            password: Some("short".into()),
            status: Some(AccountStatus::Suspended),
            ..Default::default()
        };
        let report = apply_user_update(&e.users, &e.sso, &root, &bob, &plan).await;
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].starts_with("Password: "));
        assert_eq!(
            e.users.get_user("bob").await.unwrap().status,
            AccountStatus::Suspended
        );
    }

    #[tokio::test]
    async fn cleanup_is_idempotent_and_refuses_existing_accounts() {
        let e = env();
        let root = e
            .users
            .create_user("root", "password123", Some(UserRole::SuperAdmin))
            .await
            .unwrap();
        e.users
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        e.storage.ensure_mailbox("bob").await;
        e.sso
            .generate_app_password("bob", "phone", None)
            .await
            .unwrap();
        e.crypto
            .generate_keypair("bob", "password123")
            .await
            .unwrap();
        e.groups
            .create("team", "team@example.com", "bob")
            .await
            .unwrap();
        e.groups.add_member("team", "bob").await.unwrap();

        // While the account exists nothing is touched.
        let failures = cleanup_deleted_user(
            &e.users,
            &e.storage,
            &e.sso,
            Some(&e.crypto),
            &e.groups,
            "Bob",
        )
        .await;
        assert_eq!(failures.len(), 1);
        assert!(e.crypto.has_keys("bob").await);
        assert!(!e.sso.list_app_passwords("bob").await.is_empty());

        e.users.delete_user("bob", &root).await.unwrap();
        for _ in 0..2 {
            let failures = cleanup_deleted_user(
                &e.users,
                &e.storage,
                &e.sso,
                Some(&e.crypto),
                &e.groups,
                "bob",
            )
            .await;
            assert!(failures.is_empty(), "{:?}", failures);
        }
        assert!(!e.crypto.has_keys("bob").await);
        assert!(e.sso.get_user_data("bob").await.is_none());
        assert!(e.storage.message_meta("bob").await.is_none());
        let g = e.groups.get("team").await.unwrap();
        assert!(!g.is_member("bob"));
        assert_ne!(g.owner, "bob");
    }

    #[tokio::test]
    async fn cleanup_reports_key_deletion_failure() {
        let e = env();
        // Keys can never be saved: keys.json exists but is unreadable.
        std::fs::write(e.data.join("keys.json"), b"garbage").unwrap();
        let broken = CryptoManager::with_enabled(e.data.clone(), true);
        assert!(broken.load_error().is_some());
        let failures = cleanup_deleted_user(
            &e.users,
            &e.storage,
            &e.sso,
            Some(&broken),
            &e.groups,
            "ghost",
        )
        .await;
        assert_eq!(failures.len(), 1, "{:?}", failures);
        assert!(failures[0].contains("encryption keys"), "{:?}", failures);
    }

    #[tokio::test]
    async fn purge_orphans_removes_leftovers_of_missing_users() {
        let e = env();
        e.users
            .create_user("alice", "password123", None)
            .await
            .unwrap();
        for u in ["alice", "ghost"] {
            e.storage.ensure_mailbox(u).await;
            e.sso.generate_app_password(u, "phone", None).await.unwrap();
            e.crypto.generate_keypair(u, "password123").await.unwrap();
        }
        e.storage.save().await.unwrap();
        // Written without a user manager, so the unknown member is kept.
        let members = vec!["alice".to_string(), "phantom".to_string()];
        GroupManager::new(e.data.clone())
            .create_with_members("team", "team@example.com", "alice", None, &members)
            .await
            .unwrap();
        e.groups.load().await.unwrap();

        let report = purge_orphans(
            &e.data,
            &e.users,
            &e.storage,
            &e.sso,
            Some(&e.crypto),
            &e.groups,
        )
        .await;
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(
            report.purged,
            vec!["ghost".to_string(), "phantom".to_string()]
        );
        assert!(!e.crypto.has_keys("ghost").await);
        assert!(e.crypto.has_keys("alice").await);
        assert!(e.sso.get_user_data("ghost").await.is_none());
        assert!(e.sso.get_user_data("alice").await.is_some());
        assert!(e.storage.message_meta("ghost").await.is_none());
        assert!(e.storage.message_meta("alice").await.is_some());
        let g = e.groups.get("team").await.unwrap();
        assert!(g.is_member("alice") && !g.is_member("phantom"));

        // Nothing left the second time.
        let report = purge_orphans(
            &e.data,
            &e.users,
            &e.storage,
            &e.sso,
            Some(&e.crypto),
            &e.groups,
        )
        .await;
        assert!(report.purged.is_empty());
    }

    #[test]
    fn session_currency_tracks_password_changes() {
        let mut user = UserAccount::new("bob".into(), "password123", "example.com".into()).unwrap();
        let issued = user.password_changed_at;
        assert!(session_is_current(issued, &user));
        user.password_change_required = true;
        assert!(!session_is_current(issued, &user));
        user.password_change_required = false;
        user.password_changed_at = issued + chrono::Duration::seconds(1);
        assert!(!session_is_current(issued, &user));
    }
}
