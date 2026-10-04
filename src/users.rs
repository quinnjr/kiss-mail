//! Comprehensive user management module.
//!
//! Provides user CRUD operations, authentication, roles, quotas, and admin functions.

use crate::crypto::CryptoManager;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore, SemaphorePermit};

/// The account created on first start (and the identity the CLI acts as).
pub const BOOTSTRAP_ADMIN: &str = "admin";

/// Usernames that can never be created (they name built-in API principals).
pub const RESERVED_USERNAMES: &[&str] = &["api-key", "api-admin"];

/// Longest accepted username, in bytes (also bounds login throttle keys).
pub const MAX_USERNAME_LEN: usize = 64;

/// Canonical form of a username / mailbox key (trimmed, lowercase).
pub fn canonical_username(s: &str) -> String {
    s.trim().to_lowercase()
}

/// Canonical local part of an address (`Alice@Example.com` -> `alice`); a
/// string without `@` is canonicalised as a whole.
pub fn local_part(addr: &str) -> String {
    match addr.rsplit_once('@') {
        Some((local, _)) => canonical_username(local),
        None => canonical_username(addr),
    }
}

/// User role for access control
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    /// Regular user - can send/receive emails
    #[default]
    User,
    /// Administrator - can manage users and server settings
    Admin,
    /// Super administrator - full access including other admins
    SuperAdmin,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::User => write!(f, "user"),
            UserRole::Admin => write!(f, "admin"),
            UserRole::SuperAdmin => write!(f, "superadmin"),
        }
    }
}

impl FromStr for UserRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "user" => Ok(UserRole::User),
            "admin" => Ok(UserRole::Admin),
            "superadmin" | "super_admin" | "super-admin" => Ok(UserRole::SuperAdmin),
            other => Err(format!("unknown role: {}", other)),
        }
    }
}

/// Account status
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountStatus {
    /// Account is active and can be used
    #[default]
    Active,
    /// Account is suspended (can't login)
    Suspended,
    /// Account is locked by an administrator (failed logins only cause a
    /// temporary, per-IP throttle; see `LoginThrottle`)
    Locked,
    /// Account is pending email verification
    PendingVerification,
    /// Account is disabled permanently
    Disabled,
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountStatus::Active => write!(f, "active"),
            AccountStatus::Suspended => write!(f, "suspended"),
            AccountStatus::Locked => write!(f, "locked"),
            AccountStatus::PendingVerification => write!(f, "pending"),
            AccountStatus::Disabled => write!(f, "disabled"),
        }
    }
}

impl FromStr for AccountStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "active" => Ok(AccountStatus::Active),
            "suspended" => Ok(AccountStatus::Suspended),
            "disabled" => Ok(AccountStatus::Disabled),
            "locked" => Ok(AccountStatus::Locked),
            "pending" | "pendingverification" => Ok(AccountStatus::PendingVerification),
            other => Err(format!("unknown account status: {}", other)),
        }
    }
}

/// User quota settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserQuota {
    /// Maximum mailbox size in bytes (0 = unlimited)
    pub max_mailbox_size: u64,
    /// Maximum single message size in bytes
    pub max_message_size: u64,
    /// Maximum number of messages (0 = unlimited)
    pub max_messages: u32,
    /// Maximum outgoing emails per day (0 = unlimited)
    pub max_outgoing_per_day: u32,
    /// Current mailbox usage in bytes
    pub current_usage: u64,
    /// Current message count
    pub current_messages: u32,
    /// Outgoing emails sent today
    pub outgoing_today: u32,
    /// Date of last outgoing count reset
    pub outgoing_reset_date: DateTime<Utc>,
}

impl Default for UserQuota {
    fn default() -> Self {
        Self {
            max_mailbox_size: 100 * 1024 * 1024, // 100MB
            max_message_size: 25 * 1024 * 1024,  // 25MB
            max_messages: 10000,
            max_outgoing_per_day: 500,
            current_usage: 0,
            current_messages: 0,
            outgoing_today: 0,
            outgoing_reset_date: Utc::now(),
        }
    }
}

impl UserQuota {
    /// Check if user can receive a message of given size
    pub fn can_receive(&self, message_size: u64) -> Result<(), QuotaError> {
        if self.max_message_size > 0 && message_size > self.max_message_size {
            return Err(QuotaError::MessageTooLarge {
                size: message_size,
                max: self.max_message_size,
            });
        }

        if self.max_mailbox_size > 0 && self.current_usage + message_size > self.max_mailbox_size {
            return Err(QuotaError::MailboxFull {
                current: self.current_usage,
                max: self.max_mailbox_size,
            });
        }

        if self.max_messages > 0 && self.current_messages >= self.max_messages {
            return Err(QuotaError::TooManyMessages {
                current: self.current_messages,
                max: self.max_messages,
            });
        }

        Ok(())
    }

    /// Record a received message
    pub fn record_received(&mut self, size: u64) {
        self.current_usage += size;
        self.current_messages += 1;
    }

    /// Get usage percentage
    pub fn usage_percent(&self) -> f32 {
        if self.max_mailbox_size == 0 {
            return 0.0;
        }
        (self.current_usage as f32 / self.max_mailbox_size as f32) * 100.0
    }
}

/// Quota error types
#[derive(Debug, Clone)]
pub enum QuotaError {
    MessageTooLarge { size: u64, max: u64 },
    MailboxFull { current: u64, max: u64 },
    TooManyMessages { current: u32, max: u32 },
}

impl std::fmt::Display for QuotaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuotaError::MessageTooLarge { size, max } => {
                write!(f, "Message too large: {} bytes (max: {} bytes)", size, max)
            }
            QuotaError::MailboxFull { current, max } => {
                write!(f, "Mailbox full: {} / {} bytes", current, max)
            }
            QuotaError::TooManyMessages { current, max } => {
                write!(f, "Too many messages: {} / {}", current, max)
            }
        }
    }
}

/// User settings and preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSettings {
    /// Display name
    pub display_name: Option<String>,
    /// Auto-reply message (vacation responder)
    pub auto_reply: Option<String>,
    /// Auto-reply enabled
    pub auto_reply_enabled: bool,
    /// Forward emails to another address
    pub forward_to: Option<String>,
    /// Keep copy when forwarding
    pub forward_keep_copy: bool,
    /// Signature for outgoing emails
    pub signature: Option<String>,
    /// Preferred language
    pub language: String,
    /// Timezone
    pub timezone: String,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            display_name: None,
            auto_reply: None,
            auto_reply_enabled: false,
            forward_to: None,
            forward_keep_copy: true,
            signature: None,
            language: "en".to_string(),
            timezone: "UTC".to_string(),
        }
    }
}

/// Login history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRecord {
    pub timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub protocol: String, // SMTP, IMAP, POP3
    pub success: bool,
    pub failure_reason: Option<String>,
    /// Whether the connection was TLS-protected (absent in older records).
    #[serde(default)]
    pub tls: bool,
}

/// Complete user account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    /// Unique username (email local part)
    pub username: String,
    /// Hashed password (Argon2)
    pub password_hash: String,
    /// User's email domain
    pub domain: String,
    /// User role
    pub role: UserRole,
    /// Account status
    pub status: AccountStatus,
    /// Quota settings
    pub quota: UserQuota,
    /// User settings
    pub settings: UserSettings,
    /// Account creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
    /// Last successful login
    pub last_login: Option<DateTime<Utc>>,
    /// Failed login attempts since the last success (informational; lockout
    /// is enforced by the in-memory per-IP throttle)
    pub failed_login_attempts: u32,
    /// Last failed login attempt
    pub last_failed_login: Option<DateTime<Utc>>,
    /// Login history (last N entries)
    pub login_history: Vec<LoginRecord>,
    /// Password change required on next login
    pub password_change_required: bool,
    /// Password last changed
    pub password_changed_at: DateTime<Utc>,
    /// Allowed IP addresses (empty = all allowed)
    pub allowed_ips: Vec<String>,
    /// Account notes (admin only)
    pub admin_notes: Option<String>,
    /// Set when the password is managed by an external directory (`"ldap"`
    /// for LDAP-provisioned accounts); such accounts cannot change their
    /// password here.
    #[serde(default)]
    pub external_auth: Option<String>,
}

impl UserAccount {
    /// Create a new user account
    #[cfg(test)]
    pub fn new(username: String, password: &str, domain: String) -> Result<Self, String> {
        let password_hash = hash_password(password)?;
        Ok(Self::with_hash(username, password_hash, domain))
    }

    /// Create a new user account from an already computed password hash,
    /// with defaults for every other field (Active, role User, no external
    /// auth). Use this instead of a struct literal so new fields do not
    /// break callers (an empty hash never verifies).
    pub(crate) fn with_hash(username: String, password_hash: String, domain: String) -> Self {
        let now = Utc::now();

        Self {
            username,
            password_hash,
            domain,
            role: UserRole::User,
            status: AccountStatus::Active,
            quota: UserQuota::default(),
            settings: UserSettings::default(),
            created_at: now,
            updated_at: now,
            last_login: None,
            failed_login_attempts: 0,
            last_failed_login: None,
            login_history: Vec::new(),
            password_change_required: false,
            password_changed_at: now,
            allowed_ips: Vec::new(),
            admin_notes: None,
            external_auth: None,
        }
    }

    /// Get the full email address
    pub fn email(&self) -> String {
        format!("{}@{}", self.username, self.domain)
    }

    /// Verify password
    #[cfg(test)]
    pub fn verify_password(&self, password: &str) -> bool {
        verify_password(password, &self.password_hash)
    }

    /// Install an already computed password hash.
    fn set_password_hash(&mut self, hash: String) {
        self.password_hash = hash;
        self.password_changed_at = Utc::now();
        self.password_change_required = false;
        self.updated_at = Utc::now();
    }

    /// Record a login attempt
    pub fn record_login(
        &mut self,
        ip: &str,
        protocol: &str,
        tls: bool,
        success: bool,
        failure_reason: Option<&str>,
    ) {
        let record = LoginRecord {
            timestamp: Utc::now(),
            ip_address: ip.to_string(),
            protocol: protocol.to_string(),
            success,
            failure_reason: failure_reason.map(String::from),
            tls,
        };

        self.login_history.push(record);

        // Keep only last 100 login records
        const MAX_LOGIN_HISTORY: usize = 100;
        if self.login_history.len() > MAX_LOGIN_HISTORY {
            let excess = self.login_history.len() - MAX_LOGIN_HISTORY;
            self.login_history.drain(..excess);
        }

        // Failed attempts are only counted here for display; lockout is a
        // temporary per-(username, ip) throttle and never changes `status`.
        if success {
            self.last_login = Some(Utc::now());
            self.failed_login_attempts = 0;
        } else {
            self.failed_login_attempts = self.failed_login_attempts.saturating_add(1);
            self.last_failed_login = Some(Utc::now());
        }
    }

    /// Check if account can login
    pub fn can_login(&self) -> Result<(), String> {
        match self.status {
            AccountStatus::Active => Ok(()),
            AccountStatus::Suspended => Err("Account is suspended".to_string()),
            AccountStatus::Locked => Err("Account is locked".to_string()),
            AccountStatus::PendingVerification => {
                Err("Account is pending email verification".to_string())
            }
            AccountStatus::Disabled => Err("Account is disabled".to_string()),
        }
    }

    /// Status and IP allow-list check shared by every login path. Only call
    /// it after the credentials have been verified, so the result does not
    /// reveal anything about accounts whose password the caller does not know.
    pub fn check_login_from(&self, ip: &str) -> Result<(), UserError> {
        self.can_login().map_err(UserError::PermissionDenied)?;
        if !self.is_ip_allowed(ip) {
            return Err(UserError::PermissionDenied(format!(
                "Login from IP {} is not allowed",
                ip
            )));
        }
        Ok(())
    }

    /// Whether the password is managed by an external directory (LDAP).
    pub fn is_externally_managed(&self) -> bool {
        self.external_auth.is_some()
    }

    /// Whether this account may log in and holds an admin role.
    pub fn is_active_admin(&self) -> bool {
        self.can_login().is_ok() && matches!(self.role, UserRole::Admin | UserRole::SuperAdmin)
    }

    /// Check if IP is allowed
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self.allowed_ips.is_empty() {
            return true;
        }
        self.allowed_ips.iter().any(|allowed| {
            allowed == ip || allowed == "*" || ip.starts_with(allowed.trim_end_matches('*'))
        })
    }
}

/// Hash a password using Argon2
fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("Failed to hash password: {}", e))
}

/// Process-wide limit on concurrent Argon2 computations (password hashing,
/// verification and key derivation), so a flood of logins cannot exhaust
/// memory or the blocking pool.
static ARGON2_LIMIT: LazyLock<Semaphore> = LazyLock::new(|| {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    Semaphore::new((cpus * 2).max(2))
});

/// Acquire a slot for one Argon2 computation. Hold the returned permit until
/// the computation has finished.
pub(crate) async fn argon2_permit() -> SemaphorePermit<'static> {
    ARGON2_LIMIT
        .acquire()
        .await
        .expect("Argon2 semaphore is never closed")
}

/// Hash verified against when the username does not exist, so the response
/// time does not reveal which accounts exist. Computed once, on first use
/// (inside the blocking pool).
static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| hash_password("kiss-mail-dummy-password").unwrap_or_default());

fn join_error(what: &str, e: tokio::task::JoinError) -> UserError {
    tracing::error!("Password {} task failed: {}", what, e);
    UserError::StorageError(format!("password {} failed", what))
}

/// Hash a password on the blocking thread pool.
async fn hash_password_blocking(password: &str) -> Result<String, UserError> {
    let password = password.to_string();
    let _permit = argon2_permit().await;
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| join_error("hashing", e))?
        .map_err(UserError::StorageError)
}

/// Verify a password on the blocking thread pool. `None` verifies against
/// the dummy hash (and therefore always fails). A failed task is an error,
/// never a wrong password.
async fn verify_password_blocking(password: &str, hash: Option<String>) -> Result<bool, UserError> {
    let password = password.to_string();
    let _permit = argon2_permit().await;
    tokio::task::spawn_blocking(move || match hash {
        Some(hash) => verify_password(&password, &hash),
        None => {
            verify_password(&password, &DUMMY_HASH);
            false
        }
    })
    .await
    .map_err(|e| join_error("verification", e))
}

/// Failed attempts per (username, ip) before a temporary lockout.
const LOCKOUT_THRESHOLD: u32 = 5;
/// First lockout duration; doubles with each consecutive lockout.
const LOCKOUT_BASE: Duration = Duration::from_secs(60);
/// Upper bound for a single lockout; also the quiet period after which the
/// backoff level resets.
const LOCKOUT_MAX: Duration = Duration::from_secs(60 * 60);
/// Hard cap on the number of entries in each throttle bucket.
const THROTTLE_CAP: usize = 50_000;
/// Minimum number of inserts between two sweeps of expired entries.
const PRUNE_MIN_INTERVAL: usize = 1024;
/// Per-username delay step once the username bucket is over its threshold.
const USER_DELAY_STEP: Duration = Duration::from_millis(250);
/// Upper bound for the per-username delay.
const USER_DELAY_MAX: Duration = Duration::from_secs(2);
/// Pair key used for every username that has no local account.
const UNKNOWN_USER_KEY: &str = "<unknown>";
/// Longest IP string kept in a throttle key.
const MAX_IP_KEY_LEN: usize = 64;

/// How one throttle bucket counts failures.
#[derive(Debug, Clone, Copy)]
struct Policy {
    /// Failures within `window` that trigger the policy.
    threshold: u32,
    /// Fixed counting window.
    window: Duration,
    /// Lock out (with exponential backoff) when reached; otherwise the
    /// bucket only drives a delay.
    lockout: bool,
}

/// Per (username, ip): lockout after 5 failures in 15 minutes.
const PAIR_POLICY: Policy = Policy {
    threshold: LOCKOUT_THRESHOLD,
    window: Duration::from_secs(15 * 60),
    lockout: true,
};
/// Per source (IPv4 /32, IPv6 /64) across usernames: lockout after 20
/// failures in 10 minutes.
const SOURCE_POLICY: Policy = Policy {
    threshold: 20,
    window: Duration::from_secs(10 * 60),
    lockout: true,
};
/// Per username across sources: progressive delay (never a lockout) after
/// more than 10 failures in 10 minutes.
const USER_POLICY: Policy = Policy {
    threshold: 10,
    window: Duration::from_secs(10 * 60),
    lockout: false,
};

#[derive(Debug, Default)]
struct ThrottleEntry {
    /// Failed attempts in the current window.
    failures: u32,
    /// Verifications currently in flight.
    pending: u32,
    /// Number of consecutive lockouts (drives the exponential backoff).
    level: u32,
    locked_until: Option<Instant>,
    /// Start of the current counting window.
    window_start: Option<Instant>,
    /// Last failure or end of the last lockout (for the backoff reset).
    last_activity: Option<Instant>,
    /// Insertion sequence number (matches the bucket's eviction queue).
    seq: u64,
}

impl ThrottleEntry {
    /// Expire a finished lockout, an elapsed window and a stale backoff.
    fn refresh(&mut self, now: Instant, policy: Policy) {
        if let Some(until) = self.locked_until {
            if until > now {
                return;
            }
            self.locked_until = None;
            self.failures = 0;
            self.window_start = None;
        }
        if self
            .window_start
            .is_some_and(|t| now.saturating_duration_since(t) >= policy.window)
        {
            self.failures = 0;
            self.window_start = None;
        }
        if self
            .last_activity
            .is_some_and(|t| now.saturating_duration_since(t) >= LOCKOUT_MAX)
        {
            self.level = 0;
        }
    }

    /// `Err(wait)` while this entry blocks new attempts.
    fn check(&self, now: Instant, policy: Policy) -> Result<(), Duration> {
        if !policy.lockout {
            return Ok(());
        }
        if let Some(until) = self.locked_until
            && until > now
        {
            return Err(until - now);
        }
        if self.failures + self.pending >= policy.threshold {
            // Enough attempts are already in flight to reach the threshold.
            return Err(LOCKOUT_BASE);
        }
        Ok(())
    }

    /// Count a failure; returns the lockout duration if it triggered one.
    fn record_failure(&mut self, now: Instant, policy: Policy) -> Option<Duration> {
        self.refresh(now, policy);
        if self.locked_until.is_some() {
            // Already locked out (a slot reserved before the lockout).
            return None;
        }
        self.window_start.get_or_insert(now);
        self.failures = self.failures.saturating_add(1);
        self.last_activity = Some(now);
        if policy.lockout && self.failures >= policy.threshold {
            let factor = 1u32 << self.level.min(16);
            let duration = LOCKOUT_BASE.saturating_mul(factor).min(LOCKOUT_MAX);
            self.locked_until = Some(now + duration);
            self.last_activity = Some(now + duration);
            self.failures = 0;
            self.window_start = None;
            self.level = self.level.saturating_add(1);
            return Some(duration);
        }
        None
    }

    /// Delay for a delay-only bucket: one step per failure over the
    /// threshold, capped.
    fn delay(&self, policy: Policy) -> Duration {
        let excess = self.failures.saturating_sub(policy.threshold);
        USER_DELAY_STEP.saturating_mul(excess).min(USER_DELAY_MAX)
    }

    /// Nothing worth remembering.
    fn is_idle(&self) -> bool {
        self.pending == 0 && self.failures == 0 && self.locked_until.is_none() && self.level == 0
    }

    /// Still affects future attempts (kept by the expiry sweep).
    fn is_live(&self, now: Instant, policy: Policy) -> bool {
        self.pending > 0
            || self.locked_until.is_some_and(|t| t > now)
            || self
                .window_start
                .is_some_and(|t| now.saturating_duration_since(t) < policy.window)
            || (self.level > 0
                && self
                    .last_activity
                    .is_some_and(|t| now.saturating_duration_since(t) < LOCKOUT_MAX))
    }
}

/// One throttle map with a hard size cap.
///
/// New keys are appended to an insertion-order queue; when the map is full
/// the oldest entries are evicted from the front of the queue. Removed keys
/// leave stale queue items behind (recognised by their sequence number) that
/// are skipped on eviction and compacted away once they outnumber the live
/// entries. Expired entries are swept at most once every
/// `max(len, PRUNE_MIN_INTERVAL)` inserts. Every operation is amortised O(1).
#[derive(Debug)]
struct Bucket<K> {
    policy: Policy,
    cap: usize,
    map: HashMap<K, ThrottleEntry>,
    order: VecDeque<(u64, K)>,
    next_seq: u64,
    inserts_since_prune: usize,
}

impl<K: Eq + Hash + Clone> Bucket<K> {
    fn new(policy: Policy, cap: usize) -> Self {
        Self {
            policy,
            cap: cap.max(1),
            map: HashMap::new(),
            order: VecDeque::new(),
            next_seq: 0,
            inserts_since_prune: 0,
        }
    }

    /// `Err(wait)` if an existing entry for `key` blocks new attempts.
    fn check(&mut self, key: &K, now: Instant) -> Result<(), Duration> {
        let policy = self.policy;
        match self.map.get_mut(key) {
            Some(entry) => {
                entry.refresh(now, policy);
                entry.check(now, policy)
            }
            None => Ok(()),
        }
    }

    /// Current delay for `key` (zero if unknown).
    fn delay(&mut self, key: &K, now: Instant) -> Duration {
        let policy = self.policy;
        match self.map.get_mut(key) {
            Some(entry) => {
                entry.refresh(now, policy);
                entry.delay(policy)
            }
            None => Duration::ZERO,
        }
    }

    fn get_or_insert(&mut self, key: K, now: Instant) -> &mut ThrottleEntry {
        let policy = self.policy;
        let fresh_seq = if self.map.contains_key(&key) {
            0
        } else {
            self.make_room(now);
            let seq = self.next_seq;
            self.next_seq += 1;
            self.order.push_back((seq, key.clone()));
            seq
        };
        let entry = self.map.entry(key).or_insert_with(|| ThrottleEntry {
            seq: fresh_seq,
            ..Default::default()
        });
        entry.refresh(now, policy);
        entry
    }

    /// Make space for one new entry.
    fn make_room(&mut self, now: Instant) {
        self.inserts_since_prune += 1;
        if self.inserts_since_prune >= self.map.len().max(PRUNE_MIN_INTERVAL) {
            self.inserts_since_prune = 0;
            let policy = self.policy;
            self.map.retain(|_, e| e.is_live(now, policy));
            self.compact();
        }
        while self.map.len() >= self.cap {
            let Some((seq, key)) = self.order.pop_front() else {
                break;
            };
            if self.map.get(&key).is_some_and(|e| e.seq == seq) {
                self.map.remove(&key);
            }
        }
        if self.order.len() >= 2 * self.map.len() + PRUNE_MIN_INTERVAL {
            self.compact();
        }
    }

    /// Drop queue items whose entry is gone (or was re-inserted later).
    fn compact(&mut self) {
        let map = &self.map;
        self.order
            .retain(|(seq, key)| map.get(key).is_some_and(|e| e.seq == *seq));
    }

    /// Release a slot. Failures are always recorded (re-creating an evicted
    /// entry); successes and cancellations just release it. Returns the
    /// lockout duration if this failure triggered one.
    fn finish(&mut self, key: &K, outcome: Outcome, now: Instant) -> Option<Duration> {
        let policy = self.policy;
        match outcome {
            Outcome::Failure => {
                let entry = self.get_or_insert(key.clone(), now);
                entry.pending = entry.pending.saturating_sub(1);
                entry.record_failure(now, policy)
            }
            Outcome::Success | Outcome::Cancelled => {
                if let Some(entry) = self.map.get_mut(key) {
                    entry.pending = entry.pending.saturating_sub(1);
                    if entry.is_idle() {
                        self.map.remove(key);
                    }
                }
                None
            }
        }
    }
}

/// How a reserved attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The credentials were correct.
    Success,
    /// The credentials were wrong (counted).
    Failure,
    /// Not decided (task error, account state check, dropped slot).
    Cancelled,
}

#[derive(Debug)]
struct ThrottleState {
    /// (username or `<unknown>`, ip) -> lockout.
    pairs: Bucket<(String, String)>,
    /// Source network -> lockout across usernames.
    sources: Bucket<String>,
    /// Known username -> delay across sources.
    users: Bucket<String>,
}

/// In-memory, time-based login throttle with three buckets:
///
/// - per (username, ip): after `LOCKOUT_THRESHOLD` failures the pair is
///   locked out for `LOCKOUT_BASE`, doubling with every further lockout up
///   to `LOCKOUT_MAX`; unknown usernames share one `<unknown>` pair per ip;
/// - per source (IPv4 /32, IPv6 /64) across usernames: the same lockout
///   after `SOURCE_POLICY.threshold` failures (password spraying);
/// - per known username across sources: a progressive delay only, so a
///   distributed attack cannot lock the real user out.
///
/// A slot is reserved before each verification, so parallel attempts cannot
/// exceed the thresholds. Each bucket is hard-capped. Nothing here changes
/// the persisted account status. Time is passed in (`reserve_at` /
/// `finish_at`) so tests can control it.
#[derive(Debug)]
struct LoginThrottle {
    state: std::sync::Mutex<ThrottleState>,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::with_cap(THROTTLE_CAP)
    }
}

/// Keys of one reserved attempt.
#[derive(Debug)]
struct SlotKeys {
    pair: (String, String),
    source: String,
    /// `None` for usernames without a local account.
    user: Option<String>,
}

/// A reserved login attempt. Finish it with [`ThrottleSlot::success`] or
/// [`ThrottleSlot::failure`]; dropping it releases the slot without counting
/// anything (cancelled).
#[derive(Debug)]
pub struct ThrottleSlot<'a> {
    throttle: &'a LoginThrottle,
    keys: SlotKeys,
    delay: Duration,
    done: bool,
}

impl ThrottleSlot<'_> {
    /// Progressive delay the caller should wait before verifying (the
    /// per-username bucket; zero normally).
    pub fn delay(&self) -> Duration {
        self.delay
    }

    /// The credentials were correct.
    pub fn success(self) {
        self.finish_at(Outcome::Success, Instant::now());
    }

    /// The credentials were wrong.
    pub fn failure(self) {
        self.finish_at(Outcome::Failure, Instant::now());
    }

    fn finish_at(mut self, outcome: Outcome, now: Instant) {
        self.done = true;
        self.throttle.finish_at(&self.keys, outcome, now);
    }
}

impl Drop for ThrottleSlot<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.throttle
                .finish_at(&self.keys, Outcome::Cancelled, Instant::now());
        }
    }
}

/// `s` cut to at most `max` bytes (on a char boundary).
fn truncate_key(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn parse_ip(ip: &str) -> Option<IpAddr> {
    let ip: IpAddr = ip.trim().parse().ok()?;
    Some(match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    })
}

/// Normalised client address for the per-(username, ip) bucket.
fn ip_key(ip: &str) -> String {
    match parse_ip(ip) {
        Some(addr) => addr.to_string(),
        None => truncate_key(ip, MAX_IP_KEY_LEN),
    }
}

/// Source network for the per-source bucket: the IPv4 address (/32) or the
/// IPv6 /64 prefix.
fn source_key(ip: &str) -> String {
    match parse_ip(ip) {
        Some(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Some(v4) => v4.to_string(),
        None => truncate_key(ip, MAX_IP_KEY_LEN),
    }
}

impl LoginThrottle {
    fn with_cap(cap: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(ThrottleState {
                pairs: Bucket::new(PAIR_POLICY, cap),
                sources: Bucket::new(SOURCE_POLICY, cap),
                users: Bucket::new(USER_POLICY, cap),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ThrottleState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reserve a verification slot at `now`, or return how long the caller
    /// must wait. `username` must be canonical and at most
    /// `MAX_USERNAME_LEN` bytes; `known` says whether it has a local account
    /// (unknown names share the `<unknown>` pair and get no username entry).
    fn reserve_at(
        &self,
        username: &str,
        ip: &str,
        known: bool,
        now: Instant,
    ) -> Result<ThrottleSlot<'_>, Duration> {
        let pair_user = if known { username } else { UNKNOWN_USER_KEY };
        let keys = SlotKeys {
            pair: (pair_user.to_string(), ip_key(ip)),
            source: source_key(ip),
            user: known.then(|| username.to_string()),
        };

        let mut state = self.lock();
        // Check before inserting anything.
        state.sources.check(&keys.source, now)?;
        state.pairs.check(&keys.pair, now)?;
        let delay = match &keys.user {
            Some(user) => state.users.delay(user, now),
            None => Duration::ZERO,
        };
        state
            .sources
            .get_or_insert(keys.source.clone(), now)
            .pending += 1;
        state.pairs.get_or_insert(keys.pair.clone(), now).pending += 1;
        drop(state);

        Ok(ThrottleSlot {
            throttle: self,
            keys,
            delay,
            done: false,
        })
    }

    /// Release a slot at `now`, recording its outcome.
    fn finish_at(&self, keys: &SlotKeys, outcome: Outcome, now: Instant) {
        let mut state = self.lock();
        if outcome == Outcome::Success {
            // Correct credentials clear the pair (not the source or username
            // buckets, so an attacker cannot reset them with their own
            // account).
            state.pairs.map.remove(&keys.pair);
        } else if let Some(duration) = state.pairs.finish(&keys.pair, outcome, now) {
            tracing::warn!(
                "Too many failed logins for {} from {}; locked out for {}s",
                keys.pair.0,
                keys.pair.1,
                duration.as_secs()
            );
        }
        if let Some(duration) = state.sources.finish(&keys.source, outcome, now) {
            tracing::warn!(
                "Too many failed logins from {} across usernames; source blocked for {}s",
                keys.source,
                duration.as_secs()
            );
        }
        if outcome == Outcome::Failure
            && let Some(user) = &keys.user
        {
            state.users.finish(user, outcome, now);
        }
    }

    /// Forget all throttle state for a user (admin unlock / reset / delete).
    fn clear_user(&self, username: &str) {
        let mut state = self.lock();
        state.pairs.map.retain(|(user, _), e| {
            if user != username {
                return true;
            }
            // Keep in-flight slots so their release still finds the entry.
            e.failures = 0;
            e.level = 0;
            e.locked_until = None;
            e.window_start = None;
            e.pending > 0
        });
        state.users.map.remove(username);
    }

    /// Entry counts of the (pair, source, user) buckets.
    #[cfg(test)]
    fn sizes(&self) -> (usize, usize, usize) {
        let state = self.lock();
        (
            state.pairs.map.len(),
            state.sources.map.len(),
            state.users.map.len(),
        )
    }
}

/// Canonicalise a username given to a login path and check its length
/// before it can reach the throttle.
fn login_username(raw: &str) -> Result<String, UserError> {
    if raw.trim().len() > MAX_USERNAME_LEN {
        return Err(UserError::InvalidUsername);
    }
    let username = canonical_username(raw);
    if username.len() > MAX_USERNAME_LEN {
        return Err(UserError::InvalidUsername);
    }
    Ok(username)
}

fn locked_error(wait: Duration) -> UserError {
    UserError::AccountLocked(format!(
        "Too many failed login attempts; try again in {} seconds",
        wait.as_secs().max(1)
    ))
}

/// The one error every credential failure (unknown user, wrong password,
/// concurrent deletion) is reported as.
fn bad_credentials() -> UserError {
    UserError::InvalidPassword("Invalid username or password".to_string())
}

/// Verify a password against a hash
fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// User management errors
#[derive(Debug, Clone)]
pub enum UserError {
    NotFound(String),
    AlreadyExists(String),
    InvalidPassword(String),
    PermissionDenied(String),
    AccountLocked(String),
    InvalidInput(String),
    StorageError(String),
    /// A new password does not meet the password policy.
    WeakPassword(String),
    /// The local account password verified, but the account is flagged
    /// `password_change_required`; the user must change it (see
    /// [`UserManager::change_password_from`]) before logging in.
    PasswordChangeRequired,
    /// The password is managed by an external directory (LDAP) and cannot be
    /// changed here.
    ExternallyManaged,
    /// The username is longer than [`MAX_USERNAME_LEN`].
    InvalidUsername,
    /// A password change was saved, but re-wrapping the mail keys failed and
    /// the change could not be rolled back.
    KeysOutOfSync,
}

/// User-facing text of [`UserError::KeysOutOfSync`].
pub const KEYS_OUT_OF_SYNC_MESSAGE: &str =
    "new password is active but mail keys still use the old one; contact an admin";

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserError::NotFound(msg) => write!(f, "User not found: {}", msg),
            UserError::AlreadyExists(msg) => write!(f, "User already exists: {}", msg),
            UserError::InvalidPassword(msg) => write!(f, "Invalid password: {}", msg),
            UserError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            UserError::AccountLocked(msg) => write!(f, "Account locked: {}", msg),
            UserError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            UserError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            UserError::WeakPassword(msg) => write!(f, "Password policy: {}", msg),
            UserError::PasswordChangeRequired => write!(f, "Password change required"),
            UserError::ExternallyManaged => {
                write!(f, "Password is managed by an external directory")
            }
            UserError::InvalidUsername => write!(f, "Invalid username"),
            UserError::KeysOutOfSync => write!(f, "{}", KEYS_OUT_OF_SYNC_MESSAGE),
        }
    }
}

/// Why a self-service password change failed, as shown to the user. Web,
/// API and CLI map their status codes from this (`Locked` is HTTP 429
/// everywhere). Every credential or account-state failure is
/// `BadCredentials`, so the result does not reveal whether an account
/// exists or what state it is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordChangeFailure {
    /// The new password violates the policy (message is user-facing).
    Weak(String),
    /// Throttled: too many failed attempts.
    Locked,
    /// Internal failure (message is user-facing; details are logged).
    Storage(String),
    /// Wrong username/password, or the account may not log in.
    BadCredentials,
    /// The password is managed by an external directory.
    ExternallyManaged,
}

impl From<UserError> for PasswordChangeFailure {
    fn from(e: UserError) -> Self {
        match e {
            UserError::WeakPassword(msg) => PasswordChangeFailure::Weak(msg),
            UserError::AccountLocked(_) => PasswordChangeFailure::Locked,
            UserError::ExternallyManaged => PasswordChangeFailure::ExternallyManaged,
            UserError::KeysOutOfSync => {
                PasswordChangeFailure::Storage(KEYS_OUT_OF_SYNC_MESSAGE.to_string())
            }
            UserError::StorageError(msg) => {
                tracing::error!("Password change failed: {}", msg);
                PasswordChangeFailure::Storage(
                    "Could not change the password (see server log)".to_string(),
                )
            }
            UserError::NotFound(_)
            | UserError::AlreadyExists(_)
            | UserError::InvalidPassword(_)
            | UserError::PermissionDenied(_)
            | UserError::InvalidInput(_)
            | UserError::InvalidUsername
            | UserError::PasswordChangeRequired => PasswordChangeFailure::BadCredentials,
        }
    }
}

impl PasswordChangeFailure {
    /// Text to show the user.
    pub fn user_message(&self) -> String {
        match self {
            PasswordChangeFailure::Weak(msg) | PasswordChangeFailure::Storage(msg) => msg.clone(),
            PasswordChangeFailure::Locked => {
                "Too many failed attempts; try again later".to_string()
            }
            PasswordChangeFailure::BadCredentials => "Invalid username or password".to_string(),
            PasswordChangeFailure::ExternallyManaged => {
                "This account's password is managed by an external directory; change it there"
                    .to_string()
            }
        }
    }
}

/// Minimum length of an account password.
pub const MIN_PASSWORD_LEN: usize = 8;

/// The password policy for new account passwords.
pub fn check_password_policy(password: &str) -> Result<(), UserError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(UserError::WeakPassword(format!(
            "Password must be at least {} characters",
            MIN_PASSWORD_LEN
        )));
    }
    Ok(())
}

fn io_to_user_error(e: std::io::Error) -> UserError {
    UserError::StorageError(format!("failed to save users: {}", e))
}

/// User manager for CRUD operations
pub struct UserManager {
    users: Arc<RwLock<HashMap<String, UserAccount>>>,
    default_domain: String,
    data_dir: PathBuf,
    /// Optional encryption key manager (see `attach_crypto`).
    crypto: RwLock<Option<Arc<CryptoManager>>>,
    /// Serialises writes of `users.json`.
    save_lock: tokio::sync::Mutex<()>,
    /// Login throttle (see `LoginThrottle`).
    throttle: LoginThrottle,
    /// Test-only count of password verifications (Argon2 runs).
    #[cfg(test)]
    verifications: std::sync::atomic::AtomicUsize,
    /// Test-only count of `users.json` writes.
    #[cfg(test)]
    saves: std::sync::atomic::AtomicUsize,
}

/// Failed attempts at or above which the pre-throttle code locked accounts
/// (`status = Locked`) automatically; see `migrate_legacy_lockouts`.
const LEGACY_AUTO_LOCK_THRESHOLD: u32 = 5;

/// One-time migration: earlier versions set `status = Locked` after
/// repeated failed logins. Failed logins now only throttle, so accounts that
/// look auto-locked (Locked, at least 5 failed attempts and a recorded last
/// failure) are re-activated. Returns how many accounts changed.
fn migrate_legacy_lockouts(users: &mut HashMap<String, UserAccount>) -> usize {
    let mut migrated = 0;
    for user in users.values_mut() {
        if user.status == AccountStatus::Locked
            && user.failed_login_attempts >= LEGACY_AUTO_LOCK_THRESHOLD
            && user.last_failed_login.is_some()
        {
            tracing::warn!(
                "Re-activating {}: it was locked automatically after {} failed logins by an \
                 earlier version (failed logins now only throttle); lock it again with \
                 set-status if that was intended",
                user.username,
                user.failed_login_attempts
            );
            user.status = AccountStatus::Active;
            user.failed_login_attempts = 0;
            migrated += 1;
        }
    }
    migrated
}

/// The password-related fields of an account (what a rollback restores).
#[derive(Debug, Clone)]
struct PasswordFields {
    hash: String,
    changed_at: DateTime<Utc>,
    change_required: bool,
}

impl PasswordFields {
    fn of(user: &UserAccount) -> Self {
        Self {
            hash: user.password_hash.clone(),
            changed_at: user.password_changed_at,
            change_required: user.password_change_required,
        }
    }

    fn apply(&self, user: &mut UserAccount) {
        user.password_hash = self.hash.clone();
        user.password_changed_at = self.changed_at;
        user.password_change_required = self.change_required;
    }
}

impl std::fmt::Debug for UserManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserManager")
            .field("default_domain", &self.default_domain)
            .field("data_dir", &self.data_dir)
            .finish_non_exhaustive()
    }
}

impl UserManager {
    pub fn new(default_domain: String, data_dir: PathBuf) -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            default_domain,
            data_dir,
            crypto: RwLock::new(None),
            save_lock: tokio::sync::Mutex::new(()),
            throttle: LoginThrottle::default(),
            #[cfg(test)]
            verifications: Default::default(),
            #[cfg(test)]
            saves: Default::default(),
        }
    }

    /// Attach the encryption key manager. After this, `create_user` generates a
    /// key pair (when encryption is enabled), `change_password` re-wraps the
    /// private key, and `admin_reset_password` regenerates keys.
    pub async fn attach_crypto(&self, crypto: Arc<CryptoManager>) {
        *self.crypto.write().await = Some(crypto);
    }

    /// The attached crypto manager, whether or not encryption of new mail is
    /// enabled. Used for key maintenance (password changes, resets, deletion)
    /// so existing keys stay in sync with the account password.
    async fn attached_crypto(&self) -> Option<Arc<CryptoManager>> {
        self.crypto.read().await.clone()
    }

    /// The attached crypto manager if encryption of new mail is enabled. Only
    /// used to decide whether to create key pairs for accounts without one.
    async fn active_crypto(&self) -> Option<Arc<CryptoManager>> {
        self.attached_crypto().await.filter(|c| c.is_enabled())
    }

    /// The default mail domain for local accounts.
    pub fn default_domain(&self) -> &str {
        &self.default_domain
    }

    /// Make sure a user has an encryption key pair (migration for accounts
    /// created before encryption was wired up). Must only be called with the
    /// user's real account password. Concurrent calls yield a single key pair
    /// (`generate_keypair` is insert-if-absent).
    pub async fn ensure_keys(&self, username: &str, password: &str) {
        let Some(crypto) = self.active_crypto().await else {
            return;
        };
        let username = canonical_username(username);
        if crypto.has_keys(&username).await {
            return;
        }
        if let Err(e) = crypto.generate_keypair(&username, password).await {
            tracing::error!("Could not generate encryption keys for {}: {}", username, e);
        }
    }

    /// Load users from storage (a missing file means no users). Legacy
    /// automatic lockouts are migrated (see `migrate_legacy_lockouts`) and
    /// saved once if anything changed.
    pub async fn load(&self) -> Result<(), std::io::Error> {
        let path = self.data_dir.join("users.json");
        let Some(mut users) =
            crate::storage::read_json::<HashMap<String, UserAccount>>(&path).await?
        else {
            return Ok(());
        };
        let migrated = migrate_legacy_lockouts(&mut users);
        let count = users.len();
        *self.users.write().await = users;
        tracing::info!("Loaded {} user accounts", count);

        if migrated > 0
            && let Err(e) = self.save().await
        {
            // Memory is migrated; the next successful save persists it.
            tracing::warn!(
                "Could not persist {} migrated account(s) to {}: {}",
                migrated,
                path.display(),
                e
            );
        }
        Ok(())
    }

    /// Save users to storage (atomic write; concurrent saves are serialised and
    /// each snapshot is taken after acquiring the save lock, so a newer snapshot
    /// is never overwritten by an older one).
    pub async fn save(&self) -> Result<(), std::io::Error> {
        let _guard = self.save_lock.lock().await;
        #[cfg(test)]
        self.saves
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tokio::fs::create_dir_all(&self.data_dir).await?;
        let path = self.data_dir.join("users.json");
        let data = {
            let users = self.users.read().await;
            serde_json::to_vec_pretty(&*users)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        };
        crate::storage::write_atomic(&path, data).await
    }

    /// Create a new user
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: Option<UserRole>,
    ) -> Result<UserAccount, UserError> {
        self.create_user_with(username, password, role, |_| {})
            .await
    }

    /// Create a new user, letting `init` adjust the account before it is
    /// stored (e.g. `password_change_required`, `external_auth`). The
    /// account is saved exactly once. `init` cannot change the username or
    /// the password hash.
    pub async fn create_user_with(
        &self,
        username: &str,
        password: &str,
        role: Option<UserRole>,
        init: impl FnOnce(&mut UserAccount),
    ) -> Result<UserAccount, UserError> {
        // Validate username
        let username = canonical_username(username);
        if username.is_empty() {
            return Err(UserError::InvalidInput(
                "Username cannot be empty".to_string(),
            ));
        }
        if username.len() > MAX_USERNAME_LEN {
            return Err(UserError::InvalidInput("Username too long".to_string()));
        }
        if !username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '-')
        {
            return Err(UserError::InvalidInput(
                "Username can only contain letters, numbers, dots, underscores, and hyphens"
                    .to_string(),
            ));
        }
        if RESERVED_USERNAMES.contains(&username.as_str()) {
            return Err(UserError::InvalidInput(format!(
                "Username {} is reserved",
                username
            )));
        }

        check_password_policy(password)?;

        if self.users.read().await.contains_key(&username) {
            return Err(UserError::AlreadyExists(username));
        }

        // Build the account (and run `init`) before the await, so `init` is
        // not held across it.
        let mut account =
            UserAccount::with_hash(username.clone(), String::new(), self.default_domain.clone());
        if let Some(r) = role {
            account.role = r;
        }
        init(&mut account);
        account.username = username.clone();

        // Hash outside the lock (Argon2 is slow).
        account.password_hash = hash_password_blocking(password).await?;

        {
            let mut users = self.users.write().await;
            if users.contains_key(&username) {
                return Err(UserError::AlreadyExists(username));
            }
            users.insert(username.clone(), account.clone());
        }

        if let Err(e) = self.save().await {
            // Keep memory consistent with disk.
            self.users.write().await.remove(&username);
            return Err(io_to_user_error(e));
        }

        if let Some(crypto) = self.active_crypto().await
            && let Err(e) = crypto.generate_keypair(&username, password).await
        {
            // The account is usable; keys will be generated on next login.
            tracing::error!("Could not generate encryption keys for {}: {}", username, e);
        }

        tracing::info!("Created user account: {}", username);
        Ok(account)
    }

    /// Get a user by username
    pub async fn get_user(&self, username: &str) -> Option<UserAccount> {
        let username = canonical_username(username);
        self.users.read().await.get(&username).cloned()
    }

    /// Check if a user exists
    pub async fn user_exists(&self, username: &str) -> bool {
        let username = canonical_username(username);
        self.users.read().await.contains_key(&username)
    }

    /// Update a user
    pub async fn update_user<F>(
        &self,
        username: &str,
        update_fn: F,
    ) -> Result<UserAccount, UserError>
    where
        F: FnOnce(&mut UserAccount),
    {
        let username = canonical_username(username);
        let mut users = self.users.write().await;

        let user = users
            .get_mut(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        update_fn(user);
        user.updated_at = Utc::now();

        let updated = user.clone();
        drop(users);

        self.save().await.map_err(io_to_user_error)?;

        Ok(updated)
    }

    /// Apply the same update to several users and save once.
    /// Unknown usernames are skipped.
    pub async fn update_users<F>(
        &self,
        usernames: &[String],
        mut update_fn: F,
    ) -> Result<(), UserError>
    where
        F: FnMut(&mut UserAccount),
    {
        {
            let mut users = self.users.write().await;
            let now = Utc::now();
            for name in usernames {
                if let Some(user) = users.get_mut(&canonical_username(name)) {
                    update_fn(user);
                    user.updated_at = now;
                }
            }
        }
        self.save().await.map_err(io_to_user_error)
    }

    /// Delete a user, their encryption keys (dropping any unlocked session)
    /// and their login throttle state. The mailbox is removed by the caller
    /// (`Storage::remove_mailbox`).
    pub async fn delete_user(&self, username: &str, actor: &UserAccount) -> Result<(), UserError> {
        let username = canonical_username(username);

        // Check permissions
        if actor.role == UserRole::User {
            return Err(UserError::PermissionDenied(
                "Only administrators can delete users".to_string(),
            ));
        }

        let mut users = self.users.write().await;

        let target = users
            .get(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        // SuperAdmins can only be deleted by other SuperAdmins
        if target.role == UserRole::SuperAdmin && actor.role != UserRole::SuperAdmin {
            return Err(UserError::PermissionDenied(
                "Only super administrators can delete super administrators".to_string(),
            ));
        }

        // Can't delete yourself
        if target.username == actor.username {
            return Err(UserError::PermissionDenied(
                "Cannot delete your own account".to_string(),
            ));
        }

        let removed = users.remove(&username);
        drop(users);

        if let Err(e) = self.save().await {
            // Keep memory consistent with disk.
            if let Some(account) = removed {
                self.users.write().await.insert(username.clone(), account);
            }
            return Err(io_to_user_error(e));
        }

        self.throttle.clear_user(&username);

        if let Some(crypto) = self.attached_crypto().await
            && let Err(e) = crypto.delete_keys(&username).await
        {
            tracing::warn!("Could not delete encryption keys for {}: {}", username, e);
        }

        tracing::info!("Deleted user account: {} (by {})", username, actor.username);
        Ok(())
    }

    /// Reserve a login-throttle slot for an authentication path that does
    /// not go through [`UserManager::authenticate`] (LDAP binds, app
    /// passwords). Finish it with `success()` / `failure()`; dropping it
    /// cancels the attempt. Callers should wait `slot.delay()` before
    /// verifying.
    ///
    /// Errors: [`UserError::InvalidUsername`] for names longer than
    /// [`MAX_USERNAME_LEN`] (checked before anything is stored),
    /// [`UserError::AccountLocked`] while the (username, ip) pair or the
    /// source network is locked out.
    pub(crate) fn throttle_reserve(
        &self,
        username: &str,
        ip: &str,
    ) -> Result<ThrottleSlot<'_>, UserError> {
        let username = login_username(username)?;
        // Sync API: if the user map is being written right now, count the
        // name as known (its entries are still capped).
        let known = self
            .users
            .try_read()
            .map(|users| users.contains_key(&username))
            .unwrap_or(true);
        self.throttle
            .reserve_at(&username, ip, known, Instant::now())
            .map_err(locked_error)
    }

    /// Authenticate a user with the local account password.
    ///
    /// The password hash is verified on the blocking pool (bounded by the
    /// Argon2 semaphore) without holding the user map lock, through the
    /// login throttle (see `LoginThrottle`); failed attempts never change the
    /// persisted account status. Unknown usernames are verified against a
    /// dummy hash and fail exactly like a wrong password. The account status
    /// and IP allow-list are only checked once the password has verified.
    ///
    /// When the password is correct but the account has
    /// `password_change_required` set, this returns
    /// [`UserError::PasswordChangeRequired`]: the attempt is not counted as a
    /// failure (the throttle failures for this user and IP are cleared) and
    /// no login is recorded. The flag only concerns the local account
    /// password: app passwords and LDAP logins (handled by
    /// `Storage::authenticate`) never reach this check.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        ip: &str,
        protocol: &str,
        tls: bool,
    ) -> Result<UserAccount, UserError> {
        let username = login_username(username)?;
        let (_, slot) = self
            .verify_credentials(&username, password, ip, protocol, tls)
            .await?;

        // Success: short write lock for bookkeeping.
        let authenticated = {
            let mut users = self.users.write().await;
            // Deleted concurrently: the slot is cancelled on drop.
            let user = users.get_mut(&username).ok_or_else(bad_credentials)?;
            user.check_login_from(ip)?;
            if user.password_change_required {
                None
            } else {
                user.record_login(ip, protocol, tls, true, None);
                Some(user.clone())
            }
        };
        // The password was correct either way.
        slot.success();

        let Some(authenticated) = authenticated else {
            tracing::info!(
                "User {} must change their password before logging in via {} from {}",
                username,
                protocol,
                ip
            );
            return Err(UserError::PasswordChangeRequired);
        };

        if let Err(e) = self.save().await {
            tracing::warn!("Could not persist login for {}: {}", username, e);
        }

        // Migration: accounts created before encryption was wired up get keys
        // on their first successful password login.
        self.ensure_keys(&username, password).await;

        tracing::info!(
            "User {} authenticated via {} from {}",
            username,
            protocol,
            ip
        );
        Ok(authenticated)
    }

    /// Verify `password` against the local account `username` (canonical,
    /// length-checked) through the login throttle.
    ///
    /// Order matters for enumeration resistance: reserve a throttle slot,
    /// wait the per-username delay, verify the hash (a dummy hash for
    /// unknown users), and only then check the account status and IP
    /// allow-list with [`UserAccount::check_login_from`]. Every credential
    /// failure is the same `bad_credentials()` error. Failures are counted
    /// (and recorded in the login history). On success returns the verified
    /// hash and the still-open slot; the caller decides how to finish it.
    async fn verify_credentials(
        &self,
        username: &str,
        password: &str,
        ip: &str,
        protocol: &str,
        tls: bool,
    ) -> Result<(String, ThrottleSlot<'_>), UserError> {
        let password_hash = self
            .users
            .read()
            .await
            .get(username)
            .map(|user| user.password_hash.clone());

        // Reserve an attempt slot before verifying, so parallel guesses
        // cannot exceed the thresholds.
        let slot = self
            .throttle
            .reserve_at(username, ip, password_hash.is_some(), Instant::now())
            .map_err(locked_error)?;
        if !slot.delay().is_zero() {
            tokio::time::sleep(slot.delay()).await;
        }

        #[cfg(test)]
        self.verifications
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // A task failure is an error, not a wrong password: the slot is
        // released (on drop) without counting a failure.
        let valid = verify_password_blocking(password, password_hash.clone()).await?;

        let Some(password_hash) = password_hash.filter(|_| valid) else {
            slot.failure();
            self.record_failed_login(username, ip, protocol, tls, "Invalid password")
                .await;
            return Err(bad_credentials());
        };

        // The password is correct: now the account state may be revealed.
        let state = self
            .users
            .read()
            .await
            .get(username)
            .map(|user| user.check_login_from(ip));
        match state {
            // Deleted concurrently: the slot is cancelled on drop.
            None => Err(bad_credentials()),
            Some(Err(e)) => {
                self.record_failed_login(username, ip, protocol, tls, &e.to_string())
                    .await;
                Err(e)
            }
            Some(Ok(())) => Ok((password_hash, slot)),
        }
    }

    /// Record a failed login in the account history (in memory only; no-op
    /// for unknown users).
    async fn record_failed_login(
        &self,
        username: &str,
        ip: &str,
        protocol: &str,
        tls: bool,
        reason: &str,
    ) {
        if let Some(user) = self.users.write().await.get_mut(username) {
            user.record_login(ip, protocol, tls, false, Some(reason));
        }
    }

    /// Apply `update` to a user's account and persist it. With
    /// `expected_hash`, the update is only applied if the current hash still
    /// equals it (otherwise the password changed concurrently). On a save
    /// failure the password fields are restored (compare-and-swap, see
    /// [`UserManager::restore_password_fields`]). Returns the previous
    /// password fields for a later rollback.
    async fn install_password_hash(
        &self,
        username: &str,
        expected_hash: Option<&str>,
        update: impl FnOnce(&mut UserAccount),
    ) -> Result<PasswordFields, UserError> {
        let (previous, installed) = {
            let mut users = self.users.write().await;
            let user = users
                .get_mut(username)
                .ok_or_else(|| UserError::NotFound(username.to_string()))?;
            if expected_hash.is_some_and(|h| h != user.password_hash) {
                return Err(UserError::InvalidPassword(
                    "Password was changed concurrently; try again".to_string(),
                ));
            }
            let previous = PasswordFields::of(user);
            update(user);
            (previous, user.password_hash.clone())
        };
        if let Err(e) = self.save().await {
            self.restore_password_fields(username, &installed, &previous)
                .await;
            return Err(io_to_user_error(e));
        }
        Ok(previous)
    }

    /// Compare-and-swap: put back `previous` password fields only if the
    /// account still has the hash `installed` (the one this call installed),
    /// so a concurrent change or reset is never clobbered. Status and
    /// failed-login counters are left alone. Returns the replaced fields if
    /// it restored anything.
    async fn restore_password_fields(
        &self,
        username: &str,
        installed: &str,
        previous: &PasswordFields,
    ) -> Option<PasswordFields> {
        let mut users = self.users.write().await;
        let user = users.get_mut(username)?;
        if user.password_hash != installed {
            return None;
        }
        let replaced = PasswordFields::of(user);
        previous.apply(user);
        Some(replaced)
    }

    /// Roll back a persisted password change after the key update failed:
    /// restore the old password fields (compare-and-swap on `installed`) and
    /// save again, so `users.json` matches the (unchanged) keys. If that save
    /// fails, the new password stays active in memory (matching disk) and
    /// [`UserError::KeysOutOfSync`] is returned.
    async fn rollback_password_change(
        &self,
        username: &str,
        installed: &str,
        previous: &PasswordFields,
    ) -> Result<(), UserError> {
        let Some(replaced) = self
            .restore_password_fields(username, installed, previous)
            .await
        else {
            tracing::warn!(
                "Not rolling back the password change for {}: it was changed again concurrently",
                username
            );
            return Ok(());
        };
        if let Err(e) = self.save().await {
            tracing::error!(
                "Could not roll back password change for {} after key update failure: {}; users.json keeps the new password while the mail keys still use the old one",
                username,
                e
            );
            // Keep memory consistent with what is on disk.
            self.restore_password_fields(username, &previous.hash, &replaced)
                .await;
            return Err(UserError::KeysOutOfSync);
        }
        Ok(())
    }

    /// Change a user's password from the CLI (no client IP; see
    /// [`UserManager::change_password_from`]).
    pub async fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), UserError> {
        self.change_password_from("local", username, old_password, new_password, false)
            .await
    }

    /// Change a user's password, proving knowledge of the current one.
    ///
    /// The current password is verified like a login from `ip` (see
    /// `verify_credentials`): same throttle, Argon2 semaphore and
    /// status/IP checks after verification, so wrong guesses count towards
    /// the lockout. It works while `password_change_required` is set (this is
    /// how users clear it). The new password must satisfy
    /// [`check_password_policy`] and differ from the current one; externally
    /// managed accounts are refused with [`UserError::ExternallyManaged`].
    /// Map errors for users with [`PasswordChangeFailure::from`].
    ///
    /// The new hash is persisted first (clearing `password_change_required`);
    /// then, with encryption attached, the private key is re-wrapped with the
    /// new password. If the re-wrap fails, the old password fields are
    /// restored and saved again, so the password and the keys never diverge
    /// (or [`UserError::KeysOutOfSync`] if that save fails). On success all
    /// throttle failures for the user are cleared.
    pub async fn change_password_from(
        &self,
        ip: &str,
        username: &str,
        old_password: &str,
        new_password: &str,
        tls: bool,
    ) -> Result<(), UserError> {
        let username = login_username(username)?;

        check_password_policy(new_password)?;

        let (current_hash, slot) = self
            .verify_credentials(&username, old_password, ip, "password-change", tls)
            .await?;
        slot.success();

        let externally_managed = self
            .users
            .read()
            .await
            .get(&username)
            .is_some_and(|u| u.is_externally_managed());
        if externally_managed {
            return Err(UserError::ExternallyManaged);
        }
        if new_password == old_password {
            return Err(UserError::WeakPassword(
                "new password must differ from the current one".to_string(),
            ));
        }

        let new_hash = hash_password_blocking(new_password).await?;

        let previous = self
            .install_password_hash(&username, Some(&current_hash), |user| {
                user.set_password_hash(new_hash.clone());
            })
            .await?;

        if let Some(crypto) = self.attached_crypto().await {
            if crypto.has_keys(&username).await {
                if let Err(e) = crypto
                    .change_password(&username, old_password, new_password)
                    .await
                {
                    self.rollback_password_change(&username, &new_hash, &previous)
                        .await?;
                    return Err(UserError::StorageError(format!(
                        "could not re-encrypt mail keys: {}",
                        e
                    )));
                }
            } else if crypto.is_enabled()
                && let Err(e) = crypto.generate_keypair(&username, new_password).await
            {
                tracing::error!("Could not generate encryption keys for {}: {}", username, e);
            }
        }

        self.throttle.clear_user(&username);

        tracing::info!("Password changed for user: {} (from {})", username, ip);
        Ok(())
    }

    /// Admin reset password (no old password needed).
    ///
    /// With encryption attached, the user's private key cannot be recovered
    /// without the old password, so a new key pair is generated (and any
    /// unlocked session dropped); previously stored encrypted mail becomes
    /// unreadable. The new hash is persisted first; if the key regeneration
    /// fails, the old password fields are restored and saved again.
    pub async fn admin_reset_password(
        &self,
        username: &str,
        new_password: &str,
        actor: &UserAccount,
        require_change: bool,
    ) -> Result<(), UserError> {
        // Check permissions
        if actor.role == UserRole::User {
            return Err(UserError::PermissionDenied(
                "Only administrators can reset passwords".to_string(),
            ));
        }

        let username = canonical_username(username);

        check_password_policy(new_password)?;

        {
            let users = self.users.read().await;
            let user = users
                .get(&username)
                .ok_or_else(|| UserError::NotFound(username.clone()))?;

            // SuperAdmins can only have password reset by other SuperAdmins
            if user.role == UserRole::SuperAdmin && actor.role != UserRole::SuperAdmin {
                return Err(UserError::PermissionDenied(
                    "Only super administrators can reset super administrator passwords".to_string(),
                ));
            }
        }

        let new_hash = hash_password_blocking(new_password).await?;

        let previous = self
            .install_password_hash(&username, None, |user| {
                user.set_password_hash(new_hash.clone());
                user.password_change_required = require_change;
                // Unlock if locked
                if user.status == AccountStatus::Locked {
                    user.status = AccountStatus::Active;
                }
                user.failed_login_attempts = 0;
            })
            .await?;

        if let Some(crypto) = self.attached_crypto().await {
            if crypto.has_keys(&username).await {
                tracing::warn!(
                    "Admin password reset for {}: regenerating encryption keys; previously stored encrypted mail for this user becomes unreadable",
                    username
                );
            }
            if let Err(e) = crypto.regenerate_keypair(&username, new_password).await {
                self.rollback_password_change(&username, &new_hash, &previous)
                    .await?;
                return Err(UserError::StorageError(format!(
                    "could not regenerate mail keys: {}",
                    e
                )));
            }
        }

        self.throttle.clear_user(&username);

        tracing::info!(
            "Password reset for user: {} (by {})",
            username,
            actor.username
        );
        Ok(())
    }

    /// Set user status
    pub async fn set_status(
        &self,
        username: &str,
        status: AccountStatus,
        actor: &UserAccount,
    ) -> Result<(), UserError> {
        // Check permissions
        if actor.role == UserRole::User {
            return Err(UserError::PermissionDenied(
                "Only administrators can change user status".to_string(),
            ));
        }

        let username = canonical_username(username);
        let mut users = self.users.write().await;

        let user = users
            .get_mut(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        // SuperAdmins can only be modified by other SuperAdmins
        if user.role == UserRole::SuperAdmin && actor.role != UserRole::SuperAdmin {
            return Err(UserError::PermissionDenied(
                "Only super administrators can modify super administrators".to_string(),
            ));
        }

        let old_status = user.status;
        user.status = status;
        user.updated_at = Utc::now();

        // Reset failed attempts if unlocking
        let unlocking = old_status == AccountStatus::Locked && status == AccountStatus::Active;
        if unlocking {
            user.failed_login_attempts = 0;
        }

        drop(users);
        self.save().await.map_err(io_to_user_error)?;
        if unlocking {
            self.throttle.clear_user(&username);
        }

        tracing::info!(
            "Status changed for user {}: {:?} -> {:?} (by {})",
            username,
            old_status,
            status,
            actor.username
        );
        Ok(())
    }

    /// Set user role
    pub async fn set_role(
        &self,
        username: &str,
        role: UserRole,
        actor: &UserAccount,
    ) -> Result<(), UserError> {
        // Only SuperAdmins can change roles
        if actor.role != UserRole::SuperAdmin {
            return Err(UserError::PermissionDenied(
                "Only super administrators can change user roles".to_string(),
            ));
        }

        let username = canonical_username(username);
        let mut users = self.users.write().await;

        let user = users
            .get_mut(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        // Can't change your own role
        if user.username == actor.username {
            return Err(UserError::PermissionDenied(
                "Cannot change your own role".to_string(),
            ));
        }

        let old_role = user.role;
        user.role = role;
        user.updated_at = Utc::now();

        drop(users);
        self.save().await.map_err(io_to_user_error)?;

        tracing::info!(
            "Role changed for user {}: {:?} -> {:?} (by {})",
            username,
            old_role,
            role,
            actor.username
        );
        Ok(())
    }

    /// Set user quota
    pub async fn set_quota(
        &self,
        username: &str,
        quota: UserQuota,
        actor: &UserAccount,
    ) -> Result<(), UserError> {
        // Check permissions
        if actor.role == UserRole::User {
            return Err(UserError::PermissionDenied(
                "Only administrators can change user quotas".to_string(),
            ));
        }

        let username = canonical_username(username);
        let mut users = self.users.write().await;

        let user = users
            .get_mut(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        // Preserve current usage stats
        let current_usage = user.quota.current_usage;
        let current_messages = user.quota.current_messages;
        let outgoing_today = user.quota.outgoing_today;
        let outgoing_reset_date = user.quota.outgoing_reset_date;

        user.quota = quota;
        user.quota.current_usage = current_usage;
        user.quota.current_messages = current_messages;
        user.quota.outgoing_today = outgoing_today;
        user.quota.outgoing_reset_date = outgoing_reset_date;
        user.updated_at = Utc::now();

        drop(users);
        self.save().await.map_err(io_to_user_error)?;

        tracing::info!(
            "Quota updated for user {} (by {})",
            username,
            actor.username
        );
        Ok(())
    }

    /// List all users
    pub async fn list_users(&self) -> Vec<UserAccount> {
        self.users.read().await.values().cloned().collect()
    }

    /// List users with filtering
    pub async fn list_users_filtered(
        &self,
        role: Option<UserRole>,
        status: Option<AccountStatus>,
        search: Option<&str>,
    ) -> Vec<UserAccount> {
        self.users
            .read()
            .await
            .values()
            .filter(|u| {
                if let Some(r) = role
                    && u.role != r
                {
                    return false;
                }
                if let Some(s) = status
                    && u.status != s
                {
                    return false;
                }
                if let Some(q) = search {
                    let q = q.to_lowercase();
                    if !u.username.contains(&q)
                        && !u.email().contains(&q)
                        && !u
                            .settings
                            .display_name
                            .as_ref()
                            .is_some_and(|n| n.to_lowercase().contains(&q))
                    {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    /// Get user statistics
    #[allow(clippy::field_reassign_with_default)]
    pub async fn get_stats(&self) -> UserStats {
        let users = self.users.read().await;

        let mut stats = UserStats::default();
        stats.total_users = users.len() as u32;

        for user in users.values() {
            match user.status {
                AccountStatus::Active => stats.active_users += 1,
                AccountStatus::Suspended => stats.suspended_users += 1,
                AccountStatus::Locked => stats.locked_users += 1,
                AccountStatus::PendingVerification => stats.pending_users += 1,
                AccountStatus::Disabled => stats.disabled_users += 1,
            }

            match user.role {
                UserRole::User => stats.regular_users += 1,
                UserRole::Admin => stats.admin_users += 1,
                UserRole::SuperAdmin => stats.superadmin_users += 1,
            }

            stats.total_storage_used += user.quota.current_usage;
            stats.total_messages += user.quota.current_messages as u64;
        }

        stats
    }
}

/// User statistics
#[derive(Debug, Default, Clone)]
pub struct UserStats {
    pub total_users: u32,
    pub active_users: u32,
    pub suspended_users: u32,
    pub locked_users: u32,
    pub pending_users: u32,
    pub disabled_users: u32,
    pub regular_users: u32,
    pub admin_users: u32,
    pub superadmin_users: u32,
    pub total_storage_used: u64,
    pub total_messages: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash));
        assert!(!verify_password("wrong_password", &hash));
    }

    #[test]
    fn test_user_account_creation() {
        let account = UserAccount::new(
            "testuser".to_string(),
            "password123",
            "example.com".to_string(),
        )
        .unwrap();

        assert_eq!(account.username, "testuser");
        assert_eq!(account.domain, "example.com");
        assert_eq!(account.email(), "testuser@example.com");
        assert!(account.verify_password("password123"));
        assert!(!account.verify_password("wrongpassword"));
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_quota_checks() {
        let mut quota = UserQuota::default();
        quota.max_mailbox_size = 1000;
        quota.max_message_size = 500;
        quota.max_messages = 10;

        assert!(quota.can_receive(100).is_ok());
        assert!(quota.can_receive(600).is_err()); // Too large

        quota.current_usage = 900;
        assert!(quota.can_receive(200).is_err()); // Would exceed mailbox

        quota.current_messages = 10;
        assert!(quota.can_receive(50).is_err()); // Too many messages
    }

    #[test]
    fn test_account_locking() {
        let mut account = UserAccount::new(
            "testuser".to_string(),
            "password123",
            "example.com".to_string(),
        )
        .unwrap();

        // Failed logins are counted but never lock the persisted account.
        for _ in 0..10 {
            account.record_login("127.0.0.1", "IMAP", false, false, Some("bad password"));
        }

        assert_eq!(account.failed_login_attempts, 10);
        assert_eq!(account.status, AccountStatus::Active);
        assert!(account.can_login().is_ok());

        account.status = AccountStatus::Locked;
        assert!(account.can_login().is_err());
    }

    #[tokio::test]
    async fn test_user_manager() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());

        // Create user
        let user = manager
            .create_user("john", "password123", None)
            .await
            .unwrap();
        assert_eq!(user.username, "john");
        assert_eq!(user.role, UserRole::User);

        // Check exists
        assert!(manager.user_exists("john").await);
        assert!(!manager.user_exists("jane").await);

        // Get user
        let retrieved = manager.get_user("john").await.unwrap();
        assert_eq!(retrieved.username, "john");

        // Duplicate should fail
        assert!(
            manager
                .create_user("john", "password456", None)
                .await
                .is_err()
        );
    }

    async fn manager_with_crypto(dir: &std::path::Path) -> (UserManager, Arc<CryptoManager>) {
        let manager = UserManager::new("test.com".to_string(), dir.to_path_buf());
        let crypto = Arc::new(CryptoManager::with_enabled(dir.to_path_buf(), true));
        manager.attach_crypto(Arc::clone(&crypto)).await;
        (manager, crypto)
    }

    #[tokio::test]
    async fn test_create_user_generates_keys_and_change_password_rewraps() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, crypto) = manager_with_crypto(dir.path()).await;

        manager
            .create_user("alice", "password123", None)
            .await
            .unwrap();
        assert!(crypto.has_keys("alice").await);
        let generation = crypto.unlock_keys("alice", "password123").await.unwrap();
        crypto.lock_keys("alice", generation).await;
        let pk_before = crypto.get_public_key("alice").await.unwrap();
        let ciphertext = crypto
            .encrypt_email("alice", b"before the change", None)
            .await
            .unwrap();

        // Wrong old password: neither the hash nor the keys change.
        assert!(
            manager
                .change_password("alice", "wrongpass", "newpassword1")
                .await
                .is_err()
        );

        manager
            .change_password("alice", "password123", "newpassword1")
            .await
            .unwrap();
        assert!(crypto.unlock_keys("alice", "password123").await.is_err());
        assert!(crypto.unlock_keys("alice", "newpassword1").await.is_ok());
        assert!(
            manager
                .get_user("alice")
                .await
                .unwrap()
                .verify_password("newpassword1")
        );
        // Same key pair, so mail encrypted before the change still decrypts.
        assert_eq!(crypto.get_public_key("alice").await.unwrap(), pk_before);
        assert_eq!(
            crypto.decrypt_email("alice", &ciphertext).await.unwrap(),
            b"before the change"
        );
    }

    #[tokio::test]
    async fn change_password_wrong_old_password_keeps_old_keys_working() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, crypto) = manager_with_crypto(dir.path()).await;
        manager
            .create_user("alice", "password123", None)
            .await
            .unwrap();
        let pk = crypto.get_public_key("alice").await.unwrap();

        let result = manager
            .change_password("alice", "wrongpass1", "newpassword1")
            .await;
        assert!(matches!(result, Err(UserError::InvalidPassword(_))));

        assert_eq!(crypto.get_public_key("alice").await.unwrap(), pk);
        assert!(crypto.unlock_keys("alice", "password123").await.is_ok());
        assert!(crypto.unlock_keys("alice", "newpassword1").await.is_err());
        let user = manager.get_user("alice").await.unwrap();
        assert!(user.verify_password("password123"));
        assert!(!user.verify_password("newpassword1"));
    }

    #[tokio::test]
    async fn change_password_rewrap_failure_restores_old_hash() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, crypto) = manager_with_crypto(dir.path()).await;
        manager
            .create_user("alice", "password123", None)
            .await
            .unwrap();
        // Make keys.json unwritable: replace the data dir's keys file with a
        // directory so the atomic rename fails.
        let keys_path = dir.path().join("keys.json");
        std::fs::remove_file(&keys_path).unwrap();
        std::fs::create_dir(&keys_path).unwrap();

        let result = manager
            .change_password("alice", "password123", "newpassword1")
            .await;
        assert!(matches!(result, Err(UserError::StorageError(_))));

        // Memory and disk both keep the old password; keys still unlock with it.
        assert!(
            manager
                .get_user("alice")
                .await
                .unwrap()
                .verify_password("password123")
        );
        let reloaded = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        assert!(
            reloaded
                .get_user("alice")
                .await
                .unwrap()
                .verify_password("password123")
        );
        assert!(crypto.unlock_keys("alice", "password123").await.is_ok());
    }

    #[tokio::test]
    async fn concurrent_ensure_keys_yields_single_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Arc::new(UserManager::new(
            "test.com".to_string(),
            dir.path().to_path_buf(),
        ));
        manager
            .create_user("carol", "password123", None)
            .await
            .unwrap();
        let crypto = Arc::new(CryptoManager::with_enabled(dir.path().to_path_buf(), true));
        manager.attach_crypto(Arc::clone(&crypto)).await;

        let mut tasks = Vec::new();
        for _ in 0..5 {
            let manager = Arc::clone(&manager);
            let crypto = Arc::clone(&crypto);
            tasks.push(tokio::spawn(async move {
                manager.ensure_keys("carol", "password123").await;
                crypto.get_public_key("carol").await.unwrap()
            }));
        }
        let mut keys = Vec::new();
        for t in tasks {
            keys.push(t.await.unwrap());
        }
        assert!(keys.windows(2).all(|w| w[0] == w[1]));
        assert!(crypto.unlock_keys("carol", "password123").await.is_ok());

        let reloaded = CryptoManager::with_enabled(dir.path().to_path_buf(), true);
        assert_eq!(reloaded.get_public_key("carol").await.unwrap(), keys[0]);
    }

    #[tokio::test]
    async fn lockout_is_per_ip_and_does_not_lock_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        manager
            .create_user("dave", "password123", None)
            .await
            .unwrap();

        for _ in 0..LOCKOUT_THRESHOLD {
            let r = manager
                .authenticate("dave", "wrongpass", "10.0.0.1", "IMAP", false)
                .await;
            assert!(matches!(r, Err(UserError::InvalidPassword(_))));
        }
        // Locked out from this IP, even with the right password...
        let r = manager
            .authenticate("dave", "password123", "10.0.0.1", "IMAP", false)
            .await;
        assert!(matches!(r, Err(UserError::AccountLocked(_))));
        // ...but not from another IP, and the account itself is not locked.
        assert!(
            manager
                .authenticate("dave", "password123", "10.0.0.2", "IMAP", false)
                .await
                .is_ok()
        );
        assert_eq!(
            manager.get_user("dave").await.unwrap().status,
            AccountStatus::Active
        );
    }

    /// Fail `n` attempts for (user, ip) at `now`.
    fn fail_n(t: &LoginThrottle, user: &str, ip: &str, n: u32, now: Instant) {
        for _ in 0..n {
            t.reserve_at(user, ip, true, now)
                .unwrap()
                .finish_at(Outcome::Failure, now);
        }
    }

    #[test]
    fn pair_lockout_is_time_based_with_backoff() {
        let t = LoginThrottle::default();
        let t0 = Instant::now();
        fail_n(&t, "dave", "10.0.0.1", LOCKOUT_THRESHOLD, t0);
        assert!(t.reserve_at("dave", "10.0.0.1", true, t0).is_err());
        assert!(t.reserve_at("dave", "10.0.0.2", true, t0).is_ok());

        // The lockout expires...
        let t1 = t0 + LOCKOUT_BASE + Duration::from_secs(1);
        assert!(t.reserve_at("dave", "10.0.0.1", true, t1).is_ok());
        // ...and the next one lasts twice as long.
        fail_n(&t, "dave", "10.0.0.1", LOCKOUT_THRESHOLD, t1);
        let t2 = t1 + LOCKOUT_BASE + Duration::from_secs(1);
        assert!(t.reserve_at("dave", "10.0.0.1", true, t2).is_err());
        let t3 = t1 + 2 * LOCKOUT_BASE + Duration::from_secs(1);
        // A success clears the pair entirely.
        t.reserve_at("dave", "10.0.0.1", true, t3)
            .unwrap()
            .finish_at(Outcome::Success, t3);
        fail_n(&t, "dave", "10.0.0.1", LOCKOUT_THRESHOLD - 1, t3);
        assert!(t.reserve_at("dave", "10.0.0.1", true, t3).is_ok());
    }

    #[test]
    fn record_login_stores_tls_and_old_records_default_false() {
        let mut account = UserAccount::new(
            "tlsuser".to_string(),
            "password123",
            "example.com".to_string(),
        )
        .unwrap();
        account.record_login("1.2.3.4", "IMAP", true, true, None);
        assert!(account.login_history.last().unwrap().tls);

        let old = r#"{"timestamp":"2024-01-01T00:00:00Z","ip_address":"1.2.3.4","protocol":"IMAP","success":true,"failure_reason":null}"#;
        let rec: LoginRecord = serde_json::from_str(old).unwrap();
        assert!(!rec.tls);
    }

    #[test]
    fn throttle_rejects_long_usernames() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        let long = "a".repeat(MAX_USERNAME_LEN + 1);
        assert!(matches!(
            manager.throttle_reserve(&long, "10.0.0.1"),
            Err(UserError::InvalidUsername)
        ));
        assert_eq!(manager.throttle.sizes(), (0, 0, 0));
        let ok = "a".repeat(MAX_USERNAME_LEN);
        assert!(manager.throttle_reserve(&ok, "10.0.0.1").is_ok());
    }

    #[tokio::test]
    async fn authenticate_rejects_long_usernames_before_throttle() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        let long = "b".repeat(10_000);
        assert!(matches!(
            manager
                .authenticate(&long, "x", "10.0.0.1", "IMAP", false)
                .await,
            Err(UserError::InvalidUsername)
        ));
        assert_eq!(manager.throttle.sizes(), (0, 0, 0));
    }

    #[test]
    fn throttle_map_is_capped() {
        let cap = 100;
        let t = LoginThrottle::with_cap(cap);
        let now = Instant::now();
        for i in 0..5_000u32 {
            let ip = format!("10.{}.{}.{}", i >> 16, (i >> 8) & 0xff, i & 0xff);
            let user = format!("user{i}");
            t.reserve_at(&user, &ip, true, now)
                .unwrap()
                .finish_at(Outcome::Failure, now);
            let (pairs, sources, users) = t.sizes();
            assert!(pairs <= cap && sources <= cap && users <= cap);
        }
        // The newest entries survive eviction.
        let state = t.lock();
        assert!(state.users.map.contains_key("user4999"));
        assert!(!state.users.map.contains_key("user0"));
        // The eviction queue does not grow without bound either.
        assert!(state.users.order.len() <= 2 * cap + PRUNE_MIN_INTERVAL);
    }

    #[test]
    fn per_source_bucket_blocks_spraying() {
        let t = LoginThrottle::default();
        let now = Instant::now();
        // One failure each for many usernames from one IPv6 /64 (different
        // addresses inside it).
        for i in 0..SOURCE_POLICY.threshold {
            let ip = format!("2001:db8:1:2::{:x}", i + 1);
            fail_n(&t, &format!("victim{i}"), &ip, 1, now);
        }
        assert!(
            t.reserve_at("another", "2001:db8:1:2::ffff", true, now)
                .is_err()
        );
        // Unknown usernames are blocked too.
        assert!(
            t.reserve_at("nobody", "2001:db8:1:2::1", false, now)
                .is_err()
        );
        // A different /64 is unaffected.
        assert!(
            t.reserve_at("another", "2001:db8:1:3::1", true, now)
                .is_ok()
        );
        // The block expires (with backoff on the next one).
        let later = now + LOCKOUT_BASE + Duration::from_secs(1);
        assert!(
            t.reserve_at("another", "2001:db8:1:2::1", true, later)
                .is_ok()
        );
    }

    #[test]
    fn unknown_usernames_count_toward_source_without_user_entries() {
        let t = LoginThrottle::default();
        let now = Instant::now();
        for i in 0..SOURCE_POLICY.threshold {
            // The shared `<unknown>` pair locks first; then everything stops.
            let slot = t.reserve_at(&format!("ghost{i}"), "192.0.2.7", false, now);
            match slot {
                Ok(slot) => slot.finish_at(Outcome::Failure, now),
                Err(_) => break,
            }
        }
        let (pairs, sources, users) = t.sizes();
        assert_eq!(users, 0);
        assert_eq!(pairs, 1, "unknown names share one pair entry");
        assert_eq!(sources, 1);
        assert!(t.reserve_at("ghost-x", "192.0.2.7", false, now).is_err());
    }

    #[test]
    fn per_username_bucket_delays_but_never_locks() {
        let t = LoginThrottle::default();
        let now = Instant::now();
        // Failures for one username from many different sources.
        for i in 0..(USER_POLICY.threshold + 20) {
            let ip = format!("198.51.100.{}", i % 250);
            let slot = t.reserve_at("target", &ip, true, now).unwrap();
            let expected = USER_DELAY_STEP
                .saturating_mul(i.saturating_sub(USER_POLICY.threshold))
                .min(USER_DELAY_MAX);
            assert_eq!(slot.delay(), expected, "after {i} failures");
            slot.finish_at(Outcome::Failure, now);
        }
        // Capped at the maximum, never an error.
        let slot = t.reserve_at("target", "203.0.113.1", true, now).unwrap();
        assert_eq!(slot.delay(), USER_DELAY_MAX);
        drop(slot);
        // A success does not reset the username bucket...
        t.reserve_at("target", "203.0.113.2", true, now)
            .unwrap()
            .finish_at(Outcome::Success, now);
        assert_eq!(
            t.reserve_at("target", "203.0.113.3", true, now)
                .unwrap()
                .delay(),
            USER_DELAY_MAX
        );
        // ...but the window does.
        let later = now + USER_POLICY.window;
        assert_eq!(
            t.reserve_at("target", "203.0.113.4", true, later)
                .unwrap()
                .delay(),
            Duration::ZERO
        );
    }

    #[test]
    fn source_keys_group_ipv6_by_64() {
        assert_eq!(source_key("192.0.2.1"), "192.0.2.1");
        assert_eq!(source_key("::ffff:192.0.2.1"), "192.0.2.1");
        assert_eq!(source_key("2001:db8:a:b:1:2:3:4"), "2001:db8:a:b::/64");
        assert_eq!(source_key("2001:db8:a:b::9"), "2001:db8:a:b::/64");
        assert_eq!(source_key(&"x".repeat(500)).len(), MAX_IP_KEY_LEN);
        assert_eq!(ip_key("local"), "local");
    }

    #[tokio::test]
    async fn parallel_failed_logins_cannot_exceed_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let manager = Arc::new(UserManager::new(
            "test.com".to_string(),
            dir.path().to_path_buf(),
        ));
        manager
            .create_user("erin", "password123", None)
            .await
            .unwrap();

        let mut tasks = Vec::new();
        for _ in 0..20 {
            let manager = Arc::clone(&manager);
            tasks.push(tokio::spawn(async move {
                manager
                    .authenticate("erin", "wrongpass", "10.0.0.9", "IMAP", false)
                    .await
            }));
        }
        let mut verified = 0;
        for t in tasks {
            if let Err(UserError::InvalidPassword(_)) = t.await.unwrap() {
                verified += 1;
            }
        }
        assert!(
            verified <= LOCKOUT_THRESHOLD as usize,
            "{verified} guesses verified"
        );
        assert!(matches!(
            manager
                .authenticate("erin", "password123", "10.0.0.9", "IMAP", false)
                .await,
            Err(UserError::AccountLocked(_))
        ));
    }

    async fn require_change(manager: &UserManager, user: &str) {
        manager
            .update_user(user, |u| u.password_change_required = true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn password_change_required_is_reported_after_verification() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        manager
            .create_user("hank", "password123", None)
            .await
            .unwrap();
        require_change(&manager, "hank").await;

        // Wrong password: still a plain failure (the flag is not revealed).
        for _ in 0..LOCKOUT_THRESHOLD - 1 {
            assert!(matches!(
                manager
                    .authenticate("hank", "wrongpass", "10.0.0.1", "IMAP", false)
                    .await,
                Err(UserError::InvalidPassword(_))
            ));
        }
        // Correct password: change required, and the earlier failures from
        // this IP are cleared rather than counted.
        for _ in 0..LOCKOUT_THRESHOLD + 1 {
            assert!(matches!(
                manager
                    .authenticate("hank", "password123", "10.0.0.1", "IMAP", false)
                    .await,
                Err(UserError::PasswordChangeRequired)
            ));
        }
        for _ in 0..LOCKOUT_THRESHOLD - 1 {
            let r = manager
                .authenticate("hank", "wrongpass", "10.0.0.1", "IMAP", false)
                .await;
            assert!(matches!(r, Err(UserError::InvalidPassword(_))), "{:?}", r);
        }
        let user = manager.get_user("hank").await.unwrap();
        assert!(user.last_login.is_none());
        assert!(user.login_history.iter().all(|r| !r.success));
    }

    #[tokio::test]
    async fn admin_reset_sets_or_clears_change_required() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        let admin = manager
            .create_user("root", "password123", Some(UserRole::SuperAdmin))
            .await
            .unwrap();
        manager
            .create_user("ivy", "password123", None)
            .await
            .unwrap();

        manager
            .admin_reset_password("ivy", "password456", &admin, true)
            .await
            .unwrap();
        assert!(
            manager
                .get_user("ivy")
                .await
                .unwrap()
                .password_change_required
        );
        assert!(matches!(
            manager
                .authenticate("ivy", "password456", "127.0.0.1", "IMAP", false)
                .await,
            Err(UserError::PasswordChangeRequired)
        ));

        // `passwd <user>` without --require-change clears the flag.
        manager
            .admin_reset_password("ivy", "password789", &admin, false)
            .await
            .unwrap();
        assert!(
            !manager
                .get_user("ivy")
                .await
                .unwrap()
                .password_change_required
        );
        assert!(
            manager
                .authenticate("ivy", "password789", "127.0.0.1", "IMAP", false)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn change_password_works_while_flag_set_and_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, crypto) = manager_with_crypto(dir.path()).await;
        manager
            .create_user("jane", "password123", None)
            .await
            .unwrap();
        let ciphertext = crypto
            .encrypt_email("jane", b"old mail", None)
            .await
            .unwrap();
        require_change(&manager, "jane").await;

        // Policy is enforced (before the current password is checked).
        assert!(matches!(
            manager
                .change_password_from("10.0.0.5", "jane", "password123", "short", false)
                .await,
            Err(UserError::WeakPassword(_))
        ));

        manager
            .change_password_from("10.0.0.5", "Jane", "password123", "newpassword1", false)
            .await
            .unwrap();
        let user = manager.get_user("jane").await.unwrap();
        assert!(!user.password_change_required);
        assert!(user.verify_password("newpassword1"));

        // Login works with the new password and old mail still decrypts.
        manager
            .authenticate("jane", "newpassword1", "10.0.0.5", "IMAP", false)
            .await
            .unwrap();
        crypto.unlock_keys("jane", "newpassword1").await.unwrap();
        assert_eq!(
            crypto.decrypt_email("jane", &ciphertext).await.unwrap(),
            b"old mail"
        );

        // Persisted.
        let reloaded = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        assert!(
            !reloaded
                .get_user("jane")
                .await
                .unwrap()
                .password_change_required
        );
    }

    #[tokio::test]
    async fn change_password_wrong_old_password_is_throttled() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        manager
            .create_user("kate", "password123", None)
            .await
            .unwrap();

        for _ in 0..LOCKOUT_THRESHOLD {
            assert!(matches!(
                manager
                    .change_password_from("10.0.0.7", "kate", "wrongpass", "newpassword1", false)
                    .await,
                Err(UserError::InvalidPassword(_))
            ));
        }
        // Locked out for that IP, for both password changes and logins.
        assert!(matches!(
            manager
                .change_password_from("10.0.0.7", "kate", "password123", "newpassword1", false)
                .await,
            Err(UserError::AccountLocked(_))
        ));
        assert!(matches!(
            manager
                .authenticate("kate", "password123", "10.0.0.7", "IMAP", false)
                .await,
            Err(UserError::AccountLocked(_))
        ));
        // Unknown users are generic failures, never a different error.
        assert!(matches!(
            manager
                .change_password_from("10.0.0.8", "ghost", "whatever1", "newpassword1", false)
                .await,
            Err(UserError::InvalidPassword(_))
        ));

        // From another IP the change succeeds and clears every lockout.
        manager
            .change_password_from("10.0.0.9", "kate", "password123", "newpassword1", false)
            .await
            .unwrap();
        manager
            .authenticate("kate", "newpassword1", "10.0.0.7", "IMAP", false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn unknown_user_is_bad_credentials_and_throttled() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        for i in 0..LOCKOUT_THRESHOLD {
            // Different unknown names share the `<unknown>` bucket per ip.
            assert!(matches!(
                manager
                    .authenticate(&format!("ghost{i}"), "x", "10.0.0.1", "IMAP", false)
                    .await,
                Err(UserError::InvalidPassword(_))
            ));
        }
        // No per-username entries for unknown names.
        assert_eq!(manager.throttle.sizes().2, 0);
        assert!(matches!(
            manager
                .authenticate("ghost", "x", "10.0.0.1", "IMAP", false)
                .await,
            Err(UserError::AccountLocked(_))
        ));
    }

    #[tokio::test]
    async fn admin_reset_drops_unlocked_session() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, crypto) = manager_with_crypto(dir.path()).await;
        let admin = manager
            .create_user("root", "password123", Some(UserRole::SuperAdmin))
            .await
            .unwrap();
        manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        crypto.unlock_keys("bob", "password123").await.unwrap();
        assert_eq!(crypto.stats().await.active_sessions, 1);

        manager
            .admin_reset_password("bob", "resetpass1", &admin, false)
            .await
            .unwrap();
        assert_eq!(crypto.stats().await.active_sessions, 0);
    }

    #[tokio::test]
    async fn key_maintenance_works_when_encryption_disabled() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (manager, _) = manager_with_crypto(dir.path()).await;
            manager
                .create_user("alice", "password123", None)
                .await
                .unwrap();
        }
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        manager.load().await.unwrap();
        let crypto = Arc::new(CryptoManager::with_enabled(dir.path().to_path_buf(), false));
        manager.attach_crypto(Arc::clone(&crypto)).await;

        manager
            .change_password("alice", "password123", "newpassword1")
            .await
            .unwrap();
        let generation = crypto.unlock_keys("alice", "newpassword1").await.unwrap();
        crypto.lock_keys("alice", generation).await;

        let admin = manager
            .create_user("root", "password123", Some(UserRole::SuperAdmin))
            .await
            .unwrap();
        manager.delete_user("alice", &admin).await.unwrap();
        assert!(!crypto.has_keys("alice").await);
    }

    #[test]
    fn role_and_status_from_str_round_trip() {
        for role in [UserRole::User, UserRole::Admin, UserRole::SuperAdmin] {
            assert_eq!(role.to_string().parse::<UserRole>().unwrap(), role);
        }
        for s in ["super_admin", "Super-Admin", "SUPERADMIN"] {
            assert_eq!(s.parse::<UserRole>().unwrap(), UserRole::SuperAdmin);
        }
        assert!("root".parse::<UserRole>().is_err());

        for status in [
            AccountStatus::Active,
            AccountStatus::Suspended,
            AccountStatus::Locked,
            AccountStatus::PendingVerification,
            AccountStatus::Disabled,
        ] {
            assert_eq!(status.to_string().parse::<AccountStatus>().unwrap(), status);
        }
        assert_eq!(
            "PendingVerification".parse::<AccountStatus>().unwrap(),
            AccountStatus::PendingVerification
        );
        assert!("gone".parse::<AccountStatus>().is_err());
    }

    #[test]
    fn canonical_username_and_local_part() {
        assert_eq!(canonical_username("  Alice "), "alice");
        assert_eq!(local_part("Alice@Example.com"), "alice");
        assert_eq!(local_part("a@b@example.com"), "a@b");
        assert_eq!(local_part(" Bob "), "bob");
    }

    #[tokio::test]
    async fn manager_methods_canonicalise_usernames() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        manager
            .create_user(" Frank ", "password123", None)
            .await
            .unwrap();
        assert!(manager.user_exists(" FRANK ").await);
        assert!(manager.get_user("frank ").await.is_some());
        assert!(
            manager
                .authenticate(" Frank", "password123", "127.0.0.1", "IMAP", false)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_admin_reset_regenerates_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, crypto) = manager_with_crypto(dir.path()).await;
        let admin = manager
            .create_user("root", "password123", Some(UserRole::SuperAdmin))
            .await
            .unwrap();
        manager
            .create_user("bob", "password123", None)
            .await
            .unwrap();
        let old_pk = crypto.get_public_key("bob").await.unwrap();

        manager
            .admin_reset_password("bob", "resetpass1", &admin, true)
            .await
            .unwrap();
        let new_pk = crypto.get_public_key("bob").await.unwrap();
        assert_ne!(old_pk, new_pk);
        assert!(crypto.unlock_keys("bob", "resetpass1").await.is_ok());
    }

    #[tokio::test]
    async fn test_login_generates_missing_keys() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        manager
            .create_user("carol", "password123", None)
            .await
            .unwrap();

        let crypto = Arc::new(CryptoManager::with_enabled(dir.path().to_path_buf(), true));
        manager.attach_crypto(Arc::clone(&crypto)).await;
        assert!(!crypto.has_keys("carol").await);
        manager
            .authenticate("carol", "password123", "127.0.0.1", "IMAP", false)
            .await
            .unwrap();
        assert!(crypto.has_keys("carol").await);
    }

    #[tokio::test]
    async fn test_save_is_atomic_and_reloadable() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        manager
            .create_user("dave", "password123", None)
            .await
            .unwrap();
        manager
            .create_user("erin", "password123", None)
            .await
            .unwrap();

        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty());

        let reloaded = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        assert!(reloaded.user_exists("dave").await);
        assert!(reloaded.user_exists("erin").await);
    }

    #[tokio::test]
    async fn test_save_failure_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        // data_dir is a regular file, so saving must fail.
        let file_path = dir.path().join("not-a-dir");
        std::fs::write(&file_path, "x").unwrap();
        let manager = UserManager::new("test.com".to_string(), file_path);
        let result = manager.create_user("frank", "password123", None).await;
        assert!(matches!(result, Err(UserError::StorageError(_))));
    }

    #[test]
    fn test_login_history_is_capped() {
        let mut account =
            UserAccount::new("g".to_string(), "password123", "example.com".to_string()).unwrap();
        for _ in 0..150 {
            account.record_login("127.0.0.1", "IMAP", false, true, None);
        }
        assert_eq!(account.login_history.len(), 100);
    }

    #[tokio::test]
    async fn rollback_does_not_clobber_concurrent_reset() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        manager
            .create_user("lena", "password123", None)
            .await
            .unwrap();
        manager
            .update_user("lena", |u| u.failed_login_attempts = 3)
            .await
            .unwrap();

        // This call installs H1...
        let h1 = hash_password("newpassword1").unwrap();
        let previous = manager
            .install_password_hash("lena", None, |u| u.set_password_hash(h1.clone()))
            .await
            .unwrap();
        // ...an admin reset installs H2 and changes the status concurrently...
        let h2 = hash_password("resetpass1").unwrap();
        manager
            .update_user("lena", |u| {
                u.set_password_hash(h2.clone());
                u.status = AccountStatus::Suspended;
            })
            .await
            .unwrap();
        // ...so the rollback of H1 must not touch anything.
        manager
            .rollback_password_change("lena", &h1, &previous)
            .await
            .unwrap();
        let user = manager.get_user("lena").await.unwrap();
        assert_eq!(user.password_hash, h2);
        assert_eq!(user.status, AccountStatus::Suspended);

        // Without the concurrent change, only the password fields come back.
        let h3 = hash_password("another1pw").unwrap();
        let previous = manager
            .install_password_hash("lena", None, |u| {
                u.set_password_hash(h3.clone());
                u.failed_login_attempts = 0;
                u.status = AccountStatus::Active;
            })
            .await
            .unwrap();
        manager
            .rollback_password_change("lena", &h3, &previous)
            .await
            .unwrap();
        let user = manager.get_user("lena").await.unwrap();
        assert_eq!(user.password_hash, h2);
        assert_eq!(user.status, AccountStatus::Active);
        assert_eq!(user.failed_login_attempts, 0);
    }

    #[tokio::test]
    async fn same_password_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        manager
            .create_user("mike", "password123", None)
            .await
            .unwrap();
        let r = manager
            .change_password("mike", "password123", "password123")
            .await;
        match r {
            Err(UserError::WeakPassword(msg)) => {
                assert_eq!(msg, "new password must differ from the current one")
            }
            other => panic!("unexpected: {:?}", other),
        }
        // A wrong current password is reported as such, not as "same".
        assert!(matches!(
            manager
                .change_password("mike", "wrongpass", "wrongpass")
                .await,
            Err(UserError::InvalidPassword(_))
        ));
    }

    #[tokio::test]
    async fn enumeration_suspended_and_unknown_look_the_same() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        let admin = manager
            .create_user("root", "password123", Some(UserRole::SuperAdmin))
            .await
            .unwrap();
        manager
            .create_user("nina", "password123", None)
            .await
            .unwrap();
        manager
            .set_status("nina", AccountStatus::Suspended, &admin)
            .await
            .unwrap();

        let count = || {
            manager
                .verifications
                .load(std::sync::atomic::Ordering::Relaxed)
        };
        let before = count();
        let suspended = manager
            .authenticate("nina", "guess1234", "10.1.0.1", "IMAP", false)
            .await
            .unwrap_err();
        assert_eq!(count(), before + 1, "Argon2 ran for the suspended user");
        let unknown = manager
            .authenticate("nobody", "guess1234", "10.1.0.2", "IMAP", false)
            .await
            .unwrap_err();
        assert_eq!(count(), before + 2, "Argon2 ran for the unknown user");
        assert_eq!(suspended.to_string(), unknown.to_string());
        assert_eq!(
            PasswordChangeFailure::from(suspended),
            PasswordChangeFailure::from(unknown)
        );

        // Password changes too, and with the correct password the status
        // failure still maps to BadCredentials.
        let a = manager
            .change_password_from("10.1.0.3", "nina", "guess1234", "newpassword1", false)
            .await
            .unwrap_err();
        let b = manager
            .change_password_from("10.1.0.4", "nobody", "guess1234", "newpassword1", false)
            .await
            .unwrap_err();
        assert_eq!(a.to_string(), b.to_string());
        let c = manager
            .change_password_from("10.1.0.5", "nina", "password123", "newpassword1", false)
            .await
            .unwrap_err();
        assert_eq!(
            PasswordChangeFailure::from(c),
            PasswordChangeFailure::BadCredentials
        );
        // The status is revealed only after a correct password.
        assert!(matches!(
            manager
                .authenticate("nina", "password123", "10.1.0.6", "IMAP", false)
                .await,
            Err(UserError::PermissionDenied(_))
        ));
    }

    #[tokio::test]
    async fn legacy_locked_account_is_migrated() {
        let dir = tempfile::tempdir().unwrap();
        {
            let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
            manager
                .create_user("auto", "password123", None)
                .await
                .unwrap();
            manager
                .create_user("manual", "password123", None)
                .await
                .unwrap();
            manager
                .update_user("auto", |u| {
                    u.status = AccountStatus::Locked;
                    u.failed_login_attempts = 5;
                    u.last_failed_login = Some(Utc::now());
                })
                .await
                .unwrap();
            manager
                .update_user("manual", |u| u.status = AccountStatus::Locked)
                .await
                .unwrap();
        }
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        manager.load().await.unwrap();
        assert_eq!(
            manager.get_user("auto").await.unwrap().status,
            AccountStatus::Active
        );
        assert_eq!(
            manager.get_user("manual").await.unwrap().status,
            AccountStatus::Locked
        );
        assert_eq!(
            manager.get_user("manual").await.unwrap().can_login(),
            Err("Account is locked".to_string())
        );
        // Persisted by the load.
        let reloaded = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        assert_eq!(reloaded.saves.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(
            reloaded.get_user("auto").await.unwrap().status,
            AccountStatus::Active
        );
    }

    #[tokio::test]
    async fn create_user_with_single_save() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        let saves = || manager.saves.load(std::sync::atomic::Ordering::Relaxed);
        let before = saves();
        let created = manager
            .create_user_with(
                BOOTSTRAP_ADMIN,
                "password123",
                Some(UserRole::SuperAdmin),
                |u| {
                    u.password_change_required = true;
                    u.external_auth = Some("ldap".to_string());
                    // Cannot rename the account.
                    u.username = "someone-else".to_string();
                },
            )
            .await
            .unwrap();
        assert_eq!(saves(), before + 1);
        assert_eq!(created.username, BOOTSTRAP_ADMIN);
        assert!(created.verify_password("password123"));

        let reloaded = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        reloaded.load().await.unwrap();
        let user = reloaded.get_user(BOOTSTRAP_ADMIN).await.unwrap();
        assert!(user.password_change_required);
        assert!(user.is_externally_managed());
        assert_eq!(user.role, UserRole::SuperAdmin);
        assert!(reloaded.get_user("someone-else").await.is_none());
    }

    #[tokio::test]
    async fn reserved_usernames_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        for name in RESERVED_USERNAMES {
            assert!(matches!(
                manager.create_user(name, "password123", None).await,
                Err(UserError::InvalidInput(_))
            ));
            assert!(matches!(
                manager
                    .create_user(&name.to_uppercase(), "password123", None)
                    .await,
                Err(UserError::InvalidInput(_))
            ));
        }
        assert!(manager.list_users().await.is_empty());
    }

    #[tokio::test]
    async fn externally_managed_change_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manager = UserManager::new("test.com".to_string(), dir.path().to_path_buf());
        manager
            .create_user_with("ldapuser", "password123", None, |u| {
                u.external_auth = Some("ldap".to_string())
            })
            .await
            .unwrap();
        let r = manager
            .change_password_from("10.2.0.1", "ldapuser", "password123", "newpassword1", false)
            .await;
        assert!(matches!(r, Err(UserError::ExternallyManaged)));
        assert!(
            manager
                .get_user("ldapuser")
                .await
                .unwrap()
                .verify_password("password123")
        );
        // Accounts saved before the field existed default to local.
        let json = serde_json::to_value(manager.get_user("ldapuser").await.unwrap()).unwrap();
        let mut obj = json.as_object().unwrap().clone();
        obj.remove("external_auth");
        let legacy: UserAccount = serde_json::from_value(obj.into()).unwrap();
        assert!(!legacy.is_externally_managed());
    }

    #[test]
    fn password_change_failure_mapping() {
        use PasswordChangeFailure as F;
        let cases = [
            (
                UserError::WeakPassword("too short".into()),
                F::Weak("too short".into()),
            ),
            (UserError::AccountLocked("x".into()), F::Locked),
            (UserError::ExternallyManaged, F::ExternallyManaged),
            (
                UserError::KeysOutOfSync,
                F::Storage(KEYS_OUT_OF_SYNC_MESSAGE.to_string()),
            ),
            (
                UserError::StorageError("disk on fire".into()),
                F::Storage("Could not change the password (see server log)".into()),
            ),
            (UserError::NotFound("x".into()), F::BadCredentials),
            (UserError::InvalidPassword("x".into()), F::BadCredentials),
            (UserError::PermissionDenied("x".into()), F::BadCredentials),
            (UserError::InvalidUsername, F::BadCredentials),
            (UserError::PasswordChangeRequired, F::BadCredentials),
        ];
        for (e, expected) in cases {
            assert_eq!(F::from(e), expected);
        }
        assert_eq!(F::Weak("too short".into()).user_message(), "too short");
        assert_eq!(
            F::Storage(KEYS_OUT_OF_SYNC_MESSAGE.into()).user_message(),
            KEYS_OUT_OF_SYNC_MESSAGE
        );
        assert!(
            !F::Storage("Could not change the password (see server log)".into())
                .user_message()
                .contains("disk")
        );
        assert_eq!(
            F::BadCredentials.user_message(),
            "Invalid username or password"
        );
        assert!(F::Locked.user_message().contains("try again"));
        assert!(
            F::ExternallyManaged
                .user_message()
                .contains("external directory")
        );
    }

    #[test]
    fn check_login_from_checks_status_and_ip() {
        let mut account =
            UserAccount::new("h".to_string(), "password123", "example.com".to_string()).unwrap();
        assert!(account.check_login_from("10.0.0.1").is_ok());
        account.allowed_ips = vec!["192.168.*".to_string()];
        assert!(matches!(
            account.check_login_from("10.0.0.1"),
            Err(UserError::PermissionDenied(_))
        ));
        assert!(account.check_login_from("192.168.1.5").is_ok());
        account.status = AccountStatus::Disabled;
        assert!(matches!(
            account.check_login_from("192.168.1.5"),
            Err(UserError::PermissionDenied(_))
        ));
    }
}
