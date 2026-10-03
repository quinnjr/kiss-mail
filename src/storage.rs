//! Shared mailbox storage for the KISS mail server.
//!
//! Provides a simple in-memory mail storage with file persistence.
//! Supports encryption of stored messages at rest (see `crate::crypto`).

use crate::crypto::{CryptoError, CryptoManager, EncryptionMetadata};
use crate::ldap::{LdapAuthResult, LdapClient};
use crate::sso::SsoManager;
use crate::users::{QuotaError, UserAccount, UserManager};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// A single email message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Email {
    pub id: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub raw: String,
    pub received_at: DateTime<Utc>,
    pub size: usize,
    pub seen: bool,
    pub deleted: bool,
    /// IMAP UID (unique within the mailbox; assigned by `Mailbox::add_email`).
    #[serde(default)]
    pub uid: u32,
    /// IMAP `\Flagged` flag
    #[serde(default)]
    pub flagged: bool,
    /// IMAP `\Answered` flag
    #[serde(default)]
    pub answered: bool,
    /// IMAP `\Draft` flag
    #[serde(default)]
    pub draft: bool,
    /// Encryption metadata (if encrypted at rest)
    #[serde(default)]
    pub encryption: EncryptionMetadata,
    /// Encrypted body (if encrypted)
    #[serde(default)]
    pub encrypted_body: Option<Vec<u8>>,
}

impl Email {
    pub fn new(from: String, to: Vec<String>, raw: String) -> Self {
        let (subject, headers, body) = Self::parse_raw(&raw);
        let size = raw.len();

        Self {
            id: Uuid::new_v4().to_string(),
            from,
            to,
            subject,
            headers,
            body,
            raw,
            received_at: Utc::now(),
            size,
            seen: false,
            deleted: false,
            uid: 0,
            flagged: false,
            answered: false,
            draft: false,
            encryption: EncryptionMetadata::default(),
            encrypted_body: None,
        }
    }

    /// An encrypted-at-rest copy of this message (new id, same metadata and
    /// flags). Only the parsed headers are copied; the plaintext body and raw
    /// message are not.
    pub fn encrypted_copy(&self, encrypted_body: Vec<u8>, metadata: EncryptionMetadata) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            from: self.from.clone(),
            to: self.to.clone(),
            subject: self.subject.clone(),
            headers: self.headers.clone(),
            body: "[Encrypted]".to_string(), // Placeholder for encrypted content
            raw: String::new(),              // Don't store unencrypted raw
            received_at: self.received_at,
            size: self.size,
            seen: self.seen,
            deleted: self.deleted,
            uid: 0,
            flagged: self.flagged,
            answered: self.answered,
            draft: self.draft,
            encryption: metadata,
            encrypted_body: Some(encrypted_body),
        }
    }

    /// The message shown in place of an encrypted message that cannot be
    /// decrypted in the current session: the original headers plus a notice.
    pub fn locked_placeholder(&self) -> String {
        let mut out = String::new();
        for (name, value) in &self.headers {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out.push_str(
            "[This message is encrypted at rest and could not be decrypted in this session. \
             Log in with your account password to read it.]\r\n",
        );
        out
    }

    /// Check if email is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.encryption.encrypted
    }

    /// Current flag state.
    pub fn flags(&self) -> EmailFlags {
        EmailFlags {
            seen: self.seen,
            deleted: self.deleted,
            flagged: self.flagged,
            answered: self.answered,
            draft: self.draft,
        }
    }

    /// Overwrite the flag state.
    pub fn set_flags(&mut self, flags: &EmailFlags) {
        self.seen = flags.seen;
        self.deleted = flags.deleted;
        self.flagged = flags.flagged;
        self.answered = flags.answered;
        self.draft = flags.draft;
    }

    /// Split a raw message into (subject, headers, body). Header names keep
    /// their original case; the body lines are re-joined with CRLF (without a
    /// trailing line break).
    fn parse_raw(raw: &str) -> (String, Vec<(String, String)>, String) {
        let (head, body) = crate::mime::split_headers_body(raw);
        let headers = crate::mime::parse_headers_preserving_case(head);
        // With several Subject headers the last one wins.
        let subject = headers
            .iter()
            .rev()
            .find(|(n, _)| n.eq_ignore_ascii_case("subject"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let body = body.lines().collect::<Vec<_>>().join("\r\n");
        (subject, headers, body)
    }

    pub fn get_header(&self, name: &str) -> Option<&str> {
        crate::mime::header(&self.headers, name)
    }
}

/// Flag state of a message (IMAP system flags we persist).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmailFlags {
    pub seen: bool,
    pub deleted: bool,
    pub flagged: bool,
    pub answered: bool,
    pub draft: bool,
}

/// Lightweight per-message metadata (no bodies), used for session snapshots.
#[derive(Debug, Clone)]
pub struct MessageMeta {
    pub id: String,
    pub uid: u32,
    /// Size of the plaintext message in bytes.
    pub size: usize,
    pub flags: EmailFlags,
}

/// Result of a successful protocol login (`Storage::login`).
#[derive(Debug, Clone)]
pub struct LoginOutcome {
    /// Canonical (lower-case) username to use for mailbox access.
    pub username: String,
    /// The key-session generation returned by `CryptoManager::unlock_keys`
    /// when the user's encryption keys were unlocked for this session, `None`
    /// otherwise. The caller must pass it to `Storage::logout` when the
    /// session ends, so a session opened before a key regeneration does not
    /// release a reference held by a newer one.
    pub key_generation: Option<u64>,
}

/// Why a protocol login (`Storage::authenticate_full` / `Storage::login`)
/// failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The local account password is correct, but the account must change
    /// it first (`password_change_required`). Protocols report this with a
    /// dedicated response pointing at the password-change page.
    PasswordChangeRequired,
    /// Any other failure (bad credentials, locked out, ...). The message is
    /// for logs only and must not be sent to clients.
    Failed(String),
    /// The credentials could not be checked right now (directory server or
    /// app-password store unavailable). Protocols report a temporary failure
    /// (SMTP `454 4.7.0`, IMAP `NO [UNAVAILABLE]`, POP3 `-ERR [SYS/TEMP]`).
    /// The message is for logs only.
    Temporary(String),
}

impl AuthError {
    pub fn is_password_change_required(&self) -> bool {
        matches!(self, AuthError::PasswordChangeRequired)
    }

    pub fn is_temporary(&self) -> bool {
        matches!(self, AuthError::Temporary(_))
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::PasswordChangeRequired => write!(f, "Password change required"),
            AuthError::Failed(msg) => write!(f, "{}", msg),
            AuthError::Temporary(msg) => write!(f, "temporary failure: {}", msg),
        }
    }
}

impl From<String> for AuthError {
    fn from(msg: String) -> Self {
        AuthError::Failed(msg)
    }
}

impl From<crate::users::UserError> for AuthError {
    fn from(e: crate::users::UserError) -> Self {
        match e {
            crate::users::UserError::PasswordChangeRequired => AuthError::PasswordChangeRequired,
            other => AuthError::Failed(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMethod {
    AppPassword,
    Ldap,
    Local,
}

pub use crate::users::canonical_username;

/// `UserAccount::external_auth` value for accounts managed by LDAP.
pub const LDAP_EXTERNAL_AUTH: &str = "ldap";

/// Maximum number of local recipients a single message may expand to
/// (after group expansion).
pub const MAX_EXPANDED_RECIPIENTS: usize = 1000;

/// Why delivery to one recipient failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryError {
    /// Retrying will not help (unknown user, ...): 5xx.
    Permanent(String),
    /// The message exceeds the recipient's maximum message size (permanent;
    /// SMTP `552 5.3.4`).
    TooLarge(String),
    /// The sender should retry later (quota full, encryption failure, ...): 4xx.
    Temporary(String),
}

impl DeliveryError {
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            DeliveryError::Permanent(_) | DeliveryError::TooLarge(_)
        )
    }

    pub fn is_too_large(&self) -> bool {
        matches!(self, DeliveryError::TooLarge(_))
    }
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeliveryError::Permanent(msg) => write!(f, "permanent failure: {}", msg),
            DeliveryError::TooLarge(msg) => write!(f, "permanent failure: {}", msg),
            DeliveryError::Temporary(msg) => write!(f, "temporary failure: {}", msg),
        }
    }
}

impl std::error::Error for DeliveryError {}

/// Read and parse a JSON file. Returns `Ok(None)` if the file does not exist;
/// a parse error is reported as `ErrorKind::InvalidData`.
pub(crate) async fn read_json<T: DeserializeOwned>(path: &Path) -> std::io::Result<Option<T>> {
    let data = match tokio::fs::read(path).await {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    serde_json::from_slice(&data).map(Some).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: {}", path.display(), e),
        )
    })
}

/// Atomically replace `path` with `data`: write a temp file in the same
/// directory, fsync it, then rename over the target (and fsync the directory).
/// On Unix the file is created with mode 0600.
pub(crate) async fn write_atomic(path: &Path, data: Vec<u8>) -> std::io::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || write_atomic_sync(&path, &data))
        .await
        .map_err(std::io::Error::other)?
}

fn write_atomic_sync(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?
        .to_string_lossy()
        .to_string();
    let tmp = dir.join(format!(".{}.{}.tmp", file_name, Uuid::new_v4().simple()));

    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;

    // Make the rename durable. Some filesystems do not support fsync on a
    // directory, so a failure here is logged rather than failing the write
    // (the data itself is already on disk under the final name).
    #[cfg(unix)]
    if let Err(e) = std::fs::File::open(dir).and_then(|d| d.sync_all()) {
        tracing::warn!(
            "Could not fsync directory {} after writing {}: {}",
            dir.display(),
            path.display(),
            e
        );
    }
    Ok(())
}

/// A user's mailbox containing their emails.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Mailbox {
    pub emails: Vec<Email>,
    pub uidvalidity: u32,
    pub uidnext: u32,
}

/// A fresh UIDVALIDITY value of at least `min`: time-based, and strictly
/// greater than any value handed out earlier by this process, so a mailbox
/// that is removed and recreated (even within the same second) never reuses
/// the previous epoch.
fn next_uidvalidity(min: u32) -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static LAST: AtomicU32 = AtomicU32::new(0);
    let now = u32::try_from(Utc::now().timestamp()).unwrap_or(u32::MAX);
    let mut prev = LAST.load(Ordering::Relaxed);
    loop {
        let next = now.max(min).max(prev.saturating_add(1));
        match LAST.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(actual) => prev = actual,
        }
    }
}

impl Mailbox {
    /// An empty mailbox with a fresh, time-based UIDVALIDITY.
    pub fn new() -> Self {
        Self {
            emails: Vec::new(),
            uidvalidity: next_uidvalidity(1),
            uidnext: 1,
        }
    }

    pub fn add_email(&mut self, mut email: Email) -> u32 {
        if self.uidvalidity == 0 {
            self.bump_uidvalidity();
        }
        if self.uidnext == 0 {
            self.uidnext = 1;
        }
        let uid = self.uidnext;
        self.uidnext += 1;
        email.uid = uid;
        self.emails.push(email);
        uid
    }

    /// Start a new UIDVALIDITY epoch: strictly greater than the current value
    /// and (normally) time-based, so it never repeats an earlier epoch.
    pub fn bump_uidvalidity(&mut self) {
        self.uidvalidity = next_uidvalidity(self.uidvalidity.saturating_add(1));
    }

    /// Assign UIDs to messages stored without one (old data, or messages merged
    /// from another mailbox) and make sure `uidnext` is above every existing
    /// UID. Assigning any UID starts a new UIDVALIDITY epoch, since clients may
    /// have cached a different UID mapping. Returns true if anything changed.
    pub fn assign_missing_uids(&mut self) -> bool {
        let mut changed = false;
        let max_uid = self.emails.iter().map(|e| e.uid).max().unwrap_or(0);
        if self.uidnext <= max_uid {
            self.uidnext = max_uid + 1;
            changed = true;
        }
        if self.uidnext == 0 {
            self.uidnext = 1;
            changed = true;
        }
        let mut assigned = false;
        for email in self.emails.iter_mut().filter(|e| e.uid == 0) {
            email.uid = self.uidnext;
            self.uidnext += 1;
            assigned = true;
        }
        if assigned || self.uidvalidity == 0 {
            self.bump_uidvalidity();
            changed = true;
        }
        changed
    }
}

/// A user's mail data (mailbox only, credentials managed by UserManager).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMailbox {
    pub username: String,
    pub mailbox: Mailbox,
}

impl UserMailbox {
    pub fn new(username: String) -> Self {
        Self {
            username,
            mailbox: Mailbox::new(),
        }
    }
}

/// The main storage backend.
#[derive(Clone)]
pub struct Storage {
    mailboxes: Arc<RwLock<HashMap<String, UserMailbox>>>,
    user_manager: Arc<UserManager>,
    ldap_client: Option<Arc<LdapClient>>,
    sso_manager: Option<Arc<SsoManager>>,
    crypto_manager: Option<Arc<CryptoManager>>,
    data_dir: PathBuf,
    /// Serialises writes of `mailboxes.json`.
    save_lock: Arc<tokio::sync::Mutex<()>>,
}

impl Storage {
    pub fn new(data_dir: PathBuf, user_manager: Arc<UserManager>) -> Self {
        Self {
            mailboxes: Arc::new(RwLock::new(HashMap::new())),
            user_manager,
            ldap_client: None,
            sso_manager: None,
            crypto_manager: None,
            data_dir,
            save_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Create storage with full encryption support
    pub fn with_encryption(
        data_dir: PathBuf,
        user_manager: Arc<UserManager>,
        ldap_client: Arc<LdapClient>,
        sso_manager: Arc<SsoManager>,
        crypto_manager: Arc<CryptoManager>,
    ) -> Self {
        Self {
            ldap_client: Some(ldap_client),
            sso_manager: Some(sso_manager),
            crypto_manager: Some(crypto_manager),
            ..Self::new(data_dir, user_manager)
        }
    }

    pub async fn load(&self) -> Result<(), std::io::Error> {
        let path = self.data_dir.join("mailboxes.json");
        let Some(loaded) = read_json::<HashMap<String, UserMailbox>>(&path).await? else {
            return Ok(());
        };

        // Canonicalise keys, merging mailboxes that differ only by case. Keys
        // are processed in a deterministic order: for each canonical name the
        // already-canonical key comes first, then the others sorted, so the
        // surviving mailbox (and its UIDs) does not depend on hash order.
        let mut entries: Vec<(String, String, UserMailbox)> = loaded
            .into_iter()
            .map(|(key, mb)| (canonical_username(&key), key, mb))
            .collect();
        entries.sort_by(|(ca, ka, _), (cb, kb, _)| {
            ca.cmp(cb)
                .then_with(|| (ka != ca).cmp(&(kb != cb)))
                .then_with(|| ka.cmp(kb))
        });

        let mut merged = false;
        let mut mailboxes: HashMap<String, UserMailbox> = HashMap::new();
        for (key, original_key, mut user_mailbox) in entries {
            user_mailbox.username = key.clone();
            match mailboxes.get_mut(&key) {
                Some(existing) => {
                    tracing::warn!(
                        "Merging mailbox {:?} into {:?} (names differ only by case)",
                        original_key,
                        key
                    );
                    // Merged messages get fresh UIDs; `assign_missing_uids`
                    // then starts a new UIDVALIDITY epoch for this mailbox.
                    for mut email in user_mailbox.mailbox.emails {
                        email.uid = 0;
                        existing.mailbox.emails.push(email);
                    }
                    merged = true;
                }
                None => {
                    mailboxes.insert(key, user_mailbox);
                }
            }
        }
        let mut uids_changed = false;
        for user_mailbox in mailboxes.values_mut() {
            uids_changed |= user_mailbox.mailbox.assign_missing_uids();
        }

        let count = mailboxes.len();
        *self.mailboxes.write().await = mailboxes;
        tracing::info!("Loaded {} mailboxes from storage", count);

        if (merged || uids_changed)
            && let Err(e) = self.save().await
        {
            tracing::error!(
                "Could not persist repaired mailboxes to {}: {}",
                path.display(),
                e
            );
        }

        Ok(())
    }

    /// Persist mailboxes (atomic write; saves are serialised and each snapshot
    /// is taken after acquiring the save lock).
    pub async fn save(&self) -> Result<(), std::io::Error> {
        let _guard = self.save_lock.lock().await;
        tokio::fs::create_dir_all(&self.data_dir).await?;
        let path = self.data_dir.join("mailboxes.json");
        let data = {
            let mailboxes = self.mailboxes.read().await;
            serde_json::to_vec_pretty(&*mailboxes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        };
        write_atomic(&path, data).await
    }

    /// Get the user manager
    pub fn user_manager(&self) -> &Arc<UserManager> {
        &self.user_manager
    }

    /// Make sure a mailbox entry exists for `username` (does not touch an
    /// existing one).
    pub async fn ensure_mailbox(&self, username: &str) {
        let key = canonical_username(username);
        let mut mailboxes = self.mailboxes.write().await;
        mailboxes
            .entry(key.clone())
            .or_insert_with(|| UserMailbox::new(key));
    }

    /// Authenticate with full details (tries SSO app passwords, then LDAP,
    /// then local accounts). Only the local-password path can return
    /// [`AuthError::PasswordChangeRequired`].
    pub async fn authenticate_full(
        &self,
        username: &str,
        password: &str,
        ip: &str,
        protocol: &str,
    ) -> Result<UserAccount, AuthError> {
        self.authenticate(username, password, ip, protocol)
            .await
            .map(|(account, _)| account)
    }

    /// Authenticate a mail-protocol login and open the session: unlocks the
    /// user's encryption keys (generating them first for LDAP accounts that
    /// have none) and makes sure the mailbox exists.
    ///
    /// Keys are unlocked whenever they exist, even if encryption of new mail
    /// is turned off, so previously encrypted messages stay readable. The
    /// returned [`LoginOutcome::key_generation`] must be passed to
    /// [`Storage::logout`] when the session ends.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        ip: &str,
        protocol: &str,
    ) -> Result<LoginOutcome, AuthError> {
        let (account, method) = self.authenticate(username, password, ip, protocol).await?;
        let canonical = canonical_username(&account.username);
        let local_account = self.user_manager.user_exists(&canonical).await;

        let mut key_generation = None;
        if let Some(crypto) = &self.crypto_manager {
            if method == AuthMethod::AppPassword {
                tracing::debug!(
                    "{} logged in with an app password; encrypted messages stay locked",
                    canonical
                );
            } else if local_account {
                if method == AuthMethod::Ldap {
                    // First login of an LDAP account: wrap new keys with the
                    // directory password (no-op when keys already exist).
                    self.user_manager.ensure_keys(&canonical, password).await;
                }
                if crypto.has_keys(&canonical).await {
                    key_generation =
                        Self::unlock_session_keys(crypto, &canonical, password, method).await;
                }
            }
        }

        if local_account {
            self.ensure_mailbox(&canonical).await;
        }

        Ok(LoginOutcome {
            username: canonical,
            key_generation,
        })
    }

    /// Unlock `username`'s keys for a session. Returns the key-session
    /// generation on success.
    ///
    /// Keys are never regenerated here. For LDAP logins the directory bind has
    /// already proven the password, so an unlock failure means the directory
    /// password changed since the keys were wrapped; the keys stay locked
    /// (encrypted mail shows the placeholder) until an administrator resets
    /// them.
    async fn unlock_session_keys(
        crypto: &CryptoManager,
        username: &str,
        password: &str,
        method: AuthMethod,
    ) -> Option<u64> {
        match crypto.unlock_keys(username, password).await {
            Ok(generation) => Some(generation),
            Err(CryptoError::InvalidPassword) if method == AuthMethod::Ldap => {
                tracing::warn!(
                    "{}: mail keys could not be unlocked with the directory password; \
                     an admin reset is required",
                    username
                );
                None
            }
            Err(e) => {
                tracing::warn!("Could not unlock encryption keys for {}: {}", username, e);
                None
            }
        }
    }

    /// Close a session opened by `login`; `key_generation` is
    /// [`LoginOutcome::key_generation`] from that login.
    pub async fn logout(&self, username: &str, key_generation: Option<u64>) {
        let Some(generation) = key_generation else {
            return;
        };
        if let Some(crypto) = &self.crypto_manager {
            crypto
                .lock_keys(&canonical_username(username), generation)
                .await;
        }
    }

    /// Check account status and IP restrictions for a non-local-password login.
    fn check_login_allowed(user: &UserAccount, ip: &str) -> Result<(), AuthError> {
        user.check_login_from(ip).map_err(AuthError::from)
    }

    /// Account record for an LDAP-authenticated user whose local account could
    /// not be created.
    fn external_ldap_account(username: &str, display_name: Option<String>) -> UserAccount {
        let mut account = UserAccount::with_hash(
            canonical_username(username),
            String::new(),
            LDAP_EXTERNAL_AUTH.to_string(),
        );
        account.settings.display_name = display_name;
        account.last_login = Some(account.created_at);
        account.external_auth = Some(LDAP_EXTERNAL_AUTH.to_string());
        account
    }

    /// Authenticate and report which method succeeded.
    async fn authenticate(
        &self,
        username: &str,
        password: &str,
        ip: &str,
        protocol: &str,
    ) -> Result<(UserAccount, AuthMethod), AuthError> {
        let username = canonical_username(username);
        let username = username.as_str();

        // Try SSO app passwords first if configured.
        if let Some(sso) = &self.sso_manager
            && let Some(user) = self
                .try_app_password(sso, username, password, ip, protocol)
                .await?
        {
            return Ok((user, AuthMethod::AppPassword));
        }

        // Try LDAP if configured.
        if let Some(ldap) = &self.ldap_client
            && ldap.is_enabled()
            && let Some(user) = self.try_ldap(ldap, username, password, ip).await?
        {
            return Ok((user, AuthMethod::Ldap));
        }

        // Local authentication (throttled inside `UserManager::authenticate`).
        self.user_manager
            .authenticate(username, password, ip, protocol)
            .await
            .map(|u| (u, AuthMethod::Local))
            .map_err(AuthError::from)
    }

    /// Check `password` as an SSO app password. `Ok(None)`: not an app
    /// password, try the other methods. App passwords are only accepted for
    /// existing local accounts. The check runs inside a login-throttle slot; a
    /// mismatch cancels the slot because the password check that follows
    /// records the attempt.
    async fn try_app_password(
        &self,
        sso: &SsoManager,
        username: &str,
        password: &str,
        ip: &str,
        protocol: &str,
    ) -> Result<Option<UserAccount>, AuthError> {
        let slot = self.user_manager.throttle_reserve(username, ip)?;
        tokio::time::sleep(slot.delay()).await;
        let verified = match sso.verify_app_password(username, password, protocol).await {
            Ok(verified) => verified,
            Err(e) => {
                tracing::warn!("App password check for {} failed: {}", username, e);
                return Err(AuthError::Temporary(format!(
                    "app password check failed: {}",
                    e
                )));
            }
        };
        if !verified {
            drop(slot);
            return Ok(None);
        }
        let Some(user) = self.user_manager.get_user(username).await else {
            slot.failure();
            tracing::warn!(
                "App password for {} via {} from {} refused: no local account",
                username,
                protocol,
                ip
            );
            return Err(AuthError::Failed(
                "App password for a user without a local account".to_string(),
            ));
        };
        slot.success();
        Self::check_login_allowed(&user, ip)?;
        tracing::info!(
            "SSO app password authentication successful for {} via {} from {}",
            username,
            protocol,
            ip
        );
        Ok(Some(user))
    }

    /// Authenticate against LDAP inside a login-throttle slot. `Ok(None)`:
    /// fall through to local authentication (fallback enabled), which then
    /// records the attempt itself.
    async fn try_ldap(
        &self,
        ldap: &LdapClient,
        username: &str,
        password: &str,
        ip: &str,
    ) -> Result<Option<UserAccount>, AuthError> {
        let slot = self.user_manager.throttle_reserve(username, ip)?;
        tokio::time::sleep(slot.delay()).await;
        match ldap.authenticate(username, password).await {
            LdapAuthResult::Success(ldap_user) => {
                slot.success();
                tracing::info!("LDAP authentication successful for {}", username);
                match self
                    .provision_ldap_user(username, password, &ldap_user)
                    .await
                {
                    Some(user) => {
                        Self::check_login_allowed(&user, ip)?;
                        Ok(Some(user))
                    }
                    None => Ok(Some(Self::external_ldap_account(
                        username,
                        ldap_user.display_name,
                    ))),
                }
            }
            LdapAuthResult::InvalidCredentials => {
                tracing::debug!(
                    "LDAP authentication failed for {}: invalid credentials",
                    username
                );
                if ldap.fallback_enabled() {
                    drop(slot);
                    return Ok(None);
                }
                slot.failure();
                Err(AuthError::Failed("Invalid credentials".to_string()))
            }
            LdapAuthResult::UserNotFound => {
                tracing::debug!("User {} not found in LDAP", username);
                if ldap.fallback_enabled() {
                    drop(slot);
                    return Ok(None);
                }
                slot.failure();
                Err(AuthError::Failed("User not found".to_string()))
            }
            LdapAuthResult::Error(e) => {
                tracing::warn!("LDAP error for {}: {}", username, e);
                drop(slot);
                if ldap.fallback_enabled() {
                    return Ok(None);
                }
                Err(AuthError::Temporary(format!("LDAP error: {}", e)))
            }
            LdapAuthResult::NotEnabled => Ok(None),
        }
    }

    /// Make sure an LDAP-authenticated user has a local account (created with
    /// the directory display name and marked as externally managed) and a
    /// mailbox. Returns the local account, or `None` if it could not be
    /// created.
    async fn provision_ldap_user(
        &self,
        username: &str,
        password: &str,
        ldap_user: &crate::ldap::LdapUser,
    ) -> Option<UserAccount> {
        if !self.user_manager.user_exists(username).await {
            let display_name = ldap_user.display_name.clone();
            let created = self
                .user_manager
                .create_user_with(username, password, None, move |u| {
                    u.external_auth = Some(LDAP_EXTERNAL_AUTH.to_string());
                    if display_name.is_some() {
                        u.settings.display_name = display_name;
                    }
                })
                .await;
            match created {
                Ok(_) => {
                    self.ensure_mailbox(username).await;
                    tracing::info!(
                        "Created local user {} from LDAP ({})",
                        username,
                        ldap_user.email.as_deref().unwrap_or("no email")
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to create local user {} from LDAP: {}", username, e);
                }
            }
        }

        let user = self.user_manager.get_user(username).await?;
        if user.external_auth.is_some() {
            return Some(user);
        }
        // An existing account that now authenticates through LDAP becomes
        // externally managed.
        match self
            .user_manager
            .update_user(username, |u| {
                if u.external_auth.is_none() {
                    u.external_auth = Some(LDAP_EXTERNAL_AUTH.to_string());
                }
            })
            .await
        {
            Ok(updated) => Some(updated),
            Err(e) => {
                tracing::error!(
                    "Could not mark {} as LDAP-managed (external_auth): {}",
                    username,
                    e
                );
                Some(user)
            }
        }
    }

    pub async fn user_exists(&self, username: &str) -> bool {
        self.user_manager.user_exists(username).await
    }

    /// Check whether `username` could receive a message of `size` bytes.
    /// Unknown users pass (recipient existence is checked separately).
    pub async fn check_recipient_quota(&self, username: &str, size: u64) -> Result<(), QuotaError> {
        match self.user_manager.get_user(username).await {
            Some(user) => user.quota.can_receive(size),
            None => Ok(()),
        }
    }

    /// Deliver a message to one local recipient (test helper).
    #[cfg(test)]
    pub(crate) async fn deliver_email(
        &self,
        recipient: &str,
        email: Email,
    ) -> Result<String, DeliveryError> {
        self.deliver_to_many(&[recipient.to_string()], email)
            .await
            .into_iter()
            .next()
            .map(|(_, r)| r)
            .unwrap_or_else(|| Err(DeliveryError::Permanent("No recipient".to_string())))
    }

    /// Deliver a message to several local recipients, updating quota usage with
    /// a single `users.json` write. Returns one result per distinct local part
    /// (case-insensitive duplicates are delivered once), carrying the stored
    /// message id on success.
    ///
    /// Unknown users and oversized messages fail permanently; a full mailbox
    /// or an encryption failure fails temporarily. A message that should be
    /// encrypted is never stored in plaintext.
    ///
    /// Recipients are processed one at a time and each stored copy is moved
    /// into the mailbox before the next is built, so at most one extra
    /// plaintext copy and one encrypted copy exist at any time.
    pub async fn deliver_to_many(
        &self,
        recipients: &[String],
        email: Email,
    ) -> Vec<(String, Result<String, DeliveryError>)> {
        let mut results = Vec::new();
        let mut delivered: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        let email_size = email.size as u64;

        for recipient in recipients {
            let local_part = crate::users::local_part(recipient);
            if !seen.insert(local_part.clone()) {
                continue;
            }
            let result = self.deliver_one(&local_part, &email).await;
            if result.is_ok() {
                delivered.push(local_part);
            }
            results.push((recipient.clone(), result));
        }

        if !delivered.is_empty() {
            // Update quota usage for all recipients with one save.
            if let Err(e) = self
                .user_manager
                .update_users(&delivered, |u| u.quota.record_received(email_size))
                .await
            {
                tracing::error!("Could not persist quota usage for {:?}: {}", delivered, e);
            }
        }

        results
    }

    /// Build and store one recipient's copy of `email`.
    async fn deliver_one(&self, local_part: &str, email: &Email) -> Result<String, DeliveryError> {
        let Some(user) = self.user_manager.get_user(local_part).await else {
            return Err(DeliveryError::Permanent(format!(
                "No such user: {}",
                local_part
            )));
        };

        match user.quota.can_receive(email.size as u64) {
            Ok(()) => {}
            Err(e @ QuotaError::MessageTooLarge { .. }) => {
                return Err(DeliveryError::TooLarge(e.to_string()));
            }
            Err(e) => {
                return Err(DeliveryError::Temporary(format!("Quota exceeded: {}", e)));
            }
        }

        let to_store = match &self.crypto_manager {
            Some(crypto) if crypto.is_enabled() && crypto.has_keys(local_part).await => {
                match crypto
                    .encrypt_for_storage(local_part, email.raw.as_bytes())
                    .await
                {
                    Ok((encrypted_body, metadata)) if metadata.encrypted => {
                        email.encrypted_copy(encrypted_body, metadata)
                    }
                    // Keys disappeared between the check and the call: the
                    // user has no keys, so plaintext storage is expected.
                    Ok(_) => Self::plain_copy(email),
                    Err(e) => {
                        tracing::error!(
                            "Failed to encrypt message for {}; not storing it: {}",
                            local_part,
                            e
                        );
                        return Err(DeliveryError::Temporary(format!(
                            "Could not encrypt message for {}",
                            local_part
                        )));
                    }
                }
            }
            _ => Self::plain_copy(email),
        };

        let id = to_store.id.clone();
        let encrypted = to_store.is_encrypted();
        {
            let mut mailboxes = self.mailboxes.write().await;
            // Re-check under the mailbox lock: if the account was deleted
            // while the copy was being built, `remove_mailbox` may already
            // have run, and inserting here would resurrect a stale mailbox.
            // (Account deletion removes the user before the mailbox, so a
            // deletion that starts after this check removes our copy too.)
            if !self.user_manager.user_exists(local_part).await {
                return Err(DeliveryError::Permanent(format!(
                    "No such user: {}",
                    local_part
                )));
            }
            mailboxes
                .entry(local_part.to_string())
                .or_insert_with(|| UserMailbox::new(local_part.to_string()))
                .mailbox
                .add_email(to_store);
        }
        tracing::info!(
            "Delivered email to {} (encrypted: {})",
            local_part,
            encrypted
        );
        Ok(id)
    }

    fn plain_copy(email: &Email) -> Email {
        let mut copy = email.clone();
        copy.id = Uuid::new_v4().to_string();
        copy
    }

    /// Undo a (partial) delivery: remove the given messages and revert their
    /// quota usage.
    pub async fn rollback_delivery(&self, delivered: &[(String, String)]) {
        let mut by_user: HashMap<String, Vec<String>> = HashMap::new();
        for (user, id) in delivered {
            by_user
                .entry(canonical_username(user))
                .or_default()
                .push(id.clone());
        }
        for (user, ids) in by_user {
            let removed = self.expunge_by_ids(&user, &ids).await;
            if removed.len() != ids.len() {
                tracing::warn!(
                    "Rollback for {}: {} of {} messages were already gone",
                    user,
                    ids.len() - removed.len(),
                    ids.len()
                );
            }
        }
    }

    /// Delete a user's mailbox entry (e.g. when the account is deleted) and
    /// persist the change.
    pub async fn remove_mailbox(&self, user: &str) -> std::io::Result<()> {
        let key = canonical_username(user);
        let removed = self.mailboxes.write().await.remove(&key).is_some();
        if removed {
            tracing::info!("Removed mailbox for {}", key);
        }
        self.save().await
    }

    /// Decrypt an email for a user (requires active session)
    pub async fn decrypt_email(&self, username: &str, email: &Email) -> Result<String, String> {
        if !email.is_encrypted() {
            return Ok(email.raw.clone());
        }

        let crypto = self
            .crypto_manager
            .as_ref()
            .ok_or_else(|| "Encryption not configured".to_string())?;

        let encrypted_body = email
            .encrypted_body
            .as_ref()
            .ok_or_else(|| "Email marked as encrypted but no encrypted body".to_string())?;

        let decrypted = crypto
            .decrypt_from_storage(username, encrypted_body, &email.encryption)
            .await
            .map_err(|e| e.to_string())?;

        String::from_utf8(decrypted).map_err(|e| format!("Invalid UTF-8 in decrypted email: {}", e))
    }

    /// Message content for a session: decrypted when encrypted (requires the
    /// user's keys to be unlocked); otherwise the raw message. If decryption is
    /// not possible `Email::locked_placeholder` (original headers + notice) is
    /// returned.
    pub async fn email_content(&self, username: &str, email: &Email) -> String {
        if !email.is_encrypted() {
            return email.raw.clone();
        }
        match self
            .decrypt_email(&canonical_username(username), email)
            .await
        {
            Ok(raw) => raw,
            Err(e) => {
                tracing::warn!(
                    "Could not decrypt message {} for {}: {}",
                    email.id,
                    username,
                    e
                );
                email.locked_placeholder()
            }
        }
    }

    /// The size (in octets) to report for a message whose content, as
    /// returned by `email_content`, is `content`. IMAP `RFC822.SIZE` and POP3
    /// sizes must use this so the advertised size equals what is sent (an
    /// undecryptable message is sent as its placeholder, not the original).
    /// Falls back to the stored size when no content is available.
    pub fn display_size(&self, email: &Email, content: &str) -> usize {
        if content.is_empty() && !email.is_encrypted() {
            email.size
        } else {
            content.len()
        }
    }

    /// A copy of the user's mailbox (test helper; deep-clones every message).
    #[cfg(test)]
    pub(crate) async fn get_mailbox(&self, username: &str) -> Option<Mailbox> {
        let key = canonical_username(username);
        self.mailboxes
            .read()
            .await
            .get(&key)
            .map(|mb| mb.mailbox.clone())
    }

    /// Run `f` against the user's mailbox under the read lock (no clone).
    /// Returns `None` if the user has no mailbox entry.
    pub async fn with_mailbox<R>(
        &self,
        username: &str,
        f: impl FnOnce(&Mailbox) -> R,
    ) -> Option<R> {
        let key = canonical_username(username);
        let mailboxes = self.mailboxes.read().await;
        mailboxes.get(&key).map(|mb| f(&mb.mailbox))
    }

    /// Metadata for every message in the mailbox (including messages flagged
    /// deleted), in mailbox order. Empty for existing users without mail;
    /// `None` for unknown users.
    pub async fn message_meta(&self, username: &str) -> Option<Vec<MessageMeta>> {
        let meta = self
            .with_mailbox(username, |mb| {
                mb.emails
                    .iter()
                    .map(|e| MessageMeta {
                        id: e.id.clone(),
                        uid: e.uid,
                        size: e.size,
                        flags: e.flags(),
                    })
                    .collect::<Vec<_>>()
            })
            .await;
        match meta {
            Some(m) => Some(m),
            None if self.user_manager.user_exists(username).await => Some(Vec::new()),
            None => None,
        }
    }

    /// Clone only the requested messages (by id).
    pub async fn get_emails_by_ids(
        &self,
        username: &str,
        ids: &[String],
    ) -> HashMap<String, Email> {
        let wanted: HashSet<&str> = ids.iter().map(|s| s.as_str()).collect();
        self.with_mailbox(username, |mb| {
            mb.emails
                .iter()
                .filter(|e| wanted.contains(e.id.as_str()))
                .map(|e| (e.id.clone(), e.clone()))
                .collect()
        })
        .await
        .unwrap_or_default()
    }

    /// Apply `f` to each message whose id is in `ids`; returns the resulting
    /// flags by id (messages that no longer exist are absent).
    pub async fn update_emails_by_ids<F>(
        &self,
        username: &str,
        ids: &[String],
        mut f: F,
    ) -> HashMap<String, EmailFlags>
    where
        F: FnMut(&mut Email),
    {
        let wanted: HashSet<&str> = ids.iter().map(|s| s.as_str()).collect();
        let key = canonical_username(username);
        let mut mailboxes = self.mailboxes.write().await;
        let mut out = HashMap::new();
        if let Some(user_mailbox) = mailboxes.get_mut(&key) {
            for email in user_mailbox
                .mailbox
                .emails
                .iter_mut()
                .filter(|e| wanted.contains(e.id.as_str()))
            {
                f(email);
                out.insert(email.id.clone(), email.flags());
            }
        }
        out
    }

    /// Permanently remove the given messages (by id), updating quota usage.
    /// Returns the ids actually removed.
    pub async fn expunge_by_ids(&self, username: &str, ids: &[String]) -> Vec<String> {
        let wanted: HashSet<&str> = ids.iter().map(|s| s.as_str()).collect();
        let key = canonical_username(username);
        let mut removed = Vec::new();
        let mut removed_size: u64 = 0;
        {
            let mut mailboxes = self.mailboxes.write().await;
            let Some(user_mailbox) = mailboxes.get_mut(&key) else {
                return removed;
            };
            user_mailbox.mailbox.emails.retain(|e| {
                if wanted.contains(e.id.as_str()) {
                    removed.push(e.id.clone());
                    removed_size += e.size as u64;
                    false
                } else {
                    true
                }
            });
        }
        if !removed.is_empty() {
            self.record_removed(&key, removed_size, removed.len()).await;
        }
        removed
    }

    async fn record_removed(&self, username: &str, size: u64, count: usize) {
        if let Err(e) = self
            .user_manager
            .update_user(username, |u| {
                u.quota.current_usage = u.quota.current_usage.saturating_sub(size);
                u.quota.current_messages = u.quota.current_messages.saturating_sub(count as u32);
            })
            .await
        {
            tracing::error!("Could not update quota usage for {}: {}", username, e);
        }
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> StorageStats {
        let mailboxes = self.mailboxes.read().await;
        let user_stats = self.user_manager.get_stats().await;

        let mut total_emails = 0u64;
        let mut total_size = 0u64;

        for mb in mailboxes.values() {
            total_emails += mb.mailbox.emails.len() as u64;
            total_size += mb.mailbox.emails.iter().map(|e| e.size as u64).sum::<u64>();
        }

        StorageStats {
            total_mailboxes: mailboxes.len() as u32,
            total_emails,
            total_size,
            user_stats,
        }
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_mailboxes: u32,
    pub total_emails: u64,
    pub total_size: u64,
    pub user_stats: crate::users::UserStats,
}

/// Storage with encryption at rest enabled (regardless of the environment)
/// and one user, `bob` / `password123`, who has keys and three delivered
/// messages (`Subject: m{i}` / `body {i}`, i = 1..=3) stored encrypted.
/// Keys are not unlocked; use `Storage::login` to open a session.
#[cfg(test)]
pub(crate) async fn test_storage_encrypted(dir: &Path) -> Arc<Storage> {
    let users = Arc::new(UserManager::new(
        "example.com".to_string(),
        dir.to_path_buf(),
    ));
    let crypto = Arc::new(CryptoManager::with_enabled(dir.to_path_buf(), true));
    users.attach_crypto(Arc::clone(&crypto)).await;
    users.create_user("bob", "password123", None).await.unwrap();
    assert!(crypto.has_keys("bob").await, "bob must have keys");
    let storage = Arc::new(Storage {
        crypto_manager: Some(crypto),
        ..Storage::new(dir.to_path_buf(), users)
    });
    for i in 1..=3 {
        let raw = format!("Subject: m{}\r\n\r\nbody {}\r\n", i, i);
        storage
            .deliver_email("bob@example.com", Email::new("a@b".into(), vec![], raw))
            .await
            .unwrap();
    }
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "password123";

    async fn test_storage(dir: &Path, users: &[&str]) -> Storage {
        let manager = Arc::new(UserManager::new(
            "example.com".to_string(),
            dir.to_path_buf(),
        ));
        for u in users {
            manager.create_user(u, PW, None).await.unwrap();
        }
        Storage::new(dir.to_path_buf(), manager)
    }

    fn msg(subject: &str, body: &str) -> Email {
        Email::new(
            "a@b".into(),
            vec![],
            format!("Subject: {}\r\n\r\n{}\r\n", subject, body),
        )
    }

    fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    // Characterization tests for `Email::parse_raw` (written against the
    // original hand-rolled parser before it moved onto `crate::mime`).

    #[test]
    fn parse_raw_folded_headers_crlf() {
        let raw = "Subject: Hello\r\n  world\r\nX-Long: a\r\n\tb\r\n c\r\n\r\nline1\r\nline2\r\n";
        let (subject, headers, body) = Email::parse_raw(raw);
        assert_eq!(subject, "Hello world");
        assert_eq!(
            headers,
            hdrs(&[("Subject", "Hello world"), ("X-Long", "a b c")])
        );
        assert_eq!(body, "line1\r\nline2");
    }

    #[test]
    fn parse_raw_lf_only_matches_crlf() {
        let lf = "From: a@b\nSubject: Hi\n there\n\nbody1\nbody2\n";
        let crlf = lf.replace('\n', "\r\n");
        let a = Email::parse_raw(lf);
        let b = Email::parse_raw(&crlf);
        assert_eq!(a, b);
        assert_eq!(a.0, "Hi there");
        assert_eq!(a.1, hdrs(&[("From", "a@b"), ("Subject", "Hi there")]));
        // The body is always re-joined with CRLF and loses the final newline.
        assert_eq!(a.2, "body1\r\nbody2");
    }

    #[test]
    fn parse_raw_colon_in_value_and_mixed_case_names() {
        let raw = "SUBJECT: Re: meeting: 10:30\r\nX-MiXeD-CaSe: v\r\ncontent-type: text/plain; a=b\r\n\r\nx";
        let (subject, headers, body) = Email::parse_raw(raw);
        assert_eq!(subject, "Re: meeting: 10:30");
        assert_eq!(
            headers,
            hdrs(&[
                ("SUBJECT", "Re: meeting: 10:30"),
                ("X-MiXeD-CaSe", "v"),
                ("content-type", "text/plain; a=b"),
            ])
        );
        assert_eq!(body, "x");
        let email = Email::new("a@b".into(), vec![], raw.to_string());
        assert_eq!(email.get_header("x-mixed-case"), Some("v"));
        assert!(
            email
                .locked_placeholder()
                .starts_with("SUBJECT: Re: meeting: 10:30\r\nX-MiXeD-CaSe: v\r\n")
        );
    }

    #[test]
    fn parse_raw_empty_body_and_no_blank_line() {
        let (subject, headers, body) = Email::parse_raw("Subject: s\r\n\r\n");
        assert_eq!(subject, "s");
        assert_eq!(headers, hdrs(&[("Subject", "s")]));
        assert_eq!(body, "");

        // Without a blank line everything is headers.
        let (subject, headers, body) = Email::parse_raw("Subject: s\r\nTo: x@y\r\n");
        assert_eq!(subject, "s");
        assert_eq!(headers, hdrs(&[("Subject", "s"), ("To", "x@y")]));
        assert_eq!(body, "");

        let (subject, headers, body) = Email::parse_raw("");
        assert_eq!(
            (subject.as_str(), headers.len(), body.as_str()),
            ("", 0, "")
        );
    }

    #[test]
    fn parse_raw_body_keeps_blank_lines_and_header_like_text() {
        let raw = "A: 1\r\n\r\n\r\nSubject: not a header\r\n\r\nend";
        let (subject, headers, body) = Email::parse_raw(raw);
        assert_eq!(subject, "");
        assert_eq!(headers, hdrs(&[("A", "1")]));
        assert_eq!(body, "\r\nSubject: not a header\r\n\r\nend");
    }

    #[test]
    fn parse_raw_last_subject_wins_and_first_header_is_returned() {
        let raw = "Subject: one\r\nX-A: 1\r\nsubject: two\r\nx-a: 2\r\n\r\n";
        let email = Email::new("a@b".into(), vec![], raw.to_string());
        assert_eq!(email.subject, "two");
        assert_eq!(email.get_header("X-A"), Some("1"));
        assert_eq!(email.headers.len(), 4);
    }

    // The two tests below pin behaviour of the `crate::mime` parser that
    // INTENTIONALLY differs from the old hand-rolled parser: header names are
    // trimmed (so "Subject :" is the Subject header), and a continuation of
    // an empty value does not start with a separating space.

    #[test]
    fn parse_raw_space_before_colon() {
        let raw = "Subject : spaced\r\nX-A\t: tabbed\r\n\r\nbody";
        let (subject, headers, body) = Email::parse_raw(raw);
        assert_eq!(subject, "spaced");
        assert_eq!(headers, hdrs(&[("Subject", "spaced"), ("X-A", "tabbed")]));
        assert_eq!(body, "body");
    }

    #[test]
    fn parse_raw_empty_value_then_continuation() {
        let raw = "Subject:\r\n  continued here\r\nX-Empty:\r\n\r\n";
        let (subject, headers, _) = Email::parse_raw(raw);
        assert_eq!(subject, "continued here");
        assert_eq!(
            headers,
            hdrs(&[("Subject", "continued here"), ("X-Empty", "")])
        );
    }

    #[test]
    fn parse_raw_skips_lines_without_colon_and_leading_continuation() {
        let raw = " orphan\r\nA: 1\r\ngarbage line\r\nB:2\r\n\r\n";
        let (_, headers, _) = Email::parse_raw(raw);
        assert_eq!(headers, hdrs(&[("A", "1"), ("B", "2")]));
    }

    #[tokio::test]
    async fn password_change_required_is_a_typed_auth_error() {
        let dir = tempfile::tempdir().unwrap();
        let users = Arc::new(UserManager::new(
            "example.com".to_string(),
            dir.path().to_path_buf(),
        ));
        users.create_user("bob", PW, None).await.unwrap();
        users
            .update_user("bob", |u| u.password_change_required = true)
            .await
            .unwrap();
        let sso = Arc::new(SsoManager::new(
            crate::sso::SsoConfig::default(),
            dir.path().to_path_buf(),
        ));
        let app_pw = sso
            .generate_app_password("bob", "test", None)
            .await
            .unwrap();
        let storage = Storage::with_encryption(
            dir.path().to_path_buf(),
            users,
            Arc::new(LdapClient::new(crate::ldap::LdapConfig::default())),
            sso,
            Arc::new(CryptoManager::with_enabled(dir.path().to_path_buf(), false)),
        );

        let err = storage
            .authenticate_full("bob", PW, "127.0.0.1", "SMTP")
            .await
            .unwrap_err();
        assert!(err.is_password_change_required());
        assert_eq!(err, AuthError::PasswordChangeRequired);
        let err = storage
            .login("bob", PW, "127.0.0.1", "IMAP")
            .await
            .unwrap_err();
        assert!(err.is_password_change_required());

        // Wrong password: an ordinary failure.
        let err = storage
            .login("bob", "wrongpass", "127.0.0.1", "IMAP")
            .await
            .unwrap_err();
        assert!(!err.is_password_change_required());

        // App passwords are not affected by the local-password flag.
        assert!(
            storage
                .login("bob", &app_pw, "127.0.0.1", "IMAP")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn app_password_without_local_account_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let users = Arc::new(UserManager::new(
            "example.com".to_string(),
            dir.path().to_path_buf(),
        ));
        let sso = Arc::new(SsoManager::new(
            crate::sso::SsoConfig::default(),
            dir.path().to_path_buf(),
        ));
        let app_pw = sso
            .generate_app_password("ghost", "test", None)
            .await
            .unwrap();
        let storage = Storage::with_encryption(
            dir.path().to_path_buf(),
            Arc::clone(&users),
            Arc::new(LdapClient::new(crate::ldap::LdapConfig::default())),
            sso,
            Arc::new(CryptoManager::with_enabled(dir.path().to_path_buf(), false)),
        );

        let err = storage
            .login("ghost", &app_pw, "127.0.0.1", "IMAP")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Failed(_)), "{:?}", err);
        let err = storage
            .authenticate_full("Ghost", &app_pw, "127.0.0.1", "SMTP")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Failed(_)), "{:?}", err);
        assert!(!users.user_exists("ghost").await);
        assert!(storage.get_mailbox("ghost").await.is_none());
    }

    #[tokio::test]
    async fn ldap_login_does_not_regenerate_keys() {
        // There is no LDAP test seam, so exercise the unlock helper that the
        // LDAP login path uses with a (changed) directory password.
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage_encrypted(dir.path()).await;
        let crypto = storage.crypto_manager.as_ref().unwrap();
        let public_before = crypto.get_public_key("bob").await.unwrap();

        let generation =
            Storage::unlock_session_keys(crypto, "bob", "new-directory-pw", AuthMethod::Ldap).await;
        assert!(generation.is_none());
        assert_eq!(crypto.get_public_key("bob").await.unwrap(), public_before);

        // The original keys still unlock with the old password, and existing
        // mail remains readable.
        let generation = Storage::unlock_session_keys(crypto, "bob", PW, AuthMethod::Ldap).await;
        assert!(generation.is_some());
        let email = storage.get_mailbox("bob").await.unwrap().emails[0].clone();
        assert!(
            storage
                .email_content("bob", &email)
                .await
                .contains("body 1")
        );
        storage.logout("bob", generation).await;
    }

    #[tokio::test]
    async fn recreated_mailbox_new_uidvalidity() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path(), &["bob"]).await;
        storage.deliver_email("bob", msg("1", "1")).await.unwrap();
        let first = storage.get_mailbox("bob").await.unwrap().uidvalidity;

        storage.remove_mailbox("bob").await.unwrap();
        storage.deliver_email("bob", msg("2", "2")).await.unwrap();
        let second = storage.get_mailbox("bob").await.unwrap();
        assert_ne!(second.uidvalidity, first);
        assert!(second.uidvalidity > first);
        assert_eq!(second.emails[0].uid, 1);
    }

    #[tokio::test]
    async fn delivery_to_deleted_user_is_permanent_and_creates_no_mailbox() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path(), &["bob"]).await;
        let admin = storage
            .user_manager()
            .create_user("root", PW, Some(crate::users::UserRole::SuperAdmin))
            .await
            .unwrap();
        storage
            .user_manager()
            .delete_user("bob", &admin)
            .await
            .unwrap();
        let result = storage.deliver_email("bob", msg("s", "b")).await;
        assert!(matches!(result, Err(DeliveryError::Permanent(_))));
        assert!(storage.get_mailbox("bob").await.is_none());
    }

    async fn quota(storage: &Storage, user: &str) -> (u64, u32) {
        let q = storage.user_manager().get_user(user).await.unwrap().quota;
        (q.current_usage, q.current_messages)
    }

    async fn mailbox_len(storage: &Storage, user: &str) -> usize {
        storage
            .get_mailbox(user)
            .await
            .map(|m| m.emails.len())
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn deliver_to_many_dedups_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path(), &["bob"]).await;
        let email = msg("hi", "hello");
        let size = email.size as u64;
        let recipients = vec![
            "bob@example.com".to_string(),
            "BOB@example.com".to_string(),
            " Bob ".to_string(),
        ];
        let results = storage.deliver_to_many(&recipients, email).await;
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_ok());
        assert_eq!(mailbox_len(&storage, "bob").await, 1);
        assert_eq!(quota(&storage, "bob").await, (size, 1));
    }

    #[tokio::test]
    async fn unknown_user_is_permanent_and_over_quota_is_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path(), &["bob", "carol", "dave"]).await;
        storage
            .user_manager()
            .update_user("carol", |u| {
                u.quota.max_messages = 1;
                u.quota.current_messages = 1;
            })
            .await
            .unwrap();
        storage
            .user_manager()
            .update_user("dave", |u| u.quota.max_message_size = 1)
            .await
            .unwrap();

        let recipients: Vec<String> = ["nobody@example.com", "carol@example.com", "dave", "bob"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let results = storage.deliver_to_many(&recipients, msg("s", "b")).await;
        assert_eq!(results.len(), 4);
        assert!(matches!(results[0].1, Err(DeliveryError::Permanent(_))));
        assert!(matches!(results[1].1, Err(DeliveryError::Temporary(_))));
        assert!(matches!(results[2].1, Err(DeliveryError::TooLarge(_))));
        assert!(results[2].1.as_ref().unwrap_err().is_permanent());
        let id = results[3].1.as_ref().unwrap();
        assert_eq!(storage.get_mailbox("bob").await.unwrap().emails[0].id, *id);
        assert_eq!(mailbox_len(&storage, "carol").await, 0);
        assert_eq!(mailbox_len(&storage, "dave").await, 0);
    }

    #[tokio::test]
    async fn encryption_failure_is_temporary_not_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        // Create keys for bob, then corrupt his public key on disk.
        {
            let crypto = CryptoManager::with_enabled(dir.path().to_path_buf(), true);
            crypto.generate_keypair("bob", PW).await.unwrap();
        }
        let keys_path = dir.path().join("keys.json");
        let mut keys: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&keys_path).unwrap()).unwrap();
        keys["bob"]["public_key"] = serde_json::json!([1, 2, 3]);
        std::fs::write(&keys_path, serde_json::to_vec(&keys).unwrap()).unwrap();
        let crypto = Arc::new(CryptoManager::with_enabled(dir.path().to_path_buf(), true));
        assert!(crypto.has_keys("bob").await);

        let plain = test_storage(dir.path(), &["bob"]).await;
        let storage = Storage {
            crypto_manager: Some(crypto),
            ..plain
        };
        let result = storage
            .deliver_email("bob", msg("secret", "TOP-SECRET-BODY"))
            .await;
        assert!(matches!(result, Err(DeliveryError::Temporary(_))));
        assert_eq!(mailbox_len(&storage, "bob").await, 0);
        assert_eq!(quota(&storage, "bob").await, (0, 0));

        storage.save().await.unwrap();
        let saved = std::fs::read_to_string(dir.path().join("mailboxes.json")).unwrap();
        assert!(!saved.contains("TOP-SECRET-BODY"));
    }

    #[tokio::test]
    async fn rollback_delivery_removes_messages_and_quota() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path(), &["bob", "carol"]).await;
        storage
            .deliver_email("bob", msg("keep", "keep"))
            .await
            .unwrap();
        let kept = quota(&storage, "bob").await;

        let recipients = vec!["bob".to_string(), "carol@example.com".to_string()];
        let results = storage.deliver_to_many(&recipients, msg("s", "b")).await;
        let delivered: Vec<(String, String)> = results
            .into_iter()
            .map(|(rcpt, r)| (crate::users::local_part(&rcpt), r.unwrap()))
            .collect();
        assert_eq!(mailbox_len(&storage, "bob").await, 2);

        storage.rollback_delivery(&delivered).await;
        assert_eq!(mailbox_len(&storage, "bob").await, 1);
        assert_eq!(mailbox_len(&storage, "carol").await, 0);
        assert_eq!(quota(&storage, "bob").await, kept);
        assert_eq!(quota(&storage, "carol").await, (0, 0));
    }

    #[tokio::test]
    async fn remove_mailbox_then_recreate_user_gets_empty_mailbox() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path(), &["bob"]).await;
        let admin = storage
            .user_manager()
            .create_user("root", PW, Some(crate::users::UserRole::SuperAdmin))
            .await
            .unwrap();
        storage
            .deliver_email("bob", msg("old", "old"))
            .await
            .unwrap();
        storage.save().await.unwrap();

        storage
            .user_manager()
            .delete_user("bob", &admin)
            .await
            .unwrap();
        storage.remove_mailbox("Bob").await.unwrap();
        assert!(storage.get_mailbox("bob").await.is_none());
        let saved = std::fs::read_to_string(dir.path().join("mailboxes.json")).unwrap();
        assert!(!saved.contains("\"bob\""));

        storage
            .user_manager()
            .create_user("bob", PW, None)
            .await
            .unwrap();
        storage.ensure_mailbox("bob").await;
        assert_eq!(storage.message_meta("bob").await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn expunge_by_ids_ignores_other_users_ids() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path(), &["bob", "carol"]).await;
        storage.deliver_email("bob", msg("b", "b")).await.unwrap();
        let carol_id = storage.deliver_email("carol", msg("c", "c")).await.unwrap();

        let removed = storage
            .expunge_by_ids("bob", std::slice::from_ref(&carol_id))
            .await;
        assert!(removed.is_empty());
        assert_eq!(mailbox_len(&storage, "bob").await, 1);
        assert_eq!(mailbox_len(&storage, "carol").await, 1);
        assert_eq!(quota(&storage, "carol").await.1, 1);
        assert_eq!(quota(&storage, "bob").await.1, 1);
    }

    #[tokio::test]
    async fn save_then_load_round_trips_uids_and_flags() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path(), &["bob"]).await;
        storage.deliver_email("bob", msg("1", "1")).await.unwrap();
        let id2 = storage.deliver_email("bob", msg("2", "2")).await.unwrap();
        storage
            .update_emails_by_ids("bob", &[id2], |e| {
                e.seen = true;
                e.flagged = true;
                e.answered = true;
            })
            .await;
        storage.save().await.unwrap();
        let before = storage.get_mailbox("bob").await.unwrap();

        let reloaded = Storage::new(dir.path().to_path_buf(), Arc::clone(storage.user_manager()));
        reloaded.load().await.unwrap();
        let after = reloaded.get_mailbox("bob").await.unwrap();
        assert_eq!(after.uidvalidity, before.uidvalidity);
        assert_eq!(after.uidnext, before.uidnext);
        let summary = |mb: &Mailbox| {
            mb.emails
                .iter()
                .map(|e| (e.id.clone(), e.uid, e.flags()))
                .collect::<Vec<_>>()
        };
        assert_eq!(summary(&after), summary(&before));
        assert_eq!(after.emails[0].uid, 1);
        assert_eq!(after.emails[1].uid, 2);
        assert!(after.emails[1].flagged && after.emails[1].seen);
    }

    #[tokio::test]
    async fn case_merge_is_deterministic_and_bumps_uidvalidity() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path(), &["bob"]).await;

        let mailbox = |subjects: &[&str], uidvalidity: u32| {
            let mut mb = Mailbox::new();
            mb.uidvalidity = uidvalidity;
            for s in subjects {
                mb.add_email(msg(s, "x"));
            }
            mb
        };
        let mut on_disk: HashMap<String, UserMailbox> = HashMap::new();
        for (key, subjects) in [
            ("Bob", vec!["Bob-1"]),
            ("bob", vec!["bob-1", "bob-2"]),
            ("BOB", vec!["BOB-1"]),
        ] {
            on_disk.insert(
                key.to_string(),
                UserMailbox {
                    username: key.to_string(),
                    mailbox: mailbox(&subjects, 5),
                },
            );
        }
        std::fs::write(
            dir.path().join("mailboxes.json"),
            serde_json::to_vec(&on_disk).unwrap(),
        )
        .unwrap();

        storage.load().await.unwrap();
        let mb = storage.get_mailbox("bob").await.unwrap();
        let subjects: Vec<&str> = mb.emails.iter().map(|e| e.subject.as_str()).collect();
        // Canonical key first (UIDs kept), then the others in sorted order.
        assert_eq!(subjects, ["bob-1", "bob-2", "BOB-1", "Bob-1"]);
        let uids: Vec<u32> = mb.emails.iter().map(|e| e.uid).collect();
        assert_eq!(uids, [1, 2, 3, 4]);
        assert_eq!(mb.uidnext, 5);
        assert!(mb.uidvalidity > 5);

        // The repaired state was persisted under the canonical key only.
        let saved: HashMap<String, UserMailbox> = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("mailboxes.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(saved.keys().collect::<Vec<_>>(), ["bob"]);
        assert_eq!(saved["bob"].mailbox.uidvalidity, mb.uidvalidity);
    }

    #[test]
    fn assign_missing_uids_bumps_uidvalidity() {
        let mut mb = Mailbox::new();
        mb.add_email(msg("a", "a"));
        let initial = mb.uidvalidity;
        assert!(initial > 1, "time-based UIDVALIDITY");
        assert!(!mb.assign_missing_uids());
        assert_eq!(mb.uidvalidity, initial);
        let mut e = msg("b", "b");
        e.uid = 0;
        mb.emails.push(e);
        assert!(mb.assign_missing_uids());
        assert!(mb.uidvalidity > initial);
        assert_eq!(mb.emails[1].uid, 2);
    }

    #[tokio::test]
    async fn read_json_missing_is_none_and_garbage_is_invalid_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.json");
        assert!(read_json::<Vec<u32>>(&path).await.unwrap().is_none());
        std::fs::write(&path, b"not json").unwrap();
        let err = read_json::<Vec<u32>>(&path).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        write_atomic(&path, b"[1,2]".to_vec()).await.unwrap();
        assert_eq!(
            read_json::<Vec<u32>>(&path).await.unwrap(),
            Some(vec![1, 2])
        );
    }

    #[tokio::test]
    async fn deliver_stores_ciphertext_not_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage_encrypted(dir.path()).await;
        let mb = storage.get_mailbox("bob").await.unwrap();
        assert_eq!(mb.emails.len(), 3);
        assert!(
            mb.emails
                .iter()
                .all(|e| e.is_encrypted() && e.raw.is_empty())
        );

        storage.save().await.unwrap();
        let saved = std::fs::read_to_string(dir.path().join("mailboxes.json")).unwrap();
        for i in 1..=3 {
            assert!(!saved.contains(&format!("body {}", i)));
        }
    }

    #[tokio::test]
    async fn login_then_email_content_decrypts() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage_encrypted(dir.path()).await;
        let email = storage.get_mailbox("bob").await.unwrap().emails[1].clone();

        // Without a session the placeholder is served, and its size reported.
        let locked = storage.email_content("bob", &email).await;
        assert_eq!(locked, email.locked_placeholder());
        assert!(!locked.contains("body 2"));
        assert_eq!(storage.display_size(&email, &locked), locked.len());

        let outcome = storage.login("Bob", PW, "127.0.0.1", "IMAP").await.unwrap();
        assert!(outcome.key_generation.is_some());
        assert_eq!(outcome.username, "bob");
        let content = storage.email_content("bob", &email).await;
        assert!(content.contains("body 2"));
        assert_eq!(storage.display_size(&email, &content), email.size);
        storage.logout("bob", outcome.key_generation).await;
    }

    #[tokio::test]
    async fn logout_without_unlock_does_not_decrement_refcount() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage_encrypted(dir.path()).await;
        let email = storage.get_mailbox("bob").await.unwrap().emails[0].clone();

        let outcome = storage.login("bob", PW, "127.0.0.1", "IMAP").await.unwrap();
        assert!(outcome.key_generation.is_some());
        // A second session that did not unlock keys ends.
        storage.logout("bob", None).await;
        assert!(
            storage
                .email_content("bob", &email)
                .await
                .contains("body 1")
        );

        storage.logout("bob", outcome.key_generation).await;
        assert!(
            !storage
                .email_content("bob", &email)
                .await
                .contains("body 1")
        );
    }
}
