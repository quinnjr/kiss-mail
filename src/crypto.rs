//! Encryption at rest for stored mail, with password-wrapped keys.
//!
//! What this module actually does:
//! - Each user has an X25519 key pair (generated when the account is created,
//!   or lazily on the first successful password login for older accounts).
//! - The private key is wrapped (encrypted) with ChaCha20-Poly1305 under a key
//!   derived from the user's password with Argon2id; only the public key and the
//!   wrapped private key are written to `keys.json`.
//! - Each delivered message is encrypted to the recipient's public key using an
//!   ECIES-style construction: a fresh ephemeral X25519 key pair per message,
//!   ECDH with the recipient's public key, SHA-256 over a fixed label and the
//!   shared secret as the KDF, and ChaCha20-Poly1305 for the message bytes.
//! - When a user logs in (IMAP/POP3) with their password the server unwraps the
//!   private key and keeps it in memory for the session; it is dropped again on
//!   logout/disconnect.
//!
//! Limitations (this is *not* end-to-end encryption):
//! - The server receives mail in plaintext over SMTP and encrypts it itself.
//! - The server sees the user's password at login and holds the unwrapped
//!   private key in memory while a session is open.
//! - Parsed headers (From, To, Subject, ...) are stored in plaintext alongside
//!   the encrypted message so that listings work without the private key.
//! - Resetting a password without the old one (admin reset) requires a new key
//!   pair, which makes previously stored encrypted mail unreadable.
//!
//! ```text
//! Registration:  password --Argon2id--> KEK;  X25519 keypair;  wrap(private, KEK)
//! Delivery:      ephemeral X25519 + ECDH(recipient pub) --SHA-256--> key;
//!                ChaCha20-Poly1305(key, message)
//! Login:         password --Argon2id--> KEK; unwrap private key (session only)
//! Read:          ECDH(private, ephemeral pub) --SHA-256--> key; decrypt
//! ```

use argon2::Argon2;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

/// Size of symmetric encryption key (256 bits)
const KEY_SIZE: usize = 32;
/// Size of nonce for ChaCha20-Poly1305 (96 bits)
const NONCE_SIZE: usize = 12;
/// Size of Argon2 salt
const SALT_SIZE: usize = 16;

// ============================================================================
// Key Types
// ============================================================================

/// A user's encryption key pair
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserKeyPair {
    /// Public key (can be shared)
    pub public_key: Vec<u8>,
    /// Private key encrypted with user's password
    pub encrypted_private_key: Vec<u8>,
    /// Salt used for key derivation
    pub salt: Vec<u8>,
    /// Nonce used for private key encryption
    pub nonce: Vec<u8>,
    /// Key version for rotation
    pub version: u32,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Decrypted session keys (held in memory during user session)
#[derive(Clone)]
pub struct SessionKeys {
    /// Decrypted private key
    pub private_key: StaticSecret,
}

/// An unlocked key session for one user, shared by all of that user's open
/// logins (reference counted).
struct Session {
    keys: SessionKeys,
    /// Open logins holding this session.
    refs: usize,
    /// Identifies this session: returned by `unlock_keys` and required by
    /// `lock_keys`, so a login opened before a key regeneration or deletion
    /// cannot release a reference held by a newer session.
    generation: u64,
}

/// An encrypted email
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedEmail {
    /// Encrypted symmetric key (encrypted with recipient's public key)
    pub encrypted_key: Vec<u8>,
    /// Nonce for key encryption
    pub key_nonce: Vec<u8>,
    /// Encrypted email body
    pub ciphertext: Vec<u8>,
    /// Nonce for body encryption
    pub body_nonce: Vec<u8>,
    /// Encryption version
    pub version: u8,
    /// Sender's public key (for verification)
    pub sender_public_key: Option<Vec<u8>>,
}

/// Encryption metadata stored with emails
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    /// Whether the email is encrypted
    pub encrypted: bool,
    /// Encryption algorithm used
    pub algorithm: String,
    /// Key version used for encryption
    pub key_version: u32,
    /// Whether this is end-to-end encrypted (sender is also local)
    pub e2e: bool,
}

// ============================================================================
// Crypto Manager
// ============================================================================

/// Manages encryption keys and operations
pub struct CryptoManager {
    /// User keys (username -> key pair)
    keys: Arc<RwLock<HashMap<String, UserKeyPair>>>,
    /// Active key sessions (username -> session)
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    /// Source of session generations (never reused within a process).
    next_generation: AtomicU64,
    /// Data directory for key storage
    data_dir: PathBuf,
    /// Whether encryption is enabled
    enabled: bool,
    /// Set when `keys.json` existed but could not be read/parsed. While set,
    /// every key change is refused so the unreadable file is never replaced by
    /// an (incomplete) in-memory map.
    load_error: Option<String>,
    /// Serialises key changes (and with them writes of `keys.json`).
    save_lock: tokio::sync::Mutex<()>,
}

impl CryptoManager {
    /// Create a new crypto manager; encryption of new mail is enabled unless
    /// `KISS_MAIL_ENCRYPTION` is `false`/`0`/`no`/`off`.
    ///
    /// Safe to call from inside a tokio runtime (keys are loaded with plain
    /// `std::fs` before the lock is constructed).
    pub fn new(data_dir: PathBuf) -> Self {
        let enabled = crate::config::env_bool("KISS_MAIL_ENCRYPTION", true);
        Self::with_enabled(data_dir, enabled)
    }

    /// Create a crypto manager with an explicit enabled flag. `enabled` only
    /// controls whether NEW mail is encrypted; key management, unlocking and
    /// decryption work either way.
    pub fn with_enabled(data_dir: PathBuf, enabled: bool) -> Self {
        let keys_path = data_dir.join("keys.json");
        let (keys, load_error) = Self::load_keys_file(&keys_path);

        Self {
            keys: Arc::new(RwLock::new(keys)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            next_generation: AtomicU64::new(1),
            data_dir,
            enabled,
            load_error,
            save_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Read `keys.json`. A missing file yields an empty map; an unreadable or
    /// unparsable file yields an empty map plus an error (which blocks saving).
    fn load_keys_file(path: &std::path::Path) -> (HashMap<String, UserKeyPair>, Option<String>) {
        if !path.exists() {
            return (HashMap::new(), None);
        }
        let result = std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|data| {
                serde_json::from_str::<HashMap<String, UserKeyPair>>(&data)
                    .map_err(|e| e.to_string())
            });
        match result {
            Ok(keys) => (keys, None),
            Err(e) => {
                let msg = format!("failed to load {}: {}", path.display(), e);
                tracing::error!(
                    "Encryption keys could not be loaded ({}); refusing to overwrite the key file until this is fixed",
                    msg
                );
                (HashMap::new(), Some(msg))
            }
        }
    }

    /// Check if encryption of new mail is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// `Some(reason)` if `keys.json` existed but could not be read or parsed.
    /// While set, every key change is refused.
    pub fn load_error(&self) -> Option<String> {
        self.load_error.clone()
    }

    fn check_loaded(&self) -> Result<(), CryptoError> {
        match &self.load_error {
            Some(err) => {
                tracing::error!("Refusing to change encryption keys: {}", err);
                Err(CryptoError::StorageError(format!(
                    "refusing to save keys: {}",
                    err
                )))
            }
            None => Ok(()),
        }
    }

    /// Apply a change to the key map durably: the change is made on a copy,
    /// the copy is written to `keys.json`, and only after a successful write
    /// is it installed in memory. All key changes go through here while
    /// holding `save_lock`, so the copy is always current.
    ///
    /// `change` returns the value to hand back and whether it modified the map
    /// (an unchanged map is not rewritten).
    async fn commit<R>(
        &self,
        change: impl FnOnce(&mut HashMap<String, UserKeyPair>) -> Result<(R, bool), CryptoError>,
    ) -> Result<R, CryptoError> {
        self.check_loaded()?;

        let _guard = self.save_lock.lock().await;
        let mut next = self.keys.read().await.clone();
        let (result, changed) = change(&mut next)?;
        if !changed {
            return Ok(result);
        }

        let data = serde_json::to_vec_pretty(&next)
            .map_err(|e| CryptoError::StorageError(e.to_string()))?;
        tokio::fs::create_dir_all(&self.data_dir)
            .await
            .map_err(|e| CryptoError::StorageError(e.to_string()))?;
        let keys_path = self.data_dir.join("keys.json");
        crate::storage::write_atomic(&keys_path, data)
            .await
            .map_err(|e| CryptoError::StorageError(e.to_string()))?;

        *self.keys.write().await = next;
        Ok(result)
    }

    /// Create a fresh key pair wrapped with `password` (not stored).
    async fn new_keypair(password: &str) -> Result<UserKeyPair, CryptoError> {
        let private_key = StaticSecret::random();
        let public_key = PublicKey::from(&private_key);
        let (encrypted_private_key, salt, nonce) = wrap_private_key(&private_key, password).await?;

        Ok(UserKeyPair {
            public_key: public_key.as_bytes().to_vec(),
            encrypted_private_key,
            salt,
            nonce,
            version: 1,
            created_at: chrono::Utc::now(),
        })
    }

    /// Generate a key pair for a user if they do not have one yet
    /// (insert-if-absent). If the user already has keys, the existing key pair
    /// is returned unchanged. The new key pair is written to disk before it
    /// becomes visible in memory; nothing is kept if saving fails.
    pub async fn generate_keypair(
        &self,
        username: &str,
        password: &str,
    ) -> Result<UserKeyPair, CryptoError> {
        self.check_loaded()?;
        if let Some(existing) = self.keys.read().await.get(username).cloned() {
            return Ok(existing);
        }

        let keypair = Self::new_keypair(password).await?;

        let (stored, created) = self
            .commit(|keys| match keys.get(username) {
                // Someone else won the race while we were deriving.
                Some(existing) => Ok(((existing.clone(), false), false)),
                None => {
                    keys.insert(username.to_string(), keypair.clone());
                    Ok(((keypair, true), true))
                }
            })
            .await?;

        if created {
            tracing::info!("Generated encryption keypair for user: {}", username);
        }
        Ok(stored)
    }

    /// Replace a user's key pair with a fresh one wrapped with `password`
    /// (admin password reset). Saved before it is installed in memory; any
    /// unlocked session holding the old private key is dropped, so the next
    /// unlock starts a new generation and `lock_keys` calls for the old one
    /// become no-ops.
    pub async fn regenerate_keypair(
        &self,
        username: &str,
        password: &str,
    ) -> Result<UserKeyPair, CryptoError> {
        self.check_loaded()?;
        let keypair = Self::new_keypair(password).await?;

        self.commit(|keys| {
            keys.insert(username.to_string(), keypair.clone());
            Ok(((), true))
        })
        .await?;

        {
            // Drop the session only if it holds the old key (a session
            // unlocked with the new key after the commit is kept).
            let mut sessions = self.sessions.write().await;
            let stale = sessions.get(username).is_some_and(|s| {
                PublicKey::from(&s.keys.private_key).as_bytes().as_slice()
                    != keypair.public_key.as_slice()
            });
            if stale {
                sessions.remove(username);
            }
        }
        tracing::info!("Regenerated encryption keypair for user: {}", username);
        Ok(keypair)
    }

    /// Unwrap a user's private key with their password without registering a
    /// session.
    async fn unwrap_keys(
        &self,
        username: &str,
        password: &str,
    ) -> Result<SessionKeys, CryptoError> {
        let keypair = {
            let keys = self.keys.read().await;
            keys.get(username)
                .cloned()
                .ok_or_else(|| CryptoError::KeyNotFound(username.to_string()))?
        };

        // Derive KEK from password
        let kek = derive_key_async(password, &keypair.salt).await?;

        // Decrypt private key
        let cipher = ChaCha20Poly1305::new_from_slice(&kek)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

        let private_key_bytes = cipher
            .decrypt(
                Nonce::from_slice(&keypair.nonce),
                keypair.encrypted_private_key.as_slice(),
            )
            .map_err(|_| CryptoError::InvalidPassword)?;

        // Reconstruct keys
        let private_key_array: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| CryptoError::DecryptionError("Invalid key length".to_string()))?;

        Ok(SessionKeys {
            private_key: StaticSecret::from(private_key_array),
        })
    }

    /// Unlock a user's private key with their password and keep it in memory
    /// for the session. Sessions are reference counted: every successful call
    /// must be paired with one `lock_keys(username, generation)` call, passing
    /// the generation returned here.
    pub async fn unlock_keys(&self, username: &str, password: &str) -> Result<u64, CryptoError> {
        let unwrapped = self.unwrap_keys(username, password).await?;
        let public_key = PublicKey::from(&unwrapped.private_key);

        // Lock order: keys, then sessions. Holding the keys read lock means
        // no regeneration/deletion can commit between the check and the
        // insert.
        let keys = self.keys.read().await;
        let current = keys
            .get(username)
            .is_some_and(|k| k.public_key.as_slice() == public_key.as_bytes().as_slice());
        if !current {
            return Err(CryptoError::StorageError(
                "key pair changed concurrently; try again".to_string(),
            ));
        }
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .entry(username.to_string())
            .or_insert_with(|| Session {
                keys: unwrapped.clone(),
                refs: 0,
                generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
            });
        session.keys = unwrapped;
        session.refs += 1;
        Ok(session.generation)
    }

    /// Release one reference to the session of `generation`; the decrypted
    /// key is dropped from memory when the last reference ends. A stale
    /// generation (the session was dropped by a key regeneration or deletion
    /// and possibly replaced) is ignored.
    pub async fn lock_keys(&self, username: &str, generation: u64) {
        let mut sessions = self.sessions.write().await;
        match sessions.get_mut(username) {
            Some(session) if session.generation == generation => {
                session.refs = session.refs.saturating_sub(1);
                if session.refs == 0 {
                    sessions.remove(username);
                }
            }
            Some(_) => tracing::debug!(
                "Ignoring key release for {} from a previous session generation",
                username
            ),
            None => {}
        }
    }

    /// Get a user's public key
    pub async fn get_public_key(&self, username: &str) -> Option<Vec<u8>> {
        let keys = self.keys.read().await;
        keys.get(username).map(|k| k.public_key.clone())
    }

    /// Check if a user has encryption keys
    pub async fn has_keys(&self, username: &str) -> bool {
        let keys = self.keys.read().await;
        keys.contains_key(username)
    }

    /// Delete a user's keys (no-op on disk if they have none) and drop any
    /// unlocked session for them (a later unlock starts a new generation).
    pub async fn delete_keys(&self, username: &str) -> Result<(), CryptoError> {
        let result = self
            .commit(|keys| {
                let removed = keys.remove(username).is_some();
                Ok(((), removed))
            })
            .await;
        if result.is_ok() {
            self.sessions.write().await.remove(username);
        }
        result
    }

    /// Change a user's password (re-wrap the private key). The re-wrapped key
    /// is saved before it replaces the old one in memory.
    pub async fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), CryptoError> {
        self.check_loaded()?;

        // Unwrap with old password (does not open a session)
        let session = self.unwrap_keys(username, old_password).await?;
        let (encrypted_private_key, salt, nonce) =
            wrap_private_key(&session.private_key, new_password).await?;
        let public_key = PublicKey::from(&session.private_key);

        self.commit(|keys| {
            let keypair = keys
                .get_mut(username)
                .ok_or_else(|| CryptoError::KeyNotFound(username.to_string()))?;
            if keypair.public_key != public_key.as_bytes().as_slice() {
                // Replaced concurrently (e.g. admin reset); do not clobber it.
                return Err(CryptoError::StorageError(
                    "key pair changed concurrently".to_string(),
                ));
            }
            keypair.encrypted_private_key = encrypted_private_key;
            keypair.salt = salt;
            keypair.nonce = nonce;
            Ok(((), true))
        })
        .await?;

        tracing::info!(
            "Re-encrypted keys for user after password change: {}",
            username
        );
        Ok(())
    }

    /// Encrypt an email for a recipient
    pub async fn encrypt_email(
        &self,
        recipient: &str,
        plaintext: &[u8],
        sender: Option<&str>,
    ) -> Result<EncryptedEmail, CryptoError> {
        if !self.enabled {
            return Err(CryptoError::Disabled);
        }

        // Get recipient's public key
        let recipient_public_key = self
            .get_public_key(recipient)
            .await
            .ok_or_else(|| CryptoError::KeyNotFound(recipient.to_string()))?;

        let recipient_pk_array: [u8; 32] = recipient_public_key
            .clone()
            .try_into()
            .map_err(|_| CryptoError::EncryptionError("Invalid public key".to_string()))?;
        let recipient_pk = PublicKey::from(recipient_pk_array);

        // Generate ephemeral key pair for key exchange
        let ephemeral_secret = StaticSecret::random();
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Perform X25519 key exchange to derive shared secret
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

        // Derive symmetric key from shared secret
        let symmetric_key = derive_symmetric_key(shared_secret.as_bytes());

        // Generate random nonce for body encryption
        let body_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Encrypt email body
        let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let ciphertext = cipher
            .encrypt(&body_nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        // Get sender's public key if local
        let sender_public_key = if let Some(s) = sender {
            self.get_public_key(s).await
        } else {
            None
        };

        Ok(EncryptedEmail {
            encrypted_key: ephemeral_public.as_bytes().to_vec(),
            key_nonce: vec![], // Not used in X25519 scheme
            ciphertext,
            body_nonce: body_nonce.to_vec(),
            version: 1,
            sender_public_key,
        })
    }

    /// Decrypt an email
    pub async fn decrypt_email(
        &self,
        username: &str,
        encrypted: &EncryptedEmail,
    ) -> Result<Vec<u8>, CryptoError> {
        // Decryption works even when encryption of new mail is disabled, so
        // mail stored while it was enabled stays readable.
        // Get session keys
        let sessions = self.sessions.read().await;
        let session = &sessions
            .get(username)
            .ok_or_else(|| CryptoError::SessionNotFound(username.to_string()))?
            .keys;

        // Reconstruct ephemeral public key
        let ephemeral_pk_array: [u8; 32] = encrypted
            .encrypted_key
            .clone()
            .try_into()
            .map_err(|_| CryptoError::DecryptionError("Invalid ephemeral key".to_string()))?;
        let ephemeral_pk = PublicKey::from(ephemeral_pk_array);

        // Perform key exchange to recover shared secret
        let shared_secret = session.private_key.diffie_hellman(&ephemeral_pk);

        // Derive symmetric key
        let symmetric_key = derive_symmetric_key(shared_secret.as_bytes());

        // Decrypt email body
        let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(&encrypted.body_nonce);
        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_slice())
            .map_err(|_| CryptoError::DecryptionError("Failed to decrypt email".to_string()))?;

        Ok(plaintext)
    }

    /// Encrypt an email for storage (simpler version for external emails)
    pub async fn encrypt_for_storage(
        &self,
        recipient: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, EncryptionMetadata), CryptoError> {
        if !self.enabled {
            return Ok((plaintext.to_vec(), EncryptionMetadata::default()));
        }

        if !self.has_keys(recipient).await {
            return Ok((plaintext.to_vec(), EncryptionMetadata::default()));
        }

        let encrypted = self.encrypt_email(recipient, plaintext, None).await?;
        let encrypted_data = serde_json::to_vec(&encrypted)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let metadata = EncryptionMetadata {
            encrypted: true,
            algorithm: "X25519-ChaCha20-Poly1305".to_string(),
            key_version: 1,
            e2e: false,
        };

        Ok((encrypted_data, metadata))
    }

    /// Decrypt an email from storage
    pub async fn decrypt_from_storage(
        &self,
        username: &str,
        data: &[u8],
        metadata: &EncryptionMetadata,
    ) -> Result<Vec<u8>, CryptoError> {
        if !metadata.encrypted {
            return Ok(data.to_vec());
        }

        let encrypted: EncryptedEmail = serde_json::from_slice(data)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

        self.decrypt_email(username, &encrypted).await
    }

    /// Get encryption status
    pub fn status(&self) -> CryptoStatus {
        CryptoStatus {
            enabled: self.enabled,
            algorithm: "X25519-ChaCha20-Poly1305".to_string(),
            key_derivation: "Argon2id".to_string(),
        }
    }

    /// Get stats
    pub async fn stats(&self) -> CryptoStats {
        let keys = self.keys.read().await;
        let sessions = self.sessions.read().await;

        CryptoStats {
            total_keys: keys.len(),
            active_sessions: sessions.len(),
            enabled: self.enabled,
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Derive a key encryption key from password using Argon2id
fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE], CryptoError> {
    // Use Argon2id with secure parameters
    let argon2 = Argon2::default();

    // Hash password to get key using the raw salt
    let mut output = [0u8; KEY_SIZE];

    // Use raw hash output with the salt directly
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

    Ok(output)
}

/// Run the (CPU-heavy) Argon2 derivation on the blocking thread pool, bounded
/// by the process-wide Argon2 concurrency limit.
async fn derive_key_async(password: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE], CryptoError> {
    let password = password.to_string();
    let salt = salt.to_vec();
    let _permit = crate::users::argon2_permit().await;
    tokio::task::spawn_blocking(move || derive_key_from_password(&password, &salt))
        .await
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?
}

/// Wrap a private key under a fresh password-derived key.
/// Returns `(encrypted_private_key, salt, nonce)`.
async fn wrap_private_key(
    private_key: &StaticSecret,
    password: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), CryptoError> {
    let salt = generate_random_bytes(SALT_SIZE);
    let kek = derive_key_async(password, &salt).await?;

    let nonce = generate_random_bytes(NONCE_SIZE);
    let cipher = ChaCha20Poly1305::new_from_slice(&kek)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
    let encrypted_private_key = cipher
        .encrypt(Nonce::from_slice(&nonce), private_key.as_bytes().as_slice())
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    Ok((encrypted_private_key, salt, nonce))
}

/// Derive a symmetric key from shared secret using SHA-256
fn derive_symmetric_key(shared_secret: &[u8]) -> [u8; KEY_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(b"kiss-mail-v1");
    hasher.update(shared_secret);
    hasher.finalize().into()
}

/// Generate random bytes
fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone)]
pub enum CryptoError {
    /// Encryption is disabled
    Disabled,
    /// Key not found for user
    KeyNotFound(String),
    /// Invalid password
    InvalidPassword,
    /// Session not found (user not logged in)
    SessionNotFound(String),
    /// Key derivation error
    KeyDerivationError(String),
    /// Encryption error
    EncryptionError(String),
    /// Decryption error
    DecryptionError(String),
    /// Storage error
    StorageError(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "Encryption is disabled"),
            Self::KeyNotFound(u) => write!(f, "Encryption key not found for user: {}", u),
            Self::InvalidPassword => write!(f, "Invalid password"),
            Self::SessionNotFound(u) => {
                write!(f, "Session not found for user: {} (not logged in)", u)
            }
            Self::KeyDerivationError(e) => write!(f, "Key derivation error: {}", e),
            Self::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            Self::DecryptionError(e) => write!(f, "Decryption error: {}", e),
            Self::StorageError(e) => write!(f, "Storage error: {}", e),
        }
    }
}

impl std::error::Error for CryptoError {}

// ============================================================================
// Status Types
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct CryptoStatus {
    pub enabled: bool,
    pub algorithm: String,
    pub key_derivation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CryptoStats {
    pub total_keys: usize,
    pub active_sessions: usize,
    pub enabled: bool,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn enabled_manager(dir: &std::path::Path) -> CryptoManager {
        CryptoManager::with_enabled(dir.to_path_buf(), true)
    }

    #[tokio::test]
    async fn test_keypair_generation() {
        let dir = tempdir().unwrap();
        let manager = enabled_manager(dir.path());

        let keypair = manager
            .generate_keypair("alice", "password123")
            .await
            .unwrap();

        assert_eq!(keypair.public_key.len(), 32);
        assert!(!keypair.encrypted_private_key.is_empty());
        assert_eq!(keypair.version, 1);
    }

    #[tokio::test]
    async fn test_unlock_keys() {
        let dir = tempdir().unwrap();
        let manager = enabled_manager(dir.path());

        manager
            .generate_keypair("alice", "password123")
            .await
            .unwrap();

        // Correct password should work
        let session = manager.unlock_keys("alice", "password123").await;
        assert!(session.is_ok());

        // Wrong password should fail
        let session = manager.unlock_keys("alice", "wrongpassword").await;
        assert!(matches!(session, Err(CryptoError::InvalidPassword)));
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_email() {
        let dir = tempdir().unwrap();
        let manager = enabled_manager(dir.path());

        // Setup recipient
        manager.generate_keypair("bob", "bobpass").await.unwrap();
        manager.unlock_keys("bob", "bobpass").await.unwrap();

        // Encrypt email
        let plaintext = b"Hello, Bob! This is a secret message.";
        let encrypted = manager.encrypt_email("bob", plaintext, None).await.unwrap();

        // Decrypt email
        let decrypted = manager.decrypt_email("bob", &encrypted).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_password_change() {
        let dir = tempdir().unwrap();
        let manager = enabled_manager(dir.path());

        manager.generate_keypair("alice", "oldpass").await.unwrap();

        // Change password
        manager
            .change_password("alice", "oldpass", "newpass")
            .await
            .unwrap();

        // Old password should fail
        let result = manager.unlock_keys("alice", "oldpass").await;
        assert!(matches!(result, Err(CryptoError::InvalidPassword)));

        // New password should work
        let result = manager.unlock_keys("alice", "newpass").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_storage_encryption() {
        let dir = tempdir().unwrap();
        let manager = enabled_manager(dir.path());

        manager.generate_keypair("alice", "pass").await.unwrap();
        manager.unlock_keys("alice", "pass").await.unwrap();

        let plaintext = b"Encrypted at rest!";
        let (encrypted, metadata) = manager
            .encrypt_for_storage("alice", plaintext)
            .await
            .unwrap();

        assert!(metadata.encrypted);
        assert_ne!(encrypted, plaintext);

        let decrypted = manager
            .decrypt_from_storage("alice", &encrypted, &metadata)
            .await
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_reload_inside_runtime() {
        let dir = tempdir().unwrap();
        {
            let manager = enabled_manager(dir.path());
            manager.generate_keypair("alice", "pass").await.unwrap();
        }
        // Constructing (and loading keys) inside a tokio runtime must not panic.
        let manager = enabled_manager(dir.path());
        assert!(manager.has_keys("alice").await);
        assert!(manager.unlock_keys("alice", "pass").await.is_ok());
    }

    #[tokio::test]
    async fn test_corrupt_keys_file_is_not_overwritten() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");
        std::fs::write(&path, "{ not json").unwrap();

        let manager = enabled_manager(dir.path());
        assert!(manager.generate_keypair("bob", "pass").await.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ not json");
    }

    #[tokio::test]
    async fn test_session_refcount() {
        let dir = tempdir().unwrap();
        let manager = enabled_manager(dir.path());
        manager.generate_keypair("carol", "pass").await.unwrap();
        let g1 = manager.unlock_keys("carol", "pass").await.unwrap();
        let g2 = manager.unlock_keys("carol", "pass").await.unwrap();
        assert_eq!(g1, g2);
        manager.lock_keys("carol", g1).await;
        assert_eq!(manager.stats().await.active_sessions, 1);
        manager.lock_keys("carol", g2).await;
        assert_eq!(manager.stats().await.active_sessions, 0);
    }

    #[tokio::test]
    async fn generation_mismatch_does_not_lock_new_session() {
        let dir = tempdir().unwrap();
        let manager = enabled_manager(dir.path());
        manager.generate_keypair("dan", "pass").await.unwrap();
        let old = manager.unlock_keys("dan", "pass").await.unwrap();

        // A regeneration drops the old session; a new login opens a new one.
        manager.regenerate_keypair("dan", "newpass").await.unwrap();
        let new = manager.unlock_keys("dan", "newpass").await.unwrap();
        assert_ne!(old, new);

        // The old login ending must not release the new session.
        manager.lock_keys("dan", old).await;
        assert_eq!(manager.stats().await.active_sessions, 1);
        manager.lock_keys("dan", new).await;
        assert_eq!(manager.stats().await.active_sessions, 0);

        // Same after a deletion and re-creation.
        let g = manager.unlock_keys("dan", "newpass").await.unwrap();
        manager.delete_keys("dan").await.unwrap();
        manager.generate_keypair("dan", "pass3").await.unwrap();
        let g2 = manager.unlock_keys("dan", "pass3").await.unwrap();
        assert_ne!(g, g2);
        manager.lock_keys("dan", g).await;
        assert_eq!(manager.stats().await.active_sessions, 1);
    }

    #[tokio::test]
    async fn generate_keypair_failed_save_does_not_insert() {
        let dir = tempdir().unwrap();
        // data_dir is a regular file, so writing keys.json must fail.
        let not_a_dir = dir.path().join("file");
        std::fs::write(&not_a_dir, "x").unwrap();
        let manager = enabled_manager(&not_a_dir);
        assert!(manager.load_error().is_none());

        assert!(manager.generate_keypair("alice", "pass").await.is_err());
        assert!(!manager.has_keys("alice").await);
        assert!(manager.get_public_key("alice").await.is_none());
    }

    #[tokio::test]
    async fn load_error_is_exposed_and_blocks_generation() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("keys.json"), "garbage").unwrap();
        let manager = enabled_manager(dir.path());
        assert!(manager.load_error().is_some());
        assert!(manager.generate_keypair("alice", "pass").await.is_err());
        assert!(!manager.has_keys("alice").await);
    }

    #[tokio::test]
    async fn generate_keypair_is_insert_if_absent() {
        let dir = tempdir().unwrap();
        let manager = enabled_manager(dir.path());
        let first = manager.generate_keypair("alice", "pass1").await.unwrap();
        let second = manager.generate_keypair("alice", "pass2").await.unwrap();
        assert_eq!(first.public_key, second.public_key);
        // The original wrapping is kept.
        assert!(manager.unlock_keys("alice", "pass1").await.is_ok());
        assert!(manager.unlock_keys("alice", "pass2").await.is_err());
    }

    #[tokio::test]
    async fn regenerate_keypair_replaces_keys_and_drops_session() {
        let dir = tempdir().unwrap();
        let manager = enabled_manager(dir.path());
        let old = manager.generate_keypair("alice", "pass").await.unwrap();
        manager.unlock_keys("alice", "pass").await.unwrap();
        assert_eq!(manager.stats().await.active_sessions, 1);

        let new = manager
            .regenerate_keypair("alice", "newpass")
            .await
            .unwrap();
        assert_ne!(old.public_key, new.public_key);
        assert_eq!(manager.stats().await.active_sessions, 0);
        assert!(manager.unlock_keys("alice", "newpass").await.is_ok());

        // Persisted.
        let reloaded = enabled_manager(dir.path());
        assert_eq!(
            reloaded.get_public_key("alice").await.unwrap(),
            new.public_key
        );
    }

    #[tokio::test]
    async fn delete_keys_drops_session() {
        let dir = tempdir().unwrap();
        let manager = enabled_manager(dir.path());
        manager.generate_keypair("alice", "pass").await.unwrap();
        manager.unlock_keys("alice", "pass").await.unwrap();
        manager.delete_keys("alice").await.unwrap();
        assert!(!manager.has_keys("alice").await);
        assert_eq!(manager.stats().await.active_sessions, 0);
    }

    #[tokio::test]
    async fn decrypt_and_unlock_work_when_disabled() {
        let dir = tempdir().unwrap();
        let encrypted = {
            let manager = enabled_manager(dir.path());
            manager.generate_keypair("bob", "pass").await.unwrap();
            manager.encrypt_email("bob", b"secret", None).await.unwrap()
        };

        let disabled = CryptoManager::with_enabled(dir.path().to_path_buf(), false);
        assert!(!disabled.is_enabled());
        disabled.unlock_keys("bob", "pass").await.unwrap();
        assert_eq!(
            disabled.decrypt_email("bob", &encrypted).await.unwrap(),
            b"secret"
        );
        // New mail is not encrypted while disabled.
        assert!(matches!(
            disabled.encrypt_email("bob", b"x", None).await,
            Err(CryptoError::Disabled)
        ));
    }
}
