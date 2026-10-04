//! Helpers shared by the line-based mail protocols (SMTP, IMAP, POP3).

use crate::storage::Storage;
use base64::Engine;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// How a protocol session ended: the connection is done, or the client
/// negotiated STARTTLS/STLS and the caller must upgrade the stream `S`.
#[allow(dead_code)] // reason: used from Task 5 (SMTP STARTTLS)
pub(crate) enum SessionEnd<S> {
    Closed,
    StartTls(S),
}

/// Whether plaintext authentication is acceptable on a connection.
#[allow(dead_code)] // reason: used from Task 5 (SMTP STARTTLS)
#[derive(Clone, Copy)]
pub(crate) struct TlsPolicy {
    /// A TLS configuration is loaded, so STARTTLS/implicit TLS can be offered.
    pub tls_available: bool,
    /// `KISS_MAIL_ALLOW_PLAINTEXT_AUTH`: allow auth before TLS anyway.
    pub allow_plaintext: bool,
}

#[allow(dead_code)] // reason: used from Task 5 (SMTP STARTTLS)
impl TlsPolicy {
    pub fn from_env(tls_available: bool) -> Self {
        Self {
            tls_available,
            allow_plaintext: crate::config::env_bool("KISS_MAIL_ALLOW_PLAINTEXT_AUTH", false),
        }
    }

    /// May credentials be exchanged on this connection?
    pub fn secure(&self, on_tls: bool) -> bool {
        on_tls || self.allow_plaintext || !self.tls_available
    }
}

/// How long a single response write may take before the session is dropped
/// (a client that stops reading must not pin a task forever).
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Write all of `bytes` and flush, failing with `ErrorKind::TimedOut` if that
/// takes longer than `d`.
pub(crate) async fn write_all_timeout<W: AsyncWrite + Unpin>(
    w: &mut W,
    bytes: &[u8],
    d: Duration,
) -> std::io::Result<()> {
    match tokio::time::timeout(d, async {
        w.write_all(bytes).await?;
        w.flush().await
    })
    .await
    {
        Ok(r) => r,
        Err(_) => Err(timed_out()),
    }
}

/// Like [`write_all_timeout`], but with an absolute deadline.
pub(crate) async fn write_all_until<W: AsyncWrite + Unpin>(
    w: &mut W,
    bytes: &[u8],
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    match tokio::time::timeout_at(deadline, async {
        w.write_all(bytes).await?;
        w.flush().await
    })
    .await
    {
        Ok(r) => r,
        Err(_) => Err(timed_out()),
    }
}

fn timed_out() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "write timed out")
}

/// Filter the result of `TcpListener::accept`: errors (EMFILE,
/// ECONNABORTED, ...) are transient and must never stop the listener, so they
/// are logged, followed by a short back-off, and turned into `None`.
pub(crate) async fn accepted<T>(proto: &str, res: std::io::Result<T>) -> Option<T> {
    match res {
        Ok(conn) => Some(conn),
        Err(e) => {
            tracing::warn!("{} accept failed: {}", proto, e);
            tokio::time::sleep(Duration::from_millis(100)).await;
            None
        }
    }
}

/// Unlocked session keys held by one IMAP/POP3 session.
///
/// The lease is filled at login with the key generation returned by
/// `Storage::login` and released with `Storage::logout` when the session
/// ends: normally via [`KeyLease::release`], or from `Drop` on panic /
/// cancellation (the logout is then spawned on the current runtime).
pub(crate) struct KeyLease {
    storage: Arc<Storage>,
    held: Option<(String, u64)>,
    proto: &'static str,
}

impl std::fmt::Debug for KeyLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyLease")
            .field("held", &self.held)
            .field("proto", &self.proto)
            .finish()
    }
}

impl KeyLease {
    pub(crate) fn new(storage: Arc<Storage>, proto: &'static str) -> Self {
        Self {
            storage,
            held: None,
            proto,
        }
    }

    /// Record the keys unlocked by a login. A lease already held is released
    /// first (in the background).
    pub(crate) fn hold(&mut self, user: String, generation: u64) {
        if let Some(old) = self.held.replace((user, generation)) {
            self.spawn_logout(old);
        }
    }

    /// Lock the keys now (no-op when nothing is held).
    pub(crate) async fn release(&mut self) {
        if let Some((user, generation)) = self.held.take() {
            self.storage.logout(&user, Some(generation)).await;
        }
    }

    fn spawn_logout(&self, (user, generation): (String, u64)) {
        let storage = Arc::clone(&self.storage);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move { storage.logout(&user, Some(generation)).await });
            }
            Err(_) => tracing::error!(
                "No runtime to release {} session keys for {}",
                self.proto,
                user
            ),
        }
    }
}

impl Drop for KeyLease {
    fn drop(&mut self) {
        let Some(held) = self.held.take() else {
            return;
        };
        if std::thread::panicking() {
            tracing::error!(
                "{} session for {} panicked; locking keys",
                self.proto,
                held.0
            );
        }
        self.spawn_logout(held);
    }
}

/// Read one line (terminated by `\n`) of at most `max` bytes.
///
/// Returns `Ok(None)` at EOF, `Ok(Some(Err(())))` if the line was longer than
/// `max` (the rest of the line is consumed and discarded), and the line
/// (lossily decoded, line terminator included) otherwise.
pub(crate) async fn read_line_limited<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> std::io::Result<Option<Result<String, ()>>> {
    let mut buf = Vec::new();
    let n = (&mut *reader)
        .take(max as u64)
        .read_until(b'\n', &mut buf)
        .await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') {
        if n < max {
            // EOF in the middle of a line: treat what we have as the line.
            return Ok(Some(Ok(String::from_utf8_lossy(&buf).into_owned())));
        }
        // Too long: discard the rest of the line.
        loop {
            buf.clear();
            let n = (&mut *reader)
                .take(max as u64)
                .read_until(b'\n', &mut buf)
                .await?;
            if n == 0 || buf.last() == Some(&b'\n') {
                break;
            }
        }
        return Ok(Some(Err(())));
    }
    Ok(Some(Ok(String::from_utf8_lossy(&buf).into_owned())))
}

/// Decode a SASL PLAIN response (`base64(authzid \0 authcid \0 password)`).
/// Returns (username, password). The authorization identity, if present,
/// must be empty or equal to the authentication identity.
pub(crate) fn decode_auth_plain(credentials: &str) -> Option<(String, String)> {
    let credentials = credentials.trim();
    if credentials == "=" {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(credentials)
        .ok()?;
    let parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
    if parts.len() != 3 {
        return None;
    }
    let authzid = std::str::from_utf8(parts[0]).ok()?;
    let username = std::str::from_utf8(parts[1]).ok()?;
    let password = std::str::from_utf8(parts[2]).ok()?;
    if username.is_empty() || (!authzid.is_empty() && authzid != username) {
        return None;
    }
    Some((username.to_string(), password.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[test]
    fn auth_plain_decoding() {
        let creds = base64::engine::general_purpose::STANDARD.encode(b"\0alice\0secret pw");
        assert_eq!(
            decode_auth_plain(&creds),
            Some(("alice".to_string(), "secret pw".to_string()))
        );
        let with_authz = base64::engine::general_purpose::STANDARD.encode(b"alice\0alice\0pw");
        assert!(decode_auth_plain(&with_authz).is_some());
        let other_authz = base64::engine::general_purpose::STANDARD.encode(b"bob\0alice\0pw");
        assert!(decode_auth_plain(&other_authz).is_none());
        assert!(decode_auth_plain("not base64!").is_none());
        let missing = base64::engine::general_purpose::STANDARD.encode(b"alice");
        assert!(decode_auth_plain(&missing).is_none());
    }

    #[tokio::test]
    async fn long_command_line_is_rejected() {
        let input = format!("{}\r\nNOOP\r\n", "A".repeat(100));
        let mut reader = BufReader::new(input.as_bytes());
        assert_eq!(
            read_line_limited(&mut reader, 10).await.unwrap(),
            Some(Err(()))
        );
        assert_eq!(
            read_line_limited(&mut reader, 10).await.unwrap(),
            Some(Ok("NOOP\r\n".to_string()))
        );
        assert_eq!(read_line_limited(&mut reader, 10).await.unwrap(), None);
    }

    #[tokio::test]
    async fn accept_error_does_not_stop_server() {
        // The listener loops call `accepted`; an error yields `None` (the loop
        // continues) after a short back-off instead of returning.
        let err = std::io::Error::other("EMFILE");
        let start = tokio::time::Instant::now();
        assert!(accepted::<()>("IMAP", Err(err)).await.is_none());
        assert!(start.elapsed() >= Duration::from_millis(50));
        assert_eq!(accepted("IMAP", Ok(7)).await, Some(7));
    }

    #[tokio::test]
    async fn write_all_timeout_times_out_on_stalled_reader() {
        let (mut w, _r) = tokio::io::duplex(8);
        write_all_timeout(&mut w, b"1234", Duration::from_millis(50))
            .await
            .unwrap();
        let err = write_all_timeout(&mut w, &[0u8; 64], Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn tls_policy_secure_matrix() {
        let p = TlsPolicy {
            tls_available: true,
            allow_plaintext: false,
        };
        assert!(!p.secure(false));
        assert!(p.secure(true));
        let p = TlsPolicy {
            tls_available: true,
            allow_plaintext: true,
        };
        assert!(p.secure(false));
        let p = TlsPolicy {
            tls_available: false,
            allow_plaintext: false,
        };
        assert!(p.secure(false));
    }

    async fn first_message_content(storage: &Storage) -> String {
        let meta = storage.message_meta("bob").await.unwrap();
        let ids = vec![meta[0].id.clone()];
        let emails = storage.get_emails_by_ids("bob", &ids).await;
        storage.email_content("bob", &emails[&ids[0]]).await
    }

    #[tokio::test]
    async fn key_lease_releases_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        let outcome = storage
            .login("bob", "password123", "127.0.0.1", "TEST", false)
            .await
            .unwrap();
        let generation = outcome.key_generation.expect("keys unlocked");
        assert!(first_message_content(&storage).await.contains("body 1"));

        let mut lease = KeyLease::new(Arc::clone(&storage), "TEST");
        lease.hold(outcome.username, generation);
        drop(lease);
        // Drop spawns the logout; give it a chance to run.
        for _ in 0..100 {
            if !first_message_content(&storage).await.contains("body 1") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!first_message_content(&storage).await.contains("body 1"));

        // `release` locks immediately; an empty lease is a no-op.
        let outcome = storage
            .login("bob", "password123", "127.0.0.1", "TEST", false)
            .await
            .unwrap();
        let mut lease = KeyLease::new(Arc::clone(&storage), "TEST");
        lease.hold(outcome.username, outcome.key_generation.unwrap());
        lease.release().await;
        assert!(!first_message_content(&storage).await.contains("body 1"));
        lease.release().await;
    }
}
