//! POP3 Server implementation.
//!
//! Implements RFC 1939 (Post Office Protocol - Version 3) with basic commands.
//! The maildrop is snapshotted at login; DELE only marks messages for deletion
//! and they are removed when the session ends with QUIT (UPDATE state). An
//! abnormal disconnect deletes nothing.

use crate::proto::{
    KeyLease, SessionEnd, TlsPolicy, WRITE_TIMEOUT, accepted, read_line_limited, write_all_timeout,
};
use crate::storage::{AuthError, Storage};
use crate::tls::Tls;
use crate::users::canonical_username;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const POP3_OK: &str = "+OK";
const POP3_ERR: &str = "-ERR";
const MAX_LINE: usize = 4096;
/// Inactivity timeout (RFC 1939 section 3: at least 10 minutes).
const READ_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Maximum concurrent connections per listener.
const MAX_CONNECTIONS: usize = 500;

#[derive(Debug, Clone, PartialEq)]
enum Pop3State {
    Authorization,
    Transaction,
}

/// A message in the maildrop snapshot (message number = index + 1).
#[derive(Debug, Clone)]
struct DropMsg {
    id: String,
    /// Stored size; used only if the message vanished before it was sized.
    stored_size: usize,
    /// Octets as sent by RETR (CRLF-normalised content, before
    /// byte-stuffing). Computed lazily from the content actually sent, so an
    /// undecryptable message reports its placeholder's size.
    size: Option<usize>,
}

impl DropMsg {
    fn size(&self) -> usize {
        self.size.unwrap_or(self.stored_size)
    }
}

#[derive(Debug)]
struct Pop3Session {
    state: Pop3State,
    username: Option<String>,
    /// Encryption keys unlocked by PASS; released when the session ends.
    lease: KeyLease,
    messages: Vec<DropMsg>,
    /// Indices (0-based) marked for deletion.
    deleted: HashSet<usize>,
    peer_ip: String,
    /// The stream is TLS-protected.
    tls: bool,
    policy: TlsPolicy,
    /// STLS was accepted; the session loop must hand the stream back.
    starttls: bool,
}

impl Pop3Session {
    fn new(peer_ip: String, storage: Arc<Storage>) -> Self {
        Self {
            state: Pop3State::Authorization,
            username: None,
            lease: KeyLease::new(storage, "POP3"),
            messages: Vec::new(),
            deleted: HashSet::new(),
            peer_ip,
            tls: false,
            policy: TlsPolicy {
                tls_available: false,
                allow_plaintext: false,
            },
            starttls: false,
        }
    }

    fn user(&self) -> &str {
        self.username.as_deref().unwrap_or("")
    }

    /// Resolve a message-number argument to a non-deleted snapshot index.
    fn message(&self, arg: Option<&str>) -> Result<usize, String> {
        let arg = arg.ok_or_else(|| format!("{} Missing message number\r\n", POP3_ERR))?;
        let num: usize = arg
            .parse()
            .map_err(|_| format!("{} Invalid message number\r\n", POP3_ERR))?;
        if num == 0 || num > self.messages.len() {
            return Err(format!("{} No such message\r\n", POP3_ERR));
        }
        if self.deleted.contains(&(num - 1)) {
            return Err(format!("{} Message {} already deleted\r\n", POP3_ERR, num));
        }
        Ok(num - 1)
    }

    /// Indices (0-based) of messages not marked for deletion.
    fn live_indices(&self) -> Vec<usize> {
        (0..self.messages.len())
            .filter(|i| !self.deleted.contains(i))
            .collect()
    }

    /// End the TRANSACTION state, returning the user if a login was open.
    /// The key lease is left in place for [`Pop3Session::finish`].
    fn take_login(&mut self) -> Option<String> {
        if self.state != Pop3State::Transaction {
            return None;
        }
        self.state = Pop3State::Authorization;
        self.username.take()
    }

    /// End the session: close the login and lock its keys.
    async fn finish(&mut self) {
        self.take_login();
        self.lease.release().await;
    }
}

/// Reply to USER/PASS while plaintext credentials are refused (RFC 3206
/// `[AUTH]`). Sent at USER so the client never gets as far as sending PASS.
const PLAINTEXT_AUTH_REPLY: &str =
    "-ERR [AUTH] Plaintext authentication disabled; use STLS or port 995\r\n";

/// How a session starts (see `serve_pop3_with`).
#[derive(Debug, Clone, Copy)]
struct Pop3Opts {
    /// The stream is TLS-protected.
    tls: bool,
    /// Send the greeting (not after STLS: RFC 2595 restarts the session).
    greet: bool,
    policy: TlsPolicy,
}

/// How the command loop ended.
enum LoopEnd {
    Closed,
    /// STLS was accepted and its +OK sent; the stream must be upgraded.
    StartTls,
}

pub struct Pop3Server {
    storage: Arc<Storage>,
    /// TLS for STLS and the implicit-TLS listener (`None`: TLS off).
    tls: Option<Arc<Tls>>,
    policy: TlsPolicy,
}

impl Pop3Server {
    pub fn new(storage: Arc<Storage>, tls: Option<Arc<Tls>>, policy: TlsPolicy) -> Self {
        // The STLS offer and the USER refusal must never disagree.
        debug_assert_eq!(
            tls.is_some(),
            policy.tls_available,
            "TLS presence and TlsPolicy disagree"
        );
        Self {
            storage,
            tls,
            policy,
        }
    }

    /// Serve the plain listener on `plain_addr` and, when `tls_addr` is set,
    /// the implicit-TLS (POP3S) listener. Both share one connection limit.
    pub async fn run(
        &self,
        plain_addr: &str,
        tls_addr: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let plain = TcpListener::bind(plain_addr)
            .await
            .map_err(|e| format!("POP3: cannot bind {}: {}", plain_addr, e))?;
        tracing::info!("POP3 server listening on {}", plain_addr);
        let implicit = match tls_addr {
            None => None,
            Some(addr) => {
                if self.tls.is_none() {
                    return Err("POP3S: TLS is not configured".into());
                }
                let listener = TcpListener::bind(addr)
                    .await
                    .map_err(|e| format!("POP3S: cannot bind {}: {}", addr, e))?;
                tracing::info!("POP3S (implicit TLS) server listening on {}", addr);
                Some(listener)
            }
        };
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        let plain_loop = self.accept_loop(plain, "POP3", false, Arc::clone(&connections));
        let implicit_loop = async {
            match implicit {
                Some(listener) => {
                    self.accept_loop(listener, "POP3S", true, Arc::clone(&connections))
                        .await
                }
                None => std::future::pending().await,
            }
        };
        tokio::try_join!(plain_loop, implicit_loop)?;
        Ok(())
    }

    /// Accept connections on `listener` until the connection semaphore closes.
    async fn accept_loop(
        &self,
        listener: TcpListener,
        name: &'static str,
        implicit: bool,
        connections: Arc<Semaphore>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let permit = Arc::clone(&connections)
                .acquire_owned()
                .await
                .map_err(|e| format!("{}: {}", name, e))?;
            let Some((socket, peer_addr)) = accepted(name, listener.accept().await).await else {
                continue;
            };
            tracing::info!("{} connection from {}", name, peer_addr);
            tokio::spawn(handle_connection(
                socket,
                peer_addr,
                Arc::clone(&self.storage),
                self.tls.clone(),
                self.policy,
                implicit,
                permit,
            ));
        }
    }
}

/// Serve one accepted connection while holding its connection-slot
/// `permit`. The session runs in its own task so a panic is logged here (and
/// the slot released) instead of being lost.
async fn handle_connection<S>(
    stream: S,
    peer: SocketAddr,
    storage: Arc<Storage>,
    tls: Option<Arc<Tls>>,
    policy: TlsPolicy,
    implicit: bool,
    permit: OwnedSemaphorePermit,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _permit = permit;
    let inner = tokio::spawn(serve_connection(
        stream, peer, storage, tls, policy, implicit,
    ));
    match inner.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("POP3 connection error ({}): {}", peer, e),
        Err(e) if e.is_panic() => {
            tracing::error!("POP3 connection task for {} panicked: {}", peer, e)
        }
        Err(e) => tracing::error!("POP3 connection task for {} failed: {}", peer, e),
    }
}

/// The session restart sequence (spec section 3.2). On the implicit-TLS
/// listener the handshake comes first; on the plain listener an accepted STLS
/// restarts the session over TLS with fresh state and no greeting. A failed
/// or timed-out handshake just closes the connection.
async fn serve_connection<S>(
    stream: S,
    peer: SocketAddr,
    storage: Arc<Storage>,
    tls: Option<Arc<Tls>>,
    policy: TlsPolicy,
    implicit: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if implicit {
        let Some(tls) = tls else {
            return Err("POP3S connection without a TLS configuration".into());
        };
        let stream = match tls.accept(stream).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::debug!("POP3S handshake with {} failed: {}", peer, e);
                return Ok(());
            }
        };
        let opts = Pop3Opts {
            tls: true,
            greet: true,
            policy,
        };
        serve_pop3_with(stream, peer, storage, READ_TIMEOUT, WRITE_TIMEOUT, opts).await?;
        return Ok(());
    }

    let opts = Pop3Opts {
        tls: false,
        greet: true,
        policy,
    };
    let end = serve_pop3_with(
        stream,
        peer,
        Arc::clone(&storage),
        READ_TIMEOUT,
        WRITE_TIMEOUT,
        opts,
    )
    .await?;
    match end {
        SessionEnd::Closed => Ok(()),
        SessionEnd::StartTls(raw) => {
            let Some(tls) = tls else {
                return Err("STLS accepted without a TLS configuration".into());
            };
            let stream = match tls.accept(raw).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::debug!("POP3 STLS handshake with {} failed: {}", peer, e);
                    return Ok(());
                }
            };
            let opts = Pop3Opts {
                tls: true,
                greet: false,
                policy,
            };
            serve_pop3_with(stream, peer, storage, READ_TIMEOUT, WRITE_TIMEOUT, opts).await?;
            Ok(())
        }
    }
}

/// Run one POP3 session over `stream`.
///
/// Returns `SessionEnd::StartTls` with the raw stream once STLS has been
/// accepted (the caller performs the handshake and starts a fresh session).
/// Client bytes already buffered at that point are discarded with the
/// `BufReader`, so commands pipelined after STLS never run under TLS.
async fn serve_pop3_with<S>(
    stream: S,
    peer: SocketAddr,
    storage: Arc<Storage>,
    read_timeout: Duration,
    write_timeout: Duration,
    opts: Pop3Opts,
) -> Result<SessionEnd<S>, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    // The session owns the key lease, so the keys are locked however this
    // future ends (normally below, or by Drop on panic / cancellation).
    let mut session = Pop3Session::new(peer.ip().to_string(), Arc::clone(&storage));
    session.tls = opts.tls;
    session.policy = opts.policy;
    let session = &mut session;

    let result = async {
        if opts.greet {
            let greeting = format!("{} kiss-mail POP3 server ready\r\n", POP3_OK);
            write_all_timeout(&mut writer, greeting.as_bytes(), write_timeout).await?;
        }

        loop {
            let read =
                tokio::time::timeout(read_timeout, read_line_limited(&mut reader, MAX_LINE)).await;
            let Ok(read) = read else {
                let msg = format!("{} timeout\r\n", POP3_ERR);
                write_all_timeout(&mut writer, msg.as_bytes(), write_timeout).await?;
                break;
            };
            let line = match read? {
                None => break,
                Some(Err(())) => {
                    let msg = format!("{} Line too long\r\n", POP3_ERR);
                    write_all_timeout(&mut writer, msg.as_bytes(), write_timeout).await?;
                    continue;
                }
                Some(Ok(line)) => line,
            };
            let line = line.trim_end_matches(['\r', '\n']);
            let cmd = command_name(line);
            if cmd == "PASS" {
                tracing::debug!("POP3 <- PASS ****");
            } else {
                tracing::debug!("POP3 <- {}", line);
            }

            let response = process_pop3_command(line, session, &storage).await;

            write_all_timeout(&mut writer, response.as_bytes(), write_timeout).await?;

            if session.starttls {
                return Ok::<LoopEnd, Box<dyn std::error::Error + Send + Sync>>(LoopEnd::StartTls);
            }
            if cmd == "QUIT" {
                break;
            }
        }
        Ok(LoopEnd::Closed)
    }
    .await;

    // Abnormal or normal end: drop decrypted keys. Pending DELEs are only
    // applied by QUIT. (A no-op after STLS: it is only accepted before login.)
    session.finish().await;
    match result? {
        LoopEnd::StartTls => Ok(SessionEnd::StartTls(reader.into_inner().unsplit(writer))),
        LoopEnd::Closed => {
            if opts.tls {
                // Send close_notify (bounded, errors ignored: the session is over).
                let _ = tokio::time::timeout(write_timeout, writer.shutdown()).await;
            }
            Ok(SessionEnd::Closed)
        }
    }
}

fn command_name(line: &str) -> String {
    line.split(' ').next().unwrap_or("").to_uppercase()
}

/// Encode a message for transmission: CRLF line endings and byte-stuffing.
/// Returns (octets of the CRLF-normalised message before byte-stuffing, data
/// to send without the terminating ".").
fn encode_message<'a>(lines: impl Iterator<Item = &'a str>) -> (usize, String) {
    let mut octets = 0;
    let mut out = String::new();
    for line in lines {
        octets += line.len() + 2;
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    (octets, out)
}

/// Octets of `content` as RETR sends it (CRLF line endings, before
/// byte-stuffing).
fn pop3_octets(content: &str) -> usize {
    content.lines().map(|l| l.len() + 2).sum()
}

/// Compute (once) the sent size of the given snapshot entries.
async fn ensure_sizes(session: &mut Pop3Session, storage: &Storage, indices: &[usize]) {
    let missing: Vec<usize> = indices
        .iter()
        .copied()
        .filter(|&i| session.messages[i].size.is_none())
        .collect();
    if missing.is_empty() {
        return;
    }
    let user = session.user().to_string();
    let ids: Vec<String> = missing
        .iter()
        .map(|&i| session.messages[i].id.clone())
        .collect();
    let emails = storage.get_emails_by_ids(&user, &ids).await;
    for i in missing {
        let msg = &mut session.messages[i];
        msg.size = Some(match emails.get(&msg.id) {
            Some(email) => pop3_octets(&storage.email_content(&user, email).await),
            None => msg.stored_size,
        });
    }
}

/// Lines for TOP: all header lines, the blank separator, then `n` body lines.
fn top_lines(content: &str, n: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut lines = content.lines();
    for line in lines.by_ref() {
        out.push(line);
        if line.is_empty() {
            break;
        }
    }
    out.extend(lines.take(n));
    out
}

async fn process_pop3_command(line: &str, session: &mut Pop3Session, storage: &Storage) -> String {
    let parts: Vec<&str> = line.split(' ').filter(|p| !p.is_empty()).collect();
    let cmd = command_name(line);

    let transaction_only = matches!(
        cmd.as_str(),
        "STAT" | "LIST" | "RETR" | "DELE" | "RSET" | "UIDL" | "TOP"
    );
    if transaction_only && session.state != Pop3State::Transaction {
        return format!("{} Not authenticated\r\n", POP3_ERR);
    }

    match cmd.as_str() {
        "USER" => {
            if session.state != Pop3State::Authorization {
                return format!("{} Already authenticated\r\n", POP3_ERR);
            }
            if !session.policy.secure(session.tls) {
                return PLAINTEXT_AUTH_REPLY.to_string();
            }
            if let Some(username) = parts.get(1) {
                session.username = Some(canonical_username(username));
                format!("{} User accepted\r\n", POP3_OK)
            } else {
                format!("{} Missing username\r\n", POP3_ERR)
            }
        }
        "PASS" => {
            if session.state != Pop3State::Authorization {
                return format!("{} Already authenticated\r\n", POP3_ERR);
            }
            // Defence in depth: USER is already refused, so a client that
            // got here skipped it. No login attempt is made.
            if !session.policy.secure(session.tls) {
                return PLAINTEXT_AUTH_REPLY.to_string();
            }
            // The password is the whole remainder of the line (may contain spaces).
            let password = line.get(5..).unwrap_or("");
            let Some(username) = session.username.clone() else {
                return format!("{} USER first\r\n", POP3_ERR);
            };
            if password.is_empty() {
                return format!("{} Missing password\r\n", POP3_ERR);
            }
            match storage
                .login(&username, password, &session.peer_ip, "POP3", session.tls)
                .await
            {
                Ok(outcome) => {
                    let messages = storage
                        .message_meta(&outcome.username)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|m| !m.flags.deleted)
                        .map(|m| DropMsg {
                            id: m.id,
                            stored_size: m.size,
                            size: None,
                        })
                        .collect();
                    if let Some(generation) = outcome.key_generation {
                        session.lease.hold(outcome.username.clone(), generation);
                    }
                    session.username = Some(outcome.username);
                    session.messages = messages;
                    session.deleted.clear();
                    session.state = Pop3State::Transaction;
                    format!("{} Logged in\r\n", POP3_OK)
                }
                // RFC 3206: the credentials are fine, but login is refused.
                Err(e) if e.is_password_change_required() => format!(
                    "{} [AUTH] {}\r\n",
                    POP3_ERR,
                    crate::config::password_change_message()
                ),
                // RFC 3206: the server cannot check the credentials right now.
                Err(AuthError::Temporary(e)) => {
                    tracing::warn!(
                        "POP3 login for {} from {} failed temporarily: {}",
                        username,
                        session.peer_ip,
                        e
                    );
                    format!(
                        "{} [SYS/TEMP] Authentication temporarily unavailable; try again later\r\n",
                        POP3_ERR
                    )
                }
                Err(e) => {
                    tracing::info!(
                        "POP3 login failed for {} from {}: {}",
                        username,
                        session.peer_ip,
                        e
                    );
                    format!("{} Authentication failed\r\n", POP3_ERR)
                }
            }
        }
        "STAT" => {
            let live = session.live_indices();
            ensure_sizes(session, storage, &live).await;
            let size: usize = live.iter().map(|&i| session.messages[i].size()).sum();
            format!("{} {} {}\r\n", POP3_OK, live.len(), size)
        }
        "LIST" => {
            if parts.get(1).is_some() {
                match session.message(parts.get(1).copied()) {
                    Ok(i) => {
                        ensure_sizes(session, storage, &[i]).await;
                        format!("{} {} {}\r\n", POP3_OK, i + 1, session.messages[i].size())
                    }
                    Err(e) => e,
                }
            } else {
                let live = session.live_indices();
                ensure_sizes(session, storage, &live).await;
                let mut response = format!("{} {} messages\r\n", POP3_OK, live.len());
                for i in live {
                    response.push_str(&format!("{} {}\r\n", i + 1, session.messages[i].size()));
                }
                response.push_str(".\r\n");
                response
            }
        }
        "UIDL" => {
            if parts.get(1).is_some() {
                match session.message(parts.get(1).copied()) {
                    Ok(i) => format!("{} {} {}\r\n", POP3_OK, i + 1, session.messages[i].id),
                    Err(e) => e,
                }
            } else {
                let mut response = format!("{}\r\n", POP3_OK);
                for i in session.live_indices() {
                    response.push_str(&format!("{} {}\r\n", i + 1, session.messages[i].id));
                }
                response.push_str(".\r\n");
                response
            }
        }
        "RETR" | "TOP" => {
            let id = match session.message(parts.get(1).copied()) {
                Ok(i) => session.messages[i].id.clone(),
                Err(e) => return e,
            };
            let top_count = if cmd == "TOP" {
                match parts.get(2).map(|n| n.parse::<usize>()) {
                    Some(Ok(n)) => Some(n),
                    Some(Err(_)) => return format!("{} Invalid arguments\r\n", POP3_ERR),
                    None => return format!("{} Missing arguments\r\n", POP3_ERR),
                }
            } else {
                None
            };

            let user = session.user().to_string();
            let emails = storage
                .get_emails_by_ids(&user, std::slice::from_ref(&id))
                .await;
            let Some(email) = emails.get(&id) else {
                return format!("{} Message no longer available\r\n", POP3_ERR);
            };
            let content = storage.email_content(&user, email).await;

            let (octets, data) = match top_count {
                Some(n) => encode_message(top_lines(&content, n).into_iter()),
                None => encode_message(content.lines()),
            };
            if cmd == "TOP" {
                format!("{}\r\n{}.\r\n", POP3_OK, data)
            } else {
                format!("{} {} octets\r\n{}.\r\n", POP3_OK, octets, data)
            }
        }
        "DELE" => match session.message(parts.get(1).copied()) {
            Ok(i) => {
                session.deleted.insert(i);
                format!("{} Message {} deleted\r\n", POP3_OK, i + 1)
            }
            Err(e) => e,
        },
        "RSET" => {
            session.deleted.clear();
            format!("{} Maildrop reset\r\n", POP3_OK)
        }
        "NOOP" => format!("{}\r\n", POP3_OK),
        "QUIT" => {
            if session.state == Pop3State::Transaction && !session.deleted.is_empty() {
                // UPDATE state: commit deletions by message id.
                let ids: Vec<String> = session
                    .deleted
                    .iter()
                    .map(|&i| session.messages[i].id.clone())
                    .collect();
                let removed = storage.expunge_by_ids(session.user(), &ids).await;
                if let Err(e) = storage.save().await {
                    tracing::error!("Failed to save storage after POP3 QUIT: {}", e);
                    return format!("{} Some deleted messages not removed\r\n", POP3_ERR);
                }
                session.deleted.clear();
                return format!("{} Bye ({} messages deleted)\r\n", POP3_OK, removed.len());
            }
            format!("{} Bye\r\n", POP3_OK)
        }
        "STLS" => {
            let refusal = if parts.len() > 1 {
                Some("STLS takes no arguments")
            } else if session.state != Pop3State::Authorization {
                Some("STLS only allowed in AUTHORIZATION state")
            } else if session.tls {
                Some("TLS already active")
            } else if !session.policy.tls_available {
                Some("TLS not available")
            } else {
                None
            };
            match refusal {
                Some(reason) => format!("{} {}\r\n", POP3_ERR, reason),
                None => {
                    session.starttls = true;
                    format!("{} Begin TLS negotiation\r\n", POP3_OK)
                }
            }
        }
        "CAPA" => {
            let mut response = format!("{} Capability list follows\r\n", POP3_OK);
            if session.policy.secure(session.tls) {
                response.push_str("USER\r\n");
            }
            response.push_str("UIDL\r\n");
            response.push_str("TOP\r\n");
            if session.policy.tls_available
                && !session.tls
                && session.state == Pop3State::Authorization
            {
                response.push_str("STLS\r\n");
            }
            // RFC 2449 / RFC 3206 extended response codes ([AUTH], [SYS/TEMP]).
            response.push_str("RESP-CODES\r\n");
            response.push_str("AUTH-RESP-CODE\r\n");
            response.push_str(".\r\n");
            response
        }
        _ => format!("{} Unknown command\r\n", POP3_ERR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Email;

    async fn setup(dir: &std::path::Path) -> Arc<Storage> {
        let users = Arc::new(crate::users::UserManager::new(
            "example.com".to_string(),
            dir.to_path_buf(),
        ));
        users
            .create_user("bob", "pass word 123", None)
            .await
            .unwrap();
        let storage = Arc::new(Storage::new(dir.to_path_buf(), users));
        for i in 1..=3 {
            let raw = format!("Subject: m{}\r\n\r\nbody {}\r\n.dot\r\n", i, i);
            storage
                .deliver_email("bob", Email::new("a@b".into(), vec![], raw))
                .await
                .unwrap();
        }
        storage
    }

    async fn cmd(line: &str, session: &mut Pop3Session, storage: &Storage) -> String {
        process_pop3_command(line, session, storage).await
    }

    #[tokio::test]
    async fn pass_with_password_change_required_is_auth_error() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        storage
            .user_manager()
            .update_user("bob", |u| u.password_change_required = true)
            .await
            .unwrap();
        let mut s = Pop3Session::new("127.0.0.1".into(), Arc::clone(&storage));
        cmd("USER bob", &mut s, &storage).await;
        let resp = cmd("PASS pass word 123", &mut s, &storage).await;
        assert!(
            resp.starts_with("-ERR [AUTH] Password change required; change it "),
            "{}",
            resp
        );
        assert!(resp.ends_with("/account/password\r\n"), "{}", resp);
        assert_eq!(s.state, Pop3State::Authorization);
        let resp = cmd("PASS wrong", &mut s, &storage).await;
        assert_eq!(resp, format!("{} Authentication failed\r\n", POP3_ERR));
    }

    #[tokio::test]
    async fn dele_keeps_numbering_and_applies_on_quit() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let mut s = Pop3Session::new("127.0.0.1".into(), Arc::clone(&storage));

        assert!(cmd("USER Bob", &mut s, &storage).await.starts_with("+OK"));
        // Password with spaces is kept whole.
        assert!(
            cmd("PASS pass word 123", &mut s, &storage)
                .await
                .starts_with("+OK")
        );

        assert!(cmd("DELE 1", &mut s, &storage).await.starts_with("+OK"));
        assert!(cmd("RETR 1", &mut s, &storage).await.starts_with("-ERR"));
        assert!(cmd("DELE 1", &mut s, &storage).await.starts_with("-ERR"));

        // Message 2 is still message 2.
        let retr = cmd("RETR 2", &mut s, &storage).await;
        assert!(retr.contains("body 2"));
        let raw = "Subject: m2\r\n\r\nbody 2\r\n.dot\r\n";
        assert!(retr.starts_with(&format!("+OK {} octets\r\n", raw.len())));
        assert!(retr.contains("\r\n..dot\r\n"));
        assert!(retr.ends_with("\r\n.\r\n"));

        let stat = cmd("STAT", &mut s, &storage).await;
        assert!(stat.starts_with("+OK 2 "));

        // Nothing is removed before QUIT.
        assert_eq!(storage.message_meta("bob").await.unwrap().len(), 3);
        assert!(cmd("QUIT", &mut s, &storage).await.starts_with("+OK"));
        let left = storage.message_meta("bob").await.unwrap();
        assert_eq!(left.len(), 2);
    }

    #[tokio::test]
    async fn rset_and_disconnect_delete_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let mut s = Pop3Session::new("127.0.0.1".into(), Arc::clone(&storage));
        cmd("USER bob", &mut s, &storage).await;
        cmd("PASS pass word 123", &mut s, &storage).await;
        cmd("DELE 2", &mut s, &storage).await;
        assert!(cmd("RSET", &mut s, &storage).await.starts_with("+OK"));
        assert!(cmd("RETR 2", &mut s, &storage).await.starts_with("+OK"));
        cmd("DELE 3", &mut s, &storage).await;
        drop(s); // abnormal disconnect: no QUIT
        assert_eq!(storage.message_meta("bob").await.unwrap().len(), 3);
    }

    #[test]
    fn top_lines_include_headers_and_n_body_lines() {
        let content = "A: 1\r\nB: 2\r\n\r\nl1\r\nl2\r\nl3\r\n";
        assert_eq!(top_lines(content, 2), vec!["A: 1", "B: 2", "", "l1", "l2"]);
    }

    #[tokio::test]
    async fn dele_quit_removes_exactly_the_marked_message() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let before: Vec<String> = storage
            .message_meta("bob")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.id)
            .collect();
        let mut s = Pop3Session::new("127.0.0.1".into(), Arc::clone(&storage));
        cmd("USER bob", &mut s, &storage).await;
        cmd("PASS pass word 123", &mut s, &storage).await;
        assert!(cmd("DELE 1", &mut s, &storage).await.starts_with("+OK"));
        let quit = cmd("QUIT", &mut s, &storage).await;
        assert_eq!(quit, "+OK Bye (1 messages deleted)\r\n");
        let after: Vec<String> = storage
            .message_meta("bob")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(after, before[1..].to_vec());
    }

    #[tokio::test]
    async fn quit_save_failure_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let mut s = Pop3Session::new("127.0.0.1".into(), Arc::clone(&storage));
        cmd("USER bob", &mut s, &storage).await;
        cmd("PASS pass word 123", &mut s, &storage).await;
        cmd("DELE 2", &mut s, &storage).await;
        // Make saving fail: the target path becomes a non-empty directory.
        let target = dir.path().join("mailboxes.json");
        let _ = std::fs::remove_file(&target);
        std::fs::create_dir_all(target.join("blocker")).unwrap();
        let quit = cmd("QUIT", &mut s, &storage).await;
        assert!(quit.starts_with("-ERR"), "{}", quit);
    }

    #[tokio::test]
    async fn user_is_canonicalised_and_sizes_match_retr() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let mut s = Pop3Session::new("127.0.0.1".into(), Arc::clone(&storage));
        cmd("USER  BOB ", &mut s, &storage).await;
        assert_eq!(s.username.as_deref(), Some("bob"));
        cmd("PASS pass word 123", &mut s, &storage).await;
        let list = cmd("LIST 1", &mut s, &storage).await;
        let retr = cmd("RETR 1", &mut s, &storage).await;
        let size = list.split(' ').nth(2).unwrap().trim();
        assert!(
            retr.starts_with(&format!("+OK {} octets", size)),
            "{} / {}",
            list,
            retr
        );
    }

    // ------------------------------------------------------------------
    // Stream-level tests (tokio::io::duplex)
    // ------------------------------------------------------------------

    use tokio::io::{
        AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf,
    };

    struct Client<S = DuplexStream> {
        r: BufReader<ReadHalf<S>>,
        w: WriteHalf<S>,
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
        fn new(stream: S) -> Self {
            let (r, w) = tokio::io::split(stream);
            Client {
                r: BufReader::new(r),
                w,
            }
        }

        async fn send(&mut self, s: &str) {
            self.w.write_all(s.as_bytes()).await.unwrap();
        }

        async fn line(&mut self) -> String {
            let mut l = String::new();
            self.r.read_line(&mut l).await.unwrap();
            l
        }

        /// Read a multi-line response up to the terminating ".".
        async fn multiline(&mut self) -> String {
            let mut out = String::new();
            loop {
                let l = self.line().await;
                assert!(!l.is_empty(), "EOF in multi-line response: {}", out);
                out.push_str(&l);
                if l == ".\r\n" {
                    return out;
                }
            }
        }
    }

    const TLS_OFF: TlsPolicy = TlsPolicy {
        tls_available: false,
        allow_plaintext: false,
    };
    const TLS_REQUIRED: TlsPolicy = TlsPolicy {
        tls_available: true,
        allow_plaintext: false,
    };
    const PLAINTEXT_OK: TlsPolicy = TlsPolicy {
        tls_available: true,
        allow_plaintext: true,
    };
    const PLAIN_TLS_OFF: Pop3Opts = Pop3Opts {
        tls: false,
        greet: true,
        policy: TLS_OFF,
    };
    const AUTH_REFUSED: &str =
        "-ERR [AUTH] Plaintext authentication disabled; use STLS or port 995\r\n";

    async fn connect(storage: &Arc<Storage>) -> (Client, tokio::task::JoinHandle<()>) {
        connect_with(storage, None).await
    }

    async fn connect_with(
        storage: &Arc<Storage>,
        read_timeout: Option<Duration>,
    ) -> (Client, tokio::task::JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(1 << 16);
        let peer: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let st = Arc::clone(storage);
        let handle = tokio::spawn(async move {
            let _ = serve_pop3_with(
                server,
                peer,
                st,
                read_timeout.unwrap_or(READ_TIMEOUT),
                WRITE_TIMEOUT,
                PLAIN_TLS_OFF,
            )
            .await;
        });
        let (r, w) = tokio::io::split(client);
        let mut c = Client {
            r: BufReader::new(r),
            w,
        };
        assert!(c.line().await.starts_with("+OK"));
        (c, handle)
    }

    async fn first_message_content(storage: &Storage) -> String {
        let meta = storage.message_meta("bob").await.unwrap();
        let ids = vec![meta[0].id.clone()];
        let emails = storage.get_emails_by_ids("bob", &ids).await;
        storage.email_content("bob", &emails[&ids[0]]).await
    }

    #[tokio::test]
    async fn pop3_disconnect_in_transaction_locks_keys() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        let (mut c, h) = connect(&storage).await;
        c.send("USER bob\r\nPASS password123\r\n").await;
        assert!(c.line().await.starts_with("+OK"));
        assert!(c.line().await.starts_with("+OK"));
        assert!(first_message_content(&storage).await.contains("body 1"));
        c.send("DELE 1\r\n").await;
        assert!(c.line().await.starts_with("+OK"));

        drop(c); // no QUIT
        h.await.unwrap();
        assert!(!first_message_content(&storage).await.contains("body 1"));
        assert_eq!(storage.message_meta("bob").await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn pop3_retr_decrypts_after_pass() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        let (mut c, h) = connect(&storage).await;
        c.send("USER bob\r\nPASS password123\r\n").await;
        c.line().await;
        c.line().await;
        let raw = "Subject: m1\r\n\r\nbody 1\r\n";
        c.send("LIST 1\r\n").await;
        assert_eq!(c.line().await, format!("+OK 1 {}\r\n", raw.len()));
        c.send("RETR 1\r\n").await;
        let retr = c.multiline().await;
        assert_eq!(retr, format!("+OK {} octets\r\n{}.\r\n", raw.len(), raw));
        c.send("QUIT\r\n").await;
        assert!(c.line().await.starts_with("+OK"));
        h.await.unwrap();
        assert!(!first_message_content(&storage).await.contains("body 1"));
    }

    #[tokio::test]
    async fn idle_connection_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let timeout = Duration::from_millis(100);
        let (mut c, h) = connect_with(&storage, Some(timeout)).await;
        let start = tokio::time::Instant::now();
        assert_eq!(c.line().await, "-ERR timeout\r\n");
        // Allow timer slack below the nominal timeout.
        assert!(start.elapsed() + Duration::from_millis(50) >= timeout);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn pop3_capa_lists_resp_codes() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let (mut c, h) = connect(&storage).await;
        c.send("CAPA\r\n").await;
        let capa = c.multiline().await;
        assert!(capa.contains("\r\nRESP-CODES\r\n"), "{}", capa);
        assert!(capa.contains("\r\nAUTH-RESP-CODE\r\n"), "{}", capa);
        c.send("QUIT\r\n").await;
        assert!(c.line().await.starts_with("+OK"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn write_timeout_ends_stalled_session() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        // A tiny pipe the client never reads: the greeting fits, the CAPA
        // responses do not, so the server blocks writing.
        let (client, server) = tokio::io::duplex(64);
        let peer: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        let st = Arc::clone(&storage);
        let handle = tokio::spawn(async move {
            serve_pop3_with(
                server,
                peer,
                st,
                READ_TIMEOUT,
                Duration::from_millis(100),
                PLAIN_TLS_OFF,
            )
            .await
        });
        let (_r, mut w) = tokio::io::split(client);
        w.write_all(b"CAPA\r\nCAPA\r\n").await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("stalled session was not ended")
            .unwrap();
        let Err(err) = result else {
            panic!("session should fail with a write timeout");
        };
        let io = err.downcast_ref::<std::io::Error>().expect("io error");
        assert_eq!(io.kind(), std::io::ErrorKind::TimedOut);
    }

    // ------------------------------------------------------------------
    // TLS: STLS, [AUTH] refusal, implicit POP3S
    // ------------------------------------------------------------------

    type ConnTask = tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>;
    type ClientTls<S> = tokio_rustls::client::TlsStream<S>;

    /// After QUIT on TLS the server sent close_notify: a clean EOF
    /// (rustls reports `UnexpectedEof` otherwise).
    async fn assert_clean_tls_eof(c: &mut Client<ClientTls<DuplexStream>>) {
        let mut rest = String::new();
        assert_eq!(c.r.read_line(&mut rest).await.unwrap(), 0, "{:?}", rest);
    }

    fn test_peer() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    async fn self_signed(dir: &std::path::Path) -> Option<Arc<Tls>> {
        Some(crate::tls::test_support::self_signed(dir).await)
    }

    /// A whole plain-listener connection (the spec 3.2 sequence); the
    /// greeting is consumed.
    async fn start_conn(
        storage: &Arc<Storage>,
        tls: Option<Arc<Tls>>,
        policy: TlsPolicy,
    ) -> (Client, ConnTask) {
        let (client, server) = tokio::io::duplex(1 << 16);
        let handle = tokio::spawn(serve_connection(
            server,
            test_peer(),
            Arc::clone(storage),
            tls,
            policy,
            false,
        ));
        let (r, w) = tokio::io::split(client);
        let mut c = Client {
            r: BufReader::new(r),
            w,
        };
        assert!(c.line().await.starts_with("+OK"));
        (c, handle)
    }

    /// Client side of the TLS handshake on `c`'s stream.
    async fn upgrade(dir: &std::path::Path, c: Client) -> Client<ClientTls<DuplexStream>> {
        assert!(c.r.buffer().is_empty(), "unread server bytes before TLS");
        let raw = c.r.into_inner().unsplit(c.w);
        Client::new(
            crate::tls::test_support::connect(dir, raw)
                .await
                .expect("client handshake"),
        )
    }

    #[tokio::test]
    async fn capa_shows_stls_resp_codes_without_user() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED).await;
        c.send("CAPA\r\n").await;
        let capa = c.multiline().await;
        assert!(capa.contains("\r\nSTLS\r\n"), "{}", capa);
        assert!(capa.contains("\r\nRESP-CODES\r\n"), "{}", capa);
        assert!(capa.contains("\r\nAUTH-RESP-CODE\r\n"), "{}", capa);
        assert!(capa.contains("\r\nUIDL\r\n"), "{}", capa);
        assert!(capa.contains("\r\nTOP\r\n"), "{}", capa);
        assert!(!capa.contains("USER"), "{}", capa);
        drop(c);
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn capa_per_policy_and_transport() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        // TLS off: no STLS, USER listed.
        let (mut c, _h) = start_conn(&storage, None, TLS_OFF).await;
        c.send("CAPA\r\n").await;
        let capa = c.multiline().await;
        assert!(!capa.contains("STLS"), "{}", capa);
        assert!(capa.contains("\r\nUSER\r\n"), "{}", capa);
        // Plaintext allowed: STLS offered and USER listed.
        let (mut c, _h) = start_conn(&storage, self_signed(dir.path()).await, PLAINTEXT_OK).await;
        c.send("CAPA\r\n").await;
        let capa = c.multiline().await;
        assert!(capa.contains("\r\nSTLS\r\n"), "{}", capa);
        assert!(capa.contains("\r\nUSER\r\n"), "{}", capa);
        // After STLS: USER listed, STLS gone.
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED).await;
        c.send("STLS\r\n").await;
        assert_eq!(c.line().await, "+OK Begin TLS negotiation\r\n");
        let mut c = upgrade(dir.path(), c).await;
        c.send("CAPA\r\n").await;
        let capa = c.multiline().await;
        assert!(!capa.contains("STLS"), "{}", capa);
        assert!(capa.contains("\r\nUSER\r\n"), "{}", capa);
        c.send("QUIT\r\n").await;
        c.line().await;
        assert_clean_tls_eof(&mut c).await;
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn capa_after_login_omits_stls() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, PLAINTEXT_OK).await;
        c.send("CAPA\r\n").await;
        assert!(c.multiline().await.contains("\r\nSTLS\r\n"));
        c.send("USER bob\r\nPASS pass word 123\r\n").await;
        assert_eq!(c.line().await, "+OK User accepted\r\n");
        assert_eq!(c.line().await, "+OK Logged in\r\n");
        c.send("CAPA\r\n").await;
        let capa = c.multiline().await;
        assert!(!capa.contains("STLS"), "{}", capa);
        drop(c);
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn user_before_tls_is_auth_err() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED).await;
        c.send("USER bob\r\n").await;
        let resp = c.line().await;
        assert!(
            resp.starts_with("-ERR [AUTH] Plaintext authentication disabled"),
            "{}",
            resp
        );
        assert_eq!(resp, AUTH_REFUSED);
        // PASS is refused too (defence in depth), without a login attempt.
        c.send("PASS pass word 123\r\n").await;
        assert_eq!(c.line().await, AUTH_REFUSED);
        c.send("STAT\r\n").await;
        assert_eq!(c.line().await, "-ERR Not authenticated\r\n");
        crate::tls::test_support::assert_no_login_attempt(&storage, "bob").await;
        drop(c);
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn plaintext_allowed_policy_logs_in_without_tls() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, PLAINTEXT_OK).await;
        c.send("USER bob\r\nPASS pass word 123\r\n").await;
        assert_eq!(c.line().await, "+OK User accepted\r\n");
        assert_eq!(c.line().await, "+OK Logged in\r\n");
        let bob = storage.user_manager().get_user("bob").await.unwrap();
        assert!(!bob.login_history.last().unwrap().tls);
        drop(c);
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stls_then_user_pass_retr_works() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED).await;
        c.send("STLS\r\n").await;
        assert_eq!(c.line().await, "+OK Begin TLS negotiation\r\n");
        let mut c = upgrade(dir.path(), c).await;
        // No greeting after the handshake: the first line is USER's reply.
        c.send("USER bob\r\nPASS password123\r\n").await;
        assert_eq!(c.line().await, "+OK User accepted\r\n");
        assert_eq!(c.line().await, "+OK Logged in\r\n");
        // TLS is already active.
        c.send("STLS\r\n").await;
        assert!(c.line().await.starts_with("-ERR"));
        c.send("RETR 1\r\n").await;
        let retr = c.multiline().await;
        assert!(retr.contains("body 1"), "{}", retr);

        let bob = storage.user_manager().get_user("bob").await.unwrap();
        let rec = bob.login_history.last().unwrap();
        assert!(rec.success);
        assert!(rec.tls);
        assert_eq!(rec.protocol, "POP3");

        c.send("QUIT\r\n").await;
        assert!(c.line().await.starts_with("+OK"));
        assert_clean_tls_eof(&mut c).await;
        h.await.unwrap().unwrap();
        assert!(!first_message_content(&storage).await.contains("body 1"));
    }

    #[tokio::test]
    async fn stls_with_argument_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED).await;
        c.send("STLS now\r\n").await;
        assert!(c.line().await.starts_with("-ERR"));
        // Still plaintext and still refusing credentials.
        c.send("USER bob\r\n").await;
        assert_eq!(c.line().await, AUTH_REFUSED);
        drop(c);
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stls_tls_off_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let (mut c, h) = start_conn(&storage, None, TLS_OFF).await;
        c.send("STLS\r\n").await;
        assert!(c.line().await.starts_with("-ERR"));
        c.send("NOOP\r\n").await;
        assert_eq!(c.line().await, "+OK\r\n");
        drop(c);
        h.await.unwrap().unwrap();
    }

    /// With plaintext auth allowed a client can log in before STLS; STLS is
    /// then refused outside the AUTHORIZATION state.
    #[tokio::test]
    async fn stls_after_auth_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, PLAINTEXT_OK).await;
        c.send("USER bob\r\nPASS pass word 123\r\n").await;
        c.line().await;
        assert_eq!(c.line().await, "+OK Logged in\r\n");
        c.send("STLS\r\n").await;
        assert!(c.line().await.starts_with("-ERR"));
        // The session carries on in plaintext.
        c.send("STAT\r\n").await;
        assert!(c.line().await.starts_with("+OK 3 "));
        drop(c);
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stls_after_user_before_pass_drops_username() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, PLAINTEXT_OK).await;
        c.send("USER bob\r\n").await;
        assert_eq!(c.line().await, "+OK User accepted\r\n");
        c.send("STLS\r\n").await;
        assert_eq!(c.line().await, "+OK Begin TLS negotiation\r\n");
        let mut c = upgrade(dir.path(), c).await;
        c.send("PASS pass word 123\r\n").await;
        assert_eq!(c.line().await, "-ERR USER first\r\n");
        let bob = storage.user_manager().get_user("bob").await.unwrap();
        assert!(bob.login_history.is_empty(), "{:?}", bob.login_history);
        c.send("QUIT\r\n").await;
        c.line().await;
        assert_clean_tls_eof(&mut c).await;
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn implicit_pop3s_session_works() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let permit = Arc::clone(&connections).acquire_owned().await.unwrap();
        let (client, server) = tokio::io::duplex(1 << 16);
        let task = tokio::spawn(handle_connection(
            server,
            test_peer(),
            Arc::clone(&storage),
            self_signed(dir.path()).await,
            TLS_REQUIRED,
            true,
            permit,
        ));
        let mut c = Client::new(
            crate::tls::test_support::connect(dir.path(), client)
                .await
                .expect("client handshake"),
        );
        assert_eq!(c.line().await, "+OK kiss-mail POP3 server ready\r\n");
        c.send("USER bob\r\nPASS password123\r\nRETR 1\r\n").await;
        assert_eq!(c.line().await, "+OK User accepted\r\n");
        assert_eq!(c.line().await, "+OK Logged in\r\n");
        assert!(c.multiline().await.contains("body 1"));
        let bob = storage.user_manager().get_user("bob").await.unwrap();
        let rec = bob.login_history.last().unwrap();
        assert!(rec.tls);
        assert_eq!(rec.protocol, "POP3");
        c.send("QUIT\r\n").await;
        assert!(c.line().await.starts_with("+OK"));
        assert_clean_tls_eof(&mut c).await;
        task.await.unwrap();
        assert_eq!(connections.available_permits(), MAX_CONNECTIONS);
    }

    #[tokio::test]
    async fn stls_pipelined_commands_are_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED).await;
        c.send("STLS\r\nUSER bob\r\nPASS pass word 123\r\n").await;
        assert_eq!(c.line().await, "+OK Begin TLS negotiation\r\n");
        let mut c = upgrade(dir.path(), c).await;
        c.send("NOOP\r\n").await;
        // The pipelined USER/PASS never got a reply: the first line under TLS
        // is NOOP's.
        assert_eq!(c.line().await, "+OK\r\n");
        c.send("STAT\r\n").await;
        assert_eq!(c.line().await, "-ERR Not authenticated\r\n");
        crate::tls::test_support::assert_no_login_attempt(&storage, "bob").await;
        c.send("QUIT\r\n").await;
        c.line().await;
        assert_clean_tls_eof(&mut c).await;
        h.await.unwrap().unwrap();
    }

    /// Plaintext sent to the POP3S listener fails the handshake at once, gets
    /// no POP3 reply, and frees the connection slot.
    #[tokio::test]
    async fn plaintext_on_implicit_listener_closes_fast_and_frees_slot() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let permit = Arc::clone(&connections).acquire_owned().await.unwrap();
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(b"USER bob\r\n").await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            handle_connection(
                server,
                test_peer(),
                storage,
                self_signed(dir.path()).await,
                TLS_REQUIRED,
                true,
                permit,
            ),
        )
        .await
        .expect("handle_connection returns within 1 s");
        assert_eq!(connections.available_permits(), MAX_CONNECTIONS);
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(!String::from_utf8_lossy(&got).contains("+OK"), "{got:?}");
    }

    /// STLS accepted, then the client hangs up or sends garbage instead of a
    /// ClientHello: no panic, the slot is freed.
    #[tokio::test]
    async fn stls_then_hangup_or_garbage_frees_slot() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let tls = self_signed(dir.path()).await;
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        for garbage in [
            None,
            Some(&b"\x16\x03\x01garbage\r\n"[..]),
            Some(b"NOOP\r\n"),
        ] {
            let permit = Arc::clone(&connections).acquire_owned().await.unwrap();
            let (client, server) = tokio::io::duplex(4096);
            let task = tokio::spawn(handle_connection(
                server,
                test_peer(),
                Arc::clone(&storage),
                tls.clone(),
                TLS_REQUIRED,
                false,
                permit,
            ));
            let (r, w) = tokio::io::split(client);
            let mut c = Client {
                r: BufReader::new(r),
                w,
            };
            c.line().await;
            c.send("STLS\r\n").await;
            assert_eq!(c.line().await, "+OK Begin TLS negotiation\r\n");
            if let Some(bytes) = garbage {
                c.w.write_all(bytes).await.unwrap();
            }
            drop(c);
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("handle_connection returns promptly")
                .expect("no panic");
            assert_eq!(connections.available_permits(), MAX_CONNECTIONS);
        }
    }

    #[tokio::test]
    async fn pop3s_listener_without_tls_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let server = Pop3Server::new(storage, None, TLS_OFF);
        let err = server
            .run("127.0.0.1:0", Some("127.0.0.1:0"))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("POP3S: "), "{err}");
    }

    #[tokio::test]
    async fn session_returns_starttls_with_raw_stream() {
        let dir = tempfile::tempdir().unwrap();
        let storage = setup(dir.path()).await;
        let opts = Pop3Opts {
            tls: false,
            greet: false,
            policy: TLS_REQUIRED,
        };
        let (client, server) = tokio::io::duplex(1 << 16);
        let task = tokio::spawn(serve_pop3_with(
            server,
            test_peer(),
            storage,
            READ_TIMEOUT,
            WRITE_TIMEOUT,
            opts,
        ));
        let (r, w) = tokio::io::split(client);
        let mut c = Client {
            r: BufReader::new(r),
            w,
        };
        // greet = false: the first line is STLS's reply.
        c.send("STLS\r\n").await;
        assert_eq!(c.line().await, "+OK Begin TLS negotiation\r\n");
        let end = task.await.unwrap().unwrap();
        assert!(matches!(end, SessionEnd::StartTls(_)));
    }
}
