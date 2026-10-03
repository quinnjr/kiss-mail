//! POP3 Server implementation.
//!
//! Implements RFC 1939 (Post Office Protocol - Version 3) with basic commands.
//! The maildrop is snapshotted at login; DELE only marks messages for deletion
//! and they are removed when the session ends with QUIT (UPDATE state). An
//! abnormal disconnect deletes nothing.

use crate::proto::{KeyLease, WRITE_TIMEOUT, accepted, read_line_limited, write_all_timeout};
use crate::storage::{AuthError, Storage};
use crate::users::canonical_username;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

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

pub struct Pop3Server {
    storage: Arc<Storage>,
}

impl Pop3Server {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    pub async fn run(&self, addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("POP3 server listening on {}", addr);
        let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        loop {
            let permit = Arc::clone(&limit).acquire_owned().await?;
            let Some((socket, peer_addr)) = accepted("POP3", listener.accept().await).await else {
                continue;
            };
            tracing::info!("POP3 connection from {}", peer_addr);

            let storage = Arc::clone(&self.storage);

            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_pop3_connection(socket, peer_addr, storage).await {
                    tracing::error!("POP3 connection error: {}", e);
                }
            });
        }
    }
}

async fn handle_pop3_connection(
    socket: TcpStream,
    peer: SocketAddr,
    storage: Arc<Storage>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    serve_pop3(socket, peer, storage).await
}

/// Serve one POP3 connection over any byte stream.
pub async fn serve_pop3<S>(
    stream: S,
    peer: SocketAddr,
    storage: Arc<Storage>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    serve_pop3_with(stream, peer, storage, READ_TIMEOUT, WRITE_TIMEOUT).await
}

async fn serve_pop3_with<S>(
    stream: S,
    peer: SocketAddr,
    storage: Arc<Storage>,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    // The session owns the key lease, so the keys are locked however this
    // future ends (normally below, or by Drop on panic / cancellation).
    let mut session = Pop3Session::new(peer.ip().to_string(), Arc::clone(&storage));
    let session = &mut session;

    let result = async {
        // Send greeting
        let greeting = format!("{} kiss-mail POP3 server ready\r\n", POP3_OK);
        write_all_timeout(&mut writer, greeting.as_bytes(), write_timeout).await?;

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

            if cmd == "QUIT" {
                break;
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    // Abnormal or normal end: drop decrypted keys. Pending DELEs are only
    // applied by QUIT.
    session.finish().await;
    result
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
            // The password is the whole remainder of the line (may contain spaces).
            let password = line.get(5..).unwrap_or("");
            let Some(username) = session.username.clone() else {
                return format!("{} USER first\r\n", POP3_ERR);
            };
            if password.is_empty() {
                return format!("{} Missing password\r\n", POP3_ERR);
            }
            match storage
                .login(&username, password, &session.peer_ip, "POP3")
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
        "CAPA" => {
            let mut response = format!("{} Capability list follows\r\n", POP3_OK);
            response.push_str("USER\r\n");
            response.push_str("UIDL\r\n");
            response.push_str("TOP\r\n");
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

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

    struct Client {
        r: BufReader<ReadHalf<DuplexStream>>,
        w: WriteHalf<DuplexStream>,
    }

    impl Client {
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
            let _ = match read_timeout {
                None => serve_pop3(server, peer, st).await,
                Some(t) => serve_pop3_with(server, peer, st, t, WRITE_TIMEOUT).await,
            };
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
            serve_pop3_with(server, peer, st, READ_TIMEOUT, Duration::from_millis(100)).await
        });
        let (_r, mut w) = tokio::io::split(client);
        w.write_all(b"CAPA\r\nCAPA\r\n").await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("stalled session was not ended")
            .unwrap();
        let err = result.expect_err("session should fail with a write timeout");
        let io = err.downcast_ref::<std::io::Error>().expect("io error");
        assert_eq!(io.kind(), std::io::ErrorKind::TimedOut);
    }
}
