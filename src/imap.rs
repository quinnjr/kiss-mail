//! IMAP Server implementation.
//!
//! Implements a subset of RFC 3501 (IMAP4rev1) for a single INBOX, plus
//! IDLE (RFC 2177), SASL-IR (RFC 4959) and UNSELECT (RFC 3691).

use crate::mime::{header, header_param, header_param_names, parse_headers, split_headers_body};
use crate::proto::{
    KeyLease, SessionEnd, TlsPolicy, WRITE_TIMEOUT, accepted, decode_auth_plain, read_line_limited,
    write_all_timeout, write_all_until,
};
use crate::storage::{AuthError, Email, EmailFlags, MessageMeta, Storage};
use crate::tls::Tls;
use chrono::NaiveDate;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Tagged reply to LOGIN/AUTHENTICATE while plaintext credentials are refused
/// (RFC 5530 PRIVACYREQUIRED).
const PRIVACY_REQUIRED_REPLY: &str = "NO [PRIVACYREQUIRED] TLS required; use STARTTLS or port 993";
const STARTTLS_READY_REPLY: &str = "OK Begin TLS negotiation now";
/// Maximum size of a command line (including synchronising literals).
const MAX_COMMAND: usize = 64 * 1024;
/// How often IDLE checks for new mail.
const IDLE_POLL: Duration = Duration::from_secs(15);
/// Maximum duration of a single IDLE command before the server logs out.
const IDLE_MAX: Duration = Duration::from_secs(30 * 60);
/// Inactivity timeout before authentication.
const PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(2 * 60);
/// Inactivity timeout once authenticated (RFC 3501 section 5.4: at least 30 min).
const AUTH_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Maximum concurrent connections per listener.
const MAX_CONNECTIONS: usize = 500;
/// Maximum parenthesis nesting accepted by the tokenizer.
const MAX_TOKEN_DEPTH: usize = 16;
/// Maximum NOT/OR/parenthesis nesting in SEARCH criteria.
const MAX_SEARCH_DEPTH: usize = 32;
/// Maximum length of a LIST/LSUB mailbox pattern.
const MAX_LIST_PATTERN: usize = 256;
const AUTOLOGOUT: &[u8] = b"* BYE Autologout; idle too long\r\n";

#[derive(Debug, Clone, PartialEq)]
enum ImapState {
    NotAuthenticated,
    Authenticated,
    Selected,
}

/// A message in the selected-mailbox snapshot (sequence number = index + 1).
#[derive(Debug, Clone)]
struct SelMsg {
    id: String,
    uid: u32,
}

#[derive(Debug, Clone)]
struct Selected {
    read_only: bool,
    msgs: Vec<SelMsg>,
}

impl Selected {
    fn max_uid(&self) -> u32 {
        self.msgs.iter().map(|m| m.uid).max().unwrap_or(0)
    }
}

/// Connection time limits (constants in production; shortened in tests).
#[derive(Debug, Clone, Copy)]
struct Timeouts {
    pre_auth: Duration,
    auth: Duration,
    idle_max: Duration,
    idle_poll: Duration,
    write: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            pre_auth: PRE_AUTH_TIMEOUT,
            auth: AUTH_TIMEOUT,
            idle_max: IDLE_MAX,
            idle_poll: IDLE_POLL,
            write: WRITE_TIMEOUT,
        }
    }
}

/// How a session starts (see `serve_imap_with`).
#[derive(Debug, Clone, Copy)]
struct ImapOpts {
    /// The stream is TLS-protected.
    tls: bool,
    /// Send the greeting (not after STARTTLS: RFC 3501 section 6.2.1).
    greet: bool,
    policy: TlsPolicy,
}

/// The capability list for a session state (spec section 4.2): `STARTTLS`
/// only before login on a plaintext connection with TLS available, and
/// `LOGINDISABLED` instead of `AUTH=PLAIN` while credentials are refused.
/// After login neither `STARTTLS` nor `LOGINDISABLED` is listed.
fn capabilities(on_tls: bool, authenticated: bool, policy: TlsPolicy) -> String {
    let mut caps = vec!["IMAP4rev1"];
    if !authenticated && !on_tls && policy.tls_available {
        caps.push("STARTTLS");
    }
    if authenticated || policy.secure(on_tls) {
        caps.push("AUTH=PLAIN");
    } else {
        caps.push("LOGINDISABLED");
    }
    caps.extend(["SASL-IR", "IDLE", "UNSELECT"]);
    caps.join(" ")
}

#[derive(Debug)]
struct ImapSession {
    state: ImapState,
    username: Option<String>,
    /// Encryption keys unlocked at login; released when the session ends.
    lease: KeyLease,
    selected: Option<Selected>,
    peer_ip: String,
    timeouts: Timeouts,
    /// The session runs over TLS.
    tls: bool,
    policy: TlsPolicy,
}

impl ImapSession {
    /// A plaintext session with TLS off (plaintext logins allowed);
    /// `serve_imap_with` sets `tls` and `policy` from its options.
    fn new(peer_ip: String, storage: Arc<Storage>) -> Self {
        Self {
            state: ImapState::NotAuthenticated,
            username: None,
            lease: KeyLease::new(storage, "IMAP"),
            selected: None,
            peer_ip,
            timeouts: Timeouts::default(),
            tls: false,
            policy: TlsPolicy {
                tls_available: false,
                allow_plaintext: false,
            },
        }
    }

    /// May credentials be exchanged on this connection?
    fn secure(&self) -> bool {
        self.policy.secure(self.tls)
    }

    fn capabilities(&self) -> String {
        capabilities(
            self.tls,
            self.state != ImapState::NotAuthenticated,
            self.policy,
        )
    }

    fn user(&self) -> &str {
        self.username.as_deref().unwrap_or("")
    }

    /// End the authenticated state, returning the user if a login was open.
    /// The key lease is left in place for [`ImapSession::finish`].
    fn take_login(&mut self) -> Option<String> {
        self.state = ImapState::NotAuthenticated;
        self.selected = None;
        self.username.take()
    }

    /// End the session: close the login and lock its keys.
    async fn finish(&mut self) {
        self.take_login();
        self.lease.release().await;
    }

    fn read_timeout(&self) -> Duration {
        if self.state == ImapState::NotAuthenticated {
            self.timeouts.pre_auth
        } else {
            self.timeouts.auth
        }
    }
}

pub struct ImapServer {
    storage: Arc<Storage>,
    /// TLS for STARTTLS and the implicit-TLS listener (`None`: TLS off).
    tls: Option<Arc<Tls>>,
    policy: TlsPolicy,
}

impl ImapServer {
    pub fn new(storage: Arc<Storage>, tls: Option<Arc<Tls>>, policy: TlsPolicy) -> Self {
        // The STARTTLS offer and the LOGINDISABLED policy must never disagree.
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
    /// the implicit-TLS (IMAPS) listener. Both share one connection limit.
    pub async fn run(
        &self,
        plain_addr: &str,
        tls_addr: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let plain = TcpListener::bind(plain_addr)
            .await
            .map_err(|e| format!("IMAP: cannot bind {}: {}", plain_addr, e))?;
        tracing::info!("IMAP server listening on {}", plain_addr);
        let implicit = match tls_addr {
            None => None,
            Some(addr) => {
                if self.tls.is_none() {
                    return Err("IMAPS: TLS is not configured".into());
                }
                let listener = TcpListener::bind(addr)
                    .await
                    .map_err(|e| format!("IMAPS: cannot bind {}: {}", addr, e))?;
                tracing::info!("IMAPS (implicit TLS) server listening on {}", addr);
                Some(listener)
            }
        };
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        let plain_loop = self.accept_loop(plain, "IMAP", false, Arc::clone(&connections));
        let implicit_loop = async {
            match implicit {
                Some(listener) => {
                    self.accept_loop(listener, "IMAPS", true, Arc::clone(&connections))
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
            // Wait for a free slot before accepting, so excess clients queue
            // in the kernel backlog instead of consuming tasks.
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
        Ok(Err(e)) => tracing::error!("IMAP connection error ({}): {}", peer, e),
        Err(e) if e.is_panic() => {
            tracing::error!("IMAP connection task for {} panicked: {}", peer, e)
        }
        Err(e) => tracing::error!("IMAP connection task for {} failed: {}", peer, e),
    }
}

/// The session restart sequence (spec section 3.2). On the implicit-TLS
/// listener the handshake comes first; on the plain listener an accepted
/// STARTTLS restarts the session over TLS with fresh state and no greeting.
/// A failed or timed-out handshake just closes the connection.
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
    let timeouts = Timeouts::default();
    if implicit {
        let Some(tls) = tls else {
            return Err("IMAPS connection without a TLS configuration".into());
        };
        let stream = match tls.accept(stream).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::debug!("IMAPS handshake with {} failed: {}", peer, e);
                return Ok(());
            }
        };
        let opts = ImapOpts {
            tls: true,
            greet: true,
            policy,
        };
        serve_imap_with(stream, peer, storage, timeouts, opts).await?;
        return Ok(());
    }

    let opts = ImapOpts {
        tls: false,
        greet: true,
        policy,
    };
    match serve_imap_with(stream, peer, Arc::clone(&storage), timeouts, opts).await? {
        SessionEnd::Closed => Ok(()),
        SessionEnd::StartTls(raw) => {
            let Some(tls) = tls else {
                return Err("STARTTLS accepted without a TLS configuration".into());
            };
            let stream = match tls.accept(raw).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::debug!("IMAP STARTTLS handshake with {} failed: {}", peer, e);
                    return Ok(());
                }
            };
            let opts = ImapOpts {
                tls: true,
                greet: false,
                policy,
            };
            serve_imap_with(stream, peer, storage, timeouts, opts).await?;
            Ok(())
        }
    }
}

/// Run one IMAP session over `stream`.
///
/// Returns `SessionEnd::StartTls` with the raw stream once STARTTLS has been
/// accepted (the caller performs the handshake and starts a fresh session).
/// Client bytes already buffered at that point are discarded with the
/// `BufReader`, so commands pipelined after STARTTLS never run under TLS.
async fn serve_imap_with<S>(
    stream: S,
    peer: SocketAddr,
    storage: Arc<Storage>,
    timeouts: Timeouts,
    opts: ImapOpts,
) -> Result<SessionEnd<S>, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    // The session owns the key lease, so the keys are locked however this
    // future ends (normally below, or by Drop on panic / cancellation).
    let mut session = ImapSession::new(peer.ip().to_string(), Arc::clone(&storage));
    session.timeouts = timeouts;
    session.tls = opts.tls;
    session.policy = opts.policy;

    let result = imap_loop(&mut reader, &mut writer, &mut session, &storage, opts.greet).await;

    // A no-op after STARTTLS: it is only accepted before login.
    session.finish().await;
    match result? {
        LoopEnd::StartTls => Ok(SessionEnd::StartTls(reader.into_inner().unsplit(writer))),
        LoopEnd::Closed => {
            if opts.tls {
                // Send close_notify (bounded, errors ignored: the session is over).
                let _ = tokio::time::timeout(timeouts.write, writer.shutdown()).await;
            }
            Ok(SessionEnd::Closed)
        }
    }
}

/// How `imap_loop` ended.
enum LoopEnd {
    Closed,
    /// STARTTLS was accepted and its OK sent; the stream must be upgraded.
    StartTls,
}

/// The STARTTLS reply (spec section 4.2): `None` to accept, or the BAD
/// reply. RFC 3501 defines only OK and BAD for STARTTLS.
fn starttls_refusal(tag: &str, args: &str, session: &ImapSession) -> Option<String> {
    let reason = if !session.policy.tls_available {
        // Not advertised: the same reply as any unknown command.
        "Unknown command"
    } else if session.tls {
        "TLS already active"
    } else if !args.is_empty() {
        "STARTTLS takes no arguments"
    } else if session.state != ImapState::NotAuthenticated {
        "STARTTLS not permitted after login"
    } else {
        return None;
    };
    Some(format!("{} BAD {}\r\n", tag, reason))
}

async fn imap_loop<R, W>(
    reader: &mut R,
    writer: &mut W,
    session: &mut ImapSession,
    storage: &Storage,
    greet: bool,
) -> Result<LoopEnd, Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let wt = session.timeouts.write;
    if greet {
        let greeting = format!(
            "* OK [CAPABILITY {}] kiss-mail IMAP4rev1 server ready\r\n",
            session.capabilities()
        );
        write_all_timeout(writer, greeting.as_bytes(), wt).await?;
    }

    loop {
        let read =
            tokio::time::timeout(session.read_timeout(), read_command(reader, writer, wt)).await;
        let line = match read {
            Err(_) => {
                write_all_timeout(writer, AUTOLOGOUT, wt).await?;
                break;
            }
            Ok(r) => match r? {
                None => break,
                Some(Err(msg)) => {
                    write_all_timeout(writer, msg.as_bytes(), wt).await?;
                    continue;
                }
                Some(Ok(line)) => line,
            },
        };

        let (tag, cmd, args) = match split_command(&line) {
            Some(parts) => parts,
            None => {
                write_all_timeout(writer, b"* BAD Invalid command\r\n", wt).await?;
                continue;
            }
        };
        if cmd == "AUTHENTICATE" {
            tracing::debug!("IMAP <- {} AUTHENTICATE ...", tag);
        } else if cmd == "LOGIN" {
            tracing::debug!("IMAP <- {} LOGIN ...", tag);
        } else {
            tracing::debug!("IMAP <- {}", line);
        }

        let response: Vec<u8> = match cmd.as_str() {
            "STARTTLS" => match starttls_refusal(tag, args, session) {
                Some(bad) => bad.into_bytes(),
                None => {
                    let ok = format!("{} {}\r\n", tag, STARTTLS_READY_REPLY);
                    tracing::debug!("IMAP -> {}", ok.trim_end());
                    write_all_timeout(writer, ok.as_bytes(), wt).await?;
                    return Ok(LoopEnd::StartTls);
                }
            },
            "AUTHENTICATE" => {
                match handle_authenticate(tag, args, session, storage, reader, writer).await? {
                    Some(resp) => resp.into_bytes(),
                    None => {
                        write_all_timeout(writer, AUTOLOGOUT, wt).await?;
                        break;
                    }
                }
            }
            "IDLE" => match handle_idle(tag, session, storage, reader, writer).await? {
                Some(resp) => resp.into_bytes(),
                None => break, // connection closed or IDLE deadline reached
            },
            _ => process_imap_command(tag, &cmd, args, session, storage).await,
        };

        if tracing::enabled!(tracing::Level::DEBUG) {
            for resp_line in String::from_utf8_lossy(&response).lines() {
                tracing::debug!("IMAP -> {}", resp_line);
            }
        }
        write_all_timeout(writer, &response, wt).await?;

        if cmd == "LOGOUT" {
            break;
        }
    }

    Ok(LoopEnd::Closed)
}

/// Read one command, following synchronising (`{n}`) and non-synchronising
/// (`{n+}`) literals. Literal contents are re-encoded as quoted strings so the
/// rest of the parser only deals with one line.
async fn read_command<R, W>(
    reader: &mut R,
    writer: &mut W,
    write_timeout: Duration,
) -> std::io::Result<Option<Result<String, String>>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut command = String::new();
    loop {
        let line = match read_line_limited(reader, MAX_COMMAND).await? {
            None => return Ok(None),
            Some(Err(())) => return Ok(Some(Err("* BAD Command line too long\r\n".to_string()))),
            Some(Ok(line)) => line,
        };
        let line = line.trim_end_matches(['\r', '\n']);

        let Some((before, size, sync)) = parse_literal_marker(line) else {
            command.push_str(line);
            return Ok(Some(Ok(command)));
        };
        let used = command.len().saturating_add(before.len());
        if size > MAX_COMMAND.saturating_sub(used) {
            return Ok(Some(Err("* BAD Literal too large\r\n".to_string())));
        }
        command.push_str(before);
        if sync {
            write_all_timeout(writer, b"+ Ready for literal data\r\n", write_timeout).await?;
        }
        let mut buf = vec![0u8; size];
        reader.read_exact(&mut buf).await?;
        command.push_str(&quote(&String::from_utf8_lossy(&buf)));
    }
}

/// If `line` ends with a literal marker `{n}` / `{n+}`, return the text before
/// it, the size and whether it is synchronising.
fn parse_literal_marker(line: &str) -> Option<(&str, usize, bool)> {
    let body = line.strip_suffix('}')?;
    let open = body.rfind('{')?;
    let inner = &body[open + 1..];
    let (digits, sync) = match inner.strip_suffix('+') {
        Some(d) => (d, false),
        None => (inner, true),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((&line[..open], digits.parse().ok()?, sync))
}

/// Split a command line into tag, upper-cased command and the argument string.
fn split_command(line: &str) -> Option<(&str, String, &str)> {
    let line = line.trim_start();
    let (tag, rest) = line.split_once(' ')?;
    if tag.is_empty() {
        return None;
    }
    let rest = rest.trim_start();
    let (cmd, args) = match rest.split_once(' ') {
        Some((c, a)) => (c, a.trim()),
        None => (rest.trim(), ""),
    };
    if cmd.is_empty() {
        return None;
    }
    Some((tag, cmd.to_uppercase(), args))
}

// ============================================================================
// Tokenizer
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    /// An atom; may contain a `[...]` section and `<...>` partial suffix.
    Atom(String),
    /// A quoted string (unescaped).
    Str(String),
    /// A parenthesised list.
    List(Vec<Tok>),
}

impl Tok {
    /// The value of an atom or string.
    fn as_str(&self) -> Option<&str> {
        match self {
            Tok::Atom(s) | Tok::Str(s) => Some(s),
            Tok::List(_) => None,
        }
    }
}

fn tokenize(s: &str) -> Option<Vec<Tok>> {
    tokenize_with_depth(s, MAX_TOKEN_DEPTH)
}

/// Tokenize with at most `max_depth` levels of parenthesised lists.
fn tokenize_with_depth(s: &str, max_depth: usize) -> Option<Vec<Tok>> {
    let chars: Vec<char> = s.chars().collect();
    let mut pos = 0;
    let toks = tokenize_inner(&chars, &mut pos, 0, max_depth)?;
    if pos < chars.len() {
        return None;
    }
    Some(toks)
}

/// Does an atom with this prefix (the text before its first `[`) carry a
/// bracketed section spec?
fn has_section(prefix: &str) -> bool {
    ["BODY", "BODY.PEEK", "BINARY"]
        .iter()
        .any(|p| prefix.eq_ignore_ascii_case(p))
}

fn tokenize_inner(
    chars: &[char],
    pos: &mut usize,
    depth: usize,
    max_depth: usize,
) -> Option<Vec<Tok>> {
    let in_list = depth > 0;
    let mut toks = Vec::new();
    while *pos < chars.len() {
        match chars[*pos] {
            ' ' => *pos += 1,
            '(' => {
                if depth >= max_depth {
                    return None;
                }
                *pos += 1;
                toks.push(Tok::List(tokenize_inner(chars, pos, depth + 1, max_depth)?));
            }
            ')' => {
                if in_list {
                    *pos += 1;
                    return Some(toks);
                }
                return None;
            }
            '"' => {
                *pos += 1;
                let mut out = String::new();
                loop {
                    let c = *chars.get(*pos)?;
                    *pos += 1;
                    match c {
                        '\\' => {
                            out.push(*chars.get(*pos)?);
                            *pos += 1;
                        }
                        '"' => break,
                        c => out.push(c),
                    }
                }
                toks.push(Tok::Str(out));
            }
            _ => {
                let mut out = String::new();
                // Bracket nesting inside a section spec (`BODY[...]`); `[` in
                // any other atom is an ordinary character.
                let mut brackets = 0usize;
                let mut section_seen = false;
                while *pos < chars.len() {
                    let c = chars[*pos];
                    if brackets == 0 && (c == ' ' || c == '(' || c == ')' || c == '"') {
                        break;
                    }
                    if c == '[' && (brackets > 0 || (!section_seen && has_section(&out))) {
                        brackets += 1;
                        section_seen = true;
                    } else if c == ']' && brackets > 0 {
                        brackets -= 1;
                    }
                    out.push(c);
                    *pos += 1;
                }
                toks.push(Tok::Atom(out));
            }
        }
    }
    if in_list { None } else { Some(toks) }
}

// ============================================================================
// String helpers
// ============================================================================

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn literal(s: &str) -> String {
    format!("{{{}}}\r\n{}", s.len(), s)
}

/// Encode as an IMAP string: quoted when safe, literal otherwise.
fn imap_string(s: &str) -> String {
    if s.bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == 0 || b >= 0x80)
    {
        literal(s)
    } else {
        quote(s)
    }
}

fn nstring(s: Option<&str>) -> String {
    match s {
        Some(s) => imap_string(s),
        None => "NIL".to_string(),
    }
}

fn flags_string(flags: &EmailFlags) -> String {
    let mut out = Vec::new();
    if flags.seen {
        out.push("\\Seen");
    }
    if flags.answered {
        out.push("\\Answered");
    }
    if flags.flagged {
        out.push("\\Flagged");
    }
    if flags.deleted {
        out.push("\\Deleted");
    }
    if flags.draft {
        out.push("\\Draft");
    }
    out.join(" ")
}

// ============================================================================
// Sequence sets
// ============================================================================

/// Parse a sequence/UID set; `*` resolves to `max`. Ranges are normalised.
fn parse_set(s: &str, max: u32) -> Option<Vec<(u32, u32)>> {
    let parse_num = |p: &str| -> Option<u32> {
        if p == "*" {
            Some(max)
        } else {
            p.parse::<u32>().ok().filter(|n| *n > 0)
        }
    };
    let mut ranges = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        let (a, b) = match part.split_once(':') {
            Some((a, b)) => (parse_num(a)?, parse_num(b)?),
            None => {
                let n = parse_num(part)?;
                (n, n)
            }
        };
        ranges.push((a.min(b), a.max(b)));
    }
    Some(ranges)
}

fn in_set(n: u32, ranges: &[(u32, u32)]) -> bool {
    ranges.iter().any(|(a, b)| n >= *a && n <= *b)
}

/// Resolve a set to snapshot indices (ascending).
fn resolve_set(set: &str, sel: &Selected, uid_mode: bool) -> Option<Vec<usize>> {
    if uid_mode {
        let ranges = parse_set(set, sel.max_uid())?;
        Some(
            sel.msgs
                .iter()
                .enumerate()
                .filter(|(_, m)| in_set(m.uid, &ranges))
                .map(|(i, _)| i)
                .collect(),
        )
    } else {
        let ranges = parse_set(set, sel.msgs.len() as u32)?;
        Some(
            (0..sel.msgs.len())
                .filter(|i| in_set(*i as u32 + 1, &ranges))
                .collect(),
        )
    }
}

// ============================================================================
// Message helpers
// ============================================================================

/// Split a message into (header block including the blank line, body text).
fn split_message(raw: &str) -> (&str, &str) {
    let (_, body) = split_headers_body(raw);
    // `body` is a suffix of `raw`; the header block is everything before it.
    (&raw[..raw.len() - body.len()], body)
}

/// Select header fields (with continuation lines) from a header block.
fn filter_header_fields(header: &str, names: &[String], not: bool) -> String {
    let wanted: HashSet<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
    let mut out = String::new();
    let mut keep = false;
    for line in header.split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        if content.is_empty() {
            break;
        }
        if !(line.starts_with(' ') || line.starts_with('\t')) {
            let name = content
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            keep = wanted.contains(&name) != not;
        }
        if keep {
            out.push_str(content);
            out.push_str("\r\n");
        }
    }
    out.push_str("\r\n");
    out
}

/// Parse an address header into (display name, mailbox, host) triples.
fn parse_addresses(value: &str) -> Vec<(Option<String>, String, String)> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let (mut in_quotes, mut in_angle, mut escaped) = (false, false, false);
    for c in value.chars() {
        if escaped {
            escaped = false;
            current.push(c);
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            '<' if !in_quotes => in_angle = true,
            '>' if !in_quotes => in_angle = false,
            ',' if !in_quotes && !in_angle => {
                parts.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(c);
    }
    parts.push(current);

    parts
        .iter()
        .filter_map(|p| {
            let p = p.trim();
            if p.is_empty() {
                return None;
            }
            let (name, addr) = match (p.find('<'), p.rfind('>')) {
                (Some(l), Some(r)) if l < r => {
                    let name = unquote_display_name(p[..l].trim());
                    ((!name.is_empty()).then_some(name), p[l + 1..r].trim())
                }
                _ => (None, p),
            };
            let (mailbox, host) = match addr.rsplit_once('@') {
                Some((m, h)) => (m.to_string(), h.to_string()),
                None => (addr.to_string(), String::new()),
            };
            Some((name, mailbox, host))
        })
        .collect()
}

/// Strip surrounding quotes from a display name and undo backslash escapes.
fn unquote_display_name(name: &str) -> String {
    let inner = name
        .strip_prefix('"')
        .and_then(|n| n.strip_suffix('"'))
        .unwrap_or(name);
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out.trim().to_string()
}

fn address_list(value: Option<&str>) -> String {
    let addrs = value.map(parse_addresses).unwrap_or_default();
    if addrs.is_empty() {
        return "NIL".to_string();
    }
    let items: Vec<String> = addrs
        .iter()
        .map(|(name, mailbox, host)| {
            format!(
                "({} NIL {} {})",
                nstring(name.as_deref()),
                imap_string(mailbox),
                imap_string(host)
            )
        })
        .collect();
    format!("({})", items.join(""))
}

fn envelope(email: &Email) -> String {
    let from = email
        .get_header("From")
        .map(|s| s.to_string())
        .or_else(|| (!email.from.is_empty()).then(|| email.from.clone()));
    let sender = email
        .get_header("Sender")
        .map(|s| s.to_string())
        .or_else(|| from.clone());
    let reply_to = email
        .get_header("Reply-To")
        .map(|s| s.to_string())
        .or_else(|| from.clone());
    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        nstring(email.get_header("Date")),
        nstring(email.get_header("Subject")),
        address_list(from.as_deref()),
        address_list(sender.as_deref()),
        address_list(reply_to.as_deref()),
        address_list(email.get_header("To")),
        address_list(email.get_header("Cc")),
        address_list(email.get_header("Bcc")),
        nstring(email.get_header("In-Reply-To")),
        nstring(email.get_header("Message-ID")),
    )
}

/// A single-part BODYSTRUCTURE computed from the message. Multipart and
/// message/* messages are reported as text/plain (the client then sees the raw
/// MIME body).
fn body_structure(content: &str) -> String {
    let (head, text) = split_message(content);
    let headers = parse_headers(head);
    let size = text.len();
    let lines = text.matches('\n').count() + usize::from(!text.is_empty() && !text.ends_with('\n'));

    let (mut ty, mut subtype, mut params) = (
        "TEXT".to_string(),
        "PLAIN".to_string(),
        Vec::<(String, String)>::new(),
    );
    if let Some(ct) = header(&headers, "content-type") {
        let mime = ct.split(';').next().unwrap_or("").trim();
        if let Some((t, s)) = mime.split_once('/') {
            let (t, s) = (t.trim().to_uppercase(), s.trim().to_uppercase());
            if !t.is_empty() && !s.is_empty() && t != "MULTIPART" && t != "MESSAGE" {
                ty = t;
                subtype = s;
                for key in header_param_names(ct) {
                    if let Some(v) = header_param(ct, &key) {
                        params.push((key.to_uppercase(), v));
                    }
                }
            }
        }
    }
    if ty == "TEXT" && !params.iter().any(|(k, _)| k == "CHARSET") {
        params.push(("CHARSET".to_string(), "US-ASCII".to_string()));
    }
    let params = if params.is_empty() {
        "NIL".to_string()
    } else {
        format!(
            "({})",
            params
                .iter()
                .map(|(k, v)| format!("{} {}", quote(k), imap_string(v)))
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    let encoding = header(&headers, "content-transfer-encoding")
        .map(|e| e.trim().to_uppercase())
        .unwrap_or_else(|| "7BIT".to_string());

    if ty == "TEXT" {
        format!(
            "({} {} {} NIL NIL {} {} {})",
            quote(&ty),
            quote(&subtype),
            params,
            quote(&encoding),
            size,
            lines
        )
    } else {
        format!(
            "({} {} {} NIL NIL {} {})",
            quote(&ty),
            quote(&subtype),
            params,
            quote(&encoding),
            size
        )
    }
}

// ============================================================================
// FETCH
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum SectionKind {
    Full,
    Header,
    Text,
    HeaderFields(Vec<String>, bool),
}

#[derive(Debug, Clone, PartialEq)]
enum FetchItem {
    Flags,
    Uid,
    InternalDate,
    Rfc822Size,
    Envelope,
    BodyStructure,
    /// Non-extensible BODYSTRUCTURE (`BODY` without a section).
    Body,
    Rfc822,
    Rfc822Header,
    Rfc822Text,
    Section {
        peek: bool,
        /// Section spec as it appears in the response (`HEADER`, `TEXT`, ...).
        spec: String,
        kind: SectionKind,
        partial: Option<(usize, usize)>,
    },
}

impl FetchItem {
    /// Does fetching this item set `\Seen`?
    fn sets_seen(&self) -> bool {
        matches!(
            self,
            FetchItem::Rfc822 | FetchItem::Rfc822Text | FetchItem::Section { peek: false, .. }
        )
    }

    /// Does this item need the (decrypted) message content?
    fn needs_content(&self) -> bool {
        matches!(
            self,
            FetchItem::BodyStructure
                | FetchItem::Body
                | FetchItem::Rfc822
                | FetchItem::Rfc822Header
                | FetchItem::Rfc822Text
                | FetchItem::Section { .. }
        )
    }
}

fn parse_section(atom: &str) -> Option<FetchItem> {
    let upper = atom.to_ascii_uppercase();
    let (peek, rest) = match upper.strip_prefix("BODY.PEEK[") {
        Some(r) => (true, r),
        None => (false, upper.strip_prefix("BODY[")?),
    };
    let close = rest.find(']')?;
    let spec_raw = rest[..close].trim();
    let after = &rest[close + 1..];

    let partial = if after.is_empty() {
        None
    } else {
        let inner = after.strip_prefix('<')?.strip_suffix('>')?;
        let (start, len) = inner.split_once('.')?;
        Some((start.parse().ok()?, len.parse().ok()?))
    };

    let (kind, spec) = if spec_raw.is_empty() {
        (SectionKind::Full, String::new())
    } else if spec_raw == "HEADER" || spec_raw == "0" {
        (SectionKind::Header, "HEADER".to_string())
    } else if spec_raw == "TEXT" || spec_raw == "1" {
        (SectionKind::Text, spec_raw.to_string())
    } else {
        let (list, not) = spec_raw
            .strip_prefix("HEADER.FIELDS.NOT")
            .map(|l| (l, true))
            .or_else(|| spec_raw.strip_prefix("HEADER.FIELDS").map(|l| (l, false)))?;
        let toks = tokenize(list.trim())?;
        let names: Vec<String> = match toks.as_slice() {
            [Tok::List(items)] => items
                .iter()
                .map(|t| t.as_str().map(|s| s.to_ascii_uppercase()))
                .collect::<Option<_>>()?,
            _ => return None,
        };
        let spec = format!(
            "HEADER.FIELDS{} ({})",
            if not { ".NOT" } else { "" },
            names.join(" ")
        );
        (SectionKind::HeaderFields(names, not), spec)
    };

    Some(FetchItem::Section {
        peek,
        spec,
        kind,
        partial,
    })
}

/// Parse a FETCH attribute list (a single item, a macro, or a parenthesised
/// list). Each item appears once in the result.
fn parse_fetch_items(toks: &[Tok]) -> Option<Vec<FetchItem>> {
    let atoms: Vec<&Tok> = match toks {
        [Tok::List(items)] => items.iter().collect(),
        items => items.iter().collect(),
    };
    if atoms.is_empty() {
        return None;
    }
    let mut out: Vec<FetchItem> = Vec::new();
    let push = |item: FetchItem, out: &mut Vec<FetchItem>| {
        if !out.contains(&item) {
            out.push(item);
        }
    };
    for tok in atoms {
        let Tok::Atom(atom) = tok else {
            return None;
        };
        match atom.to_ascii_uppercase().as_str() {
            "ALL" => {
                for i in [
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                    FetchItem::Envelope,
                ] {
                    push(i, &mut out);
                }
            }
            "FAST" => {
                for i in [
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                ] {
                    push(i, &mut out);
                }
            }
            "FULL" => {
                for i in [
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                    FetchItem::Envelope,
                    FetchItem::Body,
                ] {
                    push(i, &mut out);
                }
            }
            "FLAGS" => push(FetchItem::Flags, &mut out),
            "UID" => push(FetchItem::Uid, &mut out),
            "INTERNALDATE" => push(FetchItem::InternalDate, &mut out),
            "RFC822.SIZE" => push(FetchItem::Rfc822Size, &mut out),
            "ENVELOPE" => push(FetchItem::Envelope, &mut out),
            "BODYSTRUCTURE" => push(FetchItem::BodyStructure, &mut out),
            "BODY" => push(FetchItem::Body, &mut out),
            "RFC822" => push(FetchItem::Rfc822, &mut out),
            "RFC822.HEADER" => push(FetchItem::Rfc822Header, &mut out),
            "RFC822.TEXT" => push(FetchItem::Rfc822Text, &mut out),
            _ => push(parse_section(atom)?, &mut out),
        }
    }
    Some(out)
}

/// The exact octet range `<start.len>` of `data` (clamped to its length).
fn apply_partial(data: &[u8], partial: Option<(usize, usize)>) -> &[u8] {
    let Some((start, len)) = partial else {
        return data;
    };
    let a = start.min(data.len());
    let b = a.saturating_add(len).min(data.len());
    &data[a..b]
}

/// Append an IMAP literal (`{n}\r\n` followed by the raw octets).
fn push_literal(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(format!("{{{}}}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
}

/// Build one `* n FETCH (...)` response. `content` is the (decrypted) raw
/// message and must be provided when any item needs it. `size` is the
/// RFC822.SIZE to report (`Storage::display_size`, so it matches what a body
/// fetch sends).
fn build_fetch_response(
    seq: usize,
    email: &Email,
    content: Option<&str>,
    size: usize,
    items: &[FetchItem],
) -> Vec<u8> {
    let content = content.unwrap_or(&email.raw);
    let (header, text) = split_message(content);
    let mut out = format!("* {} FETCH (", seq).into_bytes();

    for (n, item) in items.iter().enumerate() {
        if n > 0 {
            out.push(b' ');
        }
        match item {
            FetchItem::Flags => out
                .extend_from_slice(format!("FLAGS ({})", flags_string(&email.flags())).as_bytes()),
            FetchItem::Uid => out.extend_from_slice(format!("UID {}", email.uid).as_bytes()),
            FetchItem::InternalDate => out.extend_from_slice(
                format!(
                    "INTERNALDATE \"{}\"",
                    email.received_at.format("%d-%b-%Y %H:%M:%S %z")
                )
                .as_bytes(),
            ),
            FetchItem::Rfc822Size => {
                out.extend_from_slice(format!("RFC822.SIZE {}", size).as_bytes())
            }
            FetchItem::Envelope => {
                out.extend_from_slice(format!("ENVELOPE {}", envelope(email)).as_bytes())
            }
            FetchItem::BodyStructure => out
                .extend_from_slice(format!("BODYSTRUCTURE {}", body_structure(content)).as_bytes()),
            FetchItem::Body => {
                out.extend_from_slice(format!("BODY {}", body_structure(content)).as_bytes())
            }
            FetchItem::Rfc822 => {
                out.extend_from_slice(b"RFC822 ");
                push_literal(&mut out, content.as_bytes());
            }
            FetchItem::Rfc822Header => {
                out.extend_from_slice(b"RFC822.HEADER ");
                push_literal(&mut out, header.as_bytes());
            }
            FetchItem::Rfc822Text => {
                out.extend_from_slice(b"RFC822.TEXT ");
                push_literal(&mut out, text.as_bytes());
            }
            FetchItem::Section {
                spec,
                kind,
                partial,
                ..
            } => {
                let filtered;
                let data: &str = match kind {
                    SectionKind::Full => content,
                    SectionKind::Header => header,
                    SectionKind::Text => text,
                    SectionKind::HeaderFields(names, not) => {
                        filtered = filter_header_fields(header, names, *not);
                        &filtered
                    }
                };
                let data = apply_partial(data.as_bytes(), *partial);
                let origin = partial.map(|(s, _)| format!("<{}>", s)).unwrap_or_default();
                out.extend_from_slice(format!("BODY[{}]{} ", spec, origin).as_bytes());
                push_literal(&mut out, data);
            }
        }
    }

    out.extend_from_slice(b")\r\n");
    out
}

// ============================================================================
// STORE
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
enum StoreOp {
    Replace,
    Add,
    Remove,
}

/// Parse the STORE data item name; returns (op, silent).
fn parse_store_item(item: &str) -> Option<(StoreOp, bool)> {
    let upper = item.to_ascii_uppercase();
    let (op, rest) = if let Some(r) = upper.strip_prefix('+') {
        (StoreOp::Add, r.to_string())
    } else if let Some(r) = upper.strip_prefix('-') {
        (StoreOp::Remove, r.to_string())
    } else {
        (StoreOp::Replace, upper)
    };
    match rest.as_str() {
        "FLAGS" => Some((op, false)),
        "FLAGS.SILENT" => Some((op, true)),
        _ => None,
    }
}

/// Parse a flag list into a mask of the system flags we store (unknown flags
/// and keywords are ignored; `\Recent` cannot be stored).
fn parse_flag_mask(toks: &[Tok]) -> Option<EmailFlags> {
    let flags: Vec<&Tok> = match toks {
        [Tok::List(items)] => items.iter().collect(),
        items => items.iter().collect(),
    };
    let mut mask = EmailFlags::default();
    for tok in flags {
        let Tok::Atom(flag) = tok else {
            return None;
        };
        match flag.to_ascii_lowercase().as_str() {
            "\\seen" => mask.seen = true,
            "\\deleted" => mask.deleted = true,
            "\\flagged" => mask.flagged = true,
            "\\answered" => mask.answered = true,
            "\\draft" => mask.draft = true,
            _ => {}
        }
    }
    Some(mask)
}

fn apply_store(flags: &mut EmailFlags, op: StoreOp, mask: &EmailFlags) {
    let apply = |current: &mut bool, requested: bool| match op {
        StoreOp::Replace => *current = requested,
        StoreOp::Add => *current |= requested,
        StoreOp::Remove => *current &= !requested,
    };
    apply(&mut flags.seen, mask.seen);
    apply(&mut flags.deleted, mask.deleted);
    apply(&mut flags.flagged, mask.flagged);
    apply(&mut flags.answered, mask.answered);
    apply(&mut flags.draft, mask.draft);
}

// ============================================================================
// SEARCH
// ============================================================================

#[derive(Debug, Clone)]
enum SearchKey {
    All,
    Flag(fn(&EmailFlags) -> bool, bool),
    Header(String, String),
    Body(String),
    Text(String),
    Since(NaiveDate),
    Before(NaiveDate),
    On(NaiveDate),
    SentSince(NaiveDate),
    SentBefore(NaiveDate),
    SentOn(NaiveDate),
    Larger(usize),
    Smaller(usize),
    Uid(Vec<(u32, u32)>),
    Seq(Vec<(u32, u32)>),
    Not(Box<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
    And(Vec<SearchKey>),
    /// Matches nothing (e.g. RECENT: this server never reports \Recent).
    None,
}

struct SearchLimits {
    max_seq: u32,
    max_uid: u32,
}

fn parse_search_date(tok: Option<&Tok>) -> Result<NaiveDate, String> {
    let s = tok
        .and_then(|t| t.as_str())
        .ok_or_else(|| "missing date".to_string())?;
    NaiveDate::parse_from_str(s, "%d-%b-%Y").map_err(|_| format!("invalid date: {}", s))
}

fn parse_search_keys(toks: &[Tok], limits: &SearchLimits) -> Result<Vec<SearchKey>, String> {
    parse_search_keys_at(toks, limits, 0)
}

fn parse_search_keys_at(
    toks: &[Tok],
    limits: &SearchLimits,
    depth: usize,
) -> Result<Vec<SearchKey>, String> {
    let mut pos = 0;
    let mut keys = Vec::new();
    while pos < toks.len() {
        keys.push(parse_search_key(toks, &mut pos, limits, depth)?);
    }
    Ok(keys)
}

/// Parse one search key. `depth` counts enclosing NOT / OR / parenthesis
/// levels and is capped at `MAX_SEARCH_DEPTH`, which also bounds the
/// recursion of `eval_search`, `needs_content` and `Drop` on the result.
fn parse_search_key(
    toks: &[Tok],
    pos: &mut usize,
    limits: &SearchLimits,
    depth: usize,
) -> Result<SearchKey, String> {
    let tok = toks.get(*pos).ok_or("missing search key")?;
    *pos += 1;
    let nested = || -> Result<usize, String> {
        if depth >= MAX_SEARCH_DEPTH {
            Err("search criteria nested too deeply".to_string())
        } else {
            Ok(depth + 1)
        }
    };
    let atom = match tok {
        Tok::List(items) => {
            return Ok(SearchKey::And(parse_search_keys_at(
                items,
                limits,
                nested()?,
            )?));
        }
        Tok::Str(s) => return Err(format!("unexpected string: {}", s)),
        Tok::Atom(a) => a.clone(),
    };
    let string_arg = |pos: &mut usize| -> Result<String, String> {
        let s = toks
            .get(*pos)
            .and_then(|t| t.as_str())
            .ok_or_else(|| format!("{} needs an argument", atom))?
            .to_string();
        *pos += 1;
        Ok(s)
    };
    let upper = atom.to_ascii_uppercase();
    let key = match upper.as_str() {
        "ALL" => SearchKey::All,
        "SEEN" => SearchKey::Flag(|f| f.seen, true),
        "UNSEEN" => SearchKey::Flag(|f| f.seen, false),
        // NEW = RECENT UNSEEN; this server never reports \Recent.
        "NEW" => SearchKey::None,
        "OLD" => SearchKey::All,
        "RECENT" => SearchKey::None,
        "DELETED" => SearchKey::Flag(|f| f.deleted, true),
        "UNDELETED" => SearchKey::Flag(|f| f.deleted, false),
        "FLAGGED" => SearchKey::Flag(|f| f.flagged, true),
        "UNFLAGGED" => SearchKey::Flag(|f| f.flagged, false),
        "ANSWERED" => SearchKey::Flag(|f| f.answered, true),
        "UNANSWERED" => SearchKey::Flag(|f| f.answered, false),
        "DRAFT" => SearchKey::Flag(|f| f.draft, true),
        "UNDRAFT" => SearchKey::Flag(|f| f.draft, false),
        "FROM" | "TO" | "CC" | "BCC" | "SUBJECT" => {
            SearchKey::Header(upper.clone(), string_arg(pos)?)
        }
        "HEADER" => {
            let name = string_arg(pos)?;
            SearchKey::Header(name.to_ascii_uppercase(), string_arg(pos)?)
        }
        "BODY" => SearchKey::Body(string_arg(pos)?),
        "TEXT" => SearchKey::Text(string_arg(pos)?),
        "SINCE" | "BEFORE" | "ON" | "SENTSINCE" | "SENTBEFORE" | "SENTON" => {
            let date = parse_search_date(toks.get(*pos))?;
            *pos += 1;
            match upper.as_str() {
                "SINCE" => SearchKey::Since(date),
                "BEFORE" => SearchKey::Before(date),
                "ON" => SearchKey::On(date),
                "SENTSINCE" => SearchKey::SentSince(date),
                "SENTBEFORE" => SearchKey::SentBefore(date),
                _ => SearchKey::SentOn(date),
            }
        }
        "LARGER" | "SMALLER" => {
            let n: usize = string_arg(pos)?
                .parse()
                .map_err(|_| format!("{} needs a number", upper))?;
            if upper == "LARGER" {
                SearchKey::Larger(n)
            } else {
                SearchKey::Smaller(n)
            }
        }
        "UID" => {
            let set = string_arg(pos)?;
            SearchKey::Uid(parse_set(&set, limits.max_uid).ok_or("invalid UID set")?)
        }
        "NOT" => SearchKey::Not(Box::new(parse_search_key(toks, pos, limits, nested()?)?)),
        "OR" => {
            let d = nested()?;
            let a = parse_search_key(toks, pos, limits, d)?;
            let b = parse_search_key(toks, pos, limits, d)?;
            SearchKey::Or(Box::new(a), Box::new(b))
        }
        _ if atom.starts_with(|c: char| c.is_ascii_digit() || c == '*') => {
            SearchKey::Seq(parse_set(&atom, limits.max_seq).ok_or("invalid sequence set")?)
        }
        _ => return Err(format!("unsupported search key: {}", atom)),
    };
    Ok(key)
}

fn needs_content(key: &SearchKey) -> bool {
    match key {
        SearchKey::Body(_) | SearchKey::Text(_) => true,
        SearchKey::Not(k) => needs_content(k),
        SearchKey::Or(a, b) => needs_content(a) || needs_content(b),
        SearchKey::And(keys) => keys.iter().any(needs_content),
        _ => false,
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

struct SearchMsg<'a> {
    seq: u32,
    email: &'a Email,
    content: Option<&'a str>,
}

fn sent_date(email: &Email) -> NaiveDate {
    email
        .get_header("Date")
        .and_then(|d| chrono::DateTime::parse_from_rfc2822(d).ok())
        .map(|d| d.date_naive())
        .unwrap_or_else(|| email.received_at.date_naive())
}

fn eval_search(key: &SearchKey, msg: &SearchMsg) -> bool {
    let email = msg.email;
    let internal = email.received_at.date_naive();
    match key {
        SearchKey::All => true,
        SearchKey::None => false,
        SearchKey::Flag(get, want) => get(&email.flags()) == *want,
        SearchKey::Header(name, value) => {
            let header = match name.as_str() {
                "FROM" => email.get_header("From"),
                "TO" => email.get_header("To"),
                "CC" => email.get_header("Cc"),
                "BCC" => email.get_header("Bcc"),
                "SUBJECT" => email.get_header("Subject"),
                other => email.get_header(other),
            };
            let envelope_match = name == "FROM" && contains_ci(&email.from, value);
            envelope_match
                || match header {
                    Some(h) => value.is_empty() || contains_ci(h, value),
                    None => false,
                }
        }
        SearchKey::Body(s) => {
            let content = msg.content.unwrap_or(&email.raw);
            contains_ci(split_message(content).1, s)
        }
        SearchKey::Text(s) => contains_ci(msg.content.unwrap_or(&email.raw), s),
        SearchKey::Since(d) => internal >= *d,
        SearchKey::Before(d) => internal < *d,
        SearchKey::On(d) => internal == *d,
        SearchKey::SentSince(d) => sent_date(email) >= *d,
        SearchKey::SentBefore(d) => sent_date(email) < *d,
        SearchKey::SentOn(d) => sent_date(email) == *d,
        SearchKey::Larger(n) => email.size > *n,
        SearchKey::Smaller(n) => email.size < *n,
        SearchKey::Uid(ranges) => in_set(email.uid, ranges),
        SearchKey::Seq(ranges) => in_set(msg.seq, ranges),
        SearchKey::Not(k) => !eval_search(k, msg),
        SearchKey::Or(a, b) => eval_search(a, msg) || eval_search(b, msg),
        SearchKey::And(keys) => keys.iter().all(|k| eval_search(k, msg)),
    }
}

// ============================================================================
// Session helpers
// ============================================================================

/// Log in; on failure returns the text after `<tag> NO ` (a response code
/// and message). `failed` is the generic message for bad credentials.
async fn do_login(
    session: &mut ImapSession,
    storage: &Storage,
    username: &str,
    password: &str,
    failed: &str,
) -> Result<(), String> {
    match storage
        .login(username, password, &session.peer_ip, "IMAP", session.tls)
        .await
    {
        Ok(outcome) => {
            session.state = ImapState::Authenticated;
            if let Some(generation) = outcome.key_generation {
                session.lease.hold(outcome.username.clone(), generation);
            }
            session.username = Some(outcome.username);
            Ok(())
        }
        // RFC 5530: the password is correct but has expired.
        Err(e) if e.is_password_change_required() => Err(format!(
            "[EXPIRED] {}",
            crate::config::password_change_message()
        )),
        // RFC 5530: the server cannot check the credentials right now.
        Err(AuthError::Temporary(e)) => {
            tracing::warn!(
                "IMAP login for {} from {} failed temporarily: {}",
                username,
                session.peer_ip,
                e
            );
            Err("[UNAVAILABLE] Authentication temporarily unavailable; try again later".to_string())
        }
        Err(e) => {
            tracing::info!(
                "IMAP login failed for {} from {}: {}",
                username,
                session.peer_ip,
                e
            );
            Err(format!("[AUTHENTICATIONFAILED] {}", failed))
        }
    }
}

/// Bring the snapshot up to date: report messages that disappeared (EXPUNGE,
/// highest sequence number first) and new arrivals (EXISTS).
fn refresh_selected(sel: &mut Selected, meta: &[MessageMeta]) -> String {
    let mut out = String::new();
    let current: HashSet<&str> = meta.iter().map(|m| m.id.as_str()).collect();
    for i in (0..sel.msgs.len()).rev() {
        if !current.contains(sel.msgs[i].id.as_str()) {
            out.push_str(&format!("* {} EXPUNGE\r\n", i + 1));
            sel.msgs.remove(i);
        }
    }
    let known: HashSet<String> = sel.msgs.iter().map(|m| m.id.clone()).collect();
    let before = sel.msgs.len();
    for m in meta {
        if !known.contains(&m.id) {
            sel.msgs.push(SelMsg {
                id: m.id.clone(),
                uid: m.uid,
            });
        }
    }
    if sel.msgs.len() != before {
        out.push_str(&format!("* {} EXISTS\r\n", sel.msgs.len()));
    }
    out
}

async fn refresh(session: &mut ImapSession, storage: &Storage) -> String {
    let user = session.user().to_string();
    let Some(sel) = session.selected.as_mut() else {
        return String::new();
    };
    match storage.message_meta(&user).await {
        Some(meta) => refresh_selected(sel, &meta),
        None => String::new(),
    }
}

async fn handle_authenticate<R, W>(
    tag: &str,
    args: &str,
    session: &mut ImapSession,
    storage: &Storage,
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if session.state != ImapState::NotAuthenticated {
        return Ok(Some(format!("{} BAD Already authenticated\r\n", tag)));
    }
    // Before any `+` continuation, and before an initial response is decoded.
    if !session.secure() {
        return Ok(Some(format!("{} {}\r\n", tag, PRIVACY_REQUIRED_REPLY)));
    }
    let mut words = args.split_whitespace();
    let mechanism = words.next().unwrap_or("").to_ascii_uppercase();
    if mechanism != "PLAIN" {
        return Ok(Some(format!(
            "{} NO Unsupported authentication mechanism\r\n",
            tag
        )));
    }

    let response = match words.next() {
        Some(initial) => initial.to_string(),
        None => {
            write_all_timeout(writer, b"+ \r\n", session.timeouts.write).await?;
            let read = tokio::time::timeout(
                session.read_timeout(),
                read_line_limited(reader, MAX_COMMAND),
            )
            .await;
            let Ok(read) = read else {
                return Ok(None);
            };
            match read? {
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed during AUTHENTICATE",
                    ));
                }
                Some(Err(())) => return Ok(Some(format!("{} BAD Response too long\r\n", tag))),
                Some(Ok(line)) => line.trim().to_string(),
            }
        }
    };
    if response == "*" {
        return Ok(Some(format!("{} BAD AUTHENTICATE cancelled\r\n", tag)));
    }
    let Some((username, password)) = decode_auth_plain(&response) else {
        return Ok(Some(format!("{} BAD Invalid SASL PLAIN response\r\n", tag)));
    };
    let reply = match do_login(
        session,
        storage,
        &username,
        &password,
        "Authentication failed",
    )
    .await
    {
        Ok(()) => format!(
            "{} OK [CAPABILITY {}] AUTHENTICATE completed\r\n",
            tag,
            session.capabilities()
        ),
        Err(no) => format!("{} NO {}\r\n", tag, no),
    };
    Ok(Some(reply))
}

/// Run IDLE until the client sends DONE. Returns `None` if the connection
/// closed while idling, or after `* BYE` once the IDLE deadline passed.
async fn handle_idle<R, W>(
    tag: &str,
    session: &mut ImapSession,
    storage: &Storage,
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if session.state == ImapState::NotAuthenticated {
        return Ok(Some(format!("{} NO Not authenticated\r\n", tag)));
    }
    // Every write below is bounded by the IDLE deadline too, so a client that
    // stops reading cannot keep the session past it.
    let deadline = tokio::time::Instant::now() + session.timeouts.idle_max;
    write_all_until(writer, b"+ idling\r\n", deadline).await?;

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                // Best effort: succeeds only if the client has buffer room.
                write_all_until(writer, AUTOLOGOUT, deadline).await?;
                return Ok(None);
            }
            ready = reader.fill_buf() => {
                if ready?.is_empty() {
                    return Ok(None);
                }
                let read = tokio::time::timeout_at(
                    deadline,
                    read_line_limited(reader, MAX_COMMAND),
                )
                .await;
                let Ok(read) = read else {
                    write_all_until(writer, AUTOLOGOUT, deadline).await?;
                    return Ok(None);
                };
                return match read? {
                    None => Ok(None),
                    Some(Ok(line)) if line.trim().eq_ignore_ascii_case("DONE") => {
                        Ok(Some(format!("{} OK IDLE terminated\r\n", tag)))
                    }
                    Some(_) => Ok(Some(format!("{} BAD Expected DONE\r\n", tag))),
                };
            }
            _ = tokio::time::sleep(session.timeouts.idle_poll) => {
                let updates = refresh(session, storage).await;
                if !updates.is_empty() {
                    write_all_until(writer, updates.as_bytes(), deadline).await?;
                }
            }
        }
    }
}

// ============================================================================
// Command processing
// ============================================================================

async fn process_imap_command(
    tag: &str,
    cmd: &str,
    args: &str,
    session: &mut ImapSession,
    storage: &Storage,
) -> Vec<u8> {
    // Reject commands that need authentication before parsing their
    // arguments; unauthenticated input is tokenized with minimal nesting.
    let needs_auth = !matches!(cmd, "CAPABILITY" | "NOOP" | "LOGOUT" | "LOGIN");
    let authenticated = session.state != ImapState::NotAuthenticated;
    if needs_auth && !authenticated {
        return format!("{} NO Not authenticated\r\n", tag).into();
    }
    // Refuse plaintext credentials before the arguments are even parsed.
    if cmd == "LOGIN" && !authenticated && !session.secure() {
        return format!("{} {}\r\n", tag, PRIVACY_REQUIRED_REPLY).into();
    }
    let max_depth = if authenticated { MAX_TOKEN_DEPTH } else { 1 };
    let Some(toks) = tokenize_with_depth(args, max_depth) else {
        return format!("{} BAD Invalid arguments\r\n", tag).into();
    };

    let needs_selected = matches!(
        cmd,
        "CLOSE" | "UNSELECT" | "EXPUNGE" | "SEARCH" | "FETCH" | "STORE" | "COPY" | "UID" | "CHECK"
    );
    if needs_selected && session.state != ImapState::Selected {
        return format!("{} NO No mailbox selected\r\n", tag).into();
    }

    match cmd {
        "FETCH" => do_fetch(tag, &toks, false, session, storage).await,
        "UID" => {
            let Some(sub) = toks.first().and_then(|t| t.as_str()) else {
                return format!("{} BAD Missing UID command\r\n", tag).into();
            };
            let rest = &toks[1..];
            match sub.to_ascii_uppercase().as_str() {
                "FETCH" => do_fetch(tag, rest, true, session, storage).await,
                "SEARCH" => do_search(tag, rest, true, session, storage).await.into(),
                "STORE" => do_store(tag, rest, true, session, storage).await.into(),
                "COPY" => format!("{} NO [CANNOT] COPY not supported\r\n", tag).into(),
                _ => format!("{} BAD Unknown UID command\r\n", tag).into(),
            }
        }
        _ => process_text_command(tag, cmd, &toks, session, storage)
            .await
            .into(),
    }
}

/// Commands whose responses are always text.
async fn process_text_command(
    tag: &str,
    cmd: &str,
    toks: &[Tok],
    session: &mut ImapSession,
    storage: &Storage,
) -> String {
    match cmd {
        "CAPABILITY" => format!(
            "* CAPABILITY {}\r\n{} OK CAPABILITY completed\r\n",
            session.capabilities(),
            tag
        ),
        "NOOP" | "CHECK" => {
            let updates = refresh(session, storage).await;
            format!("{}{} OK {} completed\r\n", updates, tag, cmd)
        }
        "LOGOUT" => format!(
            "* BYE kiss-mail server logging out\r\n{} OK LOGOUT completed\r\n",
            tag
        ),
        "LOGIN" => {
            if session.state != ImapState::NotAuthenticated {
                return format!("{} BAD Already authenticated\r\n", tag);
            }
            let (Some(username), Some(password)) = (
                toks.first().and_then(|t| t.as_str()),
                toks.get(1).and_then(|t| t.as_str()),
            ) else {
                return format!("{} BAD Missing arguments\r\n", tag);
            };
            match do_login(session, storage, username, password, "LOGIN failed").await {
                Ok(()) => format!(
                    "{} OK [CAPABILITY {}] LOGIN completed\r\n",
                    tag,
                    session.capabilities()
                ),
                Err(no) => format!("{} NO {}\r\n", tag, no),
            }
        }
        "SELECT" | "EXAMINE" => do_select(tag, cmd, toks, session, storage).await,
        "LIST" | "LSUB" => {
            let pattern = toks.get(1).and_then(|t| t.as_str()).unwrap_or("");
            let mut response = String::new();
            if pattern.is_empty() {
                if cmd == "LIST" {
                    response.push_str("* LIST (\\Noselect) \"/\" \"\"\r\n");
                }
            } else if mailbox_matches(pattern, "INBOX") {
                response.push_str(&format!("* {} (\\HasNoChildren) \"/\" \"INBOX\"\r\n", cmd));
            }
            response.push_str(&format!("{} OK {} completed\r\n", tag, cmd));
            response
        }
        "STATUS" => do_status(tag, toks, session, storage).await,
        "CREATE" | "DELETE" | "RENAME" | "SUBSCRIBE" | "UNSUBSCRIBE" | "APPEND" => {
            // We only support INBOX
            format!("{} NO Operation not supported\r\n", tag)
        }
        "CLOSE" | "UNSELECT" => {
            let read_only = session.selected.as_ref().is_none_or(|s| s.read_only);
            if cmd == "CLOSE" && !read_only {
                // Silently expunge deleted messages
                expunge_selected(session, storage).await;
            }
            session.state = ImapState::Authenticated;
            session.selected = None;
            format!("{} OK {} completed\r\n", tag, cmd)
        }
        "EXPUNGE" => {
            if session.selected.as_ref().is_some_and(|s| s.read_only) {
                return format!("{} NO Mailbox is read-only\r\n", tag);
            }
            let mut response = expunge_selected(session, storage).await;
            response.push_str(&refresh(session, storage).await);
            response.push_str(&format!("{} OK EXPUNGE completed\r\n", tag));
            response
        }
        "SEARCH" => do_search(tag, toks, false, session, storage).await,
        "STORE" => do_store(tag, toks, false, session, storage).await,
        "COPY" => format!("{} NO [CANNOT] COPY not supported\r\n", tag),
        _ => format!("{} BAD Unknown command\r\n", tag),
    }
}

/// Snapshot of the user's INBOX: message metadata, UIDVALIDITY and UIDNEXT.
/// `None` if the user has no mailbox.
async fn mailbox_status(storage: &Storage, user: &str) -> Option<(Vec<MessageMeta>, u32, u32)> {
    let meta = storage.message_meta(user).await?;
    let (uidvalidity, uidnext) = storage
        .with_mailbox(user, |mb| (mb.uidvalidity.max(1), mb.uidnext.max(1)))
        .await
        .unwrap_or((1, 1));
    Some((meta, uidvalidity, uidnext))
}

/// SELECT / EXAMINE.
async fn do_select(
    tag: &str,
    cmd: &str,
    toks: &[Tok],
    session: &mut ImapSession,
    storage: &Storage,
) -> String {
    // Selecting (even unsuccessfully) deselects the current mailbox.
    session.selected = None;
    session.state = ImapState::Authenticated;

    let mailbox_name = toks.first().and_then(|t| t.as_str()).unwrap_or("");
    if !mailbox_name.eq_ignore_ascii_case("INBOX") {
        return format!("{} NO Mailbox does not exist\r\n", tag);
    }

    let user = session.user().to_string();
    let Some((meta, uidvalidity, uidnext)) = mailbox_status(storage, &user).await else {
        return format!("{} NO Mailbox does not exist\r\n", tag);
    };

    let read_only = cmd == "EXAMINE";
    let first_unseen = meta.iter().position(|m| !m.flags.seen).map(|i| i + 1);
    session.selected = Some(Selected {
        read_only,
        msgs: meta
            .iter()
            .map(|m| SelMsg {
                id: m.id.clone(),
                uid: m.uid,
            })
            .collect(),
    });
    session.state = ImapState::Selected;

    let mut response = String::new();
    response.push_str("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n");
    response.push_str(&format!("* {} EXISTS\r\n", meta.len()));
    response.push_str("* 0 RECENT\r\n");
    if read_only {
        response.push_str("* OK [PERMANENTFLAGS ()] Read-only mailbox\r\n");
    } else {
        response.push_str(
            "* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags permitted\r\n",
        );
    }
    if let Some(first_unseen) = first_unseen {
        response.push_str(&format!("* OK [UNSEEN {}] First unseen\r\n", first_unseen));
    }
    response.push_str(&format!(
        "* OK [UIDVALIDITY {}] UIDs valid\r\n",
        uidvalidity
    ));
    response.push_str(&format!(
        "* OK [UIDNEXT {}] Predicted next UID\r\n",
        uidnext
    ));
    let access = if read_only {
        "[READ-ONLY]"
    } else {
        "[READ-WRITE]"
    };
    response.push_str(&format!("{} OK {} {} completed\r\n", tag, access, cmd));
    response
}

/// STATUS.
async fn do_status(
    tag: &str,
    toks: &[Tok],
    session: &mut ImapSession,
    storage: &Storage,
) -> String {
    let mailbox_name = toks.first().and_then(|t| t.as_str()).unwrap_or("");
    if !mailbox_name.eq_ignore_ascii_case("INBOX") {
        return format!("{} NO Mailbox does not exist\r\n", tag);
    }
    let Some(Tok::List(items)) = toks.get(1) else {
        return format!("{} BAD Missing status items\r\n", tag);
    };
    let user = session.user().to_string();
    let Some((meta, uidvalidity, uidnext)) = mailbox_status(storage, &user).await else {
        return format!("{} NO Mailbox does not exist\r\n", tag);
    };
    let mut out = Vec::new();
    for item in items {
        let name = item.as_str().unwrap_or("").to_ascii_uppercase();
        let value = match name.as_str() {
            "MESSAGES" => meta.len() as u64,
            "RECENT" => 0,
            "UIDNEXT" => uidnext as u64,
            "UIDVALIDITY" => uidvalidity as u64,
            "UNSEEN" => meta.iter().filter(|m| !m.flags.seen).count() as u64,
            _ => return format!("{} BAD Unknown status item\r\n", tag),
        };
        out.push(format!("{} {}", name, value));
    }
    format!(
        "* STATUS \"INBOX\" ({})\r\n{} OK STATUS completed\r\n",
        out.join(" "),
        tag
    )
}

/// LIST wildcard matching (`*` and `%` both match anything, since there is
/// no hierarchy). Runs of wildcards are collapsed, the pattern is capped at
/// `MAX_LIST_PATTERN` bytes, and matching is iterative (O(pattern * name)).
fn mailbox_matches(pattern: &str, name: &str) -> bool {
    if pattern.len() > MAX_LIST_PATTERN {
        return false;
    }
    let mut p: Vec<u8> = Vec::with_capacity(pattern.len());
    for b in pattern.bytes() {
        let b = if b == b'%' { b'*' } else { b };
        if !(b == b'*' && p.last() == Some(&b'*')) {
            p.push(b);
        }
    }
    let n = name.as_bytes();
    let (mut pi, mut ni) = (0usize, 0usize);
    // Position of the last `*` in the pattern and the name index it matched up to.
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ni));
            pi += 1;
        } else if pi < p.len() && p[pi].eq_ignore_ascii_case(&n[ni]) {
            pi += 1;
            ni += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&b| b == b'*')
}

/// Expunge messages flagged \Deleted in the snapshot. Returns the untagged
/// EXPUNGE responses (highest sequence number first).
async fn expunge_selected(session: &mut ImapSession, storage: &Storage) -> String {
    let user = session.user().to_string();
    let Some(sel) = session.selected.as_mut() else {
        return String::new();
    };
    let meta = storage.message_meta(&user).await.unwrap_or_default();
    let in_snapshot: HashSet<&str> = sel.msgs.iter().map(|m| m.id.as_str()).collect();
    let to_remove: Vec<String> = meta
        .iter()
        .filter(|m| m.flags.deleted && in_snapshot.contains(m.id.as_str()))
        .map(|m| m.id.clone())
        .collect();
    if to_remove.is_empty() {
        return String::new();
    }
    let removed: HashSet<String> = storage
        .expunge_by_ids(&user, &to_remove)
        .await
        .into_iter()
        .collect();
    if let Err(e) = storage.save().await {
        tracing::error!("Failed to save storage after EXPUNGE: {}", e);
    }

    let mut out = String::new();
    for i in (0..sel.msgs.len()).rev() {
        if removed.contains(&sel.msgs[i].id) {
            out.push_str(&format!("* {} EXPUNGE\r\n", i + 1));
            sel.msgs.remove(i);
        }
    }
    out
}

async fn do_fetch(
    tag: &str,
    toks: &[Tok],
    uid_mode: bool,
    session: &mut ImapSession,
    storage: &Storage,
) -> Vec<u8> {
    let user = session.user().to_string();
    let Some(sel) = session.selected.as_ref() else {
        return format!("{} NO No mailbox selected\r\n", tag).into();
    };
    let (Some(set), Some(mut items)) = (
        toks.first().and_then(|t| t.as_str()),
        parse_fetch_items(toks.get(1..).unwrap_or(&[])),
    ) else {
        return format!("{} BAD Invalid FETCH arguments\r\n", tag).into();
    };
    if uid_mode && !items.contains(&FetchItem::Uid) {
        items.insert(0, FetchItem::Uid);
    }
    let Some(indices) = resolve_set(set, sel, uid_mode) else {
        return format!("{} BAD Invalid sequence set\r\n", tag).into();
    };

    let ids: Vec<String> = indices.iter().map(|&i| sel.msgs[i].id.clone()).collect();
    let mut emails = storage.get_emails_by_ids(&user, &ids).await;

    // Non-PEEK body fetches set \Seen (not in read-only mode).
    let sets_seen = !sel.read_only && items.iter().any(FetchItem::sets_seen);
    let mut newly_seen = HashSet::new();
    if sets_seen {
        let unseen: Vec<String> = emails
            .values()
            .filter(|e| !e.seen)
            .map(|e| e.id.clone())
            .collect();
        if !unseen.is_empty() {
            storage
                .update_emails_by_ids(&user, &unseen, |e| e.seen = true)
                .await;
            for id in &unseen {
                if let Some(e) = emails.get_mut(id) {
                    e.seen = true;
                }
            }
            newly_seen.extend(unseen);
            if let Err(e) = storage.save().await {
                tracing::error!("Failed to save storage after FETCH: {}", e);
            }
        }
    }

    let wants_content = items.iter().any(FetchItem::needs_content);
    // RFC822.SIZE of an encrypted message must match what would be sent
    // (decrypted message or the undecryptable placeholder).
    let wants_size = items.contains(&FetchItem::Rfc822Size);
    let mut response = Vec::new();
    for &i in &indices {
        let id = &sel.msgs[i].id;
        let Some(email) = emails.get(id) else {
            continue; // removed by another session
        };
        let content = if wants_content || (wants_size && email.is_encrypted()) {
            Some(storage.email_content(&user, email).await)
        } else {
            None
        };
        let mut msg_items = items.clone();
        if newly_seen.contains(id) && !msg_items.contains(&FetchItem::Flags) {
            msg_items.push(FetchItem::Flags);
        }
        let size = storage.display_size(email, content.as_deref().unwrap_or(""));
        response.extend_from_slice(&build_fetch_response(
            i + 1,
            email,
            content.as_deref(),
            size,
            &msg_items,
        ));
    }

    response.extend_from_slice(
        format!(
            "{} OK {}FETCH completed\r\n",
            tag,
            if uid_mode { "UID " } else { "" }
        )
        .as_bytes(),
    );
    response
}

async fn do_store(
    tag: &str,
    toks: &[Tok],
    uid_mode: bool,
    session: &mut ImapSession,
    storage: &Storage,
) -> String {
    let user = session.user().to_string();
    let Some(sel) = session.selected.as_ref() else {
        return format!("{} NO No mailbox selected\r\n", tag);
    };
    if sel.read_only {
        return format!("{} NO Mailbox is read-only\r\n", tag);
    }
    let (Some(set), Some(item)) = (
        toks.first().and_then(|t| t.as_str()),
        toks.get(1).and_then(|t| t.as_str()),
    ) else {
        return format!("{} BAD Missing arguments\r\n", tag);
    };
    let Some((op, silent)) = parse_store_item(item) else {
        return format!("{} BAD Invalid STORE data item\r\n", tag);
    };
    let Some(mask) = parse_flag_mask(toks.get(2..).unwrap_or(&[])) else {
        return format!("{} BAD Invalid flag list\r\n", tag);
    };
    let Some(indices) = resolve_set(set, sel, uid_mode) else {
        return format!("{} BAD Invalid sequence set\r\n", tag);
    };

    let ids: Vec<String> = indices.iter().map(|&i| sel.msgs[i].id.clone()).collect();
    let updated: HashMap<String, EmailFlags> = storage
        .update_emails_by_ids(&user, &ids, |e| {
            let mut flags = e.flags();
            apply_store(&mut flags, op, &mask);
            e.set_flags(&flags);
        })
        .await;
    if let Err(e) = storage.save().await {
        tracing::error!("Failed to save storage after STORE: {}", e);
    }

    let mut response = String::new();
    if !silent {
        for &i in &indices {
            let msg = &sel.msgs[i];
            if let Some(flags) = updated.get(&msg.id) {
                if uid_mode {
                    response.push_str(&format!(
                        "* {} FETCH (UID {} FLAGS ({}))\r\n",
                        i + 1,
                        msg.uid,
                        flags_string(flags)
                    ));
                } else {
                    response.push_str(&format!(
                        "* {} FETCH (FLAGS ({}))\r\n",
                        i + 1,
                        flags_string(flags)
                    ));
                }
            }
        }
    }
    response.push_str(&format!(
        "{} OK {}STORE completed\r\n",
        tag,
        if uid_mode { "UID " } else { "" }
    ));
    response
}

async fn do_search(
    tag: &str,
    toks: &[Tok],
    uid_mode: bool,
    session: &mut ImapSession,
    storage: &Storage,
) -> String {
    let user = session.user().to_string();
    let Some(sel) = session.selected.as_ref() else {
        return format!("{} NO No mailbox selected\r\n", tag);
    };

    let mut toks = toks;
    if toks
        .first()
        .and_then(|t| t.as_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("CHARSET"))
    {
        let charset = toks.get(1).and_then(|t| t.as_str()).unwrap_or("");
        if !charset.eq_ignore_ascii_case("UTF-8") && !charset.eq_ignore_ascii_case("US-ASCII") {
            return format!(
                "{} NO [BADCHARSET (UTF-8 US-ASCII)] Unsupported charset\r\n",
                tag
            );
        }
        toks = toks.get(2..).unwrap_or(&[]);
    }
    if toks.is_empty() {
        return format!("{} BAD Missing search criteria\r\n", tag);
    }

    let limits = SearchLimits {
        max_seq: sel.msgs.len() as u32,
        max_uid: sel.max_uid(),
    };
    let key = match parse_search_keys(toks, &limits) {
        Ok(keys) => SearchKey::And(keys),
        Err(e) => return format!("{} BAD {}\r\n", tag, e),
    };

    let ids: Vec<String> = sel.msgs.iter().map(|m| m.id.clone()).collect();
    let emails = storage.get_emails_by_ids(&user, &ids).await;
    let wants_content = needs_content(&key);

    let mut results = Vec::new();
    for (i, msg) in sel.msgs.iter().enumerate() {
        let Some(email) = emails.get(&msg.id) else {
            continue;
        };
        let content = if wants_content {
            Some(storage.email_content(&user, email).await)
        } else {
            None
        };
        let search_msg = SearchMsg {
            seq: i as u32 + 1,
            email,
            content: content.as_deref(),
        };
        if eval_search(&key, &search_msg) {
            results.push(if uid_mode { msg.uid as usize } else { i + 1 });
        }
    }

    let list: String = results.iter().map(|n| format!(" {}", n)).collect();
    format!(
        "* SEARCH{}\r\n{} OK {}SEARCH completed\r\n",
        list,
        tag,
        if uid_mode { "UID " } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetch_str(seq: usize, email: &Email, content: Option<&str>, items: &[FetchItem]) -> String {
        String::from_utf8(build_fetch_response(seq, email, content, email.size, items)).unwrap()
    }

    async fn cmd(
        tag: &str,
        command: &str,
        args: &str,
        session: &mut ImapSession,
        storage: &Storage,
    ) -> String {
        String::from_utf8_lossy(&process_imap_command(tag, command, args, session, storage).await)
            .into_owned()
    }

    fn sample_email() -> Email {
        let mut e = Email::new(
            "sender@example.com".to_string(),
            vec!["rcpt@example.com".to_string()],
            "From: \"Alice \\\"A\\\"\" <alice@example.com>\r\nTo: bob@example.com, Carol <carol@example.org>\r\nSubject: Hello \"world\"\r\nDate: Mon, 7 Feb 1994 21:52:25 -0800\r\n\r\nLine one\r\nLine two\r\n"
                .to_string(),
        );
        e.uid = 42;
        e
    }

    #[test]
    fn tokenizer_handles_sections_and_quotes() {
        let toks = tokenize("1:* (FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO)] UID)").unwrap();
        assert_eq!(toks[0], Tok::Atom("1:*".to_string()));
        let Tok::List(items) = &toks[1] else {
            panic!("expected list")
        };
        assert_eq!(items.len(), 3);
        assert_eq!(
            items[1],
            Tok::Atom("BODY.PEEK[HEADER.FIELDS (FROM TO)]".to_string())
        );

        let toks = tokenize("\"user\" \"pa ss\\\"word\"").unwrap();
        assert_eq!(toks[1], Tok::Str("pa ss\"word".to_string()));
        assert!(tokenize("(unbalanced").is_none());
    }

    #[test]
    fn literal_marker_parsing() {
        assert_eq!(
            parse_literal_marker("a LOGIN {5}"),
            Some(("a LOGIN ", 5, true))
        );
        assert_eq!(
            parse_literal_marker("a LOGIN {5+}"),
            Some(("a LOGIN ", 5, false))
        );
        assert_eq!(parse_literal_marker("a NOOP"), None);
    }

    #[test]
    fn fetch_items_macros_and_dedup() {
        let items = parse_fetch_items(&tokenize("ALL").unwrap()).unwrap();
        assert_eq!(
            items,
            vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Rfc822Size,
                FetchItem::Envelope
            ]
        );
        let items = parse_fetch_items(&tokenize("(FLAGS FLAGS UID)").unwrap()).unwrap();
        assert_eq!(items, vec![FetchItem::Flags, FetchItem::Uid]);
        assert!(parse_fetch_items(&tokenize("(FLAGS BOGUS)").unwrap()).is_none());
    }

    #[test]
    fn fetch_flags_and_size_has_no_body() {
        let email = sample_email();
        let items = parse_fetch_items(&tokenize("(FLAGS RFC822.SIZE)").unwrap()).unwrap();
        let resp = fetch_str(3, &email, None, &items);
        assert_eq!(
            resp,
            format!("* 3 FETCH (FLAGS () RFC822.SIZE {})\r\n", email.raw.len())
        );
        assert!(!resp.contains("BODY"));
        assert!(!resp.contains('{'));
    }

    #[test]
    fn fetch_sections_and_peek() {
        let email = sample_email();
        let items =
            parse_fetch_items(&tokenize("(UID BODY.PEEK[HEADER.FIELDS (SUBJECT)])").unwrap())
                .unwrap();
        assert!(!items.iter().any(FetchItem::sets_seen));
        let resp = fetch_str(1, &email, Some(&email.raw), &items);
        let expected_header = "Subject: Hello \"world\"\r\n\r\n";
        assert_eq!(
            resp,
            format!(
                "* 1 FETCH (UID 42 BODY[HEADER.FIELDS (SUBJECT)] {{{}}}\r\n{})\r\n",
                expected_header.len(),
                expected_header
            )
        );

        let items = parse_fetch_items(&tokenize("BODY[TEXT]").unwrap()).unwrap();
        assert!(items.iter().any(FetchItem::sets_seen));
        let resp = fetch_str(1, &email, Some(&email.raw), &items);
        assert!(resp.contains("BODY[TEXT] {20}\r\nLine one\r\nLine two\r\n"));

        let items = parse_fetch_items(&tokenize("BODY.PEEK[]<0.4>").unwrap()).unwrap();
        let resp = fetch_str(1, &email, Some(&email.raw), &items);
        assert!(resp.contains("BODY[]<0> {4}\r\nFrom"));
    }

    #[test]
    fn envelope_escapes_quotes() {
        let email = sample_email();
        let env = envelope(&email);
        assert!(env.contains("\"Hello \\\"world\\\"\""));
        assert!(env.contains("(\"Alice \\\"A\\\"\" NIL \"alice\" \"example.com\")"));
        assert!(env.contains(
            "((NIL NIL \"bob\" \"example.com\")(\"Carol\" NIL \"carol\" \"example.org\"))"
        ));
    }

    #[test]
    fn bodystructure_has_real_size() {
        let email = sample_email();
        let bs = body_structure(&email.raw);
        assert_eq!(
            bs,
            "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"US-ASCII\") NIL NIL \"7BIT\" 20 2)"
        );
    }

    #[test]
    fn store_flag_semantics() {
        let mut flags = EmailFlags {
            seen: true,
            ..Default::default()
        };
        let mask = parse_flag_mask(&tokenize("(\\Deleted \\Flagged)").unwrap()).unwrap();
        apply_store(&mut flags, StoreOp::Add, &mask);
        assert!(flags.seen && flags.deleted && flags.flagged);

        let mask = parse_flag_mask(&tokenize("(\\Flagged)").unwrap()).unwrap();
        apply_store(&mut flags, StoreOp::Remove, &mask);
        assert!(flags.seen && flags.deleted && !flags.flagged);

        let mask = parse_flag_mask(&tokenize("(\\Answered)").unwrap()).unwrap();
        apply_store(&mut flags, StoreOp::Replace, &mask);
        assert_eq!(
            flags,
            EmailFlags {
                answered: true,
                ..Default::default()
            }
        );

        assert_eq!(
            parse_store_item("+FLAGS.SILENT"),
            Some((StoreOp::Add, true))
        );
        assert_eq!(parse_store_item("-flags"), Some((StoreOp::Remove, false)));
        assert_eq!(parse_store_item("FLAGS"), Some((StoreOp::Replace, false)));
        assert_eq!(parse_store_item("LABELS"), None);
    }

    #[test]
    fn sequence_and_uid_sets() {
        assert_eq!(parse_set("1:3,5", 10), Some(vec![(1, 3), (5, 5)]));
        assert_eq!(parse_set("4:*", 2), Some(vec![(2, 4)]));
        assert!(parse_set("0", 5).is_none());
        assert!(parse_set("a:b", 5).is_none());

        let sel = Selected {
            read_only: false,
            msgs: vec![
                SelMsg {
                    id: "a".into(),
                    uid: 3,
                },
                SelMsg {
                    id: "b".into(),
                    uid: 7,
                },
                SelMsg {
                    id: "c".into(),
                    uid: 9,
                },
            ],
        };
        assert_eq!(resolve_set("7:*", &sel, true), Some(vec![1, 2]));
        assert_eq!(resolve_set("100:*", &sel, true), Some(vec![2]));
        assert_eq!(resolve_set("2", &sel, false), Some(vec![1]));
        assert_eq!(resolve_set("1,3", &sel, false), Some(vec![0, 2]));
    }

    #[test]
    fn search_parsing_and_eval() {
        let email = sample_email();
        let limits = SearchLimits {
            max_seq: 1,
            max_uid: 42,
        };
        let eval = |q: &str| {
            let keys = parse_search_keys(&tokenize(q).unwrap(), &limits).unwrap();
            let msg = SearchMsg {
                seq: 1,
                email: &email,
                content: Some(&email.raw),
            };
            eval_search(&SearchKey::And(keys), &msg)
        };
        assert!(eval("ALL"));
        assert!(eval("UNSEEN"));
        assert!(!eval("SEEN"));
        assert!(eval("FROM alice"));
        assert!(eval("TO CAROL"));
        assert!(eval("SUBJECT \"hello\""));
        assert!(eval("BODY \"line two\""));
        assert!(!eval("BODY Subject"));
        assert!(eval("TEXT Subject"));
        assert!(eval("UID 42"));
        assert!(!eval("UID 1:41"));
        assert!(eval("OR SEEN UNDELETED"));
        assert!(eval("NOT DELETED"));
        assert!(eval("SENTON 7-Feb-1994"));
        assert!(eval("1 (UNSEEN FROM example)"));
        assert!(parse_search_keys(&tokenize("FOO").unwrap(), &limits).is_err());
        assert!(parse_search_keys(&tokenize("SINCE notadate").unwrap(), &limits).is_err());
    }

    #[test]
    fn refresh_reports_expunges_descending_then_exists() {
        let mut sel = Selected {
            read_only: false,
            msgs: vec![
                SelMsg {
                    id: "a".into(),
                    uid: 1,
                },
                SelMsg {
                    id: "b".into(),
                    uid: 2,
                },
                SelMsg {
                    id: "c".into(),
                    uid: 3,
                },
            ],
        };
        let meta = |id: &str, uid: u32| MessageMeta {
            id: id.to_string(),
            uid,
            size: 1,
            flags: EmailFlags::default(),
        };
        let out = refresh_selected(&mut sel, &[meta("b", 2), meta("d", 4)]);
        assert_eq!(out, "* 3 EXPUNGE\r\n* 1 EXPUNGE\r\n* 2 EXISTS\r\n");
        assert_eq!(sel.msgs.len(), 2);
    }

    #[test]
    fn list_pattern_matching() {
        assert!(mailbox_matches("*", "INBOX"));
        assert!(mailbox_matches("inbox", "INBOX"));
        assert!(mailbox_matches("IN%", "INBOX"));
        assert!(!mailbox_matches("Sent", "INBOX"));
    }

    #[test]
    fn split_command_uses_token() {
        let (tag, cmd, args) = split_command("a1 logout").unwrap();
        assert_eq!((tag, cmd.as_str(), args), ("a1", "LOGOUT", ""));
        // A LOGIN whose password contains " LOGOUT" is still a LOGIN.
        let (_, cmd, _) = split_command("a2 LOGIN user \"x LOGOUT\"").unwrap();
        assert_eq!(cmd, "LOGIN");
    }

    async fn test_storage(dir: &std::path::Path) -> Arc<Storage> {
        let users = Arc::new(crate::users::UserManager::new(
            "example.com".to_string(),
            dir.to_path_buf(),
        ));
        users.create_user("bob", "password123", None).await.unwrap();
        let storage = Arc::new(Storage::new(dir.to_path_buf(), users));
        for i in 1..=3 {
            let raw = format!("Subject: m{}\r\n\r\nbody {}\r\n", i, i);
            storage
                .deliver_email("bob@example.com", Email::new("a@b".into(), vec![], raw))
                .await
                .unwrap();
        }
        storage
    }

    #[tokio::test]
    async fn session_flow_store_expunge_and_unknown_login() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let mut session = ImapSession::new("127.0.0.1".to_string(), Arc::clone(&storage));

        // Unknown user: no account gets created.
        let resp = cmd("a", "LOGIN", "nobody password123", &mut session, &storage).await;
        assert!(resp.starts_with("a NO"));
        assert!(!storage.user_exists("nobody").await);

        let resp = cmd("b", "LOGIN", "BOB password123", &mut session, &storage).await;
        assert!(resp.starts_with("b OK"), "{}", resp);

        let resp = cmd("c", "SELECT", "INBOX", &mut session, &storage).await;
        assert!(resp.contains("* 3 EXISTS"));

        let resp = cmd("d", "STORE", "2 +FLAGS (\\Deleted)", &mut session, &storage).await;
        assert!(resp.contains("* 2 FETCH (FLAGS (\\Deleted))"), "{}", resp);

        // Deleted-but-not-expunged message stays visible.
        let resp = cmd("e", "FETCH", "1:* (UID FLAGS)", &mut session, &storage).await;
        assert!(
            resp.contains("* 2 FETCH (UID 2 FLAGS (\\Deleted))"),
            "{}",
            resp
        );

        let resp = cmd("f", "UID", "FETCH 3 (FLAGS)", &mut session, &storage).await;
        assert!(resp.contains("* 3 FETCH (UID 3 FLAGS ())"), "{}", resp);

        let resp = cmd("g", "FETCH", "3 BODY[TEXT]", &mut session, &storage).await;
        assert!(resp.contains("body 3"));
        assert!(resp.contains("FLAGS (\\Seen)"));

        let resp = cmd("h", "EXPUNGE", "", &mut session, &storage).await;
        assert!(resp.starts_with("* 2 EXPUNGE\r\n"), "{}", resp);

        let resp = cmd("i", "UID", "SEARCH ALL", &mut session, &storage).await;
        assert!(resp.starts_with("* SEARCH 1 3\r\n"), "{}", resp);

        let resp = cmd("j", "EXAMINE", "INBOX", &mut session, &storage).await;
        assert!(resp.contains("[READ-ONLY]"));
        let resp = cmd("k", "STORE", "1 +FLAGS (\\Seen)", &mut session, &storage).await;
        assert!(resp.starts_with("k NO"));
    }

    #[test]
    fn tokenizer_limits_nesting_depth() {
        let deep = |n: usize| format!("{}x{}", "(".repeat(n), ")".repeat(n));
        assert!(tokenize(&deep(MAX_TOKEN_DEPTH)).is_some());
        assert!(tokenize(&deep(MAX_TOKEN_DEPTH + 1)).is_none());
        // A huge nesting attempt fails cleanly instead of overflowing the stack.
        assert!(tokenize(&deep(100_000)).is_none());
        assert!(tokenize_with_depth("(a)", 1).is_some());
        assert!(tokenize_with_depth("((a))", 1).is_none());
    }

    #[test]
    fn tokenizer_brackets_only_in_section_atoms() {
        // `[` in an ordinary atom is a plain character: the space ends it.
        let toks = tokenize("a[b c]").unwrap();
        assert_eq!(
            toks,
            vec![Tok::Atom("a[b".to_string()), Tok::Atom("c]".to_string())]
        );
        let toks = tokenize("body.peek[HEADER.FIELDS (A B)]<0.10> x").unwrap();
        assert_eq!(
            toks[0],
            Tok::Atom("body.peek[HEADER.FIELDS (A B)]<0.10>".to_string())
        );
        assert_eq!(toks[1], Tok::Atom("x".to_string()));
        let toks = tokenize("BINARY[1] y").unwrap();
        assert_eq!(toks.len(), 2);
    }

    #[tokio::test]
    async fn pre_auth_commands_rejected_before_tokenizing() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let mut session = ImapSession::new("127.0.0.1".to_string(), Arc::clone(&storage));
        let deep = format!("{}x{}", "(".repeat(10), ")".repeat(10));
        let resp = cmd("a", "SEARCH", &deep, &mut session, &storage).await;
        assert!(resp.starts_with("a NO Not authenticated"), "{}", resp);
        // LOGIN arguments are tokenized with a nesting limit of 1.
        let resp = cmd("b", "LOGIN", "((x)) y", &mut session, &storage).await;
        assert!(resp.starts_with("b BAD"), "{}", resp);
    }

    #[test]
    fn list_pattern_is_bounded() {
        let evil = format!("{}b", "*%".repeat(100));
        assert!(!mailbox_matches(&evil, &"a".repeat(64)));
        assert!(mailbox_matches("*%*N*X", "INBOX"));
        assert!(mailbox_matches("I*B*", "INBOX"));
        assert!(!mailbox_matches("I*Z", "INBOX"));
        assert!(!mailbox_matches(&"*".repeat(MAX_LIST_PATTERN + 1), "INBOX"));
    }

    #[test]
    fn search_nesting_is_limited_and_new_matches_nothing() {
        let email = sample_email();
        let limits = SearchLimits {
            max_seq: 1,
            max_uid: 42,
        };
        let q = format!("{}ALL", "NOT ".repeat(MAX_SEARCH_DEPTH + 1));
        assert!(parse_search_keys(&tokenize(&q).unwrap(), &limits).is_err());
        let q = format!("{}ALL", "NOT ".repeat(MAX_SEARCH_DEPTH));
        assert!(parse_search_keys(&tokenize(&q).unwrap(), &limits).is_ok());
        let q = format!("{}ALL ALL", "OR ".repeat(10_000));
        assert!(parse_search_keys(&tokenize(&q).unwrap(), &limits).is_err());

        let keys = parse_search_keys(&tokenize("NEW").unwrap(), &limits).unwrap();
        let msg = SearchMsg {
            seq: 1,
            email: &email,
            content: Some(&email.raw),
        };
        assert!(!eval_search(&SearchKey::And(keys), &msg));
    }

    #[test]
    fn partial_fetch_slices_exact_octets() {
        let raw = "Subject: x\r\n\r\n\u{e9}\u{e9}\r\n".to_string();
        let email = Email::new("a@b".into(), vec![], raw.clone());
        // Start in the middle of the first two-byte character.
        let items = parse_fetch_items(&tokenize("BODY.PEEK[TEXT]<1.2>").unwrap()).unwrap();
        let resp = build_fetch_response(1, &email, Some(&raw), email.size, &items);
        let body = "\u{e9}\u{e9}".as_bytes();
        let mut expected = b"* 1 FETCH (BODY[TEXT]<1> {2}\r\n".to_vec();
        expected.extend_from_slice(&body[1..3]);
        expected.extend_from_slice(b")\r\n");
        assert_eq!(resp, expected);
    }

    #[tokio::test]
    async fn literal_size_overflow_is_rejected() {
        let input = format!("a LOGIN {{{}}}\r\n", usize::MAX);
        let mut reader = BufReader::new(input.as_bytes());
        let mut out = Vec::new();
        let r = read_command(&mut reader, &mut out, WRITE_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(r, Some(Err("* BAD Literal too large\r\n".to_string())));
        assert!(out.is_empty(), "no continuation for an oversized literal");
    }

    #[test]
    fn bodystructure_uses_rfc2231_params() {
        let raw = "Content-Type: text/plain; charset*=utf-8''%41; format=flowed\r\n\r\nhi\r\n";
        let bs = body_structure(raw);
        assert!(
            bs.contains("(\"CHARSET\" \"A\" \"FORMAT\" \"flowed\")"),
            "{}",
            bs
        );
    }

    #[tokio::test]
    async fn uid_store_includes_uid_and_targets_by_uid() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let mut s = ImapSession::new("127.0.0.1".to_string(), Arc::clone(&storage));
        cmd("a", "LOGIN", "bob password123", &mut s, &storage).await;
        cmd("b", "SELECT", "INBOX", &mut s, &storage).await;
        // UID 3 is sequence number 3; sequence number 1 must not be touched.
        let resp = cmd("c", "UID", "STORE 3 +FLAGS (\\Flagged)", &mut s, &storage).await;
        assert!(
            resp.contains("* 3 FETCH (UID 3 FLAGS (\\Flagged))"),
            "{}",
            resp
        );
        assert!(resp.ends_with("c OK UID STORE completed\r\n"));
        let meta = storage.message_meta("bob").await.unwrap();
        assert!(!meta[0].flags.flagged);
        assert!(meta[2].flags.flagged);
        // A UID that does not exist matches nothing.
        let resp = cmd("d", "UID", "STORE 99 +FLAGS (\\Seen)", &mut s, &storage).await;
        assert_eq!(resp, "d OK UID STORE completed\r\n");
    }

    #[tokio::test]
    async fn concurrent_expunge_keeps_snapshot_until_noop() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let mut a = ImapSession::new("127.0.0.1".to_string(), Arc::clone(&storage));
        let mut b = ImapSession::new("127.0.0.1".to_string(), Arc::clone(&storage));
        for s in [&mut a, &mut b] {
            cmd("l", "LOGIN", "bob password123", s, &storage).await;
            cmd("s", "SELECT", "INBOX", s, &storage).await;
        }
        cmd("1", "STORE", "1 +FLAGS (\\Deleted)", &mut a, &storage).await;
        let resp = cmd("2", "EXPUNGE", "", &mut a, &storage).await;
        assert!(resp.starts_with("* 1 EXPUNGE\r\n"), "{}", resp);

        // B still sees three messages with the old numbering; the expunged
        // one is simply absent from FETCH.
        let resp = cmd("3", "FETCH", "1:* (UID)", &mut b, &storage).await;
        assert!(!resp.contains("EXPUNGE"), "{}", resp);
        assert!(resp.contains("* 2 FETCH (UID 2)"), "{}", resp);
        assert!(resp.contains("* 3 FETCH (UID 3)"), "{}", resp);
        assert_eq!(b.selected.as_ref().unwrap().msgs.len(), 3);

        let resp = cmd("4", "NOOP", "", &mut b, &storage).await;
        assert!(resp.starts_with("* 1 EXPUNGE\r\n"), "{}", resp);
        let resp = cmd("5", "FETCH", "1 (UID)", &mut b, &storage).await;
        assert!(resp.contains("* 1 FETCH (UID 2)"), "{}", resp);
    }

    #[tokio::test]
    async fn close_expunges_without_untagged_responses() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let mut s = ImapSession::new("127.0.0.1".to_string(), Arc::clone(&storage));
        cmd("a", "LOGIN", "bob password123", &mut s, &storage).await;
        cmd("b", "SELECT", "INBOX", &mut s, &storage).await;
        cmd(
            "c",
            "STORE",
            "2 +FLAGS.SILENT (\\Deleted)",
            &mut s,
            &storage,
        )
        .await;
        let resp = cmd("d", "CLOSE", "", &mut s, &storage).await;
        assert_eq!(resp, "d OK CLOSE completed\r\n");
        let meta = storage.message_meta("bob").await.unwrap();
        assert_eq!(meta.iter().map(|m| m.uid).collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(s.state, ImapState::Authenticated);
    }

    // ------------------------------------------------------------------
    // Stream-level tests (tokio::io::duplex)
    // ------------------------------------------------------------------

    use tokio::io::{AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

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

        /// Read until the tagged completion for `tag`; returns everything read.
        async fn until_tagged(&mut self, tag: &str) -> String {
            let mut out = String::new();
            loop {
                let l = self.line().await;
                assert!(!l.is_empty(), "EOF before {} completion: {}", tag, out);
                out.push_str(&l);
                if l.starts_with(&format!("{} ", tag)) {
                    return out;
                }
            }
        }
    }

    fn spawn_imap(
        storage: Arc<Storage>,
        timeouts: Option<Timeouts>,
    ) -> (Client, tokio::task::JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(1 << 16);
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let handle = tokio::spawn(async move {
            let t = timeouts.unwrap_or_default();
            let _ = serve_imap_with(server, peer, storage, t, PLAIN_TLS_OFF).await;
        });
        (Client::new(client), handle)
    }

    async fn connect_imap(storage: &Arc<Storage>) -> (Client, tokio::task::JoinHandle<()>) {
        let (mut c, h) = spawn_imap(Arc::clone(storage), None);
        assert!(c.line().await.starts_with("* OK"));
        (c, h)
    }

    /// Content of bob's first message as a fresh reader would get it now.
    async fn first_message_content(storage: &Storage) -> String {
        let meta = storage.message_meta("bob").await.unwrap();
        let ids = vec![meta[0].id.clone()];
        let emails = storage.get_emails_by_ids("bob", &ids).await;
        storage.email_content("bob", &emails[&ids[0]]).await
    }

    #[tokio::test]
    async fn imap_disconnect_without_logout_locks_keys() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        assert!(!first_message_content(&storage).await.contains("body 1"));

        let (mut c, h) = connect_imap(&storage).await;
        c.send("a LOGIN bob password123\r\n").await;
        assert!(c.until_tagged("a").await.contains("a OK"));
        assert!(first_message_content(&storage).await.contains("body 1"));

        drop(c); // disconnect without LOGOUT
        h.await.unwrap();
        assert!(!first_message_content(&storage).await.contains("body 1"));
    }

    #[tokio::test]
    async fn imap_authenticate_plain_over_stream() {
        use base64::Engine;
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let (mut c, h) = connect_imap(&storage).await;
        let creds = base64::engine::general_purpose::STANDARD.encode("\0bob\0password123");
        c.send("a AUTHENTICATE PLAIN\r\n").await;
        assert_eq!(c.line().await, "+ \r\n");
        c.send(&format!("{}\r\n", creds)).await;
        let resp = c.until_tagged("a").await;
        assert!(resp.starts_with("a OK"), "{}", resp);
        c.send("b SELECT INBOX\r\n").await;
        assert!(c.until_tagged("b").await.contains("* 3 EXISTS"));
        c.send("c LOGOUT\r\n").await;
        assert!(c.until_tagged("c").await.contains("* BYE"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn login_with_password_change_required_is_expired() {
        use base64::Engine;
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        storage
            .user_manager()
            .update_user("bob", |u| u.password_change_required = true)
            .await
            .unwrap();

        let mut session = ImapSession::new("127.0.0.1".to_string(), Arc::clone(&storage));
        let resp = cmd("a", "LOGIN", "bob password123", &mut session, &storage).await;
        assert!(
            resp.starts_with("a NO [EXPIRED] Password change required; change it "),
            "{}",
            resp
        );
        assert!(resp.contains("/account/password"), "{}", resp);
        assert_eq!(session.state, ImapState::NotAuthenticated);
        // A wrong password still gets the generic failure.
        let resp = cmd("b", "LOGIN", "bob wrongpass", &mut session, &storage).await;
        assert!(resp.starts_with("b NO [AUTHENTICATIONFAILED]"), "{}", resp);

        // AUTHENTICATE PLAIN reports the same.
        let (mut c, h) = connect_imap(&storage).await;
        let creds = base64::engine::general_purpose::STANDARD.encode("\0bob\0password123");
        c.send(&format!("c AUTHENTICATE PLAIN {}\r\n", creds)).await;
        let resp = c.until_tagged("c").await;
        assert!(
            resp.starts_with("c NO [EXPIRED] Password change required"),
            "{}",
            resp
        );
        c.send("d LOGOUT\r\n").await;
        c.until_tagged("d").await;
        h.await.unwrap();
    }

    #[tokio::test]
    async fn imap_literal_login_over_stream() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let (mut c, h) = connect_imap(&storage).await;
        c.send("a LOGIN {3}\r\n").await;
        assert!(c.line().await.starts_with("+ "));
        c.send("bob {11}\r\n").await;
        assert!(c.line().await.starts_with("+ "));
        c.send("password123\r\n").await;
        let resp = c.until_tagged("a").await;
        assert!(resp.starts_with("a OK"), "{}", resp);
        // Non-synchronising literal: no continuation request.
        c.send("b STATUS {5+}\r\nINBOX (MESSAGES)\r\n").await;
        let resp = c.until_tagged("b").await;
        assert!(resp.contains("(MESSAGES 3)"), "{}", resp);
        drop(c);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn imap_fetch_decrypts_after_login() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        let (mut c, h) = connect_imap(&storage).await;
        c.send("a LOGIN bob password123\r\nb SELECT INBOX\r\n")
            .await;
        c.until_tagged("a").await;
        c.until_tagged("b").await;
        c.send("c FETCH 1 (RFC822.SIZE BODY.PEEK[])\r\n").await;
        let resp = c.until_tagged("c").await;
        let raw = "Subject: m1\r\n\r\nbody 1\r\n";
        assert!(
            resp.contains(&format!(
                "RFC822.SIZE {} BODY[] {{{}}}\r\n{}",
                raw.len(),
                raw.len(),
                raw
            )),
            "{}",
            resp
        );
        drop(c);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn app_password_login_sees_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        // Like `test_storage_encrypted`, plus an SSO manager for app passwords.
        let users = Arc::new(crate::users::UserManager::new(
            "example.com".to_string(),
            dir.path().to_path_buf(),
        ));
        let crypto = Arc::new(crate::crypto::CryptoManager::with_enabled(
            dir.path().to_path_buf(),
            true,
        ));
        users.attach_crypto(Arc::clone(&crypto)).await;
        users.create_user("bob", "password123", None).await.unwrap();
        let sso = Arc::new(crate::sso::SsoManager::new(
            crate::sso::SsoConfig::default(),
            dir.path().to_path_buf(),
        ));
        let app_pw = sso
            .generate_app_password("bob", "test", None)
            .await
            .unwrap();
        let ldap = Arc::new(crate::ldap::LdapClient::new(
            crate::ldap::LdapConfig::default(),
        ));
        let storage = Arc::new(Storage::with_encryption(
            dir.path().to_path_buf(),
            users,
            ldap,
            sso,
            crypto,
        ));
        storage
            .deliver_email(
                "bob@example.com",
                Email::new("a@b".into(), vec![], "Subject: m1\r\n\r\nbody 1\r\n".into()),
            )
            .await
            .unwrap();

        let (mut c, h) = connect_imap(&storage).await;
        c.send(&format!("a LOGIN bob \"{}\"\r\nb SELECT INBOX\r\n", app_pw))
            .await;
        assert!(c.until_tagged("a").await.contains("a OK"));
        c.until_tagged("b").await;
        c.send("c FETCH 1 (RFC822.SIZE BODY.PEEK[])\r\n").await;
        let resp = c.until_tagged("c").await;
        assert!(!resp.contains("body 1"), "{}", resp);
        assert!(resp.contains("could not be decrypted"), "{}", resp);
        // The advertised size equals the literal actually sent.
        let size: usize = resp
            .split("RFC822.SIZE ")
            .nth(1)
            .and_then(|r| r.split(' ').next())
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            resp.contains(&format!("BODY[] {{{}}}\r\n", size)),
            "{}",
            resp
        );
        drop(c);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn two_sessions_refcount_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        let (mut c1, h1) = connect_imap(&storage).await;
        let (mut c2, h2) = connect_imap(&storage).await;
        c1.send("a LOGIN bob password123\r\n").await;
        c1.until_tagged("a").await;
        c2.send("a LOGIN bob password123\r\n").await;
        c2.until_tagged("a").await;

        c1.send("z LOGOUT\r\n").await;
        c1.until_tagged("z").await;
        h1.await.unwrap();
        // The other session still holds the keys.
        assert!(first_message_content(&storage).await.contains("body 1"));

        drop(c2);
        h2.await.unwrap();
        assert!(!first_message_content(&storage).await.contains("body 1"));
    }

    fn short_timeouts() -> Timeouts {
        Timeouts {
            pre_auth: Duration::from_millis(100),
            auth: Duration::from_secs(30),
            idle_max: Duration::from_millis(300),
            idle_poll: IDLE_POLL,
            write: WRITE_TIMEOUT,
        }
    }

    #[tokio::test]
    async fn pre_auth_idle_connection_is_logged_out() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let (mut c, h) = spawn_imap(Arc::clone(&storage), Some(short_timeouts()));
        assert!(c.line().await.starts_with("* OK"));
        assert_eq!(c.line().await, "* BYE Autologout; idle too long\r\n");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn idle_has_an_overall_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        let (mut c, h) = spawn_imap(Arc::clone(&storage), Some(short_timeouts()));
        assert!(c.line().await.starts_with("* OK"));
        c.send("a LOGIN bob password123\r\nb SELECT INBOX\r\nc IDLE\r\n")
            .await;
        c.until_tagged("a").await;
        c.until_tagged("b").await;
        assert_eq!(c.line().await, "+ idling\r\n");
        assert_eq!(c.line().await, "* BYE Autologout; idle too long\r\n");
        h.await.unwrap();
        // Logout ran: keys are locked again.
        assert!(!first_message_content(&storage).await.contains("body 1"));
    }

    #[tokio::test]
    async fn write_timeout_ends_stalled_session() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let timeouts = Timeouts {
            write: Duration::from_millis(100),
            ..Timeouts::default()
        };
        // A tiny pipe the client never reads: CAPABILITY responses fill it.
        let (client, server) = tokio::io::duplex(64);
        let peer: SocketAddr = "127.0.0.1:40003".parse().unwrap();
        let handle = tokio::spawn(async move {
            serve_imap_with(server, peer, storage, timeouts, PLAIN_TLS_OFF)
                .await
                .map(drop)
        });
        let (_r, mut w) = tokio::io::split(client);
        w.write_all(b"a CAPABILITY\r\n").await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("stalled session was not ended")
            .unwrap();
        let err = result.expect_err("session should fail with a write timeout");
        let io = err.downcast_ref::<std::io::Error>().expect("io error");
        assert_eq!(io.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn idle_deadline_with_stalled_writer() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        // The write timeout alone would keep the session for 30s; the IDLE
        // deadline must end it well before that.
        let timeouts = Timeouts {
            pre_auth: Duration::from_secs(30),
            auth: Duration::from_secs(30),
            // Generous enough for slow (coverage-instrumented) runs to fill the
            // pipe first, still far below the 30s write timeout.
            idle_max: Duration::from_millis(1500),
            idle_poll: Duration::from_millis(5),
            write: Duration::from_secs(30),
        };
        // A tiny pipe: two untagged EXISTS updates are enough to block the
        // server's writes, so the outcome doesn't depend on scheduling speed.
        let (client, server) = tokio::io::duplex(16);
        let peer: SocketAddr = "127.0.0.1:40004".parse().unwrap();
        let st = Arc::clone(&storage);
        let handle = tokio::spawn(async move {
            serve_imap_with(server, peer, st, timeouts, PLAIN_TLS_OFF)
                .await
                .map(drop)
        });
        let (r, w) = tokio::io::split(client);
        let mut c = Client {
            r: BufReader::new(r),
            w,
        };
        assert!(c.line().await.starts_with("* OK"));
        c.send("a LOGIN bob password123\r\n").await;
        c.until_tagged("a").await;
        c.send("b SELECT INBOX\r\n").await;
        c.until_tagged("b").await;
        c.send("c IDLE\r\n").await;
        assert_eq!(c.line().await, "+ idling\r\n");
        assert!(first_message_content(&storage).await.contains("body 1"));

        // Stop reading. Deliver a few messages up front so the server's EXISTS
        // updates fill the pipe well before the deadline, then keep mail
        // arriving so its writes stay blocked.
        for i in 0..5 {
            let raw = format!("Subject: pre{}\r\n\r\nx\r\n", i);
            storage
                .deliver_email("bob@example.com", Email::new("a@b".into(), vec![], raw))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let feeder_storage = Arc::clone(&storage);
        let feeder = tokio::spawn(async move {
            for i in 0..1000 {
                let raw = format!("Subject: n{}\r\n\r\nx\r\n", i);
                let _ = feeder_storage
                    .deliver_email("bob@example.com", Email::new("a@b".into(), vec![], raw))
                    .await;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        });
        let result = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("IDLE deadline did not end the stalled session")
            .unwrap();
        feeder.abort();
        let err = result.expect_err("blocked write should fail at the deadline");
        let io = err.downcast_ref::<std::io::Error>().expect("io error");
        assert_eq!(io.kind(), std::io::ErrorKind::TimedOut);
        // The session's keys were released.
        assert!(!first_message_content(&storage).await.contains("body 1"));
        drop(c);
    }

    // ------------------------------------------------------------------
    // TLS: STARTTLS, LOGINDISABLED, PRIVACYREQUIRED, implicit IMAPS
    // ------------------------------------------------------------------

    use crate::proto::SessionEnd;
    use crate::tls::Tls;
    use tokio_rustls::client::TlsStream as ClientTls;

    /// TLS off: today's behaviour (plaintext LOGIN allowed, no STARTTLS).
    const TLS_OFF: TlsPolicy = TlsPolicy {
        tls_available: false,
        allow_plaintext: false,
    };
    /// TLS configured, plaintext logins refused (the default).
    const TLS_REQUIRED: TlsPolicy = TlsPolicy {
        tls_available: true,
        allow_plaintext: false,
    };
    /// TLS configured, `KISS_MAIL_ALLOW_PLAINTEXT_AUTH=true`.
    const PLAINTEXT_OK: TlsPolicy = TlsPolicy {
        tls_available: true,
        allow_plaintext: true,
    };
    /// A plain-listener session with TLS off.
    const PLAIN_TLS_OFF: ImapOpts = ImapOpts {
        tls: false,
        greet: true,
        policy: TLS_OFF,
    };
    const PRIVACY_REQUIRED: &str = "NO [PRIVACYREQUIRED] TLS required; use STARTTLS or port 993";

    type ConnTask = tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>;

    fn test_peer() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    async fn self_signed(dir: &std::path::Path) -> Option<Arc<Tls>> {
        Some(crate::tls::test_support::self_signed(dir).await)
    }

    /// A whole plain-listener connection (the spec 3.2 sequence) over an
    /// in-memory stream.
    fn start_conn(
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
        (Client::new(client), handle)
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

    /// After LOGOUT on TLS the server sent close_notify: a clean EOF
    /// (rustls reports `UnexpectedEof` otherwise).
    async fn assert_clean_tls_eof(c: &mut Client<ClientTls<DuplexStream>>) {
        let mut rest = String::new();
        assert_eq!(c.r.read_line(&mut rest).await.unwrap(), 0, "{:?}", rest);
    }

    fn plain_ir(user: &str, password: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(format!("\0{}\0{}", user, password))
    }

    /// No login was attempted: no history, no failure count, no throttle slot.
    async fn assert_no_login_attempt(storage: &Storage) {
        let users = storage.user_manager();
        let bob = users.get_user("bob").await.unwrap();
        assert!(bob.login_history.is_empty(), "{:?}", bob.login_history);
        assert_eq!(bob.failed_login_attempts, 0);
        assert_eq!(users.throttle_sizes(), (0, 0, 0));
    }

    #[test]
    fn capability_lists_per_state() {
        assert_eq!(
            capabilities(false, false, TLS_REQUIRED),
            "IMAP4rev1 STARTTLS LOGINDISABLED SASL-IR IDLE UNSELECT"
        );
        assert_eq!(
            capabilities(false, false, PLAINTEXT_OK),
            "IMAP4rev1 STARTTLS AUTH=PLAIN SASL-IR IDLE UNSELECT"
        );
        assert_eq!(
            capabilities(false, false, TLS_OFF),
            "IMAP4rev1 AUTH=PLAIN SASL-IR IDLE UNSELECT"
        );
        for policy in [TLS_REQUIRED, PLAINTEXT_OK, TLS_OFF] {
            assert_eq!(
                capabilities(true, false, policy),
                "IMAP4rev1 AUTH=PLAIN SASL-IR IDLE UNSELECT"
            );
            for on_tls in [false, true] {
                let caps = capabilities(on_tls, true, policy);
                assert!(!caps.contains("STARTTLS"), "{caps}");
                assert!(!caps.contains("LOGINDISABLED"), "{caps}");
            }
        }
    }

    #[tokio::test]
    async fn greeting_and_capability_show_starttls_and_logindisabled() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED);
        let greeting = c.line().await;
        assert_eq!(
            greeting,
            "* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED SASL-IR IDLE UNSELECT] \
             kiss-mail IMAP4rev1 server ready\r\n"
        );
        c.send("a CAPABILITY\r\n").await;
        let resp = c.until_tagged("a").await;
        assert!(
            resp.starts_with("* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED "),
            "{resp}"
        );
        assert!(!resp.contains("AUTH=PLAIN"), "{resp}");
        c.send("z LOGOUT\r\n").await;
        c.until_tagged("z").await;
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn login_before_tls_is_privacyrequired_without_history() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED);
        c.line().await;
        c.send("a LOGIN bob password123\r\n").await;
        assert_eq!(c.line().await, format!("a {}\r\n", PRIVACY_REQUIRED));
        // Malformed arguments get the same refusal (nothing is parsed).
        c.send("b LOGIN ((x\r\n").await;
        assert_eq!(c.line().await, format!("b {}\r\n", PRIVACY_REQUIRED));
        c.send("c SELECT INBOX\r\n").await;
        assert_eq!(c.line().await, "c NO Not authenticated\r\n");
        assert_no_login_attempt(&storage).await;
        drop(c);
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn authenticate_before_tls_refused_without_continuation() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED);
        c.line().await;
        c.send("a AUTHENTICATE PLAIN\r\n").await;
        // The next line is the tagged refusal, never a `+` continuation.
        assert_eq!(c.line().await, format!("a {}\r\n", PRIVACY_REQUIRED));
        // SASL-IR: valid and undecodable initial responses are not decoded.
        c.send(&format!(
            "b AUTHENTICATE PLAIN {}\r\n",
            plain_ir("bob", "password123")
        ))
        .await;
        assert_eq!(c.line().await, format!("b {}\r\n", PRIVACY_REQUIRED));
        c.send("c AUTHENTICATE PLAIN !!not-base64!!\r\n").await;
        assert_eq!(c.line().await, format!("c {}\r\n", PRIVACY_REQUIRED));
        // The next line is a command again, not SASL data.
        c.send("d NOOP\r\n").await;
        assert_eq!(c.line().await, "d OK NOOP completed\r\n");
        assert_no_login_attempt(&storage).await;
        drop(c);
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn starttls_then_login_fetch_decrypts() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED);
        assert!(c.line().await.starts_with("* OK [CAPABILITY "));
        c.send("a STARTTLS\r\n").await;
        assert_eq!(c.line().await, "a OK Begin TLS negotiation now\r\n");
        let mut c = upgrade(dir.path(), c).await;

        // No greeting after the handshake: the first line is CAPABILITY's.
        c.send("b CAPABILITY\r\n").await;
        assert_eq!(
            c.line().await,
            "* CAPABILITY IMAP4rev1 AUTH=PLAIN SASL-IR IDLE UNSELECT\r\n"
        );
        assert_eq!(c.line().await, "b OK CAPABILITY completed\r\n");
        // TLS is already active.
        c.send("b2 STARTTLS\r\n").await;
        assert!(c.line().await.starts_with("b2 BAD "));

        c.send("c LOGIN bob password123\r\n").await;
        let resp = c.until_tagged("c").await;
        assert_eq!(
            resp,
            "c OK [CAPABILITY IMAP4rev1 AUTH=PLAIN SASL-IR IDLE UNSELECT] LOGIN completed\r\n"
        );
        c.send("d SELECT INBOX\r\n").await;
        c.until_tagged("d").await;
        c.send("e FETCH 1 BODY[]\r\n").await;
        let resp = c.until_tagged("e").await;
        assert!(resp.contains("body 1"), "{resp}");
        assert!(resp.contains("e OK"), "{resp}");

        let bob = storage.user_manager().get_user("bob").await.unwrap();
        let rec = bob.login_history.last().unwrap();
        assert!(rec.success);
        assert!(rec.tls);
        assert_eq!(rec.protocol, "IMAP");

        c.send("f LOGOUT\r\n").await;
        assert!(c.until_tagged("f").await.contains("* BYE"));
        assert_clean_tls_eof(&mut c).await;
        h.await.unwrap().unwrap();
        // The session's keys were released.
        assert!(!first_message_content(&storage).await.contains("body 1"));
    }

    #[tokio::test]
    async fn starttls_after_login_is_bad() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, PLAINTEXT_OK);
        let greeting = c.line().await;
        assert!(
            greeting.starts_with("* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN "),
            "{greeting}"
        );
        c.send("a LOGIN bob password123\r\n").await;
        let resp = c.until_tagged("a").await;
        assert!(resp.starts_with("a OK [CAPABILITY "), "{resp}");
        assert!(!resp.contains("STARTTLS"), "{resp}");
        assert!(!resp.contains("LOGINDISABLED"), "{resp}");
        c.send("b CAPABILITY\r\n").await;
        let resp = c.until_tagged("b").await;
        assert!(!resp.contains("STARTTLS"), "{resp}");
        c.send("c STARTTLS\r\n").await;
        assert!(c.line().await.starts_with("c BAD "));
        // The session goes on in plaintext.
        c.send("d NOOP\r\n").await;
        assert_eq!(c.line().await, "d OK NOOP completed\r\n");
        // The plaintext login is recorded as such.
        let bob = storage.user_manager().get_user("bob").await.unwrap();
        assert!(!bob.login_history.last().unwrap().tls);
        drop(c);
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn starttls_with_argument_is_bad() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED);
        c.line().await;
        c.send("a STARTTLS now\r\n").await;
        assert!(c.line().await.starts_with("a BAD "));
        c.send("b NOOP\r\n").await;
        assert_eq!(c.line().await, "b OK NOOP completed\r\n");
        drop(c);
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn starttls_tls_off_is_bad() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let (mut c, h) = start_conn(&storage, None, TLS_OFF);
        assert_eq!(
            c.line().await,
            "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN SASL-IR IDLE UNSELECT] \
             kiss-mail IMAP4rev1 server ready\r\n"
        );
        c.send("a STARTTLS\r\n").await;
        assert!(c.line().await.starts_with("a BAD "));
        // Plaintext LOGIN works as before.
        c.send("b LOGIN bob password123\r\n").await;
        assert!(c.until_tagged("b").await.starts_with("b OK "));
        drop(c);
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn implicit_imaps_session_works() {
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
        assert_eq!(
            c.line().await,
            "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN SASL-IR IDLE UNSELECT] \
             kiss-mail IMAP4rev1 server ready\r\n"
        );
        c.send("a LOGIN bob password123\r\nb SELECT INBOX\r\nc FETCH 1 BODY[]\r\n")
            .await;
        assert!(c.until_tagged("a").await.starts_with("a OK "));
        c.until_tagged("b").await;
        assert!(c.until_tagged("c").await.contains("body 1"));
        let bob = storage.user_manager().get_user("bob").await.unwrap();
        let rec = bob.login_history.last().unwrap();
        assert!(rec.tls);
        assert_eq!(rec.protocol, "IMAP");
        c.send("d LOGOUT\r\n").await;
        c.until_tagged("d").await;
        assert_clean_tls_eof(&mut c).await;
        task.await.unwrap();
        assert_eq!(connections.available_permits(), MAX_CONNECTIONS);
    }

    #[tokio::test]
    async fn starttls_pipelined_commands_are_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let (mut c, h) = start_conn(&storage, self_signed(dir.path()).await, TLS_REQUIRED);
        c.line().await;
        c.send("a STARTTLS\r\nb LOGIN bob password123\r\n").await;
        assert_eq!(c.line().await, "a OK Begin TLS negotiation now\r\n");
        let mut c = upgrade(dir.path(), c).await;
        c.send("c NOOP\r\n").await;
        // `b` never got a reply: the first line under TLS is c's.
        assert_eq!(c.line().await, "c OK NOOP completed\r\n");
        // Still not authenticated, and no login was attempted.
        c.send("d SELECT INBOX\r\n").await;
        assert_eq!(c.line().await, "d NO Not authenticated\r\n");
        assert_no_login_attempt(&storage).await;
        c.send("e LOGOUT\r\n").await;
        let resp = c.until_tagged("e").await;
        assert!(!resp.contains("b "), "{resp}");
        assert_clean_tls_eof(&mut c).await;
        h.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn app_password_imap_restricted_works_after_starttls() {
        let dir = tempfile::tempdir().unwrap();
        let users = Arc::new(crate::users::UserManager::new(
            "example.com".to_string(),
            dir.path().to_path_buf(),
        ));
        users.create_user("bob", "password123", None).await.unwrap();
        let sso = Arc::new(crate::sso::SsoManager::new(
            crate::sso::SsoConfig::default(),
            dir.path().to_path_buf(),
        ));
        let app_pw = sso
            .generate_app_password("bob", "phone", None)
            .await
            .unwrap();
        sso.set_allowed_protocols_for_test("bob", &["IMAP"]).await;
        let storage = Arc::new(Storage::with_encryption(
            dir.path().to_path_buf(),
            users,
            Arc::new(crate::ldap::LdapClient::new(
                crate::ldap::LdapConfig::default(),
            )),
            sso,
            Arc::new(crate::crypto::CryptoManager::with_enabled(
                dir.path().to_path_buf(),
                false,
            )),
        ));
        let tls = self_signed(dir.path()).await;

        // After STARTTLS on the plain listener.
        let (mut c, h) = start_conn(&storage, tls.clone(), TLS_REQUIRED);
        c.line().await;
        c.send("a STARTTLS\r\n").await;
        assert_eq!(c.line().await, "a OK Begin TLS negotiation now\r\n");
        let mut c = upgrade(dir.path(), c).await;
        c.send(&format!("b LOGIN bob {}\r\n", quote(&app_pw))).await;
        let resp = c.until_tagged("b").await;
        assert!(resp.starts_with("b OK "), "{resp}");
        c.send("c LOGOUT\r\n").await;
        c.until_tagged("c").await;
        h.await.unwrap().unwrap();

        // Over implicit IMAPS, with AUTHENTICATE.
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let permit = Arc::clone(&connections).acquire_owned().await.unwrap();
        let (client, server) = tokio::io::duplex(1 << 16);
        let task = tokio::spawn(handle_connection(
            server,
            test_peer(),
            Arc::clone(&storage),
            tls,
            TLS_REQUIRED,
            true,
            permit,
        ));
        let mut c = Client::new(
            crate::tls::test_support::connect(dir.path(), client)
                .await
                .unwrap(),
        );
        c.line().await;
        c.send(&format!(
            "a AUTHENTICATE PLAIN {}\r\n",
            plain_ir("bob", &app_pw)
        ))
        .await;
        let resp = c.until_tagged("a").await;
        assert!(resp.starts_with("a OK "), "{resp}");
        c.send("b LOGOUT\r\n").await;
        c.until_tagged("b").await;
        task.await.unwrap();
    }

    /// Plaintext sent to the IMAPS listener fails the handshake at once, gets
    /// no IMAP reply, and frees the connection slot.
    #[tokio::test]
    async fn plaintext_on_implicit_listener_closes_fast_and_frees_slot() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let permit = Arc::clone(&connections).acquire_owned().await.unwrap();
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(b"a CAPABILITY\r\n").await.unwrap();
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
        assert!(!String::from_utf8_lossy(&got).contains("OK"), "{got:?}");
    }

    /// STARTTLS accepted, then the client hangs up or sends garbage instead
    /// of a ClientHello: no panic, the slot is freed.
    #[tokio::test]
    async fn starttls_then_hangup_or_garbage_frees_slot() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let tls = self_signed(dir.path()).await;
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        for garbage in [
            None,
            Some(&b"\x16\x03\x01garbage\r\n"[..]),
            Some(b"a NOOP\r\n"),
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
            let mut c = Client::new(client);
            c.line().await;
            c.send("a STARTTLS\r\n").await;
            assert_eq!(c.line().await, "a OK Begin TLS negotiation now\r\n");
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
    async fn imaps_listener_without_tls_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let server = ImapServer::new(storage, None, TLS_OFF);
        let err = server
            .run("127.0.0.1:0", Some("127.0.0.1:0"))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("IMAPS: "), "{err}");
    }

    #[tokio::test]
    async fn session_returns_starttls_with_raw_stream() {
        let dir = tempfile::tempdir().unwrap();
        let storage = test_storage(dir.path()).await;
        let opts = ImapOpts {
            tls: false,
            greet: false,
            policy: TLS_REQUIRED,
        };
        let (client, server) = tokio::io::duplex(1 << 16);
        let task = tokio::spawn(serve_imap_with(
            server,
            test_peer(),
            storage,
            Timeouts::default(),
            opts,
        ));
        let mut c = Client::new(client);
        // greet = false: the first line is STARTTLS's reply.
        c.send("a STARTTLS\r\n").await;
        assert_eq!(c.line().await, "a OK Begin TLS negotiation now\r\n");
        let end = task.await.unwrap().unwrap();
        assert!(matches!(end, SessionEnd::StartTls(_)));
    }
}
