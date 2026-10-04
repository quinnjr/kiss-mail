//! SMTP Server implementation.
//!
//! Implements RFC 5321 (Simple Mail Transfer Protocol) with basic commands.
//! This server only accepts mail for local mailboxes; it does not relay.

use crate::antispam::AntiSpam;
use crate::antivirus::{AntiVirus, ClamavStatus};
use crate::groups::GroupManager;
use crate::proto::{
    SessionEnd, TlsPolicy, accepted, decode_auth_plain, read_line_limited, write_all_timeout,
};
use crate::storage::{Email, MAX_EXPANDED_RECIPIENTS, Storage};
use crate::tls::Tls;
use crate::users::{QuotaError, canonical_username, local_part};
use base64::Engine;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const SMTP_BANNER: &str = "220 kiss-mail ESMTP ready";
const SMTP_OK: &str = "250 OK";
const SMTP_BYE: &str = "221 Bye";
const SMTP_START_DATA: &str = "354 Start mail input; end with <CRLF>.<CRLF>";
const SMTP_SYNTAX_ERROR: &str = "500 Syntax error, command unrecognized";
const SMTP_BAD_SEQUENCE: &str = "503 Bad sequence of commands";
const SMTP_TOO_MANY_RECIPIENTS: &str = "452 4.5.3 Too many recipients";
const SMTP_MESSAGE_TOO_BIG: &str = "552 5.3.4 Message size exceeds fixed maximum message size";
const SMTP_STARTTLS_READY: &str = "220 2.0.0 Ready to start TLS";
const SMTP_ENCRYPTION_REQUIRED: &str =
    "538 5.7.11 Encryption required for requested authentication mechanism";

/// Maximum accepted message size (advertised via the SIZE extension).
pub const MAX_MESSAGE_SIZE: usize = 10_485_760;
/// Maximum length of a command line we buffer.
pub(crate) const MAX_COMMAND_LINE: usize = 8192;
/// Maximum recipients (RCPT commands) per transaction.
const MAX_RECIPIENTS: usize = 100;
/// Maximum concurrent connections per listener.
const MAX_CONNECTIONS: usize = 500;
/// Maximum messages scanned/delivered concurrently (per server).
const MAX_CONCURRENT_DATA: usize = 32;
/// Timeout waiting for a command (RFC 5321 section 4.5.3.2.7: 5 minutes).
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Timeout waiting for each DATA block (RFC 5321 section 4.5.3.2.5: 3 minutes).
const DATA_LINE_TIMEOUT: Duration = Duration::from_secs(3 * 60);
/// Upper bound on receiving one whole DATA section.
const DATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// After a message exceeds the size limit, how much more data is read (and
/// discarded) looking for the terminating "." before the connection is closed.
const DATA_DISCARD_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Debug, Default, Clone, PartialEq)]
enum AuthState {
    #[default]
    None,
    /// AUTH PLAIN sent without initial response; waiting for credentials.
    Plain,
    /// AUTH LOGIN; waiting for the username.
    LoginUser,
    /// AUTH LOGIN; waiting for the password of the given user.
    LoginPass(String),
}

#[derive(Debug, Default)]
struct SmtpSession {
    helo_domain: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    /// Upper bound on the recipient count after group expansion.
    expanded_count: usize,
    declared_size: Option<usize>,
    authenticated: bool,
    /// Canonical username of the authenticated user.
    auth_username: Option<String>,
    auth_state: AuthState,
    peer_ip: String,
    /// The session runs over TLS (implicit, or after STARTTLS).
    tls: bool,
    /// Implicit-TLS submission listener: MAIL requires a prior AUTH.
    submission: bool,
}

/// How a session starts (see `handle_smtp_connection`).
#[derive(Debug, Clone, Copy)]
struct SessionOpts {
    /// The stream is TLS-protected.
    tls: bool,
    /// Send the 220 greeting (not after STARTTLS: RFC 3207 section 4.2).
    greet: bool,
    /// Submission listener: MAIL before AUTH gets 530.
    submission: bool,
}

impl SmtpSession {
    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
        self.expanded_count = 0;
        self.declared_size = None;
    }
}

/// Shared, per-server context for command processing.
struct SmtpContext {
    storage: Arc<Storage>,
    groups: Arc<GroupManager>,
    antispam: Arc<AntiSpam>,
    antivirus: Arc<AntiVirus>,
    hostname: String,
    /// Limits concurrent DATA transactions (receiving, scanning, delivery).
    data_slots: Semaphore,
    command_timeout: Duration,
    data_line_timeout: Duration,
    data_total_timeout: Duration,
    write_timeout: Duration,
    max_message_size: usize,
    /// TLS for STARTTLS and the implicit-TLS listener (`None`: TLS off).
    tls: Option<Arc<Tls>>,
    policy: TlsPolicy,
}

impl SmtpContext {
    fn new(
        storage: Arc<Storage>,
        groups: Arc<GroupManager>,
        antispam: Arc<AntiSpam>,
        antivirus: Arc<AntiVirus>,
        hostname: String,
        tls: Option<Arc<Tls>>,
        policy: TlsPolicy,
    ) -> Self {
        Self {
            storage,
            groups,
            antispam,
            antivirus,
            hostname,
            tls,
            policy,
            data_slots: Semaphore::new(MAX_CONCURRENT_DATA),
            command_timeout: COMMAND_TIMEOUT,
            data_line_timeout: DATA_LINE_TIMEOUT,
            data_total_timeout: DATA_TOTAL_TIMEOUT,
            write_timeout: crate::proto::WRITE_TIMEOUT,
            max_message_size: MAX_MESSAGE_SIZE,
        }
    }
}

pub struct SmtpServer {
    ctx: Arc<SmtpContext>,
}

impl SmtpServer {
    pub fn new(
        storage: Arc<Storage>,
        groups: Arc<GroupManager>,
        antispam: Arc<AntiSpam>,
        antivirus: Arc<AntiVirus>,
        hostname: String,
        tls: Option<Arc<Tls>>,
        policy: TlsPolicy,
    ) -> Self {
        Self {
            ctx: Arc::new(SmtpContext::new(
                storage, groups, antispam, antivirus, hostname, tls, policy,
            )),
        }
    }

    /// Serve the plain listener on `plain_addr` and, when `tls_addr` is set,
    /// the implicit-TLS submission listener. Both share one connection limit
    /// and one context (so `data_slots` is shared too).
    pub async fn run(
        &self,
        plain_addr: &str,
        tls_addr: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let plain = TcpListener::bind(plain_addr)
            .await
            .map_err(|e| format!("SMTP: cannot bind {}: {}", plain_addr, e))?;
        tracing::info!("SMTP server listening on {}", plain_addr);
        let implicit = match tls_addr {
            None => None,
            Some(addr) => {
                if self.ctx.tls.is_none() {
                    return Err("SMTPS: TLS is not configured".into());
                }
                let listener = TcpListener::bind(addr)
                    .await
                    .map_err(|e| format!("SMTPS: cannot bind {}: {}", addr, e))?;
                tracing::info!("SMTPS (implicit TLS) server listening on {}", addr);
                Some(listener)
            }
        };
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        let plain_loop = accept_loop(
            plain,
            "SMTP",
            false,
            Arc::clone(&self.ctx),
            Arc::clone(&connections),
        );
        let implicit_loop = async {
            match implicit {
                Some(listener) => {
                    accept_loop(
                        listener,
                        "SMTPS",
                        true,
                        Arc::clone(&self.ctx),
                        Arc::clone(&connections),
                    )
                    .await
                }
                None => std::future::pending().await,
            }
        };
        tokio::try_join!(plain_loop, implicit_loop)?;
        Ok(())
    }
}

/// Accept connections on `listener` until the connection semaphore closes.
async fn accept_loop(
    listener: TcpListener,
    name: &'static str,
    implicit: bool,
    ctx: Arc<SmtpContext>,
    connections: Arc<Semaphore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        // Wait for a free slot before accepting, so excess clients queue in
        // the kernel backlog instead of consuming tasks.
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
            Arc::clone(&ctx),
            implicit,
            permit,
        ));
    }
}

/// Serve one accepted connection while holding its connection-slot
/// `permit`. The session runs in its own task so a panic is logged here (and
/// the slot released) instead of being lost.
async fn handle_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    ctx: Arc<SmtpContext>,
    implicit: bool,
    permit: OwnedSemaphorePermit,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _permit = permit;
    let peer_ip = peer_addr.ip().to_string();
    let inner = tokio::spawn(serve_connection(stream, peer_ip, ctx, implicit));
    match inner.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("SMTP connection error ({}): {}", peer_addr, e),
        Err(e) if e.is_panic() => {
            tracing::error!("SMTP connection task for {} panicked: {}", peer_addr, e)
        }
        Err(e) => tracing::error!("SMTP connection task for {} failed: {}", peer_addr, e),
    }
}

/// The session restart sequence (spec section 3.2). On the implicit-TLS
/// listener the handshake comes first and the session is a submission
/// session; on the plain listener an accepted STARTTLS restarts the session
/// over TLS with fresh state and no greeting. A failed or timed-out
/// handshake just closes the connection (no reply is possible).
async fn serve_connection<S>(
    stream: S,
    peer_ip: String,
    ctx: Arc<SmtpContext>,
    implicit: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if implicit {
        let Some(tls) = ctx.tls.clone() else {
            return Err("SMTPS connection without a TLS configuration".into());
        };
        let stream = match tls.accept(stream).await {
            Ok(stream) => stream,
            Err(e) => {
                tracing::debug!("SMTPS handshake with {} failed: {}", peer_ip, e);
                return Ok(());
            }
        };
        let opts = SessionOpts {
            tls: true,
            greet: true,
            submission: true,
        };
        handle_smtp_connection(stream, peer_ip, ctx, opts).await?;
        return Ok(());
    }

    let opts = SessionOpts {
        tls: false,
        greet: true,
        submission: false,
    };
    match handle_smtp_connection(stream, peer_ip.clone(), Arc::clone(&ctx), opts).await? {
        SessionEnd::Closed => Ok(()),
        SessionEnd::StartTls(raw) => {
            let Some(tls) = ctx.tls.clone() else {
                return Err("STARTTLS accepted without a TLS configuration".into());
            };
            let stream = match tls.accept(raw).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::debug!("SMTP STARTTLS handshake with {} failed: {}", peer_ip, e);
                    return Ok(());
                }
            };
            let opts = SessionOpts {
                tls: true,
                greet: false,
                submission: false,
            };
            handle_smtp_connection(stream, peer_ip, ctx, opts).await?;
            Ok(())
        }
    }
}

/// Send one reply line (CRLF appended). Fails with `TimedOut` if the client
/// does not accept it within the write timeout, which ends the session.
async fn send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    reply: &str,
    ctx: &SmtpContext,
) -> std::io::Result<()> {
    write_all_timeout(
        writer,
        format!("{}\r\n", reply).as_bytes(),
        ctx.write_timeout,
    )
    .await
}

/// Run one SMTP session over `stream`.
///
/// Returns `SessionEnd::StartTls` with the raw stream once STARTTLS has been
/// accepted (the caller performs the handshake and starts a fresh session).
/// Client bytes already buffered at that point are discarded with the
/// `BufReader`, so commands pipelined after STARTTLS never run under TLS.
async fn handle_smtp_connection<S>(
    stream: S,
    peer_ip: String,
    ctx: Arc<SmtpContext>,
    opts: SessionOpts,
) -> Result<SessionEnd<S>, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut session = SmtpSession {
        peer_ip,
        tls: opts.tls,
        submission: opts.submission,
        ..Default::default()
    };
    let timeout_reply = format!("421 4.4.2 {} Timeout", ctx.hostname);

    if opts.greet {
        send(&mut writer, SMTP_BANNER, &ctx).await?;
    }

    loop {
        let read = tokio::time::timeout(
            ctx.command_timeout,
            read_line_limited(&mut reader, MAX_COMMAND_LINE),
        )
        .await;
        let line = match read {
            Err(_elapsed) => {
                tracing::info!("SMTP command timeout from {}", session.peer_ip);
                send(&mut writer, &timeout_reply, &ctx).await?;
                break;
            }
            Ok(read) => match read? {
                None => break,
                Some(Err(())) => {
                    send(&mut writer, "500 Line too long", &ctx).await?;
                    continue;
                }
                Some(Ok(line)) => line,
            },
        };

        let line = line.trim_end_matches(['\r', '\n']);
        let response = handle_line(line, &mut session, &ctx).await;

        if response.starts_with("354") {
            // Take a processing slot before inviting the client to send
            // data, and hold it until the message has been handled.
            let slot =
                match tokio::time::timeout(ctx.command_timeout, ctx.data_slots.acquire()).await {
                    Ok(Ok(slot)) => slot,
                    Ok(Err(_)) | Err(_) => {
                        session.reset();
                        send(&mut writer, "451 4.3.2 Server busy, try again later", &ctx).await?;
                        continue;
                    }
                };
            send(&mut writer, &response, &ctx).await?;

            let read = tokio::time::timeout(
                ctx.data_total_timeout,
                read_data(
                    &mut reader,
                    ctx.max_message_size,
                    DATA_DISCARD_LIMIT,
                    ctx.data_line_timeout,
                ),
            )
            .await;
            let data = match read {
                Err(_) | Ok(Ok(DataOutcome::TimedOut)) => {
                    tracing::info!("SMTP DATA timeout from {}", session.peer_ip);
                    send(&mut writer, &timeout_reply, &ctx).await?;
                    break;
                }
                Ok(Err(e)) => return Err(e.into()),
                Ok(Ok(DataOutcome::TooLarge)) => {
                    session.reset();
                    send(&mut writer, SMTP_MESSAGE_TOO_BIG, &ctx).await?;
                    continue;
                }
                Ok(Ok(DataOutcome::TooLargeAbandoned)) => {
                    tracing::info!(
                        "SMTP DATA from {} far exceeds the size limit; closing connection",
                        session.peer_ip
                    );
                    send(&mut writer, SMTP_MESSAGE_TOO_BIG, &ctx).await?;
                    break;
                }
                Ok(Ok(DataOutcome::Message(data))) => data,
            };

            // Processing is not wrapped in a timeout: cancelling it midway
            // could leave a partial delivery without its rollback.
            let reply = process_message(&data, &session, &ctx).await;
            drop(slot);
            session.reset();
            tracing::debug!("SMTP -> {}", reply);
            send(&mut writer, &reply, &ctx).await?;
            continue;
        }

        tracing::debug!("SMTP -> {}", response);
        send(&mut writer, &response, &ctx).await?;

        if response == SMTP_STARTTLS_READY {
            // Dropping the BufReader discards any pipelined client bytes.
            return Ok(SessionEnd::StartTls(reader.into_inner().unsplit(writer)));
        }
        if response.starts_with("221") {
            break;
        }
    }

    if opts.tls {
        // Send close_notify (bounded, errors ignored: the session is over).
        let _ = tokio::time::timeout(ctx.write_timeout, writer.shutdown()).await;
    }
    Ok(SessionEnd::Closed)
}

/// Process one received line (a command, or AUTH continuation data).
async fn handle_line(line: &str, session: &mut SmtpSession, ctx: &SmtpContext) -> String {
    if session.auth_state != AuthState::None {
        tracing::debug!("SMTP <- [auth data]");
        continue_auth(line, session, &ctx.storage).await
    } else {
        tracing::debug!("SMTP <- {}", line.trim());
        process_smtp_command(line.trim(), session, ctx).await
    }
}

/// One recipient after group expansion.
#[derive(Debug, Clone, PartialEq)]
struct ExpandedRecipient {
    address: String,
    /// Named directly in a RCPT command (not only reached through a group).
    direct: bool,
}

/// Is `addr` the address of an existing local user (bare local part or
/// local part at one of our domains)? Local users take precedence over
/// groups, so a group can never shadow a user's address.
async fn is_local_user_address(addr: &str, ctx: &SmtpContext) -> bool {
    let local_domain = addr
        .rsplit_once('@')
        .is_none_or(|(_, domain)| is_local_domain(domain, ctx));
    local_domain && ctx.storage.user_exists(&local_part(addr)).await
}

/// Expand group recipients, deduplicating case-insensitively. Group members
/// are local usernames. A recipient that is both named directly and reached
/// through a group counts as direct.
async fn expand_recipients(rcpt_to: &[String], ctx: &SmtpContext) -> Vec<ExpandedRecipient> {
    let mut final_recipients: Vec<ExpandedRecipient> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut add = |address: String, direct: bool| match index.get(&local_part(&address)) {
        Some(&i) => final_recipients[i].direct |= direct,
        None => {
            index.insert(local_part(&address), final_recipients.len());
            final_recipients.push(ExpandedRecipient { address, direct });
        }
    };
    for rcpt in rcpt_to {
        if !is_local_user_address(rcpt, ctx).await
            && let Some(members) = ctx.groups.expand_recipients(rcpt).await
        {
            tracing::info!("Expanding group {} to {} members", rcpt, members.len());
            for member in members {
                add(member, false);
            }
            continue;
        }
        add(rcpt.clone(), true);
    }
    final_recipients
}

/// Scan, filter and deliver a received message; returns the SMTP reply.
///
/// The caller holds a `data_slots` permit for the duration.
async fn process_message(data: &str, session: &SmtpSession, ctx: &SmtpContext) -> String {
    let sender = session.mail_from.as_deref().unwrap_or("unknown");

    // Expand group recipients (cheap) before scanning.
    let final_recipients = expand_recipients(&session.rcpt_to, ctx).await;
    if final_recipients.is_empty() {
        tracing::warn!("Message from {} has no recipients after expansion", sender);
        return "550 5.1.1 No valid recipients".to_string();
    }
    if final_recipients.len() > MAX_EXPANDED_RECIPIENTS {
        tracing::warn!(
            "Message from {} expands to {} recipients (max {})",
            sender,
            final_recipients.len(),
            MAX_EXPANDED_RECIPIENTS
        );
        return SMTP_TOO_MANY_RECIPIENTS.to_string();
    }

    // Check for viruses first (more critical). The scanner is synchronous and
    // may talk to clamd, so run it on the blocking pool.
    let virus_result = {
        let antivirus = Arc::clone(&ctx.antivirus);
        let scan_data = data.to_string();
        match tokio::task::spawn_blocking(move || antivirus.scan(&scan_data)).await {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Virus scan failed: {}", e);
                return "451 4.3.0 Temporary failure scanning message, try again later".to_string();
            }
        }
    };
    if virus_result.is_infected {
        tracing::warn!(
            "Rejected infected email from {}: {:?}",
            sender,
            virus_result.threats
        );
        return format!(
            "550 Message rejected: malware detected ({})",
            virus_result
                .threats
                .first()
                .map(|s| s.as_str())
                .unwrap_or("unknown threat")
        );
    }
    if let ClamavStatus::Skipped(reason) = &virus_result.clamav {
        tracing::warn!(
            "ClamAV is enabled but did not scan the message from {}: {}",
            sender,
            reason
        );
        if ctx.antivirus.clamav_required() {
            return "451 4.7.0 Virus scanner unavailable, try again later".to_string();
        }
    }

    // Check for spam
    let spam_result = ctx
        .antispam
        .check(
            session.mail_from.as_deref().unwrap_or(""),
            &session.rcpt_to,
            data,
        )
        .await;

    // Train the classifier on clear-cut cases, without delaying the reply.
    // Only mail from authenticated sessions is learned from, so outsiders
    // cannot poison the classifier. The decision uses the rule-based score
    // (an independent signal) so the classifier does not just reinforce its
    // own guesses.
    let high_confidence_spam =
        spam_result.is_spam && spam_result.score >= ctx.antispam.threshold * 1.5;
    let clear_ham =
        !spam_result.is_spam && spam_result.score <= 0.5 && spam_result.ai_probability < 0.3;
    if session.authenticated
        && crate::spam_ai::should_learn_from(data)
        && (high_confidence_spam || clear_ham)
    {
        let antispam = Arc::clone(&ctx.antispam);
        let sample = data.to_string();
        tokio::spawn(async move {
            if high_confidence_spam {
                antispam.learn_spam(&sample).await;
            } else {
                antispam.learn_ham(&sample).await;
            }
        });
    }

    if spam_result.is_spam {
        tracing::warn!(
            "Rejected spam email from {} (score: {:.1})",
            sender,
            spam_result.score
        );
        return format!(
            "550 Message rejected as spam (score: {:.1})",
            spam_result.score
        );
    }

    // Add trace and security headers to email
    let addresses: Vec<String> = final_recipients.iter().map(|r| r.address.clone()).collect();
    let direct: HashSet<String> = final_recipients
        .iter()
        .filter(|r| r.direct)
        .map(|r| local_part(&r.address))
        .collect();
    let received = received_header(session, &ctx.hostname, &addresses);
    let data_with_headers = add_security_headers(data, &received, &spam_result, &virus_result);

    let email = Email::new(
        session.mail_from.clone().unwrap_or_default(),
        addresses.clone(),
        data_with_headers,
    );

    // Deliver to all recipients (including expanded group members)
    let results = ctx.storage.deliver_to_many(&addresses, email).await;
    let mut delivered: Vec<(String, String)> = Vec::new();
    let mut direct_temporary = Vec::new();
    let mut expanded_temporary = Vec::new();
    let mut permanent = Vec::new();
    for (rcpt, result) in results {
        match result {
            Ok(id) => delivered.push((local_part(&rcpt), id)),
            Err(e) if e.is_permanent() => permanent.push((rcpt, e)),
            Err(e) if direct.contains(&local_part(&rcpt)) => direct_temporary.push((rcpt, e)),
            Err(e) => expanded_temporary.push((rcpt, e)),
        }
    }
    for (rcpt, e) in &permanent {
        tracing::warn!("Failed to deliver to {}: {}", rcpt, e);
    }

    if !direct_temporary.is_empty() {
        // Ask the sender to retry the whole message; undo partial delivery so
        // the retry does not create duplicates.
        for (rcpt, e) in direct_temporary.iter().chain(&expanded_temporary) {
            tracing::error!("Failed to deliver to {}: {}", rcpt, e);
        }
        if !delivered.is_empty() {
            rollback_and_persist(ctx, &delivered).await;
        }
        return "451 4.3.0 Message could not be delivered, try again later".to_string();
    }

    // Temporary failures of recipients reached only through a group do not
    // make the sender retry (which would duplicate the message for every
    // other member); they are logged and dropped.
    for (rcpt, e) in &expanded_temporary {
        tracing::warn!(
            "Failed to deliver to group member {} (not retried): {}",
            rcpt,
            e
        );
    }

    if delivered.is_empty() {
        if !expanded_temporary.is_empty() {
            return "451 4.3.0 Message could not be delivered, try again later".to_string();
        }
        if !permanent.is_empty() && permanent.iter().all(|(_, e)| e.is_too_large()) {
            return "552 5.3.4 Message too large for recipient(s)".to_string();
        }
        return "550 5.1.1 No valid recipients".to_string();
    }

    // Save storage
    if let Err(e) = ctx.storage.save().await {
        tracing::error!("Failed to save storage: {}", e);
        rollback_and_persist(ctx, &delivered).await;
        return "451 4.3.0 Temporary storage failure, try again later".to_string();
    }

    "250 Message accepted".to_string()
}

/// Undo a partial delivery and try once to persist the rolled-back state (a
/// concurrent save may already have written the delivered copies).
async fn rollback_and_persist(ctx: &SmtpContext, delivered: &[(String, String)]) {
    ctx.storage.rollback_delivery(delivered).await;
    if let Err(e) = ctx.storage.save().await {
        tracing::error!(
            "Failed to save storage after rolling back a delivery: {}",
            e
        );
    }
}

/// Remove control characters (CR, LF, TAB, ...) from a value placed in a header.
fn strip_controls(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Build an RFC 5321 `Received:` trace header (without trailing CRLF).
fn received_header(session: &SmtpSession, hostname: &str, recipients: &[String]) -> String {
    let helo = strip_controls(session.helo_domain.as_deref().unwrap_or("unknown"));
    // RFC 3848 transmission types.
    let with = match (session.tls, session.authenticated) {
        (false, false) => "ESMTP",
        (false, true) => "ESMTPA",
        (true, false) => "ESMTPS",
        (true, true) => "ESMTPSA",
    };
    let for_clause = match recipients {
        [single] => format!("\r\n\tfor <{}>", strip_controls(single)),
        _ => String::new(),
    };
    format!(
        "Received: from {} ([{}])\r\n\tby {} (kiss-mail) with {} id {}{};\r\n\t{}",
        helo,
        strip_controls(&session.peer_ip),
        strip_controls(hostname),
        with,
        uuid::Uuid::new_v4().simple(),
        for_clause,
        chrono::Utc::now().to_rfc2822()
    )
}

/// Prepend the trace header and security scan headers to the message.
///
/// Headers are added at the very top so they can never land inside a folded
/// header or the body.
fn add_security_headers(
    data: &str,
    received: &str,
    spam_result: &crate::antispam::SpamResult,
    virus_result: &crate::antivirus::ScanResult,
) -> String {
    format!(
        "{}\r\nX-Spam-Score: {:.1}\r\nX-Spam-Status: {}\r\nX-Virus-Scanned: kiss-mail ({})\r\nX-Virus-Status: {}\r\n{}",
        received,
        spam_result.score,
        if spam_result.is_spam { "Yes" } else { "No" },
        strip_controls(&virus_result.scanner_summary()),
        if virus_result.is_infected {
            "Infected"
        } else {
            "Clean"
        },
        data
    )
}

/// Is `domain` one of the domains this server delivers for?
fn is_local_domain(domain: &str, ctx: &SmtpContext) -> bool {
    let domain = domain.trim_end_matches('.');
    domain.eq_ignore_ascii_case(&ctx.hostname)
        || domain.eq_ignore_ascii_case("localhost")
        || domain.eq_ignore_ascii_case(ctx.storage.user_manager().default_domain())
}

/// Is `s` an acceptable HELO/EHLO argument: a domain name or an address
/// literal (`[192.0.2.1]`, `[IPv6:2001:db8::1]`)?
fn is_valid_helo_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    if let Some(literal) = s.strip_prefix('[') {
        let Some(inner) = literal.strip_suffix(']') else {
            return false;
        };
        return !inner.is_empty()
            && inner
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-'));
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Parse ESMTP parameters on MAIL FROM; returns the declared SIZE if present.
fn parse_mail_size(params: &str) -> Result<Option<usize>, ()> {
    for param in params.split_whitespace() {
        if let Some((key, value)) = param.split_once('=')
            && key.eq_ignore_ascii_case("SIZE")
        {
            return value.parse::<usize>().map(Some).map_err(|_| ());
        }
    }
    Ok(None)
}

async fn process_smtp_command(line: &str, session: &mut SmtpSession, ctx: &SmtpContext) -> String {
    let upper = line.to_uppercase();
    let parts: Vec<&str> = line.splitn(2, ' ').collect();
    let cmd = parts.first().map(|s| s.to_uppercase()).unwrap_or_default();
    let hostname = &ctx.hostname;

    match cmd.as_str() {
        "HELO" | "EHLO" => {
            let Some(domain) = parts.get(1).map(|d| d.trim()) else {
                return SMTP_SYNTAX_ERROR.to_string();
            };
            if !is_valid_helo_domain(domain) {
                return "501 5.5.2 Invalid domain".to_string();
            }
            session.reset();
            session.helo_domain = Some(domain.to_string());
            if cmd == "HELO" {
                format!("250 {} Hello {}", hostname, domain)
            } else {
                let mut ehlo = format!(
                    "250-{} Hello {}\r\n250-SIZE {}\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n",
                    hostname, domain, ctx.max_message_size
                );
                if ctx.tls.is_some() && !session.tls && !session.authenticated {
                    ehlo.push_str("250-STARTTLS\r\n");
                }
                if ctx.policy.secure(session.tls) {
                    ehlo.push_str("250-AUTH PLAIN LOGIN\r\n");
                }
                ehlo.push_str("250 OK");
                ehlo
            }
        }
        "STARTTLS" => {
            // Not advertised without TLS: an unknown command, as before.
            if ctx.tls.is_none() {
                return SMTP_SYNTAX_ERROR.to_string();
            }
            if parts.get(1).is_some_and(|arg| !arg.trim().is_empty()) {
                return "501 5.5.4 Syntax error".to_string();
            }
            if session.tls {
                return "554 5.5.1 TLS already active".to_string();
            }
            if session.helo_domain.is_none() {
                return "503 5.5.1 Send EHLO first".to_string();
            }
            if session.authenticated {
                return "503 5.5.1 STARTTLS not permitted after AUTH".to_string();
            }
            // The caller restarts the session over TLS with fresh state,
            // discarding any transaction in progress (RFC 3207 section 4.2).
            SMTP_STARTTLS_READY.to_string()
        }
        "AUTH" => {
            // Privacy check first (RFC 4954 section 6): before any 334
            // continuation, before decoding an initial response, and without
            // touching the password check, throttle or login history.
            if !ctx.policy.secure(session.tls) {
                return SMTP_ENCRYPTION_REQUIRED.to_string();
            }
            if session.authenticated {
                return SMTP_BAD_SEQUENCE.to_string();
            }
            if session.mail_from.is_some() {
                return "503 AUTH not permitted during a mail transaction".to_string();
            }
            let Some(args) = parts.get(1) else {
                return "501 Syntax error in parameters".to_string();
            };
            let auth_parts: Vec<&str> = args.split_whitespace().collect();
            let initial = auth_parts.get(1).copied();
            match auth_parts.first().map(|s| s.to_uppercase()).as_deref() {
                Some("PLAIN") => match initial {
                    Some(credentials) => {
                        finish_auth_plain(credentials, session, &ctx.storage).await
                    }
                    None => {
                        session.auth_state = AuthState::Plain;
                        "334 ".to_string()
                    }
                },
                Some("LOGIN") => match initial {
                    Some(user_b64) => match decode_b64_string(user_b64) {
                        Some(user) => {
                            session.auth_state = AuthState::LoginPass(user);
                            "334 UGFzc3dvcmQ6".to_string() // "Password:"
                        }
                        None => "501 Invalid base64 data".to_string(),
                    },
                    None => {
                        session.auth_state = AuthState::LoginUser;
                        "334 VXNlcm5hbWU6".to_string() // "Username:"
                    }
                },
                _ => "504 Unrecognized authentication type".to_string(),
            }
        }
        "MAIL" => {
            if session.helo_domain.is_none() {
                return SMTP_BAD_SEQUENCE.to_string();
            }
            if session.mail_from.is_some() {
                return "503 Nested MAIL command".to_string();
            }
            if session.submission && !session.authenticated {
                return "530 5.7.0 Authentication required".to_string();
            }

            if upper.starts_with("MAIL FROM:") {
                let rest = &line[10..];
                let (from, params) = split_address_and_params(rest);
                let declared = match parse_mail_size(params) {
                    Ok(size) => size,
                    Err(()) => return "501 Invalid SIZE parameter".to_string(),
                };
                if declared.is_some_and(|size| size > ctx.max_message_size) {
                    return SMTP_MESSAGE_TOO_BIG.to_string();
                }
                // Only the authenticated owner may use a local sender address
                // (the null sender <> is always allowed; external senders are
                // relay-restricted at RCPT). A bare local part (no '@') is
                // treated as a local address.
                let local_sender = !from.is_empty()
                    && from
                        .rsplit_once('@')
                        .is_none_or(|(_, domain)| is_local_domain(domain, ctx));
                if local_sender {
                    if !session.authenticated {
                        return "550 5.7.1 Authentication required to send as a local user"
                            .to_string();
                    }
                    if session.auth_username.as_deref() != Some(local_part(&from).as_str()) {
                        return "550 5.7.1 Sender address not owned by authenticated user"
                            .to_string();
                    }
                }
                // RFC 5321 4.1.1.2: MAIL starts a new transaction.
                session.reset();
                session.mail_from = Some(from);
                session.declared_size = declared;
                SMTP_OK.to_string()
            } else {
                SMTP_SYNTAX_ERROR.to_string()
            }
        }
        "RCPT" => {
            if session.mail_from.is_none() {
                return SMTP_BAD_SEQUENCE.to_string();
            }

            if upper.starts_with("RCPT TO:") {
                let (to, _params) = split_address_and_params(&line[8..]);
                check_recipient(&to, session, ctx).await
            } else {
                SMTP_SYNTAX_ERROR.to_string()
            }
        }
        "DATA" => {
            if session.mail_from.is_none() || session.rcpt_to.is_empty() {
                SMTP_BAD_SEQUENCE.to_string()
            } else {
                SMTP_START_DATA.to_string()
            }
        }
        "RSET" => {
            session.reset();
            SMTP_OK.to_string()
        }
        "NOOP" => SMTP_OK.to_string(),
        "QUIT" => SMTP_BYE.to_string(),
        "VRFY" => "252 Cannot VRFY user, but will accept message".to_string(),
        _ => SMTP_SYNTAX_ERROR.to_string(),
    }
}

/// Validate a RCPT TO address; on success it is added to the transaction.
async fn check_recipient(to: &str, session: &mut SmtpSession, ctx: &SmtpContext) -> String {
    if session.rcpt_to.len() >= MAX_RECIPIENTS {
        return SMTP_TOO_MANY_RECIPIENTS.to_string();
    }
    if to.is_empty() {
        return "501 Syntax error in recipient address".to_string();
    }

    // Existing local users are resolved first, so a group can never shadow
    // a user's address.
    if is_local_user_address(to, ctx).await {
        if session.expanded_count + 1 > MAX_EXPANDED_RECIPIENTS {
            return SMTP_TOO_MANY_RECIPIENTS.to_string();
        }
        let local = local_part(to);
        let size = session.declared_size.unwrap_or(0) as u64;
        match ctx.storage.check_recipient_quota(&local, size).await {
            Ok(()) => {}
            Err(QuotaError::MessageTooLarge { .. }) => {
                return "552 5.3.4 Message too large for recipient".to_string();
            }
            Err(e) => {
                return format!("452 4.2.2 Recipient cannot accept mail: {}", e);
            }
        }
        session.expanded_count += 1;
        session.rcpt_to.push(to.to_string());
        return SMTP_OK.to_string();
    }

    // Active group addresses are accepted regardless of their domain,
    // subject to the group's sender policy (membership, external senders,
    // allowed domains).
    if let Some(group) = ctx.groups.get_by_email(to).await.filter(|g| g.active) {
        let members = group.members.len();
        if session.expanded_count + members > MAX_EXPANDED_RECIPIENTS {
            return SMTP_TOO_MANY_RECIPIENTS.to_string();
        }
        let sender = session.mail_from.as_deref().unwrap_or("");
        let sender_domain = sender.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
        let sender_local = local_part(sender);
        // A local sender counts as a member only if it authenticated as that
        // user; anyone else is judged as an external sender.
        let is_authenticated_local = !sender_domain.is_empty()
            && is_local_domain(sender_domain, ctx)
            && session.authenticated
            && session.auth_username.as_deref() == Some(sender_local.as_str());
        let allowed = if is_authenticated_local {
            group.can_send_from(&sender_local, sender_domain, sender_domain)
        } else {
            group.can_send_from(
                "",
                sender_domain,
                ctx.storage.user_manager().default_domain(),
            )
        };
        if !allowed {
            return "550 5.7.1 Sender not permitted to post to this group".to_string();
        }
        session.expanded_count += members;
        session.rcpt_to.push(to.to_string());
        return SMTP_OK.to_string();
    }

    if let Some((_, domain)) = to.rsplit_once('@')
        && !is_local_domain(domain, ctx)
    {
        return if session.authenticated {
            "550 5.7.1 Relaying not supported: this server only delivers to local mailboxes"
                .to_string()
        } else {
            "550 5.7.1 Relaying denied".to_string()
        };
    }

    "550 5.1.1 No such user here".to_string()
}

/// Handle a line received while an AUTH exchange is in progress.
async fn continue_auth(line: &str, session: &mut SmtpSession, storage: &Storage) -> String {
    let line = line.trim();
    if line == "*" {
        session.auth_state = AuthState::None;
        return "501 Authentication cancelled".to_string();
    }
    match std::mem::take(&mut session.auth_state) {
        AuthState::None => SMTP_BAD_SEQUENCE.to_string(),
        AuthState::Plain => finish_auth_plain(line, session, storage).await,
        AuthState::LoginUser => match decode_b64_string(line) {
            Some(user) => {
                session.auth_state = AuthState::LoginPass(user);
                "334 UGFzc3dvcmQ6".to_string()
            }
            None => "501 Invalid base64 data".to_string(),
        },
        AuthState::LoginPass(user) => match decode_b64_string(line) {
            Some(password) => finish_auth(&user, &password, session, storage).await,
            None => "501 Invalid base64 data".to_string(),
        },
    }
}

async fn finish_auth_plain(
    credentials: &str,
    session: &mut SmtpSession,
    storage: &Storage,
) -> String {
    match decode_auth_plain(credentials) {
        Some((username, password)) => finish_auth(&username, &password, session, storage).await,
        None => "501 Invalid AUTH PLAIN data".to_string(),
    }
}

async fn finish_auth(
    username: &str,
    password: &str,
    session: &mut SmtpSession,
    storage: &Storage,
) -> String {
    match storage
        .authenticate_full(username, password, &session.peer_ip, "SMTP", session.tls)
        .await
    {
        Ok(account) => {
            session.authenticated = true;
            session.auth_username = Some(canonical_username(&account.username));
            "235 2.7.0 Authentication successful".to_string()
        }
        Err(e) if e.is_password_change_required() => {
            format!("535 5.7.0 {}", crate::config::password_change_message())
        }
        Err(e) if e.is_temporary() => {
            tracing::warn!(
                "SMTP AUTH for {} from {} could not be checked: {}",
                username,
                session.peer_ip,
                e
            );
            "454 4.7.0 Temporary authentication failure".to_string()
        }
        Err(e) => {
            tracing::info!(
                "SMTP AUTH failed for {} from {}: {}",
                username,
                session.peer_ip,
                e
            );
            "535 5.7.8 Authentication failed".to_string()
        }
    }
}

fn decode_b64_string(s: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// Split `<addr> PARAMS...` into the address and the parameter string.
fn split_address_and_params(s: &str) -> (String, &str) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('<')
        && let Some(end) = rest.find('>')
    {
        return (rest[..end].trim().to_string(), rest[end + 1..].trim());
    }
    match s.split_once(char::is_whitespace) {
        Some((addr, params)) => (addr.to_string(), params.trim()),
        None => (s.to_string(), ""),
    }
}

/// Outcome of reading a DATA section.
#[derive(Debug, PartialEq)]
enum DataOutcome {
    Message(String),
    /// The message exceeded the size limit; it was read to the terminating
    /// "." and discarded.
    TooLarge,
    /// The message exceeded the size limit and the client kept sending more
    /// than the discard allowance without terminating it; the connection
    /// should be closed.
    TooLargeAbandoned,
    /// The client sent nothing for longer than the per-line timeout.
    TimedOut,
}

/// Read the DATA section up to the terminating `.` line, undoing dot-stuffing.
/// Each read must complete within `line_timeout`. Once the message exceeds
/// `max_size`, at most `discard_limit` further bytes are read looking for the
/// terminator.
/// Returns `UnexpectedEof` if the connection closes before the terminator.
async fn read_data<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_size: usize,
    discard_limit: usize,
    line_timeout: Duration,
) -> Result<DataOutcome, std::io::Error> {
    const CHUNK: u64 = 8192;
    let mut data: Vec<u8> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut too_large = false;
    let mut discarded: usize = 0;
    let mut at_line_start = true;

    loop {
        buf.clear();
        let read = tokio::time::timeout(
            line_timeout,
            (&mut *reader).take(CHUNK).read_until(b'\n', &mut buf),
        )
        .await;
        let n = match read {
            Ok(n) => n?,
            Err(_elapsed) => return Ok(DataOutcome::TimedOut),
        };
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed during DATA",
            ));
        }
        let complete_line = buf.last() == Some(&b'\n');
        let line_start = at_line_start;
        at_line_start = complete_line;

        let mut chunk: &[u8] = &buf;
        if line_start {
            if complete_line {
                let content = chunk
                    .strip_suffix(b"\n")
                    .map(|c| c.strip_suffix(b"\r").unwrap_or(c))
                    .unwrap_or(chunk);
                if content == b"." {
                    break;
                }
            }
            // Handle dot-stuffing (RFC 5321 section 4.5.2)
            if chunk.starts_with(b"..") {
                chunk = &chunk[1..];
            }
        }

        if too_large {
            discarded += chunk.len();
            if discarded > discard_limit {
                return Ok(DataOutcome::TooLargeAbandoned);
            }
            continue;
        }
        if data.len() + chunk.len() > max_size {
            too_large = true;
            data = Vec::new();
            continue;
        }
        data.extend_from_slice(chunk);
    }

    if too_large {
        return Ok(DataOutcome::TooLarge);
    }
    Ok(DataOutcome::Message(
        String::from_utf8_lossy(&data).into_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::antivirus::ClamAVConfig;
    use crate::users::UserManager;
    use std::path::Path;
    use tempfile::tempdir;
    use tokio::io::{AsyncRead, AsyncWriteExt, DuplexStream};

    const DOMAIN: &str = "example.com";
    const PW: &str = "password123";

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    fn no_clamav() -> AntiVirus {
        AntiVirus::with_config(ClamAVConfig {
            enabled: false,
            ..Default::default()
        })
    }

    /// Context with user `bob` and group `team@example.com` (member: bob).
    async fn test_ctx_with(dir: &Path, antivirus: AntiVirus) -> SmtpContext {
        let users = Arc::new(UserManager::new(DOMAIN.to_string(), dir.to_path_buf()));
        users.create_user("bob", PW, None).await.unwrap();
        let storage = Arc::new(Storage::new(dir.to_path_buf(), users));
        ctx_for_storage(dir, storage, antivirus).await
    }

    /// Context around `storage` (which must contain user `bob`) with group
    /// `team@example.com` (member: bob).
    async fn ctx_for_storage(
        dir: &Path,
        storage: Arc<Storage>,
        antivirus: AntiVirus,
    ) -> SmtpContext {
        let groups = Arc::new(GroupManager::new(dir.to_path_buf()));
        groups
            .create_with_members(
                "team",
                "team@example.com",
                "bob",
                None,
                &["bob".to_string()],
            )
            .await
            .unwrap();
        SmtpContext::new(
            storage,
            groups,
            Arc::new(AntiSpam::new(dir.to_path_buf())),
            Arc::new(antivirus),
            "mail.example.com".to_string(),
            None,
            TLS_OFF,
        )
    }

    /// TLS not configured: no STARTTLS, AUTH allowed in plaintext.
    const TLS_OFF: TlsPolicy = TlsPolicy {
        tls_available: false,
        allow_plaintext: false,
    };
    /// TLS configured, plaintext AUTH refused (the default).
    const TLS_REQUIRED: TlsPolicy = TlsPolicy {
        tls_available: true,
        allow_plaintext: false,
    };
    /// Plain session opts as used on port 25/587.
    const PLAIN: SessionOpts = SessionOpts {
        tls: false,
        greet: true,
        submission: false,
    };

    /// Like `test_ctx`, with a self-signed `Tls` (in `dir/tls`) and `policy`.
    async fn tls_ctx(dir: &Path, policy: TlsPolicy) -> SmtpContext {
        let mut ctx = test_ctx(dir).await;
        ctx.tls = Some(crate::tls::test_support::self_signed(dir).await);
        ctx.policy = policy;
        ctx
    }

    async fn test_ctx(dir: &Path) -> SmtpContext {
        test_ctx_with(dir, no_clamav()).await
    }

    fn session() -> SmtpSession {
        SmtpSession {
            peer_ip: "127.0.0.1".to_string(),
            ..Default::default()
        }
    }

    /// A session ready for DATA with the given (already accepted) recipients.
    fn session_with(from: &str, rcpts: &[&str]) -> SmtpSession {
        SmtpSession {
            helo_domain: Some("client.example.org".to_string()),
            mail_from: Some(from.to_string()),
            rcpt_to: rcpts.iter().map(|s| s.to_string()).collect(),
            ..session()
        }
    }

    async fn cmd(line: &str, session: &mut SmtpSession, ctx: &SmtpContext) -> String {
        handle_line(line, session, ctx).await
    }

    async fn authenticate(session: &mut SmtpSession, ctx: &SmtpContext, user: &str) {
        let creds = base64::engine::general_purpose::STANDARD
            .encode(format!("\0{}\0{}", user, PW).as_bytes());
        let reply = cmd(&format!("AUTH PLAIN {}", creds), session, ctx).await;
        assert!(reply.starts_with("235"), "{}", reply);
    }

    fn message() -> String {
        "From: alice@sender.example.org\r\nTo: bob@example.com\r\nSubject: Lunch\r\n\
         Date: Thu, 1 Oct 2026 12:00:00 +0000\r\nMessage-ID: <1@sender.example.org>\r\n\
         \r\nSee you at noon.\r\n"
            .to_string()
    }

    async fn mailbox_len(ctx: &SmtpContext, user: &str) -> usize {
        ctx.storage
            .get_mailbox(user)
            .await
            .map(|m| m.emails.len())
            .unwrap_or(0)
    }

    async fn add_user(ctx: &SmtpContext, name: &str) {
        ctx.storage
            .user_manager()
            .create_user(name, PW, None)
            .await
            .unwrap();
    }

    async fn read(input: &str, max: usize) -> std::io::Result<DataOutcome> {
        let mut reader = BufReader::new(input.as_bytes());
        read_data(&mut reader, max, DATA_DISCARD_LIMIT, DATA_LINE_TIMEOUT).await
    }

    #[tokio::test]
    async fn read_data_basic_and_dot_stuffing() {
        let out = read("Subject: x\r\n\r\nhello\r\n..dot\r\n.\r\n", 1000)
            .await
            .unwrap();
        assert_eq!(
            out,
            DataOutcome::Message("Subject: x\r\n\r\nhello\r\n.dot\r\n".to_string())
        );
    }

    #[tokio::test]
    async fn read_data_eof_is_error() {
        let err = read("Subject: x\r\n\r\nno terminator\r\n", 1000)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn read_data_size_cap_consumes_to_terminator() {
        let body = "x".repeat(200);
        let input = format!("{}\r\n{}\r\n.\r\nQUIT\r\n", body, body);
        let mut reader = BufReader::new(input.as_bytes());
        let out = read_data(&mut reader, 100, DATA_DISCARD_LIMIT, DATA_LINE_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(out, DataOutcome::TooLarge);
        // The next command is still readable.
        let mut rest = String::new();
        reader.read_line(&mut rest).await.unwrap();
        assert_eq!(rest, "QUIT\r\n");
    }

    #[tokio::test]
    async fn read_data_times_out() {
        let (client, server) = tokio::io::duplex(64);
        let mut reader = BufReader::new(server);
        let out = read_data(&mut reader, 1000, 1000, Duration::from_millis(20))
            .await
            .unwrap();
        assert_eq!(out, DataOutcome::TimedOut);
        drop(client);
    }

    #[tokio::test]
    async fn command_timeout_sends_421() {
        let dir = tempdir().unwrap();
        let mut ctx = test_ctx(dir.path()).await;
        ctx.command_timeout = Duration::from_millis(50);
        let ctx = Arc::new(ctx);
        let (client, server) = tokio::io::duplex(4096);
        let handle = tokio::spawn(handle_smtp_connection(
            server,
            "127.0.0.1".to_string(),
            ctx,
            PLAIN,
        ));
        let mut client = BufReader::new(client);
        let mut line = String::new();
        client.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("220"));
        line.clear();
        client.read_line(&mut line).await.unwrap();
        assert_eq!(line, "421 4.4.2 mail.example.com Timeout\r\n");
        assert!(matches!(handle.await.unwrap().unwrap(), SessionEnd::Closed));
    }

    #[test]
    fn mail_from_params() {
        let (addr, params) = split_address_and_params("<a@b.c> SIZE=1234 BODY=8BITMIME");
        assert_eq!(addr, "a@b.c");
        assert_eq!(parse_mail_size(params), Ok(Some(1234)));
        assert_eq!(parse_mail_size(""), Ok(None));
        assert!(parse_mail_size("SIZE=abc").is_err());
        assert_eq!(split_address_and_params(" <x@y> ").0, "x@y");
        assert_eq!(split_address_and_params("x@y SIZE=1").0, "x@y");
    }

    #[test]
    fn security_headers_are_prepended() {
        let spam = crate::antispam::SpamResult::new();
        let virus = crate::antivirus::ScanResult::clean();
        let out = add_security_headers(
            "Subject: hi\r\n folded\r\n\r\nbody\r\n",
            "Received: from x",
            &spam,
            &virus,
        );
        assert!(out.starts_with("Received: from x\r\nX-Spam-Score:"));
        assert!(out.contains("\r\nX-Virus-Scanned: kiss-mail (builtin only; ClamAV disabled)\r\n"));
        assert!(out.ends_with("Subject: hi\r\n folded\r\n\r\nbody\r\n"));
    }

    #[test]
    fn received_header_strips_controls() {
        let mut s = session_with("a@b", &[]);
        s.helo_domain = Some("evil\r\nX-Injected: 1".to_string());
        let h = received_header(&s, "mail.example.com", &["bob\r\nX: y".to_string()]);
        assert!(!h.contains("\r\nX-Injected"));
        assert!(!h.contains("\r\nX: y"));
    }

    #[test]
    fn helo_domain_validation() {
        assert!(is_valid_helo_domain("mail.example.org"));
        assert!(is_valid_helo_domain("[192.0.2.1]"));
        assert!(is_valid_helo_domain("[IPv6:2001:db8::1]"));
        assert!(!is_valid_helo_domain(""));
        assert!(!is_valid_helo_domain("bad domain"));
        assert!(!is_valid_helo_domain("x\ty"));
        assert!(!is_valid_helo_domain("[1.2.3.4"));
        assert!(!is_valid_helo_domain("[]"));
        assert!(!is_valid_helo_domain("a<b>"));
        assert!(!is_valid_helo_domain(&"a".repeat(256)));
    }

    #[tokio::test]
    async fn invalid_helo_rejected() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let mut s = session();
        assert_eq!(
            cmd("EHLO bad<host>", &mut s, &ctx).await,
            "501 5.5.2 Invalid domain"
        );
        assert_eq!(
            cmd("HELO a b", &mut s, &ctx).await,
            "501 5.5.2 Invalid domain"
        );
        assert!(s.helo_domain.is_none());
        assert!(
            cmd("EHLO [127.0.0.1]", &mut s, &ctx)
                .await
                .starts_with("250-")
        );
        assert!(
            cmd("HELO client.example.org", &mut s, &ctx)
                .await
                .starts_with("250 ")
        );
    }

    #[tokio::test]
    async fn auth_login_two_step_continuation() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let mut s = session();

        // Bad password
        assert_eq!(cmd("AUTH LOGIN", &mut s, &ctx).await, "334 VXNlcm5hbWU6");
        assert_eq!(cmd(&b64("bob"), &mut s, &ctx).await, "334 UGFzc3dvcmQ6");
        assert!(cmd(&b64("wrong"), &mut s, &ctx).await.starts_with("535"));
        assert!(!s.authenticated);

        // Cancelled
        assert_eq!(cmd("AUTH LOGIN", &mut s, &ctx).await, "334 VXNlcm5hbWU6");
        assert!(cmd("*", &mut s, &ctx).await.starts_with("501"));
        assert_eq!(s.auth_state, AuthState::None);

        // Success
        assert_eq!(cmd("AUTH LOGIN", &mut s, &ctx).await, "334 VXNlcm5hbWU6");
        assert_eq!(cmd(&b64("bob"), &mut s, &ctx).await, "334 UGFzc3dvcmQ6");
        assert!(cmd(&b64(PW), &mut s, &ctx).await.starts_with("235"));
        assert!(s.authenticated);
        assert_eq!(s.auth_username.as_deref(), Some("bob"));
    }

    #[tokio::test]
    async fn auth_login_with_initial_response() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let mut s = session();
        assert_eq!(
            cmd(&format!("AUTH LOGIN {}", b64("bob")), &mut s, &ctx).await,
            "334 UGFzc3dvcmQ6"
        );
        assert!(cmd(&b64(PW), &mut s, &ctx).await.starts_with("235"));
        assert!(s.authenticated);
    }

    #[tokio::test]
    async fn rcpt_external_domain_denied_unauthenticated() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        assert_eq!(
            cmd("MAIL FROM:<alice@sender.example.org>", &mut s, &ctx).await,
            SMTP_OK
        );
        assert_eq!(
            cmd("RCPT TO:<carol@elsewhere.example.net>", &mut s, &ctx).await,
            "550 5.7.1 Relaying denied"
        );
        assert!(s.rcpt_to.is_empty());
    }

    #[tokio::test]
    async fn rcpt_external_domain_denied_even_when_authenticated() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        authenticate(&mut s, &ctx, "bob").await;
        assert_eq!(
            cmd("MAIL FROM:<bob@example.com>", &mut s, &ctx).await,
            SMTP_OK
        );
        assert!(
            cmd("RCPT TO:<carol@elsewhere.example.net>", &mut s, &ctx)
                .await
                .starts_with("550 5.7.1 Relaying not supported")
        );
        assert!(s.rcpt_to.is_empty());
    }

    #[tokio::test]
    async fn mail_from_size_over_max_rejected() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        let reply = cmd(
            &format!(
                "MAIL FROM:<alice@sender.example.org> SIZE={}",
                MAX_MESSAGE_SIZE + 1
            ),
            &mut s,
            &ctx,
        )
        .await;
        assert!(reply.starts_with("552 5.3.4"), "{}", reply);
        assert!(s.mail_from.is_none());
    }

    #[tokio::test]
    async fn rcpt_quota_too_small_gives_552() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        ctx.storage
            .user_manager()
            .update_user("bob", |u| u.quota.max_message_size = 100)
            .await
            .unwrap();
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        cmd(
            "MAIL FROM:<alice@sender.example.org> SIZE=1000",
            &mut s,
            &ctx,
        )
        .await;
        assert_eq!(
            cmd("RCPT TO:<bob@example.com>", &mut s, &ctx).await,
            "552 5.3.4 Message too large for recipient"
        );
    }

    #[tokio::test]
    async fn mail_from_local_domain_requires_auth() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        for from in ["bob@example.com", "bob@EXAMPLE.com", "x@mail.example.com"] {
            assert_eq!(
                cmd(&format!("MAIL FROM:<{}>", from), &mut s, &ctx).await,
                "550 5.7.1 Authentication required to send as a local user"
            );
        }
        // Null sender and external senders are fine.
        assert_eq!(cmd("MAIL FROM:<>", &mut s, &ctx).await, SMTP_OK);
        cmd("RSET", &mut s, &ctx).await;
        assert_eq!(
            cmd("MAIL FROM:<alice@sender.example.org>", &mut s, &ctx).await,
            SMTP_OK
        );
        cmd("RSET", &mut s, &ctx).await;
        authenticate(&mut s, &ctx, "bob").await;
        assert_eq!(
            cmd("MAIL FROM:<bob@example.com>", &mut s, &ctx).await,
            SMTP_OK
        );
    }

    #[tokio::test]
    async fn auth_with_password_change_required_is_refused() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        ctx.storage
            .user_manager()
            .update_user("bob", |u| u.password_change_required = true)
            .await
            .unwrap();
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        let creds =
            base64::engine::general_purpose::STANDARD.encode(format!("\0bob\0{}", PW).as_bytes());
        let reply = cmd(&format!("AUTH PLAIN {}", creds), &mut s, &ctx).await;
        assert!(
            reply.starts_with("535 5.7.0 Password change required; change it "),
            "{}",
            reply
        );
        assert!(reply.contains("/account/password"), "{}", reply);
        assert!(!s.authenticated);
    }

    const SMTP_NOT_OWNER: &str = "550 5.7.1 Sender address not owned by authenticated user";

    #[tokio::test]
    async fn authenticated_user_cannot_send_as_another_local_user() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        add_user(&ctx, "alice").await;
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        authenticate(&mut s, &ctx, "alice").await;

        for from in ["bob@example.com", "BOB@mail.example.com", "bob@localhost"] {
            assert_eq!(
                cmd(&format!("MAIL FROM:<{}>", from), &mut s, &ctx).await,
                SMTP_NOT_OWNER,
                "{}",
                from
            );
            assert!(s.mail_from.is_none());
        }
        // Her own address, in any case and on any local domain.
        for from in [
            "alice@example.com",
            "Alice@EXAMPLE.COM",
            "ALICE@mail.example.com",
        ] {
            assert_eq!(
                cmd(&format!("MAIL FROM:<{}>", from), &mut s, &ctx).await,
                SMTP_OK,
                "{}",
                from
            );
            cmd("RSET", &mut s, &ctx).await;
        }
        // Null sender and external senders are unaffected at MAIL.
        assert_eq!(cmd("MAIL FROM:<>", &mut s, &ctx).await, SMTP_OK);
        cmd("RSET", &mut s, &ctx).await;
        assert_eq!(
            cmd("MAIL FROM:<bob@sender.example.org>", &mut s, &ctx).await,
            SMTP_OK
        );
    }

    #[tokio::test]
    async fn group_rcpt_requires_authenticated_member() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let denied = "550 5.7.1 Sender not permitted to post to this group";

        // External sender with a member's local part.
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        assert_eq!(
            cmd("MAIL FROM:<bob@evil.example>", &mut s, &ctx).await,
            SMTP_OK
        );
        assert_eq!(
            cmd("RCPT TO:<team@example.com>", &mut s, &ctx).await,
            denied
        );

        // Unauthenticated local sender: rejected at MAIL.
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        assert!(
            cmd("MAIL FROM:<bob@example.com>", &mut s, &ctx)
                .await
                .starts_with("550 5.7.1")
        );

        // Authenticated as someone else, claiming to be bob: rejected at MAIL.
        add_user(&ctx, "mallory").await;
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        authenticate(&mut s, &ctx, "mallory").await;
        assert_eq!(
            cmd("MAIL FROM:<bob@example.com>", &mut s, &ctx).await,
            SMTP_NOT_OWNER
        );

        // Authenticated bob.
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        authenticate(&mut s, &ctx, "bob").await;
        assert_eq!(
            cmd("MAIL FROM:<Bob@example.com>", &mut s, &ctx).await,
            SMTP_OK
        );
        assert_eq!(
            cmd("RCPT TO:<team@example.com>", &mut s, &ctx).await,
            SMTP_OK
        );
        assert_eq!(s.expanded_count, 1);
    }

    #[tokio::test]
    async fn expanded_recipient_cap_enforced() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;

        // At RCPT time (group and plain recipients).
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        authenticate(&mut s, &ctx, "bob").await;
        cmd("MAIL FROM:<bob@example.com>", &mut s, &ctx).await;
        s.expanded_count = MAX_EXPANDED_RECIPIENTS;
        assert_eq!(
            cmd("RCPT TO:<team@example.com>", &mut s, &ctx).await,
            SMTP_TOO_MANY_RECIPIENTS
        );
        assert_eq!(
            cmd("RCPT TO:<bob@example.com>", &mut s, &ctx).await,
            SMTP_TOO_MANY_RECIPIENTS
        );
        s.expanded_count = MAX_EXPANDED_RECIPIENTS - 1;
        assert_eq!(
            cmd("RCPT TO:<bob@example.com>", &mut s, &ctx).await,
            SMTP_OK
        );

        // After expansion at DATA time.
        let rcpts: Vec<String> = (0..=MAX_EXPANDED_RECIPIENTS)
            .map(|i| format!("u{}@example.com", i))
            .collect();
        let rcpt_refs: Vec<&str> = rcpts.iter().map(|s| s.as_str()).collect();
        let s = session_with("alice@sender.example.org", &rcpt_refs);
        assert_eq!(
            process_message(&message(), &s, &ctx).await,
            SMTP_TOO_MANY_RECIPIENTS
        );
    }

    #[tokio::test]
    async fn process_message_delivers() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let s = session_with("alice@sender.example.org", &["bob@example.com"]);
        assert_eq!(
            process_message(&message(), &s, &ctx).await,
            "250 Message accepted"
        );
        let mailbox = ctx.storage.get_mailbox("bob").await.unwrap();
        assert_eq!(mailbox.emails.len(), 1);
        assert!(
            mailbox.emails[0]
                .raw
                .contains("X-Virus-Scanned: kiss-mail (builtin only; ClamAV disabled)")
        );
    }

    #[tokio::test]
    async fn process_message_save_failure_returns_451_and_rolls_back() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let blocker = dir.path().join("mailboxes.json");
        std::fs::create_dir(&blocker).unwrap();
        std::fs::write(blocker.join("keep"), b"x").unwrap();

        let s = session_with("alice@sender.example.org", &["bob@example.com"]);
        let reply = process_message(&message(), &s, &ctx).await;
        assert!(reply.starts_with("451"), "{}", reply);
        assert_eq!(mailbox_len(&ctx, "bob").await, 0);
        let quota = ctx
            .storage
            .user_manager()
            .get_user("bob")
            .await
            .unwrap()
            .quota;
        assert_eq!(quota.current_messages, 0);
    }

    #[tokio::test]
    async fn process_message_temporary_failure_rolls_back_and_451() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        add_user(&ctx, "alice").await;
        // bob's mailbox is full (temporary failure); alice can receive.
        ctx.storage
            .user_manager()
            .update_user("bob", |u| {
                u.quota.max_messages = 1;
                u.quota.current_messages = 1;
            })
            .await
            .unwrap();
        let s = session_with(
            "carol@sender.example.org",
            &["alice@example.com", "bob@example.com"],
        );
        let reply = process_message(&message(), &s, &ctx).await;
        assert!(reply.starts_with("451"), "{}", reply);
        assert_eq!(mailbox_len(&ctx, "alice").await, 0);
        assert_eq!(mailbox_len(&ctx, "bob").await, 0);
    }

    #[tokio::test]
    async fn process_message_all_permanent_returns_550() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let s = session_with("alice@sender.example.org", &["ghost@example.com"]);
        let reply = process_message(&message(), &s, &ctx).await;
        assert!(reply.starts_with("550 5.1.1"), "{}", reply);

        // Mixed: delivered + permanent failure is accepted.
        let s = session_with(
            "alice@sender.example.org",
            &["ghost@example.com", "bob@example.com"],
        );
        assert_eq!(
            process_message(&message(), &s, &ctx).await,
            "250 Message accepted"
        );
        assert_eq!(mailbox_len(&ctx, "bob").await, 1);
    }

    #[tokio::test]
    async fn empty_group_returns_550() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        ctx.groups
            .create("empty", "empty@example.com", "admin")
            .await
            .unwrap();
        let s = session_with("alice@sender.example.org", &["empty@example.com"]);
        let reply = process_message(&message(), &s, &ctx).await;
        assert!(reply.starts_with("550 5.1.1"), "{}", reply);
    }

    #[tokio::test]
    async fn process_message_expands_group_once_per_member() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        add_user(&ctx, "alice").await;
        ctx.groups.add_member("team", "alice").await.unwrap();
        let s = session_with(
            "carol@sender.example.org",
            &["team@example.com", "BOB@example.com", "bob@example.com"],
        );
        assert_eq!(
            process_message(&message(), &s, &ctx).await,
            "250 Message accepted"
        );
        assert_eq!(mailbox_len(&ctx, "bob").await, 1);
        assert_eq!(mailbox_len(&ctx, "alice").await, 1);
    }

    #[tokio::test]
    async fn clamav_required_and_skipped_returns_451() {
        let dir = tempdir().unwrap();
        let antivirus = AntiVirus::with_config(ClamAVConfig {
            address: "127.0.0.1:1".to_string(),
            timeout_secs: 1,
            enabled: true,
            required: true,
        });
        let ctx = test_ctx_with(dir.path(), antivirus).await;
        let s = session_with("alice@sender.example.org", &["bob@example.com"]);
        assert_eq!(
            process_message(&message(), &s, &ctx).await,
            "451 4.7.0 Virus scanner unavailable, try again later"
        );
        assert_eq!(mailbox_len(&ctx, "bob").await, 0);
    }

    // ---- Full sessions over an in-memory duplex stream ----

    type Client = BufReader<DuplexStream>;
    type TlsClient = BufReader<tokio_rustls::client::TlsStream<DuplexStream>>;
    type SessionTask = tokio::task::JoinHandle<
        Result<SessionEnd<DuplexStream>, Box<dyn std::error::Error + Send + Sync>>,
    >;
    type ConnTask = tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>;

    /// One session (`handle_smtp_connection`) over an in-memory stream.
    fn start_session(ctx: Arc<SmtpContext>, opts: SessionOpts) -> (Client, SessionTask) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let handle = tokio::spawn(handle_smtp_connection(
            server,
            "127.0.0.1".to_string(),
            ctx,
            opts,
        ));
        (BufReader::new(client), handle)
    }

    /// A whole connection (the §3.2 sequence, `serve_connection`) over an
    /// in-memory stream, as on the plain or the implicit-TLS listener.
    fn start_conn(ctx: Arc<SmtpContext>, implicit: bool) -> (Client, ConnTask) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let handle = tokio::spawn(serve_connection(
            server,
            "127.0.0.1".to_string(),
            ctx,
            implicit,
        ));
        (BufReader::new(client), handle)
    }

    /// Run the client side of the TLS handshake on `c`'s stream.
    async fn upgrade(dir: &Path, c: Client) -> TlsClient {
        assert!(c.buffer().is_empty(), "unread server bytes before TLS");
        BufReader::new(
            crate::tls::test_support::connect(dir, c.into_inner())
                .await
                .expect("client handshake"),
        )
    }

    /// After QUIT or a timeout on TLS the server sent close_notify: the
    /// client sees a clean EOF (rustls reports `UnexpectedEof` otherwise).
    async fn assert_clean_tls_eof(c: &mut TlsClient) {
        let mut rest = String::new();
        assert_eq!(c.read_line(&mut rest).await.unwrap(), 0, "{:?}", rest);
    }

    fn auth_plain_line(user: &str) -> String {
        format!("AUTH PLAIN {}", b64(&format!("\0{}\0{}", user, PW)))
    }

    /// Read one (possibly multi-line) reply.
    async fn reply<S: AsyncRead + AsyncWrite + Unpin>(client: &mut BufReader<S>) -> String {
        let mut out = String::new();
        loop {
            let mut line = String::new();
            let n = client.read_line(&mut line).await.unwrap();
            assert!(n > 0, "connection closed; got so far: {:?}", out);
            out.push_str(&line);
            if line.as_bytes().get(3) != Some(&b'-') {
                return out;
            }
        }
    }

    async fn send_line<S: AsyncRead + AsyncWrite + Unpin>(
        client: &mut BufReader<S>,
        line: &str,
    ) -> String {
        client
            .write_all(format!("{}\r\n", line).as_bytes())
            .await
            .unwrap();
        reply(client).await
    }

    #[tokio::test]
    async fn smtp_session_over_duplex_delivers_and_resets() {
        let dir = tempdir().unwrap();
        let ctx = Arc::new(test_ctx(dir.path()).await);
        let (mut c, handle) = start_session(Arc::clone(&ctx), PLAIN);
        assert!(reply(&mut c).await.starts_with("220"));
        let ehlo = send_line(&mut c, "EHLO client.example.org").await;
        assert!(ehlo.contains("250-ENHANCEDSTATUSCODES\r\n"), "{}", ehlo);
        assert!(ehlo.ends_with("250 OK\r\n"), "{}", ehlo);
        assert!(
            send_line(&mut c, "MAIL FROM:<alice@sender.example.org>")
                .await
                .starts_with("250")
        );
        assert!(
            send_line(&mut c, "RCPT TO:<bob@example.com>")
                .await
                .starts_with("250")
        );
        assert!(send_line(&mut c, "DATA").await.starts_with("354"));
        c.write_all(message().as_bytes()).await.unwrap();
        assert_eq!(send_line(&mut c, ".").await, "250 Message accepted\r\n");
        assert_eq!(mailbox_len(&ctx, "bob").await, 1);

        // The transaction was reset: a new one needs MAIL again.
        assert!(send_line(&mut c, "DATA").await.starts_with("503"));
        assert!(
            send_line(&mut c, "RCPT TO:<bob@example.com>")
                .await
                .starts_with("503")
        );
        assert!(send_line(&mut c, "QUIT").await.starts_with("221"));
        assert!(matches!(handle.await.unwrap().unwrap(), SessionEnd::Closed));
        // All processing slots were released.
        assert_eq!(ctx.data_slots.available_permits(), MAX_CONCURRENT_DATA);
    }

    #[tokio::test]
    async fn smtp_data_too_large_returns_552_and_session_continues() {
        let dir = tempdir().unwrap();
        let mut ctx = test_ctx(dir.path()).await;
        ctx.max_message_size = 200;
        let ctx = Arc::new(ctx);
        let (mut c, handle) = start_session(Arc::clone(&ctx), PLAIN);
        reply(&mut c).await;
        let ehlo = send_line(&mut c, "EHLO client.example.org").await;
        assert!(ehlo.contains("250-SIZE 200\r\n"), "{}", ehlo);
        send_line(&mut c, "MAIL FROM:<alice@sender.example.org>").await;
        send_line(&mut c, "RCPT TO:<bob@example.com>").await;
        assert!(send_line(&mut c, "DATA").await.starts_with("354"));
        let big = format!("Subject: big\r\n\r\n{}\r\n", "x".repeat(1000));
        c.write_all(big.as_bytes()).await.unwrap();
        assert!(send_line(&mut c, ".").await.starts_with("552 5.3.4"));
        assert_eq!(mailbox_len(&ctx, "bob").await, 0);

        // The session continues, with the transaction reset.
        assert_eq!(send_line(&mut c, "NOOP").await, "250 OK\r\n");
        assert!(send_line(&mut c, "DATA").await.starts_with("503"));
        assert!(send_line(&mut c, "QUIT").await.starts_with("221"));
        assert!(matches!(handle.await.unwrap().unwrap(), SessionEnd::Closed));
    }

    #[tokio::test]
    async fn read_data_too_large_abandoned_after_discard_limit() {
        let line = format!("{}\r\n", "x".repeat(98));
        let input = line.repeat(20); // 2000 bytes, never terminated
        let mut reader = BufReader::new(input.as_bytes());
        let out = read_data(&mut reader, 100, 500, DATA_LINE_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(out, DataOutcome::TooLargeAbandoned);
    }

    #[tokio::test]
    async fn smtp_to_imap_encrypted_round_trip() {
        // SMTP delivery into encrypted storage, then a protocol login (as
        // IMAP/POP3 do) decrypts it.
        let dir = tempdir().unwrap();
        let storage = crate::storage::test_storage_encrypted(dir.path()).await;
        let ctx = ctx_for_storage(dir.path(), Arc::clone(&storage), no_clamav()).await;
        let s = session_with("alice@sender.example.org", &["bob@example.com"]);
        let body = "Subject: secret\r\n\r\nTOP-SECRET-SMTP-BODY\r\n";
        assert_eq!(
            process_message(body, &s, &ctx).await,
            "250 Message accepted"
        );
        let email = storage
            .get_mailbox("bob")
            .await
            .unwrap()
            .emails
            .last()
            .cloned()
            .unwrap();
        assert!(email.is_encrypted());
        assert!(!email.raw.contains("TOP-SECRET-SMTP-BODY"));
        let saved = std::fs::read_to_string(dir.path().join("mailboxes.json")).unwrap();
        assert!(!saved.contains("TOP-SECRET-SMTP-BODY"));

        let outcome = storage
            .login("bob", PW, "127.0.0.1", "IMAP", false)
            .await
            .unwrap();
        assert!(outcome.key_generation.is_some());
        let content = storage.email_content("bob", &email).await;
        assert!(content.contains("TOP-SECRET-SMTP-BODY"));
        assert!(content.contains("X-Virus-Scanned: kiss-mail"));
        storage.logout("bob", outcome.key_generation).await;
    }

    #[tokio::test]
    async fn expanded_member_temp_failure_still_delivers_others() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        add_user(&ctx, "alice").await;
        ctx.groups.add_member("team", "alice").await.unwrap();
        // bob's mailbox is full (temporary failure).
        ctx.storage
            .user_manager()
            .update_user("bob", |u| {
                u.quota.max_messages = 1;
                u.quota.current_messages = 1;
            })
            .await
            .unwrap();

        // bob reached only through the group: alice still gets it, 250.
        let s = session_with("carol@sender.example.org", &["team@example.com"]);
        assert_eq!(
            process_message(&message(), &s, &ctx).await,
            "250 Message accepted"
        );
        assert_eq!(mailbox_len(&ctx, "alice").await, 1);
        assert_eq!(mailbox_len(&ctx, "bob").await, 0);

        // bob also named directly: the whole message is retried (451) and
        // alice's copy rolled back.
        let s = session_with(
            "carol@sender.example.org",
            &["team@example.com", "bob@example.com"],
        );
        let reply = process_message(&message(), &s, &ctx).await;
        assert!(reply.starts_with("451"), "{}", reply);
        assert_eq!(mailbox_len(&ctx, "alice").await, 1);
    }

    #[tokio::test]
    async fn member_cannot_use_group_address_as_sender() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        authenticate(&mut s, &ctx, "bob").await;
        assert_eq!(
            cmd("MAIL FROM:<team@example.com>", &mut s, &ctx).await,
            SMTP_NOT_OWNER
        );
        assert!(s.mail_from.is_none());
    }

    #[tokio::test]
    async fn mail_from_bare_local_part_and_trailing_dot() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        add_user(&ctx, "alice").await;
        let auth_required = "550 5.7.1 Authentication required to send as a local user";

        // Unauthenticated: a bare local part would otherwise skip the
        // ownership check, so it is treated as local.
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        for from in ["bob", "bob@example.com.", "bob@MAIL.example.com."] {
            assert_eq!(
                cmd(&format!("MAIL FROM:<{}>", from), &mut s, &ctx).await,
                auth_required,
                "{}",
                from
            );
        }

        // Authenticated as alice.
        authenticate(&mut s, &ctx, "alice").await;
        for from in ["bob", "bob@example.com."] {
            assert_eq!(
                cmd(&format!("MAIL FROM:<{}>", from), &mut s, &ctx).await,
                SMTP_NOT_OWNER,
                "{}",
                from
            );
        }
        for from in ["alice", "alice@example.com."] {
            assert_eq!(
                cmd(&format!("MAIL FROM:<{}>", from), &mut s, &ctx).await,
                SMTP_OK,
                "{}",
                from
            );
            cmd("RSET", &mut s, &ctx).await;
        }
    }

    #[tokio::test]
    async fn user_address_wins_over_group() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        // A user whose address collides with the group's.
        add_user(&ctx, "team").await;

        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        cmd("MAIL FROM:<alice@sender.example.org>", &mut s, &ctx).await;
        // Accepted as the user (the group would refuse external senders).
        assert_eq!(
            cmd("RCPT TO:<team@example.com>", &mut s, &ctx).await,
            SMTP_OK
        );
        assert_eq!(s.expanded_count, 1);

        let s = session_with("alice@sender.example.org", &["team@example.com"]);
        assert_eq!(
            process_message(&message(), &s, &ctx).await,
            "250 Message accepted"
        );
        assert_eq!(mailbox_len(&ctx, "team").await, 1);
        assert_eq!(mailbox_len(&ctx, "bob").await, 0);
    }

    #[tokio::test]
    async fn helo_underscore_ok() {
        assert!(is_valid_helo_domain("my_host.example.org"));
        assert!(is_valid_helo_domain("_dmarc-like"));
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let mut s = session();
        assert_eq!(
            cmd("HELO win_pc.corp.example", &mut s, &ctx).await,
            "250 mail.example.com Hello win_pc.corp.example"
        );
    }

    #[tokio::test]
    async fn all_too_large_returns_552() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        add_user(&ctx, "alice").await;
        for user in ["bob", "alice"] {
            ctx.storage
                .user_manager()
                .update_user(user, |u| u.quota.max_message_size = 10)
                .await
                .unwrap();
        }
        let s = session_with(
            "carol@sender.example.org",
            &["bob@example.com", "alice@example.com"],
        );
        assert_eq!(
            process_message(&message(), &s, &ctx).await,
            "552 5.3.4 Message too large for recipient(s)"
        );

        // Mixed with an unknown user: 5.1.1.
        let s = session_with(
            "carol@sender.example.org",
            &["bob@example.com", "ghost@example.com"],
        );
        let reply = process_message(&message(), &s, &ctx).await;
        assert!(reply.starts_with("550 5.1.1"), "{}", reply);
    }

    // ---- TLS: STARTTLS, TLS-required AUTH, implicit-TLS submission ----

    const ENCRYPTION_REQUIRED: &str =
        "538 5.7.11 Encryption required for requested authentication mechanism";

    #[tokio::test]
    async fn ehlo_plain_lists_starttls_not_auth() {
        let dir = tempdir().unwrap();
        let ctx = tls_ctx(dir.path(), TLS_REQUIRED).await;
        let mut s = session();
        let ehlo = cmd("EHLO client.example.org", &mut s, &ctx).await;
        assert!(ehlo.contains("\r\n250-STARTTLS\r\n"), "{}", ehlo);
        assert!(!ehlo.contains("AUTH"), "{}", ehlo);
        assert!(ehlo.contains("250-ENHANCEDSTATUSCODES\r\n"), "{}", ehlo);
        assert!(ehlo.ends_with("\r\n250 OK"), "{}", ehlo);
    }

    #[tokio::test]
    async fn auth_plain_ir_before_tls_is_538_without_throttle_or_history() {
        let dir = tempdir().unwrap();
        let ctx = tls_ctx(dir.path(), TLS_REQUIRED).await;
        let users = ctx.storage.user_manager();
        let before = users.get_user("bob").await.unwrap();
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;

        // Valid credentials, an undecodable initial response, and the
        // continuation forms: all refused before any 334 or decoding.
        for line in [
            auth_plain_line("bob"),
            "AUTH PLAIN !!not-base64!!".to_string(),
            "AUTH PLAIN".to_string(),
            "AUTH LOGIN".to_string(),
            format!("AUTH LOGIN {}", b64("bob")),
            "AUTH CRAM-MD5".to_string(),
        ] {
            assert_eq!(
                cmd(&line, &mut s, &ctx).await,
                ENCRYPTION_REQUIRED,
                "{line}"
            );
            assert_eq!(s.auth_state, AuthState::None, "{line}");
            assert!(!s.authenticated);
        }
        // The next line is a command again, not SASL data.
        assert_eq!(cmd("NOOP", &mut s, &ctx).await, SMTP_OK);

        let after = users.get_user("bob").await.unwrap();
        assert_eq!(after.login_history.len(), before.login_history.len());
        assert!(after.login_history.is_empty());
        assert_eq!(after.failed_login_attempts, before.failed_login_attempts);
        assert_eq!(users.throttle_sizes(), (0, 0, 0));
    }

    #[tokio::test]
    async fn starttls_before_ehlo_is_503() {
        let dir = tempdir().unwrap();
        let ctx = tls_ctx(dir.path(), TLS_REQUIRED).await;
        let mut s = session();
        assert_eq!(
            cmd("STARTTLS", &mut s, &ctx).await,
            "503 5.5.1 Send EHLO first"
        );
    }

    #[tokio::test]
    async fn starttls_with_argument_is_501() {
        let dir = tempdir().unwrap();
        let ctx = tls_ctx(dir.path(), TLS_REQUIRED).await;
        let mut s = session();
        cmd("EHLO client.example.org", &mut s, &ctx).await;
        assert_eq!(
            cmd("STARTTLS now", &mut s, &ctx).await,
            "501 5.5.4 Syntax error"
        );
    }

    #[tokio::test]
    async fn starttls_upgrade_resets_state() {
        let dir = tempdir().unwrap();
        let ctx = Arc::new(tls_ctx(dir.path(), TLS_REQUIRED).await);
        let (mut c, handle) = start_conn(Arc::clone(&ctx), false);
        assert!(reply(&mut c).await.starts_with("220 "));
        send_line(&mut c, "EHLO client.example.org").await;
        // A transaction in progress is discarded by STARTTLS.
        assert_eq!(
            send_line(&mut c, "MAIL FROM:<alice@sender.example.org>").await,
            "250 OK\r\n"
        );
        assert_eq!(
            send_line(&mut c, "STARTTLS").await,
            "220 2.0.0 Ready to start TLS\r\n"
        );
        let mut c = upgrade(dir.path(), c).await;

        // No greeting after the handshake (the first reply read is MAIL's),
        // and no HELO name is carried over.
        assert!(
            send_line(&mut c, "MAIL FROM:<alice@sender.example.org>")
                .await
                .starts_with("503"),
        );
        let ehlo = send_line(&mut c, "EHLO client.example.org").await;
        assert!(ehlo.contains("250-AUTH PLAIN LOGIN\r\n"), "{}", ehlo);
        assert!(!ehlo.contains("STARTTLS"), "{}", ehlo);
        // The pre-TLS transaction is gone.
        assert!(
            send_line(&mut c, "RCPT TO:<bob@example.com>")
                .await
                .starts_with("503")
        );
        assert_eq!(
            send_line(&mut c, &auth_plain_line("bob")).await,
            "235 2.7.0 Authentication successful\r\n"
        );
        let bob = ctx.storage.user_manager().get_user("bob").await.unwrap();
        let rec = bob.login_history.last().unwrap();
        assert!(rec.success);
        assert!(rec.tls);
        assert_eq!(rec.protocol, "SMTP");

        assert!(send_line(&mut c, "QUIT").await.starts_with("221"));
        assert_clean_tls_eof(&mut c).await;
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn second_starttls_is_554() {
        let dir = tempdir().unwrap();
        let ctx = Arc::new(tls_ctx(dir.path(), TLS_REQUIRED).await);
        let (mut c, handle) = start_conn(Arc::clone(&ctx), false);
        reply(&mut c).await;
        send_line(&mut c, "EHLO client.example.org").await;
        assert!(send_line(&mut c, "STARTTLS").await.starts_with("220 2.0.0"));
        let mut c = upgrade(dir.path(), c).await;
        // Before EHLO, and after EHLO + AUTH: TLS is already active.
        assert_eq!(
            send_line(&mut c, "STARTTLS").await,
            "554 5.5.1 TLS already active\r\n"
        );
        send_line(&mut c, "EHLO client.example.org").await;
        assert!(
            send_line(&mut c, &auth_plain_line("bob"))
                .await
                .starts_with("235")
        );
        assert_eq!(
            send_line(&mut c, "STARTTLS").await,
            "554 5.5.1 TLS already active\r\n"
        );
        assert!(send_line(&mut c, "QUIT").await.starts_with("221"));
        assert_clean_tls_eof(&mut c).await;
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn starttls_after_auth_is_503() {
        let dir = tempdir().unwrap();
        let policy = TlsPolicy {
            tls_available: true,
            allow_plaintext: true,
        };
        let ctx = tls_ctx(dir.path(), policy).await;
        let mut s = session();
        let ehlo = cmd("EHLO client.example.org", &mut s, &ctx).await;
        assert!(ehlo.contains("250-STARTTLS\r\n"), "{}", ehlo);
        assert!(ehlo.contains("250-AUTH PLAIN LOGIN\r\n"), "{}", ehlo);
        authenticate(&mut s, &ctx, "bob").await;
        let ehlo = cmd("EHLO client.example.org", &mut s, &ctx).await;
        assert!(!ehlo.contains("STARTTLS"), "{}", ehlo);
        assert_eq!(
            cmd("STARTTLS", &mut s, &ctx).await,
            "503 5.5.1 STARTTLS not permitted after AUTH"
        );
        // The plaintext login is recorded as such.
        let bob = ctx.storage.user_manager().get_user("bob").await.unwrap();
        assert!(!bob.login_history.last().unwrap().tls);
    }

    #[tokio::test]
    async fn tls_off_starttls_is_500_and_auth_advertised() {
        let dir = tempdir().unwrap();
        let ctx = test_ctx(dir.path()).await;
        let mut s = session();
        let ehlo = cmd("EHLO client.example.org", &mut s, &ctx).await;
        assert!(ehlo.contains("250-AUTH PLAIN LOGIN\r\n"), "{}", ehlo);
        assert!(!ehlo.contains("STARTTLS"), "{}", ehlo);
        assert_eq!(cmd("STARTTLS", &mut s, &ctx).await, SMTP_SYNTAX_ERROR);
        assert_eq!(cmd("STARTTLS x", &mut s, &ctx).await, SMTP_SYNTAX_ERROR);
        assert_eq!(SMTP_SYNTAX_ERROR, "500 Syntax error, command unrecognized");
        authenticate(&mut s, &ctx, "bob").await;
    }

    /// EHLO, MAIL, RCPT, DATA and a message to bob; returns the final reply.
    async fn deliver_unauthenticated<S: AsyncRead + AsyncWrite + Unpin>(
        c: &mut BufReader<S>,
    ) -> String {
        assert!(
            send_line(c, "EHLO client.example.org")
                .await
                .starts_with("250-")
        );
        assert_eq!(
            send_line(c, "MAIL FROM:<alice@sender.example.org>").await,
            "250 OK\r\n"
        );
        assert_eq!(
            send_line(c, "RCPT TO:<bob@example.com>").await,
            "250 OK\r\n"
        );
        assert!(send_line(c, "DATA").await.starts_with("354"));
        c.write_all(message().as_bytes()).await.unwrap();
        send_line(c, ".").await
    }

    async fn last_raw(ctx: &SmtpContext, user: &str) -> String {
        let mailbox = ctx.storage.get_mailbox(user).await.unwrap();
        mailbox.emails.last().unwrap().raw.clone()
    }

    #[tokio::test]
    async fn plain_port25_delivery_without_tls_still_works() {
        let dir = tempdir().unwrap();
        let ctx = Arc::new(tls_ctx(dir.path(), TLS_REQUIRED).await);
        let (mut c, handle) = start_conn(Arc::clone(&ctx), false);
        assert!(reply(&mut c).await.starts_with("220 "));
        assert_eq!(
            deliver_unauthenticated(&mut c).await,
            "250 Message accepted\r\n"
        );
        assert_eq!(mailbox_len(&ctx, "bob").await, 1);
        assert!(last_raw(&ctx, "bob").await.contains(" with ESMTP id "));
        assert!(send_line(&mut c, "QUIT").await.starts_with("221"));
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn received_header_says_esmtps_on_tls() {
        let dir = tempdir().unwrap();
        let ctx = Arc::new(tls_ctx(dir.path(), TLS_REQUIRED).await);
        let (mut c, handle) = start_conn(Arc::clone(&ctx), false);
        reply(&mut c).await;
        send_line(&mut c, "EHLO client.example.org").await;
        assert!(send_line(&mut c, "STARTTLS").await.starts_with("220 2.0.0"));
        let mut c = upgrade(dir.path(), c).await;
        assert_eq!(
            deliver_unauthenticated(&mut c).await,
            "250 Message accepted\r\n"
        );
        assert!(last_raw(&ctx, "bob").await.contains(" with ESMTPS id "));
        assert!(send_line(&mut c, "QUIT").await.starts_with("221"));
        handle.await.unwrap().unwrap();

        // All four combinations.
        let mut s = session_with("a@b", &[]);
        for (tls, auth, with) in [
            (false, false, " with ESMTP id "),
            (false, true, " with ESMTPA id "),
            (true, false, " with ESMTPS id "),
            (true, true, " with ESMTPSA id "),
        ] {
            s.tls = tls;
            s.authenticated = auth;
            let h = received_header(&s, "mail.example.com", &[]);
            assert!(h.contains(with), "{}", h);
        }
    }

    #[tokio::test]
    async fn submission_listener_mail_before_auth_is_530() {
        let dir = tempdir().unwrap();
        let ctx = Arc::new(tls_ctx(dir.path(), TLS_REQUIRED).await);
        let (c, handle) = start_conn(Arc::clone(&ctx), true);
        // Implicit TLS: the handshake comes first, then the greeting.
        let mut c = upgrade(dir.path(), c).await;
        assert!(reply(&mut c).await.starts_with("220 "));
        let ehlo = send_line(&mut c, "EHLO client.example.org").await;
        assert!(ehlo.contains("250-AUTH PLAIN LOGIN\r\n"), "{}", ehlo);
        assert!(!ehlo.contains("STARTTLS"), "{}", ehlo);
        assert_eq!(
            send_line(&mut c, "MAIL FROM:<alice@sender.example.org>").await,
            "530 5.7.0 Authentication required\r\n"
        );
        assert_eq!(
            send_line(&mut c, "STARTTLS").await,
            "554 5.5.1 TLS already active\r\n"
        );
        assert!(
            send_line(&mut c, &auth_plain_line("bob"))
                .await
                .starts_with("235")
        );
        assert_eq!(
            send_line(&mut c, "MAIL FROM:<bob@example.com>").await,
            "250 OK\r\n"
        );
        assert!(send_line(&mut c, "QUIT").await.starts_with("221"));
        assert_clean_tls_eof(&mut c).await;
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn starttls_pipelined_commands_are_discarded() {
        let dir = tempdir().unwrap();
        let ctx = Arc::new(tls_ctx(dir.path(), TLS_REQUIRED).await);
        let (mut c, handle) = start_conn(Arc::clone(&ctx), false);
        reply(&mut c).await;
        send_line(&mut c, "EHLO client.example.org").await;
        // One write: the MAIL line sits in the server's read buffer when
        // STARTTLS is accepted.
        c.write_all(b"STARTTLS\r\nMAIL FROM:<x@evil>\r\n")
            .await
            .unwrap();
        assert_eq!(reply(&mut c).await, "220 2.0.0 Ready to start TLS\r\n");
        // The handshake succeeds (the plaintext bytes never reach rustls)...
        let mut c = upgrade(dir.path(), c).await;
        // ...and no transaction exists under TLS.
        assert!(
            send_line(&mut c, "RCPT TO:<bob@example.com>")
                .await
                .starts_with("503")
        );
        send_line(&mut c, "EHLO client.example.org").await;
        assert!(
            send_line(&mut c, "RCPT TO:<bob@example.com>")
                .await
                .starts_with("503")
        );
        assert!(send_line(&mut c, "QUIT").await.starts_with("221"));
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tls_command_timeout_sends_421_and_close_notify() {
        let dir = tempdir().unwrap();
        let mut ctx = tls_ctx(dir.path(), TLS_REQUIRED).await;
        ctx.command_timeout = Duration::from_millis(200);
        let ctx = Arc::new(ctx);
        let (c, handle) = start_conn(Arc::clone(&ctx), true);
        let mut c = upgrade(dir.path(), c).await;
        assert!(reply(&mut c).await.starts_with("220 "));
        assert_eq!(
            reply(&mut c).await,
            "421 4.4.2 mail.example.com Timeout\r\n"
        );
        assert_clean_tls_eof(&mut c).await;
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn implicit_listener_without_tls_is_an_error() {
        let dir = tempdir().unwrap();
        let ctx = Arc::new(test_ctx(dir.path()).await);
        let (_c, handle) = start_conn(ctx, true);
        assert!(handle.await.unwrap().is_err());
    }

    fn test_peer() -> std::net::SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    /// Review Focus #1: plaintext sent to the implicit-TLS listener fails the
    /// handshake at once (no 15 s wait), gets no SMTP reply, and frees the
    /// connection slot.
    #[tokio::test]
    async fn plaintext_on_implicit_listener_closes_fast_and_frees_slot() {
        let dir = tempdir().unwrap();
        let ctx = Arc::new(tls_ctx(dir.path(), TLS_REQUIRED).await);
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let permit = Arc::clone(&connections).acquire_owned().await.unwrap();
        assert_eq!(connections.available_permits(), MAX_CONNECTIONS - 1);

        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(b"EHLO x\r\n").await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            handle_connection(server, test_peer(), ctx, true, permit),
        )
        .await
        .expect("handle_connection returns within 1 s");
        assert_eq!(connections.available_permits(), MAX_CONNECTIONS);

        // Whatever rustls sent (at most an alert), there is no SMTP reply.
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(!got.starts_with(b"2") && !got.starts_with(b"5"), "{got:?}");
        assert!(!String::from_utf8_lossy(&got).contains("ESMTP"), "{got:?}");
    }

    /// Review Focus #2: STARTTLS accepted, then the client hangs up or sends
    /// garbage instead of a ClientHello: no panic, the slot is freed.
    #[tokio::test]
    async fn starttls_then_hangup_or_garbage_frees_slot() {
        let dir = tempdir().unwrap();
        let ctx = Arc::new(tls_ctx(dir.path(), TLS_REQUIRED).await);
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        for garbage in [
            None,
            Some(&b"\x16\x03\x01garbage\r\n"[..]),
            Some(b"QUIT\r\n"),
        ] {
            let permit = Arc::clone(&connections).acquire_owned().await.unwrap();
            let (client, server) = tokio::io::duplex(4096);
            let task = tokio::spawn(handle_connection(
                server,
                test_peer(),
                Arc::clone(&ctx),
                false,
                permit,
            ));
            let mut c = BufReader::new(client);
            assert!(reply(&mut c).await.starts_with("220 "));
            send_line(&mut c, "EHLO client.example.org").await;
            assert!(send_line(&mut c, "STARTTLS").await.starts_with("220 2.0.0"));
            if let Some(bytes) = garbage {
                c.write_all(bytes).await.unwrap();
            }
            drop(c);
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("handle_connection returns promptly")
                .expect("no panic");
            assert_eq!(connections.available_permits(), MAX_CONNECTIONS);
        }
    }
}
