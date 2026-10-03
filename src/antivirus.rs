//! Anti-virus protection module.
//!
//! Implements attachment scanning and malware detection for emails.
//! Supports ClamAV integration (TCP `host:port`, or a Unix socket path on
//! Unix) when available, with built-in fallback scanning.
//!
//! The built-in scanner only signature-scans MIME parts that are attachments
//! (Content-Disposition: attachment, a filename, or a non-text content type),
//! matching byte patterns against the decoded content. Executable magic
//! numbers are matched at offset 0 only. Weak heuristics produce
//! non-blocking warnings instead of marking the message infected.
//!
//! Parsing fails closed: excessive MIME nesting and undecodable base64
//! attachments are threats; `message/rfc822` / `message/global` parts are
//! decoded and scanned recursively.

use crate::mime::{
    header, header_all, header_param, header_param_all, parse_headers, split_headers_body,
};
use base64::Engine;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Whether ClamAV took part in a scan
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClamavStatus {
    /// ClamAV scanned the message
    Scanned,
    /// ClamAV is enabled but did not scan this message (reason)
    Skipped(String),
    /// ClamAV is disabled by configuration
    Disabled,
}

/// Scan result for an email
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub is_infected: bool,
    pub threats: Vec<String>,
    /// Non-blocking findings (suspicious but not treated as infection)
    pub warnings: Vec<String>,
    /// ClamAV participation in this scan
    pub clamav: ClamavStatus,
}

impl ScanResult {
    pub fn clean() -> Self {
        Self {
            is_infected: false,
            threats: Vec::new(),
            warnings: Vec::new(),
            clamav: ClamavStatus::Disabled,
        }
    }

    /// Which scanners ran, e.g. `"builtin+clamav"` or
    /// `"builtin only; ClamAV unavailable: <reason>"`.
    pub fn scanner_summary(&self) -> String {
        match &self.clamav {
            ClamavStatus::Scanned => "builtin+clamav".to_string(),
            ClamavStatus::Disabled => "builtin only; ClamAV disabled".to_string(),
            ClamavStatus::Skipped(reason) => {
                format!("builtin only; ClamAV unavailable: {}", reason)
            }
        }
    }

    /// Record a threat once (no duplicate entries).
    fn add_threat_once(&mut self, threat: &str) {
        if !self.threats.iter().any(|t| t == threat) {
            self.add_threat(threat.to_string());
        } else {
            self.is_infected = true;
        }
    }

    pub fn add_threat(&mut self, threat: String) {
        self.is_infected = true;
        self.threats.push(threat);
    }

    /// Record a suspicious finding that does not mark the message infected.
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
}

/// ClamAV connection configuration
#[derive(Debug, Clone)]
pub struct ClamAVConfig {
    /// ClamAV server address: `host:port` for TCP (e.g. "127.0.0.1:3310"),
    /// or an absolute Unix socket path (e.g. "/var/run/clamav/clamd.sock",
    /// Unix only).
    pub address: String,
    /// Connect/read/write timeout in seconds
    pub timeout_secs: u64,
    /// Whether ClamAV is enabled
    pub enabled: bool,
    /// Whether mail must be rejected (temporarily) when ClamAV is enabled
    /// but could not scan it (`CLAMAV_REQUIRED`)
    pub required: bool,
}

impl Default for ClamAVConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:3310".to_string(),
            timeout_secs: 30,
            enabled: true,
            required: false,
        }
    }
}

impl ClamAVConfig {
    /// Read `CLAMAV_ADDRESS`, `CLAMAV_ENABLED` and `CLAMAV_REQUIRED`.
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            address: std::env::var("CLAMAV_ADDRESS")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or(defaults.address.clone()),
            enabled: crate::config::env_bool("CLAMAV_ENABLED", defaults.enabled),
            required: crate::config::env_bool("CLAMAV_REQUIRED", defaults.required),
            ..defaults
        }
    }
}

/// How long to wait before re-probing ClamAV after a connection failure.
const CLAMAV_RETRY_BACKOFF: Duration = Duration::from_secs(60);
/// Only the first part of each attachment is searched for weak patterns
/// (strong signatures are searched over the whole decoded attachment, up to
/// `max_attachment_size`).
const CONTENT_SCAN_LIMIT: usize = 1024 * 1024;
/// Threat recorded when MIME nesting exceeds [`MAX_MIME_DEPTH`].
const DEPTH_THREAT: &str = "MIME structure too deeply nested";
/// Maximum MIME nesting depth that is parsed.
const MAX_MIME_DEPTH: usize = 8;

/// ClamAV availability state
#[derive(Debug, Clone, Copy)]
enum ClamState {
    /// Not probed yet
    Unknown,
    /// Last connection succeeded
    Available,
    /// Last connection failed; don't retry before `retry_at`
    Unavailable { retry_at: Instant },
}

/// ClamAV failure kinds
#[derive(Debug)]
enum ClamError {
    /// Could not talk to clamd (connect/IO failure) -> back off
    Unavailable(String),
    /// clamd replied with an error or an unparseable/empty reply -> no back-off
    Reply(String),
}

/// Parse a clamd INSTREAM reply. Fail closed: the reply is clean only if it
/// is exactly `stream: OK` (after trimming trailing NULs/newlines); a
/// `stream: <name> FOUND` line is a threat; anything else, including an
/// empty reply, is `ClamError::Reply`.
fn parse_clamd_reply(response: &[u8]) -> Result<Vec<String>, ClamError> {
    let text = String::from_utf8_lossy(response);
    let line = text.trim_end_matches(['\0', '\r', '\n']);
    if line == "stream: OK" {
        return Ok(Vec::new());
    }
    if !line.contains(['\0', '\r', '\n']) {
        if let Some(name) = line
            .strip_prefix("stream: ")
            .and_then(|r| r.strip_suffix(" FOUND"))
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            return Ok(vec![name.to_string()]);
        }
    }
    let shown: String = line.chars().take(200).collect();
    Err(ClamError::Reply(if shown.is_empty() {
        "empty reply from clamd".to_string()
    } else {
        format!("unexpected clamd reply: {}", shown.escape_debug())
    }))
}

/// Every distinct filename a part declares: all forms (plain, RFC 2231
/// extended and continued, duplicates included) of `filename` on every
/// Content-Disposition header and of `name` on every Content-Type header.
/// `ct_full` (the effective Content-Type, possibly defaulted) is included
/// even when the part has no Content-Type header.
fn part_filenames(headers: &[(String, String)], ct_full: &str) -> Vec<String> {
    let mut content_types = header_all(headers, "content-type");
    if !content_types.contains(&ct_full) {
        content_types.push(ct_full);
    }
    let mut filenames: Vec<String> = Vec::new();
    let names = header_all(headers, "content-disposition")
        .into_iter()
        .flat_map(|d| header_param_all(d, "filename"))
        .chain(
            content_types
                .into_iter()
                .flat_map(|ct| header_param_all(ct, "name")),
        );
    for f in names {
        if !f.is_empty() && !filenames.contains(&f) {
            filenames.push(f);
        }
    }
    filenames
}

/// How a signature is matched and what a match means
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigKind {
    /// Must appear at offset 0 of the decoded attachment -> infected
    Magic,
    /// Anywhere in the decoded attachment -> infected
    Strong,
    /// Anywhere in the decoded attachment -> warning only
    Weak,
}

/// Byte signature
#[derive(Debug, Clone, Copy)]
struct Signature {
    pattern: &'static [u8],
    name: &'static str,
    kind: SigKind,
}

const fn sig(pattern: &'static [u8], name: &'static str, kind: SigKind) -> Signature {
    Signature {
        pattern,
        name,
        kind,
    }
}

/// Connected ClamAV stream (TCP or Unix socket)
enum ClamStream {
    Tcp(std::net::TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl std::io::Read for ClamStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.read(buf),
        }
    }
}

impl std::io::Write for ClamStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            #[cfg(unix)]
            Self::Unix(s) => s.flush(),
        }
    }
}

/// Connect to clamd at `address` (Unix socket path if it starts with '/').
fn clamav_connect(address: &str, timeout: Duration) -> Result<ClamStream, String> {
    if address.starts_with('/') {
        #[cfg(unix)]
        {
            let s = std::os::unix::net::UnixStream::connect(address)
                .map_err(|e| format!("Connection to {} failed: {}", address, e))?;
            s.set_read_timeout(Some(timeout)).ok();
            s.set_write_timeout(Some(timeout)).ok();
            return Ok(ClamStream::Unix(s));
        }
        #[cfg(not(unix))]
        {
            return Err("Unix socket ClamAV addresses are not supported on this platform".into());
        }
    }

    use std::net::ToSocketAddrs;
    let addrs = address
        .to_socket_addrs()
        .map_err(|e| format!("Invalid ClamAV address {}: {}", address, e))?;
    let mut last_err = format!("No addresses resolved for {}", address);
    for addr in addrs {
        match std::net::TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                s.set_read_timeout(Some(timeout)).ok();
                s.set_write_timeout(Some(timeout)).ok();
                return Ok(ClamStream::Tcp(s));
            }
            Err(e) => last_err = format!("Connection to {} failed: {}", addr, e),
        }
    }
    Err(last_err)
}

/// Split a multipart body into its parts using delimiter lines.
fn split_multipart<'a>(body: &'a str, boundary: &str) -> Vec<&'a str> {
    let delim = format!("--{}", boundary);
    let close = format!("--{}--", boundary);
    let mut parts = Vec::new();
    let mut start: Option<usize> = None;
    let mut pos = 0;
    for line in body.split_inclusive('\n') {
        let l = line.trim_end_matches(['\r', '\n']).trim_end();
        if l == delim || l == close {
            if let Some(s) = start {
                parts.push(&body[s..pos]);
            }
            if l == close {
                return parts;
            }
            start = Some(pos + line.len());
        }
        pos += line.len();
    }
    if let Some(s) = start {
        parts.push(&body[s..]);
    }
    parts
}

/// Find `needle` in `haystack`.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Anti-virus scanner (`Send + Sync`; share via `Arc`)
#[derive(Debug)]
pub struct AntiVirus {
    /// Maximum attachment size in bytes (default: 10MB)
    pub max_attachment_size: usize,
    /// Maximum number of attachments
    pub max_attachments: usize,
    /// Blocked file extensions
    blocked_extensions: Vec<String>,
    /// Dangerous MIME types
    dangerous_mime_types: Vec<String>,
    /// Known malware byte signatures
    malware_signatures: Vec<Signature>,
    /// ClamAV configuration
    clamav_config: ClamAVConfig,
    /// ClamAV availability (with retry back-off)
    clamav_state: Mutex<ClamState>,
}

impl AntiVirus {
    /// Scanner configured from the environment (`CLAMAV_ADDRESS`,
    /// `CLAMAV_ENABLED`, `CLAMAV_REQUIRED`).
    pub fn new() -> Self {
        Self::with_config(ClamAVConfig::from_env())
    }

    /// Scanner with an explicit ClamAV configuration (no env access).
    pub fn with_config(clamav_config: ClamAVConfig) -> Self {
        Self {
            max_attachment_size: 10 * 1024 * 1024, // 10MB
            max_attachments: 50,
            clamav_config,
            clamav_state: Mutex::new(ClamState::Unknown),
            blocked_extensions: vec![
                // Executables
                ".exe".into(),
                ".com".into(),
                ".cmd".into(),
                ".bat".into(),
                ".pif".into(),
                ".scr".into(),
                ".msi".into(),
                ".msp".into(),
                // Scripts
                ".js".into(),
                ".jse".into(),
                ".vbs".into(),
                ".vbe".into(),
                ".ws".into(),
                ".wsf".into(),
                ".wsc".into(),
                ".wsh".into(),
                ".ps1".into(),
                ".psm1".into(),
                ".psd1".into(),
                // Other dangerous
                ".hta".into(),
                ".cpl".into(),
                ".msc".into(),
                ".jar".into(),
                ".reg".into(),
                ".inf".into(),
                ".scf".into(),
                ".lnk".into(),
                ".prf".into(),
                ".prg".into(),
                ".crt".into(),
                // Office macros
                ".docm".into(),
                ".xlsm".into(),
                ".pptm".into(),
                ".dotm".into(),
                ".xltm".into(),
                ".potm".into(),
                ".xlam".into(),
                ".ppam".into(),
                ".sldm".into(),
                // Archives that can contain executables
                ".iso".into(),
                ".img".into(),
                ".vhd".into(),
                ".vhdx".into(),
            ],
            dangerous_mime_types: vec![
                "application/x-msdownload".into(),
                "application/x-msdos-program".into(),
                "application/x-executable".into(),
                "application/x-dosexec".into(),
                "application/hta".into(),
                "application/x-ms-shortcut".into(),
                "application/x-javascript".into(),
                "text/javascript".into(),
                "application/x-vbscript".into(),
                "application/x-powershell".into(),
            ],
            malware_signatures: vec![
                // Executable magic numbers (offset 0 only)
                sig(b"MZ", "Windows executable (MZ header)", SigKind::Magic),
                sig(b"\x7FELF", "Linux executable (ELF)", SigKind::Magic),
                sig(
                    b"\xCA\xFE\xBA\xBE",
                    "Java class/Mach-O fat binary",
                    SigKind::Magic,
                ),
                sig(b"\xFE\xED\xFA\xCE", "Mach-O 32-bit", SigKind::Magic),
                sig(b"\xFE\xED\xFA\xCF", "Mach-O 64-bit", SigKind::Magic),
                sig(b"\xCE\xFA\xED\xFE", "Mach-O 32-bit (LE)", SigKind::Magic),
                sig(b"\xCF\xFA\xED\xFE", "Mach-O 64-bit (LE)", SigKind::Magic),
                sig(b"#!/bin", "Shell script (#!/bin)", SigKind::Magic),
                sig(b"#!/usr/bin", "Shell script (#!/usr/bin)", SigKind::Magic),
                // EICAR test signature (for testing AV)
                sig(
                    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                    "EICAR test file",
                    SigKind::Strong,
                ),
                // VBA/Macro auto-run indicators
                sig(
                    b"Attribute VB_",
                    "VBA macro (Attribute VB_)",
                    SigKind::Strong,
                ),
                sig(b"AutoOpen", "AutoOpen macro", SigKind::Strong),
                sig(b"AutoExec", "AutoExec macro", SigKind::Strong),
                sig(b"Document_Open", "Document_Open macro", SigKind::Strong),
                sig(b"Workbook_Open", "Workbook_Open macro", SigKind::Strong),
                // Execution / download primitives
                sig(b"cmd.exe /c", "cmd.exe /c execution", SigKind::Strong),
                sig(b"powershell -", "PowerShell execution", SigKind::Strong),
                sig(b"URLDownloadToFile", "URLDownloadToFile", SigKind::Strong),
                // Weak indicators (common in legitimate documents) -> warning only
                sig(b"PowerShell", "PowerShell script", SigKind::Weak),
                sig(b"Invoke-", "PowerShell Invoke- command", SigKind::Weak),
                sig(b"Sub A", "VBA Sub procedure", SigKind::Weak),
                sig(b"Function ", "VBA Function", SigKind::Weak),
                sig(b"wscript ", "WScript execution", SigKind::Weak),
                sig(b"cscript ", "CScript execution", SigKind::Weak),
                // Base64 encoded "cmd" and "powershell"
                sig(b"Y21k", "Base64 encoded 'cmd'", SigKind::Weak),
                sig(
                    b"cG93ZXJzaGVsbA",
                    "Base64 encoded 'powershell'",
                    SigKind::Weak,
                ),
                // Registry manipulation
                sig(b"REG_SZ", "Registry string value", SigKind::Weak),
                sig(b"HKEY_", "Registry hive reference", SigKind::Weak),
                // Network indicators
                sig(b"WinHttp", "WinHTTP usage", SigKind::Weak),
                // Ransomware indicators
                sig(
                    b"Your files have b",
                    "Ransomware message pattern",
                    SigKind::Weak,
                ),
                sig(b"Encrypted with", "Encryption notice", SigKind::Weak),
            ],
        }
    }

    /// Scan an email for viruses and malicious content.
    ///
    /// Synchronous (may block on ClamAV I/O up to the configured timeout);
    /// call from async code via `tokio::task::spawn_blocking`.
    pub fn scan(&self, raw_email: &str) -> ScanResult {
        // Try ClamAV if available
        let (clamav_status, clamav_threats) = self.try_clamav_scan(raw_email.as_bytes());

        // Run built-in scan
        let mut result = self.builtin_scan(raw_email);
        result.clamav = clamav_status;

        // Merge ClamAV results
        for threat in clamav_threats {
            result.add_threat(format!("ClamAV: {}", threat));
        }

        if result.is_infected {
            tracing::warn!("Virus scan detected threats: {:?}", result.threats);
        }
        if !result.warnings.is_empty() {
            tracing::info!("Virus scan warnings (not blocking): {:?}", result.warnings);
        }

        result
    }

    /// Whether ClamAV should be tried now (not inside a failure back-off window).
    fn clamav_due(&self) -> bool {
        match self.clamav_state.lock().map(|s| *s) {
            Ok(ClamState::Unavailable { retry_at }) => Instant::now() >= retry_at,
            Ok(_) => true,
            Err(_) => true,
        }
    }

    /// Record a ClamAV connection outcome, logging state transitions.
    fn set_clamav_reachable(&self, reachable: bool, err: Option<&str>) {
        let Ok(mut state) = self.clamav_state.lock() else {
            return;
        };
        let prev = *state;
        if reachable {
            if matches!(prev, ClamState::Unavailable { .. }) {
                tracing::info!(
                    "ClamAV is reachable again at {}",
                    self.clamav_config.address
                );
            }
            *state = ClamState::Available;
        } else {
            match prev {
                ClamState::Unknown => tracing::info!(
                    "ClamAV not available ({}), using built-in scanner; retrying every {}s",
                    err.unwrap_or("unknown error"),
                    CLAMAV_RETRY_BACKOFF.as_secs()
                ),
                ClamState::Available => tracing::warn!(
                    "ClamAV became unavailable ({}), falling back to built-in scanner",
                    err.unwrap_or("unknown error")
                ),
                ClamState::Unavailable { .. } => {
                    tracing::debug!("ClamAV still unavailable: {}", err.unwrap_or(""))
                }
            }
            *state = ClamState::Unavailable {
                retry_at: Instant::now() + CLAMAV_RETRY_BACKOFF,
            };
        }
    }

    /// Whether mail must be temporarily rejected when ClamAV is enabled but
    /// did not scan it (`CLAMAV_REQUIRED`).
    pub fn clamav_required(&self) -> bool {
        self.clamav_config.required
    }

    /// Try to scan with ClamAV. Returns its participation status and any
    /// threats it reported.
    fn try_clamav_scan(&self, data: &[u8]) -> (ClamavStatus, Vec<String>) {
        if !self.clamav_config.enabled {
            return (ClamavStatus::Disabled, Vec::new());
        }
        if !self.clamav_due() {
            return (
                ClamavStatus::Skipped(format!(
                    "{} unreachable (retrying after back-off)",
                    self.clamav_config.address
                )),
                Vec::new(),
            );
        }

        match self.clamav_scan_sync(data) {
            Ok(threats) => {
                self.set_clamav_reachable(true, None);
                (ClamavStatus::Scanned, threats)
            }
            Err(ClamError::Reply(e)) => {
                // clamd is up but refused this message (e.g. size limit)
                self.set_clamav_reachable(true, None);
                tracing::warn!("ClamAV scan error ({}); using built-in scanner only", e);
                (
                    ClamavStatus::Skipped(format!("scan error: {}", e)),
                    Vec::new(),
                )
            }
            Err(ClamError::Unavailable(e)) => {
                self.set_clamav_reachable(false, Some(&e));
                (ClamavStatus::Skipped(e), Vec::new())
            }
        }
    }

    /// Synchronous ClamAV INSTREAM scan
    fn clamav_scan_sync(&self, data: &[u8]) -> Result<Vec<String>, ClamError> {
        use std::io::{Read, Write};

        let timeout = Duration::from_secs(self.clamav_config.timeout_secs);
        let mut stream =
            clamav_connect(&self.clamav_config.address, timeout).map_err(ClamError::Unavailable)?;
        let io = |what: &str, e: std::io::Error| ClamError::Unavailable(format!("{}: {}", what, e));

        // Send INSTREAM command
        stream
            .write_all(b"zINSTREAM\0")
            .map_err(|e| io("Write failed", e))?;

        // Send data in chunks (ClamAV protocol: 4-byte big-endian length + data)
        for chunk in data.chunks(4096) {
            let len = (chunk.len() as u32).to_be_bytes();
            stream
                .write_all(&len)
                .map_err(|e| io("Write length failed", e))?;
            stream
                .write_all(chunk)
                .map_err(|e| io("Write chunk failed", e))?;
        }

        // Send zero-length chunk to indicate end
        stream
            .write_all(&[0, 0, 0, 0])
            .map_err(|e| io("Write end failed", e))?;

        // Read response
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| io("Read failed", e))?;

        parse_clamd_reply(&response)
    }

    /// Check if ClamAV is available (probes with PING unless inside the
    /// failure back-off window).
    pub fn is_clamav_available(&self) -> bool {
        if !self.clamav_config.enabled {
            return false;
        }

        let state = self
            .clamav_state
            .lock()
            .map(|s| *s)
            .unwrap_or(ClamState::Unknown);
        match state {
            ClamState::Available => true,
            ClamState::Unavailable { retry_at } if Instant::now() < retry_at => false,
            _ => match self.clamav_ping() {
                Ok(()) => {
                    self.set_clamav_reachable(true, None);
                    true
                }
                Err(e) => {
                    self.set_clamav_reachable(false, Some(&e));
                    false
                }
            },
        }
    }

    /// Ping ClamAV to check if it's running
    fn clamav_ping(&self) -> Result<(), String> {
        use std::io::{Read, Write};

        let mut stream = clamav_connect(&self.clamav_config.address, Duration::from_secs(5))?;

        stream
            .write_all(b"zPING\0")
            .map_err(|e| format!("Write failed: {}", e))?;

        let mut response = [0u8; 64];
        let n = stream
            .read(&mut response)
            .map_err(|e| format!("Read failed: {}", e))?;

        let response_str = String::from_utf8_lossy(&response[..n]);
        if response_str.contains("PONG") {
            Ok(())
        } else {
            Err("Invalid response".to_string())
        }
    }

    /// Get ClamAV version if available
    pub fn clamav_version(&self) -> Option<String> {
        use std::io::{Read, Write};

        if !self.clamav_config.enabled {
            return None;
        }

        let mut stream =
            clamav_connect(&self.clamav_config.address, Duration::from_secs(5)).ok()?;
        stream.write_all(b"zVERSION\0").ok()?;

        let mut response = [0u8; 256];
        let n = stream.read(&mut response).ok()?;

        let version = String::from_utf8_lossy(&response[..n])
            .trim_matches('\0')
            .trim()
            .to_string();

        if version.is_empty() {
            None
        } else {
            Some(version)
        }
    }

    /// Built-in virus scan (pattern matching on attachments)
    fn builtin_scan(&self, raw_email: &str) -> ScanResult {
        let mut result = ScanResult::clean();

        // Parse MIME structure (attachments only); records parse threats.
        let attachments = self.extract_attachments(raw_email, &mut result);

        // Check attachment count
        if attachments.len() > self.max_attachments {
            result.add_threat(format!(
                "Too many attachments: {} (max: {})",
                attachments.len(),
                self.max_attachments
            ));
        }

        for attachment in &attachments {
            self.check_extension(attachment, &mut result);
            self.check_mime_type(attachment, &mut result);
            self.check_size(attachment, &mut result);

            // Signature-scan decoded attachment bytes
            if let Some(content) = &attachment.decoded_content {
                self.scan_content(content, attachment, &mut result);
            }
        }

        let email_lower = raw_email.to_lowercase();

        // Check for suspicious patterns in the raw email
        self.check_suspicious_patterns(&email_lower, &mut result);

        // Archive heuristics (warnings only)
        self.check_archive_threats(&attachments, &email_lower, &mut result);

        result
    }

    /// Collect all attachment parts (recursing into nested multiparts and
    /// encapsulated messages). Structural problems are recorded in `result`.
    fn extract_attachments(&self, raw_email: &str, result: &mut ScanResult) -> Vec<Attachment> {
        let mut attachments = Vec::new();
        self.collect_parts(raw_email, 0, &mut attachments, result);
        attachments
    }

    fn collect_parts(
        &self,
        part: &str,
        depth: usize,
        out: &mut Vec<Attachment>,
        result: &mut ScanResult,
    ) {
        if depth > MAX_MIME_DEPTH {
            result.add_threat_once(DEPTH_THREAT);
            return;
        }

        let (header_text, body) = split_headers_body(part);
        let headers = parse_headers(header_text);
        let ct_full = header(&headers, "content-type").unwrap_or("text/plain");
        let content_type = ct_full
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let cte = header(&headers, "content-transfer-encoding")
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        if content_type.starts_with("multipart/") {
            if let Some(boundary) = header_param(ct_full, "boundary") {
                for sub in split_multipart(body, &boundary) {
                    self.collect_parts(sub, depth + 1, out, result);
                }
            }
            return;
        }

        let disposition = header(&headers, "content-disposition");
        let filenames = part_filenames(&headers, ct_full);

        if content_type == "message/rfc822" || content_type == "message/global" {
            let Some(decoded) = Self::decode_reporting(body, &cte, "encapsulated message", result)
            else {
                return;
            };
            if !filenames.is_empty() {
                // Named encapsulated message: check its names too.
                out.push(Attachment {
                    filename: filenames[0].clone(),
                    filenames,
                    content_type: content_type.clone(),
                    size: decoded.len(),
                    decoded_content: None,
                });
            }
            let inner = String::from_utf8_lossy(&decoded);
            self.collect_parts(&inner, depth + 1, out, result);
            return;
        }

        let disposition_attachment = disposition.is_some_and(|d| {
            d.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("attachment")
        });
        let is_attachment = disposition_attachment
            || !filenames.is_empty()
            || !(content_type.starts_with("text/")
                || content_type.starts_with("message/")
                || content_type.is_empty());
        if !is_attachment {
            return;
        }

        // Preferred display name: disposition filename (RFC 2231 preferred),
        // else Content-Type name.
        let filename = disposition
            .and_then(|d| header_param(d, "filename"))
            .or_else(|| header_param(ct_full, "name"))
            .unwrap_or_default();
        let label = if filename.is_empty() {
            content_type.clone()
        } else {
            filename.clone()
        };
        let what = format!("attachment {}", label);

        let decoded_content = Self::decode_reporting(body, &cte, &what, result);
        let size = decoded_content
            .as_ref()
            .map(|c| c.len())
            .unwrap_or(body.len());

        out.push(Attachment {
            filename,
            filenames,
            content_type,
            size,
            decoded_content,
        });
    }

    /// Decode a part body, recording problems in `result`: an unknown
    /// Content-Transfer-Encoding is a warning (raw bytes are returned),
    /// invalid base64 is a threat (`None`). `what` names the part.
    fn decode_reporting(
        body: &str,
        cte: &str,
        what: &str,
        result: &mut ScanResult,
    ) -> Option<Vec<u8>> {
        match Self::decode_body(body, cte) {
            Decoded::Bytes(b) => Some(b),
            Decoded::UnknownCte(b) => {
                result.add_warning(format!(
                    "Unknown Content-Transfer-Encoding '{}' on {}",
                    cte, what
                ));
                Some(b)
            }
            Decoded::InvalidBase64 => {
                result.add_threat(format!("Invalid base64 in {} (cannot be scanned)", what));
                None
            }
        }
    }

    /// Decode a part body according to its Content-Transfer-Encoding.
    fn decode_body(body: &str, cte: &str) -> Decoded {
        match cte {
            "base64" => {
                use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
                const LENIENT: GeneralPurpose = GeneralPurpose::new(
                    &base64::alphabet::STANDARD,
                    GeneralPurposeConfig::new()
                        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
                        .with_decode_allow_trailing_bits(true),
                );
                // Drop everything outside the base64 alphabet (whitespace,
                // stray punctuation), then decode; failure is reported.
                let cleaned: Vec<u8> = body
                    .bytes()
                    .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
                    .collect();
                // Padding may only appear at the end.
                let trimmed_len = cleaned
                    .iter()
                    .rposition(|&b| b != b'=')
                    .map_or(0, |p| p + 1);
                if cleaned[..trimmed_len].contains(&b'=') {
                    return Decoded::InvalidBase64;
                }
                match LENIENT.decode(&cleaned[..trimmed_len]) {
                    Ok(b) => Decoded::Bytes(b),
                    Err(_) => Decoded::InvalidBase64,
                }
            }
            "quoted-printable" => Decoded::Bytes(decode_quoted_printable(body)),
            "" | "7bit" | "8bit" | "binary" => Decoded::Bytes(body.as_bytes().to_vec()),
            _ => Decoded::UnknownCte(body.as_bytes().to_vec()),
        }
    }

    /// Filename checks run on every filename form; the attachment is flagged
    /// if ANY form is blocked.
    fn check_extension(&self, attachment: &Attachment, result: &mut ScanResult) {
        for name in &attachment.filenames {
            self.check_filename(name, result);
        }
    }

    fn check_filename(&self, filename: &str, result: &mut ScanResult) {
        let filename_lower = filename
            .to_lowercase()
            .trim_end_matches(['.', ' '])
            .to_string();

        // Check for blocked extensions
        let mut blocked = false;
        for ext in &self.blocked_extensions {
            if filename_lower.ends_with(ext) {
                result.add_threat(format!(
                    "Blocked file extension: {} (file: {})",
                    ext, filename
                ));
                blocked = true;
                break;
            }
        }

        // Check for double extensions (e.g., .pdf.exe)
        if !blocked {
            let parts: Vec<&str> = filename_lower.split('.').collect();
            if parts.len() > 2 {
                let last_ext = format!(".{}", parts.last().unwrap_or(&""));
                if self.blocked_extensions.contains(&last_ext) {
                    result.add_threat(format!(
                        "Suspicious double extension: {} (file: {})",
                        last_ext, filename
                    ));
                }
            }
        }

        // Check for Unicode tricks in filename
        if filename.chars().any(|c| {
            matches!(
                c,
                '\u{202E}' | // Right-to-left override
                '\u{200B}' | // Zero-width space
                '\u{200C}' | // Zero-width non-joiner
                '\u{200D}' | // Zero-width joiner
                '\u{FEFF}' // Zero-width no-break space
            )
        }) {
            result.add_threat(format!("Suspicious Unicode in filename: {}", filename));
        }
    }

    fn check_mime_type(&self, attachment: &Attachment, result: &mut ScanResult) {
        let content_type_lower = attachment.content_type.to_lowercase();

        for dangerous_type in &self.dangerous_mime_types {
            if content_type_lower.contains(dangerous_type) {
                result.add_threat(format!(
                    "Dangerous MIME type: {} (file: {})",
                    dangerous_type, attachment.filename
                ));
                return;
            }
        }

        // Check for MIME type / extension mismatch
        if !attachment.filename.is_empty() && !attachment.content_type.is_empty() {
            let filename_lower = attachment.filename.to_lowercase();

            // PDF should be application/pdf. Many clients send generic
            // application/octet-stream; that is only a warning.
            let generic = content_type_lower == "application/octet-stream";
            if filename_lower.ends_with(".pdf") && !content_type_lower.contains("pdf") && generic {
                result.add_warning(format!(
                    "Generic MIME type for PDF {}: {}",
                    attachment.filename, attachment.content_type
                ));
            } else if filename_lower.ends_with(".pdf") && !content_type_lower.contains("pdf") {
                result.add_threat(format!(
                    "MIME type mismatch: {} claims to be PDF but has type {}",
                    attachment.filename, attachment.content_type
                ));
            }

            // Image files
            if (filename_lower.ends_with(".jpg")
                || filename_lower.ends_with(".jpeg")
                || filename_lower.ends_with(".png")
                || filename_lower.ends_with(".gif"))
                && !content_type_lower.contains("image")
            {
                let add = if generic {
                    ScanResult::add_warning
                } else {
                    ScanResult::add_threat
                };
                add(
                    result,
                    format!(
                        "MIME type mismatch: {} claims to be image but has type {}",
                        attachment.filename, attachment.content_type
                    ),
                );
            }
        }
    }

    fn check_size(&self, attachment: &Attachment, result: &mut ScanResult) {
        if attachment.size > self.max_attachment_size {
            result.add_threat(format!(
                "Attachment too large: {} bytes (max: {} bytes, file: {})",
                attachment.size, self.max_attachment_size, attachment.filename
            ));
        }
    }

    /// Match byte signatures against a decoded attachment.
    fn scan_content(&self, content: &[u8], attachment: &Attachment, result: &mut ScanResult) {
        let filename = attachment.filename.as_str();
        let weak_window = &content[..content.len().min(CONTENT_SCAN_LIMIT)];
        let strong_window = &content[..content.len().min(self.max_attachment_size.max(1))];

        for s in &self.malware_signatures {
            let hit = match s.kind {
                SigKind::Magic => content.starts_with(s.pattern),
                SigKind::Strong => contains_bytes(strong_window, s.pattern),
                SigKind::Weak => contains_bytes(weak_window, s.pattern),
            };
            if !hit {
                continue;
            }
            match s.kind {
                SigKind::Magic | SigKind::Strong => result.add_threat(format!(
                    "Malware signature detected: {} (file: {})",
                    s.name, filename
                )),
                SigKind::Weak => result.add_warning(format!(
                    "Suspicious content: {} (file: {})",
                    s.name, filename
                )),
            }
        }

        // Check for executable content in non-executable files (any form)
        let names_lower: Vec<String> = attachment
            .filenames
            .iter()
            .map(|f| f.to_lowercase())
            .collect();
        let any_ends = |exts: &[&str]| {
            names_lower
                .iter()
                .any(|f| exts.iter().any(|e| f.ends_with(e)))
        };
        let is_supposed_to_be_safe = any_ends(&[".pdf", ".doc", ".docx", ".txt", ".jpg", ".png"]);

        if is_supposed_to_be_safe {
            if content.starts_with(b"MZ") {
                result.add_threat(format!(
                    "Executable content hidden in {}: PE header detected",
                    filename
                ));
            }
            if content.starts_with(b"\x7FELF") {
                result.add_threat(format!(
                    "Executable content hidden in {}: ELF header detected",
                    filename
                ));
            }
        }

        // Check for Office macros in Office documents
        if any_ends(&[".doc", ".docx", ".xls", ".xlsx"]) {
            // Look for VBA project stream indicators
            if content.windows(4).any(|w| w == b"_VBA" || w == b"VBA_") {
                result.add_threat(format!(
                    "VBA macro detected in Office document: {}",
                    filename
                ));
            }
        }
    }

    /// Heuristics over the whole (lowercased) message. Patterns that are
    /// specific to malware are threats; ones that also appear in ordinary
    /// technical mail are warnings.
    fn check_suspicious_patterns(&self, email_lower: &str, result: &mut ScanResult) {
        // Obfuscation / scripting (common in developer mail too) -> warnings
        if email_lower.contains("fromcharcode") {
            result.add_warning("JavaScript fromCharCode obfuscation detected".to_string());
        }
        if email_lower.contains("eval(") || email_lower.contains("eval (") {
            result.add_warning("JavaScript eval() detected".to_string());
        }
        if email_lower.contains("data:application/octet-stream") {
            result.add_warning("Suspicious data URI detected".to_string());
        }

        // Encoded PowerShell
        if email_lower.contains("-encodedcommand") {
            result.add_threat("Encoded PowerShell command detected".to_string());
        }

        // Common exploit kit patterns
        if email_lower.contains("activexobject") {
            result.add_threat("ActiveX object instantiation detected".to_string());
        }
        if email_lower.contains("wscript.shell") || email_lower.contains("wshshell") {
            result.add_threat("WScript.Shell usage detected".to_string());
        }

        // Hidden iframe injection (HTML emails)
        if email_lower.contains("<iframe")
            && email_lower.contains("src=")
            && (email_lower.contains("width=\"0\"")
                || email_lower.contains("width='0'")
                || email_lower.contains("height=\"0\"")
                || email_lower.contains("height='0'")
                || email_lower.contains("display:none")
                || email_lower.contains("visibility:hidden"))
        {
            result.add_threat("Hidden iframe detected".to_string());
        }

        // Data URIs with executables
        if email_lower.contains("data:application/x-msdownload") {
            result.add_threat("Executable data URI detected".to_string());
        }
    }

    /// Archive heuristics. These never mark mail infected; they only add
    /// warnings (password-protected archives and many archives are common in
    /// legitimate mail).
    fn check_archive_threats(
        &self,
        attachments: &[Attachment],
        email_lower: &str,
        result: &mut ScanResult,
    ) {
        let archive_extensions = [".zip", ".rar", ".7z", ".tar", ".gz", ".tgz"];
        let archives: Vec<&Attachment> = attachments
            .iter()
            .filter(|a| {
                let f = a.filename.to_lowercase();
                archive_extensions.iter().any(|ext| f.ends_with(ext))
            })
            .collect();

        if !archives.is_empty()
            && (email_lower.contains("password")
                || email_lower.contains("passwort")
                || email_lower.contains("contraseña"))
        {
            result.add_warning(
                "Archive attachment with password mentioned (possible scan evasion)".to_string(),
            );
        }

        if archives.len() > 3 {
            result.add_warning(format!("Many archive attachments: {}", archives.len()));
        }
    }

    /// Configure ClamAV connection
    #[cfg(test)]
    pub fn set_clamav_address(&mut self, address: String) {
        self.clamav_config.address = address;
        // Reset availability check
        if let Ok(mut state) = self.clamav_state.lock() {
            *state = ClamState::Unknown;
        }
    }

    /// Enable or disable ClamAV
    #[cfg(test)]
    pub fn set_clamav_enabled(&mut self, enabled: bool) {
        self.clamav_config.enabled = enabled;
    }

    /// Get scanner status info
    pub fn status(&self) -> ScannerStatus {
        let clamav_available = self.is_clamav_available();
        let clamav_version = if clamav_available {
            self.clamav_version()
        } else {
            None
        };

        ScannerStatus {
            clamav_enabled: self.clamav_config.enabled,
            clamav_available,
            clamav_address: self.clamav_config.address.clone(),
            clamav_version,
        }
    }
}

/// Scanner status information
#[derive(Debug, Clone)]
pub struct ScannerStatus {
    pub clamav_enabled: bool,
    pub clamav_available: bool,
    pub clamav_address: String,
    pub clamav_version: Option<String>,
}

/// Outcome of decoding a part body by its Content-Transfer-Encoding
enum Decoded {
    Bytes(Vec<u8>),
    /// Unknown CTE: raw bytes returned for scanning
    UnknownCte(Vec<u8>),
    /// Base64 that cannot be decoded even after stripping non-alphabet bytes
    InvalidBase64,
}

/// Decode a quoted-printable body (RFC 2045 6.7). Invalid escapes are kept
/// literally; soft line breaks are removed.
fn decode_quoted_printable(body: &str) -> Vec<u8> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = body.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b != b'=' {
            out.push(b);
            i += 1;
            continue;
        }
        // Soft line break: '=' followed by optional whitespace then (CR)LF
        let mut j = i + 1;
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'\n' {
            i = j + 1;
            continue;
        }
        if j + 1 < bytes.len() && bytes[j] == b'\r' && bytes[j + 1] == b'\n' {
            i = j + 2;
            continue;
        }
        if j == bytes.len() {
            i = j;
            continue;
        }
        if i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    out
}

impl Default for AntiVirus {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents an email attachment
#[derive(Debug)]
struct Attachment {
    /// Preferred display filename (may be empty)
    filename: String,
    /// Every distinct filename form found in the headers
    filenames: Vec<String>,
    content_type: String,
    size: usize,
    decoded_content: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_email() {
        let av = av();
        let result = av.scan(
            "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Hello\r\n\r\nHello, world!",
        );
        assert!(!result.is_infected);
    }

    #[test]
    fn test_exe_attachment() {
        let av = av();
        let email = r#"From: sender@example.com
To: recipient@example.com
Subject: Check this out
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Please run the attached file.

--boundary123
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="virus.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQA==

--boundary123--
"#;
        let result = av.scan(email);
        assert!(result.is_infected);
        assert!(result.threats.iter().any(|t| t.contains(".exe")));
    }

    #[test]
    fn test_double_extension() {
        let av = av();
        let email = r#"Content-Type: multipart/mixed; boundary="bound"

--bound
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="document.pdf.exe"

test content

--bound--
"#;
        let result = av.scan(email);
        assert!(result.is_infected);
        // The double extension .exe is caught by the blocked extension check
        assert!(result.threats.iter().any(|t| t.contains(".exe")));
    }

    #[test]
    fn test_eicar_detection() {
        let av = av();
        // EICAR test string (standard AV test pattern)
        let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let email = format!(
            "Content-Type: multipart/mixed; boundary=\"testbound\"\r\n\r\n--testbound\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"test.dat\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--testbound--",
            base64::engine::general_purpose::STANDARD.encode(eicar)
        );
        let result = av.scan(&email);
        assert!(result.is_infected);
        assert!(result.threats.iter().any(|t| t.contains("EICAR")));
    }

    fn av() -> AntiVirus {
        AntiVirus::with_config(ClamAVConfig {
            enabled: false,
            ..Default::default()
        })
    }

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AntiVirus>();
    }

    #[test]
    fn test_benign_multipart_not_flagged() {
        let email = "From: a@example.com\r\nSubject: code review\r\nContent-Type: multipart/alternative; boundary=\"AbC\"\r\n\r\n--AbC\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nFunction foo() returns 4D5A. MZ is fine here.\r\nConnect to hostname=mail.example.com please.\r\nSee the attached .zip, password is in the other mail. Also a.tar b.gz c.tar d.gz\r\n--AbC\r\nContent-Type: text/html\r\n\r\n<p>Function Sub A HKEY_ REG_SZ</p>\r\n--AbC--\r\n";
        let result = av().scan(email);
        assert!(!result.is_infected, "{:?}", result.threats);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    }

    #[test]
    fn test_body_text_mz_not_detected_but_attachment_pe_is() {
        let pe = base64::engine::general_purpose::STANDARD.encode(b"MZ\x90\x00\x03\x00\x00\x00");
        let email = format!(
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nMZ 4D5A header talk\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--b--\r\n",
            pe
        );
        let result = av().scan(&email);
        assert!(result.is_infected);
        assert!(
            result
                .threats
                .iter()
                .any(|t| t.contains("MZ header") && t.contains("data.bin"))
        );

        // "MZ" not at offset 0 of the attachment -> not a PE magic hit
        let txt = base64::engine::general_purpose::STANDARD.encode(b"hello MZ world");
        let email = format!(
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"notes.dat\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--b--\r\n",
            txt
        );
        assert!(!av().scan(&email).is_infected);
    }

    #[test]
    fn test_password_zip_is_warning_not_infection() {
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nThe password is 1234\r\n--b\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename=\"files.zip\"\r\nContent-Transfer-Encoding: base64\r\n\r\nUEsDBAoAAAAAAA==\r\n--b--\r\n";
        let result = av().scan(email);
        assert!(!result.is_infected, "{:?}", result.threats);
        assert!(result.warnings.iter().any(|w| w.contains("password")));
    }

    #[test]
    fn test_filename_only_from_headers() {
        // name=/filename= in body must not be taken as a filename
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/pdf; name=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--b\r\nContent-Type: text/plain\r\n\r\nfilename=evil.exe hostname=x.exe\r\n--b--\r\n";
        let atts = av().extract_attachments(email, &mut ScanResult::clean());
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0].filename, "report.pdf");
        assert!(!av().scan(email).is_infected);

        assert_eq!(
            header_param(
                "attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.exe",
                "filename"
            ),
            Some("résumé.exe".to_string())
        );
        assert_eq!(header_param("text/plain; hostname=a", "name"), None);
        assert_eq!(
            header_param("attachment; filename=\"a;b.exe\"", "filename"),
            Some("a;b.exe".to_string())
        );
    }

    #[test]
    fn test_parse_clamd_reply() {
        // Clean only for exactly "stream: OK" (trailing NUL/newline trimmed)
        assert!(parse_clamd_reply(b"stream: OK\0").unwrap().is_empty());
        assert!(parse_clamd_reply(b"stream: OK\n").unwrap().is_empty());
        assert!(parse_clamd_reply(b"stream: OK").unwrap().is_empty());

        // FOUND -> threat name
        assert_eq!(
            parse_clamd_reply(b"stream: Eicar-Test-Signature FOUND\0").unwrap(),
            vec!["Eicar-Test-Signature".to_string()]
        );

        // Empty and garbage replies fail closed
        for reply in [
            &b""[..],
            b"\0",
            b"\n",
            b"garbage",
            b"stream: OK extra",
            b"OK",
            b"stream: FOUND",
            b"INSTREAM size limit exceeded. ERROR\0",
            b"stream: OK\nstream: Evil FOUND\0",
        ] {
            assert!(
                matches!(parse_clamd_reply(reply), Err(ClamError::Reply(_))),
                "{:?}",
                String::from_utf8_lossy(reply)
            );
        }
    }

    #[test]
    fn test_duplicate_filename_params_flagged() {
        // Duplicate filename parameter: the later evil.exe must be seen
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"a.pdf\"; filename=\"evil.exe\"\r\n\r\nJVBERi0xLjQK\r\n--b--\r\n";
        let atts = av().extract_attachments(email, &mut ScanResult::clean());
        assert_eq!(atts.len(), 1);
        assert!(atts[0].filenames.contains(&"evil.exe".to_string()));
        let result = av().scan(email);
        assert!(
            result.threats.iter().any(|t| t.contains("evil.exe")),
            "{:?}",
            result.threats
        );

        // Second Content-Disposition header carrying evil.exe
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\nContent-Disposition: attachment; filename=\"evil.exe\"\r\n\r\nJVBERi0xLjQK\r\n--b--\r\n";
        let result = av().scan(email);
        assert!(
            result.threats.iter().any(|t| t.contains("evil.exe")),
            "{:?}",
            result.threats
        );

        // Second Content-Type header carrying a name
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\nContent-Type: application/octet-stream; name=\"evil.exe\"\r\n\r\nJVBERi0xLjQK\r\n--b--\r\n";
        let result = av().scan(email);
        assert!(
            result.threats.iter().any(|t| t.contains("evil.exe")),
            "{:?}",
            result.threats
        );
    }

    #[test]
    fn test_nested_multipart_attachment_detected() {
        let email = "Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n\r\n--OUTER\r\nContent-Type: multipart/alternative; boundary=\"Inner\"\r\n\r\n--Inner\r\nContent-Type: text/plain\r\n\r\nhi\r\n--Inner--\r\n--OUTER\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"setup.exe\"\r\n\r\nxx\r\n--OUTER--\r\n";
        let result = av().scan(email);
        assert!(result.threats.iter().any(|t| t.contains(".exe")));
    }

    #[test]
    fn scan_flags_attachment_containing_base64_cmd() {
        let content = format!("echo {}", b64(b"cmd"));
        let email = format!(
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--b--\r\n",
            b64(content.as_bytes())
        );
        let result = av().scan(&email);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("Base64 encoded 'cmd'") && w.contains("data.bin")),
            "{:?}",
            result.warnings
        );
    }

    #[test]
    fn rfc822_nested_exe_detected() {
        let inner = format!(
            "From: x@example.com\r\nSubject: inner\r\nContent-Type: multipart/mixed; boundary=in\r\n\r\n--in\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--in--\r\n",
            b64(b"MZ\x90\x00\x03\x00")
        );
        // Encapsulated message, itself base64-encoded.
        let email = format!(
            "Content-Type: multipart/mixed; boundary=out\r\n\r\n--out\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--out\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--out--\r\n",
            b64(inner.as_bytes())
        );
        let result = av().scan(&email);
        assert!(
            result
                .threats
                .iter()
                .any(|t| t.contains("MZ header") && t.contains("data.bin")),
            "{:?}",
            result.threats
        );

        // Plain (7bit) message/global with a blocked filename inside.
        let email = "Content-Type: multipart/mixed; boundary=out\r\n\r\n--out\r\nContent-Type: message/global\r\n\r\nSubject: fwd\r\nContent-Type: application/octet-stream; name=\"run.exe\"\r\n\r\nxx\r\n--out--\r\n";
        let result = av().scan(email);
        assert!(
            result.threats.iter().any(|t| t.contains(".exe")),
            "{:?}",
            result.threats
        );
    }

    #[test]
    fn qp_encoded_mz_detected() {
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=4D=5A=90=00=03=\r\n=00\r\n--b--\r\n";
        let atts = av().extract_attachments(email, &mut ScanResult::clean());
        assert_eq!(
            atts[0].decoded_content.as_deref(),
            Some(&b"MZ\x90\x00\x03\x00\r\n"[..])
        );
        let result = av().scan(email);
        assert!(
            result.threats.iter().any(|t| t.contains("MZ header")),
            "{:?}",
            result.threats
        );
    }

    #[test]
    fn invalid_base64_attachment_flagged() {
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTV=qQAAMAAAA\r\n--b--\r\n";
        let result = av().scan(email);
        assert!(result.is_infected);
        assert!(
            result.threats.iter().any(|t| t.contains("Invalid base64")),
            "{:?}",
            result.threats
        );

        // Non-alphabet junk is stripped, not fatal.
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\naGVs!bG8g\r\nd29y*bGQ=\r\n--b--\r\n";
        let result = av().scan(email);
        assert!(!result.is_infected, "{:?}", result.threats);
    }

    #[test]
    fn unknown_cte_on_attachment_warns() {
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"data.bin\"\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 x\r\n--b--\r\n";
        let result = av().scan(email);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("Unknown Content-Transfer-Encoding")),
            "{:?}",
            result.warnings
        );
    }

    #[test]
    fn filename_star_shadowing_detected() {
        // Benign plain filename, blocked RFC 2231 form.
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"report.txt\"; filename*=UTF-8''report.exe\r\n\r\nxx\r\n--b--\r\n";
        let result = av().scan(email);
        assert!(
            result.threats.iter().any(|t| t.contains(".exe")),
            "{:?}",
            result.threats
        );

        // Blocked plain filename shadowed by a benign extended form.
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"run.exe\"; filename*=UTF-8''report.txt\r\n\r\nxx\r\n--b--\r\n";
        let result = av().scan(email);
        assert!(
            result.threats.iter().any(|t| t.contains(".exe")),
            "{:?}",
            result.threats
        );

        // Continuations reassembled.
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*0=\"invoice\"; filename*1=\".e\"; filename*2=\"xe\"\r\n\r\nxx\r\n--b--\r\n";
        let result = av().scan(email);
        assert!(
            result.threats.iter().any(|t| t.contains(".exe")),
            "{:?}",
            result.threats
        );

        // Content-Type name differs from disposition filename.
        let email = "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream; name=\"setup.scr\"\r\nContent-Disposition: attachment; filename=\"photo.dat\"\r\n\r\nxx\r\n--b--\r\n";
        let result = av().scan(email);
        assert!(
            result.threats.iter().any(|t| t.contains(".scr")),
            "{:?}",
            result.threats
        );
    }

    #[test]
    fn depth_overflow_flagged() {
        let mut email =
            "Content-Type: application/octet-stream; name=\"a.bin\"\r\n\r\nxx\r\n".to_string();
        for i in 0..(MAX_MIME_DEPTH + 2) {
            email = format!(
                "Content-Type: multipart/mixed; boundary=\"b{i}\"\r\n\r\n--b{i}\r\n{email}\r\n--b{i}--\r\n"
            );
        }
        let result = av().scan(&email);
        assert!(result.is_infected);
        assert_eq!(
            result.threats.iter().filter(|t| *t == DEPTH_THREAT).count(),
            1,
            "{:?}",
            result.threats
        );

        // Within the limit: no depth threat.
        let mut email = "Content-Type: text/plain\r\n\r\nhi\r\n".to_string();
        for i in 0..MAX_MIME_DEPTH {
            email = format!(
                "Content-Type: multipart/mixed; boundary=\"b{i}\"\r\n\r\n--b{i}\r\n{email}\r\n--b{i}--\r\n"
            );
        }
        assert!(!av().scan(&email).is_infected);
    }

    #[test]
    fn scanner_summary_reports_skipped_clamav() {
        let result = av().scan("Subject: hi\r\n\r\nhello");
        assert_eq!(result.clamav, ClamavStatus::Disabled);
        assert!(result.scanner_summary().starts_with("builtin only"));

        #[cfg(unix)]
        let address = "/nonexistent/clamd.sock".to_string();
        #[cfg(not(unix))]
        let address = "127.0.0.1:1".to_string();
        let av = AntiVirus::with_config(ClamAVConfig {
            address,
            timeout_secs: 1,
            enabled: true,
            required: true,
        });
        assert!(av.clamav_required());
        let result = av.scan("Subject: hi\r\n\r\nhello");
        assert!(matches!(result.clamav, ClamavStatus::Skipped(_)));
        assert!(
            result
                .scanner_summary()
                .starts_with("builtin only; ClamAV unavailable:"),
            "{}",
            result.scanner_summary()
        );
        // Inside the back-off window: still Skipped.
        let result = av.scan("Subject: hi\r\n\r\nhello");
        assert!(matches!(result.clamav, ClamavStatus::Skipped(_)));

        let mut scanned = ScanResult::clean();
        scanned.clamav = ClamavStatus::Scanned;
        assert_eq!(scanned.scanner_summary(), "builtin+clamav");
    }

    #[test]
    fn test_clamav_unavailable_backoff() {
        let mut av = av();
        av.set_clamav_enabled(true);
        // Nonexistent unix socket / refused TCP port -> unavailable quickly
        #[cfg(unix)]
        av.set_clamav_address("/nonexistent/clamd.sock".to_string());
        #[cfg(not(unix))]
        av.set_clamav_address("127.0.0.1:1".to_string());
        let (status, threats) = av.try_clamav_scan(b"x");
        assert!(matches!(status, ClamavStatus::Skipped(_)));
        assert!(threats.is_empty());
        assert!(matches!(
            *av.clamav_state.lock().unwrap(),
            ClamState::Unavailable { .. }
        ));
        assert!(!av.clamav_due());
        // Back-off elapsed -> retried
        *av.clamav_state.lock().unwrap() = ClamState::Unavailable {
            retry_at: Instant::now() - Duration::from_secs(1),
        };
        assert!(av.clamav_due());
    }
}
