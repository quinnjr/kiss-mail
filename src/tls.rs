#![allow(dead_code)] // removed in Task 8 once wired

//! Native TLS: certificate source selection, PEM validation, and the
//! hot-reloading acceptor.

use rustls::ServerConfig;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

/// `KISS_MAIL_TLS`: whether native TLS is offered at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Auto,
    Off,
}

/// Parse `KISS_MAIL_TLS`. Unset means `Auto`; accepts `auto`/`off` plus the
/// [`crate::config::parse_bool`] aliases. Anything else is a startup error.
pub(crate) fn parse_tls_mode(v: Option<&str>) -> Result<TlsMode, String> {
    let Some(v) = v else {
        return Ok(TlsMode::Auto);
    };
    match v.trim().to_ascii_lowercase().as_str() {
        "auto" => return Ok(TlsMode::Auto),
        "off" => return Ok(TlsMode::Off),
        _ => {}
    }
    match crate::config::parse_bool(v) {
        Some(true) => Ok(TlsMode::Auto),
        Some(false) => Ok(TlsMode::Off),
        None => Err(format!(
            "KISS_MAIL_TLS: invalid value {v:?} (expected auto, off, or a boolean)"
        )),
    }
}

/// Where the serving certificate comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertSource {
    Env { cert: PathBuf, key: PathBuf },
    FixedLocation { cert: PathBuf, key: PathBuf },
    SelfSigned,
}

/// Pick the certificate source: env vars, then `$DATA_DIR/tls/{cert,key}.pem`,
/// then self-signed. A half-configured source aborts rather than falling back.
pub(crate) fn select_source(
    lookup: impl Fn(&str) -> Option<String>,
    data_dir: &Path,
) -> Result<CertSource, String> {
    let get = |name: &str| lookup(name).filter(|v| !v.trim().is_empty());
    match (get("KISS_MAIL_TLS_CERT"), get("KISS_MAIL_TLS_KEY")) {
        (Some(cert), Some(key)) => {
            return Ok(CertSource::Env {
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
            });
        }
        (Some(_), None) => {
            return Err("KISS_MAIL_TLS_CERT is set but KISS_MAIL_TLS_KEY is not".to_string());
        }
        (None, Some(_)) => {
            return Err("KISS_MAIL_TLS_KEY is set but KISS_MAIL_TLS_CERT is not".to_string());
        }
        (None, None) => {}
    }
    let dir = data_dir.join("tls");
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    match (cert.exists(), key.exists()) {
        (true, true) => Ok(CertSource::FixedLocation { cert, key }),
        (false, false) => Ok(CertSource::SelfSigned),
        (true, false) => Err(format!(
            "{} exists but {} is missing",
            cert.display(),
            key.display()
        )),
        (false, true) => Err(format!(
            "{} exists but {} is missing",
            key.display(),
            cert.display()
        )),
    }
}

/// A validated certificate chain and key, ready to serve.
pub(crate) struct LoadedCert {
    pub key: Arc<CertifiedKey>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub subject: String,
    /// SHA-256 over the chain DER followed by the private key DER.
    pub fingerprint: [u8; 32],
    /// DNS subjectAltNames of the leaf certificate, in certificate order.
    pub sans: Vec<String>,
}

fn to_system_time(ts: i64) -> SystemTime {
    if ts >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(ts as u64)
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_secs(ts.unsigned_abs())
    }
}

/// Load and validate a PEM cert chain and key. Every error names the file.
pub(crate) fn load_pair(cert: &Path, key: &Path, now: SystemTime) -> Result<LoadedCert, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("cannot read certificate {}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("cannot parse certificate {}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("no PEM certificate found in {}", cert.display()));
    }
    let key_der = PrivateKeyDer::from_pem_file(key).map_err(|e| match e {
        rustls::pki_types::pem::Error::NoItemsFound => {
            format!("no PEM private key found in {}", key.display())
        }
        e => format!("cannot read private key {}: {e}", key.display()),
    })?;

    let mut hasher = Sha256::new();
    for c in &chain {
        hasher.update(c.as_ref());
    }
    hasher.update(key_der.secret_der());
    let fingerprint: [u8; 32] = hasher.finalize().into();

    let (not_before, not_after, subject, sans) = {
        let (_, x509) = x509_parser::parse_x509_certificate(chain[0].as_ref())
            .map_err(|e| format!("cannot parse certificate {}: {e}", cert.display()))?;
        let validity = x509.validity();
        let subject = x509
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(str::to_string)
            .or_else(|| {
                let san = x509.subject_alternative_name().ok().flatten()?;
                san.value.general_names.iter().find_map(|n| match n {
                    x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
            })
            .unwrap_or_default();
        let sans: Vec<String> = x509
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|san| {
                san.value
                    .general_names
                    .iter()
                    .filter_map(|n| match n {
                        x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        (
            to_system_time(validity.not_before.timestamp()),
            to_system_time(validity.not_after.timestamp()),
            subject,
            sans,
        )
    };

    if now < not_before {
        return Err(format!(
            "certificate {} is not yet valid (valid from {})",
            cert.display(),
            chrono::DateTime::<chrono::Utc>::from(not_before).to_rfc3339()
        ));
    }
    if now > not_after {
        return Err(format!(
            "certificate {} expired on {}; renew it (e.g. certbot renew)",
            cert.display(),
            chrono::DateTime::<chrono::Utc>::from(not_after).to_rfc3339()
        ));
    }

    let certified = CertifiedKey::from_der(chain, key_der, &default_provider()).map_err(|e| {
        format!(
            "private key {} does not match certificate {}: {e}",
            key.display(),
            cert.display()
        )
    })?;

    Ok(LoadedCert {
        key: Arc::new(certified),
        not_before,
        not_after,
        subject,
        fingerprint,
        sans,
    })
}

const SELF_SIGNED_CERT: &str = "self-signed-cert.pem";
const SELF_SIGNED_KEY: &str = "self-signed-key.pem";
/// Self-signed validity, and the renewal margin before it runs out.
const SELF_SIGNED_VALIDITY_DAYS: u64 = 397;
const SELF_SIGNED_RENEW_DAYS: u64 = 30;

/// SANs for the self-signed cert: the domain plus `localhost`. Names that are
/// not valid DNS names are dropped.
pub(crate) fn self_signed_sans(domain: &str) -> Vec<String> {
    let mut out = Vec::new();
    for name in [domain, "localhost"] {
        let name = name.trim();
        if rcgen::string::Ia5String::try_from(name).is_ok()
            && rustls::pki_types::DnsName::try_from(name).is_ok()
            && !out.iter().any(|n| n == name)
        {
            out.push(name.to_string());
        }
    }
    out
}

fn generate_self_signed(domain: &str, now: SystemTime) -> Result<(String, String), String> {
    use chrono::{Datelike, Utc};
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, date_time_ymd};

    let sans = self_signed_sans(domain);
    let cn = sans.first().cloned().unwrap_or_else(|| "localhost".into());
    let key = KeyPair::generate().map_err(|e| format!("self-signed key generation failed: {e}"))?;
    let mut params = CertificateParams::new(sans)
        .map_err(|e| format!("self-signed certificate parameters: {e}"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    // rcgen takes calendar dates, so the window is aligned to midnight UTC.
    let from = chrono::DateTime::<Utc>::from(now);
    let to = from + chrono::Duration::days(SELF_SIGNED_VALIDITY_DAYS as i64);
    params.not_before = date_time_ymd(from.year(), from.month() as u8, from.day() as u8);
    params.not_after = date_time_ymd(to.year(), to.month() as u8, to.day() as u8);
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("self-signed certificate generation failed: {e}"))?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Load the persisted self-signed pair from `tls_dir`, generating a new one
/// when it is missing, unparseable, within 30 days of expiry, or issued for
/// different names. Returns the cert and whether it was (re)generated.
pub(crate) async fn ensure_self_signed(
    tls_dir: &Path,
    domain: &str,
    now: SystemTime,
) -> Result<(LoadedCert, bool), String> {
    let cert_path = tls_dir.join(SELF_SIGNED_CERT);
    let key_path = tls_dir.join(SELF_SIGNED_KEY);

    if let Ok(loaded) = load_pair(&cert_path, &key_path, now) {
        let margin = Duration::from_secs(SELF_SIGNED_RENEW_DAYS * 86_400);
        let fresh = loaded.not_after > now + margin;
        if fresh && loaded.sans == self_signed_sans(domain) {
            return Ok((loaded, false));
        }
    }

    create_tls_dir(tls_dir)?;
    let (cert_pem, key_pem) = generate_self_signed(domain, now)?;
    crate::storage::write_atomic(&key_path, key_pem.into_bytes())
        .await
        .map_err(|e| format!("cannot write {}: {e}", key_path.display()))?;
    crate::storage::write_atomic(&cert_path, cert_pem.into_bytes())
        .await
        .map_err(|e| format!("cannot write {}: {e}", cert_path.display()))?;
    let loaded = load_pair(&cert_path, &key_path, now)?;
    Ok((loaded, true))
}

fn create_tls_dir(dir: &Path) -> Result<(), String> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
        .map_err(|e| format!("cannot create TLS directory {}: {e}", dir.display()))
}

/// Upper bound on a TLS handshake (implicit TLS or after STARTTLS).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// How often the reloader re-reads the active certificate files.
const RELOAD_INTERVAL: Duration = Duration::from_secs(60);
/// Warn this long before the serving certificate expires...
const EXPIRY_WARN_WINDOW: Duration = Duration::from_secs(14 * 86_400);
/// ...at most this often.
const EXPIRY_WARN_EVERY: Duration = Duration::from_secs(86_400);

const SELF_SIGNED_WARNING: &str = "Using a self-signed certificate; mail clients will warn, \
     and Outlook/Gmail refuse it. Run certbot (see DEPLOY.md) or set \
     KISS_MAIL_TLS_CERT/KISS_MAIL_TLS_KEY.";

/// What the banner shows about the serving certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsStatus {
    /// The certificate path, or `self-signed`.
    pub source: String,
    pub subject: String,
    pub not_after: SystemTime,
    pub self_signed: bool,
}

/// Result of one reload check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReloadOutcome {
    /// The active files hash the same as the last successful load.
    Unchanged,
    /// A new certificate was validated and swapped in.
    Reloaded,
    /// The files changed but failed validation; the current cert stays.
    Failed(String),
    /// Self-signed with no fixed-location pair to upgrade to.
    NothingToReload,
}

/// Serves whichever certificate was loaded last; swapped on reload. Live
/// sessions keep the key they negotiated with.
#[derive(Debug)]
struct ReloadingResolver(RwLock<Arc<CertifiedKey>>);

impl ReloadingResolver {
    fn current(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.0.read().unwrap_or_else(|e| e.into_inner()))
    }

    fn set(&self, key: Arc<CertifiedKey>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = key;
    }
}

impl ResolvesServerCert for ReloadingResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

/// The active source plus what the last successful load recorded.
struct Active {
    source: CertSource,
    /// SHA-256 of the raw cert file bytes then key file bytes at the last
    /// successful load; `None` for self-signed (those files are not watched).
    file_fp: Option<[u8; 32]>,
    subject: String,
    not_after: SystemTime,
}

/// The TLS acceptor and its hot-reloading certificate.
pub struct Tls {
    resolver: Arc<ReloadingResolver>,
    acceptor: TlsAcceptor,
    data_dir: PathBuf,
    active: Mutex<Active>,
    /// Serializes reloads (timer and SIGHUP).
    reload_lock: tokio::sync::Mutex<()>,
    last_expiry_warn: Mutex<Option<SystemTime>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// SHA-256 of the cert file bytes followed by the key file bytes, unparsed.
async fn file_fingerprint(cert: &Path, key: &Path) -> Result<[u8; 32], String> {
    let c = tokio::fs::read(cert)
        .await
        .map_err(|e| format!("cannot read certificate {}: {e}", cert.display()))?;
    let k = tokio::fs::read(key)
        .await
        .map_err(|e| format!("cannot read private key {}: {e}", key.display()))?;
    let mut h = Sha256::new();
    h.update(&c);
    h.update(&k);
    Ok(h.finalize().into())
}

/// SHA-256 of the leaf certificate, as `openssl x509 -fingerprint -sha256`
/// prints it, so operators can compare with what clients show.
fn leaf_fingerprint(key: &CertifiedKey) -> String {
    let digest = Sha256::digest(key.cert[0].as_ref());
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn rfc3339(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()
}

impl Tls {
    /// Build from `KISS_MAIL_TLS`, `KISS_MAIL_TLS_CERT` and `KISS_MAIL_TLS_KEY`.
    /// `None` when TLS is off; `Err` aborts startup.
    pub async fn from_env(data_dir: &Path, domain: &str) -> Result<Option<Arc<Tls>>, String> {
        let mode = parse_tls_mode(std::env::var("KISS_MAIL_TLS").ok().as_deref())?;
        Self::from_parts(
            mode,
            |k| std::env::var(k).ok(),
            data_dir,
            domain,
            SystemTime::now(),
        )
        .await
    }

    /// [`Tls::from_env`] with the mode, variable lookup and clock passed in.
    pub(crate) async fn from_parts(
        mode: TlsMode,
        lookup: impl Fn(&str) -> Option<String>,
        data_dir: &Path,
        domain: &str,
        now: SystemTime,
    ) -> Result<Option<Arc<Tls>>, String> {
        if mode == TlsMode::Off {
            return Ok(None);
        }
        let source = select_source(lookup, data_dir)?;
        let (loaded, file_fp) = match &source {
            CertSource::Env { cert, key } | CertSource::FixedLocation { cert, key } => {
                // Hash before loading: a change in between just reloads later.
                let fp = file_fingerprint(cert, key).await?;
                let loaded = load_pair(cert, key, now)?;
                tracing::info!(
                    "TLS certificate {}: subject {}, expires {}",
                    cert.display(),
                    loaded.subject,
                    rfc3339(loaded.not_after)
                );
                (loaded, Some(fp))
            }
            CertSource::SelfSigned => {
                let (loaded, regenerated) =
                    ensure_self_signed(&data_dir.join("tls"), domain, now).await?;
                if regenerated {
                    tracing::warn!(
                        "Generated a new self-signed TLS certificate; its fingerprint changed. \
                         SHA-256 fingerprint: {}",
                        leaf_fingerprint(&loaded.key)
                    );
                }
                tracing::warn!("{SELF_SIGNED_WARNING}");
                (loaded, None)
            }
        };

        let resolver = Arc::new(ReloadingResolver(RwLock::new(Arc::clone(&loaded.key))));
        let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| format!("TLS configuration: {e}"))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>);

        let tls = Arc::new(Tls {
            resolver,
            acceptor: TlsAcceptor::from(Arc::new(config)),
            data_dir: data_dir.to_path_buf(),
            active: Mutex::new(Active {
                source,
                file_fp,
                subject: loaded.subject,
                not_after: loaded.not_after,
            }),
            reload_lock: tokio::sync::Mutex::new(()),
            last_expiry_warn: Mutex::new(None),
        });
        tls.maybe_warn_expiry(now);
        Ok(Some(tls))
    }

    /// Server-side handshake, bounded by [`HANDSHAKE_TIMEOUT`].
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        s: S,
    ) -> std::io::Result<tokio_rustls::server::TlsStream<S>> {
        self.accept_with(s, HANDSHAKE_TIMEOUT).await
    }

    /// [`Tls::accept`] with an explicit timeout; a timeout is `TimedOut`.
    pub(crate) async fn accept_with<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        s: S,
        timeout: Duration,
    ) -> std::io::Result<tokio_rustls::server::TlsStream<S>> {
        match tokio::time::timeout(timeout, self.acceptor.accept(s)).await {
            Ok(result) => result,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TLS handshake timed out",
            )),
        }
    }

    pub fn status(&self) -> TlsStatus {
        let a = lock(&self.active);
        let (source, self_signed) = match &a.source {
            CertSource::Env { cert, .. } | CertSource::FixedLocation { cert, .. } => {
                (cert.display().to_string(), false)
            }
            CertSource::SelfSigned => ("self-signed".to_string(), true),
        };
        TlsStatus {
            source,
            subject: a.subject.clone(),
            not_after: a.not_after,
            self_signed,
        }
    }

    /// Re-read the active source's files and swap the cert in if they changed
    /// and validate (§2.3).
    pub(crate) async fn reload_now(&self) -> ReloadOutcome {
        self.reload_at(SystemTime::now()).await
    }

    async fn reload_at(&self, now: SystemTime) -> ReloadOutcome {
        let _serial = self.reload_lock.lock().await;
        let (source, last_fp) = {
            let a = lock(&self.active);
            (a.source.clone(), a.file_fp)
        };
        let (cert, key, upgrade) = match source {
            CertSource::Env { cert, key } | CertSource::FixedLocation { cert, key } => {
                (cert, key, false)
            }
            // Self-signed upgrades as soon as a real pair is installed.
            CertSource::SelfSigned => match select_source(|_| None, &self.data_dir) {
                Ok(CertSource::FixedLocation { cert, key }) => (cert, key, true),
                Ok(_) => return ReloadOutcome::NothingToReload,
                Err(e) => return ReloadOutcome::Failed(e),
            },
        };
        let fp = match file_fingerprint(&cert, &key).await {
            Ok(fp) => fp,
            Err(e) => return ReloadOutcome::Failed(e),
        };
        if Some(fp) == last_fp {
            return ReloadOutcome::Unchanged;
        }
        let loaded = match load_pair(&cert, &key, now) {
            Ok(l) => l,
            Err(e) => return ReloadOutcome::Failed(e),
        };
        self.resolver.set(Arc::clone(&loaded.key));
        {
            let mut a = lock(&self.active);
            if upgrade {
                a.source = CertSource::FixedLocation { cert, key };
            }
            a.file_fp = Some(fp);
            a.subject = loaded.subject;
            a.not_after = loaded.not_after;
        }
        // A new certificate gets its own expiry warning schedule.
        *lock(&self.last_expiry_warn) = None;
        ReloadOutcome::Reloaded
    }

    /// Log a WARN when the serving cert expires within 14 days, at most once
    /// per 24 h. Returns whether it warned.
    fn maybe_warn_expiry(&self, now: SystemTime) -> bool {
        let st = self.status();
        let warn_from = st
            .not_after
            .checked_sub(EXPIRY_WARN_WINDOW)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if now < warn_from {
            return false;
        }
        let mut last = lock(&self.last_expiry_warn);
        if let Some(prev) = *last {
            // A clock that went backwards counts as "warned recently".
            let elapsed = now.duration_since(prev).unwrap_or(Duration::ZERO);
            if elapsed < EXPIRY_WARN_EVERY {
                return false;
            }
        }
        *last = Some(now);
        drop(last);
        if now >= st.not_after {
            tracing::warn!(
                "TLS certificate {} ({}) expired on {}; renew it (e.g. certbot renew)",
                st.source,
                st.subject,
                rfc3339(st.not_after)
            );
        } else {
            let days = st
                .not_after
                .duration_since(now)
                .unwrap_or_default()
                .as_secs()
                / 86_400;
            tracing::warn!(
                "TLS certificate {} ({}) expires in {days} day(s), on {}; renew it (e.g. certbot renew)",
                st.source,
                st.subject,
                rfc3339(st.not_after)
            );
        }
        true
    }

    /// Check for new certificate files every 60 s and log expiry warnings.
    /// The task ends once the last other reference to `self` is dropped.
    pub fn spawn_reloader(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(RELOAD_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // the first tick is immediate; startup just loaded
            loop {
                tick.tick().await;
                let Some(tls) = weak.upgrade() else { break };
                let outcome = tls.reload_now().await;
                tls.log_outcome("periodic check", &outcome);
                tls.maybe_warn_expiry(SystemTime::now());
            }
        });
    }

    fn log_outcome(&self, trigger: &str, outcome: &ReloadOutcome) {
        match outcome {
            ReloadOutcome::Reloaded => {
                let st = self.status();
                tracing::info!(
                    "TLS certificate reloaded ({trigger}) from {}: subject {}, expires {}",
                    st.source,
                    st.subject,
                    rfc3339(st.not_after)
                );
            }
            ReloadOutcome::Failed(e) => tracing::error!(
                "TLS certificate reload failed ({trigger}); keeping the current certificate: {e}"
            ),
            ReloadOutcome::Unchanged => {
                tracing::debug!("TLS certificate unchanged ({trigger})")
            }
            ReloadOutcome::NothingToReload => {
                tracing::debug!("TLS: self-signed, no certificate files to load ({trigger})")
            }
        }
    }
}

/// Install the SIGHUP listener (Unix). Each HUP triggers an immediate reload
/// of `tls`, or logs "SIGHUP: nothing to reload" without one. This is separate
/// from the shutdown signals, so a HUP never stops the server.
pub fn spawn_sighup_handler(tls: Option<Arc<Tls>>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut hup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("cannot install the SIGHUP handler: {e}");
                return;
            }
        };
        tokio::spawn(async move {
            while hup.recv().await.is_some() {
                match &tls {
                    Some(tls) => {
                        let outcome = tls.reload_now().await;
                        if outcome == ReloadOutcome::NothingToReload {
                            tracing::info!("SIGHUP: nothing to reload");
                        } else {
                            tls.log_outcome("SIGHUP", &outcome);
                        }
                    }
                    None => tracing::info!("SIGHUP: nothing to reload"),
                }
            }
        });
    }
    #[cfg(not(unix))]
    drop(tls);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, date_time_ymd};
    use std::fs;
    use std::time::Duration;

    // Test-only fixtures, generated once with openssl (never used outside
    // tests). Valid for 100 years. rcgen's ring backend cannot generate RSA
    // keys, and only emits PKCS#8, so RSA (PKCS#1) and SEC1 are static.
    const TEST_RSA_CRT: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIDHjCCAgagAwIBAgIUY5ehJy673L1x742NS9Ae2ONEseQwDQYJKoZIhvcNAQEL\n\
BQAwEzERMA8GA1UEAwwIcnNhLnRlc3QwIBcNMjYxMDA0MTUyMzA2WhgPMjEyNjA5\n\
MTAxNTIzMDZaMBMxETAPBgNVBAMMCHJzYS50ZXN0MIIBIjANBgkqhkiG9w0BAQEF\n\
AAOCAQ8AMIIBCgKCAQEA1lFBOcRV5Da/8dgQyDBRH3LsjP3JIoQFtGIekQbz4CRF\n\
WzHDILtzP+J7fYSu9nP6ZUaqcOtuNz/lH87swgE+xOaRJhmLN9cLXAtw9vFGy6dG\n\
MlsI4RDIZ1eHBEdLD8EdpgoLQ0DMaxSyQCLCUbmYUoRpEZtq9U+xzUVT5oiCWpjX\n\
R110poEdK2LjXQvjh5PPrF53+f5JyrYaQt9NtZ19AIcYU1Rcuqxc8Hs1uzwPrBrK\n\
YPc3MwNIhKOxm7hgtj7KN4pnv2FF8bqs0ttMsz2y5zlyoH4ggJAfN9tTjMxIAsYf\n\
DVny6OAx85CE7xhKrVu7m+KXI+yHe6PYi36FqKT3SwIDAQABo2gwZjAdBgNVHQ4E\n\
FgQUXApSYZND/KW7A9lOBymWtT+3gkYwHwYDVR0jBBgwFoAUXApSYZND/KW7A9lO\n\
BymWtT+3gkYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHREEDDAKgghyc2EudGVzdDAN\n\
BgkqhkiG9w0BAQsFAAOCAQEAI7z9ldfbvnro1EsStjGCN0imeBKSwRU8o1wgMpRB\n\
hg45DlzWgAPz6k5Vym5LIyx1j3RBEKlbqO/Ntie5J0GpG7MUqP/+z7CRPQO6iVHn\n\
2m3MzuybxV107Ags9H5sJusNKI5QO93V9de+rPGofHp5NfdBZ4FyNeQvr6WxxBRx\n\
gQq2b09FWjBC7Ns7+kCXleGs4fdQOQbj2GQRMKMFeMlAxTJqHRenDieURxvCx6kD\n\
/k/pZabG29VDNpfkp5MTHPNgqD5zevGgeEJmGqjA8XB1HNU7p7b0vwFZiDIUszdQ\n\
Jjub5UnBLz9uto2QzlECUn/Rrt7cp/WPJaeRz0/S3Xhk7w==\n\
-----END CERTIFICATE-----\n\
    ";
    const TEST_RSA_KEY: &str = "\
-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEA1lFBOcRV5Da/8dgQyDBRH3LsjP3JIoQFtGIekQbz4CRFWzHD\n\
ILtzP+J7fYSu9nP6ZUaqcOtuNz/lH87swgE+xOaRJhmLN9cLXAtw9vFGy6dGMlsI\n\
4RDIZ1eHBEdLD8EdpgoLQ0DMaxSyQCLCUbmYUoRpEZtq9U+xzUVT5oiCWpjXR110\n\
poEdK2LjXQvjh5PPrF53+f5JyrYaQt9NtZ19AIcYU1Rcuqxc8Hs1uzwPrBrKYPc3\n\
MwNIhKOxm7hgtj7KN4pnv2FF8bqs0ttMsz2y5zlyoH4ggJAfN9tTjMxIAsYfDVny\n\
6OAx85CE7xhKrVu7m+KXI+yHe6PYi36FqKT3SwIDAQABAoIBABXU6SQNUAKTYTIt\n\
pGgAJANkHZyvLZIKiNo7NInpf2ZRy47intHyxma3l4TNw1Tvs44liK9ADFYseBap\n\
aYzJu68rHZYX/AqQKWQS9krxgRi1zXzLsTfcEc4VKHfTG15beb20QDl1nF08GnxW\n\
Dh1tHospWdqlTlv25lHWwhk1xrGbuHmc5vcx6e6B6oWWp3r9EoPKng2DDMOp2bsc\n\
ln8yDPi0gk6D8CK9O9DmhD0gRKzlHU775Zk0tAidFCsp5CF/fXMXU0UEhE+bLVE+\n\
aDvOkRXP4NPJdQSceA7POOL+SUZLblLepJ0pMU1yZAaiEpcW3Ox3WiS3LbS8wiYe\n\
lQhSEKECgYEA6lHh+bDy48qSDMK4jGdVuGRBA9ECxrLxOiiEU6n77kJHC8ewcWK1\n\
e+IhepaU8wYUZGlQx8jB33yJCms+HIhRuCWfe/80IliUvA+4zWeg3qj8UU27/1xt\n\
85p3HLXUIvQJulcloC9CM2REW7mKmbNDpsiX7cjLIsBeCbBfK9KIpXcCgYEA6iWX\n\
rlbr5jorJIqimXqQtTxCzxzSn9NCSoPy63ttjbeZDOPAMaUQjMQFyR1smmE9YQ4m\n\
y900yQAV3j7RHAQRAMq3mYXl6tdJ81qJXLLjC5nF2T67Cvlvc21Bj5CY4dpAR/DC\n\
rzlRXFSQDd4LHRGo4GSwt0+6r5Y2W9wrCmzFAc0CgYBeOcM3V1K1C1ajzwHLZBpy\n\
Zc5HLJuDL54VlwlvY2Gts/VB5XEsh1cXlB2GYFtRRtaYcklLrY1Yw4mQKQP3EVJb\n\
TLXPdRaP4TMeVOwpnUxxfV7JiwrYa2DDnw/a+btuutfWmQjGW3qxk9ZxVDFKEW5Y\n\
+T0vH5mgRd8K4mPDCYxtjQKBgQDTGV1tUvSPtvXalhsOoJACtffN3sCOU9s6b0f9\n\
wmP9FwAnvNY0bAtFvh0xOxQFA5JhBG858Y97gFY27w98YLYrrphlE3E8jyke/AtH\n\
xggpF1RnDsV3mXc/68rl8onDZg/6TDhZ3iVaRusxdXUzmg5VcLJaMsmvMJCFtTQg\n\
y/u6KQKBgACdcw6iekhXNXvz4+K/i6ZGOnaqlu3S+AxP4oU29PjatIb+WmkbTLY3\n\
5MlMyD0HkadVCY7Mbon+z+d7UtLR6vzuBNTJWq1fqegq+lqJ/8G+8yZHdrC3UuhG\n\
p3fVjCCb6OUa2anoVnpp7aU7owdbQVf34bhkhOmlyC3N+sR8guFh\n\
-----END RSA PRIVATE KEY-----\n\
    ";
    const TEST_EC_CRT: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIBfjCCASWgAwIBAgIUbwsPoK599ahsw/V4y5nsQYTvvYYwCgYIKoZIzj0EAwIw\n\
FDESMBAGA1UEAwwJc2VjMS50ZXN0MCAXDTI2MTAwNDE1MjMwNloYDzIxMjYwOTEw\n\
MTUyMzA2WjAUMRIwEAYDVQQDDAlzZWMxLnRlc3QwWTATBgcqhkjOPQIBBggqhkjO\n\
PQMBBwNCAAQ1i36z8fTgQSZAt47ehBUztyh+23Wzp5Q9UyLsQOf7uTA9R+y0bukp\n\
O+wjKvNxSJWJajhyAu5hfAfyUPn6wXJmo1MwUTAdBgNVHQ4EFgQUM09v/Ng06kaW\n\
MofLT84X8NdUGhYwHwYDVR0jBBgwFoAUM09v/Ng06kaWMofLT84X8NdUGhYwDwYD\n\
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBhNESoI2pql9Z2Z8mg5DRO\n\
X/ikFfIsTbDtMJr9UH5zcQIgTV8gJfxDMjEhImbrQCPtaMc5vnlOdVAF2bkw2nZN\n\
Agg=\n\
-----END CERTIFICATE-----\n\
    ";
    const TEST_EC_KEY: &str = "\
-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIIZsoMu4ivzJghiy86aSPQ5Y1mr6cPKVVTs4W6omQJ5ioAoGCCqGSM49\n\
AwEHoUQDQgAENYt+s/H04EEmQLeO3oQVM7coftt1s6eUPVMi7EDn+7kwPUfstG7p\n\
KTvsIyrzcUiViWo4cgLuYXwH8lD5+sFyZg==\n\
-----END EC PRIVATE KEY-----\n\
    ";

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    /// Self-signed ECDSA (PKCS#8) cert + key PEMs with a fixed validity window.
    fn make_cert(name: &str, from: (i32, u8, u8), to: (i32, u8, u8)) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.not_before = date_time_ymd(from.0, from.1, from.2);
        params.not_after = date_time_ymd(to.0, to.1, to.2);
        params.distinguished_name.push(DnType::CommonName, name);
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn write(dir: &Path, name: &str, body: impl AsRef<[u8]>) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    fn now() -> SystemTime {
        SystemTime::now()
    }

    #[test]
    fn tls_mode_parsing() {
        assert!(matches!(parse_tls_mode(None), Ok(TlsMode::Auto)));
        assert!(matches!(parse_tls_mode(Some("auto")), Ok(TlsMode::Auto)));
        for v in ["OFF", "false", "0", "off"] {
            assert!(matches!(parse_tls_mode(Some(v)), Ok(TlsMode::Off)), "{v}");
        }
        for v in ["on", "true", "1"] {
            assert!(matches!(parse_tls_mode(Some(v)), Ok(TlsMode::Auto)), "{v}");
        }
        let err = parse_tls_mode(Some("maybe")).err().unwrap();
        assert!(err.contains("KISS_MAIL_TLS"), "{err}");
    }

    #[test]
    fn select_env_wins_over_fixed_location() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("tls")).unwrap();
        write(&dir.path().join("tls"), "cert.pem", "x");
        write(&dir.path().join("tls"), "key.pem", "x");
        let lookup = |k: &str| match k {
            "KISS_MAIL_TLS_CERT" => s("/e/cert.pem"),
            "KISS_MAIL_TLS_KEY" => s("/e/key.pem"),
            _ => None,
        };
        match select_source(lookup, dir.path()).unwrap() {
            CertSource::Env { cert, key } => {
                assert_eq!(cert, PathBuf::from("/e/cert.pem"));
                assert_eq!(key, PathBuf::from("/e/key.pem"));
            }
            other => panic!("expected Env, got {other:?}"),
        }
    }

    #[test]
    fn select_env_half_set_aborts() {
        let dir = tempfile::tempdir().unwrap();
        let only_cert = |k: &str| (k == "KISS_MAIL_TLS_CERT").then(|| "/c".to_string());
        let err = select_source(only_cert, dir.path()).unwrap_err();
        assert!(err.contains("KISS_MAIL_TLS_KEY"), "{err}");
        let only_key = |k: &str| (k == "KISS_MAIL_TLS_KEY").then(|| "/k".to_string());
        let err = select_source(only_key, dir.path()).unwrap_err();
        assert!(err.contains("KISS_MAIL_TLS_CERT"), "{err}");
    }

    #[test]
    fn select_fixed_location_and_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let none = |_: &str| None;
        assert!(matches!(
            select_source(none, dir.path()).unwrap(),
            CertSource::SelfSigned
        ));
        let tls = dir.path().join("tls");
        fs::create_dir_all(&tls).unwrap();
        write(&tls, "cert.pem", "x");
        let err = select_source(none, dir.path()).unwrap_err();
        assert!(err.contains("key.pem"), "{err}");
        fs::remove_file(tls.join("cert.pem")).unwrap();
        write(&tls, "key.pem", "x");
        let err = select_source(none, dir.path()).unwrap_err();
        assert!(err.contains("cert.pem"), "{err}");
        write(&tls, "cert.pem", "x");
        match select_source(none, dir.path()).unwrap() {
            CertSource::FixedLocation { cert, key } => {
                assert_eq!(cert, tls.join("cert.pem"));
                assert_eq!(key, tls.join("key.pem"));
            }
            other => panic!("expected FixedLocation, got {other:?}"),
        }
    }

    #[test]
    fn load_pair_accepts_rsa_pkcs1_sec1_and_pkcs8() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (c8, k8) = make_cert("pkcs8.test", (2020, 1, 1), (2200, 1, 1));
        let cases = [
            (
                "rsa",
                TEST_RSA_CRT.to_string(),
                TEST_RSA_KEY.to_string(),
                "rsa.test",
            ),
            (
                "sec1",
                TEST_EC_CRT.to_string(),
                TEST_EC_KEY.to_string(),
                "sec1.test",
            ),
            ("pkcs8", c8, k8, "pkcs8.test"),
        ];
        for (name, cert, key, subject) in cases {
            let c = write(d, &format!("{name}.crt"), cert);
            let k = write(d, &format!("{name}.key"), key);
            let loaded = load_pair(&c, &k, now()).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(loaded.subject, subject, "{name}");
            assert!(loaded.not_before < now(), "{name}");
            assert!(
                loaded.not_after > now() + Duration::from_secs(86400 * 365),
                "{name}"
            );
            assert_eq!(loaded.fingerprint.len(), 32);
            // Deterministic.
            let again = load_pair(&c, &k, now()).unwrap();
            assert_eq!(loaded.fingerprint, again.fingerprint);
        }
    }

    #[test]
    fn load_pair_mismatched_key() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, _k1) = make_cert("a.test", (2020, 1, 1), (2200, 1, 1));
        let (_c2, k2) = make_cert("b.test", (2020, 1, 1), (2200, 1, 1));
        let c = write(dir.path(), "c.pem", c1);
        let k = write(dir.path(), "k.pem", k2);
        let err = load_pair(&c, &k, now()).err().unwrap();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn load_pair_expired_and_not_yet_valid() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, k1) = make_cert("old.test", (2020, 1, 1), (2021, 1, 1));
        let c = write(dir.path(), "old.pem", c1);
        let k = write(dir.path(), "oldkey.pem", k1);
        let err = load_pair(&c, &k, now()).err().unwrap();
        assert!(err.contains("expired"), "{err}");
        assert!(err.contains(&c.display().to_string()), "{err}");
        assert!(err.contains("certbot renew"), "{err}");

        let (c2, k2) = make_cert("future.test", (2090, 1, 1), (2091, 1, 1));
        let c = write(dir.path(), "new.pem", c2);
        let k = write(dir.path(), "newkey.pem", k2);
        let err = load_pair(&c, &k, now()).err().unwrap();
        assert!(err.contains("not yet valid"), "{err}");
        assert!(err.contains(&c.display().to_string()), "{err}");
    }

    #[test]
    fn load_pair_missing_file_names_path() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, k1) = make_cert("a.test", (2020, 1, 1), (2200, 1, 1));
        let c = write(dir.path(), "c.pem", c1);
        let k = write(dir.path(), "k.pem", k1);
        let missing = dir.path().join("nope.pem");
        let err = load_pair(&missing, &k, now()).err().unwrap();
        assert!(err.contains(&missing.display().to_string()), "{err}");
        let err = load_pair(&c, &missing, now()).err().unwrap();
        assert!(err.contains(&missing.display().to_string()), "{err}");
    }

    #[test]
    fn load_pair_der_files_are_rejected_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, k1) = make_cert("a.test", (2020, 1, 1), (2200, 1, 1));
        let good_c = write(dir.path(), "c.pem", c1);
        let good_k = write(dir.path(), "k.pem", k1);
        let der = write(
            dir.path(),
            "bin.der",
            [0x30u8, 0x82, 0x01, 0x0a, 0xff, 0x00, 0x80],
        );
        let err = load_pair(&der, &good_k, now()).err().unwrap();
        assert!(err.contains("no PEM certificate found"), "{err}");
        assert!(err.contains(&der.display().to_string()), "{err}");
        let err = load_pair(&good_c, &der, now()).err().unwrap();
        assert!(err.contains("no PEM private key found"), "{err}");
        assert!(err.contains(&der.display().to_string()), "{err}");
    }

    #[test]
    fn subject_falls_back_to_first_san() {
        let dir = tempfile::tempdir().unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["san.test".to_string()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2200, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        let c = write(dir.path(), "c.pem", cert.pem());
        let k = write(dir.path(), "k.pem", key.serialize_pem());
        assert_eq!(load_pair(&c, &k, now()).unwrap().subject, "san.test");
    }

    const DAY: Duration = Duration::from_secs(86_400);

    #[test]
    fn self_signed_sans_drops_invalid_names() {
        assert_eq!(self_signed_sans("bad_host!"), vec!["localhost"]);
        assert_eq!(
            self_signed_sans("mail.example.com"),
            vec!["mail.example.com", "localhost"]
        );
        assert_eq!(self_signed_sans("localhost"), vec!["localhost"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn self_signed_first_call_generates_with_modes() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("tls");
        let t = now();
        let (c, regen) = ensure_self_signed(&dir, "mail.example.com", t)
            .await
            .unwrap();
        assert!(regen);
        assert_eq!(c.sans, vec!["mail.example.com", "localhost"]);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("self-signed-cert.pem")), 0o600);
        assert_eq!(mode(&dir.join("self-signed-key.pem")), 0o600);
        assert_eq!(c.not_after.duration_since(c.not_before).unwrap(), 397 * DAY);
    }

    #[tokio::test]
    async fn self_signed_reused_when_unchanged() {
        let base = tempfile::tempdir().unwrap();
        let t = now();
        let (a, r1) = ensure_self_signed(base.path(), "mail.example.com", t)
            .await
            .unwrap();
        let (b, r2) = ensure_self_signed(base.path(), "mail.example.com", t)
            .await
            .unwrap();
        assert!(r1 && !r2);
        assert_eq!(a.fingerprint, b.fingerprint);
    }

    #[tokio::test]
    async fn self_signed_regenerates_near_expiry() {
        let base = tempfile::tempdir().unwrap();
        let t = now();
        ensure_self_signed(base.path(), "mail.example.com", t)
            .await
            .unwrap();
        let (_, r) = ensure_self_signed(base.path(), "mail.example.com", t + 368 * DAY)
            .await
            .unwrap();
        assert!(r);
    }

    #[tokio::test]
    async fn self_signed_regenerates_on_domain_change() {
        let base = tempfile::tempdir().unwrap();
        let t = now();
        ensure_self_signed(base.path(), "mail.example.com", t)
            .await
            .unwrap();
        let (c, r) = ensure_self_signed(base.path(), "other.example.org", t)
            .await
            .unwrap();
        assert!(r);
        assert_eq!(c.sans, vec!["other.example.org", "localhost"]);
    }

    #[tokio::test]
    async fn self_signed_regenerates_on_corrupt_cert() {
        let base = tempfile::tempdir().unwrap();
        let t = now();
        ensure_self_signed(base.path(), "mail.example.com", t)
            .await
            .unwrap();
        fs::write(base.path().join("self-signed-cert.pem"), b"garbage").unwrap();
        let (_, r) = ensure_self_signed(base.path(), "mail.example.com", t)
            .await
            .unwrap();
        assert!(r);
    }

    // ---- Task 3: Tls handle ----

    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn valid_pair() -> (String, String) {
        make_cert("localhost", (2020, 1, 1), (2200, 1, 1))
    }

    fn cert_der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    fn sha(der: &[u8]) -> [u8; 32] {
        Sha256::digest(der).into()
    }

    /// Write `$DATA_DIR/tls/{cert,key}.pem`.
    fn write_fixed(data_dir: &Path, cert: &str, key: &str) {
        let tls = data_dir.join("tls");
        fs::create_dir_all(&tls).unwrap();
        fs::write(tls.join("cert.pem"), cert).unwrap();
        fs::write(tls.join("key.pem"), key).unwrap();
    }

    async fn tls_with_fixed(data_dir: &Path, cert: &str, key: &str) -> Arc<Tls> {
        write_fixed(data_dir, cert, key);
        Tls::from_parts(TlsMode::Auto, no_env, data_dir, "localhost", now())
            .await
            .unwrap()
            .expect("TLS on")
    }

    type ClientStream = tokio_rustls::client::TlsStream<DuplexStream>;
    type ServerStream = tokio_rustls::server::TlsStream<DuplexStream>;

    /// Handshake a ring-provider client that trusts only `trust` against `tls`.
    async fn handshake(
        tls: &Tls,
        trust: &CertificateDer<'static>,
    ) -> Result<(ClientStream, ServerStream), String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(trust.clone()).unwrap();
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let (c, s) = tokio::io::duplex(64 * 1024);
        let name = ServerName::try_from("localhost").unwrap();
        let (cr, sr) = tokio::join!(connector.connect(name, c), tls.accept(s));
        Ok((
            cr.map_err(|e| format!("client: {e}"))?,
            sr.map_err(|e| format!("server: {e}"))?,
        ))
    }

    fn peer_cert(c: &ClientStream) -> CertificateDer<'static> {
        c.get_ref().1.peer_certificates().unwrap()[0]
            .clone()
            .into_owned()
    }

    #[tokio::test]
    async fn off_mode_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::from_parts(TlsMode::Off, no_env, dir.path(), "localhost", now())
            .await
            .unwrap();
        assert!(tls.is_none());
        assert!(!dir.path().join("tls").exists(), "Off must not touch disk");
    }

    #[tokio::test]
    async fn self_signed_handshake_presents_localhost() {
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::from_parts(TlsMode::Auto, no_env, dir.path(), "localhost", now())
            .await
            .unwrap()
            .unwrap();
        let st = tls.status();
        assert!(st.self_signed);
        assert_eq!(st.source, "self-signed");
        assert_eq!(st.subject, "localhost");
        let pem = fs::read_to_string(dir.path().join("tls/self-signed-cert.pem")).unwrap();
        let trust = cert_der(&pem);
        let (client, _server) = handshake(&tls, &trust).await.unwrap();
        let peer = peer_cert(&client);
        assert_eq!(peer, trust);
        let (_, x509) = x509_parser::parse_x509_certificate(peer.as_ref()).unwrap();
        let san = x509.subject_alternative_name().unwrap().unwrap();
        assert!(
            san.value.general_names.iter().any(|n| matches!(
                n,
                x509_parser::extensions::GeneralName::DNSName("localhost")
            )),
            "SANs: {:?}",
            san.value.general_names
        );
    }

    #[tokio::test]
    async fn fixed_location_status_and_unchanged_reload() {
        let dir = tempfile::tempdir().unwrap();
        let (c, k) = valid_pair();
        let tls = tls_with_fixed(dir.path(), &c, &k).await;
        let st = tls.status();
        assert!(!st.self_signed);
        assert_eq!(
            st.source,
            dir.path().join("tls/cert.pem").display().to_string()
        );
        assert_eq!(tls.reload_now().await, ReloadOutcome::Unchanged);
    }

    #[tokio::test]
    async fn reload_swaps_cert_for_new_handshakes() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, k1) = valid_pair();
        let tls = tls_with_fixed(dir.path(), &c1, &k1).await;
        let (client, _) = handshake(&tls, &cert_der(&c1)).await.unwrap();
        assert_eq!(
            sha(peer_cert(&client).as_ref()),
            sha(cert_der(&c1).as_ref())
        );

        let (c2, k2) = valid_pair();
        write_fixed(dir.path(), &c2, &k2);
        assert_eq!(tls.reload_now().await, ReloadOutcome::Reloaded);
        let (client, _) = handshake(&tls, &cert_der(&c2)).await.unwrap();
        assert_eq!(
            sha(peer_cert(&client).as_ref()),
            sha(cert_der(&c2).as_ref())
        );
        assert_eq!(tls.reload_now().await, ReloadOutcome::Unchanged);
    }

    #[tokio::test]
    async fn reload_mismatched_intermediate_state_heals() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, k1) = valid_pair();
        let tls = tls_with_fixed(dir.path(), &c1, &k1).await;
        let (c2, k2) = valid_pair();
        // New cert lands before its key.
        fs::write(dir.path().join("tls/cert.pem"), &c2).unwrap();
        match tls.reload_now().await {
            ReloadOutcome::Failed(e) => assert!(e.contains("does not match"), "{e}"),
            other => panic!("expected Failed, got {other:?}"),
        }
        // Failure is not recorded: the same files fail again (retry).
        assert!(matches!(tls.reload_now().await, ReloadOutcome::Failed(_)));
        // Old cert still served.
        let (client, _) = handshake(&tls, &cert_der(&c1)).await.unwrap();
        assert_eq!(peer_cert(&client), cert_der(&c1));
        fs::write(dir.path().join("tls/key.pem"), &k2).unwrap();
        assert_eq!(tls.reload_now().await, ReloadOutcome::Reloaded);
        let (client, _) = handshake(&tls, &cert_der(&c2)).await.unwrap();
        assert_eq!(peer_cert(&client), cert_der(&c2));
    }

    #[tokio::test]
    async fn reload_expired_replacement_fails_and_keeps_old() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, k1) = valid_pair();
        let tls = tls_with_fixed(dir.path(), &c1, &k1).await;
        let (c2, k2) = make_cert("localhost", (2020, 1, 1), (2021, 1, 1));
        write_fixed(dir.path(), &c2, &k2);
        match tls.reload_now().await {
            ReloadOutcome::Failed(e) => assert!(e.contains("expired"), "{e}"),
            other => panic!("expected Failed, got {other:?}"),
        }
        let (client, _) = handshake(&tls, &cert_der(&c1)).await.unwrap();
        assert_eq!(peer_cert(&client), cert_der(&c1));
        assert_eq!(tls.status().not_after, load_status_not_after(&c1, &k1));
    }

    fn load_status_not_after(cert: &str, key: &str) -> SystemTime {
        let d = tempfile::tempdir().unwrap();
        let c = write(d.path(), "c.pem", cert);
        let k = write(d.path(), "k.pem", key);
        load_pair(&c, &k, now()).unwrap().not_after
    }

    #[tokio::test]
    async fn reload_missing_files_fails_and_keeps_old() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, k1) = valid_pair();
        let tls = tls_with_fixed(dir.path(), &c1, &k1).await;
        fs::remove_file(dir.path().join("tls/key.pem")).unwrap();
        match tls.reload_now().await {
            ReloadOutcome::Failed(e) => assert!(e.contains("key.pem"), "{e}"),
            other => panic!("expected Failed, got {other:?}"),
        }
        let (client, _) = handshake(&tls, &cert_der(&c1)).await.unwrap();
        assert_eq!(peer_cert(&client), cert_der(&c1));
    }

    #[tokio::test]
    async fn self_signed_upgrades_to_fixed_location() {
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::from_parts(TlsMode::Auto, no_env, dir.path(), "localhost", now())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tls.reload_now().await, ReloadOutcome::NothingToReload);
        let (c, k) = valid_pair();
        write_fixed(dir.path(), &c, &k);
        assert_eq!(tls.reload_now().await, ReloadOutcome::Reloaded);
        let st = tls.status();
        assert!(!st.self_signed);
        assert_eq!(
            st.source,
            dir.path().join("tls/cert.pem").display().to_string()
        );
        let (client, _) = handshake(&tls, &cert_der(&c)).await.unwrap();
        assert_eq!(peer_cert(&client), cert_der(&c));
        assert_eq!(tls.reload_now().await, ReloadOutcome::Unchanged);
    }

    #[tokio::test]
    async fn self_signed_upgrade_with_bad_pair_stays_self_signed() {
        let dir = tempfile::tempdir().unwrap();
        let tls = Tls::from_parts(TlsMode::Auto, no_env, dir.path(), "localhost", now())
            .await
            .unwrap()
            .unwrap();
        let (c, _) = valid_pair();
        let (_, k) = valid_pair();
        write_fixed(dir.path(), &c, &k);
        assert!(matches!(tls.reload_now().await, ReloadOutcome::Failed(_)));
        assert!(tls.status().self_signed);
    }

    #[tokio::test]
    async fn env_source_is_watched() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, k1) = valid_pair();
        let cp = write(dir.path(), "env-cert.pem", &c1);
        let kp = write(dir.path(), "env-key.pem", &k1);
        let (cs, ks) = (cp.display().to_string(), kp.display().to_string());
        let lookup = move |k: &str| match k {
            "KISS_MAIL_TLS_CERT" => Some(cs.clone()),
            "KISS_MAIL_TLS_KEY" => Some(ks.clone()),
            _ => None,
        };
        let tls = Tls::from_parts(TlsMode::Auto, lookup, dir.path(), "localhost", now())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tls.status().source, cp.display().to_string());
        let (c2, k2) = valid_pair();
        write(dir.path(), "env-cert.pem", &c2);
        write(dir.path(), "env-key.pem", &k2);
        assert_eq!(tls.reload_now().await, ReloadOutcome::Reloaded);
    }

    #[tokio::test]
    async fn startup_errors_abort() {
        let dir = tempfile::tempdir().unwrap();
        let (c, k) = make_cert("localhost", (2020, 1, 1), (2021, 1, 1));
        write_fixed(dir.path(), &c, &k);
        let err = Tls::from_parts(TlsMode::Auto, no_env, dir.path(), "localhost", now())
            .await
            .err()
            .unwrap();
        assert!(err.contains("expired"), "{err}");
    }

    #[tokio::test]
    async fn handshake_timeout_returns_timed_out() {
        let dir = tempfile::tempdir().unwrap();
        let (c, k) = valid_pair();
        let tls = tls_with_fixed(dir.path(), &c, &k).await;
        let (_client, server) = tokio::io::duplex(1024);
        let err = tls
            .accept_with(server, Duration::from_millis(100))
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(15));
    }

    #[tokio::test]
    async fn live_session_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, k1) = valid_pair();
        let tls = tls_with_fixed(dir.path(), &c1, &k1).await;
        let (mut client, mut server) = handshake(&tls, &cert_der(&c1)).await.unwrap();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let n = server.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                server.write_all(&buf[..n]).await.unwrap();
                server.flush().await.unwrap();
            }
        });
        let mut buf = [0u8; 5];
        client.write_all(b"one\r\n").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"one\r\n");

        let (c2, k2) = valid_pair();
        write_fixed(dir.path(), &c2, &k2);
        assert_eq!(tls.reload_now().await, ReloadOutcome::Reloaded);

        client.write_all(b"two\r\n").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"two\r\n");
        // The live session still uses the old cert; new handshakes get the new one.
        assert_eq!(peer_cert(&client), cert_der(&c1));
        let (fresh, _) = handshake(&tls, &cert_der(&c2)).await.unwrap();
        assert_eq!(peer_cert(&fresh), cert_der(&c2));
        client.shutdown().await.unwrap();
        drop(client);
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn expiry_warning_within_14_days_at_most_daily() {
        let dir = tempfile::tempdir().unwrap();
        let (c, k) = valid_pair();
        let tls = tls_with_fixed(dir.path(), &c, &k).await;
        let not_after = tls.status().not_after;
        // Far from expiry: no warning (the startup check did not fire either).
        assert!(!tls.maybe_warn_expiry(not_after - 15 * DAY));
        let t = not_after - 14 * DAY;
        assert!(tls.maybe_warn_expiry(t));
        assert!(!tls.maybe_warn_expiry(t + Duration::from_secs(23 * 3600)));
        assert!(tls.maybe_warn_expiry(t + DAY));
        // Already expired still warns, once per day.
        assert!(tls.maybe_warn_expiry(not_after + DAY));
        assert!(!tls.maybe_warn_expiry(not_after + DAY + Duration::from_secs(60)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sighup_triggers_reload() {
        let dir = tempfile::tempdir().unwrap();
        let (c1, k1) = valid_pair();
        let tls = tls_with_fixed(dir.path(), &c1, &k1).await;
        spawn_sighup_handler(Some(Arc::clone(&tls)));
        let before = tls.status().not_after;
        let (c2, k2) = make_cert("localhost", (2020, 1, 1), (2199, 1, 1));
        write_fixed(dir.path(), &c2, &k2);
        // SAFETY: raise() is async-signal-safe; the handler is installed above.
        assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tls.status().not_after == before {
            assert!(
                tokio::time::Instant::now() < deadline,
                "SIGHUP did not reload"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (client, _) = handshake(&tls, &cert_der(&c2)).await.unwrap();
        assert_eq!(peer_cert(&client), cert_der(&c2));
    }
}
