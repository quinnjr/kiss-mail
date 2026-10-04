#![allow(dead_code)] // removed in Task 8 once wired

//! Native TLS: certificate source selection and PEM validation.

use rustls::crypto::ring::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

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

    let (not_before, not_after, subject) = {
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
        (
            to_system_time(validity.not_before.timestamp()),
            to_system_time(validity.not_after.timestamp()),
            subject,
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
    })
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
}
