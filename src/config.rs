//! Environment-based configuration helpers shared by the server and the CLI.
//!
//! Every lookup has a pure `resolve_*` variant that takes an env lookup
//! function so it can be unit-tested without touching the process
//! environment.

use std::env;
use std::path::PathBuf;

/// Default data directory when neither `KISS_MAIL_DATA_DIR` nor
/// `KISS_MAIL_DATA` is set.
const DEFAULT_DATA_DIR: &str = "./mail_data";

/// Deprecated aliases and the canonical variable that replaces each one.
const ALIASES: [(&str, &str); 4] = [
    ("KISS_MAIL_DATA", "KISS_MAIL_DATA_DIR"),
    ("SMTP_PORT", "KISS_MAIL_SMTP_PORT"),
    ("IMAP_PORT", "KISS_MAIL_IMAP_PORT"),
    ("POP3_PORT", "KISS_MAIL_POP3_PORT"),
];

fn process_env(name: &str) -> Option<String> {
    env::var(name).ok()
}

/// The value of `name` if it is set and not empty/whitespace.
pub(crate) fn env_nonempty(name: &str) -> Option<String> {
    resolve_nonempty(process_env, name)
}

fn resolve_nonempty(lookup: impl Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    lookup(name).filter(|v| !v.trim().is_empty())
}

/// Parse a boolean setting case-insensitively (`1/true/yes/on`,
/// `0/false/no/off`). Anything else is `None`.
pub(crate) fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Read a boolean environment variable (see [`parse_bool`]). Unset or empty
/// gives `default`; an unrecognised value gives `default` and logs a warning.
pub(crate) fn env_bool(name: &str, default: bool) -> bool {
    resolve_bool(process_env, name, default)
}

fn resolve_bool(lookup: impl Fn(&str) -> Option<String>, name: &str, default: bool) -> bool {
    let Some(value) = resolve_nonempty(lookup, name) else {
        return default;
    };
    parse_bool(&value).unwrap_or_else(|| {
        tracing::warn!(
            "Ignoring invalid boolean in {}: '{}' (use true/false, 1/0, yes/no or on/off); using default {}",
            name,
            value,
            default
        );
        default
    })
}

/// Resolve the data directory from an env lookup:
/// `KISS_MAIL_DATA_DIR`, then `KISS_MAIL_DATA`, then `./mail_data`.
/// Empty values are treated as unset.
pub(crate) fn resolve_data_dir(lookup: impl Fn(&str) -> Option<String>) -> PathBuf {
    ["KISS_MAIL_DATA_DIR", "KISS_MAIL_DATA"]
        .iter()
        .find_map(|k| resolve_nonempty(&lookup, k))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR))
}

/// The data directory used by the server and every local CLI command.
pub(crate) fn data_dir() -> PathBuf {
    resolve_data_dir(process_env)
}

/// Resolve a port from the first of `keys` that is set (non-empty).
/// A set but invalid value is an error rather than being silently ignored.
pub(crate) fn resolve_port(
    lookup: impl Fn(&str) -> Option<String>,
    keys: &[&str],
    default: u16,
) -> Result<u16, String> {
    for key in keys {
        if let Some(value) = resolve_nonempty(&lookup, key) {
            return value
                .trim()
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("Invalid port in {}: '{}'", key, value));
        }
    }
    Ok(default)
}

/// Read a port from the environment variable `name` (see [`resolve_port`]):
/// unset or empty gives `default`; a set but invalid value is an error.
pub(crate) fn env_port(name: &str, default: u16) -> Result<u16, String> {
    resolve_port(process_env, &[name], default)
}

/// Resolve SMTP/IMAP/POP3 ports. `KISS_MAIL_*_PORT` wins over the short alias.
pub(crate) fn resolve_ports(
    lookup: impl Fn(&str) -> Option<String>,
    defaults: (u16, u16, u16),
) -> Result<(u16, u16, u16), String> {
    Ok((
        resolve_port(&lookup, &["KISS_MAIL_SMTP_PORT", "SMTP_PORT"], defaults.0)?,
        resolve_port(&lookup, &["KISS_MAIL_IMAP_PORT", "IMAP_PORT"], defaults.1)?,
        resolve_port(&lookup, &["KISS_MAIL_POP3_PORT", "POP3_PORT"], defaults.2)?,
    ))
}

fn running_as_root() -> bool {
    // SAFETY: getuid() has no preconditions and cannot fail.
    #[cfg(unix)]
    let is_root = unsafe { libc::getuid() } == 0;
    #[cfg(not(unix))]
    let is_root = false;
    is_root
}

/// Standard ports when running as root, high ports otherwise.
pub(crate) fn default_ports() -> (u16, u16, u16) {
    if running_as_root() {
        (25, 143, 110)
    } else {
        (2525, 1143, 1100)
    }
}

/// Ports from the environment, falling back to `default_ports()`.
pub(crate) fn configured_ports() -> Result<(u16, u16, u16), String> {
    resolve_ports(process_env, default_ports())
}

/// TLS listener ports (SMTPS, IMAPS, POP3S): 465/993/995 as root, otherwise
/// 4465/1993/1995.
#[allow(dead_code)] // reason: used from Task 5 (SMTP STARTTLS)
pub(crate) fn default_tls_ports() -> (u16, u16, u16) {
    if running_as_root() {
        (465, 993, 995)
    } else {
        (4465, 1993, 1995)
    }
}

/// TLS ports from an env lookup (`KISS_MAIL_SMTPS_PORT`, `KISS_MAIL_IMAPS_PORT`,
/// `KISS_MAIL_POP3S_PORT`). A TLS port equal to any plain port is an error.
#[allow(dead_code)] // reason: used from Task 5 (SMTP STARTTLS)
pub(crate) fn resolve_tls_ports(
    lookup: impl Fn(&str) -> Option<String>,
    plain: (u16, u16, u16),
) -> Result<(u16, u16, u16), String> {
    let defaults = default_tls_ports();
    let tls = (
        resolve_port(&lookup, &["KISS_MAIL_SMTPS_PORT"], defaults.0)?,
        resolve_port(&lookup, &["KISS_MAIL_IMAPS_PORT"], defaults.1)?,
        resolve_port(&lookup, &["KISS_MAIL_POP3S_PORT"], defaults.2)?,
    );
    let tls_named = [("SMTPS", tls.0), ("IMAPS", tls.1), ("POP3S", tls.2)];
    let plain_named = [("SMTP", plain.0), ("IMAP", plain.1), ("POP3", plain.2)];
    for (tls_name, tls_port) in tls_named {
        for (plain_name, plain_port) in plain_named {
            if tls_port == plain_port {
                return Err(format!(
                    "{tls_name} port conflicts with {plain_name} port {plain_port}"
                ));
            }
        }
    }
    Ok(tls)
}

/// TLS ports from the environment, falling back to `default_tls_ports()`.
#[allow(dead_code)] // reason: used from Task 5 (SMTP STARTTLS)
pub(crate) fn configured_tls_ports(plain: (u16, u16, u16)) -> Result<(u16, u16, u16), String> {
    resolve_tls_ports(process_env, plain)
}

/// Mail domain: `KISS_MAIL_DOMAIN`, then the hostname, then `localhost`.
pub(crate) fn mail_domain() -> String {
    env_nonempty("KISS_MAIL_DOMAIN")
        .or_else(|| hostname::get().ok().and_then(|h| h.into_string().ok()))
        .unwrap_or_else(|| "localhost".to_string())
}

/// Path of the self-service password change page in the web interface.
pub(crate) const ACCOUNT_PASSWORD_PATH: &str = "/account/password";

/// Human-readable notice sent by SMTP/IMAP/POP3 when the password is correct
/// but must be changed first. Points at `KISS_MAIL_PUBLIC_URL` (the public
/// base URL of the web interface, e.g. `https://mail.example.com`) plus
/// [`ACCOUNT_PASSWORD_PATH`] when set.
pub(crate) fn password_change_message() -> String {
    resolve_password_change_message(process_env)
}

fn resolve_password_change_message(lookup: impl Fn(&str) -> Option<String>) -> String {
    let base = resolve_nonempty(lookup, "KISS_MAIL_PUBLIC_URL").map(|url| {
        // Never let a control character (CR/LF) into a protocol response.
        let url: String = url.trim().chars().filter(|c| !c.is_control()).collect();
        url.trim_end_matches('/').to_string()
    });
    match base.filter(|b| !b.is_empty()) {
        Some(base) if base.ends_with(ACCOUNT_PASSWORD_PATH) => {
            format!("Password change required; change it at {}", base)
        }
        Some(base) => format!(
            "Password change required; change it at {}{}",
            base, ACCOUNT_PASSWORD_PATH
        ),
        None => format!(
            "Password change required; change it via the web interface at {}",
            ACCOUNT_PASSWORD_PATH
        ),
    }
}

/// Warnings about deprecated or conflicting configuration variables.
///
/// Kept separate from the resolvers (which run before logging may be set up)
/// so callers can emit them once, after logging is initialised.
pub(crate) fn resolve_config_warnings(lookup: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let mut warnings = Vec::new();
    for (alias, canonical) in ALIASES {
        let Some(alias_value) = resolve_nonempty(&lookup, alias) else {
            continue;
        };
        match resolve_nonempty(&lookup, canonical) {
            None => warnings.push(format!(
                "{} is deprecated and will be removed in 0.3.0; use {} instead",
                alias, canonical
            )),
            Some(canonical_value) if canonical_value.trim() != alias_value.trim() => {
                warnings.push(format!(
                    "Both {}='{}' and {}='{}' are set; using {} ({} is deprecated and will be removed in 0.3.0)",
                    canonical, canonical_value, alias, alias_value, canonical, alias
                ))
            }
            Some(_) => warnings.push(format!(
                "{} is deprecated (will be removed in 0.3.0) and redundant with {}; remove it",
                alias, canonical
            )),
        }
    }
    warnings
}

/// Log [`resolve_config_warnings`] for the process environment. Call once
/// after logging is initialised.
pub(crate) fn log_config_warnings() {
    for warning in resolve_config_warnings(process_env) {
        tracing::warn!("{}", warning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn password_change_message_uses_public_url() {
        assert_eq!(
            resolve_password_change_message(env_of(&[])),
            "Password change required; change it via the web interface at /account/password"
        );
        assert_eq!(
            resolve_password_change_message(env_of(&[("KISS_MAIL_PUBLIC_URL", "  ")])),
            "Password change required; change it via the web interface at /account/password"
        );
        assert_eq!(
            resolve_password_change_message(env_of(&[(
                "KISS_MAIL_PUBLIC_URL",
                "https://mail.example.com/"
            )])),
            "Password change required; change it at https://mail.example.com/account/password"
        );
        assert_eq!(
            resolve_password_change_message(env_of(&[(
                "KISS_MAIL_PUBLIC_URL",
                "https://mail.example.com/account/password\r\n"
            )])),
            "Password change required; change it at https://mail.example.com/account/password"
        );
    }

    #[test]
    fn data_dir_precedence() {
        assert_eq!(resolve_data_dir(env_of(&[])), PathBuf::from("./mail_data"));
        assert_eq!(
            resolve_data_dir(env_of(&[("KISS_MAIL_DATA", "/legacy")])),
            PathBuf::from("/legacy")
        );
        assert_eq!(
            resolve_data_dir(env_of(&[("KISS_MAIL_DATA_DIR", "/data")])),
            PathBuf::from("/data")
        );
        assert_eq!(
            resolve_data_dir(env_of(&[
                ("KISS_MAIL_DATA_DIR", "/data"),
                ("KISS_MAIL_DATA", "/legacy")
            ])),
            PathBuf::from("/data")
        );
        // Empty DATA_DIR falls through to DATA
        assert_eq!(
            resolve_data_dir(env_of(&[
                ("KISS_MAIL_DATA_DIR", ""),
                ("KISS_MAIL_DATA", "/legacy")
            ])),
            PathBuf::from("/legacy")
        );
    }

    #[test]
    fn ports_defaults_and_aliases() {
        let d = (2525, 1143, 1100);
        assert_eq!(resolve_ports(env_of(&[]), d), Ok(d));
        assert_eq!(
            resolve_ports(env_of(&[("SMTP_PORT", "25"), ("IMAP_PORT", "143")]), d),
            Ok((25, 143, 1100))
        );
        assert_eq!(
            resolve_ports(
                env_of(&[
                    ("KISS_MAIL_SMTP_PORT", "587"),
                    ("SMTP_PORT", "25"),
                    ("KISS_MAIL_POP3_PORT", "995")
                ]),
                d
            ),
            Ok((587, 1143, 995))
        );
    }

    #[test]
    fn ports_reject_invalid_values() {
        let d = (2525, 1143, 1100);
        assert!(resolve_ports(env_of(&[("SMTP_PORT", "abc")]), d).is_err());
        assert!(resolve_ports(env_of(&[("KISS_MAIL_IMAP_PORT", "70000")]), d).is_err());
        assert!(resolve_ports(env_of(&[("POP3_PORT", "0")]), d).is_err());
        // Empty values count as unset
        assert_eq!(resolve_ports(env_of(&[("SMTP_PORT", "")]), d), Ok(d));
    }

    #[test]
    fn bool_parsing() {
        for v in ["1", "true", "TRUE", "Yes", "on", " On "] {
            assert_eq!(parse_bool(v), Some(true), "{}", v);
        }
        for v in ["0", "false", "False", "NO", "off"] {
            assert_eq!(parse_bool(v), Some(false), "{}", v);
        }
        assert_eq!(parse_bool("maybe"), None);
        assert_eq!(parse_bool(""), None);
    }

    #[test]
    fn tls_ports_defaults_and_errors() {
        let plain = (2525, 1143, 1100);
        // Not root in CI and dev; as root the defaults differ by design.
        #[cfg(unix)]
        if unsafe { libc::getuid() } != 0 {
            assert_eq!(
                resolve_tls_ports(env_of(&[]), plain),
                Ok((4465, 1993, 1995))
            );
            assert_eq!(default_tls_ports(), (4465, 1993, 1995));
        }
        let err = resolve_tls_ports(env_of(&[("KISS_MAIL_IMAPS_PORT", "abc")]), plain).unwrap_err();
        assert!(err.contains("KISS_MAIL_IMAPS_PORT"), "{err}");
        let err =
            resolve_tls_ports(env_of(&[("KISS_MAIL_IMAPS_PORT", "1143")]), plain).unwrap_err();
        assert!(
            err.contains("IMAPS port conflicts with IMAP port 1143"),
            "{err}"
        );
        let err =
            resolve_tls_ports(env_of(&[("KISS_MAIL_SMTPS_PORT", "2525")]), plain).unwrap_err();
        assert!(
            err.contains("SMTPS port conflicts with SMTP port 2525"),
            "{err}"
        );
        let err =
            resolve_tls_ports(env_of(&[("KISS_MAIL_POP3S_PORT", "1100")]), plain).unwrap_err();
        assert!(
            err.contains("POP3S port conflicts with POP3 port 1100"),
            "{err}"
        );
        assert_eq!(
            resolve_tls_ports(env_of(&[("KISS_MAIL_SMTPS_PORT", "5000")]), plain)
                .unwrap()
                .0,
            5000
        );
    }

    #[test]
    fn env_bool_defaults() {
        let env = env_of(&[("A", "yes"), ("B", "off"), ("C", "maybe"), ("D", " ")]);
        assert!(resolve_bool(&env, "A", false));
        assert!(!resolve_bool(&env, "B", true));
        // Invalid, empty and unset values keep the default
        assert!(resolve_bool(&env, "C", true));
        assert!(!resolve_bool(&env, "C", false));
        assert!(resolve_bool(&env, "D", true));
        assert!(!resolve_bool(&env, "MISSING", false));
    }

    #[test]
    fn nonempty_filters_blank_values() {
        let env = env_of(&[("A", "x"), ("B", "  ")]);
        assert_eq!(resolve_nonempty(&env, "A"), Some("x".to_string()));
        assert_eq!(resolve_nonempty(&env, "B"), None);
        assert_eq!(resolve_nonempty(&env, "C"), None);
    }

    #[test]
    fn config_warnings_for_aliases_and_conflicts() {
        assert!(resolve_config_warnings(env_of(&[])).is_empty());
        assert!(resolve_config_warnings(env_of(&[("KISS_MAIL_DATA_DIR", "/d")])).is_empty());

        let w = resolve_config_warnings(env_of(&[("KISS_MAIL_DATA", "/legacy")]));
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("KISS_MAIL_DATA is deprecated"));
        assert!(w[0].contains("KISS_MAIL_DATA_DIR"));
        assert!(w[0].contains("will be removed in 0.3.0"), "{}", w[0]);

        let w = resolve_config_warnings(env_of(&[
            ("KISS_MAIL_DATA_DIR", "/data"),
            ("KISS_MAIL_DATA", "/legacy"),
        ]));
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("/data") && w[0].contains("/legacy"));
        assert!(w[0].contains("using KISS_MAIL_DATA_DIR"));

        let w = resolve_config_warnings(env_of(&[("SMTP_PORT", "25"), ("POP3_PORT", "110")]));
        assert_eq!(w.len(), 2);
        assert!(w.iter().any(|m| m.contains("KISS_MAIL_SMTP_PORT")));
        assert!(w.iter().any(|m| m.contains("KISS_MAIL_POP3_PORT")));

        // Empty alias is ignored
        assert!(resolve_config_warnings(env_of(&[("IMAP_PORT", "")])).is_empty());
    }
}
