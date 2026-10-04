# Changelog

All notable changes to KISS Mail will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Native TLS and STARTTLS for the mail protocols (no proxy needed):
  - Implicit TLS listeners: SMTPS 465 (submission only, AUTH required), IMAPS
    993 and POP3S 995 (4465/1993/1995 inside the container; override with
    `KISS_MAIL_SMTPS_PORT`, `KISS_MAIL_IMAPS_PORT`, `KISS_MAIL_POP3S_PORT`).
  - `STARTTLS` on SMTP (25/587) and IMAP (143), `STLS` on POP3 (110).
  - Settings: `KISS_MAIL_TLS` (`auto`/`off`, plus boolean aliases),
    `KISS_MAIL_TLS_CERT`, `KISS_MAIL_TLS_KEY`, `KISS_MAIL_ALLOW_PLAINTEXT_AUTH`.
  - Certificate source: the env vars, then `$DATA_DIR/tls/cert.pem` + `key.pem`,
    then a self-signed certificate (397 days, regenerated within 30 days of
    expiry, stable fingerprint across restarts). Reloaded within 60 s and on
    `SIGHUP`. An expired, unparseable or mismatched configured certificate
    aborts startup. TLS 1.2 and 1.3 only.
  - VM bootstrap installs a Certbot deploy hook
    (`/etc/letsencrypt/renewal-hooks/deploy/kiss-mail.sh`); Helm gets
    `tls.mode`, `tls.existingSecret` (cert-manager) and `tls.allowPlaintextAuth`;
    firewall rules and compose/Kubernetes manifests cover the new ports.
- Zero-knowledge email encryption (ProtonMail-style)
  - X25519 key exchange
  - ChaCha20-Poly1305 authenticated encryption
  - Password-protected private keys with Argon2id
- Web admin dashboard with Tailwind CSS
- REST API for remote administration
- Remote CLI support (`--server` and `--api-key` flags)
- SSO authentication (1Password, Google, Microsoft, Okta, Auth0)
- LDAP integration (Active Directory, OpenLDAP)
- Groups and distribution lists
- AI-powered spam detection (Bayesian classifier)
- ClamAV antivirus integration
- Comprehensive deployment options:
  - Docker and Docker Compose
  - Kubernetes manifests
  - Helm chart
  - AWS Terraform
  - Digital Ocean Terraform
  - One-click install script
- Self-service password change for every local user: web page
  `GET/POST /account/password` (outside `/admin`; CSRF double-submit cookie,
  Origin/Referer check, per-user/IP throttle), REST endpoint
  `POST /api/account/password` (no token needed; 200/400/401/403/429), CLI
  `kiss-mail change-password <user> [--stdin]` (local, or `--server` without
  an API key) and `RemoteClient::change_password`. The admin navigation links
  to it ("Change my password").
- `KISS_MAIL_PUBLIC_URL`: public base URL of the web interface, used in
  "password change required" replies.
- Nginx (shared deploy block), the Kubernetes ingress and the Helm ingress
  route `/account/`, `/static/` and `/callback` to the web admin.
- `KISS_MAIL_TRUSTED_PROXIES` (comma-separated CIDRs, default
  `127.0.0.1/32,::1/128`): when the TCP peer is trusted, the client IP is taken
  from `X-Real-IP`, otherwise from the rightmost untrusted `X-Forwarded-For`
  entry. It is used for lockout and `allowed_ips`. The deploy scripts trust
  the Docker bridge range, Nginx overwrites (no longer appends to)
  `X-Forwarded-For`, and Helm/Kubernetes have a `trustedProxies` value /
  ConfigMap entry to set to the ingress controller pod CIDR.
- `SSO_ALLOW_SUBDOMAINS` and `SSO_AUTO_BIND_ADMINS` (both default false).
- CLI: `kiss-mail sso-link <user> <provider> <sub>` (provider = the configured
  display name, e.g. `Google`/`OIDC`), `kiss-mail sso-unbind <user>` and
  `kiss-mail purge-orphans` (local only). `passwd <user> <pw>
  [--require-change]` (`--require-change` is local only).
- Remote CLI `--insecure`: needed for plain `http://` to a non-loopback host.
- SMTP `EHLO` advertises `ENHANCEDSTATUSCODES`; POP3 `CAPA` advertises
  `RESP-CODES` and `AUTH-RESP-CODE`.
- Web admin: embedded `/static/app.css` and `/static/app.js` (no Tailwind
  CDN) and a strict `Content-Security-Policy`.
- `POST /api/groups` body: `{name, email?, description?, members?}`; `email`
  defaults to `name@domain` and every member must exist.
- Helm: `publicUrl` (`KISS_MAIL_PUBLIC_URL`, omitted when empty),
  `trustedProxies`, `webAdmin.secureCookie`, `sso.allowSubdomains`,
  `sso.autoBindAdmins`. `sso.provider=onepassword` emits
  `ONEPASSWORD_USERINFO_URL` (required). Compose and the Kubernetes ConfigMap
  have commented-out `KISS_MAIL_PUBLIC_URL` lines. The bootstrap sets
  `KISS_MAIL_PUBLIC_URL=http://<public IP>`, and `install.sh` has
  `--public-url`.

### Changed
- **Breaking: plaintext logins are disabled by default.** SMTP answers
  `538 5.7.11`, IMAP `NO [PRIVACYREQUIRED]` (with `LOGINDISABLED`) and POP3
  `-ERR [AUTH]` on connections without TLS. Checklist:
  - [ ] Point mail clients at implicit TLS (993/465/995) or use STARTTLS/STLS.
  - [ ] `upgrade.sh` keeps existing installs working: it adds
        `KISS_MAIL_ALLOW_PLAINTEXT_AUTH=true` when the old container has no
        TLS settings and prints how to remove it
        (`--no-pull --env KISS_MAIL_ALLOW_PLAINTEXT_AUTH=false`).
  - [ ] Docker Compose and Helm users: set `KISS_MAIL_ALLOW_PLAINTEXT_AUTH=true`
        (Helm `tls.allowPlaintextAuth`) until clients switch, or switch to TLS.
  - [ ] `KISS_MAIL_TLS=off` disables TLS and keeps plaintext logins allowed,
        with a startup warning and a banner line.
  - [ ] Install a real certificate: Outlook and Gmail refuse the self-signed
        one.
- Docker images are built only from the standard Alpine `Dockerfile` (`rust:1.94-alpine` builder, `alpine:3.23` runtime). The Docker Hardened Images (`dhi.io`) variant and `Dockerfile.alpine` were removed: dhi.io is enterprise-only, and the CI workflow no longer needs Docker Hub credentials.
- Improved startup banner with security status
- **REST API status codes** now follow the error kind: 400 invalid input
  (including an unknown `role` or `status` value, which used to be ignored),
  401 missing/invalid credentials, 403 insufficient role, 404 unknown user or
  group, 409 already exists, 500 server-side failures. Previously most errors
  were returned with 200 and `success: false`.
- Actions performed with an admin-API login token are limited by the role of
  the user who logged in (an Admin token can no longer act as a SuperAdmin).
- A failed `POST /api/auth/login` returns 401 with the standard error envelope
  (`{"success": false, "error": "..."}`).
- CLI: every command exits with status 1 on error and prints errors to
  stderr; `add` prints the role of the created user; `passwd <user> --stdin`
  reads the new password from stdin.
- Environment variables renamed: `KISS_MAIL_DATA` -> `KISS_MAIL_DATA_DIR`,
  `SMTP_PORT`/`IMAP_PORT`/`POP3_PORT` -> `KISS_MAIL_SMTP_PORT`/
  `KISS_MAIL_IMAP_PORT`/`KISS_MAIL_POP3_PORT`. The old names still work as
  deprecated aliases and log a warning (the new name wins if both are set).
- Encryption at rest is now actually applied to newly delivered mail
  (`KISS_MAIL_ENCRYPTION=false` disables it for new mail; existing encrypted
  mail stays readable).
- The bootstrap `admin` password is high-entropy, must be changed at first
  login and is written to `$KISS_MAIL_DATA_DIR/initial-admin-password` (0600)
  instead of only being printed; the log line containing "admin account" says
  where the file is.
- The web session cookie is `Secure` by default unless the web admin binds a
  loopback address (`KISS_MAIL_WEB_SECURE_COOKIE` overrides).
- `RUST_LOG` is honoured for log filtering. The binary default is
  `kiss_mail=info`, and the images, compose file, deploy scripts, Kubernetes
  ConfigMap and Helm chart (`logging.level`) now use it as well (plain `info`
  also enables every dependency's logs).
- Lockout: per (user, client IP) lockout, plus a per-source limit (20
  failures per 10 minutes) and a per-username progressive delay that never
  locks the account. A locked-out login returns **HTTP 429** from the web
  admin and the API (the account password endpoint used to return 403).
- The `Locked` account status is admin-only ("Account is locked"); accounts
  auto-locked by older versions are migrated back to Active on load.
- Sessions and API tokens end when a user's password changes or a change is
  required. An admin password reset also revokes the user's app passwords.
  The new password must differ from the old one.
- LDAP users can't use the self-service password change (the directory
  manages it), and LDAP logins no longer regenerate mail keys.
- App-password logins for accounts that don't exist locally are refused. Only
  the 20 most recent non-expired app passwords of a user are checked at login.
- REST API: creating an app password for an unknown user returns 404;
  revoking returns 404 for an unknown id and 500 when the revocation couldn't
  be saved.
- Web admin: logout is `POST /admin/logout` only; flash messages use
  `?flash=<code>` with a fixed set of codes (`user_created`, `user_updated`,
  `user_deleted`, `user_deleted_cleanup_failed`, `user_not_found`,
  `user_delete_denied`, `user_delete_failed`, `group_created`,
  `group_updated`, `group_deleted`, `group_not_found`, `group_delete_failed`,
  `member_added`, `member_removed`).
- SSO: domain matching is exact by default (`SSO_ALLOW_SUBDOMAINS=true`
  accepts subdomains, never parents). `email_verified=true` is required from
  every provider except Microsoft. Microsoft must be pinned to a tenant
  (`MICROSOFT_TENANT_ID`; `common`, `organizations` and `consumers` are
  refused), and a token's `tid` claim must match it when present. Admin
  accounts must be linked to an SSO identity first. Bindings are keyed on
  (provider, sub); a legacy binding is re-bound, with a warning, when the
  provider changes.
- Remote CLI: a server without a scheme means `https://`. Use
  `--server http://127.0.0.1:8025` for the API's own (plain HTTP) listener,
  normally through `ssh -L 8025:127.0.0.1:8025`. Passwords are read without
  echo.
- CLI `del` also removes the mailbox and SSO data, and exits with status 2 if
  that cleanup fails. SSO data, mailboxes and keys of users that no longer
  exist are purged at every startup.
- An invalid `KISS_MAIL_WEB_PORT` or `KISS_MAIL_API_PORT` aborts startup.
- Groups: a group address can't collide with a local user's address, users
  win over groups at `RCPT TO`, and a temporary failure for one
  group-expanded member no longer bounces the whole message.
- SMTP `HELO` accepts `_` in the hostname.
- ClamAV: only an exact `stream: OK` reply counts as clean; anything else is
  a scanner failure (451 with `CLAMAV_REQUIRED=true`).
- Helm: `sso.tenantId` is required for Microsoft (the chart no longer
  defaults it to `common`, which the server now refuses).
  `webAdmin.secureCookie` defaults to `"true"` only when the Ingress has
  `tls`, otherwise `"false"`.
- Deploy scripts set the admin password offline (stop, `docker run --rm -i ...
  passwd admin --stdin`, start), because `passwd` against a running server
  can be overwritten. The Terraform bootstrap marks the VM provisioned only
  once the password is set, and otherwise retries on the next boot
  (`/opt/kiss-mail/.admin-password-pending`).
- `upgrade.sh`: the snapshot is written atomically with mode 0600; a failed
  health check restores the snapshot (the new data goes to
  `<data-dir>.failed-upgrade-<timestamp>`); `HUP` also triggers a rollback,
  and the rollback itself can't be interrupted. It adds
  `KISS_MAIL_WEB_SECURE_COOKIE=false` and the Docker bridge range as
  `KISS_MAIL_TRUSTED_PROXIES` when they're missing, and prefers
  `KISS_MAIL_SMTP_PORT` over the `SMTP_PORT` alias.
- `uninstall.sh` also lists and removes upgrade snapshots, aborts if the
  container can't be stopped, and warns when the container's `/data` mount
  differs from `--data-dir`.
- Terraform: AWS requires IMDSv2 with a hop limit of 1; GCP uses a dedicated
  service account with no roles and only the logging scope; Azure ignores
  `custom_data` changes like the other providers.
- CI: workflow permissions are read-only by default (release jobs request
  `contents: write` themselves), Docker runs are serialised per ref, and
  `dtolnay/rust-toolchain` uses a single pin with an explicit `toolchain`.
  codecov-action is on v5, actions/stale on v11 and actions/labeler on v7.

### Removed
- `LDAP_GROUP_BASE_DN` and `LDAP_GROUP_FILTER` no longer do anything (LDAP
  group lookup was removed); delete them from your configuration.
- **`password_change_required` is enforced** for the local account password:
  after the password verifies, SMTP AUTH answers
  `535 5.7.0 Password change required; ...`, IMAP `NO [EXPIRED] ...`, POP3
  `-ERR [AUTH] ...`, the web admin login redirects to
  `/account/password?username=<u>&reason=required` without a session, and
  `POST /api/auth/login` returns 403 `password_change_required` with a hint.
  App passwords and LDAP logins are not affected. The bootstrap `admin`
  account therefore cannot be used until its password is changed (the deploy
  scripts set a new password, which clears the flag).
- Group members must be existing accounts: unknown usernames are rejected
  with "user X does not exist" (HTTP 400); `POST /api/groups` validates its
  `members` before creating anything. Deleting a user removes them from all
  groups and hands groups they owned to `admin` (owner kept, with a warning,
  if there is no `admin` account). The server warns at startup about group
  members that do not exist. Removing a non-member is now reported as "X is
  not a member of the group".
- New passwords that are too short are reported as a password-policy error
  (HTTP 400 in the API).
- Message header parsing for stored mail uses the shared MIME helpers
  (header names keep their case; surrounding whitespace in header names and
  blank continuation lines are now trimmed as in the rest of the server).
- Deployment: all Terraform providers boot Ubuntu 24.04 LTS and share one
  bootstrap script (`deploy/common/bootstrap.sh.tftpl`), also used by
  `install.sh` and the generic cloud-init file. Provider pins: aws `~> 6.0`,
  azurerm `~> 4.0` (needs `subscription_id` or `ARM_SUBSCRIPTION_ID`),
  google `~> 7.0`.
- Deployment: the `admin_password` Terraform variable was removed from every
  provider; the password is generated on the VM.
- Helm: `api.enabled` defaults to `false`; `KISS_MAIL_API_ENABLED` is only set
  when it is true; generic OIDC requires `sso.userinfoUrl`; optional
  `networkPolicy` and `sso.allowedDomain` values.
- Docker Compose publishes the web admin (8080) and REST API (8025) on
  127.0.0.1 only and runs with `init: true`.
- Container images: CI pushes only an immutable `sha-<commit>` tag, scans it
  with Trivy, and only then adds `latest`/semver/branch tags and signs the
  final digest with cosign. All GitHub Actions are pinned to commit SHAs.

### Upgrade notes
- **TLS.** Servers set up with Certbot before this release lack the deploy
  hook, so renewed certificates are not copied to the mail ports. Install
  `/etc/letsencrypt/renewal-hooks/deploy/kiss-mail.sh` (script in DEPLOY.md,
  from `install_tls_hook` in `deploy/common/bootstrap.sh.tftpl`), then run
  `certbot reconfigure --cert-name <domain> --deploy-hook <hook>` or reissue
  with `certbot --nginx --redirect -d <domain> --deploy-hook <hook>`. Run
  `terraform apply` for the new firewall rules and `upgrade.sh` for the
  465/993/995 bindings (busy host ports are skipped with a warning).
- **Back up the data directory before upgrading** (`upgrade.sh` now writes
  `<data-dir>.pre-upgrade-<timestamp>.tgz` automatically).
- **No rollback to earlier versions once encrypted mail has arrived**: older
  releases cannot read mail encrypted at rest. To go back, restore the
  pre-upgrade backup (mail received since then is lost).
- Installs created before the `UserManager` user store was introduced must
  first upgrade through the previous release (v0.1.0) so their users are
  migrated, then upgrade to this version.
- Rename `KISS_MAIL_DATA` and `SMTP_PORT`/`IMAP_PORT`/`POP3_PORT` in your
  configuration. The aliases are deprecated and **will be removed in 0.3.0**.
- SSO:
  - `SSO_ALLOWED_DOMAIN` or `KISS_MAIL_DOMAIN` is now required, and domains
    match exactly. With `KISS_MAIL_DOMAIN=mail.example.com`, `user@example.com`
    is rejected unless `SSO_ALLOWED_DOMAIN=example.com`. Subdomains need
    `SSO_ALLOW_SUBDOMAINS=true`.
  - Microsoft needs your own `MICROSOFT_TENANT_ID`.
  - Other providers must send `email_verified=true`.
- SSO bindings: admin accounts must now be linked explicitly:
  `kiss-mail sso-link <user> <provider> <sub>` (or set
  `SSO_AUTO_BIND_ADMINS=true`). Existing (legacy) bindings keep working and
  are re-bound, with a warning, if the provider changes. To fix a wrong
  binding, run `kiss-mail sso-unbind <user>` and link again.
- Accounts that older versions locked automatically are migrated back to
  Active when the user store loads. `Locked` is now set only by admins.
- Accounts flagged "must change password" (including a bootstrap `admin`
  whose password was never changed) can't log in until it's changed. Their
  mail clients fail with SMTP `535`, IMAP `NO [EXPIRED]` or POP3
  `-ERR [AUTH]`. Find them with `kiss-mail info <user>`. To clear the flag,
  set a new password (web admin, `/account/password`, or `kiss-mail passwd`
  with the server stopped).
- Secure session cookie: if you serve the web admin over plain HTTP on a
  non-loopback address, set `KISS_MAIL_WEB_SECURE_COOKIE=false` until HTTPS
  is in place, or logins won't stick.
  - `upgrade.sh` adds `KISS_MAIL_WEB_SECURE_COOKIE=false` (with a notice) to
    containers that don't set it.
  - Helm now emits `KISS_MAIL_WEB_SECURE_COOKIE` itself: `"true"` with
    `ingress.tls`, otherwise `"false"`. Override it with
    `webAdmin.secureCookie`.
  - In the plain Kubernetes ConfigMap, uncomment
    `KISS_MAIL_WEB_SECURE_COOKIE: "false"` for HTTP access.
- Behind a reverse proxy, set `KISS_MAIL_TRUSTED_PROXIES`, or every client
  shares the proxy's IP for lockout. `upgrade.sh` adds the Docker bridge
  range when the variable is missing.
- Remote CLI: write `--server http://127.0.0.1:8025` (through an SSH tunnel).
  A bare `host:8025` now means https.
- Remove `LDAP_GROUP_BASE_DN` / `LDAP_GROUP_FILTER`.
- Helm with Microsoft SSO: set `sso.tenantId`.
- Terraform users: remove `admin_password` from `terraform.tfvars`; Azure users
  set `subscription_id` (azurerm 4.x).
- Docker Compose users: the web admin is now on `127.0.0.1:8080`; use an SSH
  tunnel or a reverse proxy for remote access.

### Fixed
- Build after the Dependabot major bumps: ported to the `rand` 0.10 traits (`RngExt` and `Rng`). X25519 keys are now generated with `x25519-dalek` 3 `StaticSecret::random()` from the OS RNG. The redundant direct `password-hash` dependency was removed: Argon2 hashing uses `argon2`'s re-export.
- Server no longer exits right after startup; the Docker image's
  `ENTRYPOINT`/`CMD` start the server correctly.
- Encryption at rest was configured but never applied; encryption failures
  now defer delivery instead of storing plaintext.
- IMAP `UID` commands, `FETCH` (including `BODYSTRUCTURE` and RFC 2231
  parameters), flags and `EXPUNGE` were stubs or incorrect.
- SMTP multi-recipient delivery distinguishes permanent and temporary
  failures and rolls back partial deliveries.
- The web admin session cookie could be forged; sessions are now server-side.
- Deleting a user also removes their mailbox and SSO data / app passwords.
- Usernames are canonicalised (trimmed, lower-case) everywhere.
- JSON state files are written atomically.
- Deploy scripts, Kubernetes manifests and the Helm chart used environment
  variable names the binary did not read.
- Deploy scripts raced the server's first writes; they now wait for the SMTP
  port (up to 90 s) and write `credentials.txt` before starting the container.
- `install.sh` reports "passwd failed" and "restart failed" separately.
- `upgrade.sh` rolls back on errors and interruptions from every partial
  state, keeps hardening options (network mode, read-only rootfs,
  capabilities, security options, memory and PID limits, logging, tmpfs,
  user, labels) and refuses Compose-managed containers.

### Security
- Plaintext-login refusal happens before credentials are read (for IMAP,
  before literal continuations are accepted), so a refused client never sends
  its password.
- Admin password generated on the VM and stored only in the root-only
  `credentials.txt`; never in Terraform state or instance metadata, and
  passed to the server on stdin. Setup copies are deleted after provisioning.
- Nginx (all deploy targets) no longer exposes the REST API: `location /api`
  allows only 127.0.0.1; use an SSH tunnel for the remote CLI. The SSO
  `/callback` is proxied explicitly.
- Time-based login lockout per (user, client IP) with exponential backoff
  (5 failures -> 1 min, doubling up to 1 h); `Locked` status is admin-only.
- Only a SuperAdmin can create or promote SuperAdmins.
- Posting to a group from a local-domain sender address requires SMTP AUTH as
  that user.
- SMTP: an authenticated user can no longer use another local user's address
  as `MAIL FROM` (`550 5.7.1 Sender address not owned by authenticated user`).
- SSO: `email_verified=true` is required (Microsoft: pinned tenant and `tid`
  check). The username is the email local part. Bindings are keyed on
  (provider, sub), and admin accounts must be linked explicitly.
- `CLAMAV_REQUIRED=true` makes SMTP return 451 when ClamAV cannot scan a
  message; the `X-Virus` header names the scanners that ran.
- LDAP: user DN template values are escaped with `dn_escape`; every LDAP
  operation has a timeout (`LDAP_TIMEOUT`).
- `SIGTERM` triggers a graceful shutdown (`STOPSIGNAL SIGTERM` in the images).
- Terraform `domain` variables are validated; the generic cloud-init parses
  its config file instead of sourcing it; `uninstall.sh` refuses to delete a
  directory that does not look like a KISS Mail data directory; RHEL-family
  installs set `httpd_can_network_connect`; apt waits for the dpkg lock.
- CI: third-party actions pinned to full commit SHAs; images are signed only
  after the vulnerability scan passes.
- Added automatic email encryption at rest
- Per-user encryption key pairs
- Secure key derivation with Argon2id

## [0.1.0] - 2025-01-03

### Added
- Initial release
- SMTP server (RFC 5321)
- IMAP server (RFC 3501)
- POP3 server (RFC 1939)
- Simple user management
- In-memory storage with JSON persistence
- Anti-spam filtering with rule-based scoring
- Basic anti-virus scanning
- CLI for administration
- Zero-configuration deployment
- Single binary distribution

[Unreleased]: https://github.com/quinnjr/kiss-mail/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/quinnjr/kiss-mail/releases/tag/v0.1.0
