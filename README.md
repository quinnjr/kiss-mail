# KISS Mail

A dead-simple email server. SMTP, IMAP, and POP3 in one container.

## Quick Start (Docker)

```bash
# Run with Docker (recommended)
docker run -d \
  --name kiss-mail \
  -p 25:2525 -p 587:2525 \
  -p 143:1143 -p 110:1100 \
  -p 127.0.0.1:8080:8080 \
  -v kiss-mail-data:/data \
  -e KISS_MAIL_DOMAIN=mail.example.com \
  ghcr.io/quinnjr/kiss-mail:latest

# Access web admin
open http://localhost:8080/admin
```

That's it. On first start the server creates an `admin` superadmin account
with a high-entropy random password, writes it to
`$KISS_MAIL_DATA_DIR/initial-admin-password` (mode 0600) and logs a line
containing "admin account" that says where the file is. The password must be
changed before the account can be used: logins with it are refused with a
"password change required" reply until you change it, either at
`http://localhost:8080/account/password` or with
`kiss-mail change-password admin`.

```bash
docker logs kiss-mail 2>&1 | grep "admin account"
docker exec kiss-mail cat /data/initial-admin-password
```

Or set it yourself, offline. Don't run `kiss-mail passwd` inside the running
container: the server keeps accounts in memory and can overwrite the change.
The password is read from stdin, so it never appears in a process listing:

```bash
docker stop kiss-mail
printf '%s' "$NEW_PASSWORD" | docker run --rm -i -v kiss-mail-data:/data \
  ghcr.io/quinnjr/kiss-mail:latest passwd admin --stdin
docker run --rm -v kiss-mail-data:/data --entrypoint rm \
  ghcr.io/quinnjr/kiss-mail:latest -f /data/initial-admin-password
docker start kiss-mail
```

To change it while the server runs, use the web admin, or
`PUT /api/users/admin` through an SSH tunnel to the REST API.

> **TLS:** SMTP, IMAP and POP3 support implicit TLS (465/993/995) and
> STARTTLS out of the box, using a self-signed certificate until you provide a
> real one (see [TLS](#tls-and-starttls)). Logins over plaintext connections
> are refused by default. The web admin is plain HTTP: put HTTPS in front of it
> (the VM installers set up Nginx and Certbot for that) before exposing it.

### One-Line Deploy (Any VPS)

```bash
curl -fsSL https://raw.githubusercontent.com/quinnjr/kiss-mail/main/deploy/scripts/install.sh | sudo bash
```

### Build from Source (Optional)

```bash
cargo build --release
./target/release/kiss-mail
```

## Usage

```bash
# Start the server
kiss-mail

# Create a user
kiss-mail add alice mysecretpassword

# List users
kiss-mail list

# Change a password (prompt-free; reads the new password from stdin)
printf '%s' "$NEW_PASSWORD" | kiss-mail passwd alice --stdin

# Change your own password, proving the current one (prompts on stderr,
# or reads current/new from stdin lines 1 and 2 with --stdin)
printf '%s\n%s\n' "$CURRENT" "$NEW_PASSWORD" | kiss-mail change-password alice --stdin

# Delete a user
kiss-mail del alice

# Show stats
kiss-mail stats
```

## Connect Your Email Client

Prefer implicit TLS (SSL/TLS) where your client offers it.

| Setting  | Implicit TLS (recommended)        | STARTTLS                    |
|----------|-----------------------------------|-----------------------------|
| Server   | localhost                         | localhost                   |
| IMAP     | 1993 (993 as root), SSL/TLS       | 1143 (143 as root)          |
| SMTP     | 4465 (465 as root), SSL/TLS       | 2525 (25 as root); submission 587 where published |
| POP3     | 1995 (995 as root), SSL/TLS       | 1100 (110 as root), `STLS`  |
| Username | your_username                     | your_username               |
| Password | your_password                     | your_password               |

In the Docker image the TLS ports are 4465/1993/1995 inside the container;
the published host ports are 465/993/995 in the VM installers, while
`docker-compose.yml` publishes 4465/1993/1995 (map them to 465/993/995 in
production). Port 465 is submission only: `MAIL`
requires `AUTH`.

- Plaintext logins are **refused by default**: SMTP answers `538 5.7.11`, IMAP
  `NO [PRIVACYREQUIRED]` (and advertises `LOGINDISABLED`), POP3 `-ERR [AUTH]`.
  Use implicit TLS or issue `STARTTLS` / `STLS` first. To keep plaintext
  logins working for old clients, set `KISS_MAIL_ALLOW_PLAINTEXT_AUTH=true`.
- STARTTLS can be stripped by an attacker who controls the network path, so
  clients should be set to require TLS (or use the implicit TLS ports). For
  server-to-server delivery on port 25 that stripping is accepted (MTA-STS and
  DANE are not implemented).
- Out of the box the server uses a self-signed certificate. Clients warn about
  it, and Outlook and Gmail refuse it; install a real certificate (below).
- TLS 1.2 and 1.3 only: very old clients that only support CBC or RSA key
  exchange cannot connect.

### TLS and STARTTLS

Listeners: implicit TLS on SMTPS, IMAPS and POP3S, plus SMTP `STARTTLS`
(25/587), IMAP `STARTTLS` (143) and POP3 `STLS` (110).

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_TLS` | auto | `auto` or `off`. Also accepts true/on/yes/1 (auto) and false/off/no/0 (off). `off` disables every TLS listener and STARTTLS **and allows plaintext logins**; the server logs a startup warning and prints a banner line |
| `KISS_MAIL_TLS_CERT` / `KISS_MAIL_TLS_KEY` | (unset) | PEM certificate chain and private key; set both or neither |
| `KISS_MAIL_SMTPS_PORT` | 4465 (465 as root) | Implicit TLS SMTP (submission, AUTH required) |
| `KISS_MAIL_IMAPS_PORT` | 1993 (993 as root) | Implicit TLS IMAP |
| `KISS_MAIL_POP3S_PORT` | 1995 (995 as root) | Implicit TLS POP3 |
| `KISS_MAIL_ALLOW_PLAINTEXT_AUTH` | false | Allow logins on connections without TLS |

A TLS port equal to a plain port aborts startup.

Certificate source, first match wins:

1. `KISS_MAIL_TLS_CERT` + `KISS_MAIL_TLS_KEY`
2. `$KISS_MAIL_DATA_DIR/tls/cert.pem` + `key.pem`
3. a self-signed certificate (397 days, regenerated within 30 days of expiry,
   names = `KISS_MAIL_DOMAIN` and `localhost`, same fingerprint across
   restarts while the data directory is kept)

The server checks the certificate files every 60 seconds (by content hash)
and reloads on `SIGHUP` immediately (`docker kill --signal=HUP kiss-mail`).
Only new connections see the new certificate. It switches from self-signed to
the files in `$DATA_DIR/tls/` as soon as they appear.

An expired, unparseable or mismatched configured certificate **aborts
startup**, and the message names the file. Renew it (`certbot renew`), then
start the server again. An expiry within 14 days is logged as a warning.

See [DEPLOY.md](DEPLOY.md#ssltls) for Certbot on VMs, cert-manager on
Kubernetes, firewalls and upgrading existing installs.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_DATA_DIR` (deprecated alias `KISS_MAIL_DATA`) | `./mail_data` | Data directory (`KISS_MAIL_DATA_DIR` wins if both are set) |
| `KISS_MAIL_DOMAIN` | (hostname) | Email domain |
| `KISS_MAIL_SMTP_PORT` (deprecated alias `SMTP_PORT`) | 2525 (25 as root) | SMTP port |
| `KISS_MAIL_IMAP_PORT` (deprecated alias `IMAP_PORT`) | 1143 (143 as root) | IMAP port |
| `KISS_MAIL_POP3_PORT` (deprecated alias `POP3_PORT`) | 1100 (110 as root) | POP3 port |
| `KISS_MAIL_TLS`, `KISS_MAIL_TLS_CERT`, `KISS_MAIL_TLS_KEY`, `KISS_MAIL_SMTPS_PORT`, `KISS_MAIL_IMAPS_PORT`, `KISS_MAIL_POP3S_PORT`, `KISS_MAIL_ALLOW_PLAINTEXT_AUTH` | see [TLS and STARTTLS](#tls-and-starttls) | Native TLS settings |
| `RUST_LOG` | `kiss_mail=info` (server), `kiss_mail=warn` (CLI) | Log filter in `tracing` syntax, e.g. `kiss_mail=debug`. Plain `info` also enables the logs of every dependency |
| `CLAMAV_REQUIRED` | false | When true, SMTP answers 451 (try again later) if ClamAV could not scan a message, instead of accepting it with the built-in scanner only. Only an exact `stream: OK` reply counts as clean; anything else is a scanner failure |
| `KISS_MAIL_TRUSTED_PROXIES` | `127.0.0.1/32,::1/128` | Comma-separated CIDRs of reverse proxies. When the TCP peer is trusted, the client IP comes from `X-Real-IP`, otherwise from the rightmost untrusted `X-Forwarded-For` entry. Used for lockout and `allowed_ips`. Behind Nginx on the Docker host add the bridge range (e.g. `172.16.0.0/12`); behind a Kubernetes Ingress, the ingress controller pod CIDR |
| `KISS_MAIL_PUBLIC_URL` | (unset) | Public base URL of the web interface, e.g. `https://mail.example.com`. Used in "password change required" replies (`<url>/account/password`); unset, the reply points at `/account/password` on the web interface |

The deprecated aliases still work but log a warning at startup; they will be
**removed in 0.3.0**. Boolean settings accept `1`/`true`/`yes`/`on` or
`0`/`false`/`no`/`off` (any case). An invalid `KISS_MAIL_WEB_PORT` or
`KISS_MAIL_API_PORT` aborts startup.

### Security behaviour

- **Login lockout** is time-based and tracked per (user, client IP): after 5
  failed logins that pair is blocked for 1 minute, doubling with each further
  failure up to 1 hour; it expires on its own. A failing attacker IP cannot
  lock the real user out from elsewhere. On top of that, a client IP is
  blocked after 20 failures in 10 minutes (any usernames), and each username
  gets a progressive delay that never locks the account. A locked-out login
  gets HTTP 429 from the web admin and the API. The `locked` account status is
  only set by an administrator ("Account is locked"). Accounts that older
  versions locked automatically are migrated back to Active on load. The
  client IP comes from `KISS_MAIL_TRUSTED_PROXIES` (see above).
- **Bootstrap admin password**: see Quick Start; it is stored in
  `initial-admin-password` in the data directory and must be changed at first
  login.
- **Password change required**: accounts flagged "must change password" (the
  bootstrap admin, or `kiss-mail passwd <user> <pass> --require-change`) cannot
  log in with their local password until they change it. The password is still
  verified first (a wrong one is an ordinary failure, and a correct one is not
  counted towards the lockout). Each protocol answers with a dedicated reply,
  where `<where>` is `KISS_MAIL_PUBLIC_URL` + `/account/password`, or
  "via the web interface at /account/password" when that is unset:
  - SMTP AUTH: `535 5.7.0 Password change required; change it at <where>`
  - IMAP LOGIN/AUTHENTICATE: `<tag> NO [EXPIRED] Password change required; ...` (RFC 5530)
  - POP3 PASS: `-ERR [AUTH] Password change required; ...` (RFC 3206)
  - Web admin login: no session; redirect to `/account/password?username=<u>&reason=required`
  - `POST /api/auth/login`: HTTP 403, `"error": "password_change_required"` plus a `hint`

  App passwords and LDAP logins are not affected (the flag concerns the local
  account password). Change the password at `/account/password`, with
  `POST /api/account/password`, or with `kiss-mail change-password <user>`;
  an admin reset without `--require-change` (`kiss-mail passwd <user>`) also
  clears the flag. To find flagged accounts whose mail clients fail with the
  replies above, run `kiss-mail info <user>`.
- **Password changes**: the new password must differ from the old one.
  Changing a password (or flagging it "must change") ends the user's web
  sessions and API tokens, and an admin password reset also revokes the
  user's app passwords. LDAP users change their password in the directory:
  the self-service change is refused for them, and LDAP logins no longer
  regenerate mail keys.
- **Deleted users**: `kiss-mail del` removes the mailbox and SSO data too, and
  exits with status 2 if that cleanup fails. Restart a running server after
  a local `del`. At every startup (and with `kiss-mail purge-orphans`), the
  SSO data, mailboxes and keys of users that no longer exist are removed.
  App-password logins for accounts that don't exist locally are refused.
- **Sender addresses**: an address in a local domain may only be used as the
  SMTP `MAIL FROM` after SMTP AUTH as that same user (case-insensitive);
  otherwise the server answers `550 5.7.1 Sender address not owned by
  authenticated user` (or `Authentication required to send as a local user`
  without AUTH). The null sender `<>` is always accepted.
- **Group posting**: a sender address in the local domain may only post to a
  group after SMTP AUTH as that same user, so local addresses cannot be spoofed
  into distribution lists.
- **Admin roles**: only a SuperAdmin can create or promote SuperAdmins, and
  actions done with the admin API token are limited by the caller's role.
- **SIGTERM** (what `docker stop` and Kubernetes send) shuts the server down
  gracefully.

See the sections below for web admin, API, encryption, LDAP, SSO and ClamAV
variables.

## Docker (Recommended)

Docker is the **preferred deployment method** for KISS Mail.

### Security

Published images are built from the repository's `Dockerfile` on the official
`rust:alpine` and `alpine` base images.
- **Continuously scanned** - Trivy scan on every push; the workflow fails on fixable critical CVEs
- **Minimal attack surface** - Alpine Linux base, pure-Rust TLS (no OpenSSL)
- **SBOM and provenance attestations** - Attached to each pushed image by BuildKit
- **Non-root user** - Runs as uid 1000; `/data` must be a writable volume
- **Signed** - Keyless [cosign](https://github.com/sigstore/cosign) signature from the GitHub Actions workflow

```bash
cosign verify ghcr.io/quinnjr/kiss-mail:latest \
  --certificate-identity-regexp 'https://github.com/quinnjr/kiss-mail/.github/workflows/docker.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Pull from Registry

```bash
# Pull the official image
docker pull ghcr.io/quinnjr/kiss-mail:latest

# Run container
docker run -d \
  --name kiss-mail \
  --restart unless-stopped \
  -p 25:2525 -p 587:2525 \
  -p 143:1143 -p 110:1100 \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8025:8025 \
  -v kiss-mail-data:/data \
  -e KISS_MAIL_DOMAIN=mail.example.com \
  -e KISS_MAIL_WEB_BIND=0.0.0.0 \
  ghcr.io/quinnjr/kiss-mail:latest

# The admin account is created automatically on first start; its generated
# password is in a root-readable file in the data volume (the log says where):
docker logs kiss-mail 2>&1 | grep "admin account"
docker exec kiss-mail cat /data/initial-admin-password

# Or set your own admin password offline (read from stdin). Never run passwd
# inside the running container: the server would overwrite the change.
docker stop kiss-mail
printf '%s' "$NEW_PASSWORD" | docker run --rm -i -v kiss-mail-data:/data \
  ghcr.io/quinnjr/kiss-mail:latest passwd admin --stdin
docker start kiss-mail

# View logs
docker logs -f kiss-mail
```

### Build Locally (Optional)

```bash
docker build -t kiss-mail .
```

### Docker Compose

`docker-compose.yml` is in the repository root and requires **Docker Compose
v2.20 or newer** (it uses `depends_on.required: false`).

```bash
# Start all services
docker compose up -d

# With ClamAV antivirus
CLAMAV_ENABLED=true docker compose --profile antivirus up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

The compose file publishes the TLS ports 4465/1993/1995 (publish them as
465/993/995 on a production host). Plaintext logins are refused by default:
mount a certificate and uncomment `KISS_MAIL_TLS_CERT`/`KISS_MAIL_TLS_KEY`, or
uncomment `KISS_MAIL_ALLOW_PLAINTEXT_AUTH: "true"` for old clients.

### Container Environment Variables

Defaults below are the values set in the image.

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_DOMAIN` | localhost | Mail domain |
| `KISS_MAIL_DATA_DIR` (deprecated alias `KISS_MAIL_DATA`) | /data | Data directory (must be a writable volume) |
| `KISS_MAIL_SMTP_PORT` / `_IMAP_PORT` / `_POP3_PORT` | 2525 / 1143 / 1100 | Ports inside the container (deprecated aliases `SMTP_PORT`, `IMAP_PORT`, `POP3_PORT`) |
| `KISS_MAIL_SMTPS_PORT` / `_IMAPS_PORT` / `_POP3S_PORT` | 4465 / 1993 / 1995 | Implicit TLS ports inside the container |
| `KISS_MAIL_TLS` | auto | `auto` or `off` (see [TLS and STARTTLS](#tls-and-starttls)) |
| `KISS_MAIL_TLS_CERT` / `KISS_MAIL_TLS_KEY` | (unset) | Certificate and key; otherwise `/data/tls/cert.pem` + `key.pem`, otherwise self-signed |
| `KISS_MAIL_ALLOW_PLAINTEXT_AUTH` | false | Allow logins without TLS |
| `KISS_MAIL_WEB_PORT` | 8080 | Web admin port |
| `KISS_MAIL_WEB_BIND` | 0.0.0.0 | Web admin bind address (binary default 127.0.0.1) |
| `KISS_MAIL_WEB_SECURE_COOKIE` | true (because the bind is not loopback) | Secure session cookie; set `false` only while serving the web admin over plain HTTP on a non-localhost address |
| `KISS_MAIL_TRUSTED_PROXIES` | 127.0.0.1/32,::1/128 | Proxies trusted for `X-Real-IP` / `X-Forwarded-For`; add the Docker bridge range when a reverse proxy on the host publishes the web admin |
| `KISS_MAIL_PUBLIC_URL` | (unset) | Public base URL of the web interface |
| `KISS_MAIL_API_PORT` | 8025 | REST API port |
| `KISS_MAIL_API_BIND` | 0.0.0.0 | API bind address (binary default 127.0.0.1) |
| `KISS_MAIL_API_KEY` | (unset) | API key; unset or empty means the API is disabled |
| `KISS_MAIL_ENCRYPTION` | true | Encryption at rest |
| `CLAMAV_ADDRESS` / `CLAMAV_ENABLED` / `CLAMAV_REQUIRED` | 127.0.0.1:3310 / true / false | ClamAV daemon (see below) |
| `RUST_LOG` | kiss_mail=info | Log filter (plain `info` also enables dependency logs) |

The image declares `STOPSIGNAL SIGTERM`; `docker stop` triggers a graceful
shutdown. With Compose, `init: true` is set so a tiny init forwards the signal.

The container runs the server when started without arguments; any arguments
are passed to the `kiss-mail` CLI (e.g. `docker run --rm -v kiss-mail-data:/data ghcr.io/quinnjr/kiss-mail list`).

## Kubernetes

### Using Kustomize

```bash
# Deploy
kubectl apply -k deploy/kubernetes/

# Check status
kubectl get pods -n kiss-mail

# Port forward for local access
kubectl port-forward svc/kiss-mail 8080:8080 -n kiss-mail

# Admin password (generated on first start; must be changed at first login,
# e.g. in the web admin)
kubectl exec -n kiss-mail deploy/kiss-mail -- cat /data/initial-admin-password
```

Set `KISS_MAIL_TRUSTED_PROXIES` in `deploy/kubernetes/configmap.yaml` to your
ingress controller pod CIDR, and uncomment `KISS_MAIL_WEB_SECURE_COOKIE: "false"`
there if you reach the web admin over plain HTTP (the port-forward above, or
an Ingress without TLS).

The manifests run with a read-only root filesystem; all state is written to
the PersistentVolume mounted at `/data` (`KISS_MAIL_DATA_DIR=/data`). LDAP and
SSO are configured with the real variable names (`LDAP_*`, `GOOGLE_*`, `SSO_*`,
...) in `deploy/kubernetes/secret.yaml`.

### Using Helm

```bash
# Install
helm install kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  --create-namespace \
  --set domain=mail.example.com

# With ingress
helm install kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  --create-namespace \
  --set domain=mail.example.com \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=mail.example.com

# With external LoadBalancer
helm install kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  --create-namespace \
  --set externalService.enabled=true

# Upgrade
helm upgrade kiss-mail deploy/helm/kiss-mail --namespace kiss-mail

# Uninstall
helm uninstall kiss-mail --namespace kiss-mail
```

TLS values: `tls.mode` (`auto` or `off`), `tls.existingSecret` (a
`kubernetes.io/tls` Secret, for example from cert-manager; see
[DEPLOY.md](DEPLOY.md#ssltls)) and `tls.allowPlaintextAuth`
(`KISS_MAIL_ALLOW_PLAINTEXT_AUTH`, default false). The ConfigMap in
`deploy/kubernetes/` has the matching `KISS_MAIL_TLS*` and
`KISS_MAIL_ALLOW_PLAINTEXT_AUTH` entries.

The chart keeps the REST API off by default (`api.enabled: false`). If you
enable it, also set an API key and consider `networkPolicy.enabled=true` with
`networkPolicy.apiFrom` to limit who can reach port 8025. Generic OIDC SSO
requires `sso.authUrl`, `sso.tokenUrl` and `sso.userinfoUrl`; 1Password
requires `sso.userinfoUrl`, and Microsoft requires `sso.tenantId` (your own
tenant). Other chart values: `trustedProxies` (set it to the ingress controller
pod CIDR), `publicUrl` (`KISS_MAIL_PUBLIC_URL`; omitted when empty),
`webAdmin.secureCookie` (empty: `"true"` when `ingress.tls` is set, otherwise
`"false"`) and `sso.allowSubdomains` / `sso.autoBindAdmins`. The release notes
show how to read and change the bootstrap admin password.

## Cloud Deployment

All cloud deployments use **Docker containers** pulled from `ghcr.io/quinnjr/kiss-mail:latest`.

### One-Click Install (Any VPS)

SSH into your server and run:

```bash
curl -fsSL https://raw.githubusercontent.com/quinnjr/kiss-mail/main/deploy/scripts/install.sh | sudo bash
```

This installs Docker, pulls the container image, and starts KISS Mail
automatically. A high-entropy admin password is generated and set offline
(the container is stopped, `kiss-mail passwd admin --stdin` runs in a one-off
container on the same data, and the container is started again). It's saved, with the API
key, in the root-only `/opt/kiss-mail/credentials.txt` (written before the
container starts, then updated). `--password <pw>` is still accepted, but a
password given on the command line is visible in the process list.

Works on Ubuntu (24.04 LTS recommended), Debian, CentOS, Rocky Linux,
AlmaLinux, Amazon Linux and Fedora. On the RHEL family it enables the SELinux
boolean `httpd_can_network_connect` so Nginx can reach the container.

The installer, the generic cloud-init file and every Terraform provider share
the same provisioning code (`deploy/common/bootstrap.sh.tftpl`; run
`deploy/common/check-sync.sh` after editing it).

### Cloud Provider Comparison

All providers deploy the same Docker container:

| Provider | Cost | Deploy Command |
|----------|------|----------------|
| **Hetzner** | €3/mo | `cd deploy/hetzner && terraform apply` |
| **Vultr** | $5/mo | `cd deploy/vultr && terraform apply` |
| **Linode** | $5/mo | `cd deploy/linode && terraform apply` |
| **Digital Ocean** | $6/mo | `cd deploy/digitalocean && terraform apply` |
| **AWS** | $6-10/mo | `cd deploy/aws && terraform apply` |
| **GCP** | $5-10/mo | `cd deploy/gcp && terraform apply` |
| **Azure** | $10-15/mo | `cd deploy/azure && terraform apply` |
| **Any Cloud** | Variable | Use `deploy/generic/cloud-init.yml` |

### Quick Deploy (Terraform)

```bash
# Choose your provider
cd deploy/aws          # or gcp, azure, digitalocean, linode, vultr, hetzner

# Configure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars

# Deploy (pulls Docker container automatically)
terraform init
terraform apply
```

All providers boot Ubuntu 24.04 LTS. The admin password is **not** a Terraform
variable: it is generated on the VM, so it never ends up in Terraform state or
instance metadata. Read it with the `credentials_command` output (or
`sudo cat /opt/kiss-mail/credentials.txt` on the VM).

### Generic Cloud-Init

For any cloud provider (OVH, Scaleway, Oracle, UpCloud, etc.):

1. Copy `deploy/generic/cloud-init.yml`
2. Edit the config section with your domain
3. Create VM with Ubuntu 24.04 LTS and paste as user-data
4. Wait 2-5 minutes (installs Docker and pulls container)

### What Gets Deployed

All deployment methods create the same setup:
- Docker installed and configured
- KISS Mail container running with auto-restart
- Nginx reverse proxy for the web admin, `/account/`, `/static/` and the SSO
  callback (`/callback`). It overwrites `X-Real-IP` and `X-Forwarded-For`
  with the client address. The container publishes ports 8080/8025 on
  `127.0.0.1` only and runs with `KISS_MAIL_TRUSTED_PROXIES` set to loopback
  plus the Docker bridge subnet, and `KISS_MAIL_PUBLIC_URL=http://<public IP>`
- The REST API is **not** reachable through Nginx (`location /api` allows
  only 127.0.0.1). For the remote CLI, open an SSH tunnel:
  `ssh -L 8025:127.0.0.1:8025 user@server`, then
  `kiss-mail --server http://127.0.0.1:8025 --api-key <key> status`
- Firewall rules for mail ports
- Data persisted in `/opt/kiss-mail/data`
- Admin password and API key in `/opt/kiss-mail/credentials.txt` (root only);
  setup copies of the configuration are deleted when provisioning finishes

### DNS Configuration

After deploying, configure these DNS records:

```
A     mail.yourdomain.com         YOUR_SERVER_IP
MX    yourdomain.com       10     mail.yourdomain.com
TXT   yourdomain.com              "v=spf1 ip4:YOUR_SERVER_IP -all"
```

### Enable HTTPS

SSH into your server and run:

```bash
sudo certbot --nginx -d mail.yourdomain.com
```

The deploy scripts start the container with `KISS_MAIL_WEB_SECURE_COOKIE=false`
because Nginx serves the web admin over plain HTTP until certbot has run (the
server would otherwise mark the cookie `Secure`, since the web UI binds
`0.0.0.0` inside the container, and browsers would drop it over HTTP). Once
HTTPS works, recreate the container with `-e KISS_MAIL_WEB_SECURE_COOKIE=true`
and an https `KISS_MAIL_PUBLIC_URL`. The upgrade script can do that while
keeping everything else:

```bash
curl -fsSL https://raw.githubusercontent.com/quinnjr/kiss-mail/main/deploy/scripts/upgrade.sh \
  | sudo bash -s -- --no-pull --env KISS_MAIL_WEB_SECURE_COOKIE=true \
      --env KISS_MAIL_PUBLIC_URL=https://mail.yourdomain.com
```

`/opt/kiss-mail/credentials.txt` also suggests a `certbot --deploy-hook` that
does this once the certificate is issued.

### Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/quinnjr/kiss-mail/main/deploy/scripts/upgrade.sh | sudo bash
```

The upgrade script snapshots the data directory to
`<data-dir>.pre-upgrade-<timestamp>.tgz`, recreates the container with the
same ports, volumes, environment and hardening options, and rolls back to the
old container if the new one is not healthy within 90 s or the script is
interrupted. If the new container already ran, the data directory is
restored from the snapshot as well (the new version's data is kept in
`<data-dir>.failed-upgrade-<timestamp>`). Containers that don't set
`KISS_MAIL_WEB_SECURE_COOKIE` get `KISS_MAIL_WEB_SECURE_COOKIE=false` (with a
notice), and containers without `KISS_MAIL_TRUSTED_PROXIES` get the Docker
bridge range. Options: `--no-pull`, `--env KEY=VALUE` (repeatable),
`--no-backup`. Containers started by Docker Compose are refused; upgrade those
with `docker compose pull && docker compose up -d`. Read the upgrade notes in
[CHANGELOG.md](CHANGELOG.md) first: once mail has been stored encrypted, an
older version cannot read it.

### Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/quinnjr/kiss-mail/main/deploy/scripts/uninstall.sh | sudo bash

# Keep data
curl -fsSL ... | sudo bash -s -- --keep-data

# Non-interactive (confirmations are otherwise read from the terminal)
curl -fsSL ... | sudo bash -s -- --yes
```

The uninstaller only deletes a data directory that contains `users.json` or
lives under `/opt/kiss-mail`. It lists the upgrade snapshots next to it
(`<data-dir>.pre-upgrade-*.tgz`, `<data-dir>.failed-upgrade-*`) and removes
them in the same confirmation step. It warns if the container mounts a
different `/data` directory, and aborts (removing nothing) if the container
can't be stopped.

## Features

- ✅ SMTP server (send/receive)
- ✅ IMAP server (read emails)
- ✅ POP3 server (download emails)
- ✅ **Encryption at rest** for message bodies (X25519 + ChaCha20-Poly1305)
- ✅ **Web Admin Dashboard** (Tailwind CSS)
- ✅ Remote CLI & REST API
- ✅ SSO authentication (1Password, Google, Microsoft, Okta, Auth0)
- ✅ LDAP authentication (Active Directory, OpenLDAP)
- ✅ Groups / distribution lists
- ✅ Spam detection (naive Bayes classifier + rules)
- ✅ Anti-virus scanning (built-in + ClamAV)
- ✅ User management
- ✅ Zero configuration
- ✅ Single binary

## Email Encryption

KISS Mail encrypts stored message bodies **at rest** with per-user keys. This
protects the mail files on disk (backups, a stolen disk, other users on the
host); it is **not** end-to-end or zero-knowledge encryption.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                     User Creation                               │
│  Generate X25519 keypair                                        │
│  Password → Argon2 → key-encryption key                         │
│  Private key encrypted (wrapped) with that key → stored         │
│  Public key → stored (unencrypted)                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     Message Delivery                            │
│  1. Generate an ephemeral X25519 keypair (per message)          │
│  2. ECDH with the recipient's public key → symmetric key        │
│  3. Encrypt the message body with ChaCha20-Poly1305             │
│  4. Store: ephemeral public key + nonce + ciphertext            │
└─────────────────────────────────────────────────────────────────┘
```

### Security Properties and Limits

| Property | Description |
|----------|-------------|
| **Encrypted at rest** | Message bodies on disk are only readable with the recipient's private key |
| **Per-user keys** | X25519 key pair for each user |
| **Password-wrapped private key** | Private key encrypted with an Argon2-derived key from the user's password |
| **Per-message keys** | Ephemeral X25519 key per message |
| **Authenticated encryption** | ChaCha20-Poly1305 |
| **Not encrypted** | Headers, subject, sender and recipients stay in plaintext |
| **Server sees passwords** | Passwords arrive at login (encrypted in transit when the client uses TLS; in the clear if you enable plaintext logins), and the server holds a user's unlocked private key in memory while that user has an active session |

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_ENCRYPTION` | true | Enable/disable encryption |

### Startup Banner

```
Security:
  Anti-spam   ✓ Rules + AI (1234 patterns learned)
  Anti-virus  ✓ Built-in
  Encryption  ✓ X25519-ChaCha20-Poly1305 (5 keys)
```

### Key Management

- Keys are generated automatically when a user is created
- Private keys are encrypted with a key derived from the user's password
- A password change by the user re-encrypts the private key
- An admin password reset regenerates the user's keys: mail encrypted to the
  old key can no longer be decrypted
- Keys are stored in `keys.json` in the data directory

## AI Spam Detection

KISS Mail uses a hybrid spam detection system:

### How It Works

1. **Naive Bayes Classifier** - learning classifier that:
   - Learns from spam/ham patterns
   - Extracts about 15 feature types (URLs, capitalisation, urgency words, etc.)
   - Persists learned data to disk
   - Seeds with common spam patterns on first run

2. **Rule-based Scoring** - Traditional heuristics:
   - Rate limiting
   - Keyword detection
   - Header analysis
   - Suspicious URL patterns

3. **Combined Decision** - 60/40 weighted average of the classifier and rule
   scores, with overrides: a rule score of 5.0 or more, or a classifier spam
   probability above 0.9 with confidence above 0.8, decides on its own

### What You'll See

```
Security:
  Anti-spam   ✓ Rules + AI (847 patterns learned)
  Anti-virus  ✓ ClamAV 1.0.0
```

### Self-Learning

The classifier learns automatically from high-confidence verdicts (messages
that are clearly spam or clearly legitimate). Patterns are saved to
`spam_classifier.json` in the data directory.

## Groups / Distribution Lists

Create email groups to send messages to multiple users at once.

### Quick Start

```bash
# Create a group (auto-generates email: developers@yourdomain.com)
kiss-mail group-add developers

# Or specify a custom email
kiss-mail group-add team team-all@example.com

# Add members
kiss-mail group-add-member developers alice
kiss-mail group-add-member developers bob

# List groups
kiss-mail groups

# View group details
kiss-mail group-info developers
```

### How It Works

When an email is sent to a group address (e.g., `developers@yourdomain.com`), it's automatically expanded and delivered to all group members.

### Group Features

| Feature | Description |
|---------|-------------|
| **Distribution lists** | Emails to group go to all members |
| **Visibility levels** | Public, Internal, Private, Hidden |
| **Roles** | Owner, Manager, Member |
| **Settings** | External senders, moderation, reply-to |

Visibility levels, roles and settings are stored with each group, but only the
"allow external senders" setting is enforced at delivery time today; message
moderation is not implemented.

### CLI Commands

```bash
groups                           # List all groups
group-add <name> [email]         # Create group
group-del <name>                 # Delete group
group-info <name>                # Show details
group-add-member <group> <user>  # Add user
group-rm-member <group> <user>   # Remove user
```

Members must be existing accounts: adding an unknown username (CLI, web admin
or API, including `members` in `POST /api/groups`) fails with "user X does not
exist" (HTTP 400), and a group create with an unknown member creates nothing.
Deleting a user removes them from every group; groups they owned pass to the
`admin` account (if there is none, the owner is left as is and a warning is
logged). At startup the server warns about group members that do not exist.

A group address can't be the same as a local user's address. At `RCPT TO`, a
user address takes precedence over a group. If delivery to some members of a
group fails temporarily, only those members are retried; the message isn't
bounced for everyone.

`POST /api/groups` (REST API) takes a JSON body
`{"name": "...", "email": "...", "description": "...", "members": ["alice"]}`.
Only `name` is required; `email` defaults to `<name>@<domain>`, and every
member must be an existing user.

### Data Storage

Groups are persisted to `groups.json` in the data directory.

## LDAP Integration

Authenticate users against LDAP directories (Active Directory, OpenLDAP, etc.).

### Quick Setup

```bash
# Set LDAP server URL to enable
export LDAP_URL=ldap://ldap.example.com:389
export LDAP_BASE_DN=dc=example,dc=com

# Optional: Service account for user searches
export LDAP_BIND_DN=cn=admin,dc=example,dc=com
export LDAP_BIND_PASSWORD=secret

# Start server
kiss-mail
```

### Test LDAP Connection

```bash
# Test connection
kiss-mail ldap-test

# Test authentication
kiss-mail ldap-auth username password

# Search for user
kiss-mail ldap-search username
```

### Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `LDAP_URL` | LDAP server URL | (disabled) |
| `LDAP_BASE_DN` | Base DN for searches | `dc=example,dc=com` |
| `LDAP_BIND_DN` | Service account DN | (anonymous) |
| `LDAP_BIND_PASSWORD` | Service account password | (none) |
| `LDAP_USER_FILTER` | User search filter | `(&(objectClass=inetOrgPerson)(uid={username}))` |
| `LDAP_USER_DN_TEMPLATE` | User DN template for direct bind (e.g. `uid={username},ou=users,dc=example,dc=com`). When unset, users are found via `LDAP_USER_FILTER` and then bound; direct-bind failures also fall back to search-then-bind | (unset) |
| `LDAP_USE_TLS` | Use TLS (an `ldap://` URL is upgraded to `ldaps://`) | `false` |
| `LDAP_USE_STARTTLS` | Use StartTLS on an `ldap://` connection | `false` |
| `LDAP_FALLBACK_LOCAL` | Fall back to local auth | `true` |
| `LDAP_TIMEOUT` | Timeout in seconds for each LDAP operation (connect, bind, search) | `10` |

The username substituted into `LDAP_USER_DN_TEMPLATE` is escaped as an RDN
value (hex escapes, via ldap3's `dn_escape`), so special characters cannot
change the DN structure.

### Active Directory Example

```bash
export LDAP_URL=ldap://dc.example.com:389
export LDAP_BASE_DN=dc=example,dc=com
export LDAP_BIND_DN=cn=service,cn=users,dc=example,dc=com
export LDAP_BIND_PASSWORD=secret
export LDAP_USER_FILTER="(&(objectClass=user)(sAMAccountName={username}))"
export LDAP_USER_DN_TEMPLATE="{username}@example.com"
```

### How It Works

1. User attempts to login via IMAP/POP3
2. If LDAP is configured, authenticate against LDAP first
3. On success, auto-create local mailbox if needed
4. If LDAP fails and fallback is enabled, try local auth
5. Local mailboxes store emails, LDAP provides authentication

### Startup Banner

```
Directory:
  LDAP        ✓ ldap://ldap.example.com:389 (TLS)
```

## SSO Integration

Authenticate users via Single Sign-On providers using OAuth2/OIDC.

### Supported Providers

| Provider | Setup |
|----------|-------|
| **1Password** | `ONEPASSWORD_CLIENT_ID`, `ONEPASSWORD_CLIENT_SECRET`, `ONEPASSWORD_USERINFO_URL` (or `SSO_USERINFO_URL`) |
| **Google** | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| **Microsoft** | `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID` (required: your own tenant; `common`, `organizations` and `consumers` are refused) |
| **Okta** | `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`, `OKTA_DOMAIN` |
| **Auth0** | `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_DOMAIN` |
| **Generic OIDC** | `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`, `SSO_AUTH_URL`, `SSO_TOKEN_URL`, `SSO_USERINFO_URL` |

A provider missing any required endpoint (e.g. Okta/Auth0 without `*_DOMAIN`) is disabled with a warning.

| Variable | Default | Description |
|----------|---------|-------------|
| `SSO_REDIRECT_URI` | `http://localhost:8080/callback` | OAuth callback served by the web admin (`/callback`) |
| `SSO_ALLOWED_DOMAIN` | `KISS_MAIL_DOMAIN` | Comma-separated email domains allowed to sign in. Matching is **exact**: with only `KISS_MAIL_DOMAIN=mail.example.com`, both `user@example.com` and `user@sub.mail.example.com` are rejected; list `example.com` explicitly for the former |
| `SSO_ALLOW_SUBDOMAINS` | `false` | Also accept subdomains of an allowed domain (never parents) |
| `SSO_AUTO_BIND_ADMINS` | `false` | Let an admin account with no SSO link be bound by its first SSO login. Off by default: link admins with `kiss-mail sso-link` |

SSO sign-in is for the web admin: `/admin/sso/login` starts the flow, and only existing, active admin accounts are let in.

Requirements and rules:

- **SSO is disabled** unless `SSO_ALLOWED_DOMAIN` or `KISS_MAIL_DOMAIN` is set
  (a warning is logged).
- `email_verified=true` is required from every provider except Microsoft.
  For Microsoft, the provider is pinned to `MICROSOFT_TENANT_ID`, and a
  token's `tid` claim must equal that tenant when present.
- The local username is always the local part of the verified email address;
  a `preferred_username` without `@` is rejected.
- Bindings are keyed on (provider, `sub`); later logins must come from the
  same identity. A legacy binding (from before the provider was recorded) is
  re-bound, with a warning, when the provider changes.
- Admin accounts must be linked to an SSO identity before they can sign in
  with SSO (unless `SSO_AUTO_BIND_ADMINS=true`). These local CLI commands
  manage the links:

  ```bash
  # <provider> is the configured provider's display name, e.g. "Google" or "OIDC"
  kiss-mail sso-link admin Google 109876543210987654321
  kiss-mail sso-unbind admin       # remove the user's SSO binding
  kiss-mail purge-orphans          # drop SSO data, mailboxes and keys of deleted users
  ```

  Like other local commands, they edit the data directory directly, so stop
  or restart a running server around them.

### Quick Setup (Google Example)

```bash
export GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
export GOOGLE_CLIENT_SECRET=your-client-secret
kiss-mail
```

### App Passwords

Since email clients (Thunderbird, Outlook, etc.) don't support OAuth2, generate **app passwords**:

```bash
# Generate app password for a user
kiss-mail app-password alice "Thunderbird"
# Output (24 characters, mixed case and digits 2-9): aB3d-Ef7h-Jk9m-NpQr-St2v-WxYz

# List app passwords
kiss-mail app-passwords alice

# Revoke app password
kiss-mail app-pass-revoke alice <password-id>
```

Use the generated password in your mail client instead of your SSO password.

Only the 20 most recent non-expired app passwords of a user are checked at
login; revoke the ones you no longer use. App-password logins for accounts
that don't exist locally are refused, and an admin password reset revokes all
of the user's app passwords. The REST API answers 404 when creating an app
password for an unknown user, and when revoking an unknown id (500 if the
revocation couldn't be saved).

### CLI Commands

```bash
kiss-mail sso-status                    # Show SSO configuration
kiss-mail app-password <user> [label]   # Generate app password
kiss-mail app-passwords <user>          # List app passwords  
kiss-mail app-pass-revoke <user> <id>   # Revoke app password
```

### Startup Banner

```
Identity:
  LDAP        ✓ ldap://ldap.example.com:389
  SSO         ✓ Google + app passwords
```

## Web Admin Dashboard

A simple, beautiful web interface for managing your mail server.

### Access

```
http://localhost:8080/admin
```

Login with any admin user credentials.

### Change Your Password

```
http://localhost:8080/account/password
```

Any local user (not only admins) can change their own account password here:
enter the username, the current password and the new one twice. The page
needs no login, is protected against CSRF (double-submit cookie plus an
Origin/Referer check), and failed attempts count towards the same per-user,
per-IP lockout as logins. Wrong credentials get one generic "invalid username
or password" message. Users whose account is flagged "must change password"
are sent here from the admin login. The admin navigation has a "Change my
password" link. Deployments behind a proxy must route `/account/` (and
`/static/`) to the web admin (the bundled nginx, Kubernetes and Helm ingress
configs do). LDAP users can't change their password here: the directory
manages it. The new password must differ from the current one.

### Features

- **Dashboard** - Server overview, stats, quick actions
- **Users** - Create, edit, delete users; manage roles and status
- **Groups** - Create distribution lists, manage members

### Screenshots

The interface uses Tailwind CSS for a clean, modern design:

- Clean navigation with active state highlighting
- Responsive tables for users and groups
- Form validation and flash messages
- Session-based authentication

The stylesheet and script are built in and served from `/static/app.css` and
`/static/app.js` (no CDN). Every response carries a strict
`Content-Security-Policy` (same-origin styles and scripts only, no framing),
so a reverse proxy must also route `/static/` to the web admin.

- **Logout** is `POST /admin/logout` only (the navigation's logout button
  submits a form); a `GET` doesn't end the session.
- **Flash messages** after a redirect are selected with `?flash=<code>`, e.g.
  `/admin/users?flash=user_created`. Only known codes are shown:
  `user_created`, `user_updated`, `user_deleted`,
  `user_deleted_cleanup_failed`, `user_not_found`, `user_delete_denied`,
  `user_delete_failed`, `group_created`, `group_updated`, `group_deleted`,
  `group_not_found`, `group_delete_failed`, `member_added` and
  `member_removed`. Anything else shows nothing.
- A locked-out login gets HTTP 429.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_WEB_ENABLED` | true | Enable web admin |
| `KISS_MAIL_WEB_PORT` | 8080 | Web admin port |
| `KISS_MAIL_WEB_BIND` | 127.0.0.1 | Bind address |
| `KISS_MAIL_WEB_SECURE_COOKIE` | true unless `KISS_MAIL_WEB_BIND` is a loopback address | Mark the session cookie `Secure`. Set `false` only while the web admin is served over plain HTTP on a non-localhost address (the deploy scripts do this until certbot has run) |

### Startup Banner

```
Servers:
  SMTP  →  localhost:2525
  IMAP  →  localhost:1143
  POP3  →  localhost:1100
  Web   →  http://localhost:8080/admin
```

## Remote Administration

Manage the server remotely via CLI or REST API.

### Enable Remote API

Set an API key to enable remote access:

```bash
export KISS_MAIL_API_KEY=your-secret-key
kiss-mail
```

The API server starts on port 8025 by default:

```
Servers:
  SMTP  →  localhost:2525
  IMAP  →  localhost:1143
  POP3  →  localhost:1100
  API   →  localhost:8025
```

### Remote CLI Usage

```bash
# The API speaks plain HTTP: reach it through an SSH tunnel and give an
# explicit http:// URL on the loopback address
ssh -fN -L 8025:127.0.0.1:8025 user@mail.example.com
kiss-mail --server http://127.0.0.1:8025 --api-key your-secret-key list

# Short flags
kiss-mail -s http://localhost:8025 -k mykey status

# Using environment variables
export KISS_MAIL_SERVER=http://127.0.0.1:8025
export KISS_MAIL_API_KEY=your-secret-key
kiss-mail list
kiss-mail add bob password123
kiss-mail group-add developers
```

A server given without a scheme (`--server host:8025`) means `https://`, so
use an explicit `http://` URL for the API's own listener, or an `https://`
URL when HTTPS is terminated in front of it. Plain `http://` to a non-loopback host is
refused unless you pass `--insecure`, since the API key and passwords would
cross the network unencrypted. Passwords the CLI prompts for are read without
echo.

### Supported Remote Commands

| Command | Description |
|---------|-------------|
| `status` | Show server status |
| `list` | List all users |
| `add <user> <pass> [--role <role>]` | Create user (prints the role) |
| `del <user>` | Delete user |
| `info <user>` | Show user details |
| `passwd <user> <pass>` / `passwd <user> --stdin` | Change a password (`--stdin` keeps it out of argv). `--require-change` (flag the account "must change password") works only locally |
| `change-password <user> [--stdin]` | Change your own password with the current one; needs no API key |
| `groups` | List all groups |
| `group-add <name> [email]` | Create group |
| `group-del <name>` | Delete group |
| `group-info <name>` / `group-members <name>` | Show group details and members |
| `group-add-member <grp> <usr>` | Add user to group |
| `group-rm-member <grp> <usr>` | Remove user from group |
| `ldap-status` | Show LDAP configuration |
| `ldap-test` | Test LDAP connection |
| `sso-status` | Show SSO configuration |
| `app-password <user> [label]` | Generate an app password |
| `app-passwords <user>` | List app passwords |
| `app-pass-revoke <user> <id>` | Revoke an app password |

The CLI exits with status 1 on any error and prints errors to stderr.

Local-only commands (they edit the data directory, so restart a running
server afterwards):

| Command | Description |
|---------|-------------|
| `del <user>` | Also removes the mailbox and SSO data; exits with status 2 if that cleanup fails |
| `purge-orphans` | Remove SSO data, mailboxes and keys of users that no longer exist (also done at every startup) |
| `sso-link <user> <provider> <sub>` | Link an account to an SSO identity. `<provider>` is the configured provider's display name, e.g. `Google` or `OIDC` |
| `sso-unbind <user>` | Remove the account's SSO binding |

### REST API Endpoints

The admin API also provides REST endpoints for programmatic access:

```bash
# Authentication
POST /api/auth/login     # Login with admin credentials (429 while locked out)
POST /api/auth/logout    # Logout

# Self-service (no token or API key needed)
POST /api/account/password  # {"username","current_password","new_password"}

# Status
GET  /api/status         # Server status

# Users
GET  /api/users          # List users
POST /api/users          # Create user
GET  /api/users/{user}    # Get user
PUT  /api/users/{user}    # Update user
DELETE /api/users/{user}  # Delete user

# Groups
GET  /api/groups         # List groups
POST /api/groups         # Create group: {"name", "email"?, "description"?, "members"?}
GET  /api/groups/{name}   # Get group
DELETE /api/groups/{name} # Delete group
POST /api/groups/{name}/members           # Add member
DELETE /api/groups/{name}/members/{user}   # Remove member

# App Passwords
GET  /api/users/{user}/app-passwords      # List app passwords
POST /api/users/{user}/app-passwords      # Generate app password (404: unknown user)
DELETE /api/users/{user}/app-passwords/{id} # Revoke app password (404: unknown id, 500: could not be saved)

# LDAP
GET  /api/ldap/status    # LDAP status
POST /api/ldap/test      # Test LDAP connection

# SSO  
GET  /api/sso/status     # SSO status
```

### Example API Calls

```bash
# Get status
curl -H "Authorization: Bearer your-api-key" http://localhost:8025/api/status

# Create user
curl -X POST -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}' \
  http://localhost:8025/api/users

# List groups
curl -H "X-API-Key: your-api-key" http://localhost:8025/api/groups

# Change your own password (no API key; the current password is the credential)
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"alice","current_password":"old-secret","new_password":"new-secret-123"}' \
  http://localhost:8025/api/account/password
```

`POST /api/account/password` answers 200 on success, 401 with a generic
"Invalid username or password" for a wrong password or unknown user, 400 when
the new password violates the policy (at least 8 characters, different from
the current one), 403 for LDAP users (their password is managed by the
directory) and 429 while the user and client IP are locked out (or the
account is locked). It is throttled
per username and client IP like a login and works while a password change is
required. `POST /api/auth/login` answers 403 with
`"error": "password_change_required"` and a `hint` for such accounts.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_API_KEY` | (unset) | API key; enables the API when set to a non-empty value (empty = disabled) |
| `KISS_MAIL_API_PORT` | 8025 | API server port |
| `KISS_MAIL_API_BIND` | 127.0.0.1 | Bind address |
| `KISS_MAIL_API_ENABLED` | false | Enable API without key |

## ClamAV Integration

KISS Mail uses ClamAV when a clamd daemon is reachable and falls back to its
built-in scanner otherwise. ClamAV scanning is enabled by default
(`CLAMAV_ENABLED=true`, `CLAMAV_ADDRESS=127.0.0.1:3310`); the provided
docker-compose, Kubernetes and Helm configs set `CLAMAV_ENABLED=false` unless
you enable the ClamAV service.

### Install ClamAV (optional)

```bash
# Debian/Ubuntu
sudo apt install clamav-daemon
sudo systemctl start clamav-daemon

# macOS
brew install clamav
clamd

# The server will auto-detect ClamAV at 127.0.0.1:3310
```

### Configure ClamAV

| Variable | Default | Description |
|----------|---------|-------------|
| CLAMAV_ADDRESS | 127.0.0.1:3310 | ClamAV daemon address (`host:port`, or a Unix socket path such as `/var/run/clamav/clamd.sock`) |
| CLAMAV_ENABLED | true | Enable ClamAV scanning |
| CLAMAV_REQUIRED | false | Return SMTP 451 (temporary failure) when ClamAV is enabled but could not scan a message, instead of accepting it after the built-in scan only |

The `X-Virus` header added to delivered mail names the scanners that ran
(e.g. `builtin+clamav`, or `builtin only; ClamAV unavailable: ...`).

```bash
# Use custom ClamAV address
CLAMAV_ADDRESS=192.168.1.100:3310 kiss-mail

# Disable ClamAV (use built-in only)
CLAMAV_ENABLED=false kiss-mail
```

When ClamAV is available, you'll see:
```
Security:
  Anti-spam   ✓ Enabled
  Anti-virus  ✓ ClamAV 1.0.0/26789/...
```

When ClamAV is not available, the built-in scanner is used:
```
Security:
  Anti-spam   ✓ Enabled
  Anti-virus  ✓ Built-in (ClamAV not found)
```

## License

MIT
