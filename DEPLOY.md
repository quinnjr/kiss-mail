# KISS Mail Deployment Guide

This guide covers all deployment options for KISS Mail.

> **Recommended**: All deployments use **Docker containers** from `ghcr.io/quinnjr/kiss-mail:latest`

> **TLS in the mail protocols:** SMTP, IMAP and POP3 support implicit TLS
> (465/993/995) and STARTTLS natively, with a self-signed certificate until you
> install a real one (see [SSL/TLS](#ssltls)). Plaintext logins are refused by
> default. The scripts below put Nginx (with optional Certbot) in front of the
> web admin; the mail ports are served by kiss-mail itself.

### Admin account

On first start the server creates an `admin` superadmin with a high-entropy
random password, writes it to `$KISS_MAIL_DATA_DIR/initial-admin-password`
(mode 0600; `/data/initial-admin-password` in the container) and logs a line
containing "admin account" that says where the file is. That password must be
changed before the account can be used: every login with it (mail protocols,
web admin, API) is refused with "password change required" until it is
changed at `/account/password` (proxied by the bundled Nginx config),
`POST /api/account/password` or `kiss-mail change-password admin`. There is no
environment variable for the admin password. Set `KISS_MAIL_PUBLIC_URL` (for
example `https://mail.example.com`) so mail clients are told the full URL of
the password page.

The install script, the Terraform bootstrap script and the generic cloud-init
generate their own password on the server, wait (up to 90s) until the server
accepts SMTP connections (so `users.json` and the keys exist), stop the
container, set the password offline with a one-off container, delete the
bootstrap file, start the container again and record the password in the
root-only `/opt/kiss-mail/credentials.txt`. If that fails, the Terraform
bootstrap leaves `/opt/kiss-mail/.admin-password-pending` and retries on the
next boot.

**Never run `kiss-mail passwd` against a running server's data directory**
(for example with `docker exec`): the server keeps accounts in memory and
overwrites `users.json` with its own copy on the next change, so the new
password can be lost. To change the admin password, either use the online
paths (the web admin, or `PUT /api/users/admin` through an SSH tunnel to the
REST API), or set it offline:

```bash
docker stop kiss-mail
printf '%s' "$NEW_PASSWORD" | docker run --rm -i -v "$DATA_DIR":/data \
  ghcr.io/quinnjr/kiss-mail:latest passwd admin --stdin
docker start kiss-mail
```

(`$DATA_DIR` is the host directory or volume mounted at `/data`, e.g.
`/opt/kiss-mail/data` or `kiss-mail-data`.)

### Upgrade notes

Read these before upgrading an existing installation (see also
[CHANGELOG.md](CHANGELOG.md)):

- **Back up the data directory first.** `deploy/scripts/upgrade.sh` writes
  `<data-dir>.pre-upgrade-<timestamp>.tgz` automatically and restores it if
  the new container fails its health check.
- **No rollback to an earlier version once encrypted mail has arrived.**
  Older releases cannot read mail encrypted at rest; going back means
  restoring the pre-upgrade backup and losing mail received since.
- Installs created before the `UserManager` user store must first upgrade
  through the previous release (v0.1.0), then to this one.
- `KISS_MAIL_DATA` and `SMTP_PORT`/`IMAP_PORT`/`POP3_PORT` are deprecated
  aliases (they log a warning) and **will be removed in 0.3.0**; use
  `KISS_MAIL_DATA_DIR` and
  `KISS_MAIL_SMTP_PORT`/`KISS_MAIL_IMAP_PORT`/`KISS_MAIL_POP3_PORT`.
- **Plaintext logins are refused by default (breaking).** SMTP answers
  `538 5.7.11`, IMAP `NO [PRIVACYREQUIRED]` and POP3 `-ERR [AUTH]` until the
  client uses TLS. `upgrade.sh` adds `KISS_MAIL_ALLOW_PLAINTEXT_AUTH=true`
  (and prints how to remove it) when the old container has no
  `KISS_MAIL_TLS*` or `KISS_MAIL_ALLOW_PLAINTEXT_AUTH` setting, and publishes
  465/993/995 when those host ports are free (busy ones are skipped with a
  warning). Compose and Helm users must set
  `KISS_MAIL_ALLOW_PLAINTEXT_AUTH=true` (Helm `tls.allowPlaintextAuth`) or
  move their clients to TLS. Existing VMs also need `terraform apply` for the
  new firewall rules. Existing Certbot installs need the deploy hook, see
  [Existing installs](#existing-installs-before-the-tls-release).
- **Session cookie default.** The cookie is `Secure` unless the web admin
  binds a loopback address, and the container image binds `0.0.0.0`, so
  logins over plain HTTP stop working. Set `KISS_MAIL_WEB_SECURE_COOKIE=false`
  until HTTPS is enabled. `upgrade.sh` adds
  `KISS_MAIL_WEB_SECURE_COOKIE=false` (and prints a notice) when the old
  container doesn't set the variable. Helm sets `webAdmin.secureCookie` to
  `"true"` only when the Ingress has `tls`. For the plain Kubernetes
  manifests, uncomment `KISS_MAIL_WEB_SECURE_COOKIE` in the ConfigMap if you
  serve the web admin over HTTP.
- **Trusted proxies.** The client IP used for lockout and `allowed_ips` comes
  from `X-Real-IP` / `X-Forwarded-For` only when the TCP peer is in
  `KISS_MAIL_TRUSTED_PROXIES` (default `127.0.0.1/32,::1/128`). The deploy
  scripts add the Docker bridge range. `upgrade.sh` adds it when the variable
  is missing. Behind a Kubernetes Ingress, set it to the ingress controller
  pod CIDR (Helm `trustedProxies`).
- **SSO.**
  - `SSO_ALLOWED_DOMAIN` or `KISS_MAIL_DOMAIN` is required, and domains match
    exactly: `mail.example.com` doesn't accept `user@example.com` or
    `user@sub.mail.example.com` unless `SSO_ALLOW_SUBDOMAINS=true` (which
    accepts subdomains, never parents).
  - `email_verified=true` is now required from every provider except
    Microsoft.
  - Microsoft must be pinned to your tenant (`MICROSOFT_TENANT_ID`; `common`,
    `organizations` and `consumers` are refused), and a token's `tid` claim
    must match that tenant when it's present.
  - Admin accounts can no longer be bound by their first SSO login (unless
    `SSO_AUTO_BIND_ADMINS=true`). Link them explicitly with
    `kiss-mail sso-link <user> <provider> <sub>`.
  - Bindings are keyed on (provider, sub). A legacy binding is re-bound, with
    a warning, when the provider changes. If a legacy binding is wrong, clear
    it with `kiss-mail sso-unbind <user>` and link it again.
- **Locked accounts.** Accounts auto-locked by older versions are migrated
  back to Active on load. "Locked" is now set only by an administrator.
  Lockout after failed logins is per (user, client IP), with a per-source
  limit (20 failures per 10 minutes) and a per-username delay that never
  locks the account.
- **Accounts flagged "must change password"** (including a bootstrap `admin`
  whose password was never changed) can no longer log in until the password
  is changed. Their mail clients fail with SMTP `535`, IMAP `NO [EXPIRED]` or
  POP3 `-ERR [AUTH]`. Check a user with `kiss-mail info <user>`, and clear the
  flag by setting a new password (the web admin, `/account/password`, or
  `kiss-mail passwd` offline as shown above). A custom reverse proxy must
  route `/account/`, `/static/` and `/callback` to the web admin (port 8080).
- **Orphaned data.** At every startup (and with `kiss-mail purge-orphans`),
  the SSO bindings, mailboxes and keys of users that no longer exist are
  removed. A local `kiss-mail del` now removes the mailbox and SSO data too
  (exit status 2 if that cleanup fails); restart a running server afterwards.
- **Startup checks.** An invalid `KISS_MAIL_WEB_PORT` or `KISS_MAIL_API_PORT`
  now aborts startup.
- **Removed settings.** `LDAP_GROUP_BASE_DN` and `LDAP_GROUP_FILTER` no
  longer do anything. Remove them from your environment.
- **Logging.** The binary's default `RUST_LOG` is `kiss_mail=info`, and the
  image, compose file, deploy scripts and Helm chart now use it too. Plain
  `info` also turns on the logs of every dependency.
- Terraform: the `admin_password` variable is gone; remove it from
  `terraform.tfvars`. Azure (azurerm 4.x) needs `subscription_id` or
  `ARM_SUBSCRIPTION_ID`.

### REST API access

The deploy scripts publish the REST API (8025) on 127.0.0.1 only, and Nginx
denies `/api` to everything but 127.0.0.1. Use an SSH tunnel for the remote
CLI:

```bash
ssh -L 8025:127.0.0.1:8025 user@your-server
kiss-mail --server http://127.0.0.1:8025 --api-key "$KEY" status
```

Write the `http://` scheme explicitly: a server without a scheme means
`https://`, and the API itself speaks plain HTTP. Plain `http://` to a
non-loopback host is refused unless you pass `--insecure`.

## Deployment Options

| Method | Best For | Complexity | Cost |
|--------|----------|------------|------|
| [One-Click Script](#one-click-install) | Any VPS | ⭐ Easy | VPS cost |
| [Docker](#docker) | Local/Dev | ⭐ Easy | Free |
| [Docker Compose](#docker-compose) | Self-hosted | ⭐ Easy | VPS cost |
| [AWS Terraform](#aws) | Production | ⭐⭐ Medium | ~$10/mo |
| [GCP Terraform](#google-cloud-platform) | Production | ⭐⭐ Medium | ~$5-10/mo |
| [Azure Terraform](#microsoft-azure) | Production | ⭐⭐ Medium | ~$10-15/mo |
| [Digital Ocean Terraform](#digital-ocean) | Production | ⭐⭐ Medium | ~$6/mo |
| [Linode Terraform](#linode) | Production | ⭐⭐ Medium | ~$5/mo |
| [Vultr Terraform](#vultr) | Production | ⭐⭐ Medium | ~$5/mo |
| [Hetzner Terraform](#hetzner) | Production | ⭐⭐ Medium | ~€3/mo |
| [Generic Cloud-Init](#generic-any-cloud) | Any Cloud | ⭐ Easy | Variable |
| [Kubernetes](#kubernetes) | Enterprise | ⭐⭐⭐ Advanced | Variable |
| [Helm](#helm) | Enterprise | ⭐⭐⭐ Advanced | Variable |

---

## One-Click Install

The fastest way to deploy on any Linux server.

### Requirements
- Ubuntu 24.04 LTS (recommended) or 22.04, Debian 12+, RHEL/Rocky/AlmaLinux 9, Amazon Linux 2023, or Fedora
- Root access
- Open ports: 22, 25, 80, 110, 143, 443, 587

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/quinnjr/kiss-mail/main/deploy/scripts/install.sh | sudo bash
```

### Install with Options

```bash
curl -fsSL ... | sudo bash -s -- \
  --domain mail.example.com
```

### Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Mail domain (default: hostname) |
| `-p, --password` | Admin password (default: auto-generated; visible in the process list if given) |
| `--data-dir` | Data directory (default: /opt/kiss-mail/data) |
| `--no-nginx` | Skip Nginx installation |
| `--no-certbot` | Skip Certbot installation |
| `--secure-cookie` | Start with `KISS_MAIL_WEB_SECURE_COOKIE=true` (HTTPS already in place) |
| `--public-url` | `KISS_MAIL_PUBLIC_URL` (default: `http://<public IP>`, or `https://<domain>` with `--secure-cookie`) |

### Post-Install

1. View credentials (admin password, API key): `sudo cat /opt/kiss-mail/credentials.txt`
2. Access web admin: `http://YOUR_IP/admin`
3. Enable HTTPS: `sudo certbot --nginx -d mail.example.com`, then switch the
   session cookie to `Secure` and the public URL to https:
   `curl -fsSL .../upgrade.sh | sudo bash -s -- --no-pull --env KISS_MAIL_WEB_SECURE_COOKIE=true --env KISS_MAIL_PUBLIC_URL=https://mail.example.com`
   (`credentials.txt` also suggests a `certbot --deploy-hook` that does this
   once the certificate is issued).

The container is started with `KISS_MAIL_TRUSTED_PROXIES` set to loopback plus
the Docker bridge subnet (falling back to `172.16.0.0/12`), because Nginx
reaches it through the bridge. Nginx overwrites `X-Real-IP` and
`X-Forwarded-For` with the client address.

---

## Docker

### Quick Start

```bash
docker run -d \
  --name kiss-mail \
  -p 25:2525 -p 143:1143 -p 110:1100 \
  -p 465:4465 -p 993:1993 -p 995:1995 \
  -p 127.0.0.1:8080:8080 \
  -v kiss-mail-data:/data \
  -e KISS_MAIL_DOMAIN=mail.example.com \
  ghcr.io/quinnjr/kiss-mail:latest
```

The image's entrypoint is `kiss-mail`; with no arguments it runs the server.
It starts with a self-signed certificate and refuses plaintext logins; see
[SSL/TLS](#ssltls) to install a real certificate, or add
`-e KISS_MAIL_ALLOW_PLAINTEXT_AUTH=true` for clients that cannot use TLS yet.

### Build from Source

```bash
git clone https://github.com/quinnjr/kiss-mail.git
cd kiss-mail
docker build -t kiss-mail:latest .
```

### Environment Variables

"Image default" is what the container image sets; "binary default" applies
when running the binary directly.

| Variable | Image default | Binary default | Description |
|----------|---------------|----------------|-------------|
| `KISS_MAIL_DOMAIN` | localhost | hostname | Mail domain |
| `KISS_MAIL_DATA_DIR` (deprecated alias `KISS_MAIL_DATA`, removed in 0.3.0) | /data | ./mail_data | Data directory; `KISS_MAIL_DATA_DIR` wins if both are set. Must be writable |
| `KISS_MAIL_SMTP_PORT` (deprecated alias `SMTP_PORT`, removed in 0.3.0) | 2525 | 2525 (25 as root) | SMTP port |
| `KISS_MAIL_IMAP_PORT` (deprecated alias `IMAP_PORT`, removed in 0.3.0) | 1143 | 1143 (143 as root) | IMAP port |
| `KISS_MAIL_POP3_PORT` (deprecated alias `POP3_PORT`, removed in 0.3.0) | 1100 | 1100 (110 as root) | POP3 port |
| `KISS_MAIL_SMTPS_PORT` | 4465 | 4465 (465 as root) | Implicit TLS SMTP (submission, AUTH required) |
| `KISS_MAIL_IMAPS_PORT` | 1993 | 1993 (993 as root) | Implicit TLS IMAP |
| `KISS_MAIL_POP3S_PORT` | 1995 | 1995 (995 as root) | Implicit TLS POP3 |
| `KISS_MAIL_TLS` | - | auto | `auto` or `off` (also true/on/yes/1 and false/off/no/0). `off` disables TLS and allows plaintext logins |
| `KISS_MAIL_TLS_CERT` / `KISS_MAIL_TLS_KEY` | - | - | PEM certificate chain and key (both or neither) |
| `KISS_MAIL_ALLOW_PLAINTEXT_AUTH` | - | false | Allow logins on connections without TLS |
| `KISS_MAIL_WEB_ENABLED` | - | true | Web admin on/off |
| `KISS_MAIL_WEB_PORT` | 8080 | 8080 | Web admin port |
| `KISS_MAIL_WEB_BIND` | 0.0.0.0 | 127.0.0.1 | Web bind address |
| `KISS_MAIL_WEB_SECURE_COOKIE` | - | true unless the web bind is loopback | Mark the session cookie `Secure`. Set `false` while the web admin is served over plain HTTP |
| `KISS_MAIL_PUBLIC_URL` | - | - | Public base URL of the web interface (e.g. `https://mail.example.com`), used in "password change required" replies to mail clients |
| `KISS_MAIL_TRUSTED_PROXIES` | - | `127.0.0.1/32,::1/128` | Comma-separated CIDRs. When the TCP peer is trusted, the client IP comes from `X-Real-IP`, otherwise from the rightmost untrusted `X-Forwarded-For` entry. Used for lockout and `allowed_ips` |
| `KISS_MAIL_API_PORT` | 8025 | 8025 | API port |
| `KISS_MAIL_API_BIND` | 0.0.0.0 | 127.0.0.1 | API bind address |
| `KISS_MAIL_API_KEY` | - | - | API key; unset or empty = API disabled |
| `KISS_MAIL_API_ENABLED` | - | false | Enable the API without a key |
| `KISS_MAIL_ENCRYPTION` | - | true | Encryption at rest |
| `CLAMAV_ADDRESS` | - | 127.0.0.1:3310 | ClamAV daemon address |
| `CLAMAV_ENABLED` | - | true | Use ClamAV when reachable (built-in scanner otherwise) |
| `CLAMAV_REQUIRED` | - | false | Reject mail with a temporary `451` when ClamAV can't scan it. Only an exact `stream: OK` reply counts as clean |
| `LDAP_URL` | - | - | Setting it enables LDAP auth (see README for `LDAP_*`) |
| `LDAP_TIMEOUT` | - | 10 | LDAP connect/operation timeout in whole seconds (minimum 1) |
| `SSO_*` / `GOOGLE_*` / `MICROSOFT_*` / `OKTA_*` / `AUTH0_*` / `ONEPASSWORD_*` | - | - | SSO provider settings (see README). `MICROSOFT_TENANT_ID` must be your own tenant. `ONEPASSWORD_USERINFO_URL` is required for 1Password |
| `SSO_ALLOW_SUBDOMAINS` | - | false | Also accept subdomains of `SSO_ALLOWED_DOMAIN` (matching is exact by default) |
| `SSO_AUTO_BIND_ADMINS` | - | false | Let an unlinked admin account be bound by its first SSO login (otherwise use `kiss-mail sso-link`) |
| `RUST_LOG` | kiss_mail=info | kiss_mail=info | Log filter. Plain `info` also enables dependency logs |

Boolean settings accept `1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`
(any case).

---

## Docker Compose

`docker-compose.yml` is in the **repository root**. It requires **Docker
Compose v2.20 or newer** (it uses `depends_on.required: false` for the optional
ClamAV service).

### Basic Setup

```bash
# from the repository root
docker compose up -d
```

### With ClamAV Antivirus

```bash
CLAMAV_ENABLED=true docker compose --profile antivirus up -d
```

### Environment File

Create `.env` next to `docker-compose.yml`:

```env
KISS_MAIL_DOMAIN=mail.example.com
```

To enable the REST API, also uncomment the `KISS_MAIL_API_KEY` line in
`docker-compose.yml` and add `KISS_MAIL_API_KEY=<long random string>` to
`.env`. LDAP and SSO settings are listed (commented out) in the compose file
with their real names (`LDAP_*`, `GOOGLE_*`, `SSO_*`, ...); only uncomment the
ones you use, since setting `LDAP_URL` turns LDAP on.

### Commands

```bash
# Start
docker compose up -d

# Stop
docker compose down

# Logs
docker compose logs -f kiss-mail

# Restart
docker compose restart kiss-mail

# Update
docker compose pull && docker compose up -d
```

---

## AWS

Deploy on AWS with Terraform.

### Prerequisites

1. [Terraform](https://terraform.io) installed
2. [AWS CLI](https://aws.amazon.com/cli/) configured
3. AWS account with permissions

### Deploy

```bash
cd deploy/aws

# Configure
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars

# Deploy
terraform init
terraform apply
```

### Configuration

Edit `terraform.tfvars`:

```hcl
region         = "us-east-1"
instance_type  = "t3.micro"      # Free tier eligible
domain         = "mail.example.com"
ssh_key_name   = "your-key"      # Optional
volume_size    = 20
```

### What Gets Created

| Resource | Description | Cost |
|----------|-------------|------|
| VPC | Dedicated network | Free |
| EC2 | t3.micro instance | ~$8/mo (or free tier) |
| EIP | Static IP | Free (attached) |
| EBS | 20GB gp3 | ~$2/mo |
| Security Group | Firewall rules | Free |
| IAM Role | SSM access | Free |

### Access

```bash
# SSH (if key provided)
ssh -i ~/.ssh/key.pem ubuntu@<IP>   # Ubuntu 24.04 AMI

# SSM Session Manager (no key needed)
aws ssm start-session --target <instance-id>
```

### Cleanup

```bash
terraform destroy
```

---

## Digital Ocean

Deploy on Digital Ocean with Terraform.

### Prerequisites

1. [Terraform](https://terraform.io) installed
2. [Digital Ocean API token](https://cloud.digitalocean.com/account/api/tokens)

### Deploy

```bash
cd deploy/digitalocean

export DIGITALOCEAN_TOKEN="your-token"

terraform init
terraform apply -var="do_token=$DIGITALOCEAN_TOKEN"
```

### Configuration

Create `terraform.tfvars`:

```hcl
do_token       = "your-token"
region         = "nyc1"
droplet_size   = "s-1vcpu-1gb"   # $6/mo
domain         = "mail.example.com"
```

The admin password is generated on the droplet; read it with
`terraform output credentials_command`.

### Available Regions

| Region | Location |
|--------|----------|
| nyc1, nyc3 | New York |
| sfo3 | San Francisco |
| lon1 | London |
| ams3 | Amsterdam |
| sgp1 | Singapore |
| blr1 | Bangalore |
| fra1 | Frankfurt |
| tor1 | Toronto |
| syd1 | Sydney |

### What Gets Created

| Resource | Description | Cost |
|----------|-------------|------|
| Droplet | s-1vcpu-1gb | $6/mo |
| Reserved IP | Static IP | Free |
| Firewall | Port rules | Free |
| Project | Organization | Free |

### Access

```bash
ssh root@<reserved-ip>
```

### Cleanup

```bash
terraform destroy -var="do_token=$DIGITALOCEAN_TOKEN"
```

---

## Google Cloud Platform

Deploy on GCP Compute Engine (Ubuntu 24.04 LTS VM; the shared bootstrap script installs
Docker and Nginx and runs the container with the same port mapping as the
other providers).

### Deploy

```bash
cd deploy/gcp

# Set project
gcloud config set project YOUR_PROJECT_ID

# Enable APIs
gcloud services enable compute.googleapis.com

# Deploy
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

### Cost

| Resource | Cost |
|----------|------|
| e2-micro | Free tier eligible |
| Static IP | ~$3/month |

---

## Microsoft Azure

Deploy on Azure Virtual Machines.

### Deploy

```bash
cd deploy/azure

# Login
az login

# Deploy
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

### Cost

| Size | Cost |
|------|------|
| Standard_B1s | ~$8/month |
| Standard_B1ms | ~$15/month |

---

## Linode

Deploy on Linode (Akamai).

### Deploy

```bash
cd deploy/linode
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

### Cost

| Type | Cost |
|------|------|
| g6-nanode-1 (1GB) | $5/month |
| g6-standard-1 (2GB) | $10/month |

---

## Vultr

Deploy on Vultr.

### Deploy

```bash
cd deploy/vultr
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

### Cost

| Plan | Cost |
|------|------|
| vc2-1c-1gb | $5/month |
| vc2-1c-2gb | $10/month |

---

## Hetzner

Deploy on Hetzner Cloud (EU-based, very affordable).

### Deploy

```bash
cd deploy/hetzner
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

### Cost

| Type | Spec |
|------|------|
| cx22 (default) | 2 vCPU, 4GB |
| cx32 | 4 vCPU, 8GB |

See [Hetzner pricing](https://www.hetzner.com/cloud/) for current prices.

---

## Generic (Any Cloud)

Use the universal cloud-init configuration on **any** cloud provider.

### Supported Providers

- AWS, GCP, Azure, Digital Ocean, Linode, Vultr, Hetzner
- OVH, Scaleway, Oracle Cloud, UpCloud, and more
- Any VPS provider with cloud-init support

### Deploy

1. Copy `deploy/generic/cloud-init.yml`
2. Customize the config section:

```yaml
write_files:
  - path: /etc/kiss-mail.conf
    content: |
      DOMAIN=mail.yourdomain.com
      KISS_MAIL_API_KEY=             # empty = generated on the VM
```

The file is parsed as `KEY=VALUE` lines (never sourced). The admin password
is always generated on the VM and kept in `/opt/kiss-mail/credentials.txt`;
`/etc/kiss-mail.conf` and `/opt/kiss-mail-setup.sh` are deleted when setup
finishes.

3. Create VM with Ubuntu 24.04 LTS and paste as user-data
4. Wait 2-5 minutes for setup

### Manual (No Cloud-Init)

```bash
curl -fsSL https://raw.githubusercontent.com/quinnjr/kiss-mail/main/deploy/scripts/install.sh | sudo bash
```

---

## Kubernetes

Deploy on any Kubernetes cluster.

### Using Kustomize

```bash
# Deploy
kubectl apply -k deploy/kubernetes/

# Verify
kubectl get pods -n kiss-mail
kubectl get svc -n kiss-mail

# Port forward
kubectl port-forward svc/kiss-mail 8080:8080 -n kiss-mail
```

### Customize

Edit `deploy/kubernetes/kustomization.yaml`:

```yaml
# Change image
images:
  - name: ghcr.io/quinnjr/kiss-mail
    newName: your-registry/kiss-mail
    newTag: v1.0.0
```

Edit `deploy/kubernetes/configmap.yaml` for configuration and
`deploy/kubernetes/secret.yaml` for secrets / LDAP / SSO (real variable names:
`KISS_MAIL_API_KEY`, `LDAP_*`, `GOOGLE_*`, `SSO_*`, ...). Do not add keys with
empty values: an empty `LDAP_URL` still turns LDAP on.

The pod runs with a read-only root filesystem; state lives on the PVC mounted
at `/data` (`KISS_MAIL_DATA_DIR=/data`).

Admin password: `kubectl exec -n kiss-mail deploy/kiss-mail -- cat /data/initial-admin-password`
(the log line containing "admin account" names the file). It must be changed
at first login: log in to the web admin and set a new one. Or run
`kiss-mail passwd admin --stdin` through `kubectl exec -i`, then
`kubectl rollout restart deploy/kiss-mail -n kiss-mail` right away so the
server reloads `users.json`.

The ConfigMap sets these (adjust as needed):

- `KISS_MAIL_TRUSTED_PROXIES`: set it to your ingress controller pod CIDR, or
  every web/API client shares the ingress pod's IP for lockout.
- `KISS_MAIL_WEB_SECURE_COOKIE` (commented out): uncomment it with `"false"`
  if the web admin is reached over plain HTTP (port-forward, an Ingress
  without TLS).
- `KISS_MAIL_PUBLIC_URL` (commented out).

The Ingress routes `/admin`, `/account`, `/static`, `/callback` (Exact) and
`/` to the web port, and `/api` to the API port.

---

## Helm

Deploy with Helm for more flexibility.

### Install

```bash
helm install kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  --create-namespace \
  --set domain=mail.example.com
```

### With Custom Values

Create `values-prod.yaml`:

```yaml
domain: mail.example.com

image:
  repository: your-registry/kiss-mail
  tag: v1.0.0

persistence:
  size: 50Gi
  storageClass: fast-ssd

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: mail.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: kiss-mail-tls
      hosts:
        - mail.example.com

resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 1Gi
```

Install with values:

```bash
helm install kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  --create-namespace \
  -f values-prod.yaml
```

### Web admin, proxies and public URL

```yaml
publicUrl: https://mail.example.com   # KISS_MAIL_PUBLIC_URL (empty: omitted)
trustedProxies: "127.0.0.1/32,::1/128,10.244.0.0/16"  # add the ingress controller pod CIDR
webAdmin:
  secureCookie: ""   # empty: "true" when ingress.tls is set, otherwise "false"
logging:
  level: kiss_mail=info   # plain "info" also enables dependency logs
```

### LDAP / SSO

```yaml
ldap:
  enabled: true            # only then is LDAP_URL emitted
  url: ldap://ldap.example.com:389
  baseDn: dc=example,dc=com
  userFilter: "(uid={username})"

sso:
  enabled: true
  provider: google         # -> GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
  clientId: 1234-abc.apps.googleusercontent.com
  # microsoft: tenantId is required (common/organizations/consumers refused)
  # onepassword: userinfoUrl is required (-> ONEPASSWORD_USERINFO_URL)
  allowSubdomains: false   # SSO_ALLOW_SUBDOMAINS
  autoBindAdmins: false    # SSO_AUTO_BIND_ADMINS

secrets:
  create: true             # or existingSecret: my-secret
  ldapPassword: ...
  ssoClientSecret: ...
```

### Upgrade

```bash
helm upgrade kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  -f values-prod.yaml
```

### Uninstall

```bash
helm uninstall kiss-mail --namespace kiss-mail
```

---

## DNS Configuration

After deployment, configure these DNS records:

| Type | Name | Value | Priority |
|------|------|-------|----------|
| A | mail.example.com | YOUR_IP | - |
| MX | example.com | mail.example.com | 10 |
| TXT | example.com | "v=spf1 ip4:YOUR_IP -all" | - |

### Optional: DKIM

Generate DKIM keys and add:

| Type | Name | Value |
|------|------|-------|
| TXT | mail._domainkey.example.com | "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY" |

### Optional: DMARC

| Type | Name | Value |
|------|------|-------|
| TXT | _dmarc.example.com | "v=DMARC1; p=quarantine; rua=mailto:admin@example.com" |

---

## SSL/TLS

kiss-mail terminates TLS itself for the mail protocols: implicit TLS on
465/993/995 (4465/1993/1995 inside the container) and `STARTTLS`/`STLS` on
25/587, 143 and 110. Nginx and Certbot only cover the web admin's HTTPS.

### Client settings

| | Implicit TLS (recommended) | STARTTLS |
|---|---|---|
| IMAP | 993, SSL/TLS | 143 |
| SMTP (submission) | 465, SSL/TLS | 587 |
| POP3 | 995, SSL/TLS | 110 (`STLS`) |

Port 465 is submission only (`MAIL` requires `AUTH`). STARTTLS can be stripped
by an attacker on the network path, so prefer implicit TLS or require TLS in
the client. Stripping on port 25 (server to server) is accepted: MTA-STS and
DANE are out of scope.

### Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_TLS` | auto | `auto` or `off` (aliases: true/on/yes/1 = auto, false/off/no/0 = off) |
| `KISS_MAIL_TLS_CERT` / `KISS_MAIL_TLS_KEY` | - | Certificate chain and key in PEM |
| `KISS_MAIL_SMTPS_PORT` / `KISS_MAIL_IMAPS_PORT` / `KISS_MAIL_POP3S_PORT` | 4465 / 1993 / 1995 (465 / 993 / 995 as root) | Implicit TLS ports |
| `KISS_MAIL_ALLOW_PLAINTEXT_AUTH` | false | Allow logins without TLS |

Plaintext logins are refused by default: SMTP `538 5.7.11`, IMAP
`NO [PRIVACYREQUIRED]` (with `LOGINDISABLED` advertised), POP3 `-ERR [AUTH]`.
`KISS_MAIL_TLS=off` turns TLS off and **also allows plaintext logins**; the
server logs a startup warning and adds a banner line.

Certificate source, first match wins:

1. `KISS_MAIL_TLS_CERT` + `KISS_MAIL_TLS_KEY`
2. `$DATA_DIR/tls/cert.pem` + `key.pem`
3. a self-signed certificate: 397 days, regenerated within 30 days of expiry,
   names = `KISS_MAIL_DOMAIN` and `localhost`, same fingerprint across
   restarts while the data directory persists

Reload: the files are checked every 60 seconds (by content hash) and on
`SIGHUP` immediately (`docker kill --signal=HUP kiss-mail`). Existing sessions
keep their old certificate; new connections get the new one. The server
switches from self-signed to `$DATA_DIR/tls/` as soon as the files appear.

An **expired, unparseable or mismatched configured certificate aborts
startup**, naming the file and suggesting `certbot renew`. Renew or fix the
file, then start the container again. A certificate expiring within 14 days is
logged as a warning (at most once a day).

Limits:

- Self-signed: clients warn, and Outlook and Gmail refuse self-signed
  certificates. Install a real one for those clients.
- TLS 1.2 and 1.3 only: very old clients that only offer CBC or RSA key
  exchange cannot connect.

### With Certbot (Let's Encrypt) on a VM

The VM bootstrap (Terraform, cloud-init) installs the deploy hook
`/etc/letsencrypt/renewal-hooks/deploy/kiss-mail.sh`. After a successful
issuance or renewal it copies the new key and chain into `$DATA_DIR/tls/`
(mode 0600, owned by uid 1000) and sends `SIGHUP` to the container. It only
acts for certificates whose names include `$DOMAIN`. Once DNS points at the
server, run:

```bash
sudo certbot --nginx --redirect -d mail.example.com \
  --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/kiss-mail.sh
```

The explicit `--deploy-hook` is needed because certbot only runs the hooks in
the `renewal-hooks` directory on renewal, not on first issuance (the flag also
saves the hook for later renewals). The same certificate then serves the web
admin and the mail ports. Then mark the session cookie `Secure` and switch the
public URL to https:

```bash
curl -fsSL .../upgrade.sh | sudo bash -s -- --no-pull \
  --env KISS_MAIL_WEB_SECURE_COOKIE=true --env KISS_MAIL_PUBLIC_URL=https://mail.example.com
```

#### Existing installs (before the TLS release)

Servers set up earlier do not have the hook. Install it (it is generated by
`install_tls_hook` in `deploy/common/bootstrap.sh.tftpl`; set `DOMAIN` and
`DATA_DIR` to your values, for example `/opt/kiss-mail/data`):

```bash
sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy
sudo tee /etc/letsencrypt/renewal-hooks/deploy/kiss-mail.sh >/dev/null <<'EOF'
#!/bin/bash
DOMAIN=mail.example.com
DATA_DIR=/opt/kiss-mail/data
set -eo pipefail
TLS_DIR="$DATA_DIR/tls"
if [[ -z "$RENEWED_LINEAGE" ]]; then
    echo "kiss-mail deploy hook: RENEWED_LINEAGE is not set (this hook is run by certbot)" >&2
    exit 1
fi
case " $RENEWED_DOMAINS " in
    *" $DOMAIN "*) ;;
    *) exit 0 ;;
esac
install -d -m 0700 -o 1000 -g 1000 "$TLS_DIR"
install -m 0600 -o 1000 -g 1000 "$RENEWED_LINEAGE/privkey.pem" "$TLS_DIR/key.pem.new"
mv -f "$TLS_DIR/key.pem.new" "$TLS_DIR/key.pem"
install -m 0600 -o 1000 -g 1000 "$RENEWED_LINEAGE/fullchain.pem" "$TLS_DIR/cert.pem.new"
mv -f "$TLS_DIR/cert.pem.new" "$TLS_DIR/cert.pem"
docker kill --signal=HUP kiss-mail >/dev/null || true
echo "kiss-mail deploy hook: installed the certificate for $DOMAIN in $TLS_DIR"
EOF
sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/kiss-mail.sh
```

Then attach it to the existing certificate and run it once:

```bash
sudo certbot reconfigure --cert-name mail.example.com \
  --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/kiss-mail.sh
sudo RENEWED_LINEAGE=/etc/letsencrypt/live/mail.example.com \
  RENEWED_DOMAINS=mail.example.com \
  /etc/letsencrypt/renewal-hooks/deploy/kiss-mail.sh
```

(Alternatively reissue with the `certbot --nginx ... --deploy-hook` command
above.) Also run `upgrade.sh` (it publishes 465/993/995 when they are free and
keeps plaintext logins working with `KISS_MAIL_ALLOW_PLAINTEXT_AUTH=true`
until you remove it) and `terraform apply` for the new firewall rules.

### Docker Compose or `docker run`

Mount the files and point the server at them, or drop `cert.pem` and
`key.pem` into `$DATA_DIR/tls/` (readable by uid 1000):

```yaml
    volumes:
      - ./certs:/certs:ro
    environment:
      KISS_MAIL_TLS_CERT: /certs/fullchain.pem
      KISS_MAIL_TLS_KEY: /certs/privkey.pem
```

After renewing, run `docker kill --signal=HUP kiss-mail` (or wait up to 60
seconds).

### Kubernetes and Helm (cert-manager)

Create a `kubernetes.io/tls` Secret, for example with a cert-manager
`Certificate` for the mail host, and point the chart at it:

```yaml
tls:
  mode: auto
  existingSecret: mail-example-com-tls   # kubernetes.io/tls Secret
  allowPlaintextAuth: false
```

The Secret is mounted at `/etc/kiss-mail/tls` as a whole directory (no
`subPath`, so renewals reach the pod) and `KISS_MAIL_TLS_CERT`/`_KEY` point at
`tls.crt`/`tls.key`. Secret updates propagate to the pod within a couple of
minutes and the server reloads the files. Without `existingSecret` the server
uses `/data/tls/*` if present, else a self-signed certificate. With
`persistence.enabled: false` the self-signed fingerprint changes on every pod
restart. The plain manifests in `deploy/kubernetes/` use the same variables in
the ConfigMap.

### Firewalls

Ports published by Docker bypass ufw and firewalld; the cloud firewall
(Terraform security groups) controls what is reachable. Open 465, 993 and 995
(and 587, 143, 110, 25 for STARTTLS/plain). Existing VMs need
`terraform apply` for the new rules plus `upgrade.sh` for the port bindings.

### With Custom Certificate

Use `KISS_MAIL_TLS_CERT`/`KISS_MAIL_TLS_KEY` or `$DATA_DIR/tls/cert.pem` +
`key.pem` for the mail ports. For the web admin, place the certificate for
Nginx in `/etc/ssl/kiss-mail/` and update the Nginx configuration.

---

## Maintenance

### Upgrade

```bash
# Script
curl -fsSL .../upgrade.sh | sudo bash

# The script snapshots the data dir to <data-dir>.pre-upgrade-<timestamp>.tgz,
# keeps env/volumes/ports/hardening options and rolls back if the new
# container is unhealthy or the script is interrupted. If the new container
# already ran, the snapshot is restored too (its data is kept in
# <data-dir>.failed-upgrade-<timestamp>). Containers without
# KISS_MAIL_WEB_SECURE_COOKIE get KISS_MAIL_WEB_SECURE_COOKIE=false, and
# containers without KISS_MAIL_TRUSTED_PROXIES get the Docker bridge range.
# It refuses containers managed by Docker Compose: use
# `docker compose pull && docker compose up -d`.
# Options: --no-pull, --env KEY=VALUE, --no-backup

# Docker (manual)
docker pull ghcr.io/quinnjr/kiss-mail:latest
docker stop kiss-mail && docker rm kiss-mail
docker run ... ghcr.io/quinnjr/kiss-mail:latest

# Helm
helm upgrade kiss-mail deploy/helm/kiss-mail ...
```

### Backup

```bash
# Data directory
tar -czvf kiss-mail-backup.tar.gz /opt/kiss-mail/data

# Docker volume
docker run --rm -v kiss-mail-data:/data -v $(pwd):/backup \
  alpine tar czvf /backup/kiss-mail-backup.tar.gz /data
```

### Logs

```bash
# Docker
docker logs kiss-mail

# Systemd (if installed as service)
journalctl -u kiss-mail

# Kubernetes
kubectl logs -f deployment/kiss-mail -n kiss-mail
```

---

## Troubleshooting

### Container won't start

```bash
# Check logs
docker logs kiss-mail

# Check ports
netstat -tlnp | grep -E '25|143|110|8080'
```

### Can't receive email

1. Check MX records: `dig MX example.com`
2. Check port 25 is open: `nc -vz YOUR_IP 25`
3. Check firewall rules
4. Check ISP isn't blocking port 25

### Web admin not accessible

```bash
# Check Nginx
nginx -t
systemctl status nginx

# Check container health
docker inspect kiss-mail --format '{{.State.Health.Status}}'
```

### SSL certificate issues

```bash
# Renew certificate (the deploy hook reloads kiss-mail)
certbot renew

# Mail ports
openssl s_client -connect mail.example.com:993
openssl s_client -starttls smtp -connect mail.example.com:587

# Check certificate
openssl s_client -connect mail.example.com:443
```
