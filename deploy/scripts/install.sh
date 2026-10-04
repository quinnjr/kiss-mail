#!/bin/bash
# ============================================================================
# KISS Mail - One-Click Install Script
# ============================================================================
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/quinnjr/kiss-mail/main/deploy/scripts/install.sh | sudo bash
#
# Or with options:
#   curl -fsSL ... | sudo bash -s -- --domain mail.example.com
#
# The admin password is generated here and saved (root-only) in
# /opt/kiss-mail/credentials.txt; it is passed to the server on stdin.
# ============================================================================
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Defaults
DOMAIN="${KISS_MAIL_DOMAIN:-$(hostname -f)}"
ADMIN_PASSWORD=""
API_KEY=""
DATA_DIR="/opt/kiss-mail/data"
CONFIG_DIR="/opt/kiss-mail"
IMAGE="ghcr.io/quinnjr/kiss-mail:latest"
INSTALL_NGINX=true
INSTALL_CERTBOT=true
# Nginx serves the web admin over plain HTTP until certbot is run, so the
# session cookie is not marked Secure by default. Pass --secure-cookie when
# HTTPS is already terminated in front of the web admin.
SECURE_COOKIE=false
# Base URL of the web interface, used in "password change required" replies.
# Empty: http://<public IP> (https://<domain> with --secure-cookie).
PUBLIC_URL=""

usage() {
    echo "KISS Mail Installer"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN    Mail domain (default: hostname)"
    echo "  -p, --password PASS    Admin password (default: auto-generated; a password"
    echo "                         given here is visible in the process list)"
    echo "  --data-dir DIR         Data directory (default: /opt/kiss-mail/data)"
    echo "  --no-nginx             Skip Nginx installation"
    echo "  --no-certbot           Skip Certbot installation"
    echo "  --secure-cookie        Mark the web session cookie Secure (HTTPS already in place)"
    echo "  --public-url URL       Public base URL of the web interface (KISS_MAIL_PUBLIC_URL)"
    echo "  -h, --help             Show this help"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -p|--password)
            ADMIN_PASSWORD="$2"
            shift 2
            ;;
        --data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        --no-nginx)
            INSTALL_NGINX=false
            shift
            ;;
        --no-certbot)
            INSTALL_CERTBOT=false
            shift
            ;;
        --secure-cookie)
            SECURE_COOKIE=true
            shift
            ;;
        --public-url)
            [[ $# -ge 2 ]] || { echo "--public-url requires a value"; exit 1; }
            PUBLIC_URL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# ----------------------------------------------------------------------------
# Functions
# ----------------------------------------------------------------------------
log() {
    echo -e "${GREEN}[KISS Mail]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

public_ip() {
    curl -s --max-time 10 ifconfig.me || curl -s --max-time 10 icanhazip.com
}

banner() {
    echo -e "${BLUE}"
    echo "  ╦╔═╦╔══╗  ╔╦╗╔═╗╦╦  "
    echo "  ╠╩╗║╚═╗╚═╗║║║╠═╣║║  "
    echo "  ╩ ╩╩╚═╝╚═╝╩ ╩╩ ╩╩╩═╝"
    echo -e "${NC}"
    echo "  Simple Email Server Installer"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

# >>> kiss-mail common >>>
# Shared provisioning functions. This block is kept byte-identical in
# deploy/common/bootstrap.sh.tftpl, deploy/scripts/install.sh and
# deploy/generic/cloud-init.yml (verified by deploy/common/check-sync.sh).
# It must not contain dollar-brace or percent-brace sequences, because the
# Terraform template would interpolate them.
#
# The caller defines log, warn, error and public_ip, and sets DOMAIN, IMAGE,
# CONFIG_DIR, DATA_DIR, API_KEY, ADMIN_PASSWORD, SECURE_COOKIE and PUBLIC_URL
# (empty: derived from the public IP, or https://DOMAIN with a Secure cookie).
# After finish_admin_password, ADMIN_PASSWORD_RC holds the set_admin_password
# result (0 and 3 mean the password was set).

KM_REPO_URL="https://github.com/quinnjr/kiss-mail"
KM_TMPDIR=""

apt_get() {
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 "$@"
}

# /etc/os-release is sourced in subshells, only to read ID/VERSION_*.
# shellcheck disable=SC1091
detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect OS (no /etc/os-release)"
    fi
    OS=$(set +u; . /etc/os-release; echo "$ID")
    OS_VERSION=$(set +u; . /etc/os-release; echo "$VERSION_ID")
    OS_CODENAME=$(set +u; . /etc/os-release; echo "$VERSION_CODENAME")
    log "Detected OS: $OS $OS_VERSION"
}

pkg_install() {
    case "$OS" in
        ubuntu|debian) apt_get install -y "$@" ;;
        centos|rhel|rocky|almalinux|fedora|amzn) dnf install -y "$@" ;;
        *) error "Unsupported OS: $OS" ;;
    esac
}

validate_domain() {
    if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]]; then
        error "Invalid domain '$DOMAIN' (allowed: letters, digits, '.' and '-')"
    fi
}

install_base_packages() {
    log "Installing base packages..."
    case "$OS" in
        ubuntu|debian)
            apt_get update
            pkg_install ca-certificates curl gnupg openssl
            ;;
        *)
            pkg_install ca-certificates openssl
            # Amazon Linux ships curl-minimal, which conflicts with curl
            command -v curl >/dev/null 2>&1 || pkg_install curl
            ;;
    esac
}

install_docker() {
    if command -v docker >/dev/null 2>&1; then
        log "Docker already installed"
    else
        log "Installing Docker..."
        case "$OS" in
            ubuntu|debian)
                install -m 0755 -d /etc/apt/keyrings
                curl -fsSL "https://download.docker.com/linux/$OS/gpg" | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
                chmod a+r /etc/apt/keyrings/docker.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS $OS_CODENAME stable" > /etc/apt/sources.list.d/docker.list
                apt_get update
                pkg_install docker-ce docker-ce-cli containerd.io
                ;;
            centos|rhel|rocky|almalinux|fedora)
                local repo_url="https://download.docker.com/linux/centos/docker-ce.repo"
                if [[ "$OS" == "fedora" ]]; then
                    repo_url="https://download.docker.com/linux/fedora/docker-ce.repo"
                fi
                pkg_install dnf-plugins-core
                # dnf4 uses --add-repo; dnf5 (Fedora 41+) uses "addrepo --from-repofile="
                dnf config-manager --add-repo "$repo_url" 2>/dev/null \
                    || dnf config-manager addrepo --from-repofile="$repo_url"
                pkg_install docker-ce docker-ce-cli containerd.io
                ;;
            amzn)
                pkg_install docker
                ;;
            *)
                error "Unsupported OS: $OS"
                ;;
        esac
    fi
    systemctl enable --now docker
}

install_nginx() {
    if command -v nginx >/dev/null 2>&1; then
        log "Nginx already installed"
    else
        log "Installing Nginx..."
        pkg_install nginx
    fi
}

# The web admin (8080) and REST API (8025) are published on 127.0.0.1 only.
# Nginx proxies the web admin, the self-service password page (/account/),
# the web UI assets (/static/) and the SSO callback on port 80. The REST API is
# NOT exposed through Nginx (loopback clients only); for remote CLI use, open
# an SSH tunnel: ssh -L 8025:127.0.0.1:8025 <server>, then use
# kiss-mail --server http://127.0.0.1:8025 --api-key <key> <command>.
# X-Real-IP and X-Forwarded-For are overwritten with the TCP peer (never
# appended to), so a client cannot inject an address; kiss-mail trusts them
# because Nginx reaches it from a KISS_MAIL_TRUSTED_PROXIES range.
configure_nginx() {
    log "Configuring Nginx..."
    cat > /etc/nginx/conf.d/kiss-mail.conf << 'NGINX'
server {
    listen 80;
    server_name _;

    # Web Admin
    location /admin {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Self-service password change (any mail user), served by the web admin
    location /account/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Stylesheet and script of the web UI
    location /static/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # SSO (OIDC) callback, served by the web admin
    location = /callback {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # REST API: loopback only. Remote CLI: ssh -L 8025:127.0.0.1:8025 <server>
    location /api {
        allow 127.0.0.1;
        allow ::1;
        deny all;
        proxy_pass http://127.0.0.1:8025;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Root redirect
    location / {
        return 301 /admin;
    }
}
NGINX
    # Debian/Ubuntu: the default site also listens on port 80
    rm -f /etc/nginx/sites-enabled/default
    # RHEL family: SELinux blocks Nginx from connecting to the upstream ports
    if command -v setsebool >/dev/null 2>&1; then
        setsebool -P httpd_can_network_connect 1 || warn "setsebool httpd_can_network_connect failed"
    fi
    nginx -t
    systemctl enable nginx
    systemctl restart nginx
}

install_certbot() {
    if command -v certbot >/dev/null 2>&1; then
        log "Certbot already installed"
        return 0
    fi
    log "Installing Certbot..."
    local ok=true
    case "$OS" in
        ubuntu|debian)
            apt_get install -y certbot python3-certbot-nginx || ok=false
            ;;
        fedora)
            dnf install -y certbot python3-certbot-nginx || ok=false
            ;;
        centos|rhel|rocky|almalinux)
            # certbot lives in EPEL on Enterprise Linux
            { dnf install -y epel-release && dnf install -y certbot python3-certbot-nginx; } || ok=false
            ;;
        amzn)
            # Amazon Linux 2023 has no certbot package; install it with pip
            { dnf install -y python3-pip && pip3 install certbot certbot-nginx; } || ok=false
            ;;
        *)
            ok=false
            ;;
    esac
    if [[ "$ok" != "true" ]]; then
        warn "Certbot could not be installed automatically; install it manually to enable HTTPS"
    fi
    return 0
}

# Certbot runs every executable in renewal-hooks/deploy after each renewal,
# with RENEWED_LINEAGE (the live/ directory of the certificate) and
# RENEWED_DOMAINS set. This hook copies the KISS Mail certificate to the
# fixed location the server watches ($DATA_DIR/tls/key.pem and cert.pem,
# owned by the container user 1000:1000) and sends SIGHUP so it reloads at
# once; the server also notices new files on its own within 60 seconds. It is
# installed before certbot ever runs. On the first issuance, certbot runs
# directory hooks only when the same path is passed as --deploy-hook (see
# credentials.txt); renewals run it once. Never put upgrade.sh in a certbot
# hook: it snapshots the data directory on every run.
# The hook is written to KM_TLS_HOOK.
KM_TLS_HOOK="/etc/letsencrypt/renewal-hooks/deploy/kiss-mail.sh"
install_tls_hook() {
    local hook="$KM_TLS_HOOK"
    log "Installing the certbot deploy hook $hook..."
    mkdir -p "$(dirname "$hook")"
    {
        echo '#!/bin/bash'
        echo '# KISS Mail certbot deploy hook, written by the KISS Mail installer.'
        printf 'DOMAIN=%q\n' "$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
        printf 'DATA_DIR=%q\n' "$DATA_DIR"
        cat << 'HOOK'
# No "set -u": certbot sets RENEWED_LINEAGE and RENEWED_DOMAINS.
set -eo pipefail
TLS_DIR="$DATA_DIR/tls"
if [[ -z "$RENEWED_LINEAGE" ]]; then
    echo "kiss-mail deploy hook: RENEWED_LINEAGE is not set (this hook is run by certbot)" >&2
    exit 1
fi
# Certbot runs this for every certificate on the machine; only act on ours.
# Certbot lowercases RENEWED_DOMAINS; DOMAIN was lowercased when written.
RENEWED_DOMAINS="$(printf '%s' "$RENEWED_DOMAINS" | tr '[:upper:]' '[:lower:]')"
case " $RENEWED_DOMAINS " in
    *" $DOMAIN "*) ;;
    *)
        echo "kiss-mail deploy hook: $RENEWED_DOMAINS does not include $DOMAIN; skipping" >&2
        exit 0
        ;;
esac
install -d -m 0700 -o 1000 -g 1000 "$TLS_DIR"
# Stage both files under temp names first, then rename key and cert. If a
# staging step fails (set -e), neither live file has changed, so the server
# never sees a mismatched pair or a half-written file.
install -m 0600 -o 1000 -g 1000 "$RENEWED_LINEAGE/privkey.pem" "$TLS_DIR/key.pem.new"
install -m 0600 -o 1000 -g 1000 "$RENEWED_LINEAGE/fullchain.pem" "$TLS_DIR/cert.pem.new"
mv -f "$TLS_DIR/key.pem.new" "$TLS_DIR/key.pem"
mv -f "$TLS_DIR/cert.pem.new" "$TLS_DIR/cert.pem"
# During upgrade.sh the container may be stopped or named kiss-mail-old; the
# new container loads the copied files when it starts.
docker kill --signal=HUP kiss-mail >/dev/null || true
echo "kiss-mail deploy hook: installed the certificate for $DOMAIN in $TLS_DIR"
HOOK
    } > "$hook.new"
    chmod 0755 "$hook.new"
    mv -f "$hook.new" "$hook"
}

configure_firewall() {
    # Ports published by Docker bypass ufw/firewalld (Docker's iptables rules
    # come first); the cloud firewall is what really limits exposure. These
    # rules are kept for consistency.
    log "Configuring firewall..."
    local port
    if command -v ufw >/dev/null 2>&1; then
        ufw default deny incoming
        ufw default allow outgoing
        for port in 22 25 587 143 110 465 993 995 80 443; do
            ufw allow "$port/tcp"
        done
        ufw --force enable || warn "Could not enable ufw"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-service=smtp
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        for port in 587 143 110 465 993 995; do
            firewall-cmd --permanent --add-port="$port/tcp"
        done
        firewall-cmd --reload || warn "Could not reload firewalld"
    else
        warn "No host firewall (ufw/firewalld) found; restrict inbound traffic to ports 22, 25, 587, 143, 110, 465, 993, 995, 80 and 443 yourself"
    fi
}

prepare_dirs() {
    # Only the data dir belongs to the container user (uid 1000); the config
    # dir holding credentials.txt stays root-only.
    mkdir -p "$CONFIG_DIR" "$DATA_DIR"
    chmod 700 "$CONFIG_DIR"
    chown -R 1000:1000 "$DATA_DIR"
}

cleanup_tmpdir() {
    if [[ -n "$KM_TMPDIR" ]]; then
        rm -rf "$KM_TMPDIR"
        KM_TMPDIR=""
    fi
}

pull_or_build_image() {
    log "Pulling $IMAGE..."
    if docker pull "$IMAGE"; then
        return 0
    fi
    warn "Registry image not available, building from source..."
    KM_TMPDIR=$(mktemp -d)
    trap cleanup_tmpdir EXIT
    command -v git >/dev/null 2>&1 || pkg_install git
    git clone --depth 1 "$KM_REPO_URL.git" "$KM_TMPDIR/src"
    docker build -t "$IMAGE" "$KM_TMPDIR/src"
    cleanup_tmpdir
    trap - EXIT
}

generate_secrets() {
    if [[ -z "$API_KEY" ]]; then
        API_KEY=$(openssl rand -hex 32)
    fi
    if [[ -z "$ADMIN_PASSWORD" ]]; then
        ADMIN_PASSWORD=$(openssl rand -base64 48 | tr -d '/+=\n' | cut -c1-32)
    fi
}

detect_public_ip() {
    PUBLIC_IP=$(public_ip 2>/dev/null || true)
    if [[ -z "$PUBLIC_IP" ]]; then
        PUBLIC_IP="YOUR_IP"
    fi
    # Base URL of the web interface, used in "password change required"
    # replies to mail clients. Switch it to https:// once certbot has run.
    if [[ -z "$PUBLIC_URL" ]]; then
        if [[ "$SECURE_COOKIE" == "true" ]]; then
            PUBLIC_URL="https://$DOMAIN"
        elif [[ "$PUBLIC_IP" != "YOUR_IP" ]]; then
            PUBLIC_URL="http://$PUBLIC_IP"
        fi
    fi
}

# Requests proxied by Nginx reach the container from the Docker bridge
# gateway, so that range must be a trusted proxy for kiss-mail to take the
# client IP (lockout, allowed_ips) from X-Real-IP. Prints the bridge subnet,
# or the whole default Docker range when it cannot be determined.
docker_bridge_cidr() {
    local subnet
    for subnet in $(docker network inspect bridge --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null); do
        if [[ "$subnet" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            echo "$subnet"
            return 0
        fi
    done
    echo "172.16.0.0/12"
}

# credentials.txt is written (root-only) as soon as the secrets exist, so they
# are never lost if a later step fails, and rewritten once the admin password
# has been set.
write_credentials() {
    local admin_line="$1"
    (
        umask 077
        cat > "$CONFIG_DIR/credentials.txt.new" << CREDS
KISS Mail Server Credentials
=============================
Domain: $DOMAIN
Admin user: admin
$admin_line
API Key: $API_KEY
Web Admin: http://$PUBLIC_IP/admin
REST API: loopback only; from your machine: ssh -L 8025:127.0.0.1:8025 <user>@$PUBLIC_IP
          then: kiss-mail --server http://127.0.0.1:8025 --api-key <API Key> status

Change the admin password later in the web admin, or offline:
  docker stop kiss-mail
  docker run --rm -i -v $DATA_DIR:/data $IMAGE passwd admin --stdin
  docker start kiss-mail
(never run "passwd" against the running container: the server would
overwrite the change with its in-memory copy)

Mail TLS: IMAPS 993, SMTPS 465 (submission) and POP3S 995, plus STARTTLS on
143, 587/25 and 110. Logins without TLS are refused.
TLS starts with a self-signed certificate. Outlook and Gmail refuse
self-signed certificates, so they cannot connect until a real one is installed.

HTTPS and the mail certificate: once DNS for $DOMAIN points at this server, run
  certbot --nginx --redirect -d $DOMAIN --deploy-hook $KM_TLS_HOOK
The deploy hook ($KM_TLS_HOOK) copies the certificate to
$DATA_DIR/tls/ and reloads KISS Mail, now and on every renewal.

The session cookie is currently sent with KISS_MAIL_WEB_SECURE_COOKIE=$SECURE_COOKIE
and KISS_MAIL_PUBLIC_URL is "$PUBLIC_URL".
Once HTTPS works, recreate the container once with a Secure cookie and an
https URL (a one-off command; never put it in a certbot hook, because every
renewal would re-run it):
  curl -fsSL $KM_REPO_URL/raw/main/deploy/scripts/upgrade.sh | sudo bash -s -- --no-pull --env KISS_MAIL_WEB_SECURE_COOKIE=true --env KISS_MAIL_PUBLIC_URL=https://$DOMAIN

Generated: $(date)
CREDS
        mv -f "$CONFIG_DIR/credentials.txt.new" "$CONFIG_DIR/credentials.txt"
    )
}

run_container() {
    log "Starting KISS Mail container..."
    docker rm -f kiss-mail >/dev/null 2>&1 || true
    local trusted_proxies
    trusted_proxies="127.0.0.1/32,::1/128,$(docker_bridge_cidr)"
    log "Trusted proxies: $trusted_proxies"
    # The web UI binds 0.0.0.0 inside the container, which would make the
    # session cookie Secure by default; it stays non-Secure (SECURE_COOKIE)
    # until HTTPS is enabled in front of it. An empty KISS_MAIL_PUBLIC_URL is
    # treated as unset by the server. KISS_MAIL_TLS=auto is the default; it is
    # set explicitly so upgrade.sh sees a TLS-aware install and does not turn
    # plaintext logins back on.
    docker run -d \
        --name kiss-mail \
        --restart unless-stopped \
        -p 25:2525 \
        -p 587:2525 \
        -p 143:1143 \
        -p 110:1100 \
        -p 465:4465 \
        -p 993:1993 \
        -p 995:1995 \
        -p 127.0.0.1:8080:8080 \
        -p 127.0.0.1:8025:8025 \
        -v "$DATA_DIR":/data \
        -e KISS_MAIL_DATA_DIR=/data \
        -e KISS_MAIL_DOMAIN="$DOMAIN" \
        -e KISS_MAIL_API_KEY="$API_KEY" \
        -e KISS_MAIL_WEB_BIND=0.0.0.0 \
        -e KISS_MAIL_API_BIND=0.0.0.0 \
        -e KISS_MAIL_WEB_SECURE_COOKIE="$SECURE_COOKIE" \
        -e KISS_MAIL_TRUSTED_PROXIES="$trusted_proxies" \
        -e KISS_MAIL_PUBLIC_URL="$PUBLIC_URL" \
        -e KISS_MAIL_TLS=auto \
        -e CLAMAV_ENABLED=false \
        -e RUST_LOG=kiss_mail=info \
        "$IMAGE" >/dev/null
}

# Wait until the server accepts SMTP connections. It only listens after it
# has finished initialising (users.json, keys.json, the admin account), so
# the offline passwd below never races its first writes.
wait_for_server() {
    for _ in $(seq 1 90); do
        if docker exec kiss-mail nc -z localhost 2525 >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# The running server keeps accounts in memory and would overwrite a change
# made by `kiss-mail passwd` inside the container, so the password is set
# offline: stop, run passwd in a one-off container on the same data, start.
# Returns 0 on success, 1 if the server never came up, 2 if stopping it or
# `passwd` failed (the container is started again) and 3 if the password was
# changed but the container could not be started again.
set_admin_password() {
    if ! wait_for_server; then
        return 1
    fi
    if ! docker stop kiss-mail >/dev/null; then
        return 2
    fi
    local rc=0
    # Read from stdin so the password never appears in a process listing.
    if printf '%s' "$ADMIN_PASSWORD" | docker run --rm -i \
        -v "$DATA_DIR":/data \
        -e KISS_MAIL_DATA_DIR=/data \
        -e KISS_MAIL_DOMAIN="$DOMAIN" \
        "$IMAGE" passwd admin --stdin; then
        # The server's bootstrap password is no longer valid; remove its file.
        rm -f "$DATA_DIR/initial-admin-password" || warn "Could not remove $DATA_DIR/initial-admin-password"
    else
        rc=2
    fi
    if ! docker start kiss-mail >/dev/null; then
        if [[ "$rc" -eq 0 ]]; then
            return 3
        fi
        warn "Could not start the kiss-mail container again; run: docker start kiss-mail"
        return "$rc"
    fi
    wait_for_server || warn "KISS Mail is slow to come back after the restart; check: docker logs kiss-mail"
    return "$rc"
}

ADMIN_PASSWORD_RC=0
finish_admin_password() {
    local rc=0
    local bootstrap="$DATA_DIR/initial-admin-password"
    log "Waiting for KISS Mail to start and setting the admin password..."
    set_admin_password || rc=$?
    # shellcheck disable=SC2034  # read by callers that need the result
    ADMIN_PASSWORD_RC="$rc"
    case "$rc" in
        0)
            write_credentials "Admin password: $ADMIN_PASSWORD"
            log "Admin password set"
            ;;
        1)
            warn "KISS Mail did not accept connections on port 2525 within 90s; check: docker logs kiss-mail"
            write_credentials "Admin password: NOT SET (server did not start). Once it runs, its bootstrap password is in $bootstrap (must be changed at first login)"
            ;;
        2)
            warn "Setting the admin password failed (docker run ... passwd admin --stdin)."
            warn "The server's bootstrap password is in $bootstrap"
            write_credentials "Admin password: NOT SET (passwd failed). Use the bootstrap password in $bootstrap (must be changed at first login)"
            ;;
        3)
            warn "The admin password was changed but starting the container failed; run: docker start kiss-mail"
            write_credentials "Admin password: $ADMIN_PASSWORD (start the server with: docker start kiss-mail)"
            ;;
    esac
    return 0
}
# <<< kiss-mail common <<<

install_kiss_mail() {
    log "Installing KISS Mail..."
    prepare_dirs
    pull_or_build_image
    detect_public_ip
    generate_secrets
    # Save the secrets before anything else can fail
    write_credentials "Admin password: PENDING - the installer has not finished. The server's bootstrap password is in $DATA_DIR/initial-admin-password"
    run_container
    finish_admin_password
    log "KISS Mail installed"
}

print_summary() {
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  KISS Mail Installation Complete!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Web Admin:    http://$PUBLIC_IP/admin"
    echo "  IMAPS:        $PUBLIC_IP:993 (IMAP with STARTTLS: 143)"
    echo "  SMTPS:        $PUBLIC_IP:465 (submission with STARTTLS: 587; MX: 25)"
    echo "  POP3S:        $PUBLIC_IP:995 (POP3 with STARTTLS: 110)"
    echo "  REST API:     127.0.0.1:8025 only (remote: ssh -L 8025:127.0.0.1:8025 <user>@$PUBLIC_IP)"
    echo ""
    echo "  Credentials:  $CONFIG_DIR/credentials.txt (root only)"
    echo ""
    echo -e "  ${YELLOW}DNS Records to configure:${NC}"
    echo ""
    echo "    A     $DOMAIN              $PUBLIC_IP"
    echo "    MX    $DOMAIN    10        $DOMAIN"
    echo "    TXT   $DOMAIN              \"v=spf1 ip4:$PUBLIC_IP -all\""
    echo ""
    echo -e "  ${YELLOW}TLS:${NC} mail TLS starts with a self-signed certificate; Outlook and Gmail"
    echo "  refuse it. Logins without TLS are refused."
    echo -e "  ${YELLOW}Once DNS points here, get a real certificate (HTTPS and mail):${NC}"
    echo "    certbot --nginx --redirect -d $DOMAIN --deploy-hook $KM_TLS_HOOK"
    echo "  The deploy hook copies it to $DATA_DIR/tls/ and reloads KISS Mail, now"
    echo "  and on every renewal."
    if [[ "$SECURE_COOKIE" != "true" ]]; then
        echo "  Then recreate the container once with a Secure session cookie and an https URL:"
        echo "    curl -fsSL $KM_REPO_URL/raw/main/deploy/scripts/upgrade.sh | sudo bash -s -- --no-pull --env KISS_MAIL_WEB_SECURE_COOKIE=true --env KISS_MAIL_PUBLIC_URL=https://$DOMAIN"
        echo "  (a one-off command: never put it in a certbot hook)"
    fi
    echo ""
    echo -e "  ${YELLOW}Changing the admin password later:${NC} use the web admin, or offline:"
    echo "    docker stop kiss-mail"
    echo "    docker run --rm -i -v $DATA_DIR:/data $IMAGE passwd admin --stdin"
    echo "    docker start kiss-mail"
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
main() {
    banner
    check_root
    validate_domain
    detect_os

    log "Domain: $DOMAIN"
    log "Data directory: $DATA_DIR"
    echo ""

    install_base_packages
    install_docker
    if [[ "$INSTALL_NGINX" == "true" ]]; then
        install_nginx
        configure_nginx
    fi
    if [[ "$INSTALL_CERTBOT" == "true" ]]; then
        install_certbot
    fi
    # Installed even with --no-certbot, for a certbot set up later.
    install_tls_hook
    configure_firewall
    install_kiss_mail

    print_summary
}

main "$@"
