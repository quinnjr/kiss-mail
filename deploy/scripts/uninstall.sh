#!/bin/bash
# ============================================================================
# KISS Mail - Uninstall Script
# ============================================================================
# Works when piped (curl ... | bash): confirmations are read from /dev/tty.
# Non-interactive use: pass --yes.
# ============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[KISS Mail]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

usage() {
    echo "Usage: $0 [--keep-data] [--data-dir DIR] [--yes]"
    echo ""
    echo "Options:"
    echo "  --keep-data       Keep the mail data directory"
    echo "  --data-dir DIR    Data directory to remove (default: /opt/kiss-mail/data)"
    echo "  -y, --yes         Do not ask for confirmation"
    echo "  -h, --help        Show this help"
}

KEEP_DATA=false
ASSUME_YES=false
DATA_DIR="/opt/kiss-mail/data"
INSTALL_DIR="/opt/kiss-mail"

while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-data)
            KEEP_DATA=true
            shift
            ;;
        --data-dir)
            [[ $# -ge 2 ]] || { usage; error "--data-dir requires a value"; }
            DATA_DIR="$2"
            shift 2
            ;;
        -y|--yes)
            ASSUME_YES=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            error "Unknown option: $1"
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
fi

container_exists() {
    docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$1"
}

# The /data mount of the installed container, as seen by Docker
MOUNTED_DATA_DIR=""
if command -v docker >/dev/null 2>&1 && container_exists kiss-mail; then
    # shellcheck disable=SC2016  # Go template, not a shell expansion
    MOUNTED_DATA_DIR="$(docker inspect kiss-mail --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)"
fi

# Refuse to delete anything that does not look like a KISS Mail data
# directory: it must contain users.json or live under /opt/kiss-mail, and it
# can never be / (or resolve to it).
if [[ "$KEEP_DATA" != "true" ]]; then
    DATA_DIR_REAL="$(realpath -m -- "$DATA_DIR")"
    if [[ -z "$DATA_DIR_REAL" || "$DATA_DIR_REAL" == "/" ]]; then
        error "Refusing to delete '$DATA_DIR'"
    fi
    if [[ ! -f "$DATA_DIR_REAL/users.json" && "$DATA_DIR_REAL" != "$INSTALL_DIR"/* ]]; then
        error "Refusing to delete '$DATA_DIR': it has no users.json and is not under $INSTALL_DIR"
    fi
    DATA_DIR="$DATA_DIR_REAL"
fi

if [[ -n "$MOUNTED_DATA_DIR" && "$(realpath -m -- "$MOUNTED_DATA_DIR")" != "$(realpath -m -- "$DATA_DIR")" ]]; then
    warn "The kiss-mail container mounts $MOUNTED_DATA_DIR as /data, but the data directory to handle is $DATA_DIR."
    warn "Pass --data-dir $MOUNTED_DATA_DIR if that is the directory you mean."
fi

# Pre-upgrade snapshots and data moved aside by a rolled-back upgrade
# (written by upgrade.sh next to the data directory). Both contain mail.
UPGRADE_LEFTOVERS=()
if [[ "$KEEP_DATA" != "true" ]]; then
    shopt -s nullglob
    UPGRADE_LEFTOVERS=("${DATA_DIR%/}".pre-upgrade-*.tgz "${DATA_DIR%/}".failed-upgrade-*)
    shopt -u nullglob
fi

echo ""
echo -e "${RED}╦╔═╦╔══╗  ╔╦╗╔═╗╦╦  ${NC}"
echo -e "${RED}╠╩╗║╚═╗╚═╗║║║╠═╣║║  ${NC}"
echo -e "${RED}╩ ╩╩╚═╝╚═╝╩ ╩╩ ╩╩╩═╝${NC}"
echo ""
echo "  KISS Mail Uninstaller"
echo ""

confirm() {
    local prompt="$1" answer=""
    if [[ "$ASSUME_YES" == "true" ]]; then
        return 0
    fi
    if [[ ! -r /dev/tty ]]; then
        error "No terminal available for confirmation; re-run with --yes"
    fi
    read -r -p "$prompt [y/N] " answer < /dev/tty
    [[ "$answer" =~ ^[Yy]$ ]]
}

if ! confirm "Are you sure you want to uninstall KISS Mail?"; then
    echo "Aborted."
    exit 0
fi

if [[ "$KEEP_DATA" != "true" ]]; then
    if [[ ${#UPGRADE_LEFTOVERS[@]} -gt 0 ]]; then
        echo "Upgrade snapshots that will also be deleted:"
        printf '  %s\n' "${UPGRADE_LEFTOVERS[@]}"
    fi
    if ! confirm "This permanently deletes all mail in $DATA_DIR (and the snapshots listed above). Continue?"; then
        echo "Aborted."
        exit 0
    fi
fi

log "Stopping KISS Mail container..."
if container_exists kiss-mail && ! docker stop kiss-mail >/dev/null; then
    error "Could not stop the kiss-mail container; nothing was removed"
fi

log "Removing KISS Mail container..."
docker rm kiss-mail 2>/dev/null || true
docker rm kiss-mail-old 2>/dev/null || true

log "Removing KISS Mail image..."
docker rmi kiss-mail:latest 2>/dev/null || true
docker rmi ghcr.io/quinnjr/kiss-mail:latest 2>/dev/null || true

log "Removing Nginx configuration..."
rm -f /etc/nginx/conf.d/kiss-mail.conf 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/kiss-mail 2>/dev/null || true
rm -f /etc/nginx/sites-available/kiss-mail 2>/dev/null || true
systemctl reload nginx 2>/dev/null || true

# Admin password retry unit left by the Terraform bootstrap, if any
if [[ -f /etc/systemd/system/kiss-mail-admin-password.service ]]; then
    systemctl disable kiss-mail-admin-password.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/kiss-mail-admin-password.service
    systemctl daemon-reload 2>/dev/null || true
fi
rm -f "$INSTALL_DIR/bootstrap-retry.sh" "$INSTALL_DIR/.bootstrap.lock"

if [[ "$KEEP_DATA" == "true" ]]; then
    warn "Keeping data directory: $DATA_DIR"
    rm -f "$INSTALL_DIR/credentials.txt" "$INSTALL_DIR/.provisioned" "$INSTALL_DIR/.admin-password-pending"
else
    log "Removing data directory $DATA_DIR..."
    rm -rf -- "$DATA_DIR"
    for leftover in "${UPGRADE_LEFTOVERS[@]}"; do
        log "Removing $leftover..."
        rm -rf -- "$leftover"
    done
    rm -f "$INSTALL_DIR/credentials.txt" "$INSTALL_DIR/.provisioned" "$INSTALL_DIR/.admin-password-pending"
    rmdir "$INSTALL_DIR" 2>/dev/null || true
fi

echo ""
log "KISS Mail has been uninstalled."
if [[ "$KEEP_DATA" == "true" ]]; then
    echo "  Data preserved at: $DATA_DIR"
fi
echo ""
