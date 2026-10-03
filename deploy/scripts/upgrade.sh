#!/bin/bash
# shellcheck disable=SC2016  # single-quoted {{...}} strings are Go templates for docker inspect
# ============================================================================
# KISS Mail - Upgrade Script
# ============================================================================
# Pulls the latest image and recreates the `kiss-mail` container with the
# same environment, volumes, port bindings, restart policy and hardening
# options. Before anything is stopped, the data directory is snapshotted to
# <data-dir>.pre-upgrade-<timestamp>.tgz. The old container is kept (renamed
# to kiss-mail-old) until the new one passes a health check; on failure, or
# if the script is interrupted, the old container is restored. If the new
# container already ran, the data directory is restored from the snapshot
# too (the new version's data is moved to <data-dir>.failed-upgrade-<ts>).
#
# Containers without KISS_MAIL_WEB_SECURE_COOKIE get
# KISS_MAIL_WEB_SECURE_COOKIE=false (the old non-Secure cookie behaviour), and
# containers without KISS_MAIL_TRUSTED_PROXIES get the Docker bridge range.
#
# Containers managed by Docker Compose are refused: use
#   docker compose pull && docker compose up -d
#
# Usage: upgrade.sh [--no-pull] [--env KEY=VALUE]... [--no-backup]
#   --no-pull          Recreate with the current image (e.g. to change env)
#   --env KEY=VALUE    Set/override an environment variable (repeatable), e.g.
#                      --env KISS_MAIL_WEB_SECURE_COOKIE=true after certbot
#   --no-backup        Skip the data directory snapshot (not recommended)
# ============================================================================
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

IMAGE="ghcr.io/quinnjr/kiss-mail:latest"
NAME="kiss-mail"
OLD_NAME="kiss-mail-old"
PULL=true
BACKUP=true
ENV_OVERRIDES=()

log() {
    echo -e "${GREEN}[KISS Mail]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-pull)
            PULL=false
            shift
            ;;
        --no-backup)
            BACKUP=false
            shift
            ;;
        --env)
            [[ $# -ge 2 && "$2" == *=* ]] || error "--env requires KEY=VALUE"
            ENV_OVERRIDES+=("$2")
            shift 2
            ;;
        -h|--help)
            sed -n '3,27p' "$0" 2>/dev/null || true
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
fi

echo ""
echo -e "${GREEN}╦╔═╦╔══╗  ╔╦╗╔═╗╦╦  ${NC}"
echo -e "${GREEN}╠╩╗║╚═╗╚═╗║║║╠═╣║║  ${NC}"
echo -e "${GREEN}╩ ╩╩╚═╝╚═╝╩ ╩╩ ╩╩╩═╝${NC}"
echo ""
echo "  KISS Mail Upgrade"
echo ""

container_exists() {
    docker ps -a --format '{{.Names}}' | grep -qx "$1"
}

if ! container_exists "$NAME"; then
    error "KISS Mail container not found. Is it installed?"
fi
if container_exists "$OLD_NAME"; then
    error "A container named $OLD_NAME already exists (left over from a previous upgrade?). Remove it first: docker rm $OLD_NAME"
fi

COMPOSE_PROJECT=$(docker inspect "$NAME" --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null || true)
if [[ -n "$COMPOSE_PROJECT" && "$COMPOSE_PROJECT" != "<no value>" ]]; then
    error "The $NAME container is managed by Docker Compose (project '$COMPOSE_PROJECT'). Upgrade it with: docker compose pull && docker compose up -d"
fi

CURRENT_IMAGE=$(docker inspect "$NAME" --format '{{.Config.Image}}')
CURRENT_IMAGE_ID=$(docker inspect "$NAME" --format '{{.Image}}')
log "Current image: $CURRENT_IMAGE"

# ----------------------------------------------------------------------------
# Get the new image
# ----------------------------------------------------------------------------
if [[ "$PULL" != "true" ]]; then
    log "Keeping the current image (--no-pull)"
    NEW_IMAGE="$CURRENT_IMAGE_ID"
elif docker pull "$IMAGE"; then
    log "Pulled $IMAGE"
    NEW_IMAGE="$IMAGE"
else
    warn "Could not pull from registry, building from source..."
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    (
        cd "$tmpdir"
        if command -v git &> /dev/null; then
            git clone --depth 1 https://github.com/quinnjr/kiss-mail.git .
        else
            curl -fsSL https://github.com/quinnjr/kiss-mail/archive/main.tar.gz | tar xz --strip-components=1
        fi
        docker build -t "$IMAGE" .
    )
    rm -rf "$tmpdir"
    trap - EXIT
    NEW_IMAGE="$IMAGE"
fi

# ----------------------------------------------------------------------------
# Capture the current container configuration
# ----------------------------------------------------------------------------
log "Reading current container configuration..."

# Environment defaults baked into the old image are NOT copied, so the new
# image's defaults apply. PATH is never copied.
mapfile -t IMAGE_ENV < <(docker image inspect "$CURRENT_IMAGE_ID" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null || true)
mapfile -t CONTAINER_ENV < <(docker inspect "$NAME" --format '{{range .Config.Env}}{{println .}}{{end}}')

is_image_default() {
    local entry="$1" d
    for d in "${IMAGE_ENV[@]}"; do
        [[ "$d" == "$entry" ]] && return 0
    done
    return 1
}

RUN_ARGS=(run -d --name "$NAME")

RESTART_POLICY=$(docker inspect "$NAME" --format '{{.HostConfig.RestartPolicy.Name}}')
if [[ -z "$RESTART_POLICY" || "$RESTART_POLICY" == "no" ]]; then
    RESTART_POLICY="unless-stopped"
fi
RUN_ARGS+=(--restart "$RESTART_POLICY")

is_overridden() {
    local key="${1%%=*}" o
    for o in "${ENV_OVERRIDES[@]}"; do
        [[ "${o%%=*}" == "$key" ]] && return 0
    done
    return 1
}

# The server prefers KISS_MAIL_SMTP_PORT over the deprecated SMTP_PORT alias
# (removed in 0.3.0), so the alias is only used when the new name is absent.
SMTP_INTERNAL_PORT=2525
SMTP_PORT_NEW=""
SMTP_PORT_ALIAS=""
HAS_SECURE_COOKIE=false
HAS_TRUSTED_PROXIES=false
for entry in "${CONTAINER_ENV[@]}" "${ENV_OVERRIDES[@]}"; do
    [[ -z "$entry" ]] && continue
    # Container values that an --env override replaces are dropped here; the
    # override itself is appended in the second half of the loop.
    if is_overridden "$entry" && ! printf '%s\n' "${ENV_OVERRIDES[@]}" | grep -qxF -- "$entry"; then
        continue
    fi
    [[ "$entry" == PATH=* ]] && continue
    case "$entry" in
        KISS_MAIL_SMTP_PORT=*) SMTP_PORT_NEW="${entry#*=}" ;;
        SMTP_PORT=*) SMTP_PORT_ALIAS="${entry#*=}" ;;
        KISS_MAIL_WEB_SECURE_COOKIE=*) HAS_SECURE_COOKIE=true ;;
        KISS_MAIL_TRUSTED_PROXIES=*) HAS_TRUSTED_PROXIES=true ;;
    esac
    is_image_default "$entry" && ! is_overridden "$entry" && continue
    RUN_ARGS+=(-e "$entry")
done
if [[ -n "$SMTP_PORT_NEW" ]]; then
    SMTP_INTERNAL_PORT="$SMTP_PORT_NEW"
elif [[ -n "$SMTP_PORT_ALIAS" ]]; then
    SMTP_INTERNAL_PORT="$SMTP_PORT_ALIAS"
fi

# Containers created before KISS_MAIL_WEB_SECURE_COOKIE existed relied on a
# non-Secure session cookie. Current versions mark the cookie Secure when the
# web UI binds a non-loopback address, which breaks logins over plain HTTP, so
# keep the old behaviour explicitly.
if [[ "$HAS_SECURE_COOKIE" != "true" ]]; then
    RUN_ARGS+=(-e KISS_MAIL_WEB_SECURE_COOKIE=false)
    warn "KISS_MAIL_WEB_SECURE_COOKIE was not set; keeping a non-Secure session cookie (KISS_MAIL_WEB_SECURE_COOKIE=false)."
    warn "Once the web admin is served over HTTPS, re-run with: --no-pull --env KISS_MAIL_WEB_SECURE_COOKIE=true"
fi

# Requests proxied from the host (Nginx -> 127.0.0.1:8080) reach the container
# from the Docker bridge gateway. Trust that range so the client IP is taken
# from X-Real-IP / X-Forwarded-For (used for lockout and allowed_ips).
bridge_subnet() {
    local net="bridge" subnet
    case "$NETWORK_MODE" in
        ""|default|bridge|host|none|container:*) ;;
        *) net="$NETWORK_MODE" ;;
    esac
    for subnet in $(docker network inspect "$net" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null); do
        if [[ "$subnet" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            echo "$subnet"
            return 0
        fi
    done
    echo "172.16.0.0/12"
}
NETWORK_MODE=$(docker inspect "$NAME" --format '{{.HostConfig.NetworkMode}}')
if [[ "$HAS_TRUSTED_PROXIES" != "true" ]]; then
    TRUSTED_PROXIES="127.0.0.1/32,::1/128,$(bridge_subnet)"
    RUN_ARGS+=(-e "KISS_MAIL_TRUSTED_PROXIES=$TRUSTED_PROXIES")
    log "Setting KISS_MAIL_TRUSTED_PROXIES=$TRUSTED_PROXIES (Docker bridge range, for the host's reverse proxy)"
fi

# Port bindings, e.g. "127.0.0.1|8080|8080/tcp"
while IFS='|' read -r host_ip host_port container_port; do
    [[ -z "$container_port" ]] && continue
    if [[ -n "$host_ip" ]]; then
        RUN_ARGS+=(-p "${host_ip}:${host_port}:${container_port}")
    else
        RUN_ARGS+=(-p "${host_port}:${container_port}")
    fi
done < <(docker inspect "$NAME" --format '{{range $p, $conf := .HostConfig.PortBindings}}{{range $conf}}{{.HostIp}}|{{.HostPort}}|{{$p}}{{println}}{{end}}{{end}}')

# Volumes / bind mounts
while IFS='|' read -r _type source dest rw; do
    [[ -z "$dest" ]] && continue
    spec="${source}:${dest}"
    [[ "$rw" == "false" ]] && spec+=":ro"
    RUN_ARGS+=(-v "$spec")
done < <(docker inspect "$NAME" --format '{{range .Mounts}}{{.Type}}|{{if eq .Type "volume"}}{{.Name}}{{else}}{{.Source}}{{end}}|{{.Destination}}|{{.RW}}{{println}}{{end}}')

# Hardening and runtime options
fmt() { docker inspect "$NAME" --format "$1"; }

if [[ -n "$NETWORK_MODE" && "$NETWORK_MODE" != "default" ]]; then
    RUN_ARGS+=(--network "$NETWORK_MODE")
fi
if [[ "$(fmt '{{.HostConfig.ReadonlyRootfs}}')" == "true" ]]; then
    RUN_ARGS+=(--read-only)
fi
while IFS= read -r cap; do
    [[ -n "$cap" ]] && RUN_ARGS+=(--cap-add "$cap")
done < <(fmt '{{range .HostConfig.CapAdd}}{{println .}}{{end}}')
while IFS= read -r cap; do
    [[ -n "$cap" ]] && RUN_ARGS+=(--cap-drop "$cap")
done < <(fmt '{{range .HostConfig.CapDrop}}{{println .}}{{end}}')
while IFS= read -r opt; do
    [[ -n "$opt" ]] && RUN_ARGS+=(--security-opt "$opt")
done < <(fmt '{{range .HostConfig.SecurityOpt}}{{println .}}{{end}}')
MEMORY=$(fmt '{{.HostConfig.Memory}}')
if [[ -n "$MEMORY" && "$MEMORY" != "0" ]]; then
    RUN_ARGS+=(--memory "$MEMORY")
fi
PIDS_LIMIT=$(fmt '{{if .HostConfig.PidsLimit}}{{.HostConfig.PidsLimit}}{{end}}')
if [[ -n "$PIDS_LIMIT" && "$PIDS_LIMIT" != "0" ]]; then
    RUN_ARGS+=(--pids-limit "$PIDS_LIMIT")
fi
LOG_DRIVER=$(fmt '{{.HostConfig.LogConfig.Type}}')
if [[ -n "$LOG_DRIVER" ]]; then
    RUN_ARGS+=(--log-driver "$LOG_DRIVER")
    while IFS= read -r opt; do
        [[ -n "$opt" ]] && RUN_ARGS+=(--log-opt "$opt")
    done < <(fmt '{{range $k, $v := .HostConfig.LogConfig.Config}}{{$k}}={{$v}}{{println}}{{end}}')
fi
while IFS= read -r t; do
    [[ -n "$t" ]] && RUN_ARGS+=(--tmpfs "$t")
done < <(fmt '{{range $k, $v := .HostConfig.Tmpfs}}{{$k}}{{if $v}}:{{$v}}{{end}}{{println}}{{end}}')
CONTAINER_USER=$(fmt '{{.Config.User}}')
IMAGE_USER=$(docker image inspect "$CURRENT_IMAGE_ID" --format '{{.Config.User}}' 2>/dev/null || true)
if [[ -n "$CONTAINER_USER" && "$CONTAINER_USER" != "$IMAGE_USER" ]]; then
    RUN_ARGS+=(--user "$CONTAINER_USER")
fi
# Labels set on the container (image labels are inherited from the new image)
mapfile -t IMAGE_LABELS < <(docker image inspect "$CURRENT_IMAGE_ID" --format '{{range $k, $v := .Config.Labels}}{{$k}}={{$v}}{{println}}{{end}}' 2>/dev/null || true)
while IFS= read -r label; do
    [[ -z "$label" ]] && continue
    skip=false
    for l in "${IMAGE_LABELS[@]}"; do
        [[ "$l" == "$label" ]] && { skip=true; break; }
    done
    [[ "$skip" == "true" ]] || RUN_ARGS+=(--label "$label")
done < <(fmt '{{range $k, $v := .Config.Labels}}{{$k}}={{$v}}{{println}}{{end}}')

RUN_ARGS+=("$NEW_IMAGE")

# ----------------------------------------------------------------------------
# Snapshot the data directory
# ----------------------------------------------------------------------------
# Mail encrypted by a newer version cannot be read by an older one, so a
# snapshot taken before the upgrade is the only way back.
DATA_SOURCE=$(fmt '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}')
BACKUP_FILE=""
if [[ "$BACKUP" == "true" ]]; then
    if [[ -n "$DATA_SOURCE" && -d "$DATA_SOURCE" ]]; then
        BACKUP_FILE="${DATA_SOURCE%/}.pre-upgrade-$(date +%Y%m%d-%H%M%S).tgz"
        log "Snapshotting $DATA_SOURCE to $BACKUP_FILE (container stopped briefly for consistency)..."
    else
        warn "Could not find the /data mount of $NAME on the host; no snapshot will be taken"
    fi
fi

# ----------------------------------------------------------------------------
# Swap containers
# ----------------------------------------------------------------------------
# STATE tracks how far the swap got so that rollback can undo exactly that:
#   running  - nothing changed yet
#   stopped  - old container stopped (still named $NAME)
#   renamed  - old container renamed to $OLD_NAME
#   started  - new container created as $NAME
STATE="running"

print_manual_recovery() {
    echo "" >&2
    echo "Manual recovery:" >&2
    echo "  docker rm -f $NAME                # remove a half-started new container" >&2
    echo "  docker rename $OLD_NAME $NAME     # if the old container is still named $OLD_NAME" >&2
    echo "  docker start $NAME" >&2
    if [[ -n "$BACKUP_FILE" ]]; then
        echo "  Data snapshot: $BACKUP_FILE" >&2
        echo "    (restore with: docker stop $NAME && mv $DATA_SOURCE $DATA_SOURCE.broken && tar xzf $BACKUP_FILE -C $(dirname "$DATA_SOURCE") && docker start $NAME)" >&2
    fi
}

# Put the pre-upgrade snapshot back in place. The data the new container may
# have written is moved aside, never deleted.
restore_snapshot() {
    local failed
    failed="${DATA_SOURCE%/}.failed-upgrade-$(date +%Y%m%d-%H%M%S)"
    log "Restoring the data directory from $BACKUP_FILE (the new version's data is kept in $failed)..."
    if ! mv "$DATA_SOURCE" "$failed"; then
        warn "could not move $DATA_SOURCE aside; the data was NOT restored"
        return 1
    fi
    if ! tar xzf "$BACKUP_FILE" -C "$(dirname "$DATA_SOURCE")"; then
        warn "could not extract $BACKUP_FILE; moving the new version's data back"
        rm -rf "$DATA_SOURCE"
        mv "$failed" "$DATA_SOURCE" || warn "could not move $failed back to $DATA_SOURCE"
        return 1
    fi
    log "Data directory restored from the snapshot"
    return 0
}

rollback() {
    # Nothing may interrupt the rollback itself.
    trap - ERR
    trap '' INT TERM HUP
    set +e
    warn "Rolling back to the previous container (state: $STATE)..."
    local data_restored=false
    case "$STATE" in
        started)
            # Stop the new container before touching its data directory.
            docker rm -f "$NAME" >/dev/null 2>&1 || warn "could not remove the new container"
            if [[ -n "$BACKUP_FILE" && -f "$BACKUP_FILE" ]] && restore_snapshot; then
                data_restored=true
            fi
            docker rename "$OLD_NAME" "$NAME" || warn "could not rename $OLD_NAME back to $NAME"
            ;;
        renamed)
            # A new container may exist if docker run failed midway
            if container_exists "$NAME" && container_exists "$OLD_NAME"; then
                docker rm -f "$NAME" >/dev/null 2>&1 || warn "could not remove the new container"
            fi
            docker rename "$OLD_NAME" "$NAME" || warn "could not rename $OLD_NAME back to $NAME"
            ;;
    esac
    if [[ "$STATE" != "running" ]]; then
        docker start "$NAME" >/dev/null || warn "could not start $NAME"
    fi
    if [[ "$STATE" == "started" && "$data_restored" != "true" ]]; then
        warn "The data directory was NOT restored: the previous container now runs on data the new version may have modified."
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" == "true" ]]; then
        echo -e "${RED}[ERROR]${NC} Upgrade failed; the previous container is running again." >&2
    else
        echo -e "${RED}[ERROR]${NC} Upgrade failed and the previous container could not be restored automatically." >&2
    fi
    print_manual_recovery
    exit 1
}

trap rollback ERR INT TERM HUP

log "Stopping current container..."
docker stop "$NAME" >/dev/null
STATE="stopped"

if [[ -n "$BACKUP_FILE" ]]; then
    # Written under a private umask and renamed only once complete, so a
    # partial archive is never mistaken for a usable snapshot.
    if ( umask 077; tar czf "$BACKUP_FILE.partial" -C "$(dirname "$DATA_SOURCE")" "$(basename "$DATA_SOURCE")" ) \
        && mv "$BACKUP_FILE.partial" "$BACKUP_FILE"; then
        log "Snapshot written: $BACKUP_FILE"
    else
        rm -f "$BACKUP_FILE.partial"
        BACKUP_FILE=""
        warn "Could not write the data snapshot"
        rollback
    fi
fi

docker rename "$NAME" "$OLD_NAME"
STATE="renamed"

log "Starting new container..."
docker "${RUN_ARGS[@]}" >/dev/null
STATE="started"

# ----------------------------------------------------------------------------
# Health check
# ----------------------------------------------------------------------------
log "Waiting for the new container to become healthy..."
healthy=false
for _ in $(seq 1 45); do
    sleep 2
    if [[ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" == "true" ]] \
        && [[ "$(docker inspect -f '{{.State.Restarting}}' "$NAME" 2>/dev/null)" == "false" ]] \
        && docker exec "$NAME" nc -z localhost "$SMTP_INTERNAL_PORT" >/dev/null 2>&1; then
        healthy=true
        break
    fi
done

if [[ "$healthy" != "true" ]]; then
    warn "New container did not become healthy (SMTP port $SMTP_INTERNAL_PORT not listening within 90s)"
    echo "----- logs of the new container -----"
    docker logs --tail 50 "$NAME" 2>&1 || true
    echo "-------------------------------------"
    rollback
fi

trap - ERR INT TERM HUP

log "New container is healthy; removing the old one..."
docker rm "$OLD_NAME" >/dev/null || warn "Could not remove $OLD_NAME; remove it yourself: docker rm $OLD_NAME"

echo ""
echo "  Previous image: $CURRENT_IMAGE"
echo "  New image:      $NEW_IMAGE"
if [[ -n "$BACKUP_FILE" ]]; then
    echo "  Data snapshot:  $BACKUP_FILE (delete it once you are happy with the upgrade)"
fi
echo "  Status:         $(docker inspect "$NAME" --format '{{.State.Status}}')"
echo ""

log "Cleaning up dangling images..."
docker image prune -f >/dev/null || warn "docker image prune failed (harmless)"

log "Upgrade complete!"
