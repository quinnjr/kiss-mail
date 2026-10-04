#!/bin/bash
# ============================================================================
# Test the certbot deploy hook written by install_tls_hook (shared block of
# deploy/common/bootstrap.sh.tftpl). The function is extracted from the
# template, run in a subshell against temp dirs, and the hook it writes is run
# with a fake $RENEWED_LINEAGE plus fake `install` and `docker` on PATH (the
# fake install drops -o/-g, which need root). Exits non-zero on failure.
#
# Usage: test-tls-hook.sh [copy-of-hook]  (also saves the rendered hook there,
# e.g. for shellcheck)
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEMPLATE="$ROOT/deploy/common/bootstrap.sh.tftpl"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1" >&2; failures=$((failures + 1)); }

# The shared block between the markers; it only defines functions/variables.
awk '/# >>> kiss-mail common >>>/,/# <<< kiss-mail common <<</' "$TEMPLATE" > "$WORK/common.sh"

DOMAIN="mail.example.com"
DATA_DIR="$WORK/data"
HOOK="$WORK/letsencrypt/renewal-hooks/deploy/kiss-mail.sh"
mkdir -p "$DATA_DIR"

# --- render the hook ---------------------------------------------------------
# log/warn/error are called from the sourced block.
# shellcheck disable=SC2329
if ! (
    log() { :; }
    warn() { echo "warn: $1" >&2; }
    error() { echo "error: $1" >&2; exit 1; }
    # shellcheck source=/dev/null
    . "$WORK/common.sh"
    declare -F install_tls_hook >/dev/null || error "install_tls_hook is not defined in the shared block"
    # shellcheck disable=SC2034  # read by install_tls_hook
    KM_TLS_HOOK="$HOOK"
    install_tls_hook
); then
    fail "install_tls_hook ran"
    echo "1 or more checks failed" >&2
    exit 1
fi
pass "install_tls_hook ran"
if [[ $# -gt 0 ]]; then
    cp -- "$HOOK" "$1"
fi

if [[ -f "$HOOK" && "$(stat -c %a "$HOOK")" == "755" ]]; then
    pass "hook written with mode 755"
else
    fail "hook written with mode 755 ($(stat -c %a "$HOOK" 2>/dev/null || echo missing))"
fi
# shellcheck disable=SC2016  # literal patterns, not expansions
if grep -qF -e '${' -e '%{' "$HOOK"; then
    fail "hook contains no dollar-brace or percent-brace"
else
    pass "hook contains no dollar-brace or percent-brace"
fi

# --- fakes -------------------------------------------------------------------
REAL_INSTALL="$(command -v install)"
mkdir -p "$WORK/bin"
cat > "$WORK/bin/install" << EOF
#!/bin/bash
# Fake install: drop -o/-g (they need root), keep everything else.
args=()
while [[ \$# -gt 0 ]]; do
    case "\$1" in
        -o|-g) shift 2 ;;
        *) args+=("\$1"); shift ;;
    esac
done
echo "install \${args[*]}" >> "$WORK/calls.log"
exec "$REAL_INSTALL" "\${args[@]}"
EOF
cat > "$WORK/bin/docker" << EOF
#!/bin/bash
echo "docker \$*" >> "$WORK/calls.log"
EOF
chmod +x "$WORK/bin/install" "$WORK/bin/docker"

LINEAGE="$WORK/letsencrypt/live/$DOMAIN"
mkdir -p "$LINEAGE"
echo "KEY" > "$LINEAGE/privkey.pem"
echo "CHAIN" > "$LINEAGE/fullchain.pem"

run_hook() {
    env PATH="$WORK/bin:$PATH" RENEWED_LINEAGE="$1" RENEWED_DOMAINS="$2" bash "$HOOK"
}

# --- a certificate for another domain is ignored -----------------------------
OTHER="$WORK/letsencrypt/live/other.example.org"
mkdir -p "$OTHER"
echo "OTHERKEY" > "$OTHER/privkey.pem"
echo "OTHERCHAIN" > "$OTHER/fullchain.pem"
: > "$WORK/calls.log"
if run_hook "$OTHER" "other.example.org" && [[ ! -e "$DATA_DIR/tls/cert.pem" && ! -s "$WORK/calls.log" ]]; then
    pass "certificate for another domain is ignored"
else
    fail "certificate for another domain is ignored"
fi

# --- the kiss-mail certificate is installed ----------------------------------
: > "$WORK/calls.log"
if run_hook "$LINEAGE" "$DOMAIN www.$DOMAIN"; then
    pass "hook exits 0"
else
    fail "hook exits 0"
fi
for f in key.pem cert.pem; do
    mode="$(stat -c %a "$DATA_DIR/tls/$f" 2>/dev/null || echo missing)"
    if [[ "$mode" == "600" ]]; then
        pass "$f exists with mode 600"
    else
        fail "$f exists with mode 600 (got $mode)"
    fi
done
if [[ "$(cat "$DATA_DIR/tls/key.pem" 2>/dev/null)" == "KEY" && "$(cat "$DATA_DIR/tls/cert.pem" 2>/dev/null)" == "CHAIN" ]]; then
    pass "key.pem <- privkey.pem, cert.pem <- fullchain.pem"
else
    fail "key.pem <- privkey.pem, cert.pem <- fullchain.pem"
fi
if compgen -G "$DATA_DIR/tls/*.new" >/dev/null; then
    fail "no temp files left behind"
else
    pass "no temp files left behind"
fi
key_line="$(grep -n 'privkey.pem' "$WORK/calls.log" | head -n 1 | cut -d: -f1)"
cert_line="$(grep -n 'fullchain.pem' "$WORK/calls.log" | head -n 1 | cut -d: -f1)"
if [[ -n "$key_line" && -n "$cert_line" && "$key_line" -lt "$cert_line" ]]; then
    pass "key copied before cert"
else
    fail "key copied before cert"
fi
if grep -qx 'docker kill --signal=HUP kiss-mail' "$WORK/calls.log"; then
    pass "docker kill --signal=HUP kiss-mail called"
else
    fail "docker kill --signal=HUP kiss-mail called"
fi

# --- mixed-case DOMAIN: hook lowercases DOMAIN and RENEWED_DOMAINS -----------
MIXED="$WORK/mixed"
mkdir -p "$MIXED/data" "$MIXED/letsencrypt/renewal-hooks/deploy"
MIXED_HOOK="$MIXED/letsencrypt/renewal-hooks/deploy/kiss-mail.sh"
# log/warn/error are called from the sourced block.
# shellcheck disable=SC2329
if (
    log() { :; }
    warn() { :; }
    error() { echo "error: $1" >&2; exit 1; }
    # shellcheck source=/dev/null
    . "$WORK/common.sh"
    DOMAIN="Mail.Example.COM"
    DATA_DIR="$MIXED/data"
    # shellcheck disable=SC2034  # read by install_tls_hook
    KM_TLS_HOOK="$MIXED_HOOK"
    install_tls_hook
) && grep -qx 'DOMAIN=mail.example.com' "$MIXED_HOOK"; then
    pass "hook written with a lowercased DOMAIN"
else
    fail "hook written with a lowercased DOMAIN"
fi
if env PATH="$WORK/bin:$PATH" RENEWED_LINEAGE="$LINEAGE" RENEWED_DOMAINS="MAIL.example.com" bash "$MIXED_HOOK" \
    && [[ "$(cat "$MIXED/data/tls/cert.pem" 2>/dev/null)" == "CHAIN" ]]; then
    pass "mixed-case domain matches"
else
    fail "mixed-case domain matches"
fi

# --- a skip is reported on stderr --------------------------------------------
skip_err="$(run_hook "$OTHER" "other.example.org" 2>&1 >/dev/null || true)"
if [[ "$skip_err" == *"other.example.org does not include mail.example.com; skipping"* ]]; then
    pass "skip prints a message on stderr"
else
    fail "skip prints a message on stderr (got: $skip_err)"
fi

# --- partial failure: a failing chain install leaves key.pem/cert.pem alone --
echo "OLDKEY" > "$DATA_DIR/tls/key.pem"
echo "OLDCHAIN" > "$DATA_DIR/tls/cert.pem"
mv "$WORK/bin/install" "$WORK/bin/install.real"
cat > "$WORK/bin/install" << 'FAKE'
#!/bin/bash
for a in "$@"; do
    [[ "$a" == */cert.pem.new ]] && exit 1
done
exec "$(dirname "$0")/install.real" "$@"
FAKE
chmod +x "$WORK/bin/install"
if run_hook "$LINEAGE" "$DOMAIN"; then
    fail "hook fails when installing the chain fails"
else
    pass "hook fails when installing the chain fails"
fi
if [[ "$(cat "$DATA_DIR/tls/key.pem")" == "OLDKEY" && "$(cat "$DATA_DIR/tls/cert.pem")" == "OLDCHAIN" ]]; then
    pass "key.pem and cert.pem unchanged after a partial failure"
else
    fail "key.pem and cert.pem unchanged after a partial failure"
fi
mv -f "$WORK/bin/install.real" "$WORK/bin/install"

# --- a failing docker (container stopped or renamed) does not fail the hook --
printf '#!/bin/bash\nexit 1\n' > "$WORK/bin/docker"
if run_hook "$LINEAGE" "$DOMAIN"; then
    pass "hook exits 0 when docker kill fails"
else
    fail "hook exits 0 when docker kill fails"
fi

if [[ "$failures" -ne 0 ]]; then
    echo "$failures check(s) failed" >&2
    exit 1
fi
echo "certbot deploy hook: all checks passed"
