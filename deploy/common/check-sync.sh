#!/bin/bash
# ============================================================================
# Verify that the shared "kiss-mail common" provisioning block is identical in
# every script that embeds it. Run from anywhere; exits non-zero on drift.
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REFERENCE="deploy/common/bootstrap.sh.tftpl"
COPIES=(
    "deploy/scripts/install.sh"
    "deploy/generic/cloud-init.yml"
)

# Print the block between the markers, with the marker line's indentation
# removed from every line (the cloud-init copy is indented inside YAML).
extract() {
    awk '
        /# >>> kiss-mail common >>>/ {
            match($0, /^ */); indent = RLENGTH; inside = 1
        }
        inside { print substr($0, indent + 1) }
        /# <<< kiss-mail common <<</ { inside = 0 }
    ' "$ROOT/$1"
}

ref="$(extract "$REFERENCE")"
if [[ -z "$ref" ]]; then
    echo "No common block found in $REFERENCE" >&2
    exit 1
fi

status=0
# Terraform's templatefile() would interpolate these in the .tftpl copy.
# shellcheck disable=SC2016  # literal patterns, not expansions
if bad="$(printf '%s\n' "$ref" | grep -nF -e '${' -e '%{')"; then
    echo "FORBIDDEN: the common block in $REFERENCE contains dollar-brace or percent-brace:" >&2
    printf '%s\n' "$bad" >&2
    status=1
fi
for copy in "${COPIES[@]}"; do
    if ! diff -u --label "$REFERENCE" --label "$copy" <(printf '%s\n' "$ref") <(extract "$copy"); then
        echo "DRIFT: $copy differs from $REFERENCE" >&2
        status=1
    fi
done
[[ $status -eq 0 ]] && echo "kiss-mail common block is in sync (${#COPIES[@]} copies)"
exit $status
