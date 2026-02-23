#!/usr/bin/env bash
set -euo pipefail
umask 022

REPO_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="/usr/local/bin"
DEST_DIR="$REPO_DIR/deploy/usr-local/bin"

mkdir -p "$DEST_DIR"

# exact list of "real" tools to vendor (no backups / legacy)
TOOLS=(
  as-root
  as-tony
  vps-sentry
  vps-sentry-app-sanity
  vps-sentry-evidence-seal
  vps-sentry-evidence-verify
  vps-sentry-ports-normalize
  vps-sentry-publish
  vps-sentry-selftest
  vps-sentry-ship
  vps-sentry-status-merge
  vps-sentry-web-healthcheck
)

echo "=== vendoring tools into: $DEST_DIR"
for t in "${TOOLS[@]}"; do
  src="$SRC_DIR/$t"
  if [[ -f "$src" ]]; then
    cp -a "$src" "$DEST_DIR/$t"
    echo "OK: $t"
  else
    echo "WARN: missing $src (skipping)"
  fi
done

# Special handling: vps-sentry-push-web may contain embedded secrets/tokens.
PUSH="$SRC_DIR/vps-sentry-push-web"
if [[ -f "$PUSH" ]]; then
  if grep -Eqi '(authorization: *bearer|bearer +[A-Za-z0-9._-]{16,}|token=|VPS_SENTRY_.*TOKEN|api[_-]?key|secret)' "$PUSH"; then
    echo "WARN: $PUSH looks like it may contain a token/secret."
    echo "      Writing a SAFE version to deploy/usr-local/bin/vps-sentry-push-web instead."
    cat >"$DEST_DIR/vps-sentry-push-web" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# SAFE push-web helper:
# - does NOT embed tokens
# - expects token/url via env or /etc/vps-sentry-push-web.env (0600 root:root)

ENV_FILE="/etc/vps-sentry-push-web.env"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

URL="${VPS_SENTRY_PUSH_URL:-${1:-}}"
PAYLOAD="${VPS_SENTRY_PUSH_PAYLOAD:-${2:-}}"
TOKEN="${VPS_SENTRY_PUSH_TOKEN:-}"

if [[ -z "${URL:-}" || -z "${PAYLOAD:-}" ]]; then
  cat <<'USAGE' >&2
Usage:
  vps-sentry-push-web <url> <payload.json>

Env (preferred):
  /etc/vps-sentry-push-web.env (0600 root:root):
    VPS_SENTRY_PUSH_URL=...
    VPS_SENTRY_PUSH_TOKEN=...
    VPS_SENTRY_PUSH_PAYLOAD=...

Notes:
- This script intentionally will NOT work without a token in env.
USAGE
  exit 2
fi

if [[ -z "${TOKEN:-}" ]]; then
  echo "FATAL: missing VPS_SENTRY_PUSH_TOKEN (set in /etc/vps-sentry-push-web.env)" >&2
  exit 1
fi

curl -fsS \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @"${PAYLOAD}" \
  "${URL}"
EOF
    chmod 0755 "$DEST_DIR/vps-sentry-push-web"
  else
    cp -a "$PUSH" "$DEST_DIR/vps-sentry-push-web"
    echo "OK: vps-sentry-push-web (copied as-is)"
  fi
else
  echo "WARN: missing $PUSH (skipping)"
fi

chown -R tony:tony "$DEST_DIR"
echo "DONE."