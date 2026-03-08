#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$ROOT_DIR/deploy/launchd/com.tony.vps-sentry-external-sentinel.plist.template"
SOURCE_SENTINEL="$ROOT_DIR/bin/vps-sentry-external-sentinel"
SOURCE_NOTIFY="$ROOT_DIR/deploy/usr-local/bin/vps-sentry-notify"
SOURCE_RUNNER="$ROOT_DIR/scripts/run-external-sentinel.sh"

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/vps-sentry"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/vps-sentry/external-sentinel"
LOG_DIR="$HOME/Library/Logs"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
INSTALL_ROOT="$HOME/Library/Application Support/VPSSentry"
BUNDLE_DIR="$INSTALL_ROOT/external-sentinel"
BIN_DIR="$BUNDLE_DIR/bin"
SCRIPTS_DIR="$BUNDLE_DIR/scripts"
CONFIG_FILE="$CONFIG_DIR/external-sentinel.env"
PLIST_FILE="$LAUNCH_AGENTS_DIR/com.tony.vps-sentry-external-sentinel.plist"
LABEL="com.tony.vps-sentry-external-sentinel"
UID_VALUE="$(id -u)"
DOMAIN="gui/$UID_VALUE"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

ensure_dirs() {
  mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR" "$LAUNCH_AGENTS_DIR" "$BIN_DIR" "$SCRIPTS_DIR"
}

shell_quote() {
  printf '%q' "$1"
}

config_get() {
  local key="$1"
  python3 - "$CONFIG_FILE" "$key" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
key = sys.argv[2]

if not path.exists():
    raise SystemExit(0)

for raw in path.read_text().splitlines():
    if not raw.startswith(f"{key}="):
        continue
    print(raw.split("=", 1)[1])
    raise SystemExit(0)
PY
}

config_upsert() {
  local key="$1"
  local value="$2"
  local escaped tmp

  escaped="$(shell_quote "$value")"
  tmp="$(mktemp)"

  python3 - "$CONFIG_FILE" "$tmp" "$key" "$escaped" <<'PY'
import pathlib
import sys

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2])
key = sys.argv[3]
value = sys.argv[4]

lines = src.read_text().splitlines() if src.exists() else []
out = []
done = False
prefix = f"{key}="

for line in lines:
    if line.startswith(prefix):
        out.append(f"{key}={value}")
        done = True
    else:
        out.append(line)

if not done:
    out.append(f"{key}={value}")

dst.write_text("\n".join(out) + "\n")
PY

  install -m 0600 "$tmp" "$CONFIG_FILE"
  rm -f "$tmp"
}

sync_bundle() {
  install -m 0755 "$SOURCE_SENTINEL" "$BIN_DIR/vps-sentry-external-sentinel"
  install -m 0755 "$SOURCE_NOTIFY" "$BIN_DIR/vps-sentry-notify"
  install -m 0755 "$SOURCE_RUNNER" "$SCRIPTS_DIR/run-external-sentinel.sh"
}

write_default_config_if_missing() {
  if [[ -f "$CONFIG_FILE" ]]; then
    return 0
  fi

  cat >"$CONFIG_FILE" <<'EOF'
# MBP external sentinel config.
# This install defaults to stub mode to avoid storing mail credentials on the MBP
# until you explicitly choose to enable active paging.
VPS_SENTRY_EXTERNAL_SENTINEL_MODE=stub
VPS_SENTRY_EXTERNAL_SENTINEL_NAME=vps-sentry-edge-mbp
VPS_SENTRY_EXTERNAL_SENTINEL_URL=https://vps-sentry.tokentap.ca/api/readyz
VPS_SENTRY_EXTERNAL_SENTINEL_EXPECTED_STATUS=200
VPS_SENTRY_EXTERNAL_SENTINEL_CONSECUTIVE_FAILURES=2
VPS_SENTRY_EXTERNAL_SENTINEL_TIMEOUT_SECONDS=10
VPS_SENTRY_EXTERNAL_SENTINEL_PROJECT=vps-sentry
EOF
  chmod 0600 "$CONFIG_FILE"
}

update_recommended_config() {
  local current_url current_notify_bin

  current_url="$(config_get "VPS_SENTRY_EXTERNAL_SENTINEL_URL" || true)"
  current_notify_bin="$(config_get "VPS_SENTRY_EXTERNAL_SENTINEL_NOTIFY_BIN" || true)"

  case "$current_url" in
    ""|"https://vps-sentry.tokentap.ca/"|"https://vps-sentry.tokentap.ca")
      config_upsert "VPS_SENTRY_EXTERNAL_SENTINEL_URL" "https://vps-sentry.tokentap.ca/api/readyz"
      ;;
  esac

  case "$current_notify_bin" in
    ""|*/deploy/usr-local/bin/vps-sentry-notify)
      config_upsert "VPS_SENTRY_EXTERNAL_SENTINEL_NOTIFY_BIN" "$BIN_DIR/vps-sentry-notify"
      ;;
  esac
}

render_plist() {
  local tmp path_value
  tmp="$(mktemp)"
  path_value="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  sed \
    -e "s#__RUNNER__#$SCRIPTS_DIR/run-external-sentinel.sh#g" \
    -e "s#__WORKDIR__#$BUNDLE_DIR#g" \
    -e "s#__STDOUT__#$LOG_DIR/vps-sentry-external-sentinel.log#g" \
    -e "s#__STDERR__#$LOG_DIR/vps-sentry-external-sentinel.err#g" \
    -e "s#__PATH__#$path_value#g" \
    "$TEMPLATE" >"$tmp"
  plutil -lint "$tmp" >/dev/null
  install -m 0644 "$tmp" "$PLIST_FILE"
  rm -f "$tmp"
}

install_launch_agent() {
  launchctl bootout "$DOMAIN" "$PLIST_FILE" >/dev/null 2>&1 || true
  launchctl bootstrap "$DOMAIN" "$PLIST_FILE"
  launchctl enable "$DOMAIN/$LABEL"
  launchctl kickstart -k "$DOMAIN/$LABEL"
}

status_summary() {
  launchctl print "$DOMAIN/$LABEL" | sed -n '1,80p'
}

need_cmd plutil
need_cmd launchctl
need_cmd python3
need_cmd sed

[[ -f "$TEMPLATE" ]] || die "missing template: $TEMPLATE"
[[ -x "$SOURCE_SENTINEL" ]] || die "missing sentinel: $SOURCE_SENTINEL"
[[ -x "$SOURCE_NOTIFY" ]] || die "missing notifier: $SOURCE_NOTIFY"
[[ -x "$SOURCE_RUNNER" ]] || die "missing runner: $SOURCE_RUNNER"

ensure_dirs
write_default_config_if_missing
sync_bundle
update_recommended_config
render_plist
install_launch_agent

echo "Installed:"
echo "  config: $CONFIG_FILE"
echo "  bundle: $BUNDLE_DIR"
echo "  plist:  $PLIST_FILE"
echo "  state:  $STATE_DIR"
echo "  logs:   $LOG_DIR/vps-sentry-external-sentinel.log"
echo "  mode:   $(sed -n 's/^VPS_SENTRY_EXTERNAL_SENTINEL_MODE=//p' "$CONFIG_FILE" | head -n 1)"
echo
status_summary
