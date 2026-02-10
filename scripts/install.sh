#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

die() {
  echo "ERROR: $*" >&2
  exit 1
}

warn() {
  echo "WARN: $*" >&2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

strip_outer_quotes() {
  local s="$1"
  if [[ "$s" == \"*\" && "$s" == *\" ]]; then
    s="${s:1:${#s}-2}"
  elif [[ "$s" == \'*\' && "$s" == *\' ]]; then
    s="${s:1:${#s}-2}"
  fi
  printf '%s' "$s"
}

safe_runtime_from_defaults_file() {
  local file="/etc/default/vps-sentry" owner mode mode_dec raw

  sudo test -f "$file" || return 0
  sudo test ! -L "$file" || die "refusing symlink override file: $file"

  owner="$(sudo stat -c '%u:%g' "$file" 2>/dev/null || true)"
  [[ "$owner" == "0:0" ]] || die "unsafe owner for $file (expected root:root)"

  mode="$(sudo stat -c '%a' "$file" 2>/dev/null || true)"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || die "unable to read safe mode for $file"
  mode_dec=$((8#$mode))
  (( (mode_dec & 0022) == 0 )) || die "unsafe permissions for $file (must not be group/other writable)"

  raw="$(sudo sed -n 's/^[[:space:]]*VPS_SENTRY_RUNTIME[[:space:]]*=[[:space:]]*//p' "$file" | tail -n 1)"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  [[ -n "$raw" ]] || return 0

  strip_outer_quotes "$raw"
}

need_cmd sudo
need_cmd install
need_cmd systemctl
need_cmd stat
need_cmd sed
need_cmd tail
need_cmd python3
need_cmd curl
need_cmd tar
need_cmd find
need_cmd mktemp
if ! command -v flock >/dev/null 2>&1; then
  warn "flock not found; shipping will run without overlap lock"
fi

DEFAULT_RUNTIME="/opt/vps-sentry/venv/bin/vps-sentry"
RUNTIME_BIN="${VPS_SENTRY_RUNTIME:-$DEFAULT_RUNTIME}"
UNIT_SRC_DIR="deploy/systemd"

if [[ ! -d "$UNIT_SRC_DIR" ]]; then
  die "missing unit source directory: $UNIT_SRC_DIR"
fi

# If no env override is passed, honor an existing systemd override file so
# preflight checks reflect what the wrapper will use at runtime.
if [[ -z "${VPS_SENTRY_RUNTIME:-}" ]]; then
  if RUNTIME_FROM_FILE="$(safe_runtime_from_defaults_file)"; then
    if [[ -n "$RUNTIME_FROM_FILE" ]]; then
      RUNTIME_BIN="$RUNTIME_FROM_FILE"
    fi
  fi
fi

if ! sudo test -x "$RUNTIME_BIN"; then
  die "runtime binary not found or not executable: $RUNTIME_BIN (set VPS_SENTRY_RUNTIME if different)"
fi

# If the caller supplied an override runtime path, persist it for systemd runs.
if [[ -n "${VPS_SENTRY_RUNTIME:-}" ]]; then
  ESCAPED_RUNTIME="${VPS_SENTRY_RUNTIME//\'/\'\"\'\"\'}"
  printf "VPS_SENTRY_RUNTIME='%s'\n" "$ESCAPED_RUNTIME" | sudo tee /etc/default/vps-sentry >/dev/null
fi

sudo install -m 0755 bin/vps-sentry          /usr/local/bin/vps-sentry
sudo install -m 0755 bin/vps-sentry-ship     /usr/local/bin/vps-sentry-ship
sudo install -m 0755 bin/vps-sentry-selftest /usr/local/bin/vps-sentry-selftest

sudo install -m 0644 "$UNIT_SRC_DIR/vps-sentry.service"      /etc/systemd/system/vps-sentry.service
sudo install -m 0644 "$UNIT_SRC_DIR/vps-sentry.timer"        /etc/systemd/system/vps-sentry.timer
sudo install -m 0644 "$UNIT_SRC_DIR/vps-sentry-ship.service" /etc/systemd/system/vps-sentry-ship.service

sudo mkdir -p /etc/systemd/system/vps-sentry.service.d
if [[ -f "$UNIT_SRC_DIR/vps-sentry.service.d/ship.conf" ]]; then
  sudo install -m 0644 "$UNIT_SRC_DIR/vps-sentry.service.d/ship.conf" /etc/systemd/system/vps-sentry.service.d/ship.conf
fi

sudo systemctl daemon-reload
sudo systemctl enable --now vps-sentry.timer

echo "Installed. Next:"
echo "  runtime: $RUNTIME_BIN"
echo "  sudo vps-sentry --format text"
echo "  sudo vps-sentry --accept-baseline"
