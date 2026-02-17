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
need_cmd grep
need_cmd sed
need_cmd tail
need_cmd cmp
need_cmd python3
need_cmd curl
need_cmd tar
need_cmd find
need_cmd mktemp
need_cmd openssl
if ! command -v flock >/dev/null 2>&1; then
  warn "flock not found; shipping will run without overlap lock"
fi

DEFAULT_RUNTIME="/opt/vps-sentry/venv/bin/vps-sentry"
RUNTIME_BIN="${VPS_SENTRY_RUNTIME:-$DEFAULT_RUNTIME}"
UNIT_SRC_DIR="deploy/systemd"
RUNTIME_CORE_SOURCE="runtime/vps_sentry/core_legacy.py"

if [[ ! -d "$UNIT_SRC_DIR" ]]; then
  die "missing unit source directory: $UNIT_SRC_DIR"
fi
if [[ ! -f "$RUNTIME_CORE_SOURCE" ]]; then
  die "missing runtime core source file: $RUNTIME_CORE_SOURCE"
fi

runtime_python_for_bin() {
  local runtime_bin="$1" venv_dir py
  venv_dir="$(dirname "$runtime_bin")"
  for py in "$venv_dir/python3" "$venv_dir/python"; do
    if sudo test -x "$py"; then
      printf '%s' "$py"
      return 0
    fi
  done
  return 1
}

runtime_core_target_for_python() {
  local py="$1"
  sudo "$py" - <<'PY'
import inspect
import sys
try:
    import vps_sentry.core_legacy as m
    p = inspect.getsourcefile(m) or inspect.getfile(m)
    if not p:
        raise RuntimeError("core_legacy source path unavailable")
    print(p)
except Exception as e:
    print(f"ERROR:{e}")
    sys.exit(1)
PY
}

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
RUNTIME_PY="$(runtime_python_for_bin "$RUNTIME_BIN" || true)"
[[ -n "$RUNTIME_PY" ]] || die "unable to locate runtime python beside: $RUNTIME_BIN"

RUNTIME_CORE_TARGET="$(runtime_core_target_for_python "$RUNTIME_PY" || true)"
[[ -n "$RUNTIME_CORE_TARGET" ]] || die "failed to resolve runtime core_legacy.py target path"
if [[ "$RUNTIME_CORE_TARGET" == ERROR:* ]]; then
  die "failed to resolve runtime core_legacy.py target path: ${RUNTIME_CORE_TARGET#ERROR:}"
fi
if ! sudo test -f "$RUNTIME_CORE_TARGET"; then
  die "runtime core target does not exist: $RUNTIME_CORE_TARGET"
fi

# If the caller supplied an override runtime path, persist it for systemd runs.
if [[ -n "${VPS_SENTRY_RUNTIME:-}" ]]; then
  ESCAPED_RUNTIME="${VPS_SENTRY_RUNTIME//\'/\'\"\'\"\'}"
  printf "VPS_SENTRY_RUNTIME='%s'\n" "$ESCAPED_RUNTIME" | sudo tee /etc/default/vps-sentry >/dev/null
fi

sudo install -m 0755 bin/vps-sentry          /usr/local/bin/vps-sentry
sudo install -m 0755 bin/vps-sentry-ship     /usr/local/bin/vps-sentry-ship
sudo install -m 0755 bin/vps-sentry-selftest /usr/local/bin/vps-sentry-selftest
sudo install -m 0755 bin/vps-sentry-publish  /usr/local/bin/vps-sentry-publish
sudo install -m 0755 bin/vps-sentry-ports-normalize /usr/local/bin/vps-sentry-ports-normalize
sudo install -m 0755 bin/vps-sentry-evidence-seal /usr/local/bin/vps-sentry-evidence-seal
sudo install -m 0755 bin/vps-sentry-evidence-verify /usr/local/bin/vps-sentry-evidence-verify

# Keep runtime IOC engine source in sync with the tracked repo file.
sudo install -m 0644 "$RUNTIME_CORE_SOURCE" "$RUNTIME_CORE_TARGET"

sudo install -m 0644 "$UNIT_SRC_DIR/vps-sentry.service"      /etc/systemd/system/vps-sentry.service
sudo install -m 0644 "$UNIT_SRC_DIR/vps-sentry.timer"        /etc/systemd/system/vps-sentry.timer
sudo install -m 0644 "$UNIT_SRC_DIR/vps-sentry-ship.service" /etc/systemd/system/vps-sentry-ship.service

sudo install -d -m 0755 /etc/systemd/system/vps-sentry.service.d
sudo install -m 0644 "$UNIT_SRC_DIR/vps-sentry.service.d/90-post.conf" /etc/systemd/system/vps-sentry.service.d/90-post.conf
if sudo test -f /etc/systemd/system/vps-sentry.service.d/95-expected-ports.conf; then
  if ! sudo cmp -s "$UNIT_SRC_DIR/vps-sentry.service.d/95-expected-ports.conf" /etc/systemd/system/vps-sentry.service.d/95-expected-ports.conf; then
    warn "existing /etc/systemd/system/vps-sentry.service.d/95-expected-ports.conf differs; leaving in place"
  else
    sudo install -m 0644 "$UNIT_SRC_DIR/vps-sentry.service.d/95-expected-ports.conf" /etc/systemd/system/vps-sentry.service.d/95-expected-ports.conf
  fi
else
  sudo install -m 0644 "$UNIT_SRC_DIR/vps-sentry.service.d/95-expected-ports.conf" /etc/systemd/system/vps-sentry.service.d/95-expected-ports.conf
fi

# Remove a legacy ship.conf drop-in that clears ExecStartPost and can disable
# other host-specific ExecStartPost hooks (publish/normalize/etc).
if sudo test -f /etc/systemd/system/vps-sentry.service.d/ship.conf; then
  if sudo grep -Eq '^[[:space:]]*ExecStartPost[[:space:]]*=[[:space:]]*$' /etc/systemd/system/vps-sentry.service.d/ship.conf; then
    sudo rm -f /etc/systemd/system/vps-sentry.service.d/ship.conf
  else
    warn "found existing /etc/systemd/system/vps-sentry.service.d/ship.conf; leaving in place"
  fi
fi

sudo systemctl daemon-reload
sudo systemctl enable --now vps-sentry.timer

echo "Installed. Next:"
echo "  runtime: $RUNTIME_BIN"
echo "  runtime python: $RUNTIME_PY"
echo "  synced: $RUNTIME_CORE_SOURCE -> $RUNTIME_CORE_TARGET"
echo "  sudo vps-sentry --format text"
echo "  sudo vps-sentry --accept-baseline"
echo "  sudo vps-sentry-evidence-verify"
