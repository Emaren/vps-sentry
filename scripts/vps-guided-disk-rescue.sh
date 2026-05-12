#!/usr/bin/env bash
set -euo pipefail

TS="${VPS_SENTRY_RESCUE_TS:-$(date -u +%Y%m%dT%H%M%SZ)}"
TARGET_ROOT="${VPS_SENTRY_GUIDED_NODE_MODULES_TARGET_ROOT:-/mnt/HC_Volume_105319120/guided-node-modules}"

log() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"
}

run_sudo() {
  sudo "$@"
}

service_exists() {
  systemctl cat "$1" >/dev/null 2>&1
}

start_maintenance() {
  local scope="$1"
  local reason="$2"
  run_sudo /usr/local/bin/vps-sentry-maintenance start --scope "$scope" --ttl 20m --reason "$reason" >/dev/null 2>&1 || true
}

contain_cpu_logind() {
  log "containing cpu-logind and hardening aoe2dewarwagers-web /var/tmp"
  start_maintenance "aoe2dewarwagers-web.service" "contain cpu-logind"

  local pid=""
  pid="$(pgrep -f '[.]\/cpu-logind -c config.json|/var/tmp/[c]pu-logind' | head -1 || true)"
  if [[ -n "$pid" ]]; then
    local q="/var/lib/vps-sentry/quarantine/cpu-logind-$TS"
    log "quarantining cpu-logind pid=$pid to $q"
    run_sudo install -d -m 0700 -o root -g root "$q"
    run_sudo cp -L --preserve=mode,timestamps "/proc/$pid/exe" "$q/cpu-logind.proc-exe" 2>/dev/null || true
    run_sudo cp -a /var/tmp/cpu-logind "$q/cpu-logind.path" 2>/dev/null || true
    run_sudo cp -a /var/tmp/config.json "$q/config.json" 2>/dev/null || true
    run_sudo sh -c "sha256sum '$q'/* > '$q/SHA256SUMS' 2>/dev/null" || true
  else
    log "cpu-logind was not running when containment started"
  fi

  run_sudo systemctl stop aoe2dewarwagers-web.service || true
  while read -r stale_pid; do
    [[ -n "$stale_pid" ]] && run_sudo kill -9 "$stale_pid" || true
  done < <(pgrep -f '[.]\/cpu-logind -c config.json|/var/tmp/[c]pu-logind' || true)
  run_sudo rm -f /var/tmp/cpu-logind /var/tmp/config.json
  run_sudo install -d -m 0755 /etc/systemd/system/aoe2dewarwagers-web.service.d
  run_sudo tee /etc/systemd/system/aoe2dewarwagers-web.service.d/25-var-tmp-noexec.conf >/dev/null <<'EOF'
[Service]
TemporaryFileSystem=/var/tmp:rw,nosuid,nodev,noexec,size=128M
EOF
  run_sudo systemctl daemon-reload
  run_sudo systemctl start aoe2dewarwagers-web.service
  sleep 4
  systemctl is-active aoe2dewarwagers-web.service
  if pgrep -f '[.]\/cpu-logind -c config.json|/var/tmp/[c]pu-logind' >/dev/null; then
    log "ERROR: cpu-logind returned after service restart"
    return 1
  fi
  log "cpu-logind contained"
}

safe_reclaim() {
  log "running safe reclaim first"
  if run_sudo /usr/local/bin/vps-sentry-garbage-reclaim --json --profile safe >"/tmp/vps-sentry-safe-reclaim-$TS.json"; then
    log "safe reclaim completed"
  else
    log "safe reclaim returned nonzero; continuing to guided relocation"
  fi
}

relocate_node_modules() {
  local path="$1"
  local slug="$2"
  shift 2
  local units=("$@")
  local target="$TARGET_ROOT/$slug/node_modules"
  local state_file="/tmp/vpssentry-guided-units-$slug-$TS.txt"

  if [[ -L "$path" ]]; then
    log "skip $path; already a symlink to $(readlink -f "$path" || true)"
    return 0
  fi
  if [[ ! -d "$path" ]]; then
    log "skip $path; directory missing"
    return 0
  fi
  if [[ -e "$target" ]]; then
    log "ERROR: target already exists: $target"
    return 1
  fi

  log "relocating $path -> $target"
  : >"$state_file"
  for unit in "${units[@]}"; do
    if ! service_exists "$unit"; then
      printf '%s missing\n' "$unit" >>"$state_file"
      continue
    fi
    local state=""
    state="$(systemctl is-active "$unit" 2>/dev/null || true)"
    printf '%s %s\n' "$unit" "${state:-unknown}" >>"$state_file"
    if [[ "$state" == "active" || "$state" == "activating" ]]; then
      log "stopping $unit"
      start_maintenance "$unit" "guided node_modules relocation"
      run_sudo systemctl stop "$unit"
    fi
  done

  run_sudo install -d -m 0755 "$(dirname "$target")"
  run_sudo mv "$path" "$target"
  run_sudo ln -s "$target" "$path"
  local owner="tony:tony"
  owner="$(stat -c '%U:%G' "$(dirname "$path")" 2>/dev/null || echo tony:tony)"
  run_sudo chown -h "$owner" "$path"

  tac "$state_file" | while read -r unit state; do
    if [[ "$state" == "active" || "$state" == "activating" ]]; then
      log "starting $unit"
      run_sudo systemctl start "$unit"
      sleep 2
      systemctl is-active "$unit"
    fi
  done

  log "relocated $(du -sh "$target" 2>/dev/null | awk '{print $1}') from root for $slug"
}

main() {
  sudo -v
  log "before"
  df -h / /mnt/HC_Volume_105319120

  contain_cpu_logind
  safe_reclaim
  relocate_node_modules /var/www/AoE2HDBets/app-prodn/node_modules aoe2hdbets-app-prodn \
    aoe2hdbets-web.service aoe2hdbets-staking-rewards.service
  relocate_node_modules /var/www/WheatAndStone/ws-app/node_modules wheatandstone-ws-app \
    wheatandstone-app.service wheatandstone-fulfillment-automation.service wheatandstone-saved-match-automation.service
  relocate_node_modules /var/www/TokenTap/token-tap-app/node_modules tokentap-token-tap-app \
    tokentap-web.service
  relocate_node_modules /var/www/Traffic/traffic-app/node_modules traffic-traffic-app \
    traffic-web.service

  log "after relocation"
  df -h / /mnt/HC_Volume_105319120
  run_sudo /usr/local/bin/vps-sentry-garbage-estimate --force --json >"/tmp/vps-sentry-garbage-guided-$TS.json"
  run_sudo systemctl start vps-sentry.service
  log "final service states"
  systemctl is-active aoe2dewarwagers-web.service aoe2hdbets-web.service wheatandstone-app.service vps-sentry-web.service || true
  log "done"
}

main "$@"
