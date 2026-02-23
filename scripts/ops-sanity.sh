#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== install /usr/local/bin from repo"
sudo "$REPO_DIR/scripts/install-usr-local-bin.sh"

echo
echo "=== audit drift"
sudo "$REPO_DIR/scripts/audit-usr-local-bin.sh"

echo
echo "=== systemd quick checks"
sudo systemctl is-enabled vps-sentry.service vps-sentry-web.service >/dev/null && echo "systemd enabled: OK"

echo "OK: ops sanity complete"