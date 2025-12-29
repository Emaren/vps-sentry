#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

sudo install -m 0755 bin/vps-sentry          /usr/local/bin/vps-sentry
sudo install -m 0755 bin/vps-sentry-ship     /usr/local/bin/vps-sentry-ship
sudo install -m 0755 bin/vps-sentry-selftest /usr/local/bin/vps-sentry-selftest

sudo install -m 0644 systemd/system/vps-sentry.service /etc/systemd/system/vps-sentry.service
sudo install -m 0644 systemd/system/vps-sentry.timer   /etc/systemd/system/vps-sentry.timer

sudo mkdir -p /etc/systemd/system/vps-sentry.service.d
if [[ -f systemd/vps-sentry.service.d/ship.conf ]]; then
  sudo install -m 0644 systemd/vps-sentry.service.d/ship.conf /etc/systemd/system/vps-sentry.service.d/ship.conf
fi

sudo systemctl daemon-reload
sudo systemctl enable --now vps-sentry.timer

echo "Installed. Next:"
echo "  sudo vps-sentry --format text"
echo "  sudo vps-sentry --accept-baseline"
