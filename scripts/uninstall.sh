#!/usr/bin/env bash
set -euo pipefail

sudo systemctl disable --now vps-sentry.timer 2>/dev/null || true

sudo rm -f /usr/local/bin/vps-sentry \
           /usr/local/bin/vps-sentry-ship \
           /usr/local/bin/vps-sentry-selftest

sudo rm -f /etc/systemd/system/vps-sentry.service \
           /etc/systemd/system/vps-sentry.timer \
           /etc/systemd/system/vps-sentry.service.d/ship.conf

sudo rmdir /etc/systemd/system/vps-sentry.service.d 2>/dev/null || true

sudo systemctl daemon-reload
echo "Uninstalled. (State in /var/lib/vps-sentry is untouched.)"
