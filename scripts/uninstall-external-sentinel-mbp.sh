#!/usr/bin/env bash
set -euo pipefail

LABEL="com.tony.vps-sentry-external-sentinel"
PLIST_FILE="$HOME/Library/LaunchAgents/$LABEL.plist"
DOMAIN="gui/$(id -u)"
INSTALL_ROOT="$HOME/Library/Application Support/VPSSentry/external-sentinel"

launchctl bootout "$DOMAIN" "$PLIST_FILE" >/dev/null 2>&1 || true
rm -f "$PLIST_FILE"
rm -rf "$INSTALL_ROOT"

echo "Removed $LABEL"
