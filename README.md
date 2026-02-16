# vps-sentry

Tiny VPS security monitor + "ship" hook, designed for systemd.

## What it does

Runs on a systemd timer (default: every 5 minutes):

* Checks SSH auth signals (failed password / invalid user / new accepts)
* Checks for unexpected **public** listening ports
* Checks watched files/dirs for changes (tripwires)
* Records JSON state under `/var/lib/vps-sentry/`
* Optionally "ships" a bundle when a **real** alert occurs

## Feature ranking (most impressive -> least)

1. **Critical runtime IOC detection**  
   Detects high-fanout outbound scan behavior and suspicious process IOC patterns, then raises immediate `critical` alerts.
2. **Threat telemetry for UI/API**  
   Publishes structured `threat` data (`suspicious_processes`, `outbound_suspicious`, `persistence_hits`, `indicators`) into `status.json`.
3. **Wide host drift coverage in one agent**  
   Correlates auth noise, public listeners, users, watched security paths, cron, firewall, self-integrity, and package drift.
4. **Self-integrity + service integrity checks**  
   Watches hashes for `/usr/local/bin/vps-sentry` and `vps-sentry.service` and treats integrity drift as high severity.
5. **Baseline signing guardrails (v1.0.0 runtime)**  
   Supports baseline signature verification/re-signing flow to reduce tamper risk on baseline artifacts.
6. **Sensitive-change forensics capture**  
   Captures SSHD and firewall forensic artifacts when those surfaces change.
7. **Actionable public-port intelligence**  
   Detects public listener drift and enriches alerts with PID/unit/exe/cmdline process attribution.
8. **Publish + normalize pipeline for dashboards**  
   Generates sanitized `/var/lib/vps-sentry/public/status.json` and computes expected vs unexpected public ports.
9. **Noise controls + memory of seen SSH identities**  
   Uses thresholds, webhook cooldowns, and TTL-based "new SSH accept" memory to reduce repeat spam.
10. **Dual-channel notifications + evidence shipping**  
    Supports Discord/email notifications and controlled outbox bundle shipping when alerts are present.
11. **Hardened systemd posture**  
    Applies restrictive service settings (`ProtectSystem=strict`, reduced address families, private temp/devices, etc).
12. **Deterministic self-test tooling**  
    Includes `vps-sentry-selftest` for repeatable validation of local and optional network shipping behavior.

## Requirements

* systemd-based Linux
* bash
* sudo/root
* Runtime binary at `/opt/vps-sentry/venv/bin/vps-sentry` (or set `VPS_SENTRY_RUNTIME` to a different executable)
* Runtime package `vps_sentry` importable in that runtime venv
* Installs wrappers/units to `/usr/local/bin` and `/etc/systemd/system`

## Quickstart (recommended)

The repo includes an installer script so you don’t have to copy/paste a giant block forever.

1. `cd ~/repos/vps-sentry`

2. (Optional) if your runtime is not at the default path, set an override:

   ```
   export VPS_SENTRY_RUNTIME=/path/to/vps-sentry
   ```

   `./scripts/install.sh` will persist this to `/etc/default/vps-sentry` so systemd uses the same runtime path.
   Or write `/etc/default/vps-sentry` manually:

   ```
   VPS_SENTRY_RUNTIME=/path/to/vps-sentry
   ```

   Keep `/etc/default/vps-sentry` owned by `root:root` and not group/other writable.

3. Install + enable timer

   ```
   ./scripts/install.sh
   ```

4. One human-friendly run + accept baseline (locks in "known good")

   ```
   sudo vps-sentry --format text
   sudo vps-sentry --accept-baseline
   ```

5. Confirm timer is active + see last logs

   ```
   sudo systemctl status vps-sentry.timer --no-pager -l
   sudo systemctl status vps-sentry.service --no-pager -l
   sudo systemctl status vps-sentry-ship.service --no-pager -l
   sudo systemctl list-timers --all | grep vps-sentry
   sudo journalctl -u vps-sentry.service -n 50 --no-pager
   sudo journalctl -u vps-sentry-ship.service -n 50 --no-pager
   ```

## Upgrade

* `git pull`
* `./scripts/install.sh` (reinstalls binaries/units; syncs tracked runtime detector source; timer stays enabled)

If you intentionally changed watched things, re-accept baseline:

* `sudo vps-sentry --accept-baseline`

## Uninstall

1. `cd ~/repos/vps-sentry`
2. `./scripts/uninstall.sh`

Note: uninstall does **not** delete runtime state under `/var/lib/vps-sentry/`.
It does remove `/etc/default/vps-sentry` if present.

## Reset state (danger)

If you want a completely fresh baseline/state:

1. `./scripts/uninstall.sh` (stops/disables timer)
2. `sudo rm -rf /var/lib/vps-sentry`
3. `./scripts/install.sh`
4. `sudo vps-sentry --accept-baseline`

## Self-test

Run deterministic local checks (no webhook delivery requirement):

* `sudo vps-sentry-selftest`

Run full checks including required webhook shipping:

* `sudo vps-sentry-selftest --with-network`

## Troubleshooting

If you see:

* `./scripts/install.sh: Permission denied`

  * Scripts aren’t executable in your clone. Fix once:

    ```
    chmod +x scripts/install.sh scripts/uninstall.sh
    ```

    (Recommended: commit the exec bit so future clones don’t need this.)

* `vps-sentry: command not found`

  * Installer didn’t run, or binaries were removed. Re-run `./scripts/install.sh`.

* `vps-sentry: runtime binary not found or not executable`

  * The wrapper can’t find the real runtime executable.
  * Default expected path is `/opt/vps-sentry/venv/bin/vps-sentry`.
  * Fix by installing the runtime there, or set `VPS_SENTRY_RUNTIME` (and optionally persist it in `/etc/default/vps-sentry`).
  * If `/etc/default/vps-sentry` exists, it must be `root:root` and not group/other writable.

* `Unit vps-sentry.service not found / Unit vps-sentry.timer not found / Failed to start vps-sentry.service: Unit vps-sentry.service not found`

  * systemd units aren’t installed (or were removed). Re-run `./scripts/install.sh` (then sudo systemctl daemon-reload if needed)

* Units exist on disk but systemd still can’t find them

  * run: `sudo systemctl daemon-reload`

* Timer is active but you want to force a run right now

  * `sudo systemctl start vps-sentry.service`
  * `sudo journalctl -u vps-sentry.service -n 80 --no-pager`

* Ship service appears idle or not sending bundles

  * `sudo systemctl status vps-sentry-ship.service --no-pager -l`
  * `sudo journalctl -u vps-sentry-ship.service -n 120 --no-pager`
  * Shipping now logs explicit skip/failure reasons (missing config, duplicate ts, test-only alert, webhook parse failure, upload failure).
  * Preferred config key is `notify.discord.webhook_url` in `/etc/vps-sentry.json` (recursive fallback still supported).

## Files + paths

Binaries (installed):

* `/usr/local/bin/vps-sentry`
* `/usr/local/bin/vps-sentry-ship`
* `/usr/local/bin/vps-sentry-selftest`
* `/usr/local/bin/vps-sentry-publish`
* `/usr/local/bin/vps-sentry-ports-normalize`

Systemd units (installed):

* `/etc/systemd/system/vps-sentry.service`
* `/etc/systemd/system/vps-sentry.timer`
* `/etc/systemd/system/vps-sentry-ship.service`
* `/etc/systemd/system/vps-sentry.service.d/90-post.conf`
* `/etc/systemd/system/vps-sentry.service.d/95-expected-ports.conf` (installed if missing; existing customized file is preserved)

State (runtime):

* `/var/lib/vps-sentry/` (baseline, last run, diffs, ship marker, etc.)
* `/var/lib/vps-sentry/public/` (`status.json`, `last.json`, `diff.json` published for UI/API)

Repo source of truth:

* `deploy/systemd/` (all unit/drop-in files installed by `scripts/install.sh`)
* `runtime/vps_sentry/core_legacy.py` (tracked runtime IOC detection source synced into installed venv by `scripts/install.sh`)
