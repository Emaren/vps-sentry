# vps-sentry

Tiny VPS security monitor + "ship" hook, designed for systemd.

## What it does

Runs on a systemd timer (default: every 5 minutes):

* Checks SSH auth signals (failed password / invalid user / new accepts)
* Checks for unexpected **public** listening ports
* Checks watched files/dirs for changes (tripwires)
* Records JSON state under `/var/lib/vps-sentry/`
* Optionally "ships" a bundle when a **real** alert occurs

## Requirements

* systemd-based Linux
* bash
* sudo/root
* Installs to `/usr/local/bin` and `/etc/systemd/system`

## Quickstart (recommended)

The repo includes an installer script so you don’t have to copy/paste a giant block forever.

1. `cd ~/repos/vps-sentry`

2. Install + enable timer

   ```
   ./scripts/install.sh
   ```

3. One human-friendly run + accept baseline (locks in "known good")

   ```
   sudo vps-sentry --format text
   sudo vps-sentry --accept-baseline
   ```

4. Confirm timer is active + see last logs

   ```
   sudo systemctl status vps-sentry.timer --no-pager -l
   sudo systemctl status vps-sentry.service --no-pager -l
   sudo systemctl list-timers --all | grep vps-sentry
   sudo journalctl -u vps-sentry.service -n 50 --no-pager
   ```

## Upgrade

* `git pull`
* `./scripts/install.sh` (reinstalls binaries/units; timer stays enabled)

If you intentionally changed watched things, re-accept baseline:

* `sudo vps-sentry --accept-baseline`

## Uninstall

1. `cd ~/repos/vps-sentry`
2. `./scripts/uninstall.sh`

Note: uninstall does **not** delete runtime state under `/var/lib/vps-sentry/`.

## Reset state (danger)

If you want a completely fresh baseline/state:

1. `./scripts/uninstall.sh` (stops/disables timer)
2. `sudo rm -rf /var/lib/vps-sentry`
3. `./scripts/install.sh`
4. `sudo vps-sentry --accept-baseline`

## Self-test

Run the built-in self test:

* `sudo vps-sentry-selftest`

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

* `Unit vps-sentry.service not found / Unit vps-sentry.timer not found / Failed to start vps-sentry.service: Unit vps-sentry.service not found`

  * systemd units aren’t installed (or were removed). Re-run `./scripts/install.sh` (then sudo systemctl daemon-reload if needed)

* Units exist on disk but systemd still can’t find them

  * run: `sudo systemctl daemon-reload`

* Timer is active but you want to force a run right now

  * `sudo systemctl start vps-sentry.service`
  * `sudo journalctl -u vps-sentry.service -n 80 --no-pager`

## Files + paths

Binaries (installed):

* `/usr/local/bin/vps-sentry`
* `/usr/local/bin/vps-sentry-ship`
* `/usr/local/bin/vps-sentry-selftest`

Systemd units (installed):

* `/etc/systemd/system/vps-sentry.service`
* `/etc/systemd/system/vps-sentry.timer`
* `/etc/systemd/system/vps-sentry.service.d/ship.conf` (optional)

State (runtime):

* `/var/lib/vps-sentry/` (baseline, last run, diffs, ship marker, etc.)
