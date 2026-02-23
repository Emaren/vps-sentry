# Admin shell + SSH + ownership rules (VPS)

## Why `as-tony` / `as-root` exist

We often connect VS Code Remote-SSH as `root` so we can save `/etc/*` and other root-owned files.
But apps/services run as `tony` (e.g. systemd units with `User=tony`), so builds/install steps should run as `tony`
to avoid root-owned `.next/`, `node_modules/`, caches, logs, etc.

## Commands

- Run system/admin ops:
  - `as-root 'systemctl restart vps-sentry-web.service'`
  - `as-root 'journalctl -u vps-sentry-web.service -n 80 --no-pager'`

- Run app/dev ops without ownership pain:
  - `as-tony 'cd /var/www/VPSSentry/vps-sentry-web && pnpm -s build'`

## Scripts are versioned

Repo source-of-truth:
- `deploy/usr-local/bin/*`

Install them (with timestamped backups):
- `scripts/install-usr-local-bin.sh`

## SSH hardening intent

- Key-only SSH (no passwords)
- Allow only required users:
  - `AllowUsers tony root`
- Root login is key-only (`PermitRootLogin prohibit-password` / `without-password`)