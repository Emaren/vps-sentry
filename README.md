# vps-sentry

Tiny VPS security monitor + ship hook, designed for systemd.

## What it does
Runs on a systemd timer (default: every 5 minutes):

- Checks SSH auth signals (failed password / invalid user)
- Checks for unexpected public listening ports
- Checks watched files/dirs for changes
- Writes JSON state under `/var/lib/vps-sentry/`
- Optionally “ships” a bundle when a real alert occurs

## Useful commands

Run once (manual):
```bash
sudo systemctl start vps-sentry.service
sudo vps-sentry --format text
sudo jq '.alerts' /var/lib/vps-sentry/last.json
```
