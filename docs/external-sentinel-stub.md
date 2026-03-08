# External Sentinel Stub

This is the off-box placeholder until a second VPS exists.

Current runner:

- `bin/vps-sentry-external-sentinel`

What it does right now:

- runs from an off-box machine such as the MBP
- checks a public URL
- keeps local incident state and failure counters
- uses the same incident model as `vps-sentry-notify`
- defaults to `stub` mode so it does not page yet

What "stub" means:

- it records when it would have opened an incident
- it records when it would have recovered
- it does not send email or webhooks until you flip it to `active`

What "active" means on the MBP:

- the MBP still only makes outbound connections
- one HTTPS probe goes to the public VPS Sentry ready endpoint
- email goes directly to your mail transport from the MBP
- no inbound port is opened on the MBP
- launchd runs a fixed local bundle under `~/Library/Application Support/VPSSentry/`

## Commands

```bash
bin/vps-sentry-external-sentinel check
bin/vps-sentry-external-sentinel status
bin/vps-sentry-external-sentinel example-env
```

## Recommended MBP Setup For Now

1. Install the launch agent:

```bash
./scripts/install-external-sentinel-mbp.sh
```

2. If you want to manage the config manually instead, copy the example config:

```bash
mkdir -p ~/.config/vps-sentry
bin/vps-sentry-external-sentinel example-env > ~/.config/vps-sentry/external-sentinel.env
```

3. Leave this line as-is for now:

```bash
VPS_SENTRY_EXTERNAL_SENTINEL_MODE=stub
```

4. Run it manually:

```bash
bin/vps-sentry-external-sentinel check
bin/vps-sentry-external-sentinel status
```

Launchd files:

```bash
~/Library/LaunchAgents/com.tony.vps-sentry-external-sentinel.plist
```

Installed bundle path:

```bash
~/Library/Application Support/VPSSentry/external-sentinel/
```

State path by default:

```bash
~/.local/state/vps-sentry/external-sentinel/
```

## When You Want Real Paging

Change:

```bash
VPS_SENTRY_EXTERNAL_SENTINEL_MODE=active
```

Then add working `VPS_SENTRY_NOTIFY_*` transport settings in the same env file.

## What This Does Not Solve Yet

- the MBP is not always on
- the MBP launch agent is still only a partial outside witness
- there is no second independent host yet

So this is useful as:

- a code stub
- a manual or MBP-assisted smoke checker
- a future-ready runner for a second VPS

## Removing The MBP Agent

```bash
./scripts/uninstall-external-sentinel-mbp.sh
```
