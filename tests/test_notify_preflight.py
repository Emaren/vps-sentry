from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
NOTIFY = ROOT / "deploy/usr-local/bin/vps-sentry-notify"


class NotifyPreflightTests(unittest.TestCase):
    def run_preflight(
        self, extra_env: dict[str, str], *, paused_webhook: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            if paused_webhook:
                marker_dir = state / "invalid-webhooks"
                marker_dir.mkdir(parents=True)
                fingerprint = hashlib.sha256(paused_webhook.encode()).hexdigest()[:40]
                (marker_dir / f"{fingerprint}.state").write_text(f"{int(time.time())}\n")
            env = os.environ.copy()
            env.update(
                {
                    "VPS_SENTRY_STATE_DIR": str(state),
                    "VPS_SENTRY_NOTIFY_ENV_FILE": str(root / "missing.env"),
                    "VPS_SENTRY_NOTIFY_CONFIG_JSON": str(root / "missing.json"),
                    "VPS_SENTRY_NOTIFY_ROUTE_INFO": "none",
                }
            )
            env.update(extra_env)
            return subprocess.run(
                [str(NOTIFY), "preflight"],
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )

    def test_explicit_smtp_email_routes_pass(self) -> None:
        proc = self.run_preflight(
            {
                "VPS_SENTRY_NOTIFY_EMAIL_PROVIDER": "smtp",
                "VPS_SENTRY_NOTIFY_EMAIL_SERVER": "smtp://user:pass@example.com:587",
                "VPS_SENTRY_NOTIFY_EMAIL_FROM": "sentinel@example.com",
                "VPS_SENTRY_NOTIFY_EMAIL_TO": "ops@example.com",
                "VPS_SENTRY_NOTIFY_ROUTE_WARN": "email",
                "VPS_SENTRY_NOTIFY_ROUTE_CRITICAL": "email",
            }
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("preflight=PASS", proc.stdout)
        self.assertIn("critical_state=PASS", proc.stdout)

    def test_missing_transport_fails(self) -> None:
        proc = self.run_preflight(
            {
                "VPS_SENTRY_NOTIFY_ROUTE_WARN": "email",
                "VPS_SENTRY_NOTIFY_ROUTE_CRITICAL": "email",
            }
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("preflight=FAIL", proc.stdout)
        self.assertIn("critical_state=FAIL", proc.stdout)

    def test_paused_webhook_does_not_count_as_ready(self) -> None:
        webhook = "https://discord.com/api/webhooks/123/test-token"
        proc = self.run_preflight(
            {
                "VPS_SENTRY_NOTIFY_WEBHOOK_URLS": webhook,
                "VPS_SENTRY_NOTIFY_ROUTE_WARN": "webhook",
                "VPS_SENTRY_NOTIFY_ROUTE_CRITICAL": "webhook",
            },
            paused_webhook=webhook,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("webhooks_total=1 webhooks_ready=0 webhooks_paused=1", proc.stdout)
        self.assertIn("preflight=FAIL", proc.stdout)

    def test_both_route_with_only_smtp_is_degraded(self) -> None:
        proc = self.run_preflight(
            {
                "VPS_SENTRY_NOTIFY_EMAIL_PROVIDER": "smtp",
                "VPS_SENTRY_NOTIFY_EMAIL_SERVER": "smtp://user:pass@example.com:587",
                "VPS_SENTRY_NOTIFY_EMAIL_FROM": "sentinel@example.com",
                "VPS_SENTRY_NOTIFY_EMAIL_TO": "ops@example.com",
                "VPS_SENTRY_NOTIFY_ROUTE_WARN": "both",
                "VPS_SENTRY_NOTIFY_ROUTE_CRITICAL": "both",
            }
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("preflight=DEGRADED", proc.stdout)
        self.assertIn("critical_state=DEGRADED", proc.stdout)


if __name__ == "__main__":
    unittest.main()
