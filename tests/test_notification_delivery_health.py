"""VPS Sentry notification transport evidence (no external network)."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
NOTIFY = ROOT / "deploy/usr-local/bin/vps-sentry-notify"


class DeliveryHealthTests(unittest.TestCase):
    def fixture(self, temp: str, **changes: str) -> tuple[dict[str, str], Path]:
        root = Path(temp)
        state = root / "state"
        webhook = root / "fake-curl"
        webhook.write_text("#!/bin/sh\nprintf '204'\n")
        webhook.chmod(0o755)
        sendmail = root / "fake-sendmail"
        sendmail.write_text("#!/bin/sh\nexit 75\n")
        sendmail.chmod(0o755)
        env = dict(
            os.environ,
            VPS_SENTRY_STATE_DIR=str(state),
            VPS_SENTRY_NOTIFY_ENV_FILE=str(root / "absent.env"),
            VPS_SENTRY_NOTIFY_CONFIG_JSON=str(root / "absent.json"),
            VPS_SENTRY_MAINTENANCE_BIN=str(root / "absent-maintenance"),
            VPS_SENTRY_PROJECT_META_BIN=str(root / "absent-project-meta"),
            VPS_SENTRY_NOTIFY_CURL_BIN=str(webhook),
            VPS_SENTRY_NOTIFY_SENDMAIL_BIN=str(sendmail),
            VPS_SENTRY_NOTIFY_MAIL_BIN=str(root / "absent-mail"),
            VPS_SENTRY_NOTIFY_EMAIL_PROVIDER="sendmail",
            VPS_SENTRY_NOTIFY_EMAIL_TO="alerts@example.test",
            VPS_SENTRY_NOTIFY_EMAIL_FROM="sentry@example.test",
            VPS_SENTRY_NOTIFY_WEBHOOK_URLS="https://discord.com/api/webhooks/test/fake",
            VPS_SENTRY_NOTIFY_ROUTE_CRITICAL="webhook",
        )
        env.update(changes)
        return env, state

    def invoke(self, env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(NOTIFY), *args],
            env=env, text=True, capture_output=True, check=False, timeout=15,
        )

    def alert(self, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return self.invoke(
            env, "alert", "--fingerprint", "unit:ssh.service",
            "--severity", "critical", "--source", "systemd-hook",
            "--host", "test-host", "--project", "vps-host",
            "--service", "ssh.service", "--title", "SSH state test",
            "--detail", "fixture, no real service state",
        )

    def incident(self, state: Path) -> str:
        incidents = list((state / "incidents" / "open").glob("*.state"))
        self.assertEqual(len(incidents), 1)
        return incidents[0].read_text()

    def test_health_is_read_only_and_unknown_without_original_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            env, state = self.fixture(temp)
            health = self.invoke(env, "delivery-health")
            self.assertEqual(health.returncode, 2, health.stderr)
            self.assertIn("delivery_state=UNKNOWN", health.stdout)
            self.assertFalse(state.exists(), "read-only view must not create state")

    def test_deliberately_disabled_alert_never_sets_open_notified(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            env, state = self.fixture(temp, VPS_SENTRY_NOTIFY_ROUTE_CRITICAL="none")
            sent = self.alert(env)
            self.assertEqual(sent.returncode, 1, sent.stderr)
            incident = self.incident(state)
            self.assertIn("OPEN_NOTIFIED=0", incident)
            self.assertIn("LAST_DELIVERY_STATUS=DISABLED", incident)
            health = self.invoke(env, "delivery-health")
            self.assertEqual(health.returncode, 1, health.stdout)
            self.assertIn("evidence_state=FAIL", health.stdout)
            self.assertIn("transport_state=DISABLED", health.stdout)

    def test_failed_configured_transport_returns_nonzero_with_durable_incident(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            env, state = self.fixture(
                temp, VPS_SENTRY_NOTIFY_ROUTE_CRITICAL="email",
            )
            sent = self.alert(env)
            self.assertEqual(sent.returncode, 1, sent.stderr)
            incident = self.incident(state)
            self.assertIn("OPEN_NOTIFIED=0", incident)
            self.assertIn("LAST_DELIVERY_STATUS=FAILED", incident)
            self.assertIn("LAST_DELIVERY_EMAIL_FAILED=1", incident)
            health = self.invoke(env, "delivery-health")
            self.assertEqual(health.returncode, 1, health.stdout)
            self.assertIn("evidence_state=FAIL", health.stdout)

    def test_partial_webhook_submission_and_failed_email_remains_degraded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            env, state = self.fixture(temp, VPS_SENTRY_NOTIFY_ROUTE_CRITICAL="both")
            sent = self.alert(env)
            self.assertEqual(sent.returncode, 0, sent.stderr)
            incident = self.incident(state)
            self.assertIn("OPEN_NOTIFIED=1", incident)
            self.assertIn("LAST_DELIVERY_STATUS=DEGRADED_UNVERIFIED", incident)
            self.assertIn("LAST_DELIVERY_WEBHOOK_SUBMITTED=1", incident)
            self.assertIn("LAST_DELIVERY_EMAIL_FAILED=1", incident)
            health = self.invoke(env, "delivery-health")
            self.assertEqual(health.returncode, 1, health.stdout)
            self.assertIn("evidence_state=FAIL", health.stdout)
            self.assertNotIn("evidence_state=PASS", health.stdout)
            self.assertNotIn("https://discord.com/api/webhooks/", health.stdout)

    def test_webhook_http_success_is_transport_only_not_end_to_end_green(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            env, state = self.fixture(temp)
            sent = self.alert(env)
            self.assertEqual(sent.returncode, 0, sent.stderr)
            incident = self.incident(state)
            self.assertIn("OPEN_NOTIFIED=1", incident)
            self.assertIn("LAST_DELIVERY_STATUS=SUBMITTED_UNVERIFIED", incident)
            health = self.invoke(env, "delivery-health")
            self.assertEqual(health.returncode, 2, health.stdout)
            self.assertIn("evidence_state=UNKNOWN", health.stdout)
            self.assertIn("original_sink_receipt=UNKNOWN", health.stdout)

    def test_expired_transport_does_not_rewrite_original_capture_time(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            env, state = self.fixture(temp, VPS_SENTRY_NOTIFY_DELIVERY_TTL_SECONDS="1")
            sent = self.alert(env)
            self.assertEqual(sent.returncode, 0, sent.stderr)
            incident_path = next((state / "incidents" / "open").glob("*.state"))
            original = incident_path.read_text()
            incident_path.write_text(
                original.replace(
                    "LAST_DELIVERY_TS=" + next(
                        x.split("=", 1)[1] for x in original.splitlines()
                        if x.startswith("LAST_DELIVERY_TS=")
                    ),
                    r"LAST_DELIVERY_TS=2026-01-01T00:00:00Z",
                )
            )
            health = self.invoke(env, "delivery-health")
            self.assertEqual(health.returncode, 2, health.stdout)
            self.assertIn("evidence_state=STALE", health.stdout)


if __name__ == "__main__":
    unittest.main()
