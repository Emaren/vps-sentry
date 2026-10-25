"""Verify source-only event unit lifecycle. Never connects to HEL1."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "deploy/systemd/vps-sentry-unit-event@.service"
HOOK = ROOT / "deploy/usr-local/bin/vps-sentry-service-event"
NOTIFY = ROOT / "deploy/usr-local/bin/vps-sentry-notify"
PROJECT_META = ROOT / "deploy/usr-local/bin/vps-sentry-project-meta"


class UnitEventLifecycleTests(unittest.TestCase):
    def test_event_oneshots_have_no_shared_runtime_directory(self) -> None:
        unit = UNIT.read_text()
        self.assertNotRegex(unit, r"(?m)^\s*RuntimeDirectory\s*=")
        self.assertNotRegex(unit, r"(?m)^\s*ReadWritePaths\s*=.*\/run\/")
        self.assertIn("StateDirectory=vps-sentry", unit)
        self.assertIn("StateDirectoryMode=0711", unit)
        self.assertIn("ReadWritePaths=/var/lib/vps-sentry", unit)
        self.assertIn("ExecStart=/usr/local/bin/vps-sentry-service-event --spec %i", unit)
        for guard in (
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "RestrictNamespaces=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
            "TimeoutStartSec=45s",
        ):
            self.assertIn(guard, unit)

    def test_dependencies_use_persistent_state_not_shared_run(self) -> None:
        for source in (HOOK, NOTIFY, PROJECT_META):
            self.assertNotIn("/run/vps-sentry", source.read_text(), str(source))
        self.assertIn('evidence_root="$STATE_DIR/incidents/evidence"', HOOK.read_text())

    def test_concurrent_started_and_stopped_hooks_use_only_scratch_state(self) -> None:
        # Source behavior fixture, NOT an observed production systemd test,
        # real notification receipt, or proof HEL1 has installed the unit.
        with tempfile.TemporaryDirectory() as tmp_path:
            tmp = Path(tmp_path)
            state = tmp / "state"
            log = tmp / "notifications.txt"
            notify = tmp / "notify"
            notify.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$VPS_SENTRY_TEST_LOG"\n')
            notify.chmod(0o755)

            def fake_systemctl(event: str, active: bool) -> Path:
                stub = tmp / f"systemctl-{event}"
                status = "0" if active else "3"
                stub.write_text(
                    "#!/bin/sh\n"
                    f'if [ "$1" = "is-active" ]; then exit {status}; fi\n'
                    'printf "%s\\n" "$1"\n'
                )
                stub.chmod(0o755)
                return stub

            processes = []
            for event, active in (("started", True), ("stopped", False)):
                env = dict(
                    os.environ,
                    VPS_SENTRY_STATE_DIR=str(state),
                    VPS_SENTRY_NOTIFY_BIN=str(notify),
                    VPS_SENTRY_SYSTEMCTL_BIN=str(fake_systemctl(event, active)),
                    VPS_SENTRY_JOURNALCTL_BIN="/bin/true",
                    VPS_SENTRY_PROJECT_META_BIN=str(tmp / "missing-project-meta"),
                    VPS_SENTRY_TEST_LOG=str(log),
                )
                proc = subprocess.Popen(
                    ["bash", str(HOOK), "--spec", f"{event}__ssh.service"],
                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                processes.append((event, proc))
            for event, proc in processes:
                stdout, stderr = proc.communicate(timeout=12)
                self.assertEqual(proc.returncode, 0, f"{event}: {stdout} {stderr}")
            self.assertCountEqual(log.read_text().splitlines(), ["recover", "alert"])
            self.assertTrue((state / "incidents" / "evidence").is_dir())


if __name__ == "__main__":
    unittest.main()
