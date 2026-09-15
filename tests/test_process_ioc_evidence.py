import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


CORE_PATH = Path(__file__).resolve().parents[1] / "runtime" / "vps_sentry" / "core_legacy.py"


def load_core_module():
    spec = importlib.util.spec_from_file_location("vps_sentry_core_process_ioc_test", CORE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not create core_legacy module spec")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProcessIocEvidencePrecedenceTest(unittest.TestCase):
    def setUp(self):
        self.core = load_core_module()

    def _detect(self, ps_line, explained):
        with (
            patch.object(self.core, "run_cmd", return_value=(0, ps_line)),
            patch.object(self.core, "proc_explain", return_value=explained),
            patch.object(self.core, "temp_exec_hardening_state", return_value=None),
        ):
            return self.core.detect_suspicious_process_iocs({}, {})

    def test_resolved_system_executable_overrides_runtime_cwd_fallback(self):
        hits = self._detect(
            "558526 415865 2.3 sshd sshd sshd: [net]",
            {
                "exe": "/usr/sbin/sshd",
                "cwd": "/run/sshd",
                "unit": "ssh.service",
                "cmdline": "sshd: [net]",
            },
        )
        self.assertEqual(hits, [])

    def test_unresolved_relative_executable_still_uses_runtime_cwd_fallback(self):
        hits = self._detect(
            "4242 123 1.0 app worker worker",
            {
                "exe": "",
                "cwd": "/run/suspicious-worker",
                "unit": "example.service",
                "cmdline": "worker",
            },
        )
        self.assertEqual(len(hits), 1)
        self.assertIn(
            "relative executable launched from suspicious writable runtime cwd (/run/suspicious-worker)",
            hits[0]["reasons"],
        )

    def test_resolved_runtime_executable_remains_an_ioc(self):
        hits = self._detect(
            "4243 123 1.0 payload payload payload",
            {
                "exe": "/run/payload",
                "cwd": "/run",
                "unit": "example.service",
                "cmdline": "payload",
            },
        )
        self.assertEqual(len(hits), 1)
        self.assertIn("executable path is in suspicious writable runtime path", hits[0]["reasons"])


if __name__ == "__main__":
    unittest.main()
