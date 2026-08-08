import importlib.machinery
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "usr-local"
    / "bin"
    / "vps-sentry-project-storage"
)


def load_storage_module():
    loader = importlib.machinery.SourceFileLoader("vps_sentry_project_storage_test", str(SCRIPT_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError("could not create project-storage module spec")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class ProjectStorageContinuityTest(unittest.TestCase):
    def test_previous_snapshot_keeps_projects_and_refreshes_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            projects_file = Path(tmp) / "projects.json"
            state_dir.mkdir()
            projects_file.write_text(json.dumps({"host_filesystems": [], "projects": []}))

            with patch.dict(
                os.environ,
                {
                    "VPS_SENTRY_STATE_DIR": str(state_dir),
                    "VPS_SENTRY_PROJECTS_FILE": str(projects_file),
                },
            ):
                module = load_storage_module()

            module.LAST_JSON.write_text(
                json.dumps(
                    {
                        "alerts": [
                            {
                                "code": "service_hardening_gap",
                                "title": "Keep this unrelated alert",
                            }
                        ]
                    }
                )
            )
            previous = {
                "schema_version": module.SCHEMA_VERSION,
                "config_fingerprint": module.config_fingerprint(),
                "measured_at": "2026-08-08T18:00:00Z",
                "host_filesystem": {"path": "/", "used_percent": 80},
                "mounted_filesystems": [],
                "projects": {
                    "aoe2hdbets": {
                        "id": "aoe2hdbets",
                        "disk_bytes": 1234,
                        "measured_at": "2026-08-08T18:00:00Z",
                    }
                },
            }
            refreshed_host = {
                "path": "/",
                "used_percent": 84.0,
                "used_bytes": 84,
                "available_bytes": 16,
                "total_bytes": 100,
            }
            refreshed_mounts = [
                {
                    "id": "hetzner-volume",
                    "path": "/mnt/HC_Volume_105319120",
                    "used_percent": 93.2,
                }
            ]

            with (
                patch.object(module, "measure_host_filesystem", return_value=refreshed_host),
                patch.object(module, "measure_mounted_filesystems", return_value=refreshed_mounts),
            ):
                merged = module.merge_previous_snapshot_for_continuity(previous, module.load_config())

            self.assertTrue(merged)
            published = json.loads(module.LAST_JSON.read_text())
            storage = published["project_storage"]
            self.assertEqual(storage["projects"]["aoe2hdbets"]["disk_bytes"], 1234)
            self.assertEqual(storage["measured_at"], "2026-08-08T18:00:00Z")
            self.assertEqual(storage["host_filesystem"], refreshed_host)
            self.assertEqual(storage["mounted_filesystems"], refreshed_mounts)
            self.assertEqual(published["alerts"][0]["code"], "service_hardening_gap")

    def test_main_preserves_verified_storage_before_an_interrupted_refresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            projects_file = Path(tmp) / "projects.json"
            state_dir.mkdir()
            projects_file.write_text(json.dumps({"host_filesystems": [], "projects": []}))

            with patch.dict(
                os.environ,
                {
                    "VPS_SENTRY_STATE_DIR": str(state_dir),
                    "VPS_SENTRY_PROJECTS_FILE": str(projects_file),
                },
            ):
                module = load_storage_module()

            module.LAST_JSON.write_text(json.dumps({"alerts": []}))
            previous = {
                "schema_version": module.SCHEMA_VERSION,
                "config_fingerprint": module.config_fingerprint(),
                "measured_at": "2026-08-08T18:00:00Z",
                "host_filesystem": {"path": "/", "used_percent": 80},
                "mounted_filesystems": [],
                "projects": {
                    "aoe2hdbets": {
                        "id": "aoe2hdbets",
                        "disk_bytes": 1234,
                        "measured_at": "2026-08-08T18:00:00Z",
                    }
                },
            }
            refreshed_host = {
                "path": "/",
                "used_percent": 84.0,
                "used_bytes": 84,
                "available_bytes": 16,
                "total_bytes": 100,
            }
            refreshed_mounts = [
                {
                    "id": "hetzner-volume",
                    "path": "/mnt/HC_Volume_105319120",
                    "used_percent": 93.2,
                }
            ]

            with (
                patch.object(module, "load_previous_snapshot", return_value=previous),
                patch.object(module, "load_cached_snapshot", return_value=None),
                patch.object(module, "measure_host_filesystem", return_value=refreshed_host),
                patch.object(module, "measure_mounted_filesystems", return_value=refreshed_mounts),
                patch.object(module, "build_snapshot", side_effect=RuntimeError("scan interrupted")),
            ):
                with self.assertRaisesRegex(RuntimeError, "scan interrupted"):
                    module.main()

            published = json.loads(module.LAST_JSON.read_text())
            storage = published["project_storage"]
            self.assertEqual(storage["projects"]["aoe2hdbets"]["disk_bytes"], 1234)
            self.assertEqual(storage["measured_at"], "2026-08-08T18:00:00Z")
            self.assertEqual(storage["host_filesystem"], refreshed_host)
            self.assertEqual(storage["mounted_filesystems"], refreshed_mounts)


if __name__ == "__main__":
    unittest.main()
