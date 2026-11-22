"""One-object Sentry L1 root cache source guards (fixture only, no host operations)."""
from __future__ import annotations
import importlib.machinery
import importlib.util
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "deploy/usr-local/bin/vps-sentry-garbage-estimate"
LOADER = importlib.machinery.SourceFileLoader("sentry_exact_one_source", str(SOURCE))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
MODULE = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(MODULE)


class ExactSingleCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sentry-exact-cache-", dir=".")
        self.addCleanup(self.tmp.cleanup)
        self.path = pathlib.Path(self.tmp.name).resolve() / "cache"
        self.path.mkdir(mode=0o700)
        (self.path / "generated.json").write_text('{"generated":true}')
        self.assertEqual(self.path.stat().st_dev, os.stat("/").st_dev)
        self.uuid = "test-root-uuid"
        self.quarantine = self.path.parent / "protected-quarantine"
        self.bytes = 65536
        self.pinner = mock.patch.object(MODULE, "EXACT_SENTRY_NEXT_CACHE", self.path)
        self.uinner = mock.patch.object(MODULE, "EXACT_SENTRY_ROOT_UUID", self.uuid)
        self.qpinner = mock.patch.object(MODULE, "EXACT_SENTRY_QUARANTINE", self.quarantine)
        self.qowner = mock.patch.object(MODULE, "EXACT_QUARANTINE_OWNER_UID", os.geteuid())
        self.sizer = mock.patch.object(MODULE, "path_disk_bytes", return_value=self.bytes)
        self.mountinfo = mock.patch.object(MODULE.Path, "read_text", autospec=True, side_effect=self._read_text)
        self.pinner.start()
        self.uinner.start()
        self.qpinner.start()
        self.qowner.start()
        self.sizer.start()
        self.mountinfo.start()
        self.addCleanup(self.pinner.stop)
        self.addCleanup(self.uinner.stop)
        self.addCleanup(self.qpinner.stop)
        self.addCleanup(self.qowner.stop)
        self.addCleanup(self.sizer.stop)
        self.addCleanup(self.mountinfo.stop)
        self.calls = []
        self.proc = mock.patch.object(MODULE.subprocess, "run", side_effect=self._fake_cmd)
        self.proc.start()
        self.addCleanup(self.proc.stop)
        self.item = {
            "id": "remove_path:" + str(self.path), "path": str(self.path),
            "key": "next_cache", "risk": "safe", "category": "recycling",
            "action": "remove_path", "bytes": self.bytes,
        }
        self.exact = {
            "id": self.item["id"], "dev": self.path.stat().st_dev,
            "inode": self.path.stat().st_ino, "bytes": self.bytes, "uuid": self.uuid,
        }
        self.fd_occupied = False

    def _read_text(self, target, *args, **kwargs):
        if str(target) == "/proc/self/mountinfo":
            return ""
        raise AssertionError("unexpected source text")

    def _fake_cmd(self, argv, **kwargs):
        self.calls.append(argv[0])
        if argv[0] == "findmnt":
            return subprocess.CompletedProcess(argv, 0, stdout=self.uuid + "\n", stderr="")
        if argv[0] == "lsof":
            return subprocess.CompletedProcess(argv, 0 if self.fd_occupied else 1,
                                               stdout="COMMAND PID FD NAME" if self.fd_occupied else "",
                                               stderr="")
        raise AssertionError("unexpected host command")

    def test_positive_one_object_preflight_is_not_prune(self):
        self.assertEqual(MODULE.qualify_exact_sentry_cache(self.item, self.exact), self.path)
        self.assertTrue(self.path.exists())
        self.assertEqual(self.calls, ["findmnt", "lsof"])

    def test_positive_one_object_delete_only_fixture(self):
        good, detail = MODULE.remove_exact_sentry_cache(self.item, self.exact)
        self.assertTrue(good, detail)
        self.assertFalse(self.path.exists())
        self.assertTrue(self.path.parent.exists())
        self.assertFalse(list(self.quarantine.glob("one-sentry-cache-*")))

    def test_wrong_candidate_class_never_deletes(self):
        for key, value in (
            ("key", "node_modules"), ("risk", "guided"),
            ("action", "guided_review"), ("category", "guided"),
        ):
            with self.subTest(key=key):
                x = dict(self.item, **{key: value})
                self.assertFalse(MODULE.remove_exact_sentry_cache(x, self.exact)[0])
                self.assertTrue(self.path.exists())

    def test_old_inode_and_filesystem_refused(self):
        for key, value in (("inode", self.exact["inode"] + 1),
                           ("dev", self.exact["dev"] + 1),
                           ("bytes", self.bytes + 1), ("uuid", "wrong")):
            with self.subTest(key=key):
                x = dict(self.exact, **{key: value})
                self.assertFalse(MODULE.remove_exact_sentry_cache(self.item, x)[0])
                self.assertTrue(self.path.exists())

    def test_missing_cache_and_replay_are_not_success(self):
        self.assertTrue(MODULE.remove_exact_sentry_cache(self.item, self.exact)[0])
        self.assertFalse(MODULE.remove_exact_sentry_cache(self.item, self.exact)[0])

    def test_nested_symlink_does_not_traverse(self):
        (self.path / "reference").symlink_to(self.path.parent, target_is_directory=True)
        self.assertFalse(MODULE.remove_exact_sentry_cache(self.item, self.exact)[0])
        self.assertTrue(self.path.exists())

    def test_hardlinked_original_does_not_prune(self):
        os.link(self.path / "generated.json", self.path.parent / "original.json")
        self.assertFalse(MODULE.remove_exact_sentry_cache(self.item, self.exact)[0])
        self.assertTrue((self.path.parent / "original.json").exists())

    def test_active_fd_blocks(self):
        self.fd_occupied = True
        self.assertFalse(MODULE.remove_exact_sentry_cache(self.item, self.exact)[0])
        self.assertTrue(self.path.exists())

    def test_class_size_cap(self):
        x = dict(self.exact, bytes=513 * 1024 * 1024)
        self.assertFalse(MODULE.remove_exact_sentry_cache(self.item, x)[0])

    def test_wrong_path_cannot_select_different_project(self):
        x = dict(self.item, path=str(self.path.parent / "elsewhere"))
        self.assertFalse(MODULE.remove_exact_sentry_cache(x, self.exact)[0])

    def test_absent_one_login_capability_is_not_faked(self):
        # The original owner session issuer is a separate admission. This
        # source exactness guard never claims to have minted one.
        self.assertNotIn("owner_signature", self.exact)
        self.assertFalse(hasattr(MODULE, "issue_owner_signature"))

    def test_cli_wrong_or_incomplete_scope_fails_before_lock(self):
        with mock.patch.object(sys, "argv", [
            str(SOURCE), "--reclaim", "--profile", "recycling",
            "--exact-object-id", self.item["id"],
        ]):
            self.assertEqual(MODULE.main(), 1)
        self.assertTrue(self.path.exists())


if __name__ == "__main__":
    unittest.main()
