"""VM-free regression checks for the historical artifact qualification harness."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location("historical_snapshots", Path(__file__).with_name("historical-snapshots.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class HistoricalSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_inventory_does_not_follow_external_symlinks_and_detects_payload_change(self):
        originals = self.root / "originals"
        originals.mkdir()
        external = self.root / "external"
        external.write_text("not part of snapshot")
        (originals / "link").symlink_to(external)
        (originals / "payload").write_text("original")
        before = smoke.inventory(originals)
        external.write_text("changed outside")
        self.assertEqual(smoke.inventory(originals), before)
        (originals / "payload").write_text("changed artifact")
        self.assertNotEqual(smoke.inventory(originals), before)
        self.assertEqual(before["link"], {"symlink": str(external)})

    def test_environment_uses_only_selected_runtime_and_agent(self):
        with patch.dict(os.environ, {"MSB_BACKEND": "cloud", "MSB_AGENTD_PATH": "/wrong", "DYLD_INSERT_LIBRARIES": "/inject"}):
            env = smoke.environment(self.root / "msb", self.root / "fw", self.root / "home")
        self.assertNotIn("MSB_AGENTD_PATH", env)
        self.assertNotIn("DYLD_INSERT_LIBRARIES", env)
        self.assertEqual(env["MSB_BACKEND"], "local")
        self.assertEqual(env["MSB_LIBKRUNFW_PATH"], str(self.root / "fw"))
        self.assertEqual(smoke.environment(self.root / "msb", self.root / "fw", self.root, self.root / "agent")["MSB_AGENTD_PATH"], str(self.root / "agent"))

    def test_failed_guest_command_is_recorded_and_not_counted_as_success(self):
        runner = smoke.Runner(Path(sys.executable), os.environ.copy(), self.root / "logs")
        with self.assertRaisesRegex(RuntimeError, "guest failed"):
            runner.run("guest", "-c", "import sys; print('corrupt'); sys.exit(7)")
        report = json.loads((runner.output / "commands.json").read_text())
        self.assertEqual(report[0]["exit"], 7)
        self.assertEqual((runner.output / "guest.stdout").read_text(), "corrupt\n")
        self.assertEqual(runner.run("cleanup", "-c", "raise SystemExit(1)", required=False), 1)

    def test_artifact_copy_is_private_not_a_hardlink(self):
        source = self.root / "original"
        source.mkdir()
        (source / "snapshot.json").write_text("original descriptor")
        destination = self.root / "working"
        smoke.copy_artifact(source, destination)
        copied = destination / "snapshot.json"
        self.assertNotEqual(copied.stat().st_ino, (source / "snapshot.json").stat().st_ino)
        copied.write_text("migrated descriptor")
        self.assertEqual((source / "snapshot.json").read_text(), "original descriptor")

    def test_descriptor_backup_must_preserve_exact_original_bytes(self):
        original, working = self.root / "original", self.root / "working"
        original.mkdir()
        working.mkdir()
        (original / "manifest.json").write_text('{ "schema": 1 }\n')
        (working / ".manifest.json.legacy").write_text('{"schema":1}')
        with self.assertRaisesRegex(RuntimeError, "original descriptor"):
            smoke.verify_descriptor_preservation(original, working)
        (working / ".manifest.json.legacy").write_bytes((original / "manifest.json").read_bytes())
        self.assertEqual(smoke.verify_descriptor_preservation(original, working), ".manifest.json.legacy")

    def test_cleanup_attempts_remove_even_if_stop_times_out(self):
        runner = Mock()
        runner.run.side_effect = [subprocess.TimeoutExpired("stop", 180), 0]
        result = smoke.cleanup(runner, "archive", "owned-fixture")
        self.assertIn("timed out", result["stop"])
        self.assertEqual(result["rm"], 0)
        self.assertEqual(runner.run.call_args.args[1:3], ("rm", "owned-fixture"))

    def test_interrupted_command_reaps_its_owned_process_group(self):
        runner = smoke.Runner(Path(sys.executable), {}, self.root / "logs")
        with patch.object(smoke.subprocess, "Popen") as spawn, patch.object(smoke.os, "killpg") as kill:
            child = spawn.return_value.__enter__.return_value
            child.pid = 12345
            child.wait.side_effect = [subprocess.TimeoutExpired("fixture", 180), 0]
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.run("timed-out", "-c", "pass")
        kill.assert_called_once_with(12345, smoke.signal.SIGKILL)
        self.assertEqual(child.wait.call_count, 2)
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        self.assertEqual(spawn.call_args.kwargs["stdin"], subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
