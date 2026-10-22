from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.work = Path(self.temp.name)
        shutil.copytree(REPO / "fixtures" / "project", self.work / "project")
        shutil.copy(REPO / "fixtures" / "task.md", self.work / "task.md")
        shutil.copy(REPO / "fixtures" / "claims.json", self.work / "claims.json")
        self.packet = self.work / "packet.json"

    def tearDown(self):
        self.temp.cleanup()

    def cli(self, *args, expected=0):
        completed = subprocess.run([sys.executable, "-m", "proofpacket", *map(str, args)], cwd=REPO,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(completed.returncode, expected, completed.stderr)
        return completed

    def init(self):
        self.cli("init", "--task", self.work / "task.md", "--claims", self.work / "claims.json",
                 "--root", self.work / "project", "--path", "sharing.py", "--path", "test_sharing.py", "--out", self.packet)

    def test_documented_flow_stale_claim_and_report(self):
        self.init()
        self.cli("run", self.packet, "--root", self.work / "project", "--id", "check-guests", "--",
                 sys.executable, "-m", "unittest", "test_sharing.py")
        self.cli("link", self.packet, "--claim", "guest-reshare", "--check", "check-guests")
        before = json.loads(self.packet.read_text(encoding="utf-8"))
        self.assertEqual(before["checks"][0]["argv"], [sys.executable, "-m", "unittest", "test_sharing.py"])
        self.assertEqual(before["checks"][0]["exit_code"], 0)
        self.assertEqual(before["claims"][0]["check_ids"], ["check-guests"])
        (self.work / "project" / "sharing.py").write_text("def can_reshare(role): return True\n", encoding="utf-8")
        verify = self.work / "verification.json"
        self.cli("verify", self.packet, "--root", self.work / "project", "--out", verify, expected=1)
        report = self.work / "report.md"
        self.cli("report", self.packet, "--root", self.work / "project", "--out", report)
        result = json.loads(verify.read_text(encoding="utf-8"))
        self.assertEqual(result["checks"][0]["freshness"], "stale")
        self.assertEqual(result["checks"][0]["changed_paths"], ["sharing.py"])
        self.assertEqual(result["claims"][0]["status"], "needs_review")
        self.assertEqual(result["claims"][1]["status"], "unlinked")
        text = report.read_text(encoding="utf-8")
        self.assertIn("Changed selected paths: `sharing.py`", text)
        self.assertIn("semantic support is not verified", text)
        self.assertIn("Changes outside this selected file set do not affect freshness", text)

    def test_launch_failure_and_invalid_mutation_preserve_packet_bytes(self):
        self.init()
        original = self.packet.read_bytes()
        self.cli("run", self.packet, "--root", self.work / "project", "--id", "no-launch", "--", 
                 str(self.work / "does-not-exist"), expected=2)
        self.assertEqual(self.packet.read_bytes(), original)
        bad = self.work / "invalid.json"
        bad.write_text('{"schema_version": true}', encoding="utf-8")
        bad_bytes = bad.read_bytes()
        self.cli("link", bad, "--claim", "x", "--check", "y", expected=2)
        self.assertEqual(bad.read_bytes(), bad_bytes)

    def test_invalid_run_never_mutates_and_failed_run_is_recorded(self):
        self.init()
        original = self.packet.read_bytes()
        self.cli("run", self.packet, "--root", self.work / "project", "--id", "empty", "--", expected=2)
        self.assertEqual(self.packet.read_bytes(), original)
        self.cli("run", self.packet, "--root", self.work / "project", "--id", "negative", "--timeout", "-1", "--", "python", "-c", "pass", expected=2)
        self.assertEqual(self.packet.read_bytes(), original)
        self.cli("run", self.packet, "--root", self.work / "project", "--id", "bad", "--", sys.executable, "-c", "raise SystemExit(4)", expected=1)
        packet = json.loads(self.packet.read_text(encoding="utf-8"))
        self.assertEqual(packet["checks"][0]["exit_code"], 4)
        self.assertEqual(packet["checks"][0]["status"], "completed")
        recorded = self.packet.read_bytes()
        self.cli("run", self.packet, "--root", self.work / "project", "--id", "bad", "--", sys.executable, "-c", "pass", expected=2)
        self.assertEqual(self.packet.read_bytes(), recorded)

    def test_output_capture_excerpt_and_hash_cover_full_bytes(self):
        self.init()
        data = "z" * 70000
        script = "import sys; sys.stdout.write('z' * 70000)"
        self.cli("run", self.packet, "--root", self.work / "project", "--id", "large", "--", sys.executable, "-c", script)
        recorded = json.loads(self.packet.read_text(encoding="utf-8"))["checks"][0]
        self.assertTrue(recorded["stdout_truncated"])
        self.assertEqual(len(recorded["stdout"]), 65536)
        self.assertEqual(recorded["stdout_sha256"], hashlib.sha256(data.encode()).hexdigest())
        report = self.work / "large.md"
        self.cli("report", self.packet, "--root", self.work / "project", "--out", report)
        self.assertIn("excerpt truncated after 65,536 decoded characters", report.read_text(encoding="utf-8"))

    def test_report_fence_cannot_be_closed_by_command_output(self):
        self.init()
        self.cli("run", self.packet, "--root", self.work / "project", "--id", "fence", "--",
                 sys.executable, "-c", "print('```')")
        report = self.work / "fence.md"
        self.cli("report", self.packet, "--root", self.work / "project", "--out", report)
        content = report.read_text(encoding="utf-8")
        self.assertIn("````text\n```\n\n````", content)

    def test_cli_help_and_version(self):
        help_result = subprocess.run([sys.executable, "-m", "proofpacket", "--help"], cwd=REPO,
                                     text=True, capture_output=True)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("init", help_result.stdout)
        version = subprocess.run([sys.executable, "-m", "proofpacket", "--version"], cwd=REPO,
                                 text=True, capture_output=True)
        self.assertEqual(version.stdout.strip(), "proofpacket 0.1.0")


if __name__ == "__main__":
    unittest.main()
