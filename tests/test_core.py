from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from proofpacket import ValidationError, assess_packet, capture_check, fingerprint_files, validate_packet


REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "fixtures" / "project"


def packet_for(root: Path, paths=("sharing.py", "test_sharing.py")) -> dict:
    hashes = fingerprint_files(root, list(paths))
    return {
        "schema_version": 1,
        "task": "Prevent guest reshares.",
        "selected_paths": [{"path": p, "sha256": h} for p, h in hashes.items()],
        "claims": [{"id": "guest", "text": "Guests cannot reshare.", "check_ids": []},
                   {"id": "unlinked", "text": "All paths are covered.", "check_ids": []}],
        "assumptions": [{"id": "role", "text": "guest is an external role."}],
        "checks": [],
    }


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "project"
        shutil.copytree(FIXTURE, self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_pass_capture_and_unlinked_claim(self):
        check = capture_check(self.root, ["sharing.py", "test_sharing.py"], "unit", [sys.executable, "-m", "unittest", "test_sharing.py"])
        self.assertEqual((check["status"], check["exit_code"]), ("completed", 0))
        self.assertIn("OK", check["stderr"])
        self.assertEqual(check["before"], check["after"])
        packet = packet_for(self.root)
        packet["checks"].append(check)
        packet["claims"][0]["check_ids"].append("unit")
        result = assess_packet(packet, self.root)
        self.assertEqual(result["claims"][0]["status"], "has_current_passing_evidence")
        self.assertEqual(result["claims"][1]["status"], "unlinked")
        self.assertFalse(result["adverse"])

    def test_selected_file_edit_makes_evidence_stale(self):
        check = capture_check(self.root, ["sharing.py"], "unit", [sys.executable, "-c", "print('ok')"])
        packet = packet_for(self.root, ("sharing.py",))
        packet["checks"] = [check]
        packet["claims"][0]["check_ids"] = ["unit"]
        (self.root / "sharing.py").write_text("def can_reshare(role): return True\n", encoding="utf-8")
        assessment = assess_packet(packet, self.root)
        self.assertEqual(assessment["checks"][0]["freshness"], "stale")
        self.assertEqual(assessment["checks"][0]["changed_paths"], ["sharing.py"])
        self.assertEqual(assessment["claims"][0]["status"], "needs_review")

    def test_unrelated_file_does_not_change_freshness(self):
        check = capture_check(self.root, ["sharing.py"], "unit", [sys.executable, "-c", "pass"])
        packet = packet_for(self.root, ("sharing.py",))
        packet["checks"] = [check]
        (self.root / "unselected.txt").write_text("outside scope")
        self.assertEqual(assess_packet(packet, self.root)["checks"][0]["freshness"], "current")

    def test_changed_during_run_is_not_current(self):
        script = "from pathlib import Path; Path('sharing.py').write_text('changed\\n'); print('done')"
        check = capture_check(self.root, ["sharing.py"], "mutating", [sys.executable, "-c", script])
        self.assertEqual(check["exit_code"], 0)
        self.assertEqual(check["changed_during_run"], ["sharing.py"])
        packet = packet_for(self.root, ("sharing.py",))
        packet["checks"] = [check]
        self.assertEqual(assess_packet(packet, self.root)["checks"][0]["freshness"], "changed_during_run")

    def test_failure_timeout_and_binary_full_stream_hash(self):
        failed = capture_check(self.root, ["sharing.py"], "fail", [sys.executable, "-c", "import sys; print('bad'); sys.exit(7)"])
        self.assertEqual((failed["status"], failed["exit_code"]), ("completed", 7))
        timed = capture_check(self.root, ["sharing.py"], "slow", [sys.executable, "-c", "import time; print('partial', flush=True); time.sleep(2)"], timeout=.05)
        self.assertEqual((timed["status"], timed["exit_code"]), ("timeout", None))
        raw = b"\xff\x00abc"
        binary = capture_check(self.root, ["sharing.py"], "binary", [sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes([255,0,97,98,99]))"])
        self.assertEqual(binary["stdout_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(binary["stdout"], raw.decode("utf-8", errors="replace"))
        self.assertEqual(binary["status"], "completed")
        unicode_output = "💡" * 65537
        unicode_check = capture_check(self.root, ["sharing.py"], "unicode", [sys.executable, "-c", "print('💡' * 65537, end='')"])
        self.assertEqual(unicode_check["stdout"], unicode_output[:65536])
        self.assertTrue(unicode_check["stdout_truncated"])
        self.assertEqual(unicode_check["stdout_sha256"], hashlib.sha256(unicode_output.encode()).hexdigest())

    def test_missing_source_is_unavailable(self):
        check = capture_check(self.root, ["sharing.py"], "unit", [sys.executable, "-c", "pass"])
        packet = packet_for(self.root, ("sharing.py",))
        packet["checks"] = [check]
        (self.root / "sharing.py").unlink()
        result = assess_packet(packet, self.root)
        self.assertEqual(result["checks"][0]["freshness"], "unavailable")
        self.assertEqual(result["checks"][0]["unavailable_paths"], ["sharing.py"])

    def test_rejects_unsafe_paths_and_escaping_symlinks(self):
        with self.assertRaises(ValidationError):
            fingerprint_files(self.root, ["../outside"])
        outside = Path(self.temp.name) / "outside.py"
        outside.write_text("secret")
        (self.root / "escape.py").symlink_to(outside)
        with self.assertRaisesRegex(ValidationError, "escapes root"):
            fingerprint_files(self.root, ["escape.py"])

    def test_invalid_references_duplicate_ids_and_bool_schema_rejected(self):
        packet = packet_for(self.root)
        packet["schema_version"] = True
        with self.assertRaises(ValidationError):
            validate_packet(packet)
        packet = packet_for(self.root)
        packet["claims"].append(dict(packet["claims"][0]))
        with self.assertRaisesRegex(ValidationError, "duplicate claims"):
            validate_packet(packet)
        packet = packet_for(self.root)
        packet["claims"][0]["check_ids"] = ["missing"]
        with self.assertRaisesRegex(ValidationError, "unknown check"):
            validate_packet(packet)


if __name__ == "__main__":
    unittest.main()
