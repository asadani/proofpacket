"""Regression cases from independent review of evidence validation."""
import copy
import os
import time
import sys
import tempfile
import unittest
from pathlib import Path
from proofpacket.core import ValidationError, capture_check, fingerprint_files, validate_packet

class EvidenceEdgeTests(unittest.TestCase):
    def test_nonfinite_timeouts_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'source.txt').write_text('source')
            for value in [float('nan'),float('inf'),-float('inf')]:
                with self.subTest(value=value), self.assertRaises(ValidationError):
                    capture_check(root,['source.txt'],'check',[sys.executable,'-c','pass'],value)

    def test_path_aliases_are_not_duplicate_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'source.txt').write_text('source')
            with self.assertRaises(ValidationError):
                fingerprint_files(root,['source.txt','./source.txt'])

    def test_changed_path_record_must_match_snapshots(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'source.txt').write_text('source')
            check=capture_check(root,['source.txt'],'check',[sys.executable,'-c','pass'])
            packet={'schema_version':1,'task':'Review','selected_paths':[{'path':'source.txt','sha256':check['before']['source.txt']}], 'claims':[], 'assumptions':[], 'checks':[check]}
            validate_packet(packet)
            absent=copy.deepcopy(packet)
            del absent['checks'][0]['changed_during_run']
            with self.assertRaises(ValidationError): validate_packet(absent)
            false=copy.deepcopy(packet)
            false['checks'][0]['changed_during_run']=['unselected.txt']
            with self.assertRaises(ValidationError): validate_packet(false)

    @unittest.skipUnless(os.name == 'posix', 'process groups are POSIX-specific')
    def test_timeout_stops_ordinary_child_processes_holding_pipes(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'source.txt').write_text('source')
            script="import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time;time.sleep(5)']); time.sleep(5)"
            started=time.monotonic()
            check=capture_check(root,['source.txt'],'check',[sys.executable,'-c',script],.2)
            self.assertEqual(check['status'],'timeout')
            self.assertLess(time.monotonic()-started,2)

    def test_init_cannot_replace_its_task_or_selected_source(self):
        import contextlib, io, json
        from proofpacket.__main__ import main
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            task=root/'task.md'; task.write_text('Keep guest sharing constrained.\n')
            claims=root/'claims.json'; claims.write_text(json.dumps({'schema_version':1,'claims':[],'assumptions':[]}))
            source=root/'source.py'; source.write_text('allowed = False\n')
            for destination in [task,claims,source]:
                before=destination.read_bytes()
                with contextlib.redirect_stderr(io.StringIO()):
                    code=main(['init','--task',str(task),'--claims',str(claims),'--root',str(root),'--path','source.py','--out',str(destination)])
                self.assertEqual(code,2)
                self.assertEqual(destination.read_bytes(),before)
