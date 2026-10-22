"""Regression cases from independent review of evidence validation."""
import copy
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
