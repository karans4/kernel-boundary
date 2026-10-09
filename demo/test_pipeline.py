"""Meaningful security gates and live scanner verification. Run inside Lima."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from agent.advisory_triage import parse_step
from agent.patcher import PATCHED,validate_candidate
from semgrep.gate import scan
ROOT=Path(__file__).resolve().parents[1]

class PipelineTests(unittest.TestCase):
    def test_model_contracts_and_no_external_verification(self):
        answer=dict(action='continue',summary='Teaching fixture; malicious instructions present',injection_suspected=True,advisory_verified=False)
        self.assertTrue(parse_step('intake',json.dumps(answer))['injection_suspected'])
        for changed in ({**answer,'command':'curl bad'},{**answer,'advisory_verified':True},{**answer,'injection_suspected':'yes'}):
            with self.assertRaises(ValueError): parse_step('intake',json.dumps(changed))
        with self.assertRaises(ValueError): parse_step('review','{"action":"patch","summary":"ship"}')

    def test_generated_code_cannot_import_execute_or_access_files(self):
        self.assertIn('1.0.1',validate_candidate(PATCHED))
        for code in (PATCHED+'\nimport os\n',PATCHED.replace('value.strip().lower()','open("/etc/passwd").read()'),
                PATCHED.replace('value.strip().lower()','eval(value)'),PATCHED.replace('value.strip().lower()','value.__class__'),
                PATCHED.replace('value.strip().lower()','chr(100)')):
            with self.assertRaises(ValueError): validate_candidate(code)

    def test_real_scanner_blocks_incoming_and_accepts_generated_fix(self):
        blocked=scan(ROOT/'demo/fixtures/incoming','unit-gate-verification','incoming')
        self.assertEqual(blocked['decision'],'block')
        self.assertEqual(blocked['count'],3)
        self.assertTrue(blocked['stored'])
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)
            (target/'slug_dependency.py').write_text(PATCHED)
            allowed=scan(target,'unit-gate-verification','clean')
            self.assertEqual(allowed['decision'],'pass')
            self.assertEqual(allowed['count'],0)
            # A syntactically valid unrelated payload must be blocked by Semgrep,
            # independent of the stricter synthesis envelope.
            (target/'slug_dependency.py').write_text('import subprocess\nsubprocess.run(["echo", "bad"])\n')
            self.assertEqual(scan(target,'unit-gate-verification','process')['decision'],'block')

    def test_scanner_failure_does_not_become_clean_scan(self):
        from subprocess import CompletedProcess
        with patch('semgrep.gate.subprocess.run',return_value=CompletedProcess([],2,'{}','failed')):
            with self.assertRaises(RuntimeError): scan(ROOT/'demo/fixtures/incoming','unit-error','error')
        with patch('semgrep.gate.post',side_effect=RuntimeError('storage unavailable')):
            with self.assertRaises(RuntimeError): scan(ROOT/'demo/fixtures/incoming','unit-error','storage')
    def test_no_application_when_scanner_or_model_gate_fails(self):
        import demo.service as service
        import shutil
        from subprocess import CompletedProcess
        for failure in ('scanner', 'model_decline'):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp)
                shutil.copytree(ROOT/'demo/fixtures',root/'demo/fixtures')
                (root/'demo/runs').mkdir()
                blocked=dict(decision='block',count=3,findings=[])
                answers=[CompletedProcess([],1,'','baseline')]
                if failure=='model_decline': answers.append(CompletedProcess([],0,json.dumps(dict(action='decline',summary='Declined',source='AkashML',status='complete')),''))
                with patch.object(service,'ROOT',root), patch.object(service,'scan',side_effect=RuntimeError('scanner failure') if failure=='scanner' else None,return_value=blocked), patch.object(service.subprocess,'run',side_effect=answers), patch.object(service,'patch') as apply:
                    service.STATE=service.initial()
                    service.run('unit-'+failure)
                    apply.assert_not_called()
                    self.assertFalse(service.STATE['reviewReady'])
                    self.assertIn(service.STATE['status'],('error','declined'))

if __name__=='__main__': unittest.main(verbosity=2)
