from pathlib import Path
import subprocess
import json
import unittest

OPA_PATH = r'C:\tools\OPA\opa.exe'


class TestOPARego(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = Path(OPA_PATH).absolute().resolve()
        if not p.exists():
            raise FileNotFoundError(f"OPA not found at: {p}")

    def assertTestResult(self, input_file: str, expected_result: bool, policy_file: str) -> None:
        p = Path(input_file).absolute().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Input file not found: {p}")
        input_file = str(p)
        p = Path(policy_file).absolute().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Policy file not found: {p}")
        policy_file = str(p)
        cmd = [
            OPA_PATH,
            'eval',
            '-i', input_file,
            '-d', policy_file,
            'data.scripts',
            '--format', 'json'
        ]
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                raise AssertionError(f"OPA failed: {stderr.decode()}")
            opa_result = json.loads(stdout)
            match_value = opa_result['result'][0]['expressions'][0]['value'].get('match', None)
            if match_value is None:
                raise AssertionError("'match' value not found in OPA output")
            self.assertEqual(expected_result, match_value, f"Expected {expected_result}, got {match_value}")
