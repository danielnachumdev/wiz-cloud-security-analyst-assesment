import os
from pathlib import Path
import subprocess
import json
import unittest

OPA_PATH = r'C:\tools\OPA\opa.exe'


class TestOPA(unittest.TestCase):
    def assertTestResult(self, input_file: str, expected_result: bool,
                         policy_file: str = "./scripts/script2.rego") -> None:
        input_file = str(Path(input_file).resolve())
        policy_file = str(Path(policy_file).resolve())
        cmd = [
            OPA_PATH,
            'eval',
            '-i', input_file,
            '-d', policy_file,
            'data.example.security_groups.match',
            '--format', 'json'
        ]
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                raise AssertionError(f"OPA failed: {stderr.decode()}")
            opa_result = json.loads(stdout)
            match_value = opa_result['result'][0]['expressions'][0]['value']
            if match_value is None:
                raise AssertionError("'match' value not found in OPA output")
            self.assertEqual(expected_result, match_value,
                             f"Expected {expected_result}, got {match_value}")

    def assertUnsafe(self, input_file: str) -> None:
        self.assertTestResult(input_file, True)

    def assertSafe(self, input_file: str) -> None:
        self.assertTestResult(input_file, False)

    def test_case1(self):
        self.assertSafe("inputs/case1.json")

    def test_case1_egress_non_empty_ipv6(self):
        self.assertUnsafe("./inputs/case1_egress_non_empty_ipv6.json")

    def test_case1_egress_non_empty_useridgrouppairs(self):
        self.assertUnsafe("./inputs/case1_egress_non_empty_useridgrouppairs.json")

    def test_case1_egress_two_ingress_ips(self):
        self.assertUnsafe("./inputs/case1_egress_two_ingress_ips.json")

    def test_case1_egress_with_from_port(self):
        self.assertUnsafe("./inputs/case1_egress_with_from_port.json")

    def test_case1_egress_with_to_port(self):
        self.assertUnsafe("./inputs/case1_egress_with_to_port.json")

    def test_case1_egress_with_two_rules(self):
        self.assertUnsafe("./inputs/case1_egress_with_two_rules.json")

    def test_case1_egress_wrong_ingress_ip(self):
        self.assertUnsafe("./inputs/case1_egress_wrong_ingress_ip.json")

    def test_case1_egress_wrong_protocol(self):
        self.assertUnsafe("./inputs/case1_egress_wrong_protocol.json")

    def test_case1_ingress_no_from_port(self):
        self.assertUnsafe("./inputs/case1_ingress_no_from_port.json")

    def test_case1_ingress_no_to_port(self):
        self.assertUnsafe("./inputs/case1_ingress_no_to_port.json")

    def test_case1_ingress_non_empty_ipv6(self):
        self.assertUnsafe("./inputs/case1_ingress_non_empty_ipv6.json")

    def test_case1_ingress_non_empty_prefixlistids(self):
        self.assertUnsafe("./inputs/case1_ingress_non_empty_prefixlistids.json")

    def test_case1_ingress_non_empty_useridgrouppairs(self):
        self.assertUnsafe("./inputs/case1_ingress_non_empty_useridgrouppairs.json")

    def test_case1_ingress_two_ipv4(self):
        self.assertUnsafe("./inputs/case1_ingress_two_ipv4.json")

    def test_case1_ingress_two_rules(self):
        self.assertUnsafe("./inputs/case1_ingress_two_rules.json")

    def test_case1_ingress_wrong_ip_mask(self):
        self.assertUnsafe("./inputs/case1_ingress_wrong_ip_mask.json")

    def test_case1_ingress_wrong_protocol(self):
        self.assertUnsafe("./inputs/case1_ingress_wrong_protocol.json")

    def test_case2(self):
        self.assertSafe("inputs/case2.json")

    def test_case2_non_empty_groupidgrouppaors(self):
        self.assertUnsafe("inputs/case2_rule1_non_empty_groupidgrouppaors.json")

    def test_case2_non_empty_ipv6(self):
        self.assertUnsafe("./inputs/case2_non_empty_ipv6.json")

    def test_case2_non_empty_prefixlistids(self):
        self.assertUnsafe("./inputs/case2_non_empty_prefixlistids.json")

    def test_case2_non_empty_useridgrouppairs(self):
        self.assertUnsafe("./inputs/case2_non_empty_useridgrouppairs.json")

    def test_case2_rule1_no_from_port(self):
        self.assertUnsafe("inputs/case2_rule1_no_from_port.json")

    def test_case2_rule1_no_to_port(self):
        self.assertUnsafe("inputs/case2_rule1_no_to_port.json")

    def test_case2_rule1_non_empty_groupidgrouppaors(self):
        self.assertUnsafe("inputs/case2_rule1_non_empty_groupidgrouppaors.json")

    def test_case2_rule1_non_empty_ipv4(self):
        self.assertUnsafe("inputs/case2_rule1_non_empty_ipv4.json")

    def test_case2_rule1_non_empty_prefixlistids(self):
        self.assertUnsafe("inputs/case2_rule1_non_empty_prefixlistids.json")

    def test_case2_rule1_two_ipv6(self):
        self.assertUnsafe("inputs/case2_rule1_two_ipv6.json")

    def test_case2_rule1_wrong_ipv6(self):
        self.assertUnsafe("inputs/case2_rule1_wrong_ipv6.json")

    def test_case2_rule1_wrong_protocol(self):
        self.assertUnsafe("inputs/case2_rule1_wrong_protocol.json")

    def test_case2_rule2_no_from_port(self):
        self.assertUnsafe("inputs/case2_rule2_no_from_port.json")

    def test_case2_rule2_no_to_port(self):
        self.assertUnsafe("inputs/case2_rule2_no_to_port.json")

    def test_case2_rule2_two_ipv4(self):
        self.assertUnsafe("inputs/case2_rule2_two_ipv4.json")

    def test_case2_rule2_wrong_protocol(self):
        self.assertUnsafe("inputs/case2_rule2_wrong_protocol.json")

    def test_case3(self):
        self.assertSafe("./inputs/case3.json")

    def test_case3_not_all_protocols(self):
        self.assertUnsafe("./inputs/case3_not_all_protocols.json")

    def test_case3_specific_from_port(self):
        self.assertUnsafe("./inputs/case3_specific_from_port.json")

    def test_case3_specific_to_port(self):
        self.assertUnsafe("./inputs/case3_specific_to_port.json")

    def test_case3_two_egress_rules(self):
        self.assertUnsafe("./inputs/case3_two_egress_rules.json")

    def test_case3_with_ingress(self):
        self.assertUnsafe("./inputs/case3_with_ingress.json")

    def test_case3_wrong_ipv4(self):
        self.assertUnsafe("./inputs/case3_wrong_ipv4.json")

    def test_case3_wrong_ipv6(self):
        self.assertUnsafe("./inputs/case3_wrong_ipv6.json")

    def test_empty_security_group(self):
        self.assertUnsafe("./inputs/empty_security_group.json")

    def test_no_security_groups(self):
        self.assertUnsafe("./inputs/no_security_groups.json")

    def test_missing_egress(self):
        self.assertUnsafe("./inputs/missing_egress.json")

    def test_missing_ingress(self):
        self.assertUnsafe("./inputs/missing_ingress.json")

    def test_multiple_safe_sg(self):
        self.assertSafe("./inputs/multiple_safe_sg.json")

    def test_safe_sg_and_unsafe_sg(self):
        self.assertSafe("./inputs/safe_sg_and_unsafe_sg.json")


if __name__ == "__main__":
    unittest.main()
