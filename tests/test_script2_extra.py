import unittest

from base import TestOPARego

POLICY_PATH = "./scripts/script2_extra.rego"


class TestOPAExtra(TestOPARego):
    def assertUnsafe(self, input_file: str) -> None:
        self.assertTestResult(input_file, True, POLICY_PATH)

    def assertSafe(self, input_file: str) -> None:
        self.assertTestResult(input_file, False, POLICY_PATH)

    def test_case1(self):
        self.assertSafe("./inputs/extra/case1.json")

    def test_case1_egress_non_empty_ipv6(self):
        self.assertUnsafe("./inputs/extra/case1_egress_non_empty_ipv6.json")

    def test_case1_egress_non_empty_useridgrouppairs(self):
        self.assertUnsafe("./inputs/extra/case1_egress_non_empty_useridgrouppairs.json")

    def test_case1_egress_two_ingress_ips(self):
        self.assertUnsafe("./inputs/extra/case1_egress_two_ingress_ips.json")

    def test_case1_egress_with_from_port(self):
        self.assertUnsafe("./inputs/extra/case1_egress_with_from_port.json")

    def test_case1_egress_with_to_port(self):
        self.assertUnsafe("./inputs/extra/case1_egress_with_to_port.json")

    def test_case1_egress_with_two_rules(self):
        self.assertUnsafe("./inputs/extra/case1_egress_with_two_rules.json")

    def test_case1_egress_wrong_ingress_ip(self):
        self.assertUnsafe("./inputs/extra/case1_egress_wrong_ingress_ip.json")

    def test_case1_egress_wrong_protocol(self):
        self.assertUnsafe("./inputs/extra/case1_egress_wrong_protocol.json")

    def test_case1_ingress_no_from_port(self):
        self.assertUnsafe("./inputs/extra/case1_ingress_no_from_port.json")

    def test_case1_ingress_no_to_port(self):
        self.assertUnsafe("./inputs/extra/case1_ingress_no_to_port.json")

    def test_case1_ingress_non_empty_ipv6(self):
        self.assertUnsafe("./inputs/extra/case1_ingress_non_empty_ipv6.json")

    def test_case1_ingress_non_empty_prefixlistids(self):
        self.assertUnsafe("./inputs/extra/case1_ingress_non_empty_prefixlistids.json")

    def test_case1_ingress_non_empty_useridgrouppairs(self):
        self.assertUnsafe("./inputs/extra/case1_ingress_non_empty_useridgrouppairs.json")

    def test_case1_ingress_two_ipv4(self):
        self.assertUnsafe("./inputs/extra/case1_ingress_two_ipv4.json")

    def test_case1_ingress_two_rules(self):
        self.assertUnsafe("./inputs/extra/case1_ingress_two_rules.json")

    def test_case1_ingress_wrong_ip_mask(self):
        self.assertUnsafe("./inputs/extra/case1_ingress_wrong_ip_mask.json")

    def test_case1_ingress_wrong_protocol(self):
        self.assertUnsafe("./inputs/extra/case1_ingress_wrong_protocol.json")

    def test_case2(self):
        self.assertSafe("./inputs/extra/case2.json")

    def test_case2_non_empty_groupidgrouppaors(self):
        self.assertUnsafe("./inputs/extra/case2_rule1_non_empty_groupidgrouppaors.json")

    def test_case2_non_empty_ipv6(self):
        self.assertUnsafe("./inputs/extra/case2_non_empty_ipv6.json")

    def test_case2_non_empty_prefixlistids(self):
        self.assertUnsafe("./inputs/extra/case2_non_empty_prefixlistids.json")

    def test_case2_non_empty_useridgrouppairs(self):
        self.assertUnsafe("./inputs/extra/case2_non_empty_useridgrouppairs.json")

    def test_case2_rule1_no_from_port(self):
        self.assertUnsafe("./inputs/extra/case2_rule1_no_from_port.json")

    def test_case2_rule1_no_to_port(self):
        self.assertUnsafe("./inputs/extra/case2_rule1_no_to_port.json")

    def test_case2_rule1_non_empty_groupidgrouppaors(self):
        self.assertUnsafe("./inputs/extra/case2_rule1_non_empty_groupidgrouppaors.json")

    def test_case2_rule1_non_empty_ipv4(self):
        self.assertUnsafe("./inputs/extra/case2_rule1_non_empty_ipv4.json")

    def test_case2_rule1_non_empty_prefixlistids(self):
        self.assertUnsafe("./inputs/extra/case2_rule1_non_empty_prefixlistids.json")

    def test_case2_rule1_two_ipv6(self):
        self.assertUnsafe("./inputs/extra/case2_rule1_two_ipv6.json")

    def test_case2_rule1_wrong_ipv6(self):
        self.assertUnsafe("./inputs/extra/case2_rule1_wrong_ipv6.json")

    def test_case2_rule1_wrong_protocol(self):
        self.assertUnsafe("./inputs/extra/case2_rule1_wrong_protocol.json")

    def test_case2_rule2_no_from_port(self):
        self.assertUnsafe("./inputs/extra/case2_rule2_no_from_port.json")

    def test_case2_rule2_no_to_port(self):
        self.assertUnsafe("./inputs/extra/case2_rule2_no_to_port.json")

    def test_case2_rule2_two_ipv4(self):
        self.assertUnsafe("./inputs/extra/case2_rule2_two_ipv4.json")

    def test_case2_rule2_wrong_protocol(self):
        self.assertUnsafe("./inputs/extra/case2_rule2_wrong_protocol.json")

    def test_case3(self):
        self.assertSafe("./inputs/extra/case3.json")

    def test_case3_not_all_protocols(self):
        self.assertUnsafe("./inputs/extra/case3_not_all_protocols.json")

    def test_case3_specific_from_port(self):
        self.assertUnsafe("./inputs/extra/case3_specific_from_port.json")

    def test_case3_specific_to_port(self):
        self.assertUnsafe("./inputs/extra/case3_specific_to_port.json")

    def test_case3_two_egress_rules(self):
        self.assertUnsafe("./inputs/extra/case3_two_egress_rules.json")

    def test_case3_with_ingress(self):
        self.assertUnsafe("./inputs/extra/case3_with_ingress.json")

    def test_case3_wrong_ipv4(self):
        self.assertUnsafe("./inputs/extra/case3_wrong_ipv4.json")

    def test_case3_wrong_ipv6(self):
        self.assertUnsafe("./inputs/extra/case3_wrong_ipv6.json")

    def test_empty_security_group(self):
        self.assertUnsafe("./inputs/extra/empty_security_group.json")

    def test_no_security_groups(self):
        self.assertUnsafe("./inputs/extra/no_security_groups.json")

    def test_missing_egress(self):
        self.assertUnsafe("./inputs/extra/missing_egress.json")

    def test_missing_ingress(self):
        self.assertUnsafe("./inputs/extra/missing_ingress.json")

    def test_multiple_safe_sg(self):
        self.assertSafe("./inputs/extra/multiple_safe_sg.json")

    def test_safe_sg_and_unsafe_sg(self):
        self.assertSafe("./inputs/extra/safe_sg_and_unsafe_sg.json")


if __name__ == "__main__":
    unittest.main()
