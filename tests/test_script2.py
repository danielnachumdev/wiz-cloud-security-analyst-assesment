import unittest

from base import TestOPARego

POLICY_PATH = "./scripts/script2.rego"


class TestScript2(TestOPARego):
    def assertUnsafe(self, input_file: str) -> None:
        self.assertTestResult(input_file, True, POLICY_PATH)

    def assertSafe(self, input_file: str) -> None:
        self.assertTestResult(input_file, False, POLICY_PATH)

    def test_icmp_22(self):
        self.assertSafe("./inputs/icmp_22.json")

    def test_icmp_1023(self):
        self.assertSafe("./inputs/icmp_1023.json")

    def test_icmp_1024(self):
        self.assertUnsafe("./inputs/icmp_1024.json")

    def test_other_22(self):
        self.assertUnsafe("./inputs/other_22.json")

    def test_other_1024(self):
        self.assertUnsafe("./inputs/other_1024.json")

    def test_tcp_22(self):
        self.assertSafe("./inputs/tcp_22.json")

    def test_tcp_23(self):
        self.assertUnsafe("./inputs/tcp_23.json")

    def test_tcp_53(self):
        self.assertSafe("./inputs/tcp_53.json")

    def test_tcp_135(self):
        self.assertSafe("./inputs/tcp_135.json")

    def test_tcp_443(self):
        self.assertSafe("./inputs/tcp_443.json")

    def test_tcp_445(self):
        self.assertSafe("./inputs/tcp_445.json")

    def test_tcp_563(self):
        self.assertSafe("./inputs/tcp_563.json")

    def test_tcp_993(self):
        self.assertSafe("./inputs/tcp_993.json")


if __name__ == "__main__":
    unittest.main()
