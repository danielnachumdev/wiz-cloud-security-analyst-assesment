import unittest

from base import TestOPARego

POLICY_PATH = "./scripts/script2.rego"


class TestScript2(TestOPARego):
    def assertUnsafe(self, input_file: str) -> None:
        self.assertTestResult(input_file, True, POLICY_PATH)

    def assertSafe(self, input_file: str) -> None:
        self.assertTestResult(input_file, False, POLICY_PATH)

    def test_tcp_22(self):
        self.assertSafe("./inputs/tcp_22.json")

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
