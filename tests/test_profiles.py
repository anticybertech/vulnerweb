import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="vulnerweb-profile-tests-")
        cls.environment = patch.dict(os.environ, {"LINCOLD_DATA_DIR": cls.temporary.name})
        cls.environment.start()
        cls.scanner = importlib.import_module("scanner")

    @classmethod
    def tearDownClass(cls):
        cls.environment.stop()
        cls.temporary.cleanup()

    def test_active_choices_remain_four(self):
        self.assertEqual(list(self.scanner.PROFILES), ["auto", "quick", "standard", "full"])

    def test_historical_php_resolves_without_being_selectable(self):
        self.assertNotIn("php", self.scanner.PROFILES)
        self.assertEqual(self.scanner.get_profile("php")["label"], "PHP Vulnerability Scan")
        command = self.scanner.build_command("https://example.com", "php", Path("/tmp/results.jsonl"))
        self.assertEqual(command[command.index("-tags") + 1], "php")

    def test_combined_profile_keeps_exclusions(self):
        command = self.scanner.build_command("https://example.com", "standard", Path("/tmp/results.jsonl"))
        excluded = set(command[command.index("-etags") + 1].split(","))
        self.assertTrue({"dos", "fuzz", "bruteforce", "intrusive", "rce", "codeinjection", "code-injection", "cmd-injection"} <= excluded)
        self.assertEqual(command[command.index("-s") + 1], "critical,high,medium")

    def test_unknown_profile_cannot_run(self):
        with self.assertRaises(KeyError):
            self.scanner.build_command("https://example.com", "unknown", Path("/tmp/results.jsonl"))


if __name__ == "__main__":
    unittest.main()