"""The lazypass CLI: set, remove, status."""

import stat
import unittest

from tests.support import SHORT_PASSWORD, Sandbox


class CliTest(unittest.TestCase):
    def setUp(self):
        self.sandbox = Sandbox()
        self.addCleanup(self.sandbox.cleanup)
        self.user_file = self.sandbox.files.user_file

    def assert_fails(self, result, message: str) -> None:
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(message, result.stderr)


class Setting(CliTest):
    def test_writes_a_yescrypt_hash_owner_writable_group_readable(self):
        self.sandbox.set_short_password()
        info = self.user_file.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o640)
        self.assertEqual(info.st_uid, self.sandbox.uid)
        self.assertTrue(self.user_file.read_text().startswith("hash = $y$j9T$"))
        self.assertNotIn(SHORT_PASSWORD, self.user_file.read_text())

    def test_entries_must_match(self):
        self.assert_fails(self.sandbox.cli("set", stdin="4859\n4860\n"), "the two entries differ")
        self.assertFalse(self.user_file.exists())

    def test_default_rules(self):
        self.assert_fails(self.sandbox.cli("set", stdin="471\n471\n"), "at least 4 characters")
        self.assert_fails(self.sandbox.cli("set", stdin="purple tractor\n" * 2), "at most 12 characters")

    def test_letter_rule_from_config(self):
        self.sandbox.write_config("min_letters = 3\n")
        self.assert_fails(self.sandbox.cli("set", stdin="1234\n1234\n"), "at least 3 English letters")
        self.sandbox.set_short_password("ab12c")

    def test_keeps_per_user_settings_when_the_short_password_changes(self):
        self.sandbox.set_short_password()
        self.user_file.write_text(self.user_file.read_text() + "max_failed_unlocks = 2\n")
        self.sandbox.set_short_password("9876")
        self.assertIn("max_failed_unlocks = 2", self.user_file.read_text())

    def test_only_the_owner_may_set_or_remove(self):
        for command in ["set", "remove"]:
            with self.subTest(command=command):
                result = self.sandbox.cli("--owner", "0", command, stdin=f"{SHORT_PASSWORD}\n{SHORT_PASSWORD}\n")
                self.assert_fails(result, "run it with sudo")
        self.assertFalse(self.user_file.exists())

    def test_root_is_not_a_target(self):
        self.assert_fails(self.sandbox.cli("set", "--user", "root", stdin=f"{SHORT_PASSWORD}\n{SHORT_PASSWORD}\n"), "root has no lock screen")


class Removing(CliTest):
    def test_removes_the_file(self):
        self.sandbox.set_short_password()
        self.assertEqual(self.sandbox.cli("remove").returncode, 0)
        self.assertFalse(self.user_file.exists())

    def test_nothing_to_remove(self):
        self.assert_fails(self.sandbox.cli("remove"), "no short_password is set")


class Status(CliTest):
    def status(self) -> str:
        result = self.sandbox.cli("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_not_set(self):
        self.assertIn("unusable: no short_password is set", self.status())

    def test_set_but_full_password_required(self):
        self.sandbox.set_short_password()
        output = self.status()
        self.assertIn("allowed for 8h after a full_password unlock, until 3 failed unlocks in a row", output)
        self.assertIn("4 to 12 characters", output)
        self.assertIn("full_password required: no full_password unlock since boot", output)

    def test_short_password_allowed_with_a_failed_unlock(self):
        self.sandbox.set_short_password()
        self.sandbox.start_short_password_window()
        self.sandbox.check("0000")
        self.assertIn("1 of 3 failed unlocks so far", self.status())

    def test_unsafe_file(self):
        self.sandbox.set_short_password()
        self.user_file.chmod(0o644)
        self.assertIn("unusable", self.status())


if __name__ == "__main__":
    unittest.main()
