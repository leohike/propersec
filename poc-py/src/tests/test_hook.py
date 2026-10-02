"""pam_hook.py end to end, run as a subprocess the way pam_exec runs it: PAM's environment
variables, the typed input on stdin with a trailing NUL, and only the exit code coming back.
"""

import os
import unittest

from common import MAX_SHORT_PASSWORD_BYTES, get_boot_id, get_boottime
from tests.support import SHORT_PASSWORD, Sandbox

UNLOCK, REFUSE = 0, 1


class HookTest(unittest.TestCase):
    def setUp(self):
        self.sandbox = Sandbox()
        self.addCleanup(self.sandbox.cleanup)
        self.sandbox.set_short_password()

    def start_short_password_window(self) -> None:
        self.assertEqual(self.sandbox.start_short_password_window(), 0)

    def failed_unlock_count(self) -> int:
        state = self.sandbox.get_state()
        assert state is not None
        return state.failed_unlock_count


class Unlocking(HookTest):
    def test_correct_short_password_unlocks_once_allowed(self):
        self.start_short_password_window()
        self.assertEqual(self.sandbox.check(SHORT_PASSWORD), UNLOCK)

    def test_wrong_short_password_fails_and_counts(self):
        self.start_short_password_window()
        self.assertEqual(self.sandbox.check("0000"), REFUSE)
        self.assertEqual(self.failed_unlock_count(), 1)

    def test_three_failed_unlocks_then_full_password_required(self):
        self.start_short_password_window()
        for _ in range(3):
            self.assertEqual(self.sandbox.check("0000"), REFUSE)
        self.assertEqual(self.sandbox.check(SHORT_PASSWORD), REFUSE)
        self.assertIn("failed unlock 3 of 3, full_password required from now on", self.sandbox.get_log())
        self.assertIn("full_password required: 3 failed unlocks in a row", self.sandbox.get_log())

    def test_correct_short_password_resets_the_failed_unlock_count(self):
        self.start_short_password_window()
        self.sandbox.check("0000")
        self.sandbox.check("0000")
        self.assertEqual(self.sandbox.check(SHORT_PASSWORD), UNLOCK)
        self.assertEqual(self.failed_unlock_count(), 0)

    def test_full_password_allows_the_short_password_again_after_failed_unlocks(self):
        self.start_short_password_window()
        for _ in range(3):
            self.sandbox.check("0000")
        self.start_short_password_window()
        self.assertEqual(self.sandbox.check(SHORT_PASSWORD), UNLOCK)

    def test_unusable_input_fails_without_counting(self):
        self.start_short_password_window()
        for typed in [b"", b"47\x0011", b"x" * (MAX_SHORT_PASSWORD_BYTES + 1), b"47\xff11"]:
            with self.subTest(typed=typed[:20]):
                self.assertEqual(self.sandbox.hook("check", typed), REFUSE)
        self.assertEqual(self.failed_unlock_count(), 0)

    def test_input_longer_than_a_short_password_fails_without_counting(self):
        self.start_short_password_window()
        for typed in ["x" * 13, "correct horse battery staple", "x" * MAX_SHORT_PASSWORD_BYTES]:
            with self.subTest(typed=typed[:20]):
                self.assertEqual(self.sandbox.check(typed), REFUSE)
                self.assertIn("longer than 12 characters, so not the short_password; not counted", self.sandbox.get_log().splitlines()[-1])
        self.assertEqual(self.failed_unlock_count(), 0)

    def test_the_length_limit_counts_characters_and_follows_the_settings(self):
        self.start_short_password_window()
        self.assertEqual(self.sandbox.check("ж" * 12), REFUSE)  # 24 bytes, but 12 characters
        self.assertEqual(self.failed_unlock_count(), 1)
        self.sandbox.write_config("max_short_password_len = 4\n")
        self.assertEqual(self.sandbox.check("48590"), REFUSE)
        self.assertEqual(self.failed_unlock_count(), 1)
        self.assertEqual(self.sandbox.check(SHORT_PASSWORD), UNLOCK)

    def test_random_input_fails(self):
        self.start_short_password_window()
        for typed in ["4859 ", " 4859", "48591", "485", "x" * 12, "ünïcødé"]:
            with self.subTest(typed=typed[:20]):
                self.assertEqual(self.sandbox.check(typed), REFUSE)
                self.start_short_password_window()

    def test_log_never_contains_a_password(self):
        self.start_short_password_window()
        self.sandbox.check(SHORT_PASSWORD)
        self.sandbox.check("9999")
        log = self.sandbox.get_log()
        self.assertNotIn(SHORT_PASSWORD, log)
        self.assertNotIn("9999", log)


class Arming(HookTest):
    def test_full_password_required_after_boot(self):
        self.assertEqual(self.sandbox.check(SHORT_PASSWORD), REFUSE)
        self.assertIn("no full_password unlock since boot", self.sandbox.get_log())

    def test_state_from_an_earlier_boot_is_ignored(self):
        self.start_short_password_window()
        self.sandbox.edit_state(boot_id="some-earlier-boot")
        self.assertEqual(self.sandbox.check(SHORT_PASSWORD), REFUSE)
        self.assertIn("earlier boot", self.sandbox.get_log())

    # The clock is seconds since boot, so a test can't move short_password_enabled_at back further than
    # the machine's uptime. A 36-second window (0.01 h) keeps these tests valid on any machine;
    # the 8-hour default itself is covered in test_common's Decision tests.

    def test_expires_after_the_configured_hours(self):
        self.sandbox.write_config("expiry_hours = 0.01\n")
        self.start_short_password_window()
        self.sandbox.edit_state(short_password_enabled_at=self.sandbox.get_state().short_password_enabled_at - 36)
        self.assertEqual(self.sandbox.check(SHORT_PASSWORD), REFUSE)
        self.assertIn("full_password required: the last full_password unlock was", self.sandbox.get_log())

    def test_works_until_just_before_expiry(self):
        self.sandbox.write_config("expiry_hours = 0.01\n")
        self.start_short_password_window()
        self.sandbox.edit_state(short_password_enabled_at=self.sandbox.get_state().short_password_enabled_at - 30)
        self.assertEqual(self.sandbox.check(SHORT_PASSWORD), UNLOCK)

    def test_input_while_full_password_required_changes_nothing(self):
        self.assertEqual(self.sandbox.check("0000"), REFUSE)
        self.assertIsNone(self.sandbox.get_state())

    def test_allowing_writes_this_boot_and_now(self):
        self.start_short_password_window()
        state = self.sandbox.get_state()
        self.assertEqual(state.boot_id, get_boot_id())
        self.assertLessEqual(abs(state.short_password_enabled_at - get_boottime()), 5)


class FailingClosed(HookTest):
    """Every way the files or the call can be wrong ends in a refusal, for the stated reason."""

    def assert_refused(self, reason: str, **options) -> None:
        self.assertEqual(self.sandbox.check(SHORT_PASSWORD, **options), REFUSE)
        self.assertIn(reason, self.sandbox.get_log().splitlines()[-1])

    def test_corrupted_or_deleted_state(self):
        state_file = self.sandbox.files.state_file
        for damage in [lambda: state_file.write_text("failed_unlock_count = 0\n"), state_file.unlink]:
            self.start_short_password_window()
            damage()
            self.assert_refused("full_password required: no full_password unlock since boot")

    def test_symlinked_state_is_not_followed(self):
        self.start_short_password_window()
        state_file = self.sandbox.files.state_file
        elsewhere = self.sandbox.root / "elsewhere"
        os.replace(state_file, elsewhere)
        state_file.symlink_to(elsewhere)
        self.assert_refused("full_password required: no full_password unlock since boot")

    def test_no_short_password_set(self):
        self.start_short_password_window()
        self.sandbox.files.user_file.unlink()
        self.assert_refused("no short_password is set")

    def test_short_password_file_others_could_change(self):
        self.start_short_password_window()
        self.sandbox.files.user_file.chmod(0o660)
        self.assert_refused("writable by its group")

    def test_broken_config(self):
        self.start_short_password_window()
        self.sandbox.write_config("max_failed_unlocks = lots\n")
        self.assert_refused("must be a number")

    def test_files_not_owned_by_the_expected_owner(self):
        # Installed, the owner is root; a file owned by the user must not pass for root's.
        self.start_short_password_window()
        flags = self.sandbox.hook_flags()
        flags[flags.index("--owner") + 1] = "0"
        self.assert_refused("not 0", flags=flags)

    def test_run_dir_shared(self):
        self.start_short_password_window()
        self.sandbox.files.run_dir.chmod(0o755)
        self.assert_refused("not a private directory")

    def test_not_from_a_pam_auth_stack(self):
        self.start_short_password_window()
        for env, reason in [({"PAM_TYPE": "account"}, "not called from a PAM auth stack"),
                            ({"PAM_USER": "someone-else"}, "PAM is authenticating 'someone-else'"),
                            ({"PAM_USER": ""}, "PAM is authenticating ''")]:
            with self.subTest(env=env):
                self.assert_refused(reason, env=env)

    def test_bad_command_lines(self):
        self.start_short_password_window()
        log_before = self.sandbox.get_log()
        for flags in [[], ["--etc", str(self.sandbox.files.etc)], [*self.sandbox.hook_flags(), "--surprise"]]:
            with self.subTest(flags=flags):
                self.assertEqual(self.sandbox.check(SHORT_PASSWORD, flags=flags), REFUSE)
        # A command line that doesn't parse can't name its log file, so it logs nothing.
        self.assertEqual(self.sandbox.get_log(), log_before)


if __name__ == "__main__":
    unittest.main()
