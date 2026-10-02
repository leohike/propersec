"""The library on its own: file format, settings, hashing, file checks, state, and the decision."""

import dataclasses
import os
import unittest

from common import (
    MAX_SHORT_PASSWORD_BYTES,
    PARAMETER_SPECS,
    LazypassError,
    ParameterSpec,
    Settings,
    ShortPasswordState,
    Yescrypt,
    describe_seconds,
    format_settings,
    parse_settings,
)
from tests.support import Sandbox

BOOT = "this-boot"
HOUR = 3600


class SettingsFormat(unittest.TestCase):
    def test_parses_comments_blanks_and_spacing(self):
        text = "# a comment\n\nmax_failed_unlocks = 5\n  expiry_hours=2  \n"
        self.assertEqual(parse_settings(text, "f"), {"max_failed_unlocks": "5", "expiry_hours": "2"})

    def test_rejects_what_it_does_not_understand(self):
        for text in ["no equals sign\n", "key =\n", "= value\n", "a = 1\na = 2\n"]:
            with self.subTest(text=text), self.assertRaises(LazypassError):
                parse_settings(text, "f")

    def test_round_trips(self):
        settings = {"hash": "$y$j9T$abc$def", "max_failed_unlocks": "2"}
        self.assertEqual(parse_settings(format_settings(settings), "f"), settings)


class SettingsRules(unittest.TestCase):
    def test_defaults_match_the_requirements(self):
        expected = Settings(short_password_hash="", expiry_hours=8, max_failed_unlocks=3, max_short_password_len=12, min_length=4, min_letters=0, hash_cost=5)
        self.assertEqual(Settings(), expected)

    def test_settings_apply_on_top(self):
        settings = Settings()
        settings.update({"expiry_hours": "0.5", "min_letters": "3"}, "f")
        self.assertEqual((settings.expiry_hours, settings.min_letters, settings.max_failed_unlocks), (0.5, 3, 3))

    def test_bad_values_are_errors_not_clamped(self):
        for key, value in [("max_failed_unlocks", "0"), ("max_failed_unlocks", "50"), ("max_failed_unlocks", "two"), ("expiry_hours", "nan"),
                           ("expiry_hours", "inf"), ("hash_cost", "12"), ("max_failed_unlocks", "2.5"), ("max_short_password_len", "0"),
                           ("max_short_password_len", "65"), ("colour", "blue")]:
            with self.subTest(key=key, value=value), self.assertRaises(LazypassError):
                Settings().update({key: value}, "f")

    def test_every_setting_but_the_hash_has_a_parameter_spec(self):
        fields = [field.name for field in dataclasses.fields(Settings) if field.name != "short_password_hash"]
        self.assertEqual([spec.name for spec in PARAMETER_SPECS], fields)

    def test_a_parameter_spec_converts_and_checks_the_range(self):
        spec = ParameterSpec("max_failed_unlocks", int, 1, 10)
        self.assertEqual(spec.check("10", "f"), 10)
        with self.assertRaisesRegex(LazypassError, "f: max_failed_unlocks must be between 1 and 10, not 11"):
            spec.check("11", "f")

    def test_only_a_users_own_file_may_set_the_hash(self):
        with self.assertRaisesRegex(LazypassError, "only a user's own file"):
            Settings().update({"hash": "$y$j9T$abc$def"}, "f")
        settings = Settings()
        settings.update({"hash": "$y$j9T$abc$def"}, "f", may_set_hash=True)
        self.assertEqual(settings.short_password_hash, "$y$j9T$abc$def")

    def test_the_hash_stays_out_of_the_repr(self):
        self.assertNotIn("abc", repr(Settings(short_password_hash="$y$j9T$abc$def")))

    def test_short_password_rules(self):
        strict = Settings(min_length=6, min_letters=3)
        self.assertEqual(strict.get_short_password_problems("abc123"), [])
        self.assertEqual(strict.get_short_password_problems("ab12"), ["at least 6 characters", "at least 3 English letters"])
        self.assertEqual(strict.get_short_password_problems("ab\tcdef"), ["no control characters"])
        self.assertEqual(Settings().get_short_password_problems("purple tractor"), ["at most 12 characters"])
        # Characters, not bytes: twelve Cyrillic letters are 24 bytes and still fit.
        self.assertEqual(Settings().get_short_password_problems("ж" * 12), [])
        self.assertIn("at least 3 English letters", strict.get_short_password_problems("жжж123"))


class SettingsFiles(unittest.TestCase):
    def setUp(self):
        self.sandbox = Sandbox()
        self.addCleanup(self.sandbox.cleanup)
        self.files = self.sandbox.files

    def write_user_file(self, text: str) -> None:
        self.files.user_file.parent.mkdir(exist_ok=True)
        self.files.user_file.write_text(text)
        self.files.user_file.chmod(0o640)

    def test_defaults_then_global_config_then_the_users_own_file(self):
        self.sandbox.write_config("expiry_hours = 4\nmax_failed_unlocks = 5\n")
        self.write_user_file("hash = $y$j9T$abc$def\nmax_failed_unlocks = 2\n")
        settings = self.files.load_settings()
        self.assertEqual((settings.min_length, settings.expiry_hours, settings.max_failed_unlocks), (4, 4.0, 2))
        self.assertEqual(settings.short_password_hash, "$y$j9T$abc$def")

    def test_no_files_means_the_defaults_and_no_short_password(self):
        self.assertEqual(self.files.load_settings(), Settings())

    def test_a_hash_in_the_global_config_is_refused(self):
        self.sandbox.write_config("hash = $y$j9T$abc$def\n")
        with self.assertRaisesRegex(LazypassError, "config: only a user's own file"):
            self.files.load_settings()

    def test_an_error_names_the_file_it_came_from(self):
        self.write_user_file("hash = $y$j9T$abc$def\nmax_failed_unlocks = 0\n")
        with self.assertRaisesRegex(LazypassError, "users/"):
            self.files.load_settings()

    def test_saving_a_hash_round_trips(self):
        self.files.save_short_password_hash("$y$j9T$abc$def", os.getgid())
        self.assertEqual(self.files.load_settings().short_password_hash, "$y$j9T$abc$def")

    def test_saving_a_new_hash_keeps_the_users_other_settings(self):
        self.write_user_file("hash = $y$j9T$old$old\nmax_failed_unlocks = 2\n")
        self.files.save_short_password_hash("$y$j9T$new$new", os.getgid())
        self.assertEqual(self.files.user_file.read_text(), "hash = $y$j9T$new$new\nmax_failed_unlocks = 2\n")

    def test_without_a_hash_nothing_verifies(self):
        self.write_user_file("max_failed_unlocks = 2\n")
        with self.assertRaisesRegex(LazypassError, "no short_password is set"):
            self.files.load_settings().verify_short_password("4859")


class Hashing(unittest.TestCase):
    yescrypt = Yescrypt()

    def test_hash_then_verify(self):
        stored = self.yescrypt.hash(b"4859", 5)
        self.assertTrue(stored.startswith("$y$j9T$"))  # j9T is cost 5
        self.assertTrue(self.yescrypt.verify(b"4859", stored))
        self.assertFalse(self.yescrypt.verify(b"4860", stored))
        self.assertFalse(self.yescrypt.verify(b"48590", stored))

    def test_settings_verify_through_it(self):
        settings = Settings(short_password_hash=self.yescrypt.hash(b"4859", 5))
        self.assertTrue(settings.verify_short_password("4859"))
        self.assertFalse(settings.verify_short_password("4860"))

    def test_same_short_password_hashes_differently_each_time(self):
        self.assertNotEqual(self.yescrypt.hash(b"4859", 5), self.yescrypt.hash(b"4859", 5))

    def test_cost_is_honoured(self):
        self.assertTrue(self.yescrypt.hash(b"4859", 4).startswith("$y$j8T$"))

    def test_nul_byte_can_not_truncate_the_short_password(self):
        stored = self.yescrypt.hash(b"4859", 5)
        with self.assertRaises(LazypassError):
            self.yescrypt.verify(b"4859\0junk", stored)

    def test_only_yescrypt_is_accepted(self):
        for stored in ["", "*0", "$6$salt$hash", "plain"]:
            with self.subTest(stored=stored), self.assertRaises(LazypassError):
                self.yescrypt.verify(b"4859", stored)

    def test_too_long_is_refused(self):
        with self.assertRaises(LazypassError):
            self.yescrypt.hash(b"x" * (MAX_SHORT_PASSWORD_BYTES + 1), 5)


class OwnedFiles(unittest.TestCase):
    def setUp(self):
        self.sandbox = Sandbox()
        self.addCleanup(self.sandbox.cleanup)
        self.path = self.sandbox.root / "file"
        self.path.write_text("key = value\n")

    def read(self, mode: int, *, owner: int | None = None, private: bool = True) -> str:
        self.path.chmod(mode)
        files = self.sandbox.files if owner is None else dataclasses.replace(self.sandbox.files, owner=owner)
        return files.read_trusted_file(self.path, private=private)

    def test_owner_and_group_may_read(self):
        self.assertEqual(self.read(0o640), "key = value\n")

    def test_refuses_a_file_others_can_change(self):
        for mode in [0o660, 0o646, 0o666]:
            with self.subTest(mode=oct(mode)), self.assertRaises(LazypassError):
                self.read(mode)

    def test_refuses_a_private_file_others_can_read(self):
        with self.assertRaises(LazypassError):
            self.read(0o644)
        self.assertEqual(self.read(0o644, private=False), "key = value\n")

    def test_refuses_the_wrong_owner(self):
        with self.assertRaises(LazypassError):
            self.read(0o640, owner=0)

    def test_refuses_a_symlink(self):
        link = self.sandbox.root / "link"
        link.symlink_to(self.path)
        with self.assertRaises(OSError):
            self.sandbox.files.read_trusted_file(link, private=True)

    def test_refuses_a_directory(self):
        with self.assertRaises(LazypassError):
            self.sandbox.files.read_trusted_file(self.sandbox.root, private=False)


class StateFile(unittest.TestCase):
    def setUp(self):
        self.sandbox = Sandbox()
        self.addCleanup(self.sandbox.cleanup)
        self.files = self.sandbox.files
        self.path = self.files.state_file

    def test_round_trips(self):
        state = ShortPasswordState(boot_id=BOOT, short_password_enabled_at=100, failed_unlock_count=2)
        self.files.save_state(state)
        self.assertEqual(self.files.load_state(), state)

    def test_missing_reads_as_no_state(self):
        self.assertIsNone(self.files.load_state())

    def test_anything_damaged_reads_as_no_state(self):
        valid = "boot_id = b\nshort_password_enabled_at = 100\nfailed_unlock_count = 0\n"
        self.path.write_text(valid)
        self.assertEqual(self.files.load_state(), ShortPasswordState(boot_id="b", short_password_enabled_at=100, failed_unlock_count=0))
        # Each case is the valid text with exactly one thing wrong.
        damaged = {
            "not key = value": "garbage",
            "a key missing": valid.replace("failed_unlock_count = 0\n", ""),
            "a key too many": valid + "extra = 1\n",
            "a key twice": valid + "failed_unlock_count = 0\n",
            "a negative count": valid.replace("failed_unlock_count = 0", "failed_unlock_count = -5"),
            "a digit, but not ASCII": valid.replace("failed_unlock_count = 0", "failed_unlock_count = ²"),
            "not an integer": valid.replace("= 100", "= 1e3"),
        }
        for name, text in damaged.items():
            with self.subTest(name):
                self.path.write_text(text)
                self.assertIsNone(self.files.load_state())
        self.path.write_bytes(b"\xff\xfe")
        self.assertIsNone(self.files.load_state())

    def test_symlink_reads_as_no_state(self):
        self.files.save_state(ShortPasswordState(boot_id=BOOT, short_password_enabled_at=100, failed_unlock_count=0))
        target = self.sandbox.root / "elsewhere"
        os.replace(self.path, target)
        self.path.symlink_to(target)
        self.assertIsNone(self.files.load_state())

    def test_saving_leaves_no_temporary_files(self):
        self.files.save_state(ShortPasswordState(boot_id=BOOT, short_password_enabled_at=100, failed_unlock_count=0))
        self.assertEqual(sorted(entry.name for entry in self.path.parent.iterdir()), ["lazypass.state"])

    def test_run_dir_must_be_private_and_ours(self):
        self.files.require_private_run_dir()
        with self.assertRaises(LazypassError):
            dataclasses.replace(self.files, uid=self.files.uid + 1).require_private_run_dir()
        with self.assertRaises(LazypassError):
            dataclasses.replace(self.files, run_base=self.sandbox.root / "absent").require_private_run_dir()
        self.files.run_dir.chmod(0o750)
        with self.assertRaises(LazypassError):
            self.files.require_private_run_dir()


class Decision(unittest.TestCase):
    settings = Settings()

    def reason(self, state: ShortPasswordState | None, now: int = 1000) -> str | None:
        return self.settings.get_reason_to_refuse_without_checking(state, BOOT, now)

    def test_short_password_allowed_inside_the_window_below_the_failed_unlock_limit(self):
        self.assertIsNone(self.reason(ShortPasswordState(BOOT, short_password_enabled_at=1000, failed_unlock_count=0)))
        self.assertIsNone(self.reason(ShortPasswordState(BOOT, short_password_enabled_at=1000, failed_unlock_count=2), now=1000 + 8 * HOUR - 1))

    def test_every_reason_the_full_password_is_required(self):
        cases = {
            "no state": (None, 1000, "no full_password unlock since boot"),
            "another boot": (ShortPasswordState("old-boot", 1000, 0), 1000, "earlier boot"),
            "from the future": (ShortPasswordState(BOOT, 2000, 0), 1000, "future"),
            "expired": (ShortPasswordState(BOOT, 1000, 0), 1000 + 8 * HOUR, "8h00m ago"),
            "too many failed unlocks": (ShortPasswordState(BOOT, 1000, 3), 1000, "3 failed unlocks in a row"),
        }
        for name, (state, now, expected) in cases.items():
            with self.subTest(name):
                self.assertIn(expected, self.reason(state, now))

    def test_defaults_to_this_boot_and_now(self):
        self.assertIsNone(self.settings.get_reason_to_refuse_without_checking(ShortPasswordState.starting_now()))
        self.assertIn("earlier boot", self.settings.get_reason_to_refuse_without_checking(ShortPasswordState(BOOT, 0, 0)))

    def test_describes_durations(self):
        self.assertEqual(describe_seconds(8 * HOUR + 5 * 60 + 59), "8h05m")


if __name__ == "__main__":
    unittest.main()
