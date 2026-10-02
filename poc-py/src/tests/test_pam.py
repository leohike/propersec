"""The whole lock-screen stack, through the real libpam and the real pam_exec.so.

The PAM files come from a temporary directory (pam_start_confdir) laid out like /etc/pam.d:

    kde            lazypass's three lines from pam/kde-auth.pam, then the stock kde auth lines
    password-auth  a mock of Fedora's: the fake pam_unix as `sufficient`, then pam_deny
    postlogin      empty, like Fedora's for auth

Only two things are swapped in lazypass's lines: the paths point into the sandbox, and
pam_unix becomes tests/fake-pam-unix, which accepts FULL_PASSWORD. The control columns are the
shipped ones, read from the shipped file.

What this cannot show: how the real pam_unix and the real greeter behave. INTEGRATION.md
lists those checks.
"""

import os
import unittest

from tests import pamharness
from tests.support import FULL_PASSWORD, HERE, HOOK, PRODUCT, SHORT_PASSWORD, SRC, Sandbox

SHIPPED_LINES = PRODUCT / "pam" / "kde-auth.pam"
FAKE_PAM_UNIX = HERE / "fake-pam-unix"

# The auth lines of Fedora 44's /usr/etc/pam.d/kde, unchanged.
STOCK_KDE_AUTH = """\
auth        substack      password-auth
auth        include       postlogin
"""

MOCK_PASSWORD_AUTH = """\
auth        sufficient    pam_exec.so quiet quiet_log expose_authtok {fake_unix} {full_password_file}
auth        required      pam_deny.so
"""


def build_test_stack(sandbox: Sandbox, hook: str = str(HOOK)) -> str:
    """The shipped lines with sandbox paths and the fake pam_unix, then the stock lines."""
    fake_unix = f"pam_exec.so quiet quiet_log expose_authtok {FAKE_PAM_UNIX} {sandbox.root / 'full_password'}"
    replacements = [
        ("/usr/local/libexec/lazypass/pam_hook.py", hook),
        ("--etc /etc/lazypass --run-base /run/user", " ".join(sandbox.hook_flags())),
        ("pam_unix.so use_first_pass", fake_unix),
    ]
    text = SHIPPED_LINES.read_text()
    for old, new in replacements:
        # Fail loudly if the shipped file changes shape, rather than test something else.
        assert old in text, f"{old!r} is no longer in {SHIPPED_LINES.name}"
        text = text.replace(old, new)
    return text + STOCK_KDE_AUTH


class PamStack(unittest.TestCase):
    def setUp(self):
        self.sandbox = Sandbox()
        self.addCleanup(self.sandbox.cleanup)
        self.sandbox.set_short_password()
        (self.sandbox.root / "full_password").write_text(FULL_PASSWORD)
        self.confdir = self.sandbox.root / "pam.d"
        self.confdir.mkdir()
        self.write_stack(build_test_stack(self.sandbox))
        (self.confdir / "password-auth").write_text(
            MOCK_PASSWORD_AUTH.format(fake_unix=FAKE_PAM_UNIX, full_password_file=self.sandbox.root / "full_password"))
        (self.confdir / "postlogin").write_text("# no auth lines, like Fedora's\n")
        # libpam logs to the journal when a confdir has no "other" fallback service.
        (self.confdir / "other").write_text("auth required pam_deny.so\n")
        self.pam = pamharness.PamClient(self.confdir, "kde", self.sandbox.user)

    def write_stack(self, text: str) -> None:
        (self.confdir / "kde").write_text(text)

    def unlock(self, typed: str) -> bool:
        attempt = self.pam.authenticate(typed)
        # One field, one prompt: no input ever triggers a second question.
        self.assertEqual(len(attempt.prompts), 1, attempt.prompts)
        self.assertEqual(attempt.messages, [])
        return attempt.unlocked

    def failed_unlock_count(self) -> int:
        return self.sandbox.get_state().failed_unlock_count


class Unlocking(PamStack):
    def test_full_password_required_until_the_first_full_password_unlock(self):
        self.assertFalse(self.unlock(SHORT_PASSWORD))
        self.assertTrue(self.unlock(FULL_PASSWORD))
        self.assertTrue(self.unlock(SHORT_PASSWORD))

    def test_wrong_input_fails(self):
        self.unlock(FULL_PASSWORD)
        for typed in ["0000", "", "x" * 300, FULL_PASSWORD + "x"]:
            with self.subTest(typed=typed[:20]):
                self.assertFalse(self.unlock(typed))

    def test_three_failed_unlocks_then_full_password_required_and_it_works(self):
        self.unlock(FULL_PASSWORD)
        for _ in range(3):
            self.assertFalse(self.unlock("0000"))
        self.assertFalse(self.unlock(SHORT_PASSWORD))
        self.assertTrue(self.unlock(FULL_PASSWORD))
        self.assertTrue(self.unlock(SHORT_PASSWORD))

    def test_full_password_works_in_every_state_and_allows_the_short_password(self):
        states = {
            "never allowed": lambda: None,
            "too many failed unlocks": lambda: [self.unlock("0000") for _ in range(3)],
            "state deleted": lambda: self.sandbox.files.state_file.unlink(missing_ok=True),
            "state corrupted": lambda: self.sandbox.files.state_file.write_text("junk"),
        }
        for name, reach_state in states.items():
            with self.subTest(name):
                reach_state()
                self.assertTrue(self.unlock(FULL_PASSWORD))
                self.assertEqual(self.failed_unlock_count(), 0)
                self.assertTrue(self.unlock(SHORT_PASSWORD))

    def test_wrong_full_password_never_allows_the_short_password(self):
        self.unlock(FULL_PASSWORD)
        self.unlock("0000")
        short_password_enabled_at = self.sandbox.get_state().short_password_enabled_at
        self.assertFalse(self.unlock("wrong full_password"))
        self.assertEqual(self.failed_unlock_count(), 1)  # too long to be the short_password, so not counted
        self.assertEqual(self.sandbox.get_state().short_password_enabled_at, short_password_enabled_at)
        self.assertNotIn("short_password window started", self.sandbox.get_log().splitlines()[-1])

    def test_short_password_does_not_extend_its_own_window(self):
        self.unlock(FULL_PASSWORD)
        self.sandbox.edit_state(short_password_enabled_at=self.sandbox.get_state().short_password_enabled_at - 10)
        short_password_enabled_at = self.sandbox.get_state().short_password_enabled_at
        self.assertTrue(self.unlock(SHORT_PASSWORD))
        self.assertEqual(self.sandbox.get_state().short_password_enabled_at, short_password_enabled_at)


class HookBroken(PamStack):
    """With the hook unable to run, the stack degrades to the full_password only.

    A hook that is missing or not executable makes pam_exec log the failed execve to the
    system journal, unconditionally. Those two tests therefore only run when asked to, with
    LAZYPASS_TESTS_MAY_LOG=1; the default run leaves the journal alone. The hook that dies
    by a signal stands in for both, and uses SIGKILL because it leaves no core dump.
    """

    def test_hook_killed(self):
        killed = self.sandbox.root / "killed-hook"
        killed.write_text("#!/bin/sh\nkill -KILL $$\n")
        killed.chmod(0o755)
        self.write_stack(build_test_stack(self.sandbox, hook=str(killed)))
        self.assertFalse(self.unlock(SHORT_PASSWORD))
        self.assertTrue(self.unlock(FULL_PASSWORD))

    def test_hook_exits_zero_without_reading_input(self):
        # Not a failure mode but a reminder of the trust placed in the hook: exit 0 IS unlock.
        accepting = self.sandbox.root / "accepting-hook"
        accepting.write_text("#!/bin/sh\nexit 0\n")
        accepting.chmod(0o755)
        self.write_stack(build_test_stack(self.sandbox, hook=str(accepting)))
        self.assertTrue(self.unlock("anything at all"))

    @unittest.skipUnless(os.environ.get("LAZYPASS_TESTS_MAY_LOG"), "logs to the journal; set LAZYPASS_TESTS_MAY_LOG=1")
    def test_hook_missing(self):
        self.write_stack(build_test_stack(self.sandbox, hook=str(self.sandbox.root / "no-such-hook")))
        self.assertFalse(self.unlock(SHORT_PASSWORD))
        self.assertTrue(self.unlock(FULL_PASSWORD))

    @unittest.skipUnless(os.environ.get("LAZYPASS_TESTS_MAY_LOG"), "logs to the journal; set LAZYPASS_TESTS_MAY_LOG=1")
    def test_hook_not_executable(self):
        copy = self.sandbox.root / "pam_hook.py"
        copy.write_bytes(HOOK.read_bytes())
        for module in ["core.py", "common.py"]:
            (self.sandbox.root / module).write_bytes((SRC / module).read_bytes())
        copy.chmod(0o644)
        self.write_stack(build_test_stack(self.sandbox, hook=str(copy)))
        self.unlock(FULL_PASSWORD)  # can't allow the short_password either, but the full_password still unlocks
        self.assertFalse(self.unlock(SHORT_PASSWORD))
        self.assertTrue(self.unlock(FULL_PASSWORD))


class Sanity(unittest.TestCase):
    def test_the_stack_under_test_is_the_shipped_one(self):
        sandbox = Sandbox()
        self.addCleanup(sandbox.cleanup)
        tested = [line.split()[:2] for line in build_test_stack(sandbox).splitlines() if line.startswith("auth")]
        shipped = [line.split()[:2] for line in SHIPPED_LINES.read_text().splitlines() if line.startswith("auth")]
        self.assertEqual(tested[:3], shipped)

    def test_never_runs_as_root(self):
        # Root would read the real files' rules differently; these tests are for a user's stack.
        self.assertNotEqual(os.getuid(), 0)


if __name__ == "__main__":
    unittest.main()
