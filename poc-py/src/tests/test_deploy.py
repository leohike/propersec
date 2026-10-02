"""deploy.py, run for real into a temporary root that the test's own user owns."""

import os
import pwd
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.support import DEPLOY, HOOK, PRODUCT


class Deploy(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lazypass-deploy-test-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.libexec = self.root / "usr/local/libexec/lazypass"
        self.deploy("install")

    def deploy(self, command: str) -> subprocess.CompletedProcess:
        owner = pwd.getpwuid(os.getuid()).pw_name
        return subprocess.run([DEPLOY, command, "--root", self.root, "--owner", owner], capture_output=True, text=True)

    def assert_check_reports(self, problem: str) -> None:
        result = self.deploy("check")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(problem, result.stdout)

    def test_installed_files_check_out_and_run(self):
        self.assertEqual(self.deploy("check").returncode, 0)
        result = self.deploy("smoke")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(result.stdout.endswith("hello lazypass\n"), result.stdout)

    def test_check_reports_a_wrong_mode_and_install_repairs_it(self):
        os.chmod(self.libexec / "core.py", 0o664)
        self.assert_check_reports("core.py: mode 0664, should be 0644")
        self.deploy("install")
        self.assertEqual(self.deploy("check").returncode, 0)

    def test_check_reports_a_stale_copy(self):
        with open(self.libexec / "common.py", "a") as file:
            file.write("# edited in place\n")
        self.assert_check_reports("common.py: differs from src/common.py")

    def test_check_reports_a_file_that_is_not_lazypass(self):
        (self.libexec / "notes.txt").touch()
        self.assert_check_reports("notes.txt: not part of lazypass")

    def test_check_reports_a_link_pointing_elsewhere(self):
        link = self.root / "usr/local/bin/lazypass"
        link.unlink()
        link.symlink_to("/bin/true")
        self.assert_check_reports("points to /bin/true")

    def test_smoke_fails_when_nothing_is_deployed(self):
        (self.libexec / "pam_hook.py").unlink()
        result = self.deploy("smoke")
        self.assertEqual(result.returncode, 1)
        self.assertIn("isn't deployed", result.stdout)


class SelfTest(unittest.TestCase):
    def test_hook_self_test_says_hello(self):
        result = subprocess.run([HOOK, "self-test"], capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout), (0, "hello lazypass\n"))

    def test_self_test_takes_no_arguments(self):
        result = subprocess.run([HOOK, "self-test", "--etc", "/nonexistent"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)


class PamFile(unittest.TestCase):
    """install-pam, backup-pam and restore-pam against a scratch /etc/pam.d/kde and vendor copy."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lazypass-pam-test-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.vendor = (PRODUCT / "backup/kde").read_text()  # this machine's vendor file, as backed up
        self.backup = self.root / "backup/kde"
        self.pam_file = self.root / "etc/pam.d/kde"
        self.vendor_file = self.root / "usr/etc/pam.d/kde"
        for path in (self.pam_file, self.vendor_file):
            path.parent.mkdir(parents=True)
            path.write_text(self.vendor)
        self.deploy("install")

    def deploy(self, *arguments, answer: str = "", pam_source: Path = PRODUCT / "pam/kde") -> subprocess.CompletedProcess:
        owner = pwd.getpwuid(os.getuid()).pw_name
        options = ["--root", self.root, "--owner", owner, "--backup", self.backup, "--pam-source", pam_source]
        return subprocess.run([DEPLOY, *arguments, *options], input=answer, capture_output=True, text=True)

    def test_stored_pam_file_is_the_vendor_file_plus_the_tested_lines(self):
        rendered = self.root / "rendered"
        self.assertEqual(self.deploy("render-pam", pam_source=rendered).returncode, 0)
        self.assertEqual(rendered.read_text(), (PRODUCT / "pam/kde").read_text())
        for line in (PRODUCT / "pam/kde-auth.pam").read_text().splitlines():
            if line.startswith("auth"):
                self.assertIn(line + "\n", rendered.read_text())

    def test_install_backs_up_then_activates_and_restore_undoes_it(self):
        result = self.deploy("install-pam", answer="y\n")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.backup.read_text(), self.vendor)
        self.assertEqual(self.pam_file.read_text(), (PRODUCT / "pam/kde").read_text())
        self.assertIn("lazypass is active", self.deploy("check").stdout)
        self.assertIn("nothing to do", self.deploy("install-pam").stdout)
        self.assertEqual(self.deploy("restore-pam", answer="y\n").returncode, 0)
        self.assertEqual(self.pam_file.read_text(), self.vendor)
        self.assertIn("lazypass is not active", self.deploy("check").stdout)

    def test_anything_but_yes_changes_nothing(self):
        result = self.deploy("install-pam", answer="yes please\n")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.pam_file.read_text(), self.vendor)

    def test_refuses_when_the_vendor_file_changed(self):
        self.vendor_file.write_text(self.vendor + "session     optional      pam_new_upstream.so\n")
        result = self.deploy("install-pam", answer="y\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("render-pam", result.stdout)
        self.assertEqual(self.pam_file.read_text(), self.vendor)

    def test_refuses_when_the_code_is_not_deployed(self):
        (self.root / "usr/local/libexec/lazypass/pam_hook.py").unlink()
        result = self.deploy("install-pam", answer="y\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("left alone", result.stdout)
        self.assertEqual(self.pam_file.read_text(), self.vendor)

    def test_restore_refuses_a_file_without_the_stock_path(self):
        broken = self.root / "broken"
        broken.write_text("auth required pam_permit.so\n")
        self.assertEqual(self.deploy("restore-pam", broken, answer="y\n").returncode, 1)
        self.assertEqual(self.pam_file.read_text(), self.vendor)

    def test_backup_never_overwrites_a_different_backup(self):
        self.deploy("backup-pam")
        self.pam_file.write_text(self.vendor + "# edited\n")
        self.assertEqual(self.deploy("backup-pam").returncode, 1)
        self.assertEqual(self.backup.read_text(), self.vendor)
