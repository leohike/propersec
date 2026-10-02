"""A throwaway stand-in for /etc/lazypass and /run/user, and helpers that drive lazypass in it.

Nothing a test does leaves its temporary directory: every command gets explicit paths and a
log file, and the files' owner is the uid running the tests rather than root.
"""

import dataclasses
import os
import pwd
import subprocess
import tempfile
from pathlib import Path

from common import ShortPasswordState, UserFiles

HERE = Path(__file__).resolve().parent
SRC = HERE.parent
PRODUCT = SRC.parent
HOOK = SRC / "pam_hook.py"
CLI = SRC / "cli.py"
DEPLOY = PRODUCT / "deploy.py"

SHORT_PASSWORD = "4859"
FULL_PASSWORD = "correct horse battery staple"


class Sandbox:
    def __init__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="lazypass-test-")
        self.root = Path(self.directory.name)
        self.uid = os.getuid()
        self.user = pwd.getpwuid(self.uid).pw_name
        self.files = UserFiles(etc=self.root / "etc", run_base=self.root / "run", owner=self.uid, user=self.user, uid=self.uid)
        self.files.etc.mkdir()
        self.files.run_dir.mkdir(parents=True, mode=0o700)
        self.log_file = self.root / "lazypass.log"

    def cleanup(self) -> None:
        self.directory.cleanup()

    # --- the hook, invoked the way pam_exec invokes it

    def hook(self, command: str, typed: bytes = b"", env: dict[str, str] | None = None, flags: list[str] | None = None) -> int:
        """Run pam_hook.py and return its exit code. `typed` gets pam_exec's trailing NUL."""
        pam_env = {"PAM_USER": self.user, "PAM_TYPE": "auth", "PAM_SERVICE": "kde"}
        result = subprocess.run(
            [HOOK, command, *(self.hook_flags() if flags is None else flags)],
            input=typed + b"\0" if typed else b"",
            env=pam_env | (env or {}),
            capture_output=True,
            timeout=10,
        )
        return result.returncode

    def hook_flags(self) -> list[str]:
        return ["--etc", str(self.files.etc), "--run-base", str(self.files.run_base), "--owner", str(self.uid), "--log", str(self.log_file)]

    def check(self, typed: str, **options) -> int:
        return self.hook("check", typed.encode(), **options)

    def start_short_password_window(self) -> int:
        return self.hook("start-short-password-window")

    # --- the CLI

    def cli(self, *args: str, stdin: str = "") -> subprocess.CompletedProcess:
        env = {key: value for key, value in os.environ.items() if key not in ("SUDO_USER", "PKEXEC_UID")}
        return subprocess.run(
            [CLI, "--etc", str(self.files.etc), "--run-base", str(self.files.run_base), "--owner", str(self.uid), *args],
            input=stdin, env=env, capture_output=True, text=True, timeout=10,
        )

    def set_short_password(self, short_password: str = SHORT_PASSWORD) -> None:
        result = self.cli("set", stdin=f"{short_password}\n{short_password}\n")
        assert result.returncode == 0, result.stderr

    # --- files

    def write_config(self, text: str) -> None:
        self.files.config.write_text(text)
        self.files.config.chmod(0o644)

    def get_state(self) -> ShortPasswordState | None:
        return self.files.load_state()

    def edit_state(self, **changes) -> None:
        """Rewrite fields of the current state, e.g. to pretend time passed or the machine rebooted."""
        state = self.get_state()
        assert state is not None
        assert changes.get("short_password_enabled_at", 0) >= 0, "can't move short_password_enabled_at to before boot"
        self.files.save_state(dataclasses.replace(state, **changes))

    def get_log(self) -> str:
        return self.log_file.read_text() if self.log_file.exists() else ""
