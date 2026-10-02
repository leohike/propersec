#!/usr/bin/python3 -I
"""Install lazypass's code and directories, check them, smoke-test them, and install the PAM file.

    sudo deploy.py install   copy src/ into place, create /etc/lazypass, fix SELinux labels
    deploy.py check          every deployed path exists, with the owner, mode, content and label it should have
    deploy.py smoke          run what was deployed, as yourself: imports, libcrypt, the CLI

    deploy.py install-pam    put pam/kde in place as /etc/pam.d/kde (sudo inside, after a diff and a yes)
    deploy.py backup-pam     copy /etc/pam.d/kde to backup/kde, never overwriting a different backup
    deploy.py restore-pam    put backup/kde (or a named file) back as /etc/pam.d/kde, after a diff and a yes
    deploy.py render-pam     rebuild pam/kde from the image's /usr/etc/pam.d/kde and pam/kde-auth.pam

`install` never touches /etc/pam.d/kde: activating lazypass is its own step, `install-pam`.
No short_password is set either: that is `sudo lazypass set`, typed by you.

--root, --owner, --backup and --pam-source exist for the tests, which deploy into a scratch
directory owned by whoever runs them. Real use passes none of them.
"""

import argparse
import difflib
import filecmp
import grp
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

PRODUCT = Path(__file__).resolve().parent
SRC = PRODUCT / "src"
CODE_MODES = {"pam_hook.py": 0o755, "cli.py": 0o755, "core.py": 0o644, "common.py": 0o644}

# The stock line lazypass's three lines go above. A file without it has lost the stock path.
STOCK_AUTH = re.compile(r"^auth\s+substack\s+password-auth\b", re.MULTILINE)
PAM_LINES = PRODUCT / "pam/kde-auth.pam"
PAM_MARKER = "# lazypass: the three lines below are pam/kde-auth.pam; `just lazypass restore-pam` takes them out\n"


def add_lazypass_lines(vendor: str) -> str:
    """The vendor PAM file with lazypass's three lines inserted above the stock auth substack."""
    added = [line for line in PAM_LINES.read_text().splitlines(keepends=True) if line.strip() and not line.startswith("#")]
    match = STOCK_AUTH.search(vendor)
    if not match:
        raise ValueError("no 'auth substack password-auth' line to put lazypass's lines above")
    return vendor[:match.start()] + PAM_MARKER + "".join(added) + vendor[match.start():]


def print_diff(old: str, new: str, old_name: str, new_name: str) -> None:
    sys.stdout.writelines(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True), old_name, new_name))


class Deployment:
    """Where lazypass lives under one root, and who must own it."""

    def __init__(self, root: Path, owner: str, backup: Path, pam_source: Path):
        self.root = root
        self.owner = pwd.getpwnam(owner)
        self.backup = backup
        self.pam_source = pam_source
        self.pam_file = root / "etc/pam.d/kde"
        self.vendor_pam_file = root / "usr/etc/pam.d/kde"
        self.libexec = root / "usr/local/libexec/lazypass"
        self.bin_link = root / "usr/local/bin/lazypass"
        self.etc = root / "etc/lazypass"
        self.users = self.etc / "users"
        self.run_base = root / "run/user"

    @property
    def is_real(self) -> bool:
        return self.root == Path("/")

    def install(self) -> None:
        os.umask(0o022)
        self.make_dir(self.libexec)
        for name, mode in CODE_MODES.items():
            self.place(self.libexec / name, mode, lambda temporary, name=name: shutil.copyfile(SRC / name, temporary))
        self.make_dir(self.bin_link.parent)
        self.place(self.bin_link, None, lambda temporary: os.symlink(self.libexec / "cli.py", temporary))
        self.make_dir(self.etc)
        self.make_dir(self.users)
        if self.is_real:
            labelled = [self.libexec.resolve(), self.bin_link.parent.resolve() / self.bin_link.name, self.etc]
            subprocess.run(["restorecon", "-RFv", *map(str, labelled)], check=True)
            # The parent too, which install may have just created; not recursively, it isn't ours.
            subprocess.run(["restorecon", "-Fv", str(self.libexec.parent.resolve())], check=True)
        print(f"installed into {self.root}")

    def make_dir(self, path: Path) -> None:
        """Create `path` and any missing parents, 0755 and owned by the owner. Existing parents are left alone."""
        missing = [path, *[parent for parent in path.parents if not parent.exists()]]
        path.mkdir(parents=True, exist_ok=True)
        for directory in missing:
            os.chmod(directory, 0o755)
            os.chown(directory, self.owner.pw_uid, self.owner.pw_gid)

    def place(self, path: Path, mode: int | None, create) -> None:
        """Make `path` by building it beside the target and renaming it over: never missing, never half-written."""
        temporary = path.with_name(f".{path.name}.deploying")
        temporary.unlink(missing_ok=True)
        create(temporary)
        if mode is not None:
            os.chmod(temporary, mode)
        os.lchown(temporary, self.owner.pw_uid, self.owner.pw_gid)
        os.replace(temporary, path)

    def check(self) -> list[str]:
        """Every problem with what is deployed. Empty means it is all in place."""
        problems = []
        uid, gid = self.owner.pw_uid, self.owner.pw_gid
        problems += self.check_path(self.libexec, stat.S_ISDIR, 0o755, uid, gid)
        for name, mode in CODE_MODES.items():
            path = self.libexec / name
            problems += self.check_path(path, stat.S_ISREG, mode, uid, gid)
            if path.is_file() and not filecmp.cmp(path, SRC / name, shallow=False):
                problems.append(f"{path}: differs from src/{name}; deploy again")
        if self.libexec.is_dir():
            extra = sorted(set(os.listdir(self.libexec)) - set(CODE_MODES))
            problems += [f"{self.libexec / name}: not part of lazypass; remove it" for name in extra]
        problems += self.check_path(self.bin_link, stat.S_ISLNK, None, uid, gid)
        if self.bin_link.is_symlink() and os.readlink(self.bin_link) != str(self.libexec / "cli.py"):
            problems.append(f"{self.bin_link}: points to {os.readlink(self.bin_link)}, not {self.libexec / 'cli.py'}")
        problems += self.check_path(self.etc, stat.S_ISDIR, 0o755, uid, gid)
        problems += self.check_path(self.users, stat.S_ISDIR, 0o755, uid, gid)
        if (self.etc / "config").exists():
            problems += self.check_path(self.etc / "config", stat.S_ISREG, 0o644, uid, gid)
        if self.users.is_dir():
            for user_file in sorted(self.users.iterdir()):
                problems += self.check_user_file(user_file)
        if self.is_real:
            problems += self.check_labels()
        return problems

    def check_path(self, path: Path, is_kind, mode: int | None, uid: int, gid: int) -> list[str]:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return [f"{path}: missing"]
        problems = []
        if not is_kind(info.st_mode):
            problems.append(f"{path}: wrong kind of file")
        if mode is not None and stat.S_IMODE(info.st_mode) != mode:
            problems.append(f"{path}: mode {stat.S_IMODE(info.st_mode):04o}, should be {mode:04o}")
        if (info.st_uid, info.st_gid) != (uid, gid):
            problems.append(f"{path}: owned by {info.st_uid}:{info.st_gid}, should be {uid}:{gid}")
        return problems

    def check_user_file(self, user_file: Path) -> list[str]:
        """A user's hash file is readable by their private group only, the group named after them."""
        try:
            group = grp.getgrnam(user_file.name)
        except KeyError:
            return [f"{user_file}: no group named {user_file.name!r} to own it"]
        return self.check_path(user_file, stat.S_ISREG, 0o640, self.owner.pw_uid, group.gr_gid)

    def check_labels(self) -> list[str]:
        """Each path's SELinux label is the one the policy says it should have (what restorecon sets)."""
        paths = [self.libexec, *[self.libexec / name for name in CODE_MODES], self.bin_link, self.etc, self.users]
        problems = []
        for path in paths:
            if not path.exists() and not path.is_symlink():
                continue  # reported as missing already
            result = subprocess.run(["matchpathcon", "-V", str(path)], capture_output=True, text=True)
            if result.returncode != 0:
                problems.append(f"SELinux label: {(result.stdout + result.stderr).strip()}; run restorecon -RF on it")
        return problems

    def smoke(self) -> bool:
        """Run what was deployed, as an ordinary user would. Changes nothing but a temporary log file."""
        if os.geteuid() == 0:
            print("run smoke as yourself, not as root: the hook refuses root by design")
            return False
        hook = self.libexec / "pam_hook.py"
        if not hook.is_file() or not self.bin_link.is_symlink():
            print("lazypass isn't deployed; run: just lazypass deploy")
            return False
        steps = []

        result = subprocess.run([hook, "self-test"], capture_output=True, text=True)
        steps.append(("hook imports its modules and libcrypt", result.returncode == 0 and result.stdout == "hello lazypass\n", result))

        # A real `check`, with no PAM around it: it must parse its arguments and then refuse.
        with tempfile.TemporaryDirectory(prefix="lazypass-smoke-") as scratch:
            log = Path(scratch) / "hook.log"
            environment = {key: value for key, value in os.environ.items() if not key.startswith("PAM_")}
            result = subprocess.run(
                [hook, "check", "--etc", self.etc, "--run-base", self.run_base, "--owner", str(self.owner.pw_uid), "--log", log],
                input=b"", capture_output=True, env=environment,
            )
            logged = log.read_text() if log.exists() else ""
            steps.append(("hook refuses outside PAM", result.returncode == 1 and "not called from a PAM auth stack" in logged, result))

        if self.is_real:
            found = shutil.which("lazypass")
            steps.append((f"`lazypass` on PATH is {self.bin_link}", found == str(self.bin_link), found))
            result = subprocess.run(["lazypass", "status"], capture_output=True, text=True)
        else:
            arguments = ["--etc", self.etc, "--run-base", self.run_base, "--owner", str(self.owner.pw_uid)]
            result = subprocess.run([self.bin_link, *arguments, "status"], capture_output=True, text=True)
        steps.append(("`lazypass status` runs through the link", result.returncode == 0 and result.stdout.startswith("user"), result))

        for summary, passed, detail in steps:
            print(f"{'ok    ' if passed else 'FAILED'}  {summary}")
            if not passed:
                print(f"        {detail}")
        if all(passed for _, passed, _ in steps):
            print("hello lazypass")
            return True
        return False


    # --- /etc/pam.d/kde

    def describe_pam_file(self) -> str:
        current = self.pam_file.read_text() if self.pam_file.is_file() else None
        if current is None:
            return f"{self.pam_file} is missing"
        if self.pam_source.is_file() and current == self.pam_source.read_text():
            return f"{self.pam_file} has lazypass's lines: lazypass is active"
        if self.vendor_pam_file.is_file() and current == self.vendor_pam_file.read_text():
            return f"{self.pam_file} is the image's vendor copy: lazypass is not active"
        return f"{self.pam_file} matches neither pam/kde nor the vendor copy"

    def render_pam(self) -> bool | None:
        """Rebuild pam/kde from the vendor file. Only the repo changes; review the diff and commit it."""
        new = add_lazypass_lines(self.vendor_pam_file.read_text())
        old = self.pam_source.read_text() if self.pam_source.is_file() else ""
        if new == old:
            print(f"{self.pam_source} is already the vendor file plus lazypass's lines")
            return True
        print_diff(old, new, str(self.pam_source), "rebuilt")
        self.pam_source.write_text(new)
        print(f"rebuilt {self.pam_source}; review and commit it")
        return True

    def install_pam(self, force: bool) -> bool | None:
        """Activate lazypass: the deployed code must check out, and pam/kde must still match the image."""
        problems = self.check()
        if problems:
            print("\n".join(problems))
            print("the code isn't deployed correctly, so /etc/pam.d/kde was left alone; run: just lazypass deploy")
            return
        if not self.vendor_pam_file.is_file():
            print(f"no vendor copy at {self.vendor_pam_file} to build on; refusing")
            return
        expected = add_lazypass_lines(self.vendor_pam_file.read_text())
        if self.pam_source.read_text() != expected:
            print_diff(self.pam_source.read_text(), expected, str(self.pam_source), f"{self.vendor_pam_file} plus lazypass's lines")
            print(f"the image's {self.vendor_pam_file} changed since pam/kde was made, and installing would drop that change.")
            print("run: just lazypass render-pam, review the diff, commit, then try again")
            return
        if not self.backup.exists() and not self.backup_pam():
            return
        print(f"backup: {self.backup}; undo with: just lazypass restore-pam")
        return self.put_pam_file(self.pam_source, force)

    def backup_pam(self) -> bool | None:
        current = self.pam_file.read_text()
        if not self.backup.exists():
            self.backup.parent.mkdir(parents=True, exist_ok=True)
            self.backup.write_text(current)
            os.chmod(self.backup, 0o644)
            print(f"backed up to {self.backup}")
        elif self.backup.read_text() == current:
            print(f"{self.backup} already matches {self.pam_file}")
        else:
            print_diff(self.backup.read_text(), current, str(self.backup), str(self.pam_file))
            print(f"{self.backup} differs from {self.pam_file} and was kept; delete it first to replace it")
            return
        print(self.describe_pam_file())
        return True

    def restore_pam(self, source: Path | None, force: bool) -> bool | None:
        return self.put_pam_file(source or self.backup, force)

    def put_pam_file(self, source: Path, force: bool) -> bool | None:
        """Make /etc/pam.d/kde a copy of `source`, after showing the diff and asking."""
        new = source.read_text() if source.is_file() else ""
        if not STOCK_AUTH.search(new):
            print(f"{source} is missing, or lacks the stock 'auth substack password-auth' line; refusing")
            return
        current = self.pam_file.read_text()
        if new == current and not force:
            print(f"{self.pam_file} already matches {source}; nothing to do (-f writes it anyway)")
            return True
        if new == current:
            print(f"{self.pam_file} already matches {source}; writing it anyway (-f)")
        print_diff(current, new, str(self.pam_file), str(source))
        if self.is_real and not sys.stdin.isatty():
            print("no terminal to confirm on; refusing")
            return
        try:
            answer = input(f"Replace {self.pam_file} with {source}? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip() != "y":
            print("nothing changed")
            return
        self.write_pam_file(source)
        print(f"{self.pam_file} now matches {source}")
        return True

    def write_pam_file(self, source: Path) -> None:
        """Written beside it, then renamed over it: PAM never sees a missing or half-written file."""
        temporary = self.pam_file.with_name(".kde.lazypass-deploying")
        if not self.is_real:
            shutil.copyfile(source, temporary)
            os.chmod(temporary, 0o644)
            os.replace(temporary, self.pam_file)
            return
        sudo = [] if os.geteuid() == 0 else ["sudo"]
        for command in [
            ["install", "-m", "0644", "-o", "root", "-g", "root", source, temporary],
            ["mv", "-f", temporary, self.pam_file],
            # -F resets the SELinux user too (system_u, like the original), not only the type.
            ["restorecon", "-Fv", self.pam_file],
        ]:
            subprocess.run([*sudo, *map(str, command)], check=True)


def main() -> bool | None:
    parser = argparse.ArgumentParser(description="Deploy lazypass, check it, smoke-test it, and install its PAM file.")
    parser.add_argument("command", choices=["install", "check", "smoke", "install-pam", "backup-pam", "restore-pam", "render-pam"])
    parser.add_argument("file", nargs="?", type=Path, help="restore-pam: the file to restore (default: backup/kde)")
    parser.add_argument("-f", "--force", action="store_true", help="install-pam, restore-pam: write even when it already matches")
    parser.add_argument("--root", type=Path, default=Path("/"), help="tests only: deploy under this directory")
    parser.add_argument("--owner", default="root", help="tests only: who owns the deployed files")
    parser.add_argument("--backup", type=Path, default=PRODUCT / "backup/kde", help="tests only: where backup-pam keeps its copy")
    parser.add_argument("--pam-source", type=Path, default=PRODUCT / "pam/kde", help="tests only: the PAM file install-pam installs")
    args = parser.parse_args()
    if args.file and args.command != "restore-pam":
        parser.error("only restore-pam takes a file")
    deployment = Deployment(args.root, args.owner, args.backup, args.pam_source)
    if args.command == "install":
        if deployment.is_real and os.geteuid() != 0:
            print("install writes /usr/local and /etc; run it with sudo", file=sys.stderr)
            return
        deployment.install()
        return True
    if args.command == "check":
        problems = deployment.check()
        for problem in problems:
            print(problem)
        if problems:
            return
        print(f"all lazypass files in place under {deployment.root}")
        print(deployment.describe_pam_file())
        return True
    if args.command == "install-pam":
        return deployment.install_pam(args.force)
    if args.command == "backup-pam":
        return deployment.backup_pam()
    if args.command == "restore-pam":
        return deployment.restore_pam(args.file, args.force)
    if args.command == "render-pam":
        return deployment.render_pam()
    return deployment.smoke()

if __name__ == "__main__":
    sys.exit(0 if main() else 1)
