#!/usr/bin/python3 -ISB
"""lazypass: manage the short_password that unlocks the KDE lock screen.

This is cli.py. Installed, the `lazypass` command is a symlink to it.

    sudo lazypass set       choose a new short_password, typed twice
    sudo lazypass remove    delete it; the lock screen is back to the full_password only
    lazypass status         what is set, which policy applies, and whether the short_password is allowed now

set and remove change files that only root may change, so they run under sudo or pkexec,
and getting there takes the full_password. That is the point: someone at an unlocked desk
must not be able to plant a short_password they know. status needs nothing.

The short_password is read from the terminal, or from stdin (two lines) when stdin isn't one. It is
never taken from the command line, where other users could see it in the process list.
"""

import argparse
import getpass
import grp
import os
import pwd
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from common import (  # noqa: E402
    LazypassError,
    UserFiles,
    Yescrypt,
    describe_seconds,
    get_boottime,
)


class Failure(Exception):
    """A problem to report to the person running the command, without a traceback."""


def main() -> bool | None:
    """True when the command succeeded."""
    args = parse_args()
    try:
        args.run(Configurator(args))
        return True
    except (Failure, LazypassError) as error:
        print(f"lazypass: {error}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="lazypass", description="Manage the short_password: a short password for the KDE lock screen.")
    parser.add_argument("--etc", type=Path, default=Path("/etc/lazypass"), help="default: %(default)s")
    parser.add_argument("--run-base", type=Path, default=Path("/run/user"), help="default: %(default)s")
    parser.add_argument("--owner", type=int, default=0, help="uid that owns the files under --etc (default: root)")
    commands = parser.add_subparsers(required=True, metavar="command")
    for name, run, summary in [
        ("set", Configurator.set_short_password, "choose a new short_password"),
        ("remove", Configurator.remove_short_password, "delete the short_password"),
        ("status", Configurator.print_status, "show what is set and whether it works right now"),
    ]:
        command = commands.add_parser(name, help=summary, description=summary)
        command.add_argument("--user", help="whose short_password (default: the sudo/pkexec caller, or you)")
        command.set_defaults(run=run)
    return parser.parse_args()


def get_target_user(name: str | None) -> pwd.struct_passwd:
    """Whose short_password: the one named, else whoever called sudo or pkexec, else whoever runs this."""
    try:
        if name:
            user = pwd.getpwnam(name)
        elif os.environ.get("SUDO_USER"):
            user = pwd.getpwnam(os.environ["SUDO_USER"])
        elif os.environ.get("PKEXEC_UID"):
            user = pwd.getpwuid(int(os.environ["PKEXEC_UID"]))
        else:
            user = pwd.getpwuid(os.getuid())
    except (KeyError, ValueError):
        raise Failure("no such user") from None
    if user.pw_uid == 0:
        raise Failure("root has no lock screen to unlock; name the user with --user")
    return user


def ask_short_password_twice() -> str:
    if sys.stdin.isatty():
        first = getpass.getpass("New short_password: ")
        second = getpass.getpass("Same again: ")
    else:
        first, second = sys.stdin.readline().rstrip("\n"), sys.stdin.readline().rstrip("\n")
    if first != second:
        raise Failure("the two entries differ; nothing was changed")
    return first


class Configurator:
    """One command, about one user's short_password."""

    def __init__(self, args: argparse.Namespace):
        self.account = get_target_user(args.user)
        self.files = UserFiles(
            etc=args.etc, run_base=args.run_base, owner=args.owner, user=self.account.pw_name, uid=self.account.pw_uid,
        )

    def set_short_password(self) -> None:
        self.require_owner()
        group = self.get_private_group()
        settings = self.files.load_settings()
        short_password = ask_short_password_twice()
        problems = settings.get_short_password_problems(short_password)
        if problems:
            raise Failure("the short_password needs " + ", ".join(problems))
        # Only the hash changes. Per-user settings already in the file are kept.
        self.files.save_short_password_hash(Yescrypt().hash(short_password.encode(), settings.hash_cost), group.gr_gid)
        print(f"Short_password set for {self.files.user}. It is allowed after the next full_password unlock at the lock screen.")

    def remove_short_password(self) -> None:
        self.require_owner()
        try:
            self.files.user_file.unlink()
        except FileNotFoundError:
            raise Failure(f"no short_password is set for {self.files.user}") from None
        print(f"Short_password removed for {self.files.user}. The lock screen takes the full_password only.")

    def print_status(self) -> None:
        print(f"user            {self.files.user}")
        try:
            settings = self.files.load_settings()
        except (OSError, LazypassError) as error:
            print(f"short_password  unusable: {error}")
            return
        if not settings.short_password_hash:
            print(f"short_password  unusable: no short_password is set for {self.files.user}")
            return
        print(f"short_password  set, in {self.files.user_file}")
        print(f"policy          allowed for {settings.expiry_hours:g}h after a full_password unlock, until {settings.max_failed_unlocks} failed unlocks in a row")
        rules = f"{settings.min_length} to {settings.max_short_password_len} characters"
        if settings.min_letters:
            rules += f", {settings.min_letters} English letters"
        print(f"set rules       {rules}, yescrypt cost {settings.hash_cost}")
        state = self.files.load_state()
        now = get_boottime()
        reason = settings.get_reason_to_refuse_without_checking(state, now=now)
        if reason:
            print(f"right now       full_password required: {reason}")
            return
        assert state is not None
        remaining = settings.expiry_seconds - (now - state.short_password_enabled_at)
        print(f"right now       short_password allowed for another {describe_seconds(remaining)}, {state.failed_unlock_count} of {settings.max_failed_unlocks} failed unlocks so far")

    def require_owner(self) -> None:
        if os.geteuid() == self.files.owner:
            return
        if self.files.owner == 0:
            raise Failure("this changes files only root may change; run it with sudo")
        raise Failure(f"this must run as uid {self.files.owner}, the owner given with --owner")

    def get_private_group(self) -> grp.struct_group:
        """The user's own group, which is allowed to read their hash file. A shared one is refused."""
        group = grp.getgrgid(self.account.pw_gid)
        shared = group.gr_mem or any(
            other.pw_gid == group.gr_gid and other.pw_name != self.account.pw_name for other in pwd.getpwall()
        )
        if group.gr_name != self.account.pw_name or shared:
            raise Failure(f"{self.account.pw_name}'s primary group {group.gr_name!r} is not private to them, so it can't guard the hash")
        return group


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
