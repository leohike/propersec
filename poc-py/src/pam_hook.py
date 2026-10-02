#!/usr/bin/python3 -ISB
"""pam_hook.py: the unlock-path half of lazypass, run by pam_exec in the lock screen's PAM stack.

    check                   Is the typed input the short_password, and is the short_password allowed right
                            now? stdin is what the user typed (pam_exec expose_authtok). Exit
                            0 unlocks.
    start-short-password-window   A full_password unlock just succeeded: allow the short_password again, with no
                            failed unlocks counted and a fresh expiry window.
    self-test               Test only, never in a PAM line: load every module and libcrypt, hash and
                            verify a dummy, print "hello lazypass". Reads and writes no files.

This file is the process around the logic: the command line, PAM's environment, stdin and the
exit code. The decisions themselves are in core.py.

Refusal is the default. Exit 0 needs a True from main(), and for `check` that True comes from
exactly one place, core.UnlockAttemptHook.unlock(). Everything else (a wrong short_password, a full_password
required, a bad file, a bad argument, any exception, the time limit) ends in exit 1, which
the PAM line reads as "not the short_password", so the full_password is checked next.

It runs as the locked user, never as root. WALKTHROUGH.md traces one unlock end to end.
"""

import argparse
import os
import pwd
import signal
import sys
from contextlib import suppress
from pathlib import Path

# -I keeps the script's own directory off sys.path. Put it back explicitly, resolved, so the
# modules imported are the ones installed beside this file.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from core import UnlockAttemptHook, start_short_password_window_upon_successful_unlock  # noqa: E402
from common import MAX_SHORT_PASSWORD_BYTES, LazypassError, Log, UserFiles, Yescrypt  # noqa: E402

# pam_exec has no timeout, and a hung hook hangs the lock screen. SIGALRM's default action
# kills the process, which pam_exec sees as a failure.
TIME_LIMIT_SECONDS = 2


def main() -> bool | None:
    """True when the command succeeded: for `check`, that means unlock."""
    signal.alarm(TIME_LIMIT_SECONDS)
    if sys.argv[1:] == ["self-test"]:
        return self_test()
    try:
        args = parse_args()
    except SystemExit:  # argparse exits on a bad command line; refuse that too
        return
    log = Log(args.log)
    try:
        user, uid = get_calling_user()
        files = UserFiles(etc=args.etc, run_base=args.run_base, owner=args.owner, user=user, uid=uid)
        if args.command == "start-short-password-window":
            start_short_password_window_upon_successful_unlock(files, log)
            return True
        unlock_attempt = UnlockAttemptHook(files, log)
        return unlock_attempt(read_typed_input())
    except Exception as error:
        log(f"short_password refused: {error}")


def self_test() -> bool | None:
    """Whether the installed copy runs at all: its imports resolve and libcrypt loads."""
    yescrypt = Yescrypt()
    stored_hash = yescrypt.hash(b"hello", 1)
    if yescrypt.verify(b"hello", stored_hash) and not yescrypt.verify(b"bye", stored_hash):
        print("hello lazypass")
        return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="lazypass's lock-screen hook; see the module docstring")
    parser.add_argument("command", choices=["check", "start-short-password-window"])
    # Required on purpose: the PAM line names every path it uses, and nothing here falls
    # back to a real system path by accident.
    parser.add_argument("--etc", type=Path, required=True, help="where config and users/ live (/etc/lazypass)")
    parser.add_argument("--run-base", type=Path, required=True, help="parent of per-uid runtime dirs (/run/user)")
    parser.add_argument("--owner", type=int, default=0, help="uid that must own the files under --etc (root)")
    parser.add_argument("--log", type=Path, help="append log lines here instead of syslog (tests)")
    return parser.parse_args()


def get_calling_user() -> tuple[str, int]:
    """The user being unlocked: who this process runs as, and who PAM says it is."""
    uid = os.getuid()
    if uid == 0 or os.geteuid() == 0:
        raise LazypassError("running as root; this hook belongs in the lock screen's stack only")
    if os.environ.get("PAM_TYPE") != "auth":
        raise LazypassError("not called from a PAM auth stack")
    name = pwd.getpwuid(uid).pw_name
    if os.environ.get("PAM_USER") != name:
        raise LazypassError(f"PAM is authenticating {os.environ.get('PAM_USER')!r}, but this runs as {name!r}")
    return name, uid


def read_typed_input() -> str | None:
    """What the user typed, or nothing when it can't possibly be the short_password.

    pam_exec writes the input followed by a NUL. Input that is empty, too long, holds a NUL of
    its own, or isn't UTF-8 can never match a stored short_password, so it isn't counted as a failed
    unlock.
    """
    raw = sys.stdin.buffer.read(MAX_SHORT_PASSWORD_BYTES + 2).removesuffix(b"\0")
    if not raw or len(raw) > MAX_SHORT_PASSWORD_BYTES or b"\0" in raw:
        return
    with suppress(UnicodeDecodeError):
        return raw.decode()


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
