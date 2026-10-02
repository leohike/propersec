"""The decisions of pam_hook.py, without the process around them.

pam_hook.py turns the command line, PAM's environment and stdin into plain values, then
hands them here. Nothing in this module parses arguments, reads stdin or looks at the
environment: it takes one user's files, a log and the typed input, and decides.

Refusal is the default. The only True on the unlock path is UnlockAttemptHook.unlock().
"""

from common import Log, Settings, ShortPasswordState, UserFiles


class UnlockAttemptHook:
    """One unlock attempt, for the user the lock screen is unlocking. Calling it decides."""

    def __init__(self, files: UserFiles, log: Log):
        self.files = files
        self.write_log = log

    def log(self, message: str) -> None:
        self.write_log(f"{self.files.user}: {message}")

    def __call__(self, typed_short_password: str | None) -> bool | None:
        """True unlocks. Every early return, and falling off the end, refuses.

        `typed_short_password` is what the user typed, or None when the hook found it unusable.
        """
        if not typed_short_password:
            self.log("empty or unusable input, refused without counting as a failed unlock")
            return
        settings = self.files.load_settings()
        if not settings.short_password_hash:
            self.log("no short_password is set, refused")
            return
        if len(typed_short_password) > settings.max_short_password_len:
            # Almost always the full_password. It can't be the short_password, so it isn't hashed, and it
            # isn't held against the short_password either.
            self.log(f"longer than {settings.max_short_password_len} characters, so not the short_password; not counted as a failed unlock")
            return
        self.files.require_private_run_dir()
        with self.files.lock():
            state = self.files.load_state()
            reason = settings.get_reason_to_refuse_without_checking(state)
            if reason:
                self.log(f"short_password refused, full_password required: {reason}")
                return
            assert state is not None  # a missing state is always a reason
            if settings.verify_short_password(typed_short_password):
                return self.unlock(state)
            self.count_failed_unlock(state, settings)

    def count_failed_unlock(self, state: ShortPasswordState, settings: Settings) -> None:
        """Count one more failed unlock. At the limit, the full_password is required."""
        state.failed_unlock_count += 1
        self.files.save_state(state)
        count, limit = state.failed_unlock_count, settings.max_failed_unlocks
        ending = ", full_password required from now on" if count >= limit else ""
        self.log(f"not the short_password, failed unlock {count} of {limit}{ending}")

    def unlock(self, state: ShortPasswordState) -> bool:
        """The only True on the unlock path. A correct short_password sets the failed unlock count back to 0."""
        state.failed_unlock_count = 0
        self.files.save_state(state)
        self.log("unlocked with the short_password")
        return True


def start_short_password_window_upon_successful_unlock(files: UserFiles, log: Log) -> None:
    """After a full_password unlock: allow the short_password again, from now, with nothing failed yet."""
    files.require_private_run_dir()
    with files.lock():
        files.save_state(ShortPasswordState.starting_now())
    log(f"{files.user}: full_password accepted, short_password window started")
