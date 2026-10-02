"""Shared code for lazypass: a short_password that unlocks the KDE lock screen, within limits.

Two words run through all of it:

- full_password: the account password. It works everywhere, always, and is checked by pam_unix.
- short_password: a short extra password that unlocks the lock screen and nothing else, and only
  while it is allowed: for some hours after a full_password unlock, and until too many wrong
  attempts in a row. Otherwise the full_password is required.

Two programs use this module:

- pam_hook.py runs inside the lock screen's PAM stack (through pam_exec), as the locked
  user, on every unlock attempt. It has to be fast, quiet, and fail closed.
- cli.py is the management CLI, installed as the `lazypass` command: set, remove, status.

Nothing here checks the full_password or implements crypto. The full_password stays with pam_unix,
and hashing is the system's libxcrypt (yescrypt), called through ctypes.

Every location comes in through UserFiles; this module never names /etc or /run itself:

    <etc>/config                       global settings, optional     owner-only writable
    <etc>/users/<user>                 the user's settings and hash  owner:<user's group> 0640
    <run-base>/<uid>/lazypass.state    a ShortPasswordState               the user's own, on tmpfs
    <run-base>/<uid>/lazypass.lock     serialises concurrent attempts

"Owner" is root once installed. Tests pass their own uid instead, so they can run unprivileged.
"""

import ctypes
import dataclasses
import fcntl
import hmac
import os
import stat
import string
import syslog
import tempfile
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path

# A hard cap, in bytes, on input the hook reads and hashes, whatever the settings say.
# pam_exec passes at most PAM_MAX_RESP_SIZE (512).
MAX_SHORT_PASSWORD_BYTES = 256

# Config and user files are a few lines; anything longer is not one of ours.
MAX_FILE_BYTES = 4096

HASH_PREFIX = "$y$"  # yescrypt, the same scheme /etc/shadow uses on Fedora

# The setting that holds the short_password hash. Only a user's own file may have it.
HASH_SETTING = "hash"


class LazypassError(Exception):
    """Something is wrong enough that the short_password must not be used."""


# ---------------------------------------------------------------------------------------
# The one file format: `key = value` lines

def parse_settings(text: str, source: str) -> dict[str, str]:
    """Parse `key = value` lines. Blank lines and # comments are skipped; anything else is an error."""
    settings: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not key or not value:
            raise LazypassError(f"{source} line {number}: expected 'key = value'")
        if key in settings:
            raise LazypassError(f"{source} line {number}: {key} is given twice")
        settings[key] = value
    return settings


def format_settings(settings: dict[str, object]) -> str:
    return "".join(f"{key} = {value}\n" for key, value in settings.items())


# ---------------------------------------------------------------------------------------
# Settings

@dataclass
class ParameterSpec:
    """The type and the inclusive range one setting must have.

    A value outside its range is an error, never clamped: a typo must not quietly allow 50
    failed unlocks.
    """

    name: str
    type: type
    min: float
    max: float

    def check(self, raw: str, source: str) -> float:
        """`raw` converted to this setting's type, once it is in range. `source` names the file, for errors."""
        try:
            value = self.type(raw)
        except ValueError:
            raise LazypassError(f"{source}: {self.name} must be a number, not {raw!r}") from None
        # NaN fails both comparisons, so it is rejected here too.
        if not self.min <= value <= self.max:
            raise LazypassError(f"{source}: {self.name} must be between {self.min} and {self.max}, not {raw}")
        return value


# Every setting but the hash, which is checked where it is used.
PARAMETER_SPECS = [
    ParameterSpec("expiry_hours", float, 0.01, 168),
    ParameterSpec("max_failed_unlocks", int, 1, 10),
    ParameterSpec("max_short_password_len", int, 1, 64),  # 64 characters fit MAX_SHORT_PASSWORD_BYTES even at 4 bytes each
    ParameterSpec("min_length", int, 1, 64),
    ParameterSpec("min_letters", int, 0, 64),
    ParameterSpec("hash_cost", int, 1, 11),
]
PARAMETER_SPECS_BY_NAME = {spec.name: spec for spec in PARAMETER_SPECS}


@dataclass
class Settings:
    """Everything that decides one user's short_password: its hash, and the rules for it.

    It is built in layers: these defaults, then the global config, then the user's own file,
    each `update` winning over the layer before. Only the user's own file may hold the hash,
    so the defaults and the global config have none. Like a line of /etc/shadow, the user's
    file keeps the secret and the rules for it together, where only root can change them.

    The unlock path uses the hash and the next three fields; `set` uses the last four.
    """

    short_password_hash: str = field(default="", repr=False)  # empty: no short_password is set
    expiry_hours: float = 8.0    # the short_password is allowed this long after a full_password unlock
    max_failed_unlocks: int = 3  # failed unlocks in a row after which the full_password is required
    max_short_password_len: int = 12   # longest short_password, in characters; longer input is never hashed
    min_length: int = 4          # shortest short_password `set` accepts
    min_letters: int = 0         # English letters `set` requires; 0 turns the rule off
    hash_cost: int = 5           # yescrypt cost `set` uses; 5 hashes in ~20 ms, 8 in ~160 ms

    def update(self, settings: dict[str, str], source: str, *, may_set_hash: bool = False) -> None:
        """Take over each of `settings`, checked against its ParameterSpec. `source` names the file, for errors.

        Only a user's own file may set the hash (`may_set_hash`). Anywhere else, one line
        would give every user the same short_password.
        """
        for key, raw in settings.items():
            if key == HASH_SETTING:
                if not may_set_hash:
                    raise LazypassError(f"{source}: only a user's own file may hold a short_password hash")
                self.short_password_hash = raw
                continue
            spec = PARAMETER_SPECS_BY_NAME.get(key)
            if not spec:
                raise LazypassError(f"{source}: unknown setting {key!r}")
            setattr(self, key, spec.check(raw, source))

    def verify_short_password(self, typed_short_password: str) -> bool:
        """Whether `typed_short_password` is the short_password. Yescrypt.verify explains how."""
        if not self.short_password_hash:
            raise LazypassError("no short_password is set")
        return Yescrypt().verify(typed_short_password.encode(), self.short_password_hash)

    @property
    def expiry_seconds(self) -> float:
        return self.expiry_hours * 3600

    def get_short_password_problems(self, short_password: str) -> list[str]:
        """What a proposed short_password is missing, phrased to follow "the short_password needs"."""
        problems = []
        if len(short_password) < self.min_length:
            problems.append(f"at least {self.min_length} characters")
        if len(short_password) > self.max_short_password_len:
            problems.append(f"at most {self.max_short_password_len} characters")
        if sum(char in string.ascii_letters for char in short_password) < self.min_letters:
            problems.append(f"at least {self.min_letters} English letters")
        if not short_password.isprintable():
            problems.append("no control characters")
        return problems

    def get_reason_to_refuse_without_checking(self, state: "ShortPasswordState | None", boot_id: str | None = None, now: int | None = None) -> str | None:
        """Why the short_password must be refused right now without even checking it, which means
        the full_password is required; or nothing when the short_password is allowed.

        `boot_id` and `now` default to this boot and this moment. Tests pass their own, so they
        can try every case without a real clock or a reboot.
        """
        boot_id = get_boot_id() if boot_id is None else boot_id
        now = get_boottime() if now is None else now
        if state is None:
            return "no full_password unlock since boot"
        if state.boot_id != boot_id:
            return "the state is from an earlier boot"
        age = now - state.short_password_enabled_at
        if age < 0:
            return "the short_password enabled-at time is in the future"
        if age >= self.expiry_seconds:
            return f"the last full_password unlock was {describe_seconds(age)} ago"
        if state.failed_unlock_count >= self.max_failed_unlocks:
            return f"{state.failed_unlock_count} failed unlocks in a row"


# ---------------------------------------------------------------------------------------
# Hashing, through the system's libxcrypt

class Yescrypt:
    """yescrypt hashing through the system's libxcrypt, called with ctypes.

    Creating one opens the library. That is cheap: the dynamic loader opens a library once per
    process and hands back the same handle after that.
    """

    DATA_SIZE = 32768            # sizeof(struct crypt_data) in libxcrypt
    GENSALT_OUTPUT_SIZE = 192

    def __init__(self):
        library = ctypes.CDLL("libcrypt.so.2", use_errno=True)
        library.crypt_rn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]
        library.crypt_rn.restype = ctypes.c_char_p
        library.crypt_gensalt_rn.argtypes = [
            ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
        ]
        library.crypt_gensalt_rn.restype = ctypes.c_char_p
        self.library = library

    def hash(self, short_password: bytes, cost: int) -> str:
        """A fresh hash of `short_password`, salted from the kernel's random source."""
        return self.compute_hash(short_password, self.make_setting(cost)).decode()

    def verify(self, typed_short_password: bytes, stored_hash: str) -> bool:
        """Whether `typed_short_password` hashes to `stored_hash`, compared in constant time.

        The salt is inside the stored hash. A crypt(3) hash is one string,
        `$y$<cost>$<salt>$<hash>`, the same format /etc/shadow uses. Handed to compute_hash as
        the setting, it makes libxcrypt hash the input with the same algorithm, cost and salt,
        ignoring the old hash part, so the right input reproduces the stored string exactly.
        """
        if not stored_hash.startswith(HASH_PREFIX):
            raise LazypassError("the stored hash is not a yescrypt hash")
        stored = stored_hash.encode()
        return hmac.compare_digest(self.compute_hash(typed_short_password, stored), stored)

    def make_setting(self, cost: int) -> bytes:
        """What compute_hash needs to make a new hash: `$y$<cost>$<salt>`, with a fresh random salt."""
        buffer = ctypes.create_string_buffer(self.GENSALT_OUTPUT_SIZE)
        setting = self.library.crypt_gensalt_rn(HASH_PREFIX.encode(), cost, None, 0, buffer, len(buffer))
        if not setting:
            raise LazypassError(f"libxcrypt could not make a yescrypt salt with cost {cost}")
        return setting

    def compute_hash(self, phrase: bytes, setting: bytes) -> bytes:
        """The full hash string of `phrase`, from libxcrypt's crypt_rn.

        `setting` names the algorithm, cost and salt; any old hash after the salt is ignored.
        Bad input and libxcrypt's failures raise, so a failure can never pass for a hash.
        """
        # ctypes hands C a NUL-terminated string, so b"1234\0junk" would hash as b"1234" and
        # match a PIN of 1234. Refuse it here as well as at every entry point.
        if b"\0" in phrase:
            raise LazypassError("the short_password contains a NUL byte")
        if len(phrase) > MAX_SHORT_PASSWORD_BYTES:
            raise LazypassError(f"the short_password is longer than {MAX_SHORT_PASSWORD_BYTES} bytes")
        work_area = ctypes.create_string_buffer(self.DATA_SIZE)
        result = self.library.crypt_rn(phrase, setting, work_area, len(work_area))
        # libxcrypt signals failure with NULL, or with a string starting with "*" in some modes.
        if not result or result.startswith(b"*"):
            raise LazypassError("libxcrypt could not hash the short_password")
        return result


# ---------------------------------------------------------------------------------------
# One user's files

@dataclass
class ShortPasswordState:
    """Whether the short_password is allowed: what the last full_password unlock set, and what happened since.

    Kept in the user's runtime directory as `key = value` lines, one per field.
    """

    boot_id: str              # the boot this state belongs to; any other boot's state is ignored
    short_password_enabled_at: int  # CLOCK_BOOTTIME seconds at the last full_password unlock
    failed_unlock_count: int  # inputs in a row that weren't the short_password, since then or since
                              # the last short_password unlock; a mistyped full_password counts too

    @classmethod
    def starting_now(cls) -> "ShortPasswordState":
        """The state a full_password unlock leaves behind: this boot, this moment, nothing failed yet."""
        return cls(boot_id=get_boot_id(), short_password_enabled_at=get_boottime(), failed_unlock_count=0)

    @classmethod
    def parse(cls, text: str, source: str) -> "ShortPasswordState | None":
        """The state in `text`, or nothing unless it parses exactly.

        Anything unexpected reads as "no state", which means "full_password required": a damaged
        file can only take the short_password away, never hand out extra attempts.
        """
        try:
            settings = parse_settings(text, source)
        except LazypassError:
            return
        if settings.keys() != {field.name for field in dataclasses.fields(cls)}:
            return
        numbers = (settings["short_password_enabled_at"], settings["failed_unlock_count"])
        # isdigit() alone accepts characters like "²"; plain ASCII digits only, so no sign either.
        if not all(value.isascii() and value.isdigit() for value in numbers):
            return
        enabled_at, failed_unlock_count = map(int, numbers)
        return cls(boot_id=settings["boot_id"], short_password_enabled_at=enabled_at, failed_unlock_count=failed_unlock_count)

    def format(self) -> str:
        return format_settings(dataclasses.asdict(self))


def read_regular_file(path: Path) -> tuple[os.stat_result, str]:
    """The metadata and text of `path`, which must be a regular file and not a symlink.

    Both come from one open descriptor, so the file described is the file read. A missing
    file raises FileNotFoundError, which callers may expect; a symlink raises OSError.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise LazypassError(f"{path} is not a regular file")
        return info, os.read(descriptor, MAX_FILE_BYTES).decode()
    except UnicodeDecodeError:
        raise LazypassError(f"{path} is not UTF-8 text") from None
    finally:
        os.close(descriptor)


@dataclass
class UserFiles:
    """One user's lazypass files, and the rules for trusting each of them.

    The settings and the hash live under `etc` and must belong to `owner`, so the user can't
    change them. The state lives in the user's own runtime directory and is theirs.
    """

    etc: Path       # /etc/lazypass once installed
    run_base: Path  # /run/user once installed
    owner: int      # uid that must own everything under etc: root once installed
    user: str
    uid: int

    def __post_init__(self):
        if not self.user or "/" in self.user or self.user in (".", ".."):
            raise LazypassError(f"{self.user!r} is not a usable user name")

    @property
    def config(self) -> Path:
        return self.etc / "config"

    @property
    def user_file(self) -> Path:
        return self.etc / "users" / self.user

    @property
    def run_dir(self) -> Path:
        return self.run_base / str(self.uid)

    @property
    def state_file(self) -> Path:
        return self.run_dir / "lazypass.state"

    @property
    def lock_file(self) -> Path:
        return self.run_dir / "lazypass.lock"

    # --- the owner's side: settings and hash

    def read_trusted_file(self, path: Path, *, private: bool) -> str:
        """The text of `path`, provided it can be trusted: a regular file owned by `owner` (root
        once installed) that nobody else can change.

        `private` also refuses a file that users outside its group can read.
        """
        info, text = read_regular_file(path)
        if info.st_uid != self.owner:
            raise LazypassError(f"{path} is owned by uid {info.st_uid}, not {self.owner}")
        if info.st_mode & 0o022:
            raise LazypassError(f"{path} is writable by its group or by others")
        if private and info.st_mode & 0o004:
            raise LazypassError(f"{path} is readable by others")
        return text

    def load_settings(self) -> Settings:
        """This user's settings: the defaults, then the global config, then the user's own file,
        the only one that may hold the short_password hash. Without that file the hash is empty."""
        settings = Settings()
        settings.update(self.read_settings_file(self.config, private=False), source=str(self.config))
        settings.update(self.read_settings_file(self.user_file, private=True), source=str(self.user_file), may_set_hash=True)
        return settings

    def read_settings_file(self, path: Path, *, private: bool) -> dict[str, str]:
        """The `key = value` lines of a trusted file, or none at all when there is no such file."""
        try:
            return parse_settings(self.read_trusted_file(path, private=private), str(path))
        except FileNotFoundError:
            return {}

    def save_short_password_hash(self, short_password_hash: str, group: int) -> None:
        """Atomically write a new hash into the user's file: owned by the owner, readable by
        `group`, mode 0640. The user's other settings in the file are kept as they are."""
        lines = {**self.read_settings_file(self.user_file, private=True), HASH_SETTING: short_password_hash}
        self.user_file.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=self.user_file.parent, prefix=f".{self.user}.")
        try:
            os.fchown(descriptor, self.owner, group)
            os.fchmod(descriptor, 0o640)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(format_settings(lines))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.user_file)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(temporary)
            raise

    # --- the user's side: per-boot state

    def require_private_run_dir(self) -> None:
        """Refuse a runtime directory that isn't the user's own private one."""
        try:
            info = os.lstat(self.run_dir)
        except FileNotFoundError:
            raise LazypassError(f"{self.run_dir} does not exist") from None
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o077:
            raise LazypassError(f"{self.run_dir} is not a private directory owned by uid {self.uid}")

    @contextmanager
    def lock(self):
        """Hold an exclusive lock for one read-decide-write cycle of the state."""
        descriptor = os.open(self.lock_file, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def load_state(self) -> ShortPasswordState | None:
        """The saved state, or nothing when there is none or it can't be trusted (see parse)."""
        try:
            _, text = read_regular_file(self.state_file)
        except (OSError, LazypassError):
            return
        return ShortPasswordState.parse(text, str(self.state_file))

    def save_state(self, state: ShortPasswordState) -> None:
        """Replace the state file atomically: a reader sees the old state or the new, never half."""
        descriptor, temporary = tempfile.mkstemp(dir=self.run_dir, prefix=".lazypass.")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(state.format())
            os.replace(temporary, self.state_file)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(temporary)
            raise


# ---------------------------------------------------------------------------------------
# Clocks

def get_boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def get_boottime() -> int:
    """Seconds since boot, time in suspend included; changing the wall clock doesn't move it."""
    return int(time.clock_gettime(time.CLOCK_BOOTTIME))


def describe_seconds(seconds: float) -> str:
    minutes = int(seconds) // 60
    return f"{minutes // 60}h{minutes % 60:02d}m"


# ---------------------------------------------------------------------------------------
# Logging

class Log:
    """One line per event: to syslog (tag "lazypass", facility authpriv), or to a file in tests.

    Never pass a short_password or a full_password, or anything derived from one, to this.
    """

    def __init__(self, file: Path | None):
        self.file = file
        if file is None:
            syslog.openlog("lazypass", syslog.LOG_PID, syslog.LOG_AUTHPRIV)

    def __call__(self, message: str) -> None:
        if self.file is None:
            syslog.syslog(syslog.LOG_NOTICE, message)
            return
        with open(self.file, "a", encoding="utf-8") as handle:
            handle.write(message + "\n")
