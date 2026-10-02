# Walkthrough: one unlock, end to end

This follows three attempts at the lock screen through PAM and through the code: the short_password, the full_password, and a wrong full_password. It assumes the files are installed as INTEGRATION.md describes. The PAM tests run exactly this sequence with temporary paths.

## The stack the lock screen runs

When you press Enter, the lock screen (`kscreenlocker_greet`, running as you) asks PAM to authenticate you for the service `kde`. PAM reads the `auth` lines of `/etc/pam.d/kde` top to bottom. With lazypass added, they are:

```
auth  [success=done default=ignore]  pam_exec.so ... expose_authtok pam_hook.py check ...   # added
auth  [success=ok default=die]       pam_unix.so use_first_pass                               # added
auth  optional                       pam_exec.so ... pam_hook.py start-short-password-window ...  # added
auth  substack                       password-auth                                            # stock
auth  include                        postlogin                                                # stock
```

The bracket on each line says what PAM does with that line's result:

- **`done`:** stop and return success.
- **`ignore`:** act as if the line never ran.
- **`ok`:** note the success and continue.
- **`die`:** stop and return failure.

`optional` means the result barely matters. `substack` runs another file's lines as a sealed group.

## Attempt one: the short_password

You type `4859` and press Enter.

**Line 1, pam_exec.** It needs the typed text (`expose_authtok`). Nothing has asked for it yet, so it asks the lock screen through PAM's conversation, which is the one field you already typed into. It stores the answer as PAM's `PAM_AUTHTOK`, so later lines can reuse it. Then it starts `pam_hook.py check`:

- as you, not root;
- with `4859` plus a NUL byte on stdin;
- with only PAM's own variables in its environment: `PAM_USER`, `PAM_TYPE=auth` and `PAM_SERVICE=kde`.

**The hook** is two files in `src/`. `pam_hook.py` is the process around the logic: the command line, PAM's environment, stdin and the exit code. `core.py` holds the decisions and touches none of those. Once `main()` knows who is being unlocked and what they typed, it builds one `UnlockAttemptHook` object from `core.py` and calls it with the typed input. The object holds that user's files (`UserFiles` in `common.py`: where they live, whose they are, who must own them) and the log:

- `main()` sets a 2-second alarm first. pam_exec has no timeout, so this is the only thing standing between a hang and a frozen lock screen. Then it parses the flags, which the PAM line spells out in full; there are no default paths to fall back to by accident.
- `get_calling_user()` refuses unless all three hold:
  - the process isn't root;
  - `PAM_TYPE` is `auth`;
  - `PAM_USER` is the user the process runs as.
- `read_typed_input()` takes the bytes from stdin and strips pam_exec's NUL. Input that is empty, too long, not UTF-8, or contains a NUL of its own comes back as nothing.
- Calling the `UnlockAttemptHook` (its `__call__`, in `core.py`):
  - Nothing typed, or nothing usable, is refused at once, without counting as a failed unlock.
  - `files.load_settings()` builds one `Settings` object in layers: the defaults, then `/etc/lazypass/config`, then your own `/etc/lazypass/users/<you>`. Your file holds the short_password hash, and any setting you have that differs from the global one; only your file may hold a hash. Without a hash, the attempt is refused here. Each file must be a regular file, not a symlink, owned by root and writable by nobody else. The checks happen on the open file, so the file checked is the file read.
  - Input longer than `max_short_password_len` (12 characters) can't be the short_password. It is refused right here, not hashed and not counted as a failed unlock. `4859` is 4 characters, so it goes on.
  - `files.require_private_run_dir()` insists that `/run/user/<uid>` is yours and private.
  - Everything from here to the end runs under `files.lock()`, so two attempts can't interleave.
  - `files.load_state()` reads `/run/user/<uid>/lazypass.state`. Anything unexpected in it reads as "no state", which means the full_password is required.
  - `settings.get_reason_to_refuse_without_checking(state)` is the whole decision, in one small method. It reads this boot's id and the time since boot itself, but tests can pass their own, so they try every case without files, a real clock or a reboot. It returns why the short_password must be refused without even checking it, which means the full_password is required:
    - there is no state;
    - the boot id is from another boot;
    - `short_password_enabled_at` is in the future;
    - the 8 hours are up;
    - there have been 3 failed unlocks in a row.
  - When the short_password is allowed, `settings.verify_short_password()` hands `4859` to `Yescrypt.verify()`, which hashes it with the stored salt using libxcrypt and compares the results in constant time. A wrong input goes to `count_failed_unlock()`.
  - It matches, so `unlock()` sets the failed unlock count back to 0 (`files.save_state()` replaces the file atomically), writes one line to the log, and returns True, so the hook exits 0. Refusal is the default: every other path returns nothing, and `unlock()` holds the only `return True` on the unlock path.

**Back in PAM:** exit 0 is a success on a `success=done` line, so the stack stops and the screen unlocks. pam_unix never ran.

## Attempt two: the full_password

You type your full_password.

**Line 1:** the hook runs as before. The full_password is longer than 12 characters, so the hook refuses it straight after loading the settings: no hash, no lock, no failed unlock counted. It exits 1. The result is `default=ignore`, so PAM carries on as if line 1 never happened. (A full_password of 12 characters or fewer would be hashed, fail to match, and count as a failed unlock, which line 3 then wipes.)

**Line 2:** pam_unix checks the same input against `/etc/shadow`, through its setuid helper, because you can't read shadow yourself. `use_first_pass` makes it reuse the stored input and never ask again. The full_password is correct, so `success=ok`: noted, and PAM continues.

**Line 3:** `pam_hook.py start-short-password-window` (`start_short_password_window_upon_successful_unlock()`, a plain function in `core.py`) allows the short_password again by writing a fresh `ShortPasswordState`: this boot's id, the current time since boot as `short_password_enabled_at`, and a `failed_unlock_count` of 0. That also wipes any failed unlocks counted before.

**Lines 4 and 5:** the stock lines run, untouched. Inside `password-auth`, pam_unix checks the same stored input again and passes; there, it's marked `sufficient`, which ends that group with success. `postlogin` has no auth lines. Overall result: success, and the screen unlocks.

## Attempt three: a wrong full_password

**Line 1:** not the short_password. If it's longer than 12 characters it is refused without counting; otherwise a failed unlock is counted. Either way the hook exits 1, `ignore`.

**Line 2:** pam_unix fails, and `default=die` stops the whole stack right here with failure.

**Line 3 never runs.** This is why the added pam_unix line exists. Without it, allowing the short_password would have to come after the stock `substack`, and PAM keeps going after a failed substack: a wrong full_password would allow the short_password again and grant three fresh guesses every time. The PAM tests check exactly this. Changing `die` to `ignore` in the shipped file makes them fail.

## Where the tests stand in for the real thing

| Real | In the tests |
|---|---|
| The lock screen asking PAM | `PamClient` in `src/tests/pamharness.py`, a small ctypes PAM client that answers every prompt with the same typed text and counts the prompts |
| `/etc/pam.d/kde`, `password-auth` | Files in a temporary directory, loaded with `pam_start_confdir`. The three lazypass lines are read from `pam/kde-auth.pam` itself. |
| pam_unix and `/etc/shadow` | `src/tests/fake-pam-unix`, run through pam_exec, accepting one known full_password |
| `/etc/lazypass`, `/run/user/<uid>` | `etc/` and `run/<uid>/` in a temporary directory, owned by you instead of root (`--owner`) |
| syslog | A log file (`--log`) |
| 8 hours passing, a reboot | Editing the state file's `short_password_enabled_at` or boot id |

libpam, pam_exec, the hook, the CLI, libxcrypt and the file checks are all the real ones.
