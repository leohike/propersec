# Learning from Linux-PAM's code

Written on 2026-10-01. It reads upstream Linux-PAM at tag `v1.7.2`, the version Fedora 44 ships (`pam-1.7.2-2.fc44`). The paths and line numbers below refer to that tag.

The question was whether lazypass could be built on top of Linux-PAM, to lean on code that is already secure and keep our own changes small. The short answer: not by forking it, and not by literally reusing its code. The repo is still the best reference there is for a later C or Rust version. Three of its modules solve, one by one, the problems lazypass solves together. This report records what to borrow, as ideas and patterns, and why.

## Why not fork it

- **A fork replaces PAM for every login, not just the lock screen.** sudo, SSH, SDDM, polkit and TTY login would all run the forked `libpam` and `pam_unix.so`. A bug in the fork could break the full_password everywhere. lazypass is built on the opposite principle: the stock path stays untouched, so the full_password always works.
- **The fork's security fixes become ours.** The repo is about 51,600 lines of C, around 44,400 without blank lines. PAM modules get CVEs, and Fedora patches and ships the fixes. A fork would have to merge every one, forever, to carry a feature of a few hundred lines.
- **The target system is image-based.** On Fedora Kinoite and its derivatives, replacing base-image packages takes `rpm-ostree override replace`, and every image update can then conflict with it.

The alternative that gets most of the benefit is a small standalone module, `pam_short_password.so`. It is built against the system's `pam-devel` headers, installed outside `/usr`, and named by its full path in `/etc/pam.d/kde` only. That's how third-party modules such as pam_u2f, fprintd's `pam_fprintd` and howdy ship. It reuses the system's libpam and libxcrypt by calling them, and copies the repo's patterns where they fit.

## The repo in numbers

Non-blank lines of C, counted with `wc`:

| Part | Lines |
|---|---|
| `libpam`, the library every PAM program links | 6,900 |
| `modules`, all bundled modules | 30,400 |
| of which `pam_unix` | 4,600 |
| of which `pam_exec` | 490 |
| `tests` | 1,800 |

The five files that matter most to lazypass total 3,137 lines including comments and blanks:

| File | Lines |
|---|---|
| `pam_unix_auth.c` | 213 |
| `support.c` | 940 |
| `passverify.c` | 1,214 |
| `unix_chkpwd.c` | 230 |
| `pam_exec.c` | 540 |

Much of `passverify.c` is about changing passwords and old hash formats. The verification itself is a small part of it.

## How pam_unix checks a password

This is the path the full_password takes through our added `pam_unix.so use_first_pass` line and through the stock substack.

- **`modules/pam_unix/pam_unix_auth.c`, `pam_sm_authenticate()`:**
  - gets the user with `pam_get_user()`, refusing names that start with `-` or `+`;
  - checks for a blank password with `_unix_blankpasswd()`;
  - takes the typed password with `pam_get_authtok()`. That's where `use_first_pass` takes effect: it reuses what an earlier line collected and never prompts.
- **`modules/pam_unix/support.c`, `_unix_verify_password()`:**
  - first asks for a 2-second delay on failure, unless the `nodelay` option is set (`support.c:726`): `pam_fail_delay(pamh, 2000000)`;
  - then picks a route. A process that can read `/etc/shadow` (it runs as root, like sudo or SDDM) verifies directly. One that can't, like our greeter running as the user, calls `_unix_run_helper_binary()`. That function forks the setuid helper `unix_chkpwd`, writes the password and a terminating NUL into a pipe, and reads the verdict from the helper's exit code.
- **`modules/pam_unix/unix_chkpwd.c`, the helper:**
  - reads the password from stdin, up to `PAM_MAX_RESP_SIZE`;
  - lets a caller that isn't root check only its own password. If the requested user doesn't match the caller's uid, it drops privileges and refuses;
  - sleeps 10 seconds on misuse, but not on an ordinary wrong password.
- **`modules/pam_unix/passverify.c`, `verify_pwd_hash()`** (from line 71):
  - refuses a locked account outright (`passverify.c:95`): a hash starting with `*` or `!`, or no password;
  - for modern hashes such as `$y$`, `$6$` and `$2b$`, calls `crypt_r(p, hash, cdata)` with the stored hash as the setting (`passverify.c:156`). Before that, it calls `crypt_checksalt()` to catch a hash method that libcrypt's configuration has disabled;
  - compares with `pam_consttime_streq(pp, hash)` (`passverify.c:169`), a constant-time string compare defined in `libpam/include/pam_inline.h:234`;
  - wipes the computed hash with `_pam_delete(pp)` (`passverify.c:177`).

**What lazypass already does the same way:**

- **The stored hash as the setting.** `Yescrypt.verify` gives the stored hash to libxcrypt's `crypt_rn` as its setting, so the right input reproduces the stored string exactly.
- **A constant-time compare.** `hmac.compare_digest` does the job of `pam_consttime_streq`.
- **The pipe format.** pam_exec hands our hook the input with a terminating NUL, the same as `unix_chkpwd` receives.
- **No root code at runtime.** The greeter runs as the user and never reads `/etc/shadow` itself.

**What lazypass doesn't do, and a port should:**

- **Wiping the secret from memory after use.** `_pam_delete` and `pam_overwrite_string` do that. Python can't do it reliably; C and Rust can.
- **`crypt_checksalt()`,** to tell a hash method that has been disabled apart from a wrong password.
- **A deliberate stance on `pam_fail_delay`.** A wrong short_password today adds no delay of its own. If the full_password then succeeds, there's no delay at all. If it fails, pam_unix's 2 seconds apply. A module could request a delay on a short_password failure as well. That slows a walk-up guesser, though the three-failure limit already caps the guesses.

## unix_chkpwd: the model for a privileged helper

The security analysis lists a verifying daemon as the right shape for a proper version: something that holds the hash where the user can't read it and answers only yes or no. `unix_chkpwd` is a 230-line working example of that pattern, as a setuid helper rather than a daemon:

- it reads the secret from a pipe, never from the command line or the environment;
- it lets a caller check only its own account, based on the real uid;
- its exit code is the only answer, so nothing else leaks;
- it drops privileges as soon as it has refused.

A daemon would identify its caller with `SO_PEERCRED` on a Unix socket instead of with the real uid. Everything else carries over.

## pam_exec: how our hook is called

`modules/pam_exec/pam_exec.c` (540 lines) defines exactly what `pam_hook.py` receives:

- the environment it runs with;
- how `expose_authtok` prompts if nothing has been typed yet, then writes the input and a NUL to stdin;
- what `quiet` and `quiet_log` suppress;
- how the exit code becomes a PAM result.

It's the reference for anything we assume about our own caller. If lazypass becomes a real module, pam_exec drops out, and so do the two Python startups it costs per full_password unlock.

## pam_timestamp: the short_password window, solved once already

`pam_timestamp` (about 2,200 lines) describes itself as "authenticate using cached successful authentication attempts", the mechanism sudo uses. A session it opens writes a timestamp file, and later attempts succeed while that file is "sufficiently recent", 5 minutes by default (`DEFAULT_TIMESTAMP_TIMEOUT`, `pam_timestamp.c:81`). That's lazypass's window under another name: a full_password unlock records a moment, and for a while afterwards something cheaper is accepted. Its design choices, set against ours:

- **The timestamp is signed.** Each file carries an HMAC made with a root-only key, `/var/run/pam_timestamp/_pam_timestamp_key`, so a user can't forge one. lazypass's state file is user-owned and unsigned, which the README lists as a known limit. Signing is the stronger design, but it needs a process that can read a root-only key, so it belongs with the daemon, not with a hook running as the user.
- **Its files are checked the way ours are.** The directory chain is walked with `lstat`, and anything that is a symlink, isn't owned by root, or is writable by group or others is refused (`pam_timestamp.c:116` onwards). The file is opened with `O_NOFOLLOW` and must be a regular file owned by root (`pam_timestamp.c:455` to `480`). That matches `read_trusted_file` closely.
- **A timestamp from before the current login doesn't count.** `check_login_time()` (`pam_timestamp.c:212`) asks logind for the user's login time and rejects anything older. It plays the same role as our boot-id check: a window from an earlier session must never carry over.
- **Its clock is the wall clock.** It uses `time(NULL)`, and `timestamp_good()` (`pam_timestamp.c:202`) even accepts a timestamp up to twice the timeout in the future, to tolerate clock changes. lazypass counts seconds since boot instead (`CLOCK_BOOTTIME`), so the clock can't be moved and needs no tolerance. Any timestamp in the future is simply refused.
- **The window is tied to a terminal** (`check_tty()`), which suits sudo. The lock screen has no terminal to tie it to, so this part doesn't carry over.

## pam_faillock: the failure counter, solved once already

`pam_faillock` (about 1,600 lines) counts authentication failures and locks the account after `deny=n` of them. Fedora's authselect profiles can switch it on. It is the closest relative of our failed unlock count.

- **It wraps pam_unix in three lines, like lazypass does.** `preauth` runs before pam_unix and refuses when the account is already locked. `authfail` runs after pam_unix fails and records the failure. `authsucc` runs after pam_unix succeeds and clears the count. lazypass's `check` line, its pam_unix gatekeeper line and its `start-short-password-window` line have the same shape, for the same reasons.
- **The tally file belongs to the user.** Tallies live in `/var/run/faillock` by default (`faillock.h:69`), one file per user. The code changes the file's owner to that user and makes it group-writable, mode `0660`, `user:root` (`faillock.c:87` to `103`). That's how an unprivileged screen locker can still record its failures, and it brings the same known limit lazypass has: code running as the user can reset their own count.
- **It locks the tally file itself** (`flock(fd, LOCK_EX)`, `faillock.c:87`), because it rewrites that file in place. lazypass replaces its state file atomically with a new one, which is why it needs a separate, never-replaced `lazypass.lock` instead.
- **It also asks for a 2-second delay on failure** (`pam_faillock.c:476`).
- **Its clock is the wall clock as well** (`pam_faillock.c:199`).

## What a port would take from where

| Part of lazypass | Reference in Linux-PAM |
|---|---|
| Hashing and comparing the short_password | `verify_pwd_hash()` in `passverify.c`: `crypt_r` with the stored hash, `crypt_checksalt`, `pam_consttime_streq`, wiping afterwards |
| The window after a full_password unlock | `pam_timestamp`: when a window is "good", rejecting windows from before the login, and file checks on the open descriptor |
| The failed unlock count and its reset | `pam_faillock`: the three-line layout around pam_unix, per-user tally ownership, locking the tally |
| A future verifying daemon or helper | `unix_chkpwd.c`: the secret over a pipe, only the caller's own account, the exit code as the only answer |
| What the hook receives today | `pam_exec.c` |
| Delay after a failure | `pam_fail_delay` as used in `support.c:726` and `pam_faillock.c:476` |

## Licence

`COPYING` is a BSD-style licence: copies of the source must keep the copyright notices and the licence text. It adds that the code may, alternatively, be distributed under the GNU GPL. Copying a function or two into a module of our own is allowed, provided the notice comes along. Most of what this report recommends is ideas and patterns rather than copied code, which needs no notice at all.
