# properpin

A PIN for the KDE Plasma lock screen, within limits. Two words run through everything here:

- **password:** your account password. It is long, it works everywhere, always, and stock `pam_unix` checks it.
- **PIN:** a short extra secret, digits or letters. It unlocks the lock screen and nothing else, and only while it is **armed**: for 8 hours after a password unlock at the lock screen, and until 3 failures in a row. Otherwise the password is required. Failures nobody forgave, counted across days and reboots, **disable** it until root turns it back on, as the failure budget section below explains.

Login, sudo, polkit, TTY and SSH never see the PIN. The full rules, the threat model and the reasoning live with the Python proof of concept in `poc-py/` (its README, WALKTHROUGH.md and docs/), which this Rust version follows rule for rule, with one change of architecture: the PIN hashes and the failure counts are reachable only by a `properpin` system group with no members, and only a helper that is setgid to that group reads them, so nothing the user runs can read a hash or reset a count. The Helper section below explains it, and `docs/threat-insider-hash-leak.md` at the repo root explains why.

**Status: not installed on any real machine.** Everything builds and runs in `target/`, temporary directories and a podman container. The installer, `packaging/install.sh`, exists and is tested against a fake root and, as root, inside a stock Fedora 44 container; no recipe runs it anywhere else.

## Try it

```
just properpin demo     # set, refused before arming, armed, unlocked, three failures, refused (through the real helper)
just properpin test     # every test: rules, files and hashing, the CLI, the PAM stack
just properpin smoke    # only the PAM stack, through the system's libpam
just properpin lint     # clippy with warnings as errors, and a formatting check
just properpin podman   # install, enable and attack it as root in a stock Fedora 44 container
```

## Crates

| Crate | Folder | What it is |
|---|---|---|
| `properpin-core` | `crates/core` | The rules, with no I/O and no `unsafe`: settings and their ranges, the state file format, the failure budget (`Budget`), every reason the PIN is refused (`Refusal`), and one unlock attempt (`check`, returning a `Verdict`) or arming (`arm`). Files, clock and hashing come in through the `Store`, `Clock` and `Hasher` traits. |
| `properpin-sys` | `crates/sys` | Those traits on a real machine: `UserFiles` (trusted-file checks on the open file, atomic writes, a lock with a timeout, the state and the budget in sticky directories of the helper's group, where each user's files must be that user's own), `Yescrypt` (the system's libxcrypt), `BootClock` (boot id, `CLOCK_BOOTTIME`, and the wall clock for the budget), account and group lookups. |
| `properpin-helper` | `crates/helper` | The setgid program that holds the hashes and counts: `check`, `arm` (after checking the password again through `unix_chkpwd`) and `status`. `lib.rs` decides, with every location passed in, so the tests drive it directly; `main.rs` is the setgid entry point; `secure.rs` holds all of its `unsafe` code (the clean start, `AT_SECURE`, syslog). |
| `pam_properpin` | `crates/pam` | The PAM module the lock screen would load: it reads what was typed, pipes it to the helper the way pam_unix feeds `unix_chkpwd`, and maps the exit code. `pam.rs` holds all of its `unsafe` code: the two entry points, `pam_get_user`, `pam_get_authtok`, `pam_syslog` and the SIGCHLD guard. Every error and every panic ends in `PAM_IGNORE`. |
| `properpin-cli` | `crates/cli` | The `properpin` command: `set`, `enable` and `remove` (as root), and `status`, which asks the helper. |
| `pamharness` | `crates/pamharness` | Test-only: a PAM client that runs `pam_authenticate` through the real libpam the way kscreenlocker does (one session for many attempts, `pam_setcred` after a success, a fail-delay callback that records instead of sleeping), with service files from a temporary directory (`pam_start_confdir`) or the system's own (`pam_start`, as the lock screen does), and the SIGCHLD settings real hosts have (`host`). |
| `properpin-systest` | `crates/systest` | Test-only: `install.sh` against a fake root (`tests/install.rs`), and the scenarios the container runs (`src/main.rs`). |

`core` ← `sys` ← `helper`, `pam`, `cli`. Nothing shipped depends on `pamharness` or `properpin-systest`.

## The PAM lines

`pam/kde-auth.pam` holds the three lines that would go above the stock `auth substack password-auth` in `/etc/pam.d/kde`. The stack tests build their PAM stack from this very file, so the control columns tested are the ones that would ship.

```
auth  [success=done default=ignore]  .../pam_properpin.so check helper=/usr/local/libexec/properpin/properpin-helper
auth  [success=ok default=die]       pam_unix.so use_first_pass
auth  optional                       .../pam_properpin.so arm helper=/usr/local/libexec/properpin/properpin-helper
```

The middle line is why a wrong password never arms the PIN at the lock screen: it stops the stack before `arm` runs. The helper checks the password again anyway, because anything the user runs can call it directly. Paths are always spelled out in the PAM line and on the CLI (`--etc`, `--helper`); nothing falls back to a real system path by accident.

## Files, once installed

| Path | Holds | Owner and mode |
|---|---|---|
| `/etc/properpin/config` | Global settings, optional | `root:root 0644` |
| `/etc/properpin/users/` | One file per user with a PIN | `root:properpin 0750` |
| `/etc/properpin/users/<user>` | That user's yescrypt hash, plus optional per-user settings | `root:properpin 0640`: the helper reads it, nobody else but root |
| `/run/properpin/` | Every user's per-boot state, created at boot by `/etc/tmpfiles.d/properpin.conf` | `root:properpin 1770`, on tmpfs: only the group can enter, and the sticky bit lets each file be replaced or deleted only by its owner |
| `/run/properpin/<uid>.state` | `boot_id`, `armed_at`, `failures` | `<uid>:properpin 0600`: the user it describes owns it, but can't enter the directory to reach it |
| `/run/properpin/<uid>.lock` | Keeps two attempts from interleaving | `<uid>:properpin 0600` |
| `/var/lib/properpin/` | Every user's failure budget, on disk, so it survives reboots | `root:properpin 1770`, like `/run/properpin` |
| `/var/lib/properpin/<uid>.budget` | Failures waiting to be forgiven, concerning failures of the last 7 days, the total since the PIN was set, and whether it is disabled | `<uid>:properpin 0600` |
| `/usr/local/libexec/properpin/properpin-helper` | The helper | `root:properpin 2755` (setgid only) |
| `/etc/sysusers.d/properpin.conf` | The `properpin` system group (`g properpin -`): no members, no account | `root:root 0644` |

The format is poc-py's `key = value` lines, and the hash is the same `$y$` yescrypt string, so a poc-py user file's `hash = ...` line carries over as is. Settings were renamed to the new vocabulary: `max_failed_unlocks` is now `max_failures`, `max_short_password_len` is `max_pin_length`, `min_length` is `min_pin_length`; `expiry_hours`, `min_letters` and `hash_cost` are unchanged. An unknown setting is an error, so an old name can't be silently ignored.

## Installing

`packaging/install.sh` does it in two separate steps, so everything can be installed and checked while the lock screen still runs its stock stack:

```
cargo build --release -p pam_properpin -p properpin-helper -p properpin-cli
sudo products/pin/packaging/install.sh install    # group, module, helper, command, /etc/properpin, /run/properpin; PAM untouched
sudo products/pin/packaging/install.sh check      # kind, mode, owner, bytes and SELinux label of every path; the group empty and locked
sudo products/pin/packaging/install.sh enable     # the three lines into /etc/pam.d/kde, after a diff and a yes
sudo properpin set                                # choose the PIN
sudo properpin enable                             # only if too many concerning failures disabled it
```

`disable` takes out exactly the lines `enable` added, between their two marker lines, and leaves everything else in the file as it is; it never deletes `/etc/pam.d/kde`. `enable` saves the file it changed as `/etc/properpin/kde.pam.before-enable`. `uninstall` refuses while enabled and keeps `/etc/properpin`, with the PINs in it, `/var/lib/properpin`, with the budgets, and the `properpin` group those files belong to. `install` creates the group with `systemd-sysusers` where it exists and `groupadd --system` otherwise; no user is ever created. `check` on the real system needs root, because it also reads `/etc/gshadow`: it fails when the group has members, is anyone's primary group, or has a password that isn't locked, since any of those would give someone the group without running the helper. The installed `properpin` command is a two-line wrapper that passes this machine's paths to the real binary in `/usr/local/libexec/properpin/`.

## The helper

`properpin-helper` is to properpin what `unix_chkpwd` is to pam_unix: a small program with more rights than its caller, which reads the secret on a pipe and answers with an exit code. It is owned by root and setgid to the `properpin` group, as Debian's `unix_chkpwd` is setgid to `shadow`: it runs as its caller, with the group added, so the caller can't change the binary, and nothing can log in as properpin, because no such account exists. The group has no members and a locked password, so running the helper is the only way to get it. The helper never takes a user name or a path from its caller: the caller is the real uid the kernel reports. Each user's counts file belongs to that user, in a sticky directory, so one user's run of the helper, even an exploited one, can't read, replace or delete another's, and a counts or lock file planted in someone else's name is refused. Before anything else it puts the process into a known state: stdin, stdout and stderr open, every other file closed, signals reset, the environment cleared, umask 077, working directory `/`, and panics abort without printing.

Arming is open to anything the user runs, so `arm` takes the password and checks it through `unix_chkpwd`, which answers about the calling user only. A wrong password arms nothing and resets nothing.

For local tests, the helper accepts `--dev-etc`, `--dev-run`, `--dev-owner`, `--dev-chkpwd` and `--dev-log`, but only when two independent checks agree that it runs without elevated rights: the kernel's `AT_SECURE` flag is clear, and the real and effective user and group ids are equal (`dev_options_allowed`). Then it has no more rights than its caller, so the caller choosing its files gives nothing away. Installed setgid, any `--dev` option is refused outright, which the container test checks. The stack and CLI tests use this to run the real binary against a sandbox. `docs/at-secure.md` at the repo root explains the two checks, `docs/helper-review.md` lists every hazard of a program with more rights than its caller and the code that handles it, and `docs/concerns.md` holds what is still open.

## The failure budget

The failures in a row stop a burst of guesses, but a correct PIN wipes them, so someone with repeated access could guess twice whenever you step away, forever. The budget closes that, without any notification:

- **Every input typed at the lock screen that doesn't unlock is a failure,** wrong passwords included, since the `check` line sees everything before `pam_unix` does. An empty input isn't, and nothing is counted for a user without a PIN.
- **The user's own typos are forgiven:** a correct PIN forgives the failures of the 45 seconds before it (`forgive_before_correct_pin`), the correct password those of the 90 seconds before it (`forgive_before_correct_password`, through `arm`, after `unix_chkpwd` accepted it). A correct password typed at the lock screen is itself a failure for a moment, until `arm` forgives it.
- **A failure nothing forgave in time is concerning.** It is judged at the helper's next run; no daemon is needed.
- **The PIN is disabled** at 10 concerning failures within 24 hours (`max_concerning_24h`), 20 within 7 days (`max_concerning_7d`), or 100 since the PIN was set (`max_concerning_total`). Disabled, the PIN is refused and the password no longer arms it, until `sudo properpin enable` (same PIN; recent failures forgotten, the total kept, so it refuses once the total is reached) or `sudo properpin set` (new PIN, fresh budget).
- **It survives reboots:** the budget is in `/var/lib/properpin`, stamped with the wall clock. A failure stamped more than a minute in the future, which means the clock went back, is concerning at once. Whoever can set the clock could age failures out of the 24-hour and 7-day windows, but never out of the total.
- **A damaged or foreign budget refuses the PIN** instead of being read as a fresh one; `set` starts it over.

The five settings may only be set in `/etc/properpin/config`, never per user. `properpin status` shows the counts, and the journal has a line for each failure that becomes concerning and for the moment the PIN is disabled. The total limit is what bounds an attacker: whatever their pace, about 100 guesses per PIN, against 60 million two-word PINs or 10,000 four-digit ones.

## Like the lock screen

The module starts the helper from inside the lock screen and needs its exit code, so process-wide state is part of its correctness: the SIGCHLD setting, who reaps which child, and what other threads do meanwhile. The tests run attempts the way kscreenlocker does: one PAM session kept for many attempts, as both 6.7.5 and 6.8 do, with `pam_setcred` after a success. `crates/pam/tests/stack.rs` then has hosts misbehave, each test in a process of its own, since SIGCHLD is one setting for the whole process: a host that ignores SIGCHLD and one whose handler reaps every child both still get every answer and keep their setting; a host thread looping on `waitpid(-1)` takes the helper's exit status, and the PIN fails closed while the password still works; the host's own child, exiting while the helper runs, can still be collected; attempts on four threads at once keep the host's handler; and a panic while SIGCHLD is changed puts it back. The four-thread test found a real race: two threads each saving and restoring SIGCHLD lost the host's handler, so properpin's attempts now take turns at that point (a mutex in `DefaultSigchld`). Nothing in the real lock screen runs properpin on two threads at once, and on Fedora no module in the fingerprint or smartcard stacks starts a child, so this was latent. `docs/harness-closer-to-kscreenlocker.md` at the repo root has the reasoning.

## The container test

`just properpin podman` builds everything with Fedora's own Rust inside a stock Fedora 44 image, takes `/etc/pam.d/kde` from Fedora's plasma-workspace package, installs and enables properpin with `install.sh` as root (creating the `properpin` group and the setgid helper), and then runs `crates/systest` (about a minute). Each PAM attempt runs as the test user, the way the lock screen runs as the locked user, so the module starts the real setgid helper and `pam_unix` checks the password through its own setuid helper `unix_chkpwd`, both for real. The test listens on `/dev/log` itself, so it sees what the module, the helper and `pam_unix` log through syslog. Nothing about this machine changes beyond podman's image storage.

The scenarios: the rollout (refused after boot, armed by the password, three failures), the PIN being refused by every other service (`sudo`, `su`, `login`, `system-auth`, `password-auth`, `passwd`, `other`), files tampered with as root (readable, owned by the user, symlinked, corrupt, a hash in the global config, a shared runtime directory, corrupt state), state from an earlier boot, from the future and expired, three wrong PINs at once, and `disable` plus `uninstall` restoring `/etc/pam.d/kde` byte for byte. Then the helper, attacked as the users would: the user can't read their hash, list the files, or read, delete or replace their counts; another user gets nothing and spends none of the tries; `--dev` options pointing at the user's own files are refused under setgid; a poisoned start (closed stdout and stderr, an extra open file, `LD_PRELOAD` and a hostile environment) changes no answer; `arm` with a wrong password arms nothing, through the real `unix_chkpwd`; a missing helper refuses the PIN while the password still works; `status` shows only the caller's own PIN and refuses root. And the helper's group, played by bob with the group added, as if he had exploited the helper: it can't append to, chmod, rename, delete or replace the helper; it can't read, overwrite, delete, rename or replace alice's counts; a lock file and an armed state planted in alice's name before her first attempt are refused, with a log line naming the lock file's owner; and `install.sh check` fails when bob is added to the group or the group's password is emptied, and no `properpin` user exists. And the budget: a wrong PIN or password followed by the right one leaves nothing behind; the slow attack (a guess, the user's correct PIN two minutes later, again) disables the PIN on the third round with the daily limit at 3; a disabled PIN stays disabled across a wiped `/run`, standing in for a reboot, even for the password, until `properpin enable`; the total limit can't be lifted by `enable`, only by `set`; and a damaged budget, or one planted by another user, refuses the PIN. Scenarios backdate the budget's timestamps as root instead of waiting. And the lifecycle of kscreenlocker 6.8: a long-lived worker process serves the password, the PIN, a wrong PIN and the PIN again on one session, only the failure asks for a delay, and the worker exits cleanly after `pam_end`; a worker killed at chosen and random moments while checking a wrong PIN, with SIGKILL or with SIGTERM and SIGKILL 25 ms later as the greeter cancels, never unlocks, its helper finishes on its own, a fresh attempt right after gets the lock, and the logged failures, the state and the budget agree. Every attempt process must exit cleanly, never by a signal, and after every scenario no helper may still be running. The run prints how long a correct PIN takes through the real stack, about 20 to 25 ms today, under the 50 ms that 6.8 calls too quick, which is what the minimum-duration row in the plan is about.

What it can't show: the greeter's own behaviour, SELinux (a container doesn't enforce the host's policy for its files), logind and the journal. The test was checked by breaking things on purpose: with the middle PAM line set to `default=ignore`, three scenarios fail and the log shows `unix_chkpwd` rejecting the password and the module arming the PIN anyway; with the readable-by-others check removed, its scenario fails; with the helper's `AT_SECURE` check disabled, the `--dev` scenario fails; with `arm`'s password check removed, the arming scenario fails, as do two local tests. For the setgid layout: with the sticky bit dropped from the run directory (in `install.sh`, the test's reset and the directory check), bob deletes alice's counts and that scenario fails; with the lock file's owner check removed, the planted-files scenario fails on its log line, though the PIN is still refused, because a state file that isn't the user's own reads as no state; with the `AT_SECURE` half of `dev_options_allowed` removed, its unit test fails while the container's `--dev` scenario still passes on the id comparison alone, which shows the two checks are independent. For the budget: with forgiveness turned into a no-op, the typos scenario and the slow-attack scenario fail, as do four unit tests; with the budget kept in `/run`, the reboot scenario fails because the password arms the PIN again; with a correct PIN clearing the recent failures, the slow-attack scenario and the matching unit test fail. For the lifecycle: with the SIGCHLD guard skipping its restore during a panic, the panic test fails; without the mutex, the four-thread test fails; with `-z nodelete` removed, every container scenario still passes, because glibc keeps a library mapped while it has thread-local destructors pending, so the crash needs a thread that exits after `pam_end`, which the load/unload test in `stack.rs` covers.

## Secrets in memory

What was typed is held in `Secret` (`properpin-core`), which is wiped when dropped and can be neither printed nor cloned. The module copies it out of libpam once, writes it into the pipe to the helper and drops it as soon as the helper has answered; the helper reads it into a buffer of fixed size, which never grows, and wipes it on exit, and `arm` passes the password on to `unix_chkpwd` through another pipe; libxcrypt's NUL-terminated input copy and its 32 KB work area are wiped after every hash, and a check compares the computed hash where libxcrypt wrote it, without copying it out. The CLI wraps both entries of `properpin set` and reads stdin into a buffer that can't grow. This is best effort: libpam's own copy (`PAM_AUTHTOK`, which `pam_unix` reads next and libpam wipes itself), the lock screen's copies and the terminal's are out of reach. `docs/pin-pam-copy.md` at the repo root holds the open question about libpam's copy.

## CI

GitHub Actions runs `.github/workflows/ci.yml` on every push to any branch and on pull requests. It has four jobs, and any of them failing fails the run:

- **Tests (Fedora 44):** `cargo test --workspace --locked` in a `fedora:44` container with Fedora's own Rust, as an unprivileged user, because the module refuses to run as root.
- **System test (podman):** the two commands behind `just properpin podman`, on an Ubuntu runner, with rootful podman (`sudo`): in the runner's rootless podman, setuid `unix_chkpwd` can't read `/etc/shadow`, so the real password never unlocks.
- **Dependency audit:** `cargo-deny` and `cargo-audit`. Only known security advisories (and crates flagged unsound) fail it; licences, bans, duplicates and sources, configured in `deny.toml` at the repo root, only add a warning to the run for now.
- **Rust 1.98 (Ubuntu):** the same tests with exactly the declared `rust-version`, against Ubuntu's libpam and libxcrypt.

clippy and fmt are not in CI: run `just properpin lint` before pushing. Results are in the repository's Actions tab, or through `gh run list` and `gh run view --log-failed`. Dependabot proposes weekly bumps for the pinned actions and for `Cargo.lock`, once the configuration is on `main`.

## Four things learned building it

- **The module must never be unloaded.** libpam `dlclose`s modules at every `pam_end`, but Rust's standard library registers thread-local destructors that glibc runs at thread exit. Once the module is unmapped, that segfaults the host process: here the lock screen (rust-lang/rust#91979). It reproduces on Fedora 44. The module is linked with `-z nodelete` (see `crates/pam/build.rs`), and the load/unload test in `tests/stack.rs` crashes without it.
- **A test that reads syslog must never stop reading.** A Unix datagram socket queues only a few messages (10 by default). The first container test read `/dev/log` between attempts only, so three concurrent attempts filled the queue, and the module, `pam_unix` and `unix_chkpwd` all blocked in `syslog()`, waiting for the test that was waiting for them. Logging from inside PAM is a blocking call, so a stalled syslog daemon could hang the lock screen the same way.
- **Setuid changes the user, not the group.** The first container run of the helper failed every scenario: it ran as `properpin` but still had the caller's group, so it couldn't read hash files readable by the `properpin` group. The fix then was making it setuid and setgid; later the account was dropped altogether, and the helper is now root-owned and setgid only, so the group is its whole identity. The local tests couldn't catch it, because there the caller owns everything; that is what the container is for.
- **`cargo test` doesn't relink the cdylib.** It rebuilds the module's rlib for the tests but leaves `target/debug/libpam_properpin.so` stale, so the stack tests build the module themselves before loading it.

## Not done yet

SELinux labels verified on a real system (install.sh sets and checks them, but only a real machine or a VM enforces them, and the helper and `/run/properpin` may need a policy of their own), the real greeter, alerts for concerning failures, duress and a TPM-backed counter. `docs/plan.md` at the repo root lists what is next, `docs/concerns.md` every smaller open point, and `docs/chaotic/` the research behind the bigger ones.
