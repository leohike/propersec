# properpin

A PIN for the KDE Plasma lock screen, within limits. Two words run through everything here:

- **password:** your account password. It is long, it works everywhere, always, and stock `pam_unix` checks it.
- **PIN:** a short extra secret, digits or letters. It unlocks the lock screen and nothing else, and only while it is **armed**: for 8 hours after a password unlock at the lock screen, and until 3 failures in a row. Otherwise the password is required.

Login, sudo, polkit, TTY and SSH never see the PIN. The full rules, the threat model and the reasoning live with the Python proof of concept in `poc-py/` (its README, WALKTHROUGH.md and docs/), which this Rust version follows rule for rule.

**Status: not installed on any real machine.** Everything builds and runs in `target/`, temporary directories and a podman container. The installer, `packaging/install.sh`, exists and is tested against a fake root and, as root, inside a stock Fedora 44 container; no recipe runs it anywhere else.

## Try it

```
just properpin demo     # set, refused before arming, armed, unlocked, three failures, refused
just properpin test     # every test: rules, files and hashing, the CLI, the PAM stack
just properpin smoke    # only the PAM stack, through the system's libpam
just properpin lint     # clippy with warnings as errors, and a formatting check
just properpin podman   # install, enable and attack it as root in a stock Fedora 44 container
```

## Crates

| Crate | Folder | What it is |
|---|---|---|
| `properpin-core` | `crates/core` | The rules, with no I/O and no `unsafe`: settings and their ranges, the state file format, every reason the PIN is refused (`Refusal`), and one unlock attempt (`check`, returning a `Verdict`) or arming (`arm`). Files, clock and hashing come in through the `Store`, `Clock` and `Hasher` traits. |
| `properpin-sys` | `crates/sys` | Those traits on a real machine: `UserFiles` (trusted-file checks on the open file, atomic writes, a lock with a timeout), `Yescrypt` (the system's libxcrypt), `BootClock` (boot id and `CLOCK_BOOTTIME`), account lookups. |
| `pam_properpin` | `crates/pam` | The PAM module the lock screen would load. `pam.rs` holds all of its `unsafe` code: the two entry points, `pam_get_user`, `pam_get_authtok` and `pam_syslog`. Every error and every panic ends in `PAM_IGNORE`. |
| `properpin-cli` | `crates/cli` | The `properpin` command: `set`, `remove`, `status`, and `dev check` / `dev arm`, which do what the lock screen does, for demos and tests. |
| `pamharness` | `crates/pamharness` | Test-only: a PAM client that runs `pam_authenticate` through the real libpam, with service files from a temporary directory (`pam_start_confdir`) or the system's own (`pam_start`, as the lock screen does). |
| `properpin-systest` | `crates/systest` | Test-only: `install.sh` against a fake root (`tests/install.rs`), and the scenarios the container runs (`src/main.rs`). |

`core` ← `sys` ← `pam`, `cli`. Nothing shipped depends on `pamharness` or `properpin-systest`.

## The PAM lines

`pam/kde-auth.pam` holds the three lines that would go above the stock `auth substack password-auth` in `/etc/pam.d/kde`. The stack tests build their PAM stack from this very file, so the control columns tested are the ones that would ship.

```
auth  [success=done default=ignore]  .../pam_properpin.so check etc=/etc/properpin run_base=/run/user
auth  [success=ok default=die]       pam_unix.so use_first_pass
auth  optional                       .../pam_properpin.so arm etc=/etc/properpin run_base=/run/user
```

The middle line is why a wrong password can never arm the PIN: it stops the stack before `arm` runs. Paths are always spelled out in the PAM line and on the CLI (`--etc`, `--run-base`); nothing falls back to a real system path by accident.

## Files, once installed

| Path | Holds | Owner and mode |
|---|---|---|
| `/etc/properpin/config` | Global settings, optional | `root:root 0644` |
| `/etc/properpin/users/<user>` | That user's yescrypt hash, plus optional per-user settings | `root:<user's private group> 0640` |
| `/run/user/<uid>/properpin.state` | `boot_id`, `armed_at`, `failures` | the user's own, on tmpfs |
| `/run/user/<uid>/properpin.lock` | Keeps two attempts from interleaving | the user's own |

The format is poc-py's `key = value` lines, and the hash is the same `$y$` yescrypt string, so a poc-py user file's `hash = ...` line carries over as is. Settings were renamed to the new vocabulary: `max_failed_unlocks` is now `max_failures`, `max_short_password_len` is `max_pin_length`, `min_length` is `min_pin_length`; `expiry_hours`, `min_letters` and `hash_cost` are unchanged. An unknown setting is an error, so an old name can't be silently ignored.

## Installing

`packaging/install.sh` does it in two separate steps, so everything can be installed and checked while the lock screen still runs its stock stack:

```
cargo build --release -p pam_properpin -p properpin-cli
sudo products/pin/packaging/install.sh install    # module, command, /etc/properpin; PAM untouched
products/pin/packaging/install.sh check           # kind, mode, owner, bytes and SELinux label of every path
sudo products/pin/packaging/install.sh enable     # the three lines into /etc/pam.d/kde, after a diff and a yes
sudo properpin set                                # choose the PIN
```

`disable` takes out exactly the lines `enable` added, between their two marker lines, and leaves everything else in the file as it is; it never deletes `/etc/pam.d/kde`. `enable` saves the file it changed as `/etc/properpin/kde.pam.before-enable`. `uninstall` refuses while enabled and keeps `/etc/properpin`, with the PINs in it. The installed `properpin` command is a two-line wrapper that passes this machine's paths to the real binary in `/usr/local/libexec/properpin/`.

## The container test

`just properpin podman` builds everything with Fedora's own Rust inside a stock Fedora 44 image, takes `/etc/pam.d/kde` from Fedora's plasma-workspace package, installs and enables properpin with `install.sh` as root, and then runs `crates/systest` (about a minute). Each PAM attempt runs as the test user, the way the lock screen runs as the locked user, so `pam_unix` checks the password through its setuid helper `unix_chkpwd` for real. The test listens on `/dev/log` itself, so it sees what the module and `pam_unix` log through syslog. Nothing about this machine changes beyond podman's image storage.

The scenarios: the rollout (refused after boot, armed by the password, three failures), the PIN being refused by every other service (`sudo`, `su`, `login`, `system-auth`, `password-auth`, `passwd`, `other`), files tampered with as root (readable, owned by the user, symlinked, corrupt, a hash in the global config, a shared runtime directory, corrupt state), state from an earlier boot, from the future and expired, three wrong PINs at once, and `disable` plus `uninstall` restoring `/etc/pam.d/kde` byte for byte.

What it can't show: the greeter's own behaviour, SELinux (a container doesn't enforce the host's policy for its files), logind and the journal. The test was checked by breaking things on purpose: with the middle PAM line set to `default=ignore`, three scenarios fail and the log shows `unix_chkpwd` rejecting the password and the module arming the PIN anyway; with the readable-by-others check removed, its scenario fails.

## Secrets in memory

What was typed is held in `Secret` (`properpin-core`), which is wiped when dropped and can be neither printed nor cloned. The module copies it out of libpam once and drops it as soon as the check is done; libxcrypt's NUL-terminated input copy and its 32 KB work area are wiped after every hash, and a check compares the computed hash where libxcrypt wrote it, without copying it out. The CLI wraps both entries of `properpin set` and reads stdin into a buffer that can't grow. This is best effort: libpam's own copy (`PAM_AUTHTOK`, which `pam_unix` reads next and libpam wipes itself), the lock screen's copies and the terminal's are out of reach. `docs/pin-pam-copy.md` at the repo root holds the open question about libpam's copy.

## Three things learned building it

- **The module must never be unloaded.** libpam `dlclose`s modules at every `pam_end`, but Rust's standard library registers thread-local destructors that glibc runs at thread exit. Once the module is unmapped, that segfaults the host process: here the lock screen (rust-lang/rust#91979). It reproduces on Fedora 44. The module is linked with `-z nodelete` (see `crates/pam/build.rs`), and the load/unload test in `tests/stack.rs` crashes without it.
- **A test that reads syslog must never stop reading.** A Unix datagram socket queues only a few messages (10 by default). The first container test read `/dev/log` between attempts only, so three concurrent attempts filled the queue, and the module, `pam_unix` and `unix_chkpwd` all blocked in `syslog()`, waiting for the test that was waiting for them. Logging from inside PAM is a blocking call, so a stalled syslog daemon could hang the lock screen the same way.
- **`cargo test` doesn't relink the cdylib.** It rebuilds the module's rlib for the tests but leaves `target/debug/libpam_properpin.so` stale, so the stack tests build the module themselves before loading it.

## Not done yet

SELinux labels verified on a real system (install.sh sets and checks them, but only a real machine or a VM enforces them), the real greeter, the repeated-access fix from poc-py's security analysis, duress, a TPM-backed counter and a verifying daemon. `docs/chaotic/` at the repo root has the research behind each of these.
