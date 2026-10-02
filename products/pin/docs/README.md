# properpin

A PIN for the KDE Plasma lock screen, within limits. Two words run through everything here:

- **password:** your account password. It is long, it works everywhere, always, and stock `pam_unix` checks it.
- **PIN:** a short extra secret, digits or letters. It unlocks the lock screen and nothing else, and only while it is **armed**: for 8 hours after a password unlock at the lock screen, and until 3 failures in a row. Otherwise the password is required.

Login, sudo, polkit, TTY and SSH never see the PIN. The full rules, the threat model and the reasoning live with the Python proof of concept in `poc-py/` (its README, WALKTHROUGH.md and docs/), which this Rust version follows rule for rule.

**Status: starter implementation, not installed.** Everything builds and runs in `target/` and temporary directories. Nothing touches `/etc`, `/run/user`, the PAM configuration or the journal, and there is no install step yet.

## Try it

```
just properpin demo     # set, refused before arming, armed, unlocked, three failures, refused
just properpin test     # every test: rules, files and hashing, the CLI, the PAM stack
just properpin smoke    # only the PAM stack, through the system's libpam
just properpin lint     # clippy with warnings as errors, and a formatting check
```

## Crates

| Crate | Folder | What it is |
|---|---|---|
| `properpin-core` | `crates/core` | The rules, with no I/O and no `unsafe`: settings and their ranges, the state file format, every reason the PIN is refused (`Refusal`), and one unlock attempt (`check`, returning a `Verdict`) or arming (`arm`). Files, clock and hashing come in through the `Store`, `Clock` and `Hasher` traits. |
| `properpin-sys` | `crates/sys` | Those traits on a real machine: `UserFiles` (trusted-file checks on the open file, atomic writes, a lock with a timeout), `Yescrypt` (the system's libxcrypt), `BootClock` (boot id and `CLOCK_BOOTTIME`), account lookups. |
| `pam_properpin` | `crates/pam` | The PAM module the lock screen would load. `pam.rs` holds all of its `unsafe` code: the two entry points, `pam_get_user`, `pam_get_authtok` and `pam_syslog`. Every error and every panic ends in `PAM_IGNORE`. |
| `properpin-cli` | `crates/cli` | The `properpin` command: `set`, `remove`, `status`, and `dev check` / `dev arm`, which do what the lock screen does, for demos and tests. |
| `pamharness` | `crates/pamharness` | Test-only: a PAM client that runs `pam_authenticate` through the real libpam with service files from a temporary directory (`pam_start_confdir`). |

`core` ← `sys` ← `pam`, `cli`. Nothing shipped depends on `pamharness`.

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

## Two things learned building it

- **The module must never be unloaded.** libpam `dlclose`s modules at every `pam_end`, but Rust's standard library registers thread-local destructors that glibc runs at thread exit. Once the module is unmapped, that segfaults the host process: here the lock screen (rust-lang/rust#91979). It reproduces on Fedora 44. The module is linked with `-z nodelete` (see `crates/pam/build.rs`), and the load/unload test in `tests/stack.rs` crashes without it.
- **`cargo test` doesn't relink the cdylib.** It rebuilds the module's rlib for the tests but leaves `target/debug/libpam_properpin.so` stale, so the stack tests build the module themselves before loading it.

## Not done yet

Installing (paths, renaming `libpam_properpin.so` to `pam_properpin.so`, SELinux labels), tests in the real Aurora image under podman, the repeated-access fix from poc-py's security analysis, wiping secrets from memory, duress, a TPM-backed counter and a verifying daemon. `docs/chaotic/` at the repo root has the research behind each of these.
