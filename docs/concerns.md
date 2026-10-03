# Open concerns

Everything still open about properpin, however small, collected while moving the PIN check into a helper with more rights than its caller (started 2026-10-02 as a setuid helper, setgid only since 2026-10-03). The goal of that work is a mostly secure proof of concept with a sound architecture; anything that didn't fit that goal is written down here instead of being done. Each entry says what the concern is, why it matters, and what would settle it. Bigger items that were already planned stay in `docs/plan.md`; this file is for the long tail.

## Decisions taken without a final answer

- **Resolved 2026-10-03: setgid to a group, with a root-owned binary, and no account.** The first version was setuid and setgid to a `properpin` account, which owned its own binary: one exploited helper bug could have rewritten it and captured every password sent to `arm`. Now the helper is `root:properpin 2755`, as Debian's `unix_chkpwd` is setgid `shadow`; `docs/spec-setgid-helper.md` has the reasoning. Its remaining costs are entries below: counts files owned by their users, and planted lock files.
- **A local-run switch, behind two guards.** The helper accepts `--dev-*` options (other file locations, a fake `unix_chkpwd`, a log file) only when `AT_SECURE` is clear and the real and effective user and group ids are equal, and refuses to run at all otherwise. It lets the real binary run in local tests without root. Each guard was shown to hold on its own in the container; a third wall is that the run directory's group must be the helper's effective group. Still the single most sensitive condition in the helper; worth a second reviewer's look.

## The helper's start and its caller

- **The caller resolves through NSS.** The helper turns its real uid into a user name with `getpwuid`, which loads whatever NSS modules `/etc/nsswitch.conf` names (files, systemd, sssd). That code runs with the helper's rights. `su`, `passwd` and `unix_chkpwd` live with the same exposure; a stricter helper could read `/etc/passwd` itself, at the cost of not supporting network accounts.
- **Resource limits aren't reset.** A caller can start the helper with tiny limits on file size, open files, memory or CPU time, which it inherits. The helper doesn't raise them (it can't raise hard limits anyway). The caller can't change them on the running helper: `prlimit` on another process also requires the target's group ids to match the caller's, and the container showed it refused (the setgid spec listed this as a cost; it isn't one). Every such limit makes it fail before or after the failure is saved, never between checking and counting, because the count is saved before the hash is checked. The worst a caller gets is a refusal of their own PIN. Not covered by a test yet.
- **The caller can signal the helper.** The helper keeps the caller's real uid, so the caller may kill or stop it at any moment, as with `unix_chkpwd`. A kill is covered by counting first. A stopped helper holds the user's lock, so that user's next attempts give up after one second: a denial of service against oneself only.
- **The terminal check protects nothing.** Like `unix_chkpwd`, `check` and `arm` refuse a terminal on stdin, which only discourages poking at the helper by hand; a pipe gets around it.
- **No timeout on `unix_chkpwd`.** `arm` waits for it as long as it takes, as pam_unix does. A hung `unix_chkpwd` would hang `arm`, which the PAM module then times out and kills (see the module below).
- **The start-up relies partly on the kernel and glibc.** Not tracing or dumping a setgid process, and the loader ignoring `LD_PRELOAD` and friends, come from the secure-execution mode, which `--dev-*` mode doesn't have. That is expected: without elevated rights there is nothing to protect. The container test checks a preloaded library is ignored under setgid only indirectly, by the helper still giving the right answers.
- **Rust's standard library runs code before `main`.** It opens `/dev/null` on closed stdin, stdout or stderr and sets SIGPIPE to ignored, before `start_clean` runs and does the same again. Nothing in it reads the environment. Worth rechecking when the Rust version changes.
- **Signals 32 and 33 can't be reset.** glibc reserves them for threads, so `signal()` fails for them and the failure is ignored. Harmless, but the loop is slightly less tidy than it reads.
- **Each password unlock now checks the password three times:** the direct `pam_unix` line, `unix_chkpwd` for `arm`, and the stock `password-auth` substack. That is about three hash computations at `/etc/shadow`'s cost, around 60 ms on the development machine. The helper's `check` for a password-length input also starts a process, a few milliseconds.

## The PAM module's side

- **The SIGCHLD guard is process-wide.** While the helper runs, the module sets SIGCHLD to its default and then puts back what it found, exactly as pam_unix does around `unix_chkpwd`. Another thread changing SIGCHLD at the same moment could have its setting overwritten. kscreenlocker runs PAM on one thread at a time; a harness test with a host that ignores SIGCHLD, or reaps children itself, would settle it.
- **The ten-second helper timeout is untested.** A test would take ten seconds, or need the timeout to be configurable, which would be a test switch in the shipped module. The module polls the helper every millisecond while it waits; harmless, but a pidfd would be tidier.
- **The password now reaches a second process.** `arm` hands the password to the helper, which runs with the `properpin` group, and the helper hands it to `unix_chkpwd`. A compromised helper would see every password typed at the lock screen. `unix_chkpwd` is in the same position, as root.
- **Every lock-screen attempt starts a process,** for `check` and, after a correct password, for `arm`, whether or not the user has a PIN. A few milliseconds each. The module could skip the helper for users without a PIN only by reading files it can no longer read.
- **The module trusts the helper's exit code completely.** Whatever sits at `helper=` decides. The PAM line is root's, so only root chooses the path, and the binary is root's too.

## Installing

- **Only the `systemd-sysusers` path is tested.** The Fedora 44 test image has it, so the `groupadd --system` fallback in `install.sh` has never run.
- **The tmpfiles rule only matters from the next boot.** `install.sh` creates `/run/properpin` itself; `systemd-tmpfiles --create` is never run, so a typo in the rule would show only after a reboot. `install.sh check` compares the rule's text with what it would write, which catches drift but not a wrong rule.
- **Uninstall keeps the group,** because the kept PIN files belong to it. It prints how to remove both.
- **Earlier layouts aren't detected.** Neither the pre-helper layout nor the account-based one was ever installed on a real system, so `install.sh` no longer looks for them; the check that refused pre-helper user files was removed with the account. An install over either would leave stray files or a stray `properpin` user, and `check` would flag the files' modes and owners.
- **The helper is executable by every local user.** By design: every user with a PIN needs it. A user without a PIN learns only that they have none.
- **SELinux is unknown for the helper.** On Fedora, the lock screen runs unconfined and the helper and `/run/properpin` get generic labels, which should work; confined users (`user_t`, `staff_t`) might not be allowed to run a setgid program from `/usr/local/libexec`. Only the real system will tell.
- **`check` needs root on the real system,** because it reads the group's password from `/etc/gshadow`. `enable` runs it, and already needs root.
- **The primary-group check enumerates `getent passwd`.** Network accounts (sssd, LDAP) often don't enumerate, so a remote user whose primary group is `properpin` would go unnoticed. Unlikely, since the group is created locally with a system gid.
- **`check` doesn't look for a `properpin` user.** Only the container test checks that none exists. A stray user of that name wouldn't have the group unless it were its primary group, which `check` does catch.

## Tests that don't exist yet

- **Nothing shows that open files are closed.** The poisoned-start tests pass an extra open file and check the answers, but nothing checks the helper didn't keep it. A test could have the helper's `status` path list `/proc/self/fd`, which would mean test code in the helper.
- **No test with resource limits, a terminal on stdin, or signals sent mid-check.** The reasoning for each is above.
- **Several users at once.** Concurrency is tested for one user's attempts; several users' attempts at once share only the directory, never a file or a lock, and aren't tested together.
- **The `--dev` attack's file wall is untested on its own.** Behind the two guards, the helper also insists that its state directory has the helper's effective group, which the attacker's directory doesn't. No test disables both guards to show that wall alone.
- **Local tests can't run setgid.** Everything that needs it is in the container test, which needs rootful podman in CI.
- **The primary-group failure of `check` isn't tested,** only members and an unlocked password are.

## Smaller points

- **`properpin status` shows only your own PIN,** and refuses root. An administrator checking someone else's PIN would need root to read the files by hand.
- **The CLI assumes the helper's group is called `properpin`** unless told otherwise with `--group`; the installed wrapper doesn't pass it.
- **`docs/pin-pam-copy.md` predates the helper.** What was typed now also passes through a pipe into the helper's process, which wipes its buffer on exit. The reasoning there still holds: both copies live shorter than libpam's.

## The setgid layout

- **Counts files belong to the users they describe.** alice's `<uid>.state` is owned by alice, which looks as if she could change it; she can't, since she can't enter `/run/properpin`. Anyone auditing the directory needs to know this.
- **A planted lock file blocks that user's PIN until reboot.** Only someone who already has the helper's group can plant one, which means exploiting the helper first. The PIN is refused and logged, the password still works. `docs/planted-lock-dos.md` describes it and how it could be fixed.
- **`fs.protected_regular=2` would refuse even sooner.** With that sysctl the kernel refuses to open, with `O_CREAT`, a file someone else owns in a group-writable sticky directory, so alice's helper would get "Permission denied" on a planted lock file before the owner check sees it. The result is the same refusal with a vaguer log line. Fedora and the test container use 1, where the owner check is what refuses; the container scenario accepts either.
- **The run directory must be exactly `1770`.** A future change to the tmpfiles rule or a distribution default that adds a bit (setgid on the directory, say) makes every PIN fail closed until `install.sh` runs again.

## The failure budget

- **Anyone at the keyboard can disable the PIN.** Ten wrong inputs, wrong passwords included, with nobody unlocking within the next 90 seconds, and the PIN stays off until root runs `properpin enable`. The password still works. That is the price of disabling at all; the alternative is letting an attack go on.
- **The user's own wrong password counts too,** when they give up and walk away instead of typing the right one within 90 seconds. Ten a day is the margin.
- **`enable` and `set` don't take the helper's lock.** They run as root without the per-boot lock file, which root must not create in the user's name. A helper run at the same moment could overwrite `enable`'s write (the PIN stays disabled; run `enable` again) or `enable` could drop a failure recorded in between. It needs an administrator running `enable` during an attempt at that user's lock screen.
- **Every attempt now writes to disk,** synced, a few milliseconds. A full disk or a read-only `/var` makes the write fail, which refuses the PIN: fail closed.
- **The clock can still be moved by root or in the firmware.** Moving it forward ages concerning failures out of the 24-hour and 7-day windows; only the total limit then holds. Moving it back is handled. Firmware access usually means the disk's encryption passphrase is needed anyway.
- **A planted budget lasts across reboots,** unlike a planted lock file: an exploited helper could create one in another user's name, and that user's PIN is refused until root runs `properpin set`, which deletes it whoever owns it. `docs/planted-lock-dos.md` covers the fix for both.
- **`enable` can be run again and again.** Each run forgets the recent failures and keeps the total, so an administrator who keeps re-enabling gives an attacker up to the total limit of guesses on one PIN. Only the total limit is absolute.
- **Failures are judged lazily,** at the helper's next run. A failure followed by no other attempt stays pending until then; nothing is lost, `status` shows it as waiting.
- **The windows are rolling,** 24 hours and 7 days back from now, not calendar days.
- **The budget's failure is recorded before the in-a-row one,** in a separate file. A kill between the two writes leaves a budget failure without its in-a-row twin: more cautious, never less.

## Where the state lives

- **The helper doesn't check that `/run/properpin` is in memory.** On every systemd distribution `/run` is a tmpfs, but in containers and chroots it can be an ordinary directory on disk: in the podman test image, `/run` is `overlayfs`. For the counts that is harmless, since state from another boot is refused anyway. Before anything secret is stored there (the pepper), the helper should check the filesystem with `statfs` and accept only tmpfs or ramfs, and the container test should mount a tmpfs at `/run/properpin` (`podman run --tmpfs`).
- **tmpfs can be swapped.** Under memory pressure its pages can go to swap, and hibernation writes all of RAM to disk. On the development machine swap is zram only and hibernation is disabled, so it stays in RAM there, but that is the machine's configuration, not properpin's guarantee. A `ramfs` mount would never be swapped; hibernation would still need encrypted swap. Only matters once a secret is stored.
