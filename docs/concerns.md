# Open concerns

Everything still open about properpin, however small, collected while moving the PIN check into a setuid helper (started 2026-10-02). The goal of that work is a mostly secure proof of concept with a sound architecture; anything that didn't fit that goal is written down here instead of being done. Each entry says what the concern is, why it matters, and what would settle it. Bigger items that were already planned stay in `docs/plan.md`; this file is for the long tail.

## Decisions taken without a final answer

- **Setuid to the `properpin` account, not setgid to its group.** Chosen for clean ownership: everything the helper creates belongs to `properpin`. The cost: the account owns its own binary, so an attacker who exploits a helper bug once could rewrite the helper and capture every passphrase sent to `arm` afterwards. Options: mark the binary immutable (`chattr +i`) at install on real systems, or switch to setgid with a root-owned binary, as Debian does for `unix_chkpwd`, which then makes the helper's new files belong to the calling user. Settle before a real install.
- **A local-run switch guarded by `AT_SECURE`.** The helper accepts `--dev-*` options (other file locations, a fake `unix_chkpwd`, a log file) only when the kernel says it was not started with elevated rights, and refuses to run at all when they're given under setuid. It lets the real binary run in local tests without root. The risk is a mistake in that one condition; a container scenario checks it under real setuid. Worth a second reviewer's look.

## The helper's start and its caller

- **The caller resolves through NSS.** The helper turns its real uid into a user name with `getpwuid`, which loads whatever NSS modules `/etc/nsswitch.conf` names (files, systemd, sssd). That code runs with the helper's rights. `su`, `passwd` and `unix_chkpwd` live with the same exposure; a stricter helper could read `/etc/passwd` itself, at the cost of not supporting network accounts.
- **Resource limits aren't reset.** A caller can start the helper with tiny limits on file size, open files, memory or CPU time. The helper doesn't raise them (it can't raise hard limits anyway). Every such limit makes it fail before or after the failure is saved, never between checking and counting, because the count is saved before the hash is checked. The worst a caller gets is a refusal of their own PIN. Not covered by a test yet.
- **The caller can signal the helper.** The helper keeps the caller's real uid, so the caller may kill or stop it at any moment, as with `unix_chkpwd`. A kill is covered by counting first. A stopped helper holds the user's lock, so that user's next attempts give up after one second: a denial of service against oneself only.
- **The terminal check protects nothing.** Like `unix_chkpwd`, `check` and `arm` refuse a terminal on stdin, which only discourages poking at the helper by hand; a pipe gets around it.
- **No timeout on `unix_chkpwd`.** `arm` waits for it as long as it takes, as pam_unix does. A hung `unix_chkpwd` would hang `arm`, which the PAM module then times out and kills (see the module below).
- **The start-up relies partly on the kernel and glibc.** Not tracing or dumping a setuid process, and the loader ignoring `LD_PRELOAD` and friends, come from the secure-execution mode, which `--dev-*` mode doesn't have. That is expected: without elevated rights there is nothing to protect. The container test checks a preloaded library is ignored under setuid only indirectly, by the helper still giving the right answers.
- **Rust's standard library runs code before `main`.** It opens `/dev/null` on closed stdin, stdout or stderr and sets SIGPIPE to ignored, before `start_clean` runs and does the same again. Nothing in it reads the environment. Worth rechecking when the Rust version changes.
- **Signals 32 and 33 can't be reset.** glibc reserves them for threads, so `signal()` fails for them and the failure is ignored. Harmless, but the loop is slightly less tidy than it reads.
- **Each password unlock now checks the password three times:** the direct `pam_unix` line, `unix_chkpwd` for `arm`, and the stock `password-auth` substack. That is about three hash computations at `/etc/shadow`'s cost, around 60 ms on the development machine. The helper's `check` for a password-length input also starts a process, a few milliseconds.

## The PAM module's side

- **The SIGCHLD guard is process-wide.** While the helper runs, the module sets SIGCHLD to its default and then puts back what it found, exactly as pam_unix does around `unix_chkpwd`. Another thread changing SIGCHLD at the same moment could have its setting overwritten. kscreenlocker runs PAM on one thread at a time; a harness test with a host that ignores SIGCHLD, or reaps children itself, would settle it.
- **The ten-second helper timeout is untested.** A test would take ten seconds, or need the timeout to be configurable, which would be a test switch in the shipped module. The module polls the helper every millisecond while it waits; harmless, but a pidfd would be tidier.
- **The password now reaches a second process.** `arm` hands the password to the helper, which runs as `properpin`, and the helper hands it to `unix_chkpwd`. A compromised helper would see every password typed at the lock screen. `unix_chkpwd` is in the same position, as root.
- **Every lock-screen attempt starts a process,** for `check` and, after a correct password, for `arm`, whether or not the user has a PIN. A few milliseconds each. The module could skip the helper for users without a PIN only by reading files it can no longer read.
- **The module trusts the helper's exit code completely.** Whatever sits at `helper=` decides. The PAM line is root's, so only root chooses the path, but the binary itself belongs to `properpin` (see the first decision above).

## Installing

- **Only the `systemd-sysusers` path is tested.** The Fedora 44 test image has it, so the `useradd --system` fallback in `install.sh` has never run.
- **The tmpfiles rule only matters from the next boot.** `install.sh` creates `/run/properpin` itself; `systemd-tmpfiles --create` is never run, so a typo in the rule would show only after a reboot. `install.sh check` compares the rule's text with what it would write, which catches drift but not a wrong rule.
- **Uninstall keeps the account,** because the kept PIN files belong to its group. It prints how to remove both.
- **Old-layout files are refused, not converted.** Anyone with a PIN from before the helper sets it again. Their old state in `/run/user/<uid>/properpin.*` stays until they log out.
- **The helper is executable by every local user.** By design: every user with a PIN needs it. A user without a PIN learns only that they have none.
- **`chattr +i` on the helper isn't done.** See the first decision above.
- **SELinux is unknown for the helper.** On Fedora, the lock screen runs unconfined and the helper and `/run/properpin` get generic labels, which should work; confined users (`user_t`, `staff_t`) might not be allowed to run a setuid program from `/usr/local/libexec`. Only the real system will tell.

## Tests that don't exist yet

- **Nothing shows that open files are closed.** The poisoned-start tests pass an extra open file and check the answers, but nothing checks the helper didn't keep it. A test could have the helper's `status` path list `/proc/self/fd`, which would mean test code in the helper.
- **No test with resource limits, a terminal on stdin, or signals sent mid-check.** The reasoning for each is above.
- **Several users at once.** Concurrency is tested for one user's attempts; several users' attempts at once share only the directory, never a file or a lock, and aren't tested together.
- **The `--dev` attack has two walls, and the test sees only the first.** With the `AT_SECURE` check disabled on purpose, the scenario's fake files still didn't unlock, because the helper also insists that its state directory belongs to the account it runs as, and the attacker's directory belongs to the attacker. The scenario fails on the exit code, so it still catches the broken check, but the second wall is untested on its own.
- **Local tests can't run setuid.** Everything that needs it is in the container test, which needs rootful podman in CI.

## Smaller points

- **`properpin status` shows only your own PIN,** and refuses root. An administrator checking someone else's PIN would need root to read the files by hand.
- **The CLI assumes the helper's group is called `properpin`** unless told otherwise with `--group`; the installed wrapper doesn't pass it.
- **`docs/pin-pam-copy.md` predates the helper.** What was typed now also passes through a pipe into the helper's process, which wipes its buffer on exit. The reasoning there still holds: both copies live shorter than libpam's.
