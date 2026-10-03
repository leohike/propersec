# Uninstall test: remaining ideas

Cases and checks left out of the first round of uninstall cases (2026-10-03), tabled rather than forgotten. `docs/install-uninstall-with-a-broken-properpin.md` describes what was built; `crates/systest/src/uninstall.rs` holds the cases.

## Broken installs not covered yet

- **An install killed partway through,** at several points, followed straight away by `uninstall` without a second `install`. Needs a way to stop `install.sh` at chosen steps from outside, such as killing it after each file appears, without putting test hooks into the script.
- **A second install over the first from a different build,** then one uninstall.
- **The helper deleted, stripped of its setgid bit, or given the wrong group.** These are close to cases already covered: the PIN fails closed and the password still works. They would show the uninstaller copes with a damaged `/usr/local/libexec/properpin`. The fake-root test `uninstall_copes_with_extra_and_missing_files` covers part of this.
- **A helper that panics.** The module refuses the PIN, so the password still works. It breaks nothing the lock screen depends on, which is why it was left out.
- **A module that crashes only in `pam_sm_setcred`, or only at unload.** kscreenlocker calls `pam_setcred` after every success, so a crash there kills the lock screen right after a correct password.
- **`/run/properpin` or `/var/lib/properpin` replaced by a symlink** to a directory that must survive. `uninstall` runs `rm -rf` on `/run/properpin` without a trailing slash, which removes only the link, but no test shows it.
- **`/etc/properpin` damaged:** the copy saved at enable deleted or edited while the PAM block is also damaged, in the container. The fake-root test `uninstall_without_a_saved_copy_removes_nothing` covers the missing copy; an edited copy that still looks stock would be restored as it is.
- **The `properpin` group deleted** before uninstall.
- **An extra file in `/usr/local/libexec/properpin/`, in the container.** The fake root covers it; `uninstall` now removes the whole directory.

## Checks not made yet

- **The confirmation prompt.** Every case runs `uninstall --yes`. The interactive path, where uninstall shows the diff and asks, is untested: it needs a terminal, or a pty in the test.
- **The SELinux labels** of a restored `/etc/pam.d/kde` and of everything uninstall leaves. Only the VM enforces them.
- **A repair from a TTY.** In the container, `sudo` stands in for the way back in. The VM rehearsal should lock itself out with one of the broken variants for real, then repair it from a text console.
- **A purge.** Uninstall keeps `/etc/properpin`, `/var/lib/properpin` and the group, and the cases allow exactly those. `docs/uninstall-should-purge-pin-hashes.md` argues that the PIN hashes, at least, should go.
