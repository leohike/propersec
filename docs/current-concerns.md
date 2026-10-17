# Current concerns

What was still open on 2026-10-17, after the pepper was dropped and `install` became the one command that edits PAM. Most come from `docs/review-of-dropping-the-pepper.md`, which has the details; the last two came out of the install change. Listed most serious first, each with the fix that seems right. The older, longer list is `docs/concerns.md`.

The first concern listed that day, state in `/var/lib/properpin` that nothing ever cleared, was fixed the same day: `set` creates the lock file and the budget and the pinchecker never creates either, so neither can be planted; a write clears the temporary files that killed writes left; a refused attempt writes only what judging changed; and `enable` and `remove` take the lock.

## The tests can be trusted a little less

- **Checks for absence can pass while checking nothing.** The system test's "no pinchecker left running" scans `/proc/*/stat` for a hardcoded process name, `PINCHECKER_COMM`. After the rename to `properpin-pinchecker` it still said `properpin-helpe`, which matches no process ever, so the check passed vacuously until it was noticed by hand. Any "X must not appear" check has that weakness: when the matcher is wrong it finds nothing, and finding nothing is a pass. The container test has more of them, each relying on a log string being spelled the way the code spells it now: a wrong password logs no "password correct", `sudo`, `su` and `login` log no `pam_properpin` or `properpin-pinchecker`, and after uninstall the PIN attempt logs no `pam_properpin`. The fix: derive the process name from the installed binary's file name, cut to the kernel's 15 bytes, instead of hardcoding it; and give every absence check a positive control, the same matcher shown to find its target once in the same run (start the pinchecker and see it listed; make the lock screen log `pam_properpin` and see it matched), so a matcher gone stale fails instead of passing.
- The confirmation prompt on a real terminal, `y` and `N`, is untested, in `properpin` and in `install.sh` alike.
- Mutation testing hasn't been run on the new code.

The fix for the last two: drive the prompts through a pseudo-terminal in the CLI tests; a run of `just mutants`, working through what survives.

## The PIN-equals-password check is narrow

- It runs only at `set`, so a later password change to the PIN, or to something close, goes unnoticed.
- It catches an exact match only.
- It is skipped, with a warning, for users without an entry in `/etc/shadow` (LDAP, systemd-homed).
- `set` no longer needs the user's password, only sudo, so an admin can set another user's PIN, and so know it, without that user's password. Root can do anything anyway, but this makes it a habit rather than an attack.

The fix: decide whether `set --user someone-else` must ask for that user's password, or be refused unless the caller is that user; and let the housekeeping log a warning when the password just typed equals the PIN, since it holds both at that moment.

## install edits any PAM file with the one stock line

`install` refuses only a `/etc/pam.d/kde` without exactly one `auth substack password-auth` line. Anything else around it passes: `pam_fprintd`, `pam_sss`, a `pam_faillock` someone added. properpin's second line assumes the password check is plain `pam_unix`, so on a machine that authenticates through sssd it would refuse the right password and lock the lock screen.

The fix, deferred: edit the file only when its auth lines are exactly Fedora's stock pair (`auth substack password-auth`, then `auth include postlogin`), and perhaps only with authselect's plain local profile behind it. Anywhere else, install and check the files, print the block with its markers, and leave the edit to the user; on later upgrades, leave a hand-placed block alone too and have `check` show how it differs from the shipped lines. The README then says plainly: automatic on stock Fedora-family KDE, manual elsewhere.

## One badly moded user file turns the PIN off for everyone

`install` now runs the full check before putting properpin's lines back, so a single user file with the wrong mode, say 0644, leaves the lines out for the whole machine until it is fixed. Before, only `check` complained. Refusing is right, since such a file has its hash readable by everyone, but the cost falls on every user, and the message should name the file and the one command that fixes it.

## Considered and dismissed

- **Moving the clock to stretch the budget.** Setting the time takes root or admin authentication; a reboot ends at the LUKS passphrase, and even with TPM unlock at the login screen, where the PIN doesn't apply; a forged NTP answer from the network can only step the clock in chrony's first updates after start, that is after a reboot, and otherwise slews it by at most about 0.08 seconds a second. And the limit of 60 per PIN doesn't depend on time at all, so clock games could at best bring those guesses sooner. So `judge` no longer treats a failure stamped in the future as proof that the clock went back (`CLOCK_SLACK`, removed on 2026-10-17 with its test): after an honest jump back, such failures just wait for the clock to catch up, and the next password unlock may forgive them as the user's own. The property test lost its reboot event when the PIN started working from boot on, since nothing in the code knows about boots any more.
