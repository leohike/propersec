# Current concerns

What was still open on 2026-10-17, after the pepper was dropped and `install` became the one command that edits PAM. Most come from `docs/review-of-dropping-the-pepper.md`, which has the details; the last two came out of the install change. Listed most serious first, each with the fix that seems right. The older, longer list is `docs/concerns.md`.

## State in /var/lib/properpin is never cleared

`/run/properpin` used to be emptied at every boot; nothing in `/var/lib/properpin` ever is.

- Stray `.<uid>.*` temporary files from attempts killed mid-write pile up for good.
- Every attempt, even one refused while the PIN is paused or disabled, saves the budget and syncs the file and the directory while the lock screen waits.

The planted lock file that was listed here first is gone: since 2026-10-17 `set` creates the lock file and the budget, and the pinchecker never creates either.

The fix: the pinchecker writes the budget through one fixed temporary name, so a killed write leaves at most one file, overwritten next time; a refused attempt saves the budget only when judging changed it.

## The tests can be trusted a little less

- The system test's "no pinchecker left running" looked for the old process name after the rename and checked nothing until it was noticed. Nothing guards against an assertion going silently empty like that again.
- The property test's model lost its reboot event, and no unit test simulates one.
- The confirmation prompt on a real terminal, `y` and `N`, is untested, in `properpin` and in `install.sh` alike.
- Mutation testing hasn't been run on the new code.

The fix: a self-check that the process name the system test looks for is the installed binary's, cut to 15 bytes; a run of `just mutants`, working through what survives.

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
