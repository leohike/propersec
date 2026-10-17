# Current concerns

What was still open on 2026-10-17, after the pepper was dropped and `install` became the one command that edits PAM. Most come from `docs/review-of-dropping-the-pepper.md`, which has the details; the last came out of the install change. Listed most serious first, each with the fix that seems right. The older, longer list is `docs/concerns.md`.

Fixed the same day: checks for absence that could pass while checking nothing. The container test's "no pinchecker left running" looked for a hardcoded process name that went stale at the rename to `properpin-pinchecker`, so it found nothing, and passed, whatever was running. Its matchers, and those of the checks that another service or an uninstalled system logs nothing of properpin's, are now derived from the installed file names, and each check for absence has a positive control that finds its target in the same run; the PAM stack test's "no housekeeping after a wrong password", which only matched the module's error, now matches the housekeeping's own answers. Breaking each matcher on purpose failed the scenario it guards.

The first concern listed that day, state in `/var/lib/properpin` that nothing ever cleared, was fixed the same day too: `set` creates the lock file and the budget and the pinchecker never creates either, so neither can be planted; a write clears the temporary files that killed writes left; a refused attempt writes only what judging changed; and `enable` and `remove` take the lock.

Also fixed that day: one badly moded user file turned the PIN off for everyone, since `install` ran the full check, user files included, before putting properpin's lines back. A problem with a user's file, budget or lock file refuses that user's PIN alone, at the pinchecker, so `install` and `check` no longer judge them, nor the config: `install` puts its lines in anyway and ends by printing what the new `sudo properpin doctor` finds. Doctor judges every file by the pinchecker's own rules, as root, so those rules now also cover what only root could meet, a file the pinchecker couldn't read at all, and a user file must have the pinchecker's group; for each problem doctor says what it does at the lock screen and which command fixes it. There are no repairs, only `remove` (whatever state the files are in, by name for an account that is gone, or `--all` for every user), `set`, `enable`, `restore-defaults`, which deletes the config, and installing again. `status` says why a PIN is refused instead of sending the user to the system log, and install no longer deletes the PINs and budgets of versions with a pepper: doctor names them.

## The tests can be trusted a little less

- The confirmation prompt on a real terminal, `y` and `N`, is untested, in `properpin` and in `install.sh` alike.
- Mutation testing hasn't been run on the new code.

The fix: drive the prompts through a pseudo-terminal in the CLI tests; a run of `just mutants`, working through what survives.

## The PIN-equals-password check is narrow

- It runs only at `set`, so a later password change to the PIN, or to something close, goes unnoticed.
- It catches an exact match only.
- It is skipped, with a warning, for users without an entry in `/etc/shadow` (LDAP, systemd-homed).
- `set` no longer needs the user's password, only sudo, so an admin can set another user's PIN, and so know it, without that user's password. Root can do anything anyway, but this makes it a habit rather than an attack.

The fix: decide whether `set --user someone-else` must ask for that user's password, or be refused unless the caller is that user; and let the housekeeping log a warning when the password just typed equals the PIN, since it holds both at that moment.

## install edits any PAM file with the one stock line

`install` refuses only a `/etc/pam.d/kde` without exactly one `auth substack password-auth` line. Anything else around it passes: `pam_fprintd`, `pam_sss`, a `pam_faillock` someone added. properpin's second line assumes the password check is plain `pam_unix`, so on a machine that authenticates through sssd it would refuse the right password and lock the lock screen.

The fix, deferred: edit the file only when its auth lines are exactly Fedora's stock pair (`auth substack password-auth`, then `auth include postlogin`), and perhaps only with authselect's plain local profile behind it. Anywhere else, install and check the files, print the block with its markers, and leave the edit to the user; on later upgrades, leave a hand-placed block alone too and have `check` show how it differs from the shipped lines. The README then says plainly: automatic on stock Fedora-family KDE, manual elsewhere.

## Considered and dismissed

- **Moving the clock to stretch the budget.** Setting the time takes root or admin authentication; a reboot ends at the LUKS passphrase, and even with TPM unlock at the login screen, where the PIN doesn't apply; a forged NTP answer from the network can only step the clock in chrony's first updates after start, that is after a reboot, and otherwise slews it by at most about 0.08 seconds a second. And the limit of 60 per PIN doesn't depend on time at all, so clock games could at best bring those guesses sooner. So `judge` no longer treats a failure stamped in the future as proof that the clock went back (`CLOCK_SLACK`, removed on 2026-10-17 with its test): after an honest jump back, such failures just wait for the clock to catch up, and the next password unlock may forgive them as the user's own. The property test lost its reboot event when the PIN started working from boot on, since nothing in the code knows about boots any more.
