# Current concerns

What was still open on 2026-10-17, after the pepper was dropped and `install` became the one command that edits PAM. Most come from `docs/review-of-dropping-the-pepper.md`, which has the details; the last two came out of the install change. Listed most serious first, each with the fix that seems right. The older, longer list is `docs/concerns.md`.

Fixed the same day: checks for absence that could pass while checking nothing. The container test's "no pinchecker left running" looked for a hardcoded process name that went stale at the rename to `properpin-pinchecker`, so it found nothing, and passed, whatever was running. Its matchers, and those of the checks that another service or an uninstalled system logs nothing of properpin's, are now derived from the installed file names, and each check for absence has a positive control that finds its target in the same run; the PAM stack test's "no housekeeping after a wrong password", which only matched the module's error, now matches the housekeeping's own answers. Breaking each matcher on purpose failed the scenario it guards.

The first concern listed that day, state in `/var/lib/properpin` that nothing ever cleared, was fixed the same day too: `set` creates the lock file and the budget and the pinchecker never creates either, so neither can be planted; a write clears the temporary files that killed writes left; a refused attempt writes only what judging changed; and `enable` and `remove` take the lock.

## The tests can be trusted a little less

- The confirmation prompt on a real terminal, `y` and `N`, is untested, in `properpin` and in `install.sh` alike.
- Mutation testing hasn't been run on the new code.

The fix: drive the prompts through a pseudo-terminal in the CLI tests; a run of `just mutants`, working through what survives.

## install edits any PAM file with the one stock line

`install` refuses only a `/etc/pam.d/kde` without exactly one `auth substack password-auth` line. Anything else around it passes: `pam_fprintd`, `pam_sss`, a `pam_faillock` someone added. properpin's second line assumes the password check is plain `pam_unix`, so on a machine that authenticates through sssd it would refuse the right password and lock the lock screen.

The fix, deferred: edit the file only when its auth lines are exactly Fedora's stock pair (`auth substack password-auth`, then `auth include postlogin`), and perhaps only with authselect's plain local profile behind it. Anywhere else, install and check the files, print the block with its markers, and leave the edit to the user; on later upgrades, leave a hand-placed block alone too and have `check` show how it differs from the shipped lines. The README then says plainly: automatic on stock Fedora-family KDE, manual elsewhere.

## One badly moded user file turns the PIN off for everyone

`install` now runs the full check before putting properpin's lines back, so a single user file with the wrong mode, say 0644, leaves the lines out for the whole machine until it is fixed. Before, only `check` complained. Refusing is right, since such a file has its hash readable by everyone, but the cost falls on every user, and the message should name the file and the one command that fixes it.

## Considered and dismissed

- **Anything an administrator does to a user's PIN.** Since the pepper went, `set` needs only root, so `sudo properpin set --user bob` gives bob a PIN the administrator chose and knows, without bob's password; root can also skip the comparison with `--shadow /dev/null`, lower `hash_cost` to 1, or re-run `enable` until the total limit. None of it is a concern: root can already unlock bob's session outright with `loginctl unlock-session`, change his password, or install a PAM module of its own, and the threat table in `docs/security-target.md` says root wins either way. Dismissed on 2026-10-17, together with the entries in `docs/concerns.md` and `docs/review-of-dropping-the-pepper.md` that only root could cause.
- **The PIN-equals-password check is narrow.** It runs only at `set`, catches an exact match only, and is skipped for users without an entry in `/etc/shadow` (LDAP, systemd-homed), so a password changed to the PIN later goes unnoticed. That is the user's own choice, and `set` says to keep the PIN different from all account passwords. The housekeeping couldn't warn about it anyway: a password equal to the PIN is taken as the PIN, so the housekeeping never runs. `docs/why-pin-same-as-password-bad.md` has what it costs. Dismissed on 2026-10-17.
- **Moving the clock to stretch the budget.** Setting the time takes root or admin authentication; a reboot ends at the LUKS passphrase, and even with TPM unlock at the login screen, where the PIN doesn't apply; a forged NTP answer from the network can only step the clock in chrony's first updates after start, that is after a reboot, and otherwise slews it by at most about 0.08 seconds a second. And the limit of 60 per PIN doesn't depend on time at all, so clock games could at best bring those guesses sooner. So `judge` no longer treats a failure stamped in the future as proof that the clock went back (`CLOCK_SLACK`, removed on 2026-10-17 with its test): after an honest jump back, such failures just wait for the clock to catch up, and the next password unlock may forgive them as the user's own. The property test lost its reboot event when the PIN started working from boot on, since nothing in the code knows about boots any more.
