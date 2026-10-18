# Review of dropping the pepper

Concerns found on 2026-10-16 when reviewing the change that dropped the pepper, the PIN's expiry and the password after every boot, and renamed the helper to the PIN checker (commits d6c23c2 to 37a8a3a). They are listed most serious first, each with the fix that seems right; the first was fixed on 2026-10-17.

## An upgrade that keeps the old PAM lines breaks the PIN quietly

With the old PAM line still ending in `start-accepting-pin`, the module rejects the unknown argument, logs "bad PAM line" and ignores itself on every password unlock, so the PIN unpause never runs. After three wrong PINs the PIN stays paused for good, since no correct PIN can unpause it. Worse, a password of 12 characters or fewer, typed at the lock screen, is checked as a PIN and never forgiven, so ordinary password unlocks slowly turn into suspicious failures and disable the PIN. `install.sh check` didn't notice: it only looked for the begin marker, not whether the block still matched `packaging/kde-auth.pam`. Nor was it only this upgrade: `install` never touched `/etc/pam.d/kde`, so any upgrade that changed the shipped lines left the old ones in place unless `disable` and `enable` were run as well, and they had changed five times.

Fixed on 2026-10-17: `enable` and `disable` are gone, and `install` takes screenlock-pin's lines out, installs and checks the files, then puts back the lines this version ships, so a failure leaves the password only and an upgrade can't keep stale lines. `check` fails when the lines differ from the shipped ones.

## State on disk now lasts forever, junk included

Before, `/run/screenlock-pin` was emptied at every boot; nothing in `/var/lib/screenlock-pin` ever is.

- A lock file planted in a user's name (which takes an exploited PIN checker) blocks their PIN until `sudo screenlock-pin set` or `remove`, which delete it. `enable` still doesn't. Fixed on 2026-10-17 at the root: `set` creates the lock file and the budget, the PIN checker never creates either, and nothing can be planted while they exist.
- Stray `.<uid>.*` temporary files from attempts killed mid-write pile up for good.
- Every attempt, even one refused while the PIN is paused or disabled, saves the budget and syncs the file and the directory while the lock screen waits. Usually milliseconds, more on a slow or busy disk.

The fix: `enable` clears the lock file too; the PIN checker deletes its own temporary files older than a minute; the refused path saves the budget only when judging changed it.

Fixed on 2026-10-17, partly otherwise. Every write of the budget, made under the lock when no other write of the user's is under way, first deletes the user's leftover temporary files, whatever their age; their names stay random, since a fixed name could be planted the way the lock file was. A refused attempt writes only what judging changed. `enable` and `remove` take the lock, and an attempt that waited on a lock file deleted meanwhile is refused.

## The tests can be trusted a little less than before

- The system test looked for the PIN checker's process under its old name (`screenlock-pin-helpe`) after the rename, so "no PIN checker left running" checked nothing until it was noticed. Nothing guards against an assertion like that going silently empty again.
- The property test's model lost its reboot event. "A reboot changes nothing" now holds only because nothing is left to change, and no unit test simulates one.
- The fix for two first attempts racing to create the lock file (the loser now opens the winner's) has no unit test; only a timing-dependent container scenario covers it. Gone on 2026-10-17, with the creation it raced on.
- The confirmation prompt on a real terminal, the answers `y` and `N`, is untested; only the refusal without a terminal and `--yes` are.
- Mutation testing hasn't been run on the new code.

The fix: a self-check in the system test that the process name it looks for is the installed binary's, cut to 15 bytes; a run of `just mutants` and work through what survives.

## The PIN-equals-password check is narrower than it looks

- It runs only at `set`. A later password change to the PIN, or to something close, goes unnoticed.
- It catches an exact match only.
- It is skipped, with a warning, for users without an entry in `/etc/shadow` (LDAP, systemd-homed).
- The installed wrapper passes on whatever follows it, so root can give `--shadow /dev/null` and skip the check. That is root weakening its own check, so it matters little.
- More important: `set` used to need the user's password and now needs only sudo. On a machine with several people, an admin can set another user's PIN, and so know it, without that user's password. Root can do anything anyway, but this makes it a one-line, unlogged habit rather than an attack.

The fix: decide whether `set --user someone-else` must ask for that user's password, or be refused unless the caller is that user; and let the PIN unpause log a warning when the password just typed equals the PIN, since it holds both at that moment.

Dismissed on 2026-10-17: the two points about root, `--shadow /dev/null` and setting another user's PIN. Root can already unlock any session with `loginctl unlock-session`, change any password or install a PAM module of its own; `docs/chaos/current-concerns.md` lists them under Considered and dismissed. Through sudo, the command line is in the journal anyway, so "unlogged" held only for a root shell.

## Considered and dismissed: copies of the hash in backups

Without the pepper, a copy of `/etc/screenlock-pin` gives up a short PIN in seconds, so backups, snapshots and disks sent for repair looked like a reason to raise `hash_cost` from 5 to 8, warn about backups at install, and purge hashes at uninstall. They are not. Backups are meant to be encrypted; whoever reads an unencrypted one already has every file of the user's, which is worth more than a PIN that only opens the lock screen, and only with the attacker at the keyboard as well. The one harm left is a PIN reused on a phone or a card, which `docs/chaos/security-target.md` already names. The same reasoning is why the pepper went.
