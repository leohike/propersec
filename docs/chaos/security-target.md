# screenlock-pin's security

A short assessment of screenlock-pin as built, first written on 2026-10-03 and rewritten on 2026-10-16, when the pepper, the PIN's expiry and the password after every boot were dropped. The question it answers: how much weaker is unlocking with a PIN than typing the full password every time?

## What screenlock-pin is

- **The setgid PIN checker** (`docs/chaos/spec-setgid-helper.md`): hashes `root:screenlock-pin 0640`, counts in `/var/lib/screenlock-pin`, a root-owned PIN checker setgid to a group with no members, in the style of `unix_chkpwd`. Nothing the user runs can read a hash or reset a count, except through the PIN checker's `unpause`, which since 2026-10-18 takes no password (docs/current-setcred.md): asking for it unpauses the PIN and forgives the failures of the last 90 seconds, which the reasoning in this file already concedes to code running as the user.
- **Three consecutive failures pause the PIN** until the next password unlock at the lock screen. The count is on disk, so a reboot doesn't reset it.
- **The failure budget**: every failure nobody forgave counts across reboots, and 10 a day, 25 a week or 60 per PIN disable it until root turns it back on, after a warning, or sets a new one.
- **PIN equal to the password refused** at `screenlock-pin set`, compared with the hash in `/etc/shadow`.
- **Assumed about the system**: full-disk encryption (LUKS). The development machine has it.

## Against each attacker

| Attacker | With the PIN | With the password only | Difference |
|---|---|---|---|
| Someone at the locked keyboard, guessing | 3 guesses before the password is required, 10 a day, about 60 per PIN whatever the pace: 1 in a million for two random words, about 1 in 170 for 4 digits | Guessing a long password is hopeless | **The PIN is weaker** (small for a strong PIN) |
| Someone watching you type, or a camera | A short secret typed many times a day | A long secret typed rarely, now that the PIN does the daily unlocks | **The PIN is easier to catch**; the password gets harder |
| Code running as you | Can't read the hash or the counts; can unlock the session directly anyway | Can unlock the session directly | **None** |
| Root on the running machine | Can read the hash | Can log the password, read memory, install a PAM module of its own | **None**: root wins either way |
| Steals files without running anything: a backup of `/etc` or `/var/lib`, a snapshot, a disk sent for repair, a bug that reads files as root | Gets a hash a few digits deep, which falls in seconds | Gets `/etc/shadow`, uncrackable for a strong password | **The PIN is weaker**, but see the section on why there is no pepper |
| Cold boot, DMA, any RAM reader | Could recover the hash | Gets the LUKS master key, in RAM for the whole session, and with it the disk | **None**: the disk key is worth more than any PIN |

## Why there is no pepper

Until 2026-10-16 the PIN was hashed with a pepper: a random secret kept in clear text only in RAM, and on disk only encrypted under a key derived from the password. A copy of the files then gave nothing without guessing the password first. It protected exactly one row of the table above, the one where someone has the files but not the running machine, and in that row the attacker gains next to nothing:

- To use the PIN at the lock screen, they also need to be at the keyboard later, with the screen locked: two separate attacks for a prize smaller than the disk they already read.
- Anyone who can run code as root, from a USB stick or an exploit, installs a PAM module or a service of their own instead of cracking a PIN.
- Code running as the user is already inside the session, and the PIN checker keeps the hash from it.
- What is left is reuse: a cracked PIN that is also the phone's or the bank card's. The answer to that is not to reuse it.

Against that, the pepper cost the password after every boot, since the pepper lived only in RAM; a PIN broken silently by every password change; a password-derived key and its cost setting; a warning when `/run` wasn't a memory filesystem; and three documents of design and open issues, which git history keeps. The setgid PIN checker, which is cheap, standard and protects the same hash from everything the user runs, stays. Excluding `/var/lib/screenlock-pin` and `/etc/screenlock-pin` from backups costs nothing, and does what the pepper did for backups.

## Why there is no expiry

The PIN used to work only for 8 hours after a password unlock. The consecutive count and the budget already bound guessing, with or without it; the expiry only helped against someone who already knows the PIN, from watching or from reuse. Short enough to matter, say 5 minutes, it defeats the point of a PIN; long enough to live with, the person who knows the PIN has the working day to use it. And whoever knows someone knows their PIN changes it.

## Conclusion

Against anyone who already runs code on the machine, screenlock-pin is as strong as the password: the hash is out of reach of everything but root, and root wins either way. Against anyone who can read RAM it changes nothing, because such an attacker takes the disk key instead. Against someone holding a copy of the files, the PIN falls, and gives them almost nothing they didn't already have.

What remains is the trade screenlock-pin was built to make: someone at the locked keyboard gets a few guesses at a shorter secret, and a short secret typed often is easier to watch. A longer PIN (two or three random words) shrinks the first to nearly nothing; nothing in software helps against the second.

## What would weaken it

- **A weak PIN**: digits fall to a few lucky guesses far sooner than words; the budget bounds it, it doesn't remove it.
- **A bug in the PIN checker**: it reads every hash while it runs. That is why it is small, runs with a group that owns nothing else, and has its own review checklist (`docs/chaos/pin-checker-review.md`).
- **Reusing the PIN elsewhere**: a PIN watched at the lock screen, or cracked from a copy of the disk, then works on the phone or card that shares it.
