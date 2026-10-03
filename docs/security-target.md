# properpin's security, once complete

A short assessment of properpin as it would be with everything planned so far built, written on 2026-10-03. The setgid helper, the failure budget, the pepper and refusing a PIN equal to the password are built; the pepper differs from the description below in the details listed in `docs/pepper-issues.md`. The question it answers: how much weaker is unlocking with a PIN than typing the full password every time?

## What "complete" means here

- **The setgid helper** (`docs/spec-setgid-helper.md`): hashes `root:properpin 0640`, counts in `/run/properpin`, a root-owned helper setgid to a group with no members. Nothing the user runs can read a hash or reset a count.
- **The pepper** (built): a random secret mixed into the PIN hash, in clear text only in RAM (`/run/properpin`) while the PIN is armed, and on disk only encrypted under a key derived from the password (`docs/pepper-terminology.md`). A stolen hash and encrypted pepper can't be cracked without guessing the password first. `/run/properpin` not being a memory filesystem is warned about, not refused.
- **The failure budget** (built): every failure nobody forgave counts across reboots, and 10 a day, 20 a week or 100 per PIN disable it until root turns it back on.
- **PIN equal to the password refused** at `properpin set`.
- **Assumed about the system**: full-disk encryption (LUKS), swap that never reaches disk unencrypted (zram, or swap inside LUKS), and no hibernation to an unencrypted disk. The development machine meets all three (zram only, hibernation disabled).

## Against each attacker

| Attacker | With the PIN | With the password only | Difference |
|---|---|---|---|
| Steals files: a backup, a disk image, a read-only bug, a moment at an unlocked desk | Gets a hash that can't be cracked without the password | Can't read `/etc/shadow` without root; a root-made copy is uncrackable for a strong password | **None** |
| Code running as you | Can't read the hash, the counts or the pepper; can unlock the session directly anyway | Can unlock the session directly | **None** |
| Someone at the locked keyboard, guessing | At most about 100 guesses per PIN, whatever the pace, and 10 a day: 100 in 60 million for two random words, 1 in 100 for 4 digits | Guessing a long password is hopeless | **The PIN is weaker** (small for a strong PIN) |
| Someone watching you type, or a camera | A short secret typed many times a day | A long secret typed rarely, now that the PIN does the daily unlocks | **The PIN is easier to catch**; the password gets harder |
| Root on the running machine | Can read the hash and the pepper | Can log the password, read memory, unlock the session | **None**: root wins either way |
| Cold boot, DMA, any RAM reader | Could recover the hash and the pepper | Gets the LUKS master key, in RAM for the whole session, and with it the disk | **None**: the disk key is worth more than any PIN |
| Reboot, or the PIN's expiry | The PIN stops working until the next password unlock | n/a | The PIN only exists while armed |

## Conclusion

Against anyone who steals files, or who already runs code on the machine, a complete properpin is as strong as the password: the hash is out of reach of everything but root, and even a copy is useless without the password. Against anyone who can read RAM it changes nothing, because such an attacker takes the disk key instead.

What remains is the trade properpin was built to make: someone at the locked keyboard gets a few guesses at a shorter secret, and a short secret typed often is easier to watch. A longer PIN (two or three random words) shrinks the first to nearly nothing; nothing in software helps against the second.

## What would weaken it

- **Disk swap without encryption, or unencrypted hibernation**: the pepper could reach the disk, and with it a crackable hash.
- **A weak PIN**: digits fall to a few lucky guesses far sooner than words; the per-boot cap bounds it, it doesn't remove it.
- **A bug in the helper**: it reads every hash and holds every pepper while it runs. That is why it is small, runs with a group that owns nothing else, and has its own review checklist (`products/pin/docs/helper-review.md`).
- **Reusing the PIN elsewhere**: a PIN watched at the lock screen then works on the phone or card that shares it.
