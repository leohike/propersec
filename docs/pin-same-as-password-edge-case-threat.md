# Edge case: a PIN that is the password

A note from 2026-10-03 on what goes wrong when a user sets their password as their PIN, and what properpin could do about it. Low priority: it needs a user to make that choice, and the fixes are small whenever they are wanted. The plan row "Refuse a PIN equal to the password" in `docs/plan.md` points here.

## What is not the problem

At first this looked like a cracking problem: the PIN file would be "a crackable copy of the password". With the defaults, it isn't:

- **The work to crack a hash is the number of guesses times the cost of each.** The number of guesses depends on the secret, which is the same in both files.
- **The cost per guess is the same by default.** Fedora's `/etc/shadow` uses yescrypt at its default cost (`$y$j9T$`), and properpin's default `hash_cost` is the same 5.
- **The salts differ, which changes nothing here.** A salt stops precomputed tables and one cracking run covering many hashes at once; it doesn't make cracking any single hash harder.
- **Who can read each file is similar.** Since the setgid helper, only root and the helper's group can read the PIN file, and backups of `/etc` hold both files anyway. Before the helper, any program the user ran could read it; that was the real exposure, and it is gone.

## What is the problem

**A watched PIN gives away the password.** The PIN is typed many times a day at the lock screen, in front of people and cameras. properpin's premise is that a watched PIN is a small loss: it unlocks only the lock screen, only while armed, only within the failure limits. A PIN equal to the password breaks that premise: whoever sees it typed gets `sudo`, login, SSH and disk unlock. This holds whatever the hash costs are.

**The costs can drift apart.** The PIN file is only as strong as its own `hash_cost`, and `/etc/shadow` follows a different setting:

- `hash_cost` lowered in `/etc/properpin/config`, down to 1 today. Only root can edit that file, so this is a mistake rather than an attack: an attacker who can do it is root already.
- The password cost raised later by an administrator, while the PIN hash keeps the cost it was made with.

Either way, a PIN equal to the password becomes a cheaper copy of it than `/etc/shadow` holds.

## What would fix it

- **Refuse an exact match at `properpin set`.** `set` runs as root, so it can check the new PIN against the user's `/etc/shadow` hash with `crypt` before saving. This closes both problems for the exact case. Whether to refuse or only warn is open; refusing is simpler to reason about.
- **Raise the lowest allowed `hash_cost` from 1 to 5,** today's default, which the plan raises to 8. This closes the "set to a weak value" half of the drift, and also helps PINs that aren't the password.
- **The pepper, later,** narrows it further: cracking a PIN hash would also need the pepper's own slow derivation from the password, so even a PIN equal to the password would cost at least that.

## What no fix catches

Only an exact match can be detected. A PIN that is part of the password, an old password, or the password of another account can't be checked against anything. `set` could say once, when it asks for the PIN, not to use a password from anywhere.
