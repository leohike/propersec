# Threat: an insider who leaks the PIN hash and comes back in person

A worked threat scenario, written on 2026-10-02, in which properpin gives clearly less security than typing the full passphrase every time. Every step has a rough estimate, so the weak link is easy to see and the fixes can be judged by what they change.

**Short version.** An insider with physical access copies the PIN hash once, in seconds and without leaving a trace. They crack a two-word PIN offline in a few days for tens of dollars, then unlock the machine in person whenever they like, on the first try. With the passphrase alone, the same insider gets nothing, because the copied hash would be useless. properpin turns a single brief read of one file into lasting, silent access. Against this attacker, the PIN is only as safe as that file is private, and today any program running as the user can read it.

## The scenario

**The victim** uses a laptop or desktop that is locked when they step away and rarely switched off: it suspends at night and reboots for updates. They log in with a passphrase that can't be cracked, even from a leaked `/etc/shadow` hash. They unlock with properpin during the day, using a PIN of two random words from the EFF long word list, such as `glider panorama`.

**The attacker** is an insider: a coworker, housemate, partner or ex who can get time alone with the locked machine. They have modest skills and a modest budget. Only an insider makes sense here: a stolen PIN hash is worth something only to someone who can later sit at the machine.

**What they want** is what is on the machine, or what will be on it later: files, mail and chat open in the browser, a password manager left unlocked, work documents. In the original version of this story the machine is offline most of the time, or the content hasn't arrived yet, so stealing it remotely isn't an option and someone has to come in person.

**The leak is read-only, or effectively read-only.** If the attacker could write to the machine, they wouldn't bother with the hash: they would leave something behind that unlocks the session for them. So the leak gives them files and nothing else, or they deliberately take only a file because that leaves no trace.

**properpin's settings** are the defaults, except `max_pin_length`, which has to be raised to about 20 for a two-word PIN (with a space, only about 14% of EFF word pairs fit in the default 12). Add the not-yet-built protection the user proposed: more than about 20 failed PIN attempts in a week disables the PIN. That makes slow, quiet guessing at the lock screen hopeless, so this scenario is about the stolen hash alone.

## How the attack goes, step by step

| Step | What it takes | Estimate | Confidence |
|---|---|---|---|
| Copy the hash | One read of `/etc/properpin/users/<victim>`, which is `0640` and readable by every program the victim runs | The weak link; see Getting the hash below | Low: depends on the victim's habits and setup |
| Crack it | Every pair of words from the 7,776-word list, in a few spellings | 25 core-days on average at cost 5: about 3 days on an 8-core desktop, or $10 to $30 of rented cloud machines | Medium: the 18 ms per guess was measured on the development machine |
| Find the PIN still valid | The victim hasn't changed the PIN since the leak | Close to certain: nobody changes a PIN without a reason, and nothing tells them to | High |
| Find the PIN armed | The machine is on, locked, and was unlocked with the passphrase in the last 8 hours (`expiry_hours`) | Most working days, during working hours | High |
| Unlock in person | A few minutes alone with the machine | First try, every time. The failure limits never come into play | High |
| Get away with it | Lock the machine again before leaving | Nothing visible: no failed attempts, and the one journal line for the PIN unlock is something nobody reads unprompted | High |

Everything after the first row is close to certain, and cheap. The whole attack is roughly as likely as the hash leaking.

### Getting the hash

The file can be read by anything that runs as the victim. For a modest insider, the realistic ways in are:

- **A few seconds at an unlocked machine.** The victim leaves the desk without locking it, once. Ten seconds isn't enough to copy what the attacker wants, or the content isn't there yet, but it is enough to copy one small file: a typed command and a photo of the screen, or a USB stick that pretends to be a keyboard and types the command itself. Unlike planting something to unlock the session later, this leaves nothing on the machine. Likelihood: depends entirely on how strict the victim is about locking. For someone with daily access to a victim who is sometimes careless, a chance within a year is plausible. This is the most realistic path, and the reason the unlocked desk belongs in this scenario: the PIN turns one careless moment into lasting access.
- **A backup or sync the insider can reach.** A household NAS or a shared cloud account that holds a copy of `/etc`, or of the whole disk. Likelihood: low in general, high in the households where it applies. A root-made backup leaks `/etc/shadow` too, but the passphrase hash is uncrackable, so the PIN is still the way in.
- **A remote bug that reads files.** A flaw in a browser, document viewer or chat app that lets a remote attacker read any file the victim can read. Likelihood for a modest insider: very low, since it takes skills or money they don't have.

### Cracking it

Two words from a 7,776-word list give 60 million possible PINs, about 26 bits. The attacker doesn't know the exact spelling, so they try about four common forms: with a space, joined, with a hyphen, and capitalized. That makes about 240 million guesses, and they find the right one halfway through on average.

| PIN | Hash cost | Average to crack, one core | 8-core desktop | Rented cloud, roughly |
|---|---|---|---|---|
| Two words | 5 (today's default, 18 ms) | 25 days | 3 days | $10 to $30 |
| Two words | 8 (125 ms) | 175 days | 3 weeks | $80 to $170 |
| Two words | 11 (1 s) | 4 years | 6 months | $700 to $1,400 |
| Three words | 5 | 530 years | 66 years | about $100,000 |

The cloud prices assume $0.02 to $0.04 per core-hour, a rough figure. yescrypt uses a lot of memory on purpose, so graphics cards don't make it much faster. If the attacker happens to know the spelling, for example because they once saw the victim type the PIN, divide every time by four.

## The same story with the passphrase alone

The insider still gets the brief moment at the unlocked desk. But there is no PIN hash to copy, and the one hash that matters, the passphrase's in `/etc/shadow`, can't be read by programs running as the victim. Even a root-made backup that contains it doesn't help, since the passphrase can't be cracked. At the locked machine they can only guess the passphrase, which is hopeless. To come back later, they would have to plant something during that brief moment. That works too, but it leaves a file on the machine that can be found, so it's a different and riskier attack.

The chain breaks at cracking: the probability is about zero, against about the chance of the leak with properpin.

## Verdict

In this scenario properpin is much weaker than the passphrase. Not because two words are easy to guess at the lock screen (they aren't: a few guesses a week against 60 million possibilities), but because the hash is easy to take and cheap to crack offline, and after that the failure limits protect nothing. The weak link is the first step: the hash is readable by everything the victim runs. The hash cost only changes the price of the second step, and at a cost the victim can live with, that price stays within an insider's budget.

## What would change it

| Change | Effect on this scenario | Price |
|---|---|---|
| Keep the hash and the counts in a dedicated `properpin` system account, checked by a small helper that answers yes or no, as `unix_chkpwd` does for the password | Closes the unlocked-desk copy and every read-only leak that runs as the victim. The remaining leak is a root-made backup or disk image, which exposes `/etc/shadow` in the same way, so the PIN hash becomes as private as the passphrase hash | Medium: a second, setuid program, a system user, and arming that requires the passphrase so code running as the user can't arm the PIN |
| Show PIN unlocks to the victim, such as "unlocked with the PIN at 12:41" after the next passphrase unlock or in `properpin status` | Doesn't prevent the attack, but makes it detectable: an unlock at a time the victim was away is a strong signal | Small |
| A three-word PIN | Out of an insider's reach at today's cost, and still much shorter to type than the passphrase | None in code; `set` could recommend it, and `max_pin_length` would have to be about 27 |
| Raise the hash cost | Two words: from days and tens of dollars to weeks and a few hundred at cost 8. Slows the attack down; doesn't stop it | Every PIN check gets slower, and memory use grows with each step (unmeasured so far) |
| A TPM-held key with the TPM's own guess limit | A copied hash is useless away from the machine, as with Windows Hello PINs | Large |

| Mix a secret derived from the passphrase into the PIN hash, kept only in memory while the PIN is armed; described in the next section | Alone: closes backups, disk images and any copy taken while the PIN isn't armed, but not the unlocked desk, since the PIN is almost always armed then. Together with the dedicated account: closes every leak in this scenario, root-made backups included | Small on top of the dedicated account; changing the passphrase means setting the PIN again |

The dedicated account is the one fix aimed at the weak link, and mixing in the passphrase makes it complete. A three-word PIN fixes this scenario today without any code, at the price of a longer PIN.

## Mixing the passphrase into the PIN hash

An idea from 2026-10-02, recorded here because it closes this scenario together with the dedicated account.

**The idea.** When the PIN is set, derive a secret from the passphrase with a slow hash, called the pepper here. Store `yescrypt(PIN + pepper)` and never store the pepper. Each time the passphrase unlocks the machine, the arm step computes the pepper again and keeps it in memory until the PIN expires or the machine reboots. It never touches the disk.

**Why mix rather than encrypt.** The first form of the idea was to encrypt the PIN hash with a key derived from the passphrase. That would turn the file into a way to test passphrase guesses: decrypt with a guess and see whether the result looks like a hash. The file is readable by the user's programs, unlike `/etc/shadow`, so it would expose any crackable password to everything the user runs. Mixed in, the file offers no such test. Checking a guess needs the right passphrase and the right PIN at the same time, and even a weak password combined with a two-word PIN leaves far too many combinations to try.

**Alone, it doesn't close the unlocked desk.** While the PIN is armed, the pepper has to be somewhere the module can read, and the module runs as the user: a file in `/run/user/<uid>` or the user's kernel keyring. Anything running as the user can read it there. A careless moment at an unlocked desk almost always comes while the PIN is armed, because the victim has just unlocked. What it does close is every copy taken while the PIN isn't armed: backups, disk images, a copy made after a reboot.

**With the dedicated account, it closes everything in this scenario:**

- **The unlocked desk:** the hash and the pepper both belong to the helper's account, so nothing running as the user can read either.
- **Root-made backups and disk images:** they capture the hash but never the pepper, which lives only in memory. A leaked hash is then worth less than the passphrase hash in `/etc/shadow`, because cracking it means guessing the passphrase and the PIN together.
- **Arming needs no separate check of the passphrase.** Without the pepper, the helper would have to confirm that the passphrase was really typed, so that code running as the user can't arm the PIN at will. With it, a wrong passphrase produces a wrong pepper and no PIN ever matches. Code running as the user can still arm with garbage, or reset the counts that way, but none of its guesses can ever succeed, and all it achieves is stopping the real PIN from working until the next passphrase unlock.
- **The hash cost hardly matters.** Cracking a leaked hash needs the pepper first, so cost 5 is enough.

**What remains:** root on the running machine while the PIN is armed, which wins anyway, and watching the victim type.

**What it costs:**

- **Changing the passphrase breaks the PIN.** It simply stops matching until `properpin set` runs again. That fails safe but needs a clear message. Warning ahead of time would take a stored check value, which is exactly the passphrase test the design avoids.
- **`set` needs the passphrase.** It runs as root, so it can check it against `/etc/shadow` first, so a typo never produces a pepper that matches nothing.
- **One more slow hash on every passphrase unlock,** to compute the pepper. Passphrase unlocks are the rare ones, so this is fine.
- **The arm step hands the passphrase to the helper,** over a pipe. `pam_unix` does the same with `unix_chkpwd`.

## Outside this scenario

- **Watching the victim type.** A PIN is typed many times a day and is short enough to catch at a glance or on a hidden camera, while the passphrase, now typed less often, is harder to catch. This needs no hash at all, and no change to how the hash is stored helps against it.
- **Planting instead of copying.** An insider with a moment at the unlocked desk can also leave behind a program that unlocks the session on a trigger. That works with or without properpin. It leaves a trace, which is why this scenario assumes the careful insider doesn't do it.
- **Attacks on a running machine.** Cold-boot and DMA attacks skip the lock screen whatever unlocks it. Only shutting down closes them.
