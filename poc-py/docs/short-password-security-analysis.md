# Short_password security analysis

This is the reasoning behind the short_password's security, recorded on 2026-10-01 while the code was still a standalone proof of concept. It covers:

- what the short_password costs compared with typing the full_password every time;
- who can attack it and what each attacker gets;
- when the hash cost matters, and when it doesn't;
- one known gap: guessing by someone with repeated access, such as a coworker. That is a future concern, not a current priority.

The README's Threat model section is the short version; this is the long one.

## The trade

The short_password is not free. A machine that wants the full_password at every unlock is strictly harder to get into than one that also accepts four digits. The question is whether the loss buys something bigger, and it does:

- **A long full_password typed thirty times a day gets shorter.** People shorten what they type constantly. A short full_password is weak exactly where nothing limits the guessing: sudo, SSH, and above all an offline crack of the `/etc/shadow` hash.
- **The short_password's weakness is fenced in.** It works at the lock screen only, a few guesses at a time, only after a full_password unlock in the same boot, and only for a limited time.

Phone PINs and Windows Hello PINs rest on the same argument. Without a TPM, the fence is weaker than theirs, as the Hash cost section below explains, but the shape of the trade is the same.

## Who can attack, and what they get

| Attacker | What they can do | What the short_password changes |
|---|---|---|
| A stranger at the locked machine | Type guesses | They get `max_failed_unlocks` guesses (3) per window, then the full_password is required. For a 4-digit short_password that's 3 in 10,000 per window. |
| Someone with repeated access: a coworker, a housemate | Type a few guesses every time you step away | The real gap, described in the Repeated access section below |
| Someone watching you type | Read your fingers | Four digits are easier to catch at a glance than a long passphrase. The attempt limit stops guessing, not watching. |
| Someone at your unlocked desk | Use the session; try to plant a short_password for later | Planting needs root, because the user's settings file and the policy belong to root. They could still do anything else the session allows, short_password or not. |
| Code running as you | Everything you can do | Nothing. It can unlock the session directly with `loginctl unlock-session`. It can read the hash and crack it, but that only helps if the short_password is reused somewhere else. |
| Something that can read files but doesn't control your session | Read `/etc/lazypass/users/<you>` | An offline crack of the short_password. See the Hash cost section below. |
| Other local users | Nothing | The user's settings file is `0640`, group-readable by your private group only. |
| Root | Everything | Nothing, either way. |
| An attacker with a powered-on or suspended machine | Cold-boot or DMA attacks | Nothing. Those skip the lock screen whatever the password. |

## Hash cost: when it matters

A slow hash only helps against an offline attacker: someone holding the hash and guessing on their own hardware. For the cost to matter, all three of these must hold:

- **The hash leaks without full access to your account.** Examples:
  - a backup of `/etc` on a NAS or in the cloud;
  - a copy of a disk image or ostree deployment;
  - a diagnostic bundle such as `sosreport`;
  - a sandboxed or containerised app that can read `/etc` but can't control the session.

  Anything that already runs as you, or as root, doesn't need to crack it.
- **It gets cracked.** How long that takes is in the table below.
- **The attacker then reaches the locked machine in time:** during the same boot, while the short_password is allowed, within `expiry_hours` of a full_password unlock. They then get it right on the first guess, so the attempt limit doesn't help.

The one exception is reuse. If the short_password is also a bank card or phone PIN, cracking it pays off no matter how lazypass is built. Never reuse it.

Measured on this machine, yescrypt through libxcrypt takes 14 ms at cost 5, 127 ms at cost 8 and 1.1 s at cost 11. Time to try every possible short_password on one core:

| Short_password | Possibilities | Cost 5 | Cost 8 | Cost 11 |
|---|---|---|---|---|
| 4 digits | 10⁴ | 2.3 min | 21 min | 3 h |
| 6 digits | 10⁶ | 4 h | 1.5 days | 13 days |
| 2 words from the 2,000 most common English ones | 4 × 10⁶ | 16 h | 6 days | 51 days |
| 6 characters, a–z and 0–9 | 2.2 × 10⁹ | 1 year | 9 years | 75 years |

Divide by the attacker's core count; this machine has 8. yescrypt is memory-hard, so GPUs gain far less on it than on fast hashes.

The table makes the main point: **cost multiplies the attacker's work by a fixed factor, while entropy grows it exponentially.** You also pay the cost on every short_password unlock, while entropy costs you a keystroke. No cost you could live with protects a 4-digit short_password, and a 6-character mixed one is safe even at cost 5. So the knob that matters is the short_password's length and alphabet, which `min_length` and `min_letters` already control. Length isn't the same as entropy, though. Two common words, such as `purple tractor`, run to 10 or 15 characters but hold about 22 bits, as much as 7 random digits or 4 random characters from a–z and 0–9. They're also easy to type and to remember, which makes them a good short_password: far stronger than 4 digits, and hopeless to guess 3 times at a time.

For a short short_password, then, the hash is mostly hygiene:

- the short_password isn't stored in plain text;
- the salt hides when two users or two machines share a short_password;
- a glance at the file, or a leaked backup, reveals nothing without work.

Cost 5 already does all of that. The default stays at 5 for now. A higher cost makes sense later, after the Rust port described in the Ideas section below.

## Online guessing: the attempt limit is the real protection

The attempt limit carries the design, not the hash. A walk-up attacker gets `max_failed_unlocks` guesses per window. After that the full_password is required, and only a full_password unlock opens a new window. The state lives in `/run/user/<uid>`. Someone at the locked machine can't edit it, and a reboot wipes it, which leaves the short_password disabled until the next full_password unlock.

The limit is enforced by the hook and a file you own, not by hardware. That's enough against someone at the keyboard. It's no barrier to code running as you, which doesn't need the short_password anyway.

## Repeated access: the known gap

**Status: a future concern, not a current priority.** Nothing below is implemented.

As built, a correct short_password resets the failed unlock count to 0. That was an explicit choice during design, so your own typos never pile up. It opens a slow, quiet way in for someone who can reach the locked machine again and again:

- **They use 2 guesses and stop.** The third would make the full_password required, and you might notice. With 2, you see nothing at all.
- **Your next short_password unlock wipes their 2 failures,** and the next time you step away they get 2 fresh guesses.
- **At 5 lock-and-leave cycles a day,** that's 10 guesses a day. A 4-digit short_password (10,000 possibilities) is about 50% found in 500 days, around 1.4 years, and certainly found in about 2.7 years.
- **Nothing alerts you.** Each failure is logged to the journal ("not the short_password, failed unlock 1 of 3"), but nobody reads that unprompted.

It's slow, but it is the only path that needs neither a stolen hash nor the full_password. The remedy is to stop treating each window as a clean slate, and to keep track of total failures as well as the current run. The options, roughly cheapest first:

- **Only a full_password unlock resets the count.** A correct short_password no longer does. Each window then allows `max_failed_unlocks` failures in total, however many short_password unlocks happen in it. A quiet attacker gets 2 guesses per full_password unlock instead of per lock-and-leave, roughly 2 to 4 a day instead of 10. The price: three of your own typos within one window means typing the full_password once. This doesn't stop the attacker; it slows them by a factor of about 3 to 5.
- **A total for the whole boot.** Keep a second counter that only a reboot clears: the state file is on tmpfs, so nobody but the owner could reset it. Past a limit, say 10, the short_password stays disabled until reboot, or until something deliberate like `lazypass reset` run by the owner. This caps the guesses per boot outright instead of just slowing them. The 10,000 possibilities of a 4-digit short_password would then need about a thousand boots.
- **Tell the owner.** Show failures since your last unlock, and the total for this boot, in `lazypass status`; later, perhaps a desktop notification after a successful unlock. Detection is what actually ends this attack: once you see "7 failed unlocks today" when you made none, you change the short_password. The journal lines are already there; this only brings them to the surface.

The likely shape is the first two together: a reset only by full_password, plus a total per boot, with the total shown in `status`. Each is a field in `ShortPasswordState` and a few lines in `UnlockAttemptHook`.

## Ideas considered

Recorded so they don't get worked out again from scratch.

- **Letting lazypass check the full_password too: rejected.** The full_password hash is in `/etc/shadow`, which only root can read. The hook runs as you. Checking it would mean one of these:
  - **keep a user-readable copy of the full_password hash:** it makes the one password that matters crackable offline by anything running as you;
  - **run the check as root:** it breaks "no root code at runtime";
  - **call `unix_chkpwd` directly:** that duplicates pam_unix and loses its account checks and faillock bookkeeping.

  A copy would also go stale after `passwd`, and keeping the stock path separate is what guarantees the full_password works even when lazypass is broken.
- **Skipping the hash for input that can't be the short_password: done, as `max_short_password_len`.** `set` refuses a short_password longer than it, and the hook refuses longer input before hashing anything, without counting a failed unlock. That's safe because such input can never match, and it means a full_password, typed right or wrong, costs the short_password nothing. It reveals nothing beyond the policy. It counts characters, not bytes, so a Cyrillic short_password gets the same allowance.

  The default is 12. That was a judgment call between two different costs. Set too high, a full_password shorter than the limit pays a pointless 14 ms hash that nobody notices, and a mistyped one counts as a failed unlock. Set too low, `set` refuses short_passwords people want: two common words with a space, like `purple tractor`, already run past 12. It's a setting, so either can be fixed per user. 20 would fit nearly every two-word short_password, while a real passphrase of three or more words is almost always longer.

  Storing the short_password's exact length instead would skip more and reveal little, because the user-readable hash already gives the length away to anyone who cracks it.
- **A lossy hash of the full_password (one of 100 buckets): rejected.** It would let full_password input skip the short_password hash. But it saves no more time than `max_short_password_len`, and it reveals about 6.6 bits of the full_password. Learning the bucket after each successful full_password unlock, without sudo, avoids staleness, but it pipes the full_password into a second hook call to save the same few milliseconds.
- **A higher hash cost: later, after the Rust port.** Rust doesn't make yescrypt any cheaper; it's libxcrypt either way. What the port removes is two Python startups, about 85 ms each, per full_password unlock. That frees time to spend on the hash, for example cost 8. The gain stays linear, as the Hash cost section above explains.
- **A verifying daemon under its own system user: the right shape for a proper version.** It would keep the hash readable only by itself, answer yes or no over a Unix socket, identify the caller with `SO_PEERCRED`, and enforce the attempt limit and the totals itself. That takes the hash out of reach of your own processes, sandboxed apps and backups of your home, leaving only online guessing. It needs no root at runtime.

  The "full_password succeeded" signal would still come from a pam_exec running as you, so code running as you could fake it. That code can unlock the session anyway, so it changes nothing for the walk-up threat.

  The costs are a systemd unit, a socket protocol, and a service that has to be running. If it isn't, the short_password fails closed and the full_password still works. The daemon is also where a TPM key would naturally live.
- **A TPM-held key: the only thing that defeats offline cracking.** An HMAC key inside the TPM, protected by the TPM's own dictionary-attack lockout, makes a stolen hash useless away from this machine. That's how Windows Hello PINs work. It belongs with the daemon, as part of a proper version.
- **Forced rotation, such as a new short_password every month: rejected.** Rotation only helps when cracking takes longer than the rotation period. A 4-digit short_password cracks in minutes to hours; a 6-character mixed one takes years. Neither is helped by monthly changes. Forced changes also produce predictable sequences like 4859, 4860, 4861, which is why NIST's password guidance dropped forced periodic changes. A gentle nudge in `status` about the short_password's age would be harmless.
- **A daily PIN from a phone app: rejected for this tool.** That's TOTP, which already exists as `pam_oath` and `pam_google_authenticator`. The verifier needs the seed, and a leaked seed is worse than a leaked hash: it gives every future PIN with no cracking. It's only acceptable behind the daemon. It also stops being lazy when every unlock means reaching for a phone.

## Order of work, if any of this happens

Integrate the Python proof of concept as it is first. After that, in rough order of value for effort:

- **Close the repeated-access gap:** the full_password-only reset, the total per boot, and showing both in `status`;
- **The Rust port,** with a higher hash cost;
- **The daemon;**
- **A TPM key behind the daemon.**
