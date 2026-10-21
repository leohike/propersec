# screenlock-pin (prototype stage)

Here, a PIN means a short alphanumeric password. On its own it has too little entropy to resist brute force, but it is faster to type and easier to remember than a long random password, and it still has more entropy than a traditional 4–6 digit PIN.

## How it works

At the KDE lock screen, you can unlock your Linux session with your PIN. Three consecutive failures pause the PIN, and you (or an attacker at your keyboard) are back to your long, random account password until you type it once. A lot of effort goes into making this approach no less secure than using the long password alone.

## Why

Without screenlock-pin, or something like it, people in practice either rarely lock their screens or settle for short, non-random account passwords which are essentially PINs as defined above, just without any of the protections that make a low-entropy PIN safe to use.

## Threat model

The same as for a lock screen in general. It protects your account/data from:

- a flatmate, colleague, prankster, opportunistic attacker guessing at your keyboard
- a thief who steals your powered-on laptop while the screen is locked
- anyone who copies the PIN's files: they are useless without your password

screenlock-pin doesn't protect from someone watching you type, malware running as you, root on the running machine, anyone who can read machine's memory, or coercion (a strong account password doesn't protect from these either). screenlock-pin also assumes full-disk encryption.

## Scope

Now: the lock screen only, KDE only, with extensive security analysis and testing, and no TPM functionality.

Not in screenlock-pin: the PIN for `sudo`. screenlock-pin is intentionally simple, and that simplicity doesn't give the security `sudo` needs; `docs/chaos/pin-for-sudo.md` has the reasoning.

Planned, as a separate product in a repo of its own: a PIN usable and secure for `sudo`, with TPM support in a systemic way such that more complex code does not simply increase the attack surface (also, TPMs aren't infallible anyway and should not be relied upon completely).

## Status

Prototype, with no official releases yet. All of the code was written through agentic coding, and the security analysis, though fairly extensive, isn't yet organised for a reviewer.

I believe agentic coding is inevitable and nothing to be ashamed of, but security-critical code needs several careful human reviews, and this code hasn't had a single one yet.

## License

Copyright 2026 Leo Hike. Licensed under either of the Apache License, Version 2.0 (`LICENSES/Apache-2.0.txt`) or the MIT license (`LICENSES/MIT.txt`), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
