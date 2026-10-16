# ProperPin (prototype stage)

Here, a PIN means a short alphanumeric password. On its own it has too little entropy to resist brute force, but it is faster to type and easier to remember than a long random password, and it still has more entropy than a traditional 4–6 digit PIN.

## How it works

At the KDE lock screen, you can unlock your Linux session with your PIN. Three failures in a row disable the PIN for a while, and you (or an attacker at your keyboard) are back to your long, random account password. A lot of effort goes into making this approach no less secure than using the long password alone.

## Why

Without ProperPin, or something like it, people in practice either rarely lock their screens or settle for short, non-random account passwords which are essentially PINs as defined above, just without any of the protections that make a low-entropy PIN safe to use.

## Threat model

The same as for a lock screen in general. It protects your account/data from:

- a flatmate, colleague, prankster, opportunistic attacker guessing at your keyboard
- a thief who steals your powered-on laptop while the screen is locked
- anyone who copies the PIN's files: they are useless without your password

ProperPin doesn't protect from someone watching you type, malware running as you, root on the running machine, anyone who can read machine's memory, or coercion (a strong account password doesn't protect from these either). ProperPin also assumes full-disk encryption.

## Scope

Now: the lock screen only, KDE only, with extensive security analysis and testing, and no TPM functionality.

Planned: make ProperPin usable and secure for `sudo`, and add TPM support in a systemic way such that more complex code does not simply increase the attack surface (also, TPMs aren't infallible anyway and should not be relied upon completely).

## Status

Prototype, with no official releases yet. All of the code was written through agentic coding, and the security analysis, though fairly extensive, isn't yet organised for a reviewer.

I believe agentic coding is inevitable and nothing to be ashamed of, but security-critical code needs several careful human reviews, and this code hasn't had a single one yet.
