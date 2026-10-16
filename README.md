# ProperPin

Here, a PIN means a short alphanumeric password. On its own it has too little entropy to resist brute force, but it is faster to type and easier to remember than a long random password, and it still has more entropy than a traditional 4–6 digit PIN.

## How it works

At the KDE lock screen, you can unlock your Linux session with your PIN. Three failures in a row disable the PIN for a while, and you (or an attacker at your keyboard) are back to your long, random account password. A lot of effort goes into making such approach no less secure than using the long password alone.

## Why

Without ProperPin, or something like it, people in practice either rarely lock their screens or settle for short, non-random account passwords. They end up using a PIN (as defined above) anyway, just without any of the protections that make a low-entropy secret safe to use.

## Threat model

The same as for a lock screen in general. It protects your computer from:

- a roommate, flatmate, colleague, opportunistic attacker or prankster;
- ???

It doesn't protect from: … xxxx (a strong account password doesn't protect from these either).

## Scope

Now: the lock screen only, KDE only, with extensive security analysis and testing, and no TPM.

Planned: make ProperPin usable and secure for `sudo`, and add TPM support while keeping the bugs that more complex code inevitably brings under control. TPMs aren't infallible either.

## Status

Prototype. The preliminary security analysis is fairly extensive but not well structured for any potential reviewer, no human has fully reviewed the code even once, and all of it was produced using agentic coding. There are no official releases yet.

I strongly believe that agentic coding is inevitable and is nothing to be ashamed of, but any critical code, especially security related, indeed should have multiple careful reviews and this was not done yet.
