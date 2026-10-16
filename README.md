# ProperPin

I define PIN as a shorter alphanumeric password which doesn't have enough entropy to protect against bruteforce in naive implementation, but is faster and easier to type, more memorable than proper long random password and still has more entropy than traditional 4-6 digits PIN code.

ProperPin UX summary: at your KDE lockscreen you can use your PIN to unlock your Linux session, 3 failures in a row temporarily disable PIN and you (or offline attacker at your keyboard) are back to using your random high-entropy account password. Extensive measures are taken to make such UX no less secure than using high entropy long passwrod alone.

Justification summary: without ProperPin or another good UX/security addition, users in practice,  do not lock their screens most of the time or settle to short non-random account passwods, thus essentially they use PINs, not passwords, but without any of the protectoins required to make low-entropy PIN safe to use.

Threat model is the same as lockscreen functionality in general:
- protect your computer from your roommate, flatmate, collegue, opportunistic attacker or prankster
- ???

Doesn't protect from: ... xxxx (note that strong acccount password doesn't protect from those either)

Current scope:
Lockscreen only, KDE only, extensive security analysis and testing, no TPM.
Planned scope:
Enhance ProperPin such that it is usable and secure to use for getting sudo rights, add TPM support while correctly managing the vulnerabilities (bugs) that would inevitable come from higher complexity code; besides, TPM are not infallible themselves. 

Project state:
Prototype. Preliminary security analysis is rather extensive, but codebase was never fully human reviewed even once. Agentic coding is heavily used. No "official" releases yet.

