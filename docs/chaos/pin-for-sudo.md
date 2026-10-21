# Why screenlock-pin has no PIN for sudo

A decision record, written on 2026-10-16 and revised on 2026-10-21. A PIN for `sudo` used to be listed as planned for this product; it was analysed on 2026-10-16 and left out. It isn't ruled out for good: a credential for `sudo` may come later, as a separate product in a repo of its own. This note keeps the reasoning, so the question doesn't have to be worked out again, and so that product knows what it has to answer. It was first written while the PIN still had a pepper and an expiry; the costs below describe the design without them.

## The decision

screenlock-pin's PIN stays at the lock screen. It won't be offered for `sudo`, and `sudo` keeps refusing it, as the container scenarios already check.

screenlock-pin is intentionally simple: a PIN checker that runs as the user with one group added, guessing limits sized for someone at the keyboard, and no TPM. That is enough for the lock screen, whose attacker is physical, as `docs/chaos/physical-vs-remote-attacks.md` explains. It is not enough for `sudo`, where the PIN would be worth root, as What it would cost below shows. A credential for `sudo` that meets that bar, whether a PIN backed by a TPM or an approval on the phone (`docs/chaos/sudo-approved-from-android-phone-over-ssh.md`), needs a design, code and review of its own, and would share little with screenlock-pin beyond the review discipline.

## Why

A PIN offers one thing: less typing. That is worth a lot at the lock screen and far less at `sudo`.

- **At the lock screen, typing can't be avoided.** No password manager is reachable behind a locked screen, and it happens ten or more times a day. That frequency is what pays for the PIN checker and the failure budget.
- **At sudo, the session is already unlocked.** A long, random password can be pasted from a password manager, which costs about what typing a PIN does. Over SSH it works the same way, from the client's clipboard. A PIN would save little, though pasting has a nuisance of its own, which the phone report takes up.
- **sudo should ask for a credential of its own anyway.** Anyone who takes security seriously gives administration a different password from the everyday one: a separate admin account, or `rootpw` or `targetpw`. Then `sudo` never asks for the user's password, and a credential tied to the user's account has no business there.

## What it would cost

Worked out before the arguments above settled it, in case the idea comes back:

- **The PIN would be worth root.** A watched PIN would give root instead of a session, and a walk-up attacker at an unlocked session would get guesses at root.
- **The PIN checker's group would be worth root.** The hashes and the counts are reachable only through the setgid PIN checker, so any logic bug in it would let code running as the user read a hash to crack offline, or reset its counts, and then use `sudo`. Today such a bug gains only the user's own lock screen.
- **Forgiveness would give free guesses.** `Budget::forgive` clears every failure in its window, whoever made it, and anything the user runs can call the PIN checker. Malware could fire guesses whenever the user starts `sudo`, and the user's correct PIN would forgive them.
- **A shared PIN would tie the two stores together.** Cracking or probing the lock-screen copy would give the sudo PIN, so it would need a PIN of its own, or the lock-screen PIN checker would join root's trusted code.
- **The lock screen's rules don't fit.** Over SSH no password is typed, so a sudo PIN would have to be always armed, with no pause for the password to lift, which leaves the budget's limits as the only bound. Its 24-hour and 7-day windows and the failures in a row would be easy to game for a patient attacker running as the user, and the password, rarely typed, would be forgotten.
- **Breaking sudo is worse than breaking the lock screen.** A check crashing inside `sudo` leaves no way to root on systems where root has no password, Fedora and Aurora among them, and the uninstall cases rely on `sudo` as the way back.
- **pam_faillock** in `system-auth` could count PIN typos toward locking the account.

## One consequence for the lock screen

`docs/chaos/pin-same-as-password-edge-case-threat.md` argues that a watched PIN equal to the password gives the watcher `sudo`. With a separate admin credential it doesn't, so that part of the threat shrinks; login and SSH with the password remain.
