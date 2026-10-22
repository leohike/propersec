# How screenlock-pin works

This is what screenlock-pin does once it is installed and working. Why it was designed this way, what it protects against and how it is built are covered elsewhere; this page mostly describes what the user sees.

For better security, every `screenlock-pin` command except `status` needs admin rights, so they ask for sudo.

## The password and the PIN

Every user already has an account **password**, the one they type to log in. screenlock-pin adds a second, shorter secret: the **PIN**. By default it must be at least 4 characters long, with at least 3 non-digits for better security.

The PIN is only for unlocking the KDE lock screen, the screen that appears when the user locks their session or comes back to a computer that locked itself. Everywhere else, nothing changes: the login screen after a reboot, `sudo`, the dialogs that ask for the password to install software or change settings, a text console and SSH all still ask for the password and never take the PIN.

## Setting the PIN

The user sets their PIN with:

```
screenlock-pin set
```

It shows the rules, then asks for the new PIN twice. As with any secret, don't reuse the PIN elsewhere.

An admin can set the PIN for someone else with `--user NAME`.

The PIN works right away, the next time the screen locks. It keeps working after a reboot (once the user has logged in with the password), and a later password change doesn't affect the PIN. To change it, the user runs `screenlock-pin set` again. To get rid of the PIN and go back to the password only:

```
screenlock-pin remove
```

Other users on the same computer who haven't set a PIN see no difference.

## Unlocking

The lock screen looks the same as before, with one field for the password or PIN. The user types either the PIN or the password and presses Enter. If it is the PIN, the screen unlocks. If it isn't, what was typed is checked as the password, the same way it always was, so the password still works too.

Most of the time the PIN is expected to be **enabled**: the lock screen accepts it as well as the password. That is the state right after the PIN is set, and it stays enabled across reboots, suspends and password changes. The other two states, paused and disabled, are explained below. Both are meant to stop an attacker guessing at the user's machine while they are away.

## Failures, and the pause

Anything typed at the lock screen that doesn't unlock it counts as a **failure**, whether it was meant as the PIN or as the password.

After 3 consecutive failures, the PIN is automatically **paused**. While paused, the lock screen doesn't check the PIN. Only the password unlocks, and typing the right PIN does nothing. Further failures aren't counted while paused.

When the user unlocks the lock screen with their password, the PIN is **unpaused**: it is enabled again and the consecutive failure count starts from zero. A correct PIN starts the count over too, so two typos followed by the right PIN leave the count at zero.

A PIN paused before a reboot is still paused afterwards, until the user unlocks with the password.

## Forgiven and suspicious failures

The pause condition only counts consecutive failures, and the count restarts at every correct PIN. On its own, that would let someone with regular access to the desk try two guesses every time the user steps away, for as long as they liked. So screenlock-pin also keeps a longer tally of failures over hours and days, the **budget**. The budget survives reboots.

The user's ordinary typos never reach the budget, because they are **forgiven** quickly. A correct PIN forgives the failures of the 45 seconds before it, and a password unlock forgives those of the 90 seconds before it. A user who mistypes the PIN and gets it right a few seconds later is nothing suspicious.

A failure that nothing forgave in time becomes a **suspicious failure**. The idea is that the user, who knows the PIN and the password, almost always follows a typo with a correct unlock within seconds, while an attacker can't, and leaves their wrong guesses unforgiven when they walk away from the desk. So the budget counts what looks like guessing, and a user who makes many typos but always gets it right in the end comes no closer to having the PIN disabled. A suspicious failure the user can't explain may mean someone was guessing their PIN.

## Disabled

If suspicious failures pile up, the PIN becomes **disabled**. That happens at 10 suspicious failures within 24 hours, 25 within 7 days, or 60 since the PIN was set. A disabled PIN is refused like a paused one. Unlike a paused PIN, it stays disabled even after the user unlocks with the password. The password keeps working throughout.

There are two ways to bring the PIN back:

```
screenlock-pin enable    # keep the same PIN
screenlock-pin set       # choose a new one
```

`enable` warns first, since the failures that disabled the PIN may have been someone guessing it. It forgets the recent failures but keeps the count since the PIN was set. Once that count reaches its limit, `enable` refuses, and only a new PIN from `set` brings back a full budget. `set` also warns when it is given the same PIN again, because that restarts the budget.

## Checking on the PIN

To see where their PIN stands, the user runs:

```
screenlock-pin status
```

It shows whether the user has a PIN, whether it is enabled, paused or disabled, and since when. It also shows consecutive and suspicious failures together with the budget.

When a PIN won't work and the reason isn't clear, an admin can run:

```
screenlock-pin doctor
```

It checks every user's PIN and names anything that makes screenlock-pin refuse one, together with the command that fixes it. It never fixes anything itself.

## Settings

The numbers on this page are the defaults: the minimum length, the 3 non-digits, the 3 consecutive failures, the 45 and 90 seconds, and the daily, weekly and total limits. An admin can change them for all users in `/etc/screenlock-pin/config`. There are no per-user settings. To put every setting back to its default:

```
screenlock-pin restore-defaults
```

This shows the current settings and asks before deleting them. PINs and budgets aren't touched.
