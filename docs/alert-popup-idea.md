# Idea: alert the user about failed PIN attempts made while away

An idea from 2026-10-03, not built. It is the "tell the owner" remedy from poc-py's security analysis (`poc-py/docs/short-password-security-analysis.md`, the Repeated access section), and the only thing that actually ends a slow repeated-access attack: once the user sees failed attempts they didn't make, they change the PIN.

## The idea

If failed PIN attempts were not followed by a successful unlock within a time limit, say 60 seconds, show the user a KDE notification after their next unlock. Optionally, in a stricter mode, offer a button that disables the PIN at once.

**Why 60 seconds separates the cases.** A genuine user who mistypes the PIN types it again correctly, or types the password, within seconds. An attacker's failures are followed by nothing until the user comes back, minutes or hours later.

## How it would work

**The helper detects.** It already sees every attempt and keeps state the user can't edit:

- remember the time of the first failure not yet followed by a success;
- on the next success (a PIN unlock, or the password through `arm`), if it came more than 60 seconds after that first failure, record a "suspicious failures" event: how many, and when.

**A session agent shows the alert.** Neither the helper nor the PAM module can show a KDE notification: they run inside the lock screen's authentication, before the session is visible. A small agent in the user's session (a systemd user service, or a KDE autostart entry) would:

- listen for "screen unlocked" on D-Bus (logind, or the screensaver interface);
- ask the helper for new events, through a new `events` request that, like `status`, answers only about the caller;
- show a notification, for example "3 failed PIN attempts at 14:02 while you were away".

## Stricter mode

Two possible shapes, which can coexist:

- **A button in the notification, "Disable PIN".** The helper can disarm the PIN until the next password unlock. Anything the user runs could call that too, but it only locks the user out of their own PIN. Removing the PIN for good needs root, so the button could run `pkexec properpin remove`, which asks for the password.
- **Automatic, with no UI at all.** Suspicious failures disarm the PIN by themselves: if an unresolved failure is older than 60 seconds at the next attempt, the PIN is refused and the password required. This is pure helper logic, works without the agent, and the notification, where there is one, then explains why the password was needed.

## Caveats

- **A reboot erases the evidence.** The state lives in `/run/properpin`, so a reboot wipes the record of the failures. The PIN is disarmed after a reboot anyway, but the user would never learn about the attempts. Keeping events across reboots needs a persistent place the helper's group can write, such as `/var/lib/properpin`, or the agent reading the journal.
- **A lucky guess looks like a typo.** An attacker who gets the PIN right within 60 seconds of their first miss isn't flagged. With the failure limit, that is 3 in 60 million for two random words, 3 in 10,000 for 4 digits.
- **Suspend can raise false alarms.** A typo, then closing the lid, flags the attempt when the machine resumes hours later. Measuring the 60 seconds on a clock that stops during suspend (`CLOCK_MONOTONIC` rather than `CLOCK_BOOTTIME`) would avoid it.
- **The agent is new territory.** It would be properpin's first component in the user's session, with D-Bus, notifications and autostart. It is the bigger part of the work, and only the real desktop can test it.
- **Code running as the user can hide the alert.** It can stop the agent or dismiss the notification. Such code can unlock the session directly anyway, so this changes nothing for the walk-up attacker the alert is for.

## Where it fits

- **The helper side** (recording events, the automatic disarm, events shown by `properpin status`) belongs with the repeated-access fix in `docs/plan.md`, since both change how failures are counted.
- **The notification agent and its button** would be a separate, later item, tested on the real system.
