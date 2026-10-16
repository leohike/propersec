# Terminology

The words for the PIN's states, fixed on 2026-10-16 when the pepper, the expiry and the password after every boot were dropped (`docs/security-target.md` says why). Earlier the same day, and before, the code and the docs said the lock screen was "accepting the PIN" after a password unlock, and "password required" otherwise; before that, that the PIN was "armed" and "disarmed". With the PIN working from boot on, nothing starts accepting it any more, so the words now describe the PIN itself. Older notes, the dated ones and everything in `docs/chaotic/`, still use the old words.

## The three states

- **Enabled:** the normal state, from the moment `properpin set` writes the PIN, and right after a reboot too. The lock screen takes the PIN as well as the password.
- **Paused (password required):** after `max_failures` (3) consecutive failures. The PIN is refused without being checked, and the next password unlock at the lock screen unpauses it. The count is in the budget on disk, so a reboot doesn't unpause it.
- **Disabled:** after too many concerning failures, the ones nothing forgave in time (10 within 24 hours, 25 within 7 days, 60 since the PIN was set). The PIN is refused without being checked, the password doesn't bring it back, and only `sudo properpin enable` (the same PIN, after asking) or `sudo properpin set` (a fresh budget) does.

A paused or disabled PIN records nothing: the input isn't checked, so it isn't a guess.

## The words for each part of speech

- State: **enabled**, **paused**, **disabled**, as in the status line "right now  enabled, 1 of 3 consecutive failures so far".
- Verbs: a failure **pauses** the PIN, a password unlock **unpauses** it, the budget **disables** it, `properpin enable` **enables** it again.
- The count: **consecutive failures**, the field `consecutive` of `Budget` and the key in the budget file. The settings keep their names, so the limit is still `max_failures`.
- After a password unlock: the **housekeeping**, `housekeeping_after_password_unlock` in `properpin-core`, the pinchecker request and PAM argument `housekeeping`, `Request::Housekeeping` and `Mode::Housekeeping`. It forgives the user's own recent failures and starts the consecutive count over.
- An attempt: **try to unlock with the PIN**, `try_unlock_with_pin`, which returns an `UnlockAttemptOutcome`.
- The program that holds the hashes and counts: the **pinchecker**, `properpin-pinchecker`, a setgid helper in the style of `unix_chkpwd`. It was called the helper until 2026-10-16; the other PAM helpers check one secret and keep nothing, while this one keeps the counts and decides, so the word undersold it.
- The log: "not the PIN, consecutive failure 2 of 3"; "not the PIN, consecutive failure 3 of 3; PIN paused, password required"; "PIN paused after 3 consecutive failures, password required"; "PIN disabled after 10 concerning failures within 24 hours, password required"; "password correct, PIN enabled"; "password correct, but the PIN stays disabled after …; sudo properpin enable or set turns it back on"; "wrong password, nothing changed"; and "housekeeping failed: …" when something is broken.

## Words to avoid

- **Accepting the PIN, start accepting, armed, disarmed:** retired, for the reason above.
- **Locked,** for the paused or disabled PIN: the lock screen is what is locked.
- **Window,** for a state: the word means the 45 and 90 second forgiveness windows and the 24-hour and 7-day budget windows.
- **In a row:** the old name of the consecutive count.
- **Sufficient:** a PAM control flag.

## Upgrading an old install

`install.sh install` removes what versions with a pepper left: their PINs, which can't be converted without the PIN itself, every budget from then, and `/run/properpin`, and it warns when `/etc/properpin/config` still sets `expiry_hours` or `seal_cost`, which now refuse the PIN until taken out. The PAM line used to end in `start-accepting-pin` (earlier, `arm`), which the module now rejects as an unknown argument, so the old line keeps the password working but never does the housekeeping: `sudo ./install.sh disable` followed by `sudo ./install.sh enable` rewrites it. Then each user sets a new PIN.
