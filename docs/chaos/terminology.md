# Terminology

The words for the PIN's states, fixed on 2026-10-16 when the pepper, the expiry and the password after every boot were dropped (`docs/chaos/security-target.md` says why). Earlier the same day, and before, the code and the docs said the lock screen was "accepting the PIN" after a password unlock, and "password required" otherwise; before that, that the PIN was "armed" and "disarmed". With the PIN working from boot on, nothing starts accepting it any more, so the words now describe the PIN itself. Older notes, the dated ones and the early research notes in `docs/chaos/`, still use the old words.

## The three states

- **Enabled:** the normal state, from the moment `properpin set` writes the PIN, and right after a reboot too. The lock screen takes the PIN as well as the password.
- **Paused (password required):** after `max_failures` (3) consecutive failures. The PIN is refused without being checked, and the next password unlock at the lock screen unpauses it. The count is in the budget on disk, so a reboot doesn't unpause it.
- **Disabled:** after too many suspicious failures, the ones nothing forgave in time (10 within 24 hours, 25 within 7 days, 60 since the PIN was set). The PIN is refused without being checked, the password doesn't bring it back, and only `sudo properpin enable` (the same PIN, after asking) or `sudo properpin set` (a fresh budget) does.

A paused or disabled PIN records nothing: the input isn't checked, so it isn't a guess.

## The words for each part of speech

- State: **enabled**, **paused**, **disabled**, as in the status line "PIN  enabled since 2026-10-17 22:22:45 IST (+0100)". The budget keeps when the PIN last became enabled or paused, the key `since`, and when it was set, the key `set`; disabled has its own time, in the `disabled` key. A budget without them is refused, and only `sudo properpin set` starts a new one.
- Verbs: a failure **pauses** the PIN, a password unlock **unpauses** it, the budget **disables** it, `properpin enable` **enables** it again.
- The count: **consecutive failures**, the field `consecutive` of `Budget` and the key in the budget file. The settings keep their names, so the limit is still `max_failures`.
- After a password unlock: **unpausing the PIN**, or the **PIN unpause**, `unpause_pin_after_password_unlock` in `properpin-core`, the pinchecker request `unpause` and `Request::Unpause`. The PAM line that asks for it is named after when it runs, not what it does: `after-password-auth`, `Mode::AfterPasswordAuth`, since it runs after anything the stock `password-auth` stack accepts, a FIDO key with authselect's `with-pam-u2f` too. It forgives the user's own recent failures and starts the consecutive count over, which is what unpauses the PIN. It is never called enabling: a disabled PIN stays disabled. Until 2026-10-18 it was the housekeeping, a name that said nothing of what it does.
- An attempt: **try to unlock with the PIN**, `try_unlock_with_pin`, which returns an `UnlockAttemptOutcome`.
- The program that holds the hashes and counts: the **pinchecker**, `properpin-pinchecker`, a setgid helper in the style of `unix_chkpwd`. It was called the helper until 2026-10-16; the other PAM helpers check one secret and keep nothing, while this one keeps the counts and decides, so the word undersold it.
- The log: "not the PIN, consecutive failure 2 of 3"; "not the PIN, consecutive failure 3 of 3; PIN paused, password required"; "PIN paused after 3 consecutive failures, password required"; "PIN disabled after 10 suspicious failures within 24 hours, password required"; "password correct, PIN enabled"; "password correct, but the PIN stays disabled after …; sudo properpin enable or set turns it back on"; "wrong password, nothing changed"; and "unpausing the PIN failed: …" when something is broken.

## Words to avoid

- **Accepting the PIN, start accepting, armed, disarmed:** retired, for the reason above.
- **Locked,** for the paused or disabled PIN: the lock screen is what is locked.
- **Window,** for a state: the word means the 45 and 90 second forgiveness windows and the 24-hour and 7-day budget windows.
- **In a row:** the old name of the consecutive count.
- **Sufficient:** a PAM control flag.

## Upgrading an old install

`install.sh install` removes `/run/properpin`, which versions with a pepper used, and leaves the rest of what they left to `sudo properpin doctor`, which it runs at the end: their PINs, which can't be converted without the PIN itself and which the pinchecker refuses for their pepper settings, and `expiry_hours` or `seal_cost` in `/etc/properpin/config`, which refuse every PIN until taken out. Doctor names each one with its fix: `sudo properpin remove --user NAME` and then a new PIN for the first, which also starts the budget over, and editing the config or `sudo properpin restore-defaults` for the second; `sudo properpin remove --all` clears every PIN at once. Until 2026-10-17 install removed those PINs and budgets itself. The PAM line used to end in `housekeeping` (earlier `start-accepting-pin`, and before that `arm`), which the module now rejects as an unknown argument, so the password no longer unpauses the PIN until the lines are replaced. `install` never touches PAM since 2026-10-18: it and `install.sh check` say the lines aren't this version's, and `just integrate-into-pam` replaces them.
