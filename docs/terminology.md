# Terminology

The words for when the PIN works, fixed on 2026-10-16. Before that the code and the docs said the PIN was "armed" after a password unlock and "disarmed" by a refusal. That metaphor points the wrong way for a security reader: an armed alarm means more protection, but an "armed" PIN means one more way in, so "disarming" sounded like lowering security exactly when it went up. Older notes, the dated ones and everything in `docs/chaotic/`, still use the old words.

## The two states

- **Accepting the PIN:** the lock screen takes the PIN as well as the password. It starts with a password unlock at the lock screen (or `properpin set`), and lasts until `expiry_hours` have passed, `max_failures` failures in a row, a refusal for any other reason, or a reboot. The pepper is in memory only during this state.
- **Password required:** everything else. The PIN is refused without being checked, and the password works as always. The PIN's own refusal message says it: "PIN refused, password required: …".

## The words for each part of speech

- Verb, on: **start accepting the PIN**. `start_accepting_pin_after_password_unlock` in `properpin-core`, the helper request and PAM argument `start-accepting-pin`, `Request::StartAcceptingPin` and `Mode::StartAcceptingPin`.
- Verb, off: **stop accepting the PIN**, which makes the password required. `stop_accepting_pin` wipes the pepper.
- State, on: **accepting the PIN**, as in "the lock screen is accepting the PIN" and the status line "accepting the PIN for another 7h59m".
- State, off: **password required**, as in the status line "right now  password required: 3 failures in a row".
- Since when: **accepting_pin_since**, the field of `PinState` and the key in the per-boot state file.
- An attempt: **try to unlock with the PIN**, `try_unlock_with_pin`, which returns an `UnlockAttemptOutcome`.
- The log, after a password unlock: "password correct, accepting the PIN for the next 8h"; "password correct, but the PIN stays disabled after …; sudo properpin enable turns it back on"; "wrong password, nothing changed"; and "can't start accepting the PIN: …" when something is broken. "Correct" rather than "accepted" for the password, so "accepted" means one thing only in a log line, and the state is named rather than what didn't happen.

## Words to avoid

- **"The PIN is accepted"** or **"PIN accepted":** this already means "the typed PIN matched", so use the "-ing" form for the state. For the password, logs say "password correct".
- **Armed, disarmed, re-armed:** retired, for the reason above.
- **No longer accepting the PIN,** for a correct password while the PIN is disabled: the lock screen already wasn't accepting it, since the PIN was disabled at an earlier attempt, so "no longer" would send a reader of the log looking for a cause in the wrong place.
- **Window,** for the state: the word already means the 45 and 90 second forgiveness windows and the 24-hour and 7-day budget windows.
- **Sufficient,** for the state: `sufficient` is a PAM control flag.
- **Enabled and disabled,** for the state: they mean the budget, which disables the PIN after too many concerning failures until `sudo properpin enable`. A disabled PIN is refused even right after a password unlock.

## Upgrading an old install

The PAM line used to end in `arm`, which the module now rejects as an unknown argument, so an old `/etc/pam.d/kde` keeps working with the password but never starts accepting the PIN. `sudo ./install.sh disable` followed by `sudo ./install.sh enable` rewrites the line. The per-boot state file's old key `armed_at` reads as no state, which means password required until the next password unlock, so nothing else needs migrating.
