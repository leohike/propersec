# Unpausing the PIN through pam_setcred

Written on 2026-10-18, from a conversation about how to stop the PIN unpause from handling the password. Claims are marked "verified" (in this repo's analysis docs or code) or "reasoned" (thought through, not tested). Built the same day, first next to the password check behind a setting, then, once tested on a real lock screen, as the only way: the password check is gone. The sections below the next one are the idea as first written, kept for the reasoning.

## What is built now

The `after-password-auth` line's `pam_sm_authenticate` answers `PAM_IGNORE` at once and never reads `PAM_AUTHTOK`. Its `pam_sm_setcred` asks the PIN checker for `unpause`, which now reads nothing on stdin and runs `unpause_pin_after_password_unlock`, logging `unlocked with the password, PIN enabled`. Any flag counts. `unix_chkpwd`, the `PasswordCheck` trait, `crates/sys/src/chkpwd.rs`, `--dev-chkpwd` and the stand-in `unix_chkpwd` scripts in the tests are gone. The PAM lines are unchanged, so nobody's `/etc/pam.d/kde` needs editing.

On the way there, from commit `6c9b21d` to the tag `both-setcred-and-password`, a setting `pin_unpause_by` (`password-check`, `setcred` or `both`) chose between the two ways, with a recipe to install each; the tests and the VM runs below used it. It is gone too, and a config that still holds it is refused like any unknown setting: the PIN is refused until the line is removed (`screenlock-pin doctor` names it).

One change to the `check` line was needed, described more fully under how libpam picks the lines: its `pam_sm_setcred` answers `PAM_SUCCESS` instead of `PAM_IGNORE`. kscreenlocker ignores what `pam_setcred` answers.

Tested on 2026-10-18: `crates/pam/tests/stack.rs` (the three paths in each mode, and a bad value), `crates/checker/tests/checker.rs` (`unlocked` in each mode, with a `unix_chkpwd` that must not run), and four new scenarios in `crates/systest` that `just podman` ran on a stock Fedora 44 through the real `kde` stack and `pam_unix`: all 45 scenarios passed. Faillock is not covered yet.

On a real lock screen, on 2026-10-18: kscreenlocker on the Aurora VM (`aurora-first`), installed with `just install-both`. Every password unlock logged `pam_setcred(PAM_REFRESH_CRED) after a password unlock; pin_unpause_by is both`, between the password check's `password correct, PIN enabled` and the setcred path's `unlocked through the password stack (setcred), PIN enabled`. No PIN unlock and no wrong input logged a `pam_setcred` line. Three wrong inputs paused the PIN, further wrong passwords left it paused, and the password unpaused it. kscreenlocker passes `PAM_REFRESH_CRED`, as its source says. A greeter started before `integrate-into-pam` kept the old lines it had read at `pam_start`, so its first attempts logged "bad PAM line" and refused the PIN alone, as designed.

Then with `just install-setcred`, the same day and VM: no `password correct` or `wrong password` line at all, so the PIN checker never saw the password. Every password unlock logged `pam_setcred(PAM_REFRESH_CRED) after a password unlock; pin_unpause_by is setcred` and `unlocked through the password stack (setcred), PIN enabled`, and only those. The password unpaused a paused PIN, and the password itself, counted for a moment as a failed PIN, was forgiven (status showed nothing left waiting to be forgiven). No PIN unlock and no wrong input reached `pam_setcred`.

## The problem

Today the `after-password-auth` line in `/etc/pam.d/kde` runs after the stock `password-auth` substack whatever it answered, since a failed substack doesn't stop the stack. So it runs after a wrong password too, and to tell a right password from a wrong one it reads `PAM_AUTHTOK`, passes it to the PIN checker, and the PIN checker checks it through `unix_chkpwd`. That makes screenlock-pin take the password, check it as the password, and so know that it holds the right one.

The `check` line sees every input too, but only as a PIN candidate: it never learns which input was the password. Holding a password we know is right is a bigger risk than that, and is what this idea removes.

## Why the password check buys no security

The check was there so that nothing the user runs could unpause the PIN or forgive its failures. But `docs/chaos/security-target.md` already says code running as the user can unlock the session directly anyway (`loginctl unlock-session`), read the user's files and keylog the PIN. All it could gain by resetting the counts is guessing the PIN through the PIN checker faster than keylogging it, which matters only if the PIN is reused elsewhere, and the security target leaves reuse to the user. Like a burglar already inside the flat: he doesn't need your spare key.

What the check does still do, in today's layout, is stop someone at the keyboard: without it, any wrong "password" would unpause the PIN. So whatever replaces it must mean "the screen was really unlocked", not "someone typed something".

## Events that were looked at and dropped

- **KDE's `org.freedesktop.ScreenSaver.ActiveChanged(false)`** on the session bus, sent by kscreenlocker on unlock ([KDE bug 359680](https://bugs.kde.org/show_bug.cgi?id=359680)).
- **logind's `LockedHint`** going false, set by the lock screen through `SetLockedHint` and announced with `PropertiesChanged` on the system bus ([kscreenlocker MR 10](https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/10), [Baeldung](https://www.baeldung.com/linux/run-script-session-locked-unlocked)). A normal user can set it, as the third-party tool [lockhinter](https://rust-digger.code-maven.com/crates/lockhinter) does.
- **logind's `Unlock` signal**, which is a request to unlock (what `loginctl unlock-session` sends), not a report that an unlock happened.

Anything the user runs can fake all three, which by the reasoning above would be fine. They were dropped for other reasons: none says how the screen was unlocked (PIN, password, fingerprint, `loginctl`), and listening for them needs a program running in the user's session. The idea below needs neither.

## What pam_setcred is

`setcred` means "set credentials". PAM splits a login into proving who you are (`pam_authenticate`) and then giving the process what comes with being that user (`pam_setcred`): a Kerberos ticket (`pam_krb5`), extra groups (`pam_group`), a network file system token. The program passes a flag saying why: `PAM_ESTABLISH_CRED` at login, `PAM_DELETE_CRED` at logout, `PAM_REFRESH_CRED` to renew them. Lock screens use the last one, so that an expired Kerberos ticket is renewed when you come back. pam_unix's `setcred` does nothing useful, and most modules don't use it.

Functions named `pam_…` (`pam_authenticate`, `pam_setcred`) are called by the program, here kscreenlocker. Functions named `pam_sm_…` (`pam_sm_authenticate`, `pam_sm_setcred`) are written by each module, "sm" meaning "service module", and libpam calls them for every line.

**kscreenlocker calls `pam_setcred(PAM_REFRESH_CRED)` only after a successful `pam_authenticate`, and ignores what it answers.** Verified for 6.7.5 and 6.8 in `docs/chaos/kscreenlocker-pam-contract.md` and `docs/analysis/debian-pam-auth-update-and-linux-pam.md` (kscreenlocker `greeter/worker/main.cpp:317`). Fingerprint and smartcard use their own services, `kde-fingerprint` and `kde-smartcard`, so their unlocks never reach the lines in `kde` (verified, `docs/analysis/kscreenlocker-pam-service.md`).

## How libpam picks the lines

There is no `setcred` line type in `/etc/pam.d`. A module on an `auth` line provides both `pam_sm_authenticate` and `pam_sm_setcred`, so `pam_setcred` walks the `auth` lines only, including those pulled in with `substack` or `include`.

It doesn't call every one. When kscreenlocker starts PAM, libpam reads `/etc/pam.d/kde` once and keeps the list of `auth` lines. `pam_authenticate` goes down the list and remembers each line's answer. `pam_setcred` goes down the same list, calls each module's `pam_sm_setcred`, and decides whether to go on using the answers remembered from `pam_authenticate`, not the new ones (verified from `linux-pam/libpam/pam_dispatch.c` in `docs/analysis/debian-pam-auth-update-and-linux-pam.md`, the setcred replay).

There is one exception, which the first stack test found: it stops where `pam_authenticate` stopped only if the module there doesn't answer `PAM_IGNORE` to `pam_sm_setcred`. `sufficient` means "done" on success, and libpam's "done" in the replay takes a new `PAM_IGNORE` as "no opinion" and goes on down the lines. With the `check` line's `pam_sm_setcred` answering `PAM_IGNORE`, as it did, libpam called the `after-password-auth` line's `pam_sm_setcred` after a PIN unlock too. With `PAM_SUCCESS` the replay ends at the `check` line after a PIN unlock. After a password unlock the `check` line's remembered answer is `PAM_IGNORE`, whose action is to go on whatever it answers now. Verified by `crates/pam/tests/stack.rs` against the system's libpam and by the container test on Fedora 44; the explanation of the code path is reasoned from memory of `pam_dispatch.c` (`_PAM_ACTION_DONE`, `retval != PAM_IGNORE || cached_retval == retval`), not re-read.

`pam_sm_setcred` gets the same four arguments as `pam_sm_authenticate`: the PAM session (`pamh`, through which a module can ask for the user name and the service), the flags (`PAM_REFRESH_CRED` from kscreenlocker), and the words after the module's path on that line (`unpause`), so the module knows which line it was called for. The password is not among them; a module could ask libpam for it through `pamh`, and ours wouldn't.

## The idea

Move the PIN unpause's work from `pam_sm_authenticate` of the `after-password-auth` line, which runs after a wrong password too, to its `pam_sm_setcred`, which runs only after a real unlock. With screenlock-pin's shipped lines (`packaging/kde-auth.pam`):

```
auth  sufficient  pam_screenlock_pin.so check          ← line 1
auth  substack    password-auth                   ← line 2 (pam_env, pam_faildelay, pam_unix, pam_deny)
auth  optional    pam_screenlock_pin.so after-password-auth   ← line 3
auth  include     postlogin                       ← line 4
```

- **After a PIN unlock:** `pam_authenticate` stopped at line 1 (`sufficient` with success means done), so `pam_setcred` calls line 1 and, since line 1 answers `PAM_SUCCESS`, stops. Line 3 is never called.
- **After a password unlock:** line 1 answered "ignore", line 2 succeeded, lines 3 and 4 ran. `pam_setcred` calls all four, and line 3's `pam_sm_setcred` does the PIN unpause.
- **After a wrong input:** kscreenlocker doesn't call `pam_setcred`, so nothing happens.

No daemon: the module is already loaded in the lock screen's process and libpam calls it directly.

## What would change

- **`packaging/kde-auth.pam`:** the lines stay exactly as they are; only the comment changes. Nothing to edit in anyone's `/etc/pam.d/kde`, and no need to run `integrate-into-pam.sh` again.
- **`crates/pam/src/pam.rs`:** `pam_sm_authenticate` on the `after-password-auth` line answers `PAM_IGNORE` and does nothing. `pam_sm_setcred`, which now always answers `PAM_IGNORE`, does the PIN unpause when its argument is `after-password-auth`, and never reads `PAM_AUTHTOK`. It should keep answering `PAM_IGNORE` either way.
- **`crates/checker/src/lib.rs`:** the `unpause` request takes no input and checks no password. `unix_chkpwd`, the `PasswordCheck` trait (`crates/core/src/attempt.rs`), `crates/sys/src/chkpwd.rs` and `--dev-chkpwd` go, along with the stand-in `unix_chkpwd` scripts in the tests.
- **Docs:** the sentence "Nothing the user runs can read a hash or reset a count" in `docs/chaos/security-target.md`, and the parts of `README-BIG.md` that describe the PIN unpause, its password check and the tests for it.

## What it would fix

- The stock stack alone decides whether the password was right, so users whose password `unix_chkpwd` can't check (sssd, systemd-homed) get their paused PIN back after a password unlock (a gap in `docs/chaos/current-concerns.md`).
- With faillock on, a right password typed while faillock has the account locked no longer unpauses the PIN, since the stock stack fails and `pam_setcred` is never called (the other gap there). A right PIN while faillock has the account locked still unlocks; that is unchanged.
- A wrong input is checked as the password once, not twice, and leaves one "password check failed" line in the journal, not two (`docs/chaos/concerns.md`).

## What we would accept

- Anything the user runs can unpause the PIN and forgive the failures of the last 90 seconds, by asking the PIN checker for `unpause` directly, and probably also by running `pam_setcred` on the `kde` service itself (reasoned, not tried). The section on why the password check buys no security, above, is why that is fine.
- A disabled PIN still stays disabled until `screenlock-pin enable` or `set`; the PIN unpause never lifts it.
- A fingerprint or smartcard unlock still doesn't unpause the PIN, as now.

## One line instead of two

It is possible to drop the `after-password-auth` line and keep only `check`, but not for free. The `check` line's `pam_sm_setcred` is called after both a PIN unlock and a password unlock, and libpam doesn't tell a module what it answered earlier. So `pam_sm_authenticate` on the `check` line would have to leave a note on the PAM session with `pam_set_data` ("this attempt was the PIN" or "was not"), and `pam_sm_setcred` would read it with `pam_get_data` and do the PIN unpause only for "was not".

It has to know: a correct PIN forgives only the failures of the 45 seconds before it (`forgive_before_correct_pin`), the password those of the 90 seconds before it (`forgive_before_correct_password`). Running the PIN unpause after a PIN unlock would make the PIN forgive 90 seconds too.

The costs: kscreenlocker keeps one PAM session for many attempts, so the note must be overwritten on every attempt or an old one could be read; it is new `unsafe` code in `crates/pam/src/pam.rs`; and existing installs have the second line, which would have to be removed or left harmless.

Current leaning: keep two lines. Line 3's position already says "the password path succeeded", so the module remembers nothing between calls and nobody's `/etc/pam.d/kde` changes.

## To check before building it

Done on 2026-10-18 for the two-line variant, except faillock; the section on what is built now has the results.

- A test in `crates/pam/tests/stack.rs` for the three paths: after a PIN unlock line 3's `pam_sm_setcred` isn't called, after a password unlock it is and the PIN is unpaused, after a wrong input nothing changes. `crates/pamharness` already calls `pam_setcred(PAM_REFRESH_CRED)` after every success, as kscreenlocker does.
- That libpam calls `pam_sm_setcred` on a line whose remembered answer was "ignore" (line 1 after a password unlock), and on the lines inside the substack, as the setcred replay suggests. Only matters for the one-line variant and for understanding; the test above covers what the two-line variant needs.
- The container test (`just podman`) on a stock Fedora, and the scenarios in `crates/systest`, which still test the PIN unpause through the real `unix_chkpwd`.
