# How kscreenlocker calls PAM

properpin's tests call PAM the way the lock screen is assumed to: `pam_start("kde", user)`, then `pam_authenticate`, answering every prompt with what was typed. This note checks that assumption against kscreenlocker's source, so the real-greeter test only has to confirm, not discover. Read on 2026-10-02; nothing here was run.

Sources:

- kscreenlocker, at `v6.7.5` (what the real machine runs today), `v6.7.91` (the 6.8 beta, commit f2099f97) and `master` (9843c147, 2026-10-01): https://invent.kde.org/plasma/kscreenlocker. In 6.7.5 the PAM code is `greeter/pamauthenticator.cpp` and `greeter/pamauthenticators.cpp`; in 6.8 it moved to `greeter/worker/main.cpp`, with `greeter/pamauthenticator.cpp` as the greeter's side.
- The lock screen UI, which decides when an attempt starts: plasma-desktop's `desktoppackage/contents/lockscreen/LockScreenUi.qml`, at `v6.7.5` and `v6.7.91`. (It moved there from plasma-workspace's lookandfeel package.)
- Linux-PAM `v1.7.2`, `libpam/pam_auth.c` and `_pam_sanitize` in `libpam/pam_misc.c`.

## The short version

The core of the contract holds in both versions: service `kde`, the locked user's own login name, the greeter's own uid (no setuid helper, no root), echo-off prompts answered with the typed text as UTF-8, info and error messages shown and never answered, `pam_setcred(PAM_REFRESH_CRED)` after a success with its errors ignored, and no `pam_acct_mgmt`, `pam_open_session` or `pam_chauthtok` at all. That is what the harness does, minus `pam_setcred`.

The differences are in lifetime and timing. Both versions keep one PAM handle for many attempts, where the harness starts a fresh one each time. 6.8 moves PAM into its own short-lived process, which the greeter kills on cancel, so attempts can now be cut off midway. And 6.8 marks a PAM service unusable when `pam_authenticate` returns within 50 ms, which a correct PIN can do. That last one is the finding that matters most, described in the 6.8 timing check section below.

## Point by point

| What | 6.7.5 | 6.8 (6.7.91 and master) | properpin and its tests |
|---|---|---|---|
| Service and user | `pam_start("kde", KUser().loginName())` | The same, passed to the worker as arguments | Matches. The module refuses unless the PAM user is the process's own user, and refuses root |
| Where PAM runs | A `QThread` inside `kscreenlocker_greet` | A separate `kscreenlocker_worker` process per authenticator, started by the greeter as the same user, talking to it over a private D-Bus connection | The container runs each attempt in its own process as the user, closer to 6.8 |
| Handle lifetime | One handle for the greeter's whole life; `pam_authenticate` called again and again on it | One handle per worker process, reused for attempts until the worker is cancelled | The harness starts and ends a handle per attempt. libpam clears `PAM_AUTHTOK` after every attempt (`_pam_sanitize`, called at the end of `pam_authenticate`), so a reused handle can't hand the previous typed text to the next attempt. The module keeps no state in memory between attempts, so loading it once changes nothing. Not yet tested |
| The conversation | Echo-off and echo-on prompts block in a nested event loop until the UI responds; info and error messages are emitted to the UI | Prompts become blocking D-Bus calls to the greeter (`MaskedPrompt`, `Prompt`); info and error messages are forwarded | Matches the harness, which answers every prompt with the typed text. With properpin's lines the lock screen asks exactly once: the module asks, and `pam_unix use_first_pass` never asks |
| When an attempt starts | When the user presses Enter (`startAuthenticating`), and the typed text answers the prompt as soon as it appears | Eagerly: when the lock screen shows, after every failure, and on a one-second heartbeat while it is visible. `pam_authenticate` then waits inside the prompt until the user submits | The module takes its lock only after the typed text arrives (`run.rs` reads it before `check` locks), so a greeter waiting in the prompt never holds the lock. This matters more in 6.8, where an attempt waits there most of the time |
| Cancelling | The conversation returns `PAM_CONV_ERR` (also on prepare-for-sleep) | `Cancel` quits the worker; the greeter sends SIGTERM and SIGKILL 25 ms later. An attempt can die anywhere, including inside the module | A failure is counted before the hash is checked, so killing an attempt never loses a count. The kernel releases the lock with the process. State is written by rename, so it is never half-written, though a stray temporary file can be left in `/run/properpin`. Not yet tested |
| After a success | `pam_setcred(PAM_REFRESH_CRED)`, errors ignored | The same | properpin's `pam_sm_setcred` returns `PAM_IGNORE`. The harness doesn't call `pam_setcred` yet |
| Account, session and password stacks | Never called | Never called | The lock screen never runs the `account` stack, with or without properpin, so an expired account still unlocks at the lock screen. Not properpin's concern, but worth knowing |
| Failure delay | Sets a `PAM_FAIL_DELAY` callback and blocks the UI until it passes | Sets the callback; the worker sleeps inside it, so inside `pam_authenticate` | The harness lets libpam sleep instead. Either way a wrong PIN costs about 2 seconds, from `pam_unix` failing on the same input |
| "Unavailable" results | `PAM_AUTHINFO_UNAVAIL` or `PAM_MODULE_UNKNOWN` mark the service unavailable | The same, plus the 50 ms check below | The module only ever returns `PAM_SUCCESS` or `PAM_IGNORE`. `install.sh enable` refuses unless the installed files check out, and `uninstall` refuses while enabled, so the PAM line never points at a missing module through the installer |
| Unloading the module | The handle ends on the worker thread when the greeter exits, and then the thread exits | `pam_end` runs as the worker process exits, and then `exit()` runs the main thread's TLS destructors | Both are exactly the rust-lang/rust#91979 pattern; `-z nodelete` covers both. The container test doesn't yet check how the attempt process exited, so a crash at exit would go unnoticed |
| Core dumps | Whatever the system allows | The worker makes itself non-dumpable unless debug logging is on | The typed PIN is less likely to reach a core dump in 6.8; wiping it from memory is still worth doing |
| Other authenticators | `kde-fingerprint` and `kde-smartcard` run alongside, as their own services | More of them (face, U2F), selectable, with an implicit fingerprint authenticator | properpin's lines are only in `kde`. A fingerprint unlock neither arms the PIN nor resets its failures. That is consistent with "armed by the password", but it is a product decision, not an accident |

## The 6.8 timing check

The 6.8 worker times every `pam_authenticate`. If it returns within 50 ms it reports the service as unavailable, before looking at whether it succeeded ("faster than is reasonable for any service"; the comment cites defunct face authenticators that report success in 0 ms). The greeter then treats that authenticator as defunct. The environment variable `KSCREENLOCKER_PAM_TIME_CHECK=0` turns the check off, but nothing sets it by default. The check first appears in commit a5ed9ca0 ("pam: flexible authenticator support", 2026-07-20), so it is in 6.7.90, 6.7.91 and master.

A correct PIN is fast: properpin's own work for one, at the default hash cost of 5, measured at about 23 ms on the development machine, against about 3 ms for input that skips hashing.

In the normal 6.8 flow this doesn't bite, because an attempt starts before the user types: the time measured includes waiting in the prompt. It bites whenever the answer is already there when the prompt arrives. Then a correct PIN returns in about 25 ms plus a D-Bus round trip, the lock screen reports "unavailable" instead of unlocking, and the password authenticator is marked defunct until the state resets. plasma-desktop 6.7.91 has exactly such a path: a password submitted during the failure delay is kept as `pendingPassword` and sent as soon as the delay ends. Today it is inert, because it checks `authenticator.pamTimeout`, a property kscreenlocker 6.7.91 doesn't have (it is called `inPasswordDelay` there). It is one rename away from being live.

The same check applies to the plain password, but `pam_unix` takes longer (it forks and execs `unix_chkpwd`, which hashes at the system's cost), and that is the path KDE itself exercises, so trouble there would be noticed upstream. properpin's PIN is a fast path nobody upstream tests.

Ways out, to decide before 6.8 reaches the real machine:

- **Pad a successful PIN check to a minimum duration in the module,** say 100 ms. It's cheap and robust, and it also evens out the timing difference between a correct and a wrong PIN.
- **Raise the default hash cost** until a check takes well over 50 ms. That's worth it for offline cracking anyway, but it ties correctness to CPU speed.
- **Set `KSCREENLOCKER_PAM_TIME_CHECK=0`.** This disables a safety check meant for other modules, and it lives in the greeter's environment, which properpin doesn't own. Not recommended.

## What to do with this

- **In the harness and the container test:**
  - several attempts on one handle, as both versions do;
  - `pam_setcred(PAM_REFRESH_CRED)` after a success;
  - check that every attempt process exited normally, not by a signal;
  - a scenario that kills attempts at random points and then checks that the state still parses and the failure count never went down. Deferred; `docs/plan.md` has the reasoning. The counting order itself is already pinned down by unit tests in `crates/core/src/attempt.rs`;
  - time a correct PIN through the real stack, and fail the test below 50 ms once the padding exists.
- **In properpin:** decide on the minimum duration, or the hash cost, before 6.8. It belongs in the plan next to the repeated-access fix.
- **On the real lock screen** (a VM or the real machine): with 6.8, the worker logs "N ms elapsed during pam_authenticate call for service kde" at warning level, so the journal shows the real timings for the PIN, the password and a wrong PIN. Also check what happens when a PIN is typed during the failure delay.
- **When 6.8.0 is tagged:** compare `greeter/worker/main.cpp`, `greeter/pamauthenticator.cpp` and `LockScreenUi.qml` against this note, mainly the timing check and the `pendingPassword` path.

## Redoing this

Where the answers were, most valuable first:

- **kscreenlocker `greeter/worker/main.cpp` (6.8):** nearly everything on the PAM side in one file. It has `pam_start` and its arguments, the conversation function (how prompts are answered, what happens to info and error messages), the `PAM_FAIL_DELAY` callback, `pam_authenticate` with the 50 ms timing check and how results map to success, failure and unavailable, `pam_setcred` after success, and the worker's process setup (die with parent, non-dumpable). Start here.
- **plasma-desktop `desktoppackage/contents/lockscreen/LockScreenUi.qml`:** the only place that says when an attempt starts (`startAuthenticating`: on show, after a failure, on the heartbeat) and when the typed text is sent (`respond`, the `pendingPassword` path). Without it the timing check can't be judged. Diff it between tags; the change from 6.7.5 to 6.7.91 is where the eager start came in.
- **kscreenlocker `greeter/pamauthenticator.cpp`:** in 6.7.5 this is the whole PAM side (the in-process `PamWorker`, the same structure as the 6.8 worker). In 6.8 it is the greeter's half: starting and killing the worker process (`startWorker`, `quitWorkerProcess`, the SIGTERM-then-SIGKILL timings in `cancel`) and the repeated-failure guard in `tryUnlock`.
- **Linux-PAM `libpam/pam_auth.c` and `_pam_sanitize` in `libpam/pam_misc.c`:** a few lines that settle whether a reused handle can leak the previous attempt's typed text. It can't: `PAM_AUTHTOK` is cleared before and after every `pam_authenticate`.
- **kscreenlocker `greeter/pamauthenticators.cpp`:** how the authenticators are combined (password, fingerprint, smartcard, and in 6.8 face and U2F) and when `startAuthenticating` actually reaches `tryUnlock`. Useful for the other-authenticators row; not needed for the core contract.
- **kscreenlocker `greeter/CMakeLists.txt` and the top-level `CMakeLists.txt`:** only to confirm that the service name defaults to `kde`.
- **Not useful:** `greeter/fallbacktheme/` (kscreenlocker's own fallback UI, not what Plasma shows), and plasma-workspace, where the lock screen QML used to live. It moved to plasma-desktop's shell package (commit 3f30472bc in plasma-workspace, "Move lockscreen in Shell package").


```
git clone https://invent.kde.org/plasma/kscreenlocker.git
git clone --filter=blob:none --no-checkout https://invent.kde.org/plasma/plasma-desktop.git
git -C kscreenlocker grep -n 'pam_start\|pam_authenticate\|pam_setcred\|pam_acct_mgmt\|tooQuick' <tag> -- greeter
git -C plasma-desktop show <tag>:desktoppackage/contents/lockscreen/LockScreenUi.qml | grep -n 'startAuthenticating\|respond(\|pendingPassword'
```

The PAM code is small, about 400 lines per version, and reading it against the table above takes about an hour.
