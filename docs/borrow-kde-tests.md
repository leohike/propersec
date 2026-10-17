# Borrowing KDE's tests

Which of KDE's own automated tests properpin could copy and adapt for end-to-end testing of the PIN, written on 2026-10-15 after reading kscreenlocker master (commit `e77531a`, 2026-10-09) and KWin's integration tests. Nothing here is built yet; it is a note for future action, and the main item should become a row in `docs/plan.md` when it is taken up. It serves the kscreenlocker 6.8 blocker in `docs/before-anybody-uses-this.md` more directly than anything else found so far.

## Why

properpin's container scenarios imitate kscreenlocker: `pamharness` keeps one PAM session for many attempts, and `crates/systest` plays 6.8's worker process, killing it with SIGKILL, or SIGTERM and SIGKILL 25 ms later, the way the greeter cancels. That imitation was written from reading kscreenlocker's code (`docs/kscreenlocker-pam-contract.md`), and the Aurora VM test (`docs/aurora-vm-test.md`) ran only 6.7.5, where PAM runs on a thread inside the greeter. Nothing has yet run properpin under 6.8's real worker. KDE's own test code can close that gap without a graphical session.

## The one to take: kscreenlocker's PAM test

`autotests/pamtest.cpp` in kscreenlocker, by David Edmundson, about 70 lines of QtTest. It creates the greeter's real `PamAuthenticator` for a service and a user and drives it the way the lock screen's QML does: `tryUnlock()`, wait for `promptForSecret`, `respond("…")`, wait for `succeeded` or `failed`, with `QSignalSpy`s on `readyChanged`, `prompt`, `busyChanged` and the rest. It tries a wrong password and then the right one, and checks that `busyChanged` fired twice per attempt.

What makes it valuable is what `PamAuthenticator` is on master: the 6.8 design. It starts the real `kscreenlocker_worker` from libexec with the service and user as arguments, hands it the address of a peer-to-peer D-Bus server on stdin, and talks to it over D-Bus (`greeter/pamauthenticator.cpp`, around lines 297 to 320). When it cancels, it terminates the worker and kills it if it hasn't exited within 25 ms (around lines 284 to 292), and it may wait as little as 5 ms for a worker to quit on its own when two have to be cancelled (around lines 169 to 173). A copy of this test therefore runs properpin's module inside kscreenlocker's own worker, through its own D-Bus protocol, with its own cancel and kill logic, rather than ours.

### How upstream runs it

Under `pam_wrapper`: `LD_PRELOAD=libpam_wrapper.so`, a service directory from the test's data, and `pam_matrix.so` as the whole stack, with a password database of one line (`test_user:my_password:test_service`). It sets `KSCREENLOCKER_PAM_TIME_CHECK=0`, because `pam_matrix` answers too fast for the 50 ms check. See `autotests/CMakeLists.txt` and `autotests/data/`.

### What to change for properpin

- **No `pam_wrapper`, no `pam_matrix`.** Use the real `kde` service, after `install.sh install`, in the same Fedora container the system test already builds, running as the test user, so the module starts the real setgid pinchecker and `pam_unix` the real `unix_chkpwd`.
- **Keep the time check on.** Do not set `KSCREENLOCKER_PAM_TIME_CHECK`. The 50 ms check is what `min_milliseconds_before_pin_unlock` exists for, and this would be the first time the real check meets it. A test with the variable set to `0` should exist only as a deliberate control, to show the difference.
- **properpin's scenarios instead of upstream's two attempts:** the PIN unlocking, a wrong PIN, three consecutive failures pausing it and a password unlock unpausing it, the budget forgiving a typo, and the PIN refused once the budget disables it.
- **Cancels, through kscreenlocker's own code:** cancel an attempt at chosen and random moments while it checks a wrong PIN, a correct PIN and the password, then check the same four points as the deferred randomized kill test in `docs/plan.md`: a readable state, the lock released, no effect from a killed attempt, and leftover temporary files counted.
- **Messages:** spy on `infoMessage` and `errorMessage` to see exactly what reaches the greeter when the module sends PAM conversation messages, if properpin starts sending them (the idea of clear messages at the lock screen; anything shown must not help an attacker at the keyboard, so no counts or remaining tries).
- **Timing:** record how long each `PamAuthenticator` attempt takes, and look for the "ms elapsed during pam_authenticate" warnings the time check logs.

### Building it

Build kscreenlocker from source inside the container, from the tag under test: 6.7.5 now (where `PamAuthenticator` still runs PAM on a thread, which makes it a test of the 6.7 path too) and 6.8.0 once tagged, as the plan's row on rechecking kscreenlocker asks. It needs Qt 6, KDE Frameworks and extra-cmake-modules; Fedora packages them, and `dnf builddep kscreenlocker` should bring most of what is needed. Only the authenticator library, the worker and the test have to be built, not the greeter UI. Everything runs without a display, so it fits in CI next to the existing podman job, at the cost of a longer image build that the cache should mostly absorb.

The test then lives in its own folder, something like `testing/kscreenlocker/`, with a small CMake project that builds against kscreenlocker's source tree, and a `just kscreenlocker` recipe that runs it in podman like the other system tests.

### Licence

kscreenlocker's code, its tests included, is GPL-2.0-or-later. A test adapted from `pamtest.cpp` and linked against `PamAuthenticator` is GPL too. That is fine for test code that is never shipped, but it should sit in its own folder with its SPDX header kept, and it is one more thing to weigh when properpin chooses its own licence (the licence blocker in `docs/before-anybody-uses-this.md`).

### What it would replace

Once it runs on 6.8, much of the 6.8 lifecycle imitation in `crates/systest` (the long-lived worker, the kills at chosen and random moments) becomes a second opinion rather than the only evidence. Keep the imitation anyway: it runs without building kscreenlocker, and it tests kills at moments kscreenlocker's code would never choose.

## Less useful

- **KWin's `autotests/integration/lockscreen.cpp`.** kscreenlocker's `tests/README.md` names it as kscreenlocker's integration tests, but it tests the compositor's side: the greeter stacked above other windows, input and shortcuts blocked while locked, screen edges, effects. It never touches PAM. It would only show that properpin doesn't change locking itself, which it doesn't.
- **kscreenlocker's `autotests/logindtest.cpp`.** Locking on logind's signals, with a fake logind. Unrelated to authentication.
- **kscreenlocker's `tests/`.** `kcheckpass_test.cpp` and `kscreenlocker_main.cpp` are programs for trying things by hand, not automated tests.

## Further: the real greeter on screen

The step after that tests what the user sees. `kscreenlocker_greet --testing` (`greeter/main.cpp`, around lines 127 to 140) starts the real greeter, QML and all, without locking a session, with an immediate lock and ptrace allowed. Run inside a headless KWin (`kwin_wayland --virtual`), it could be driven by KDE's `selenium-webdriver-at-spi`, the accessibility-based GUI test tool KDE uses for Plasma applications: type into the real field, press Enter, read the real messages. That covers the QML and the messages in a way no PAM-level test can, but the setup is much larger (a compositor, a session bus, AT-SPI, a WebDriver client). Worth it only after the PAM test above, and probably only if properpin starts showing its own messages or moves towards KDE's UI.

For release testing rather than CI, Fedora's openQA runs KDE desktop tests in full VMs. Adapting one of its lock screen tests, or using the same approach against the Incus VM, is an option for a scripted version of the manual Aurora test.

## Next step

Add a row to `docs/plan.md`: build kscreenlocker 6.7.5 in the podman image and run a `pamtest`-style QtTest against the real `kde` stack, then repeat on 6.8.0 when it is tagged. Small to medium effort; touches nothing outside podman's image storage.

## Sources

- kscreenlocker: https://invent.kde.org/plasma/kscreenlocker (`autotests/pamtest.cpp`, `autotests/CMakeLists.txt`, `autotests/data/`, `greeter/pamauthenticator.cpp`, `greeter/main.cpp`, `tests/README.md`)
- KWin's lock screen integration tests: https://invent.kde.org/plasma/kwin/-/blob/master/autotests/integration/lockscreen.cpp
- selenium-webdriver-at-spi: https://invent.kde.org/sdk/selenium-webdriver-at-spi
- pam_wrapper: https://cwrap.org/pam_wrapper.html
