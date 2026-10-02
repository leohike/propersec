---
id: 2610012058ARSk6aHTz4
datetime: 2026 Oct 1, 20:58
ctime: "2026-10-01 20:58:33"
---



Your 5-layer plan is basically right, but the most important fix is about privileges: kscreenlocker_greet runs PAM as the logged-in user, not as root.\[1\] So any tier that drives the stack with pamtester as root gives misleading results. That includes your container tier as written. Your heaviest coverage should go into a pure-Rust state-machine core tested with proptest. Next comes a thin real-libpam harness (`pam_start_confdir` or the pam-rs `bwrap` trick). Then run pamtester as an unprivileged user inside your bootc image under podman. A bcvk VM is optional, and you can stop at a short manual greeter checklist.\[2\] Full greeter automation can be done, but for a hobby project it's past the point of diminishing returns.

## TL;DR

- **Put most of the effort into tiers 1–3.** Tier 1 is a pure decision engine (inject the clock and storage) tested with `proptest-state-machine`. Tier 2 is the compiled `.so` loaded by real libpam from a temp config dir. Tier 3 is `podman run` on your actual bootc image, with pamtester run *as the test user*. Together these catch nearly all logic, FFI and stack-ordering bugs for a few evenings of setup.
- **Fix your mental model before writing the module.** The greeter is unprivileged. pam_unix therefore checks the password through the setuid `unix_chkpwd` helper, which can only verify the caller's own password.\[3\] Your module can't write root-owned state, and any state under `$HOME` can be edited by the user. Plasma 6.8 adds switchable authenticators (`kde-face`, `kde-u2f`) that cancel each other with SIGINT.\[4\] The default password service is still `kde`.\[5\]
- **Things worth copying:** pam-rs (pamtester + bubblewrap integration tests), nonstick (mock-able PAM traits), pam-client's `conv_mock`, fprintd's `test_pam_fprintd.py` (pam_wrapper + python-dbusmock), nuvious/pam-duress (duress stack pattern), and bcvk's `ephemeral run-ssh` for rootless VMs. Per GitHub's 2 April 2024 changelog, hardware-accelerated KVM works on standard 2-vCPU GitHub-hosted Linux runners; it used to need 4+ vCPUs. Skip openQA and Testing Farm unless you get bored.

## Corrections to your notes

- **The greeter is not root.** "kscreenlocker_greet runs as the session user as opposed to root" (Yubico/yubico-pam#113).\[1\] Arch users fixing broken unlocks found the cause was a missing setuid bit on `/sbin/unix_chkpwd`.\[6\] pam_unix(8) says the helper "will only check the password of the user invoking it… applications like xlock(1) work without being setuid-root".\[3\]\[7\] What this means for you:
  - Counter and timestamp files must be writable by the user. Something like `/var/lib/lazypass` owned by root won't work unless you add your own setuid/D-Bus helper.\[8\]
  - User-writable state can be reset by the user. That's acceptable for your threat model, since the attacker is at the greeter and has no shell. Still, write the assumption down. It also means a duress action runs with user privileges only.
  - The Fedora SELinux domain is almost certainly the user's `unconfined_t`; nothing in policy gives kscreenlocker_greet its own type. This comes from Fedora docs on unconfined users, not a policy file.\[9\]\[10\] Check with `ps -eZ | grep kscreenlocker_greet`. Expect plain Unix permissions to bite, not SELinux. `unix_chkpwd` itself runs confined as `chkpwd_t`.\[11\]
  - pam_faillock probably can't update tally files in this context. Treat that as unverified and test it in Tier 3/4.\[12\]
- **Only `auth` entries matter.** The kscreenlocker README: "KScreenLocker only uses the 'auth' entries".\[5\]\[13\] So "PIN allowed only within N minutes after a full-password unlock" can't hang off `account` or `session`. Use two `auth` lines instead: one before pam_unix (PIN check) and one `optional` line after pam_unix that records "full password succeeded at T".
- **Parallel stacks.** kscreenlocker MR !163 (Plasma 6.0) runs `kde`, `kde-fingerprint` and `kde-smartcard` workers at the same time.\[14\]\[15\] The non-interactive ones must not include your module. The Arch wiki warns: "Do not use auth sufficient in /etc/pam.d/kde-fingerprint… failed authentication attempts [will] bypass the lock screen."\[16\]
- **Plasma 6.8 switchable authenticators** (kscreenlocker MR !318, plasma-desktop MR !3689). KDE's 22 Aug 2026 "This Week in Plasma" calls it experimental, with no setup GUI yet.\[17\] It's opt-in through `~/.config/kscreenlockerrc` `[Authenticators]` and adds services such as `kde-face` and `kde-u2f`. The old interactive/non-interactive split becomes active/fingerprint. Switching cancels the old authenticator by sending SIGINT.\[4\]\[18\] Your module must therefore survive being abandoned mid-conversation (`pam_end` without a result, or a signal while it's blocking). Make sure a strike isn't counted twice or lost in that case.
- **Fedora's `kde` file.** Fedora ships `/etc/pam.d/kde*` in **plasma-workspace**, not kscreenlocker.\[19\] The RH-family template in MR !163 is `auth substack password-auth` + `auth include postlogin`, with `kde-fingerprint` using `fingerprint-auth`.\[14\] Faillock is only present if authselect `with-faillock` is enabled, which is off by default.\[20\] Check the real file on Aurora (`cat /etc/pam.d/kde`, `rpm -qf`). The vendor files may live in `/usr/lib/pam.d`: pam.conf(5) calls that "the Linux-PAM vendor configuration directory" and says "Files in /etc/pam.d override files with the same name in this directory". That page doesn't mention ostree, so check where Aurora actually puts them.
- **Login manager.** Fedora 44 replaced SDDM with Plasma Login Manager. The F44 "PlasmaLoginManager" Change, proposed by Neal Gompa and approved by FESCo, says "All Fedora KDE variants will use Plasma Login Manager (PLM) instead of SDDM", including Kinoite. If you ever target login as well as lock, that's a different service (`plasmalogin`).

## Module design that makes testing cheap

- **Split the crate.** `lazypass-core` is pure Rust with no FFI. It's a function `(State, Input{secret_class, now}, Config) -> (Outcome, State)`. `pam_lazypass` is a ~200-line cdylib shim (nonstick or pam-bindings) that only does I/O: get the authtok, read and write state, run the duress action.
- **Inject a `Clock` and a `Store` trait.** That lets you test window expiry, clock skew (going backwards after suspend or an NTP change) and corrupted or missing state files without sleeping.
- **Stack shape to test against:**
  - `auth [success=done ignore=ignore default=bad] pam_lazypass.so mode=pin`. It returns `PAM_IGNORE` once strikes ≥3 or the window has expired, and sets `PAM_AUTHTOK` so pam_unix can use `try_first_pass`.
  - `pam_unix` (via the `password-auth` substack).
  - `auth optional pam_lazypass.so mode=record`. This line opens the PIN window.
  - Watch control-flag syntax carefully. One Fedora lock-screen project (dromeropa/tinkero PR #47) locked users out because `auth [success=... default=...] substack password-auth` isn't valid. libpam treated `substack` as a module path and failed with "Module is unknown".\[12\] Only stack-level tests (Tier 2/3) catch this kind of bug.
- **Duress.** Copy the pattern from nuvious/pam-duress and rafket/pam_duress: `[success=1 default=ignore]` after pam_unix, and run a script on match.\[21\]\[22\] In tests, point the action at a script that writes a marker file. Assert that the return code, conversation messages and rough timing look the same as a normal unlock.

## Tier 1 — pure logic (high value, ~1–2 evenings)

- Write example tests for each rule, then a model-based test with **proptest-state-machine**. It's an official proptest-rs crate (0.8.0, March 2026).\[23\] You write a `ReferenceStateMachine` (a dumb model of strikes, window and duress) and a `StateMachineTest` that runs the real core. Failing transition sequences are shrunk automatically.\[24\] It only supports sequential transitions, which is fine here.\[25\]
- Invariants worth encoding:
  - A PIN never authenticates when strikes ≥3 or outside the window.
  - Only a full password resets strikes.
  - Duress never changes the "real" state in an observable way.
  - Time going backwards never extends the window.
  - Unparseable state fails closed (the full password is still required).
- Fuzz the state-file parser and the authtok handling with `cargo-fuzz`. Include non-UTF-8 bytes, multi-byte characters (your char-vs-byte concern) and empty or very long secrets. Miri works on this layer because there's no FFI.

## Tier 2 — the real `.so` through real libpam, no root (high value, ~1–2 evenings)

Three options. Pick one; the first two are enough.

- **`pam_start_confdir`** (Linux-PAM ≥1.4). Per pam_start(3), it "allows setting confdir argument with a path to a directory to override the default (/etc/pam.d) path", so it reads service files from your temp dir. Write a small Rust test binary on `libpam-sys`/nonstick's `TransactionBuilder`, or use `pam-client`, whose `conv_mock::Conversation::with_credentials` gives you a scripted conversation.\[26\]\[27\] Use absolute module paths in the service file. Swap pam_unix for `pam_matrix.so` (a fake passdb from pam_wrapper), or for `pam_permit`/`pam_deny` per test case.\[28\]\[29\]
- **pam-rs's bubblewrap trick.** lvkv/pam-rs runs its integration tests with `pamtester` + `bwrap`, bind-mounting a test `pam.d` over `/etc/pam.d` in a user namespace. This is the most directly copyable Rust setup; see its `.github/workflows/rust.yml`.\[30\]
- **cwrap pam_wrapper / pypamtest.** `LD_PRELOAD=libpam_wrapper.so PAM_WRAPPER=1 PAM_WRAPPER_SERVICE_DIR=…`.\[31\] It's packaged in Fedora (`pam_wrapper`, `python3-libpamtest`).\[32\] It comes with helper modules `pam_matrix`, `pam_set_items` and `pam_get_items`; `pam_set_items` lets you inject `PAM_AUTHTOK` to mimic stack ordering.\[33\]\[34\] fprintd's `tests/pam/test_pam_fprintd.py` (pam_wrapper + python-dbusmock) is the best real-world example.\[35\] It's only worth it if you'd rather write the scenarios in Python. LD_PRELOAD in a Rust test binary works but is fiddlier than `pam_start_confdir`.
- **Native-risk tests that belong here:**
  - **Load/unload loops.** libpam `dlclose`s modules at `pam_end`. kscreenlocker runs PAM in worker threads inside a long-lived process. Loop `pam_start → authenticate → pam_end` 1,000× from threads that then exit. Rust TLS destructors plus `dlclose` have caused real segfaults (rust-lang/rust#91979: a Rust cdylib dlopened in a thread, closed, then the thread exits).\[36\] Per that issue, glibc 2.17 (CentOS 7) "segfaults at __nptl_deallocate_tsd()" and "with later versions of glibc, there is no crash". Avoid `thread_local!` with `Drop` in the module. The pam_rssh AUR comments also show a Rust std regression (rust-lang/rust#125319) breaking a shipped PAM module, so pin your toolchain and keep this test in CI.\[37\]
  - **Panics.** Force a panic through a test-only arg and assert `PAM_IGNORE` or `PAM_AUTH_ERR`, never an abort. Every entry point needs `catch_unwind` (nonstick/pam-bindings macros may already do this; check). Build with `panic = "unwind"`, not abort.
  - **Concurrency.** Run two processes authenticating at once against the same state file. Use `flock` and write-to-temp-then-`rename`, and assert there are no lost strikes.
  - **Sanitizers.** Run the harness under valgrind, or build with `-Zsanitizer=address` on nightly. Miri can't cross into libpam.

## Tier 3 — your real bootc image in podman (high realism per unit of effort, ~1 evening)

- `podman run --rm -v ./target:/mnt localhost/aurora-lazypass` (or a derived test image). Add `useradd tester` + `chpasswd`, drop in the real `/etc/pam.d/kde`, then **`runuser -u tester -- pamtester kde tester authenticate`**. Running as the user is the important correction: it exercises `unix_chkpwd` exactly as the greeter does.
- This tier proves:
  - the real authselect-generated `password-auth`/`postlogin`
  - the real pam_unix, and faillock if you enable it
  - file permissions on your state path
  - that the RPM/Containerfile actually installs the module where the stack expects it
- pamtester feeds the password on stdin; use `expect` or a tiny Rust driver for multi-step scenarios (3 wrong PINs → full password). Kanidm's `pam_tester` is an alternative driver.\[38\] sssd-test-framework's faillock example (deny=3, three bad attempts, assert locked, `faillock --reset`) is a good model for the strike scenarios.\[39\]
- Not covered here: SELinux enforcement (containers usually run without the host policy applying inside), systemd/logind, and the greeter itself.

## Tier 4 — bootc VM via bcvk (optional, ~1–2 evenings, mostly for SELinux and "it boots")

- `bcvk ephemeral run-ssh localhost/aurora-lazypass -- <test script>` boots your image as a throwaway VM without root, as a podman wrapper. It needs qemu and virtiofsd on the host, and injects SSH keys automatically.\[2\]\[40\]\[41\] For persistence there's `bcvk libvirt run`, and `bcvk to-disk` gives you a qcow2 image.\[42\]\[43\] An `ephemeral test-basic` health check is in recent PRs.\[44\] Known rough edges: SSH timeout flakes on slow guests, and running bcvk from inside a toolbox fails (podman can't see the binary).\[45\]\[46\]
- Run the Tier 3 scripts again here under enforcing SELinux. Also run `ausearch -m avc` after each scenario, and check `journalctl -t kscreenlocker_greet`-style logs from your `pam_syslog` calls.
- **GitHub Actions:** GitHub's 2 April 2024 changelog says "Actions users of our 2-vCPU GitHub-hosted Linux runners will be able to make use of hardware acceleration… Previously this feature was only available on runners with 4 or more vCPUs"; you need a udev rule that grants access to `/dev/kvm`. actions/runner-images Discussion #7191 adds "All Linux runners are now on a SKU that supports nested virtualization", and a 27 Oct 2025 reply in community Discussion #8305 says "hardware accelerated virtualization works since GitHub updated the Linux runners". Older blog posts saying hosted runners lack nested virtualization are out of date.\[47\] Expect slow, sometimes flaky runs, and gate this tier as nightly rather than per-push.
- **tmt / Testing Farm:** tmt has `provision: how: bootc` (it builds a disk from your container image and runs it via testcloud), and Testing Farm supports "image mode" composes (e.g. `Fedora-44-image-mode`).\[48\]\[49\] They're useful if you want Fedora-standard test metadata, but they add nothing over bcvk + a shell script for a single-person project.

## Tier 5 — the actual greeter

- **Manual checklist, ~15 minutes per release:** keep an SSH session open into the VM or machine as an escape hatch, plus `journalctl -f`. Run through the cases: PIN in window, PIN after window, 3 bad PINs → password, duress, suspend/resume while locked, the fingerprint stack running in parallel, and a 6.8 authenticator switch while your module is mid-prompt. This catches the bugs that are realistically left after Tiers 1–4.
- **Semi-automated middle ground:** `kscreenlocker_greet --testing` runs the greeter standalone, with real PAM against the `kde` service, inside your session or a nested `kwin_wayland`.\[50\] Testing mode also allows ptrace, which is useful for gdb.\[6\]\[51\] It's the cheapest way to see your messages and PAM_FAIL_DELAY in the real UI.
- **Full automation, if you really want it:**
  - KDE's selenium-webdriver-at-spi drives apps inside a nested KWin via AT-SPI and fake input.\[52\]\[53\] One third-party project, isac322/krema, runs that whole stack in GitHub Actions inside a Fedora 43 container, using `kwin --virtual` and KWin fake-input with ScreenShot2 for pixel checks.\[54\] That shows headless CI is possible.
  - kscreenlocker's own `autotests/` (`pamtest.cpp`, `ksldtest.cpp`, `fakelogind.cpp`) show how KDE tests the authenticator logic without a full session.\[55\]
  - KDE Linux now runs openQA end-to-end tests, driven by selenium-webdriver-at-spi instead of screenshot needles. The KDE/os-autoinst-distri-kdelinux README lists "Lock screen - lock the session and unlock it with the user's password" among its scenarios. Fedora also uses openQA.\[56\]
  - For a hobbyist, running an openQA instance or keeping AT-SPI selectors working against the lock screen QML will cost more upkeep than your module does. Skip it unless the greeter integration itself becomes the hobby.

## Recommendations

- **Week 1:** the core/shim split, Tier 1 with proptest-state-machine, and Tier 2 via `pam_start_confdir` (or a copy of pam-rs's bwrap harness), including the dlopen/thread loop and the panic test. Run all of it in GitHub Actions on every push. No VM needed.
- **Week 2:** a Tier 3 podman script against your real bootc image, run as an unprivileged user. Then port your current Python/pam_exec prototype's scenarios into it, as the acceptance suite the Rust module has to pass.
- **When you touch SELinux or packaging:** Tier 4 with bcvk, locally and as a nightly CI job.
- **Every Plasma upgrade, especially 6.8:** the Tier 5 manual checklist. Re-read the shipped `/etc/pam.d/kde*` files, since the parallel-stack and authenticator-switching behaviour is still changing.
- **Diminishing returns:** after Tier 3 you're testing KDE more than your module. Tier 4 earns its keep only for SELinux and boot regressions. Automating Tier 5 is a separate project.

## Caveats

- I couldn't read Fedora's exact `/etc/pam.d/kde`. The RH-family template above comes from KDE's MR !163 and may not match what Aurora ships.
- That pam_faillock can't write tallies from the unprivileged greeter, and that the greeter runs as `unconfined_t`, are inferences from how the greeter and SELinux defaults work. Verify both on a live system.
- The Plasma 6.8 authenticator switching is labelled experimental and its service names could change before or after release.\[17\]
- pam.conf(5) documents `/usr/lib/pam.d` as the vendor directory, but nothing I found says how ostree/bootc images use it. The krema CI setup comes from a single third-party repo, not official docs.

## Sources

1. [\[BUG\] Locked screen fails unlock with YubiKey on Kubuntu (KDE-based Ubuntu) · Issue #113 · Yubico/yubico-pam](https://github.com/Yubico/yubico-pam/issues/113)
2. [GitHub - bootc-dev/bcvk · GitHub](https://github.com/bootc-dev/bcvk)
3. [pam\_unix(8) — Arch manual pages](https://man.archlinux.org/man/pam_unix.8)
4. [pam: flexible authenticator support (!318) · Merge requests · Plasma / KScreenLocker · GitLab](https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/318)
5. [GitHub - KDE/kscreenlocker: Library and components for secure lock screen architecture · GitHub](https://github.com/KDE/kscreenlocker)
6. [Can't unlock Plasma lock screen (kscreenlocker) - "unlocking failed" / Applications & Desktop Environments / Arch Linux Forums](https://bbs.archlinux.org/viewtopic.php?id=241046)
7. [unix\_chkpwd - manned.org](https://manned.org/unix_chkpwd/44e80f93)
8. [\[SOLVED\] KDE Kscreenlocker with pam-u2f didn't work / Applications & Desktop Environments / Arch Linux Forums](https://bbs.archlinux.org/viewtopic.php?id=292700)
9. [10.2.3. SELinux Contexts for Users](https://jfearn.fedorapeople.org/fdocs/en-US/Fedora/20/html/Security_Guide/sect-Security-Enhanced_Linux-SELinux_Contexts-SELinux_Contexts_for_Users.html)
10. [10.3.3. Confined and Unconfined Users](https://jfearn.fedorapeople.org/fdocs/en-US/Fedora/20/html/Security_Guide/sect-Security-Enhanced_Linux-Targeted_Policy-Confined_and_Unconfined_Users.html)
11. [\[Bug\] SELinux 发行版安装后 /usr 被标成 user\_home\_t，导致 sudo/passwd/polkit 全部失效 · Issue #67 · SuceV587/NextKde](https://github.com/SuceV587/NextKde/issues/67)
12. [pam: fix lock-screen self-lockout; reset the tally in the account phase via a Quickshell pam\_acct\_mgmt patch (Closes #46) by dromeropa · Pull Request #47 · dromeropa/tinkero](https://github.com/dromeropa/tinkero/pull/47)
13. [github.com](https://github.com/kelna/kscreenlocker)
14. [feat: run multiple pam sessions at once (!163) · Merge requests · Plasma / KScreenLocker · GitLab](https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/163)
15. [kscreenlocker/greeter/CMakeLists.txt at master · KDE/kscreenlocker](https://github.com/KDE/kscreenlocker/blob/master/greeter/CMakeLists.txt)
16. [Universal 2nd Factor - ArchWiki](https://wiki.archlinux.org/title/Universal_2nd_Factor)
17. [This Week in Plasma: UI and Performance Improvements - KDE Blogs](https://blogs.kde.org/2026/08/22/this-week-in-plasma-ui-and-performance-improvements/)
18. [lockscreen: implement authenticator switching (!3689) · Merge requests · Plasma / Plasma Desktop · GitLab](https://invent.kde.org/plasma/plasma-desktop/-/merge_requests/3689)
19. [plasma-workspace-6.6.4-1.fc45 - Fedora Packages](https://packages.fedoraproject.org/pkgs/plasma-workspace/plasma-workspace/fedora-rawhide.html)
20. [How to use Authselect to configure PAM in Fedora Linux - Fedora Magazine](https://fedoramagazine.org/how-to-use-authselect-to-configure-pam-in-fedora-linux/)
21. [GitHub - rafket/pam\_duress: A pam module written in C for duress codes in linux authentication · GitHub](https://github.com/rafket/pam_duress)
22. [pam duress](https://github.com/nuvious/pam-duress?)
23. [proptest-state-machine — Rust testing library // Lib.rs](https://lib.rs/crates/proptest-state-machine)
24. [State Machine testing - Proptest](https://proptest-rs.github.io/proptest/proptest/state-machine.html)
25. [proptest\_state\_machine - Rust](https://docs.rs/proptest-state-machine)
26. [pam\_client - Rust](https://docs.rs/pam-client/latest/pam_client/)
27. [nonstick - Rust](https://docs.rs/nonstick)
28. [man pam\_wrapper (1): A preloadable wrapper to test PAM applications and PAM Modules](https://manpages.org/pam_wrapper)
29. [Development \[LWN.net\]](https://lwn.net/Articles/670738/)
30. [GitHub - lvkv/pam-rs: Simplified PAM module creation in Rust](https://github.com/lvkv/pam-rs)
31. [Ubuntu Manpage: pam\_wrapper - A preloadable wrapper to test PAM applications and PAM Modules](https://manpages.ubuntu.com/manpages/stonking/man1/pam_wrapper.1.html)
32. [pam\_wrapper - Fedora Packages](https://packages.fedoraproject.org/pkgs/pam_wrapper/pam_wrapper/)
33. [Package pam\_wrapper - man pages](https://www.mankier.com/package/pam-wrapper)
34. [pam\_set\_items: A PAM test module to set module-specific PAM items](https://www.mankier.com/8/pam_set_items)
35. [Bug #1976256 “fprintd ftbfs in the jammy release pocket” : Bugs : fprintd package : Ubuntu](https://bugs.launchpad.net/ubuntu/+source/fprintd/+bug/1976256)
36. [github.com](https://github.com/rust-lang/rust/issues/91979)
37. [AUR (en) - pam\_rssh - Arch Linux](https://aur.archlinux.org/packages/pam_rssh)
38. [GitHub - kanidm/pam\_tester: A test helper for pam configuration validation.](https://github.com/kanidm/pam_tester)
39. [Testing PAM Modules — sssd-test-framework documentation](https://tests.sssd.io/en/latest/guides/testing-pam.html)
40. [Chapter 10. Testing and deploying bootable containers with bcvk](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/using_image_mode_for_rhel_to_build_deploy_and_manage_operating_systems/managing-image-updates-with-the-bootc-virtualization-kit-bcvk)
41. [BCVK: Because Testing bootc VMs Shouldn’t Be a Pain](https://gursmangat.medium.com/bcvk-because-testing-bootc-vms-shouldnt-be-a-pain-131fc4efefa2)
42. [GitHub - jeckersb/bcvk · GitHub](https://github.com/jeckersb/bcvk)
43. [bcvk-to-disk](https://www.mankier.com/8/bcvk-to-disk)
44. [ephemeral: Add test-basic subcommand by cgwalters-bot · Pull Request #393 · bootc-dev/bcvk](https://github.com/bootc-dev/bcvk/pull/393)
45. [ssh: Raise ConnectTimeout so slow guests don't fail after readiness by cgwalters-bot · Pull Request #377 · bootc-dev/bcvk](https://github.com/bootc-dev/bcvk/pull/377)
46. [ephemeral: Explain when podman can't see bcvk's filesystem by cgwalters-bot · Pull Request #4 · cgwalters-forge/bcvk](https://github.com/cgwalters-forge/bcvk/pull/4)
47. [How to run KVM guests in your GitHub Actions](https://actuated.com/blog/kvm-in-github-actions)
48. [RFD5 - Testing Farm support for Fedora, CentOS Stream and RHEL in Image Mode :: Testing Farm](https://docs.testing-farm.io/Testing%20Farm/0.1/rfd/rfd5-testing-image-mode.html)
49. [Provision Plugins — tmt documentation](https://tmt.readthedocs.io/en/1.42/plugins/provision.html)
50. [1376364](https://bugzilla.redhat.com/show_bug.cgi?id=1376364)
51. [kscreenlocker/greeter/main.cpp at master · KDE/kscreenlocker](https://github.com/KDE/kscreenlocker/blob/master/greeter/main.cpp)
52. [Developer](https://develop.kde.org/docs/apps/tests/index.xml)
53. [Appium automation testing](https://develop.kde.org/docs/apps/tests/appium/)
54. [test: automated E2E and QML component tests for the dock, run in CI by isac322 · Pull Request #38 · isac322/krema](https://github.com/isac322/krema/pull/38)
55. [/kf6-qt6/plasma/kscreenlocker/autotests/ - LXR - KDE](https://lxr.kde.org/source/plasma/kscreenlocker/autotests/)
56. [OpenQA - Fedora Project Wiki](https://fedoraproject.org/wiki/OpenQA)
