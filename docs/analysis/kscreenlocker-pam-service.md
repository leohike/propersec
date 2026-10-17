# Can properpin have its own PAM service instead of editing /etc/pam.d/kde?

The question this note answers: "can I make my own /etc/pam.d/properpin file that would be used instead of editing /etc/pam.d/kde?" The short answer is no, not as a service of its own: kscreenlocker's PAM service names are compile-time constants with no runtime override, so the lock screen will only ever open `kde` (plus the fixed optional slots). What properpin can do is shrink the edit to `/etc/pam.d/kde` to a single `auth include <properpin file>` line and keep its three lines in a file it owns. That works, but only with `include`, not `substack`, and it trades one failure mode for another: a missing included file locks the lock screen, where a missing module today only falls back to password-only. The recommendation at the end weighs this and proposes concrete files.

Read on 2026-10-17; nothing here was run against a live lock screen. Every claim is marked either "verified" (read in code or observed on this machine, with path:line) or "inferred" (reasoned from what was read, not checked end to end).

Sources:

- kscreenlocker, reference clone at `/var/home/shared/projects/pam-related/kscreenlocker`, `master` at `e77531ae` (2026-10-09, `v6.7.90-35`). `git diff v6.8.0 HEAD -- greeter/` is empty, so every `greeter/` line number below for master is also the line number in the `v6.8.0` tag. Older code is cited as `v6.7.5:path:line` (read with `git show`). The host machine runs `kscreenlocker-6.7.5-1.fc44`; Fedora's packaging repo (`fedora-rpm-kscreenlocker`, `6f3a790`) is already at `6.8.0-2`.
- Linux-PAM, reference clone at `/var/home/shared/projects/pam-related/linux-pam`, `v1.7.3-32-g584ef227`. The host runs `pam-1.7.2-2.fc44`; the files cited (`libpam/pam_handlers.c`, `libpam/pam_dispatch.c`) have the same logic in 1.7.2 as far as the behaviour discussed here goes (inferred: not diffed tag by tag, but the relevant code dates from 2015 and earlier, as the history notes below say).
- authselect at `1.8.0-2-g3084703`, gdm, and the host's own `/etc/pam.d`, `/usr/lib/pam.d`, `/usr/etc/pam.d` and `rpm` metadata (Aurora 44.20261013.1, Kinoite based).

## The short version

- **Service names are compile time only (verified).** In 6.8 they come from five CMake cache variables in `greeter/worker/CMakeLists.txt:6-32` (`KSCREENLOCKER_PAM_PASSWORD_SERVICE` = `kde`, `..._FINGERPRINT_SERVICE` = `kde-fingerprint`, `..._SMARTCARD_SERVICE` = `kde-smartcard`, `..._FACE_SERVICE` = `kde-face`, `..._UNIVERSAL2FACTOR_SERVICE` = `kde-u2f`), baked into `constexpr` strings by `greeter/worker/config-worker.h.in:8-21`. No environment variable, no KConfig key and no command line option names a service. Fedora builds with plain `%cmake_kf6` (`fedora-rpm-kscreenlocker/kscreenlocker.spec:69`), so the defaults ship.
- **kscreenlocker never checks whether `/etc/pam.d/<name>` exists (verified).** A service counts as present or absent only by what `pam_authenticate` returns: `PAM_AUTHINFO_UNAVAIL` or `PAM_MODULE_UNKNOWN` make it "unavailable" (`greeter/worker/main.cpp:335-339`), plus a greeter-side guard that gives up on a service once four failures in a row each arrive less than 2 s after the previous one (five quick failures in all) (`greeter/pamauthenticator.cpp:113-131`). A missing file silently becomes the `other` service, which on Fedora is `pam_deny` (host `/etc/pam.d/other`, owned by `pam`).
- **Option A, a separate service, is not possible without rebuilding (verified),** and hijacking an existing slot is a bad idea: on 6.7.5 (the host today) the extra slots are non-interactive and never receive typed text; on 6.8 only the Smartcard slot shows a password field, it is off unless the user enables it in `kscreenlockerrc`, it is labelled "Smartcard" with a card icon, and `/etc/pam.d/kde-smartcard` is a `plasma-workspace` config file just like `/etc/pam.d/kde`, so nothing is gained.
- **Option B, one `include` line in `kde` pointing at a properpin file, works (verified in libpam code), but `substack` would break properpin (verified).** In a substack, `success=done` and `die` only end the substack; the parent then runs `auth substack password-auth`, which checks the PIN as a password and fails, so a correct PIN would never unlock. `include` inlines the lines at the same stack level, so `done` and `die` behave exactly as they do today.
- **Lockout trade-off (verified).** Today, if the module `.so` disappears, line 1 and line 3 are "faulty modules" whose `PAM_MODULE_UNKNOWN` is ignored and the lock screen degrades to the password. Under Option B, if the included file disappears, libpam installs a must-fail handler with action `bad`, and the lock screen refuses everything, password included, until the file is back.
- **Vendor dir (verified on this machine).** libpam always searches `/etc/pam.d/<name>` then `/usr/lib/pam.d/<name>` (whole file, first hit wins), for services and for include targets alike. Upstream 1.7.2 also enables a third directory (`vendordir`, default `/usr/share/pam`), but Fedora's `libpam.so.0` contains only the `/etc/pam.d/%s` and `/usr/lib/pam.d/%s` format strings, so Fedora builds without it. On Aurora, `/usr/lib/pam.d` is part of the read-only image; properpin, which installs under `/usr/local`, cannot put files there without layering an RPM or a sysext.
- **Recommendation:** move to Option B with `include`, with the included file at `/etc/pam.d/properpin-kde-auth`, a one-line change to `kde` plus one marker comment, the installer ordering that never leaves `kde` including a missing file, and a new `PAM_SERVICE == "kde"` check in the module. Concrete files are in the Recommendation section below. If losing the "degrades to password-only" property is judged worse than a bigger diff, stay on Option C; the analysis below is meant to make that choice explicit.
- **Bonus:** kscreenlocker 6.8.0 dropped the 50 ms "too fast" check that `docs/chaos/kscreenlocker-pam-contract.md` worried about (commit `5d848610`, cherry-picked as `7ca40864`, inside `v6.8.0`). It also added a "more than three failures less than two seconds apart" guard that applies to the password authenticator too, which properpin's fast paths should keep in mind. Details in the Bonus section at the end.

## Which services kscreenlocker opens, and where the names come from

### 6.8 (v6.8.0 and master)

Verified, all paths relative to the kscreenlocker clone:

- `greeter/worker/CMakeLists.txt:4-33` declares five CMake cache strings. With CMake 4.2 or later they use the new `set(CACHE{...})` form (lines 6-25), otherwise plain `set(... CACHE STRING ...)` (lines 28-32). Defaults: `kde` ("CANNOT be disabled!"), `kde-fingerprint`, `kde-smartcard`, `kde-face`, `kde-u2f`; each optional one may be set to the literal `disabled`.
- `greeter/worker/config-worker.h.in:8-21` turns each into a `constexpr QLatin1String` with a `static_assert` that it is non-empty. The header is generated at configure time (`greeter/worker/CMakeLists.txt:35`).
- The top-level `CMakeLists.txt:86-95` still has the old `define_pam_service(KScreenLocker)` macro, which defines a `KSCREENLOCKER_PAM_SERVICE` cache variable (default `kde`) and writes `KSCREENSAVER_PAM_SERVICE` into `config-unix.h` (`config-unix.h.cmake:1-2`). Nothing in the 6.8 sources reads either (verified: `grep` for `KSCREENSAVER_PAM_SERVICE` and `KSCREENLOCKER_PAM_SERVICE` in `*.cpp`/`*.h` finds no users). So in 6.8 the old knob is vestigial; a distro that still passes `-DKSCREENLOCKER_PAM_SERVICE=...` gets `kde` anyway (inferred consequence).
- The names are used in exactly two places: `greeter/pamauthenticators.cpp:139` (the implicit fingerprint authenticator) and `greeter/pamauthenticators.cpp:176-195` (the active authenticator, a `switch` over the five types), plus `greeter/worker/main.cpp:259`, where the worker compares its service name with the fingerprint one to enable fingerprint-specific handling.
- The greeter starts `kscreenlocker_worker` with the service name as `argv[1]` (`greeter/pamauthenticator.cpp:306-307`, `KLibexec::path(u"kscreenlocker_worker"_s)`), and the worker calls `pam_start(service, user, ...)` with it (`greeter/worker/main.cpp:262-265`, `376`). The worker would accept any name, but only the greeter starts it, and the greeter only passes the compile-time constants. The worker's own comment calls a manual start wrong (`greeter/worker/main.cpp:371-374`).

Runtime configuration that does exist (verified), none of which names a service:

- `kscreenlockerrc`, group `[Authenticators]`, keys `Smartcard`, `Fingerprint`, `Face`, `Universal2Factor`, all default `false` (`greeter/pamauthenticatormodel.cpp:41-42`, `55`, `62`, `69`, `77`). They decide which non-password authenticators the UI offers. The config is opened as `KConfig(u"kscreenlockerrc"_s)`, the usual cascade of `~/.config/kscreenlockerrc` over `/etc/xdg/kscreenlockerrc` (inferred from KConfig's standard behaviour).
- `kscreenlockerrc`, group `[UI]`, key `ShowPromptInRegularAuthenticator` (default `false`, `greeter/pamauthenticatormodel.cpp:52-54`): whether the password authenticator shows the PAM prompt text.
- The state file `kscreenlockerrc` (`KSharedConfig::openStateConfig`, so under `~/.local/state`), group `[Greeter]`, key `Authenticator`: the last authenticator that unlocked successfully, which becomes the active one next time (`greeter/pamauthenticators.cpp:56-72`, `142`, `201`; loaded at construction, `greeter/pamauthenticators.h:116`).
- `KSCREENLOCKER_PAM_TIME_CHECK` was an environment variable, but it only switched a timing check and it was removed before 6.8.0 (see the Bonus section). It never chose a service.

### 6.7.5 (what the host runs today)

Verified with `git show v6.7.5:...`:

- `v6.7.5:CMakeLists.txt:118-127` is the same `define_pam_service` macro, here actually used: `v6.7.5:greeter/CMakeLists.txt:92-97` passes `KSCREENLOCKER_PAM_SERVICE`, `KSCREENLOCKER_PAM_FINGERPRINT_SERVICE` and `KSCREENLOCKER_PAM_SMARTCARD_SERVICE` as compile definitions. `KSCREENLOCKER_PAM_PASSWORD_SERVICE` is set at `v6.7.5:greeter/CMakeLists.txt:80-82` but never passed to the compiler, so in 6.7.5 the password service is controlled by `KSCREENLOCKER_PAM_SERVICE`, and in 6.8 by `KSCREENLOCKER_PAM_PASSWORD_SERVICE`. A rebuild recipe would have to know which version it targets (inferred).
- `v6.7.5:greeter/greeterapp.cpp:138-144` creates one interactive authenticator for `kde` and two non-interactive ones for `kde-fingerprint` and `kde-smartcard`. No face or U2F.
- No environment or config override of any service name (verified: the only `getenv`-style calls in `v6.7.5:greeter` are about Wayland and the input method, `v6.7.5:greeter/main.cpp:85-86`).

### On this machine

Verified with `rpm -qf` and `rpm -q --qf '%{FILEFLAGS:fflags}'`: `/etc/pam.d/kde`, `/etc/pam.d/kde-fingerprint` and `/etc/pam.d/kde-smartcard` belong to `plasma-workspace-6.7.5-1.fc44` and are flagged `cn` (`%config(noreplace)`), with pristine copies in `/usr/etc/pam.d/` (the ostree default `/etc`). There is no `kde-face` and no `kde-u2f` anywhere, so on 6.8 those two services would fall through to `other` if a user enabled them. `/etc/pam.d/kde` is the stock file (properpin is not installed on the host).

## How the authenticators run side by side

### 6.7.5: one interactive, two always-on non-interactive

Verified:

- `v6.7.5:greeter/pamauthenticators.cpp:142-154`: `startAuthenticating` calls `tryUnlock` on the interactive authenticator and on every non-interactive one, in parallel; each has its own PAM handle on its own `QThread`.
- `v6.7.5:greeter/pamauthenticators.cpp:203-207`: `respond` (the typed text) goes only to the interactive authenticator. A non-interactive service whose module asks a question would wait forever for an answer that never comes (inferred from the code: nothing else answers its prompts).
- Availability: `v6.7.5:greeter/pamauthenticator.cpp:203-205` marks a service unavailable on `PAM_AUTHINFO_UNAVAIL` or `PAM_MODULE_UNKNOWN`; `isAvailable` is "in authentication and not unavailable" (`:338`). The UI's fingerprint and smartcard hints follow the set of available non-interactive types (`v6.7.5:greeter/pamauthenticators.cpp:22-31`).
- This design came in with commit `adfae584` ("Run multiple PAM sessions at once", Janet Blackquill, 2023-10-26, in v5.90.0, "FIXED-IN: 6.0", BUG 475024). Its message says "PAM files will need to be adjusted to make use of this feature", pointing at kscreenlocker merge request 163; on Fedora that adjustment is the `kde-fingerprint` and `kde-smartcard` files shipped by `plasma-workspace`.

How Fedora keeps the optional slots quiet (verified): `kde-smartcard` substacks `smartcard-auth`, which under authselect's `local` profile is the single line `auth required pam_debug.so auth=authinfo_unavail` (host `/etc/pam.d/smartcard-auth`; authselect `profiles/local/smartcard-auth:1`). That returns `PAM_AUTHINFO_UNAVAIL`, which kscreenlocker reads as "no smartcard here". So "presence" is a convention between authselect and kscreenlocker, expressed in return codes, not in which files exist.

### 6.8: one selectable active authenticator plus an implicit fingerprint one

Verified:

- Commit `a5ed9ca0` ("pam: flexible authenticator support", Harald Sitter, 2026-07-20) replaced the interactive/non-interactive split with an "active / fingerprint split". Its message: "the user can select the type of authentication they want to use and then we'll switch the relevant authenticator in as active. this means the new authenticator takes over the prompting ... because we only ever have one active type. this gets augmented by the fingerprint handling which may be active on any number of types as secondary log in option." It also moved each `pam_authenticate` into its own `kscreenlocker_worker` process "because we now switch authenticators at will that means we also need them to cancel".
- `greeter/pamauthenticators.cpp:176-195`: the active authenticator is built for whichever of Regular, Fingerprint, Smartcard, Face or Universal2Factor is selected, with the matching service name.
- `greeter/pamauthenticators.cpp:133-174`: unless the active one is itself Fingerprint, an implicit fingerprint authenticator for `kde-fingerprint` is always created, regardless of the `[Authenticators] Fingerprint` key (that key only controls whether Fingerprint is offered as a selectable active type). `startAuthenticating` runs both (`:84-99`).
- `greeter/pamauthenticators.cpp:301-305`: typed text goes only to the active authenticator.
- `greeter/pamauthenticatormodel.cpp:45-89` describes each type for the UI. The relevant flags (`greeter/pamauthenticatordescriptor.h:21-32`): `passwordField` ("requires a password field to be shown in the UI") and `expectingPrompt`. Regular: password field yes, expects a prompt yes. Smartcard: yes, yes. Fingerprint, Face and Universal2Factor: no password field, no prompt expected. Regular is always enabled; the others need both a non-`disabled` compile-time name and the `[Authenticators]` key.
- `greeter/pamauthenticatormodel.cpp:107-114`: `markDefunct` refuses to mark Regular defunct ("This is unexpected and we ignore it").
- The UI itself (how a user picks the active type) lives in plasma-desktop's `LockScreenUi.qml`, which is not among the reference clones, so how the selection is presented is not verified here. kscreenlocker's own fallback theme only shows a password field plus fingerprint and smartcard hints (`greeter/fallbacktheme/Greeter.qml:82-106`).

How "unavailable" is decided in 6.8 (verified):

- In the worker, `greeter/worker/main.cpp:316-341`: success becomes `Success` (after `pam_setcred(PAM_REFRESH_CRED)`); for the fingerprint service, `PAM_AUTHINFO_UNAVAIL` within 250 ms becomes `Unavailable` and later than that `Failure` (`:322-333`); otherwise `PAM_AUTHINFO_UNAVAIL` or `PAM_MODULE_UNKNOWN` becomes `Unavailable` (`:335-339`); anything else is `Failure`.
- In the greeter, `greeter/pamauthenticator.cpp:113-131`: if a `Failure` arrives less than 2 s after the previous one, a counter goes up; above 3 the authenticator is marked unavailable. This guard came in with `cc1ee1ad` ("pamauthenticator: detect slow broken services more reliably", 2026-08-18, in v6.8.0). Its comment names pam-u2f without a token as the motivating case.
- `greeter/pamauthenticator.cpp:94-97`: an unavailable authenticator never tries again. For the active authenticator, `greeter/pamauthenticators.cpp:205-213` also marks its model entry defunct (ignored for Regular, as above), and `startAuthenticating` skips non-functional ones (`:90-93`). The `PamAuthenticator` object for Regular stays unavailable until the active authenticator is switched and rebuilt (`:123-131`, inferred: nothing else resets `m_unavailable`).
- A missing service file: libpam falls back to `other` (see the Linux-PAM section below), Fedora's `other` is `auth required pam_deny.so`, `pam_deny` returns `PAM_AUTH_ERR`, so the worker reports `Failure`, not `Unavailable` (verified chain). Whether the greeter then gives up on it depends on the 2-second guard (inferred: `pam_deny` sets no fail delay, so retries would be fast and the guard would trip after a few rounds).

## Linux-PAM semantics that decide Options B and C

### How a service file is found, and the vendor directory

Verified in `libpam/pam_handlers.c` and `libpam/pam_private.h`:

- `pam_private.h:29-36`: `PAM_CONFIG_DF` is `/etc/pam.d/%s`, `PAM_CONFIG_DIST_DF` is `/usr/lib/pam.d/%s`, and only if `VENDORDIR` is defined, `PAM_CONFIG_DIST2_DF` is `VENDORDIR"/pam.d/%s"`.
- `_pam_open_config_file`, `pam_handlers.c:292-352`: a name starting with `/` is opened as an absolute path (`:307-313`); if the application set a `confdir` (`pam_start_confdir`), only `confdir/name` is tried and nothing else (`:314-331`); otherwise the directories are tried in order `/etc/pam.d`, `/usr/lib/pam.d`, vendordir, and the first file that opens wins (`:333-349`). There is no merging: `/etc/pam.d/kde` shadows `/usr/lib/pam.d/kde` completely.
- The same function opens include and substack targets (`_pam_load_conf_file`, `:382`), so an `include` argument is looked up exactly like a service: `/etc/pam.d` first, then `/usr/lib/pam.d`, or as an absolute path.
- `/usr/lib/pam.d` and absolute paths both arrived in one commit, `10b83ef2` (2015-03-25, "Support alternative 'vendor configuration' files as fallback to /etc", patch from Kay Sievers), first released in Linux-PAM 1.2.0. `/usr/lib/pam.d` is documented (`doc/man/pam.conf.5.xml:47-55`, "Files in /etc/pam.d override files with the same name in this directory"); the absolute-path form is not documented anywhere in `doc/` (verified by grep), so relying on it means relying on undocumented behaviour.
- Service not found at all: `pam_handlers.c:478-512` reads the service file if it opens, and then always reads `other` (`:514-546`); `other`'s lines go into a separate handler list that `_pam_dispatch` uses only when the service has no lines of the requested type (`pam_dispatch.c:383-401`). So a service file with only `auth` lines falls to `other` for `account`, `password` and `session`.

The vendordir on Fedora (verified on the host):

- Upstream's meson option `vendordir` defaults to `/usr/share/pam` (`meson_options.txt:90`, commit `aea30822`, 2025-08-26; `NEWS` for 1.7.2: "build: enabled vendordir by default."), and `meson.build:126-138` defines `VENDORDIR` only when it is non-empty.
- Fedora's `/usr/lib64/libpam.so.0` (pam-1.7.2-2.fc44) contains the strings `/etc/pam.d/%s`, `/usr/lib/pam.d/%s`, `/etc/pam.d` and `/usr/lib/pam.d`, and no `/usr/share/pam...` string. So Fedora builds with the vendordir disabled. (The `pam` package does own an empty `/usr/share/pam.d` directory, which libpam does not read.) Fedora's `pam.spec` is not among the clones, so the exact flag is inferred from the binary.
- `/usr/lib/pam.d` is real and used on this machine: it is owned by `systemd` and holds `plasmalogin`, `plasmalogin-autologin`, `plasmalogin-greeter` (from `plasma-login-manager`), `polkit-1`, `systemd-run0`, `systemd-user`. So the `/usr/lib/pam.d` fallback is a well-trodden path on Fedora 44.
- On Aurora `/usr` is the read-only ostree image. A file can only get into `/usr/lib/pam.d` by layering an RPM (`rpm-ostree install`) or a systemd-sysext overlay. properpin's install path is `/usr/local` (`/var/usrlocal` on ostree systems), so a vendor file is not available to it today (inferred from the image layout; not tried).

### include versus substack, precisely

Parsing, verified in `pam_handlers.c`:

- `include` and `substack` are spellings of the control field itself (`:185-192`), which is why a substack cannot take a `[...]` control clause, as `packaging/kde-auth.pam` already notes.
- For `substack`, an extra handler of type `PAM_HT_SUBSTACK` is added at the current level (`:202-211`), and the target file is parsed with `stack_level + substack`, that is one level deeper (`:212-213`). For `include`, `substack` is 0, so the included lines are parsed at the same `stack_level` as the including file; only `include_level` (a recursion limit of 16, `pam_private.h:208`, checked at `pam_handlers.c:370-374`) goes up.
- Lines in the included file are added in place, in order, to the same handler list (`_pam_add_handler`, `:811-814`, appends). So `auth include X` placed above `auth substack password-auth` yields exactly the same handler list as pasting X's `auth` lines there. Lines of other types in X are skipped (`:141-146`).

Dispatch, verified in `pam_dispatch.c:34-318`:

- There is one `impression` and one `status` for the whole walk, shared by all levels (`:37`, `:72-73`). On entering a deeper level, the current values are saved only so that `reset` can restore them (`:89-93`, `:202-206`).
- The `PAM_HT_SUBSTACK` marker handler is skipped (`:99-101`); its (empty) control is never evaluated. The substack's result is simply whatever its modules did to the shared `impression`/`status`.
- `done` (`:208-229`) and `die` (`:231-251`) jump to `decision_made`, which skips the following handlers whose `stack_level >= stack_level` of the current handler (`:302-306`), and then the loop continues with the next handler at a lower level. At level 0 that is the end of the stack. Inside a substack it is the end of the substack only; the parent carries on.
- `bad`/`die` set the impression negative and record the status only if it was not already negative (`:240-247`), and nothing later can turn a negative impression positive (`ok`/`done` only act when the impression is undefined or positive with success, `:211-219`). So once anything says `bad`, the stack fails, however many modules succeed afterwards.

What this means for properpin's three lines (inferred from the code above, with the module behaviour taken from `packaging/kde-auth.pam` and `crates/pam/src/pam.rs:163`, which reads the typed text with `pam_get_authtok` and so leaves it in `PAM_AUTHTOK`):

- **Inside `include`: identical to today.** Correct PIN: line 1 `success=done` at level 0 ends the whole stack with success; `password-auth` and `postlogin` never run. Wrong password: line 2 `default=die` at level 0 ends the whole stack with failure. Correct password: line 2 `ok`, line 3 runs, then the stock `substack password-auth` re-checks the same `PAM_AUTHTOK` without prompting (`pam_unix_auth.c:152` calls `pam_get_authtok`, which returns an existing token, `libpam/pam_get_authtok.c`, the `prevauthtok != NULL` branch).
- **Inside `substack`: broken.** Correct PIN: line 1 sets the impression positive and `done` ends only the properpin substack. The parent continues with `auth substack password-auth`: `pam_env`, `pam_faildelay delay=2000000`, `pam_unix nullok` (sufficient) checks the PIN as if it were the password and fails, then `auth required pam_deny.so` returns failure with action `bad`, which flips the impression negative. The PIN never unlocks, and every PIN attempt costs the password failure delay. Wrong password: `die` ends only the substack (already negative), then `password-auth` checks the same wrong text again; the result is still failure, but with a second `pam_unix` run. The only way to use a substack would be to put the whole auth chain, including `auth substack password-auth`, inside properpin's file and replace kde's `auth substack password-auth` line with `auth substack <properpin file>`; that is a replacement edit rather than an insertion, with no advantage over `include`.

### What happens when a referenced file or module is missing

Verified in `pam_handlers.c` and `pam_dispatch.c`:

- **A missing module** (today's failure mode if `/usr/local/lib64/security/pam_properpin.so` disappears): `_pam_load_module` logs "unable to dlopen" and adds a "faulty module" (`:664-685`); `_pam_add_handler` then finds no function (`:798-801`), and at dispatch a handler with no function returns `PAM_MODULE_UNKNOWN` (`pam_dispatch.c:102-104`). Line 1 (`default=ignore`) ignores it; line 3 (`optional`) ignores it. The stack behaves as stock: the lock screen takes the password only. The final return code comes from `pam_unix`/`password-auth`, so kscreenlocker never sees `PAM_MODULE_UNKNOWN` as the result and does not mark the service unavailable (inferred from the dispatch rules: an ignored code never becomes `status`).
- **A missing include or substack file** (Option B's failure mode): `_pam_load_conf_file` fails, and the parser installs a `PAM_HT_MUST_FAIL` handler with every action set to `bad` (`:212-222`). At dispatch it returns `PAM_PERM_DENIED` (`pam_dispatch.c:17`, `:96-98`) with action `bad`, so the impression is negative from that point and no later success can fix it. Every unlock attempt at the lock screen fails, the password included. The `-` prefix (`-auth`) does not help: it only sets `PAM_HT_SILENT_MODULE` (`:118-120`), which the missing-include branch overwrites with `PAM_HT_MUST_FAIL` (`:221`).
- **A missing `/etc/pam.d/kde`**: the `other` service, `pam_deny`, every unlock fails. `packaging/install.sh` already says this in its header comment ("Deleting /etc/pam.d/kde would hand the lock screen to the 'other' service, which denies everyone").

Recovery from a lock-screen lockout is the same in all cases (inferred, standard Plasma behaviour): another VT or SSH, then `loginctl unlock-session`, or fixing the file. Login, sudo, polkit and SSH are unaffected because they use other services.

## Option A: a separate service, or borrowing a slot

### A service named properpin

Not possible without rebuilding kscreenlocker (verified above): the greeter only ever passes the five compile-time names to the worker, and nothing at runtime chooses another. A rebuild with `-DKSCREENLOCKER_PAM_PASSWORD_SERVICE=properpin` (6.8) or `-DKSCREENLOCKER_PAM_SERVICE=properpin` (6.7.5) would do it, but on Aurora that means replacing a package in the image, it must be redone for every Plasma update, and it is far more invasive than editing one config file. Not worth pursuing.

Dropping `/etc/pam.d/properpin` next to `kde` and doing nothing else has no effect at all: nothing opens it.

### Borrowing an existing slot

The candidates, all verified against the descriptors in `greeter/pamauthenticatormodel.cpp:45-84` and the host's files:

| Slot | Service file on Fedora | 6.7.5 behaviour | 6.8 behaviour | Verdict |
|---|---|---|---|---|
| Fingerprint | `/etc/pam.d/kde-fingerprint`, `plasma-workspace` config file | Non-interactive, runs in parallel, never gets typed text | Implicit fingerprint authenticator, always running unless Fingerprint is the active type; no password field | Unusable: no typed text reaches it, and it would take fingerprint unlock away from users who have a reader |
| Smartcard | `/etc/pam.d/kde-smartcard`, `plasma-workspace` config file | Non-interactive, never gets typed text | Selectable active type with a password field (`passwordField` true, `expectingPrompt` true), off unless `[Authenticators] Smartcard=true` | Works on 6.8 only, as a hack: see below |
| Face | none shipped (falls to `other`) | does not exist | Selectable, no password field, off unless `[Authenticators] Face=true` | No password field, so no way to type a PIN (inferred from the descriptor's documented meaning) |
| Universal2Factor | none shipped (falls to `other`) | does not exist | Selectable, no password field, off unless `[Authenticators] Universal2Factor=true` | Same as Face |

The Smartcard slot is the only one where the idea even runs, and only on 6.8. What it would look like (inferred): properpin rewrites `/etc/pam.d/kde-smartcard` to hold the PIN lines followed by the normal password chain, sets `[Authenticators] Smartcard=true` in `/etc/xdg/kscreenlockerrc` or the user's file, and the user selects "Smartcard" once; after the first successful unlock the state file remembers it (`greeter/pamauthenticators.cpp:65-72`, `201`). The stock `kde` stays pristine and remains selectable as "Password", which is genuinely attractive as a fallback.

Why it is still a bad idea:

- It does not avoid editing a distro config file: `/etc/pam.d/kde-smartcard` is a `cn` file of `plasma-workspace`, exactly like `kde`. The update, `.rpmnew` and ostree-merge story is the same as Options B and C.
- It does not work on 6.7.5, which is what the host runs today (non-interactive slot, typed text never sent, `v6.7.5:greeter/pamauthenticators.cpp:203-207`).
- The UI calls it "Smartcard" with the `secure-card-symbolic` icon and that tooltip (`greeter/pamauthenticatormodel.cpp:55-61`), and it takes the slot away from anyone with a real smartcard.
- It depends on per-user or `/etc/xdg` KConfig state and on a 6.8 UI flow that is brand new (`a5ed9ca0`, July 2026) and visibly still moving (the descriptor gained `showPrompt` in `f1a30c53`, 2026-08-27). A slot's meaning could change in any release.
- Using `kde-face` or `kde-u2f`, which Fedora does not ship, would avoid editing a distro file, but those slots have no password field, and a future Fedora could start shipping them.

## Option B: one include line in kde, properpin's lines in a file properpin owns

What changes in `/etc/pam.d/kde`: one marker comment and one `auth include` line, above `auth substack password-auth`. properpin's three lines move into a file of its own; the module path, arguments and control flags then live only there, so a properpin upgrade that changes them touches only properpin's file and never `kde` again.

Where the included file can live:

- **`/etc/pam.d/<name>` (recommended).** Found first by the normal lookup, survives ostree updates as a locally added `/etc` file (inferred, standard ostree `/etc` merge), labelled `etc_t` by `restorecon` like every PAM file (inferred). The one wrinkle: any file in `/etc/pam.d` is also a service name, so `pam_start("<name>", ...)` from any program would run it. The file has only `auth` lines, so `account`, `password` and `session` fall to `other` and are denied (verified dispatch rule above); and the module already refuses unless the PAM user is the calling process's own user and refuses root (per `docs/chaos/kscreenlocker-pam-contract.md`), so a privileged program authenticating someone else gets nothing from it. Adding an explicit `PAM_SERVICE == "kde"` check to the module closes the rest cheaply, and also protects against someone copying the lines into another service by hand.
- **An absolute path, say `/etc/properpin/kde-auth.pam`.** Avoids the extra service name, works since Linux-PAM 1.2.0 (`pam_handlers.c:307-313`), but is undocumented. When the test harness uses `pam_start_confdir`, absolute includes are still honoured (the absolute check comes first, `:308`), but they escape the sandbox confdir, which makes `crates/pam/tests/stack.rs` less hermetic (inferred). Second choice.
- **`/usr/lib/pam.d/<name>`.** The systemd-style place for a vendor file, overridable by an `/etc/pam.d` file of the same name. Not writable on Aurora without layering or a sysext; and if a sysext is unmerged, the include target vanishes, which is the lockout case. Worth revisiting only if properpin ever ships as an RPM.

Robustness (inferred from the semantics above and the host's package metadata):

- **Package updates.** `kde` is still modified, so `plasma-workspace` updates behave as today: `rpm` keeps the modified file and writes `kde.rpmnew` when the packaged one changes; ostree's three-way `/etc` merge keeps the local file and silently stops following `/usr/etc/pam.d/kde`. The difference is that the local delta is one recognisable line, so re-applying it to a new stock file is trivial and could be automated by `install.sh check`.
- **authselect.** authselect only manages `system-auth`, `password-auth`, `fingerprint-auth`, `smartcard-auth`, `switchable-auth` and `postlogin` (`authselect/src/lib/paths.h:59-64`), and never touches `kde` or a properpin file. But both B and C hard-code `pam_unix.so use_first_pass` with `default=die` as the password check; a machine switched to an sssd or LDAP profile would make that line fail for network accounts and lock them out of the lock screen. That is a design limit of the three lines, not of where they live.
- **Uninstall.** Strictly ordered: take the include line out of `kde` first, then delete the included file, then the module. Install is the reverse: module and pinchecker, then the included file (written to a temporary name and renamed, then relabelled), then the line in `kde`.
- **Lockout.** The new risk is the missing-include rule: if the included file is deleted, renamed, unreadable or has a syntax error that makes `_pam_parse_conf_file` fail, the lock screen refuses everything. Under C the corresponding accidents (module deleted) degrade to password-only. A malformed line inside a file, under either option, becomes a must-fail handler (`pam_handlers.c:108-137`, `156-162`), so syntax errors are equally dangerous in both.

## Option C: the current marked block

What it is today (verified in `packaging/install.sh` and `packaging/kde-auth.pam`): three lines between a begin marker (`# properpin: added by install.sh install; ...`) and `# properpin end`, inserted above the single `auth substack password-auth` line after a diff and a yes, with the stock file saved as `kde.pam.without-properpin`, and `check` and `uninstall` that recognise the block, a damaged block, and fall back to the saved copy.

Strengths: no extra file to lose; a missing module degrades to the password; the installer's handling of damaged blocks and its backup are already written and tested. Weaknesses: the diff in a distro-owned file is five lines including long module arguments, every properpin release that changes a flag or argument re-edits `kde` (and re-prompts), and comparing the user's `kde` with a new stock one is noisier.

## Comparison

| | A: own service or borrowed slot | B: one include line | C: marked block (today) |
|---|---|---|---|
| Edits a distro-owned file | Yes (rebuild, or `kde-smartcard`) | Yes, one line plus a comment | Yes, three lines plus two markers |
| Works on 6.7.5 | No | Yes | Yes |
| Works on 6.8 | Smartcard slot only, opt-in, mislabelled | Yes | Yes |
| properpin upgrades touch `kde` | n/a | No, only properpin's file | Yes, whenever the lines change |
| Module `.so` missing | n/a | Password only | Password only |
| properpin's PAM file missing | n/a | Lock screen refuses everything | Not applicable (no such file) |
| `kde` replaced by a package update or by hand | n/a | properpin silently gone (password only) | properpin silently gone (password only) |
| authselect | Untouched | Untouched (but `pam_unix` hard-coded) | Untouched (but `pam_unix` hard-coded) |
| Uninstall | n/a | Remove one line, then the file | Remove the block between markers |
| Test harness | n/a | `stack.rs` can build `kde` with the include line plus the shipped file in its confdir, testing `include` for real | As today |

## Recommendation

Use Option B with `include`, placing the included file in `/etc/pam.d`, and harden the two places where it is weaker than C. In detail:

- `/etc/pam.d/kde` gains exactly two lines above the stock first line. The marker comment is kept so that `check` and `uninstall` can recognise a hand-damaged state, as they do today:

```
# properpin: added by install.sh install; install.sh uninstall removes this line and the next
auth        include       properpin-kde-auth
auth        substack      password-auth
auth        include       postlogin
...
```

- `/etc/pam.d/properpin-kde-auth`, root-owned, mode 0644, relabelled after writing, written by `install.sh install` through a temporary file and a rename (`packaging/kde-auth.pam` becomes this file, comments and all, since PAM ignores `#` lines):

```
#%PAM-1.0
# properpin: the lock-screen PIN. Included by /etc/pam.d/kde ("auth include properpin-kde-auth"); not a service of its own.
# Only auth lines: account, password and session fall to "other", which denies. The module also refuses any service but kde.
# Deleting this file while /etc/pam.d/kde still includes it makes the lock screen refuse every password: run install.sh uninstall instead.
auth  [success=done default=ignore]  /usr/local/lib64/security/pam_properpin.so check pinchecker=/usr/local/libexec/properpin/properpin-pinchecker config=/etc/properpin/config
auth  [success=ok default=die]       pam_unix.so use_first_pass
auth  optional                       /usr/local/lib64/security/pam_properpin.so housekeeping pinchecker=/usr/local/libexec/properpin/properpin-pinchecker
```

- In the module: return `PAM_IGNORE` unless `PAM_SERVICE` is `kde` (or a `service=` argument naming it, if the tests need another name). This makes the extra service name harmless and enforces "lock screen only" in code instead of only in where the lines are placed.
- In `install.sh`: install writes the module and pinchecker, then `properpin-kde-auth`, verifies it parses as intended (a `pamtester`-style check through the real file is ideal; at minimum compare with the shipped file), and only then shows the one-line diff of `kde` and asks. Uninstall removes the two lines from `kde` first and deletes `properpin-kde-auth` only after that write succeeded. `check` reports both "kde includes properpin-kde-auth but the file is missing" (urgent: lock screen dead) and "file present but not included" (harmless leftover). An upgrade from today's block takes the block out and puts the include line in, in one write of `kde`, after the new file is in place.
- In `crates/pam/tests/stack.rs`: build `pam.d/kde` from the stock text with the include line and copy the shipped `properpin-kde-auth` into the same confdir; libpam resolves the include inside the confdir (`pam_handlers.c:314-319`), so the test then exercises `include` semantics for real. Add a test that deleting the included file makes every attempt fail, so the documented lockout is pinned down rather than assumed.

If the "a missing properpin file locks the lock screen" property is judged unacceptable, the alternative is to stay with Option C and accept the bigger diff; nothing in kscreenlocker or libpam offers a fail-open include. Do not use `substack` in either case, and do not pursue a separate service or a borrowed slot.

## Bonus: rate limiting and PIN-related bits in kscreenlocker

- **The 50 ms time check is gone in 6.8.0 (verified).** Commit `5d848610` ("worker: drop time check", Harald Sitter, 2026-09-28, BUG 526194) removed the `KSCREENLOCKER_PAM_TIME_CHECK` check that returned `Unavailable` for any `pam_authenticate` faster than 50 ms. The message: "this is causing a bit too many problems at this time. notably no password scenarios on the regular authenticator will run into this wall unexpectedly. let's remove it for now to avoid problems in 6.8 and revisit its need once we have a good face authenticator to focus on". It was cherry-picked to `Plasma/6.8` as `7ca40864`, which is an ancestor of `v6.8.0`; `v6.8.0:greeter/worker/main.cpp` has no `TIME_CHECK` and no `50ms` (only the fingerprint `250ms` rule at `:325`). `docs/chaos/kscreenlocker-pam-contract.md` describes the check as present in 6.8; that is now out of date. properpin's `min_milliseconds_before_pin_unlock` padding does no harm and is worth keeping in case the check returns, as the commit message suggests it might.
- **A new repeated-failure guard (verified, `cc1ee1ad`, in 6.8.0).** `greeter/pamauthenticator.cpp:113-131`: a `Failure` less than 2 s after the previous one increments a counter, otherwise resets it; above 3 the authenticator becomes unavailable and never tries again (`:94-97`). It does not exempt Regular. A wrong PIN costs `pam_unix`'s own 2 s fail delay (`modules/pam_unix/support.c:721`), applied inside the worker through the `PAM_FAIL_DELAY` callback before the reply (`greeter/worker/main.cpp:166-178`, `:344-350`), and libpam randomises that delay around the requested value (`libpam/pam_delay.c:51-56`, `:105-111`). So replies to fast consecutive wrong guesses can arrive under 2 s apart, and four such quick gaps in a row (five failures) would leave the password field dead until the authenticator is rebuilt (inferred; not reproduced). This is the same for the stock password and is upstream's behaviour, but properpin should make sure none of its paths returns failure without a delay (for example a paused PIN or a broken pinchecker must still go through `pam_unix` and its delay), and the real-lock-screen test plan could include "five fast wrong PINs".
- **No PIN feature of its own (verified by grep).** The only "PIN" in kscreenlocker is commit `1d74690e` ("Fix smartcard/PIN authentication UX issues", 2026-03-21, in v6.6.90), which makes the fallback theme show the PAM prompt text (for example "PIN for alun:") as the password field's placeholder (`greeter/fallbacktheme/Greeter.qml:83`). For the Plasma theme, the 6.8 `[UI] ShowPromptInRegularAuthenticator` key decides whether the password authenticator's prompt text is shown (`greeter/pamauthenticatormodel.cpp:52-54`), so a properpin prompt such as "PIN or password:" would be invisible by default. properpin currently passes a null prompt to `pam_get_authtok` (`crates/pam/src/pam.rs:163`), which gives libpam's default.
- **Other limits, unchanged:** the failure delay blocks the UI (`greeter/pamauthenticator.cpp:237-244`), `graceLocked` suppresses attempts during the grace period (`greeter/pamauthenticators.cpp:84-88`), and the worker is non-dumpable unless debug logging is on (`greeter/worker/main.cpp:362-365`). kscreenlocker itself counts no attempts and imposes no lockout; that is left entirely to PAM (`pam_faillock` is not in Fedora's default `password-auth`, as the host file shows).

## Redoing this

- `git -C kscreenlocker grep -n 'KSCREENLOCKER_PAM_' <tag> -- greeter CMakeLists.txt` shows every service-name knob and its users; compare `greeter/worker/CMakeLists.txt` and `greeter/pamauthenticators.cpp` between tags.
- `git -C kscreenlocker log --oneline <old>..<new> -- greeter/worker greeter/pamauthenticator*.cpp greeter/pamauthenticatormodel.cpp` lists what changed in the authenticator logic; read the messages, they are informative.
- In Linux-PAM, `_pam_parse_conf_file` and `_pam_open_config_file` in `libpam/pam_handlers.c` and `_pam_dispatch_aux` in `libpam/pam_dispatch.c` hold everything about lookup, include versus substack and missing files, in about 600 lines.
- On a Fedora machine, `strings /usr/lib64/libpam.so.0 | grep pam.d` shows which directories that build searches, and `rpm -qf` plus `rpm -q --qf '[%{FILEFLAGS:fflags} %{FILENAMES}\n]' plasma-workspace | grep pam` shows who owns the PAM files and whether they are `noreplace`.
