# How GDM and fprintd add an alternative unlock method

A read-only study, written on 2026-10-17, of how the two biggest GNOME/freedesktop "add another way to unlock" stacks plug into PAM: GDM (with GNOME Shell's login and unlock dialogs, which both go through GDM) and fprintd with its `pam_fprintd` module. The aim is to compare their integration with properpin's, which today inserts three marked lines from `packaging/kde-auth.pam` above `auth substack password-auth` in `/etc/pam.d/kde`, after a diff and a yes, through `packaging/install.sh`.

## Sources and how to read the citations

- GDM: the reference clone at `/var/home/shared/projects/pam-related/gdm`, at `51.0-15-gc18aa51af` (last commit 2026-10-17). Paths below are relative to that clone unless they start with another name.
- fprintd: the reference clone at `/var/home/shared/projects/pam-related/fprintd`, at `v1.94.5-94-g5731b9a`.
- authselect and kscreenlocker: the reference clones next to them, used only where they explain how GDM's or fprintd's files are wired on Fedora.
- GNOME Shell is not among the reference clones. Its `js/gdm/*.js` and `js/ui/unlockDialog.js` were downloaded from `gitlab.gnome.org/GNOME/gnome-shell` branch `main` (head `0dea3091`, 2026-10-17) into the session scratchpad for reading only; citations to them are `gnome-shell:js/gdm/<file>:<line>` and refer to that snapshot.
- Debian packaging (`gdm3` 51.0-2, `fprintd` 1.94.5-4) was read through sources.debian.org; it is not in the reference clones. Citations are `debian:<package>/debian/<file>`.
- The running machine (Aurora 44.20261013.1, Kinoite based) was inspected read-only: `/etc/pam.d`, `authselect current`, `rpm -q --scripts`.
- "Verified" means read in code, a commit message, or on this machine. "Inferred" means my reading of the design, not stated anywhere.

## The short answer

Nobody in this part of the ecosystem edits another package's PAM file. GDM ships one PAM service per authentication method (`gdm-password`, `gdm-fingerprint`, `gdm-smartcard`, `gdm-switchable-auth`, plus the daemon-only `gdm-autologin` and `gdm-launch-environment`), runs each in its own worker process as a separate "conversation", and lets the greeter pick which ones to start. fprintd ships only `pam_fprintd.so` and a man page; its README tells the admin to edit PAM by hand, and the actual wiring is done by distro mechanisms (authselect's `with-fingerprint` feature on Fedora, a `pam-auth-update` profile on Debian). KDE's Plasma 6.8 authenticators (`kde-fingerprint`, `kde-smartcard`, …) are a direct copy of the GDM pattern.

The separate-service pattern exists because a PAM stack is serial: fprintd's own docs say a module cannot accept "either the password or a fingerprint" and that the fix is for "the login managers [to] run 2 separate PAM stacks". It works smoothly only for non-interactive methods. Both GNOME Shell and kscreenlocker let exactly one *interactive* method own the text field at a time; fingerprint is the only one allowed to run in the background. A typed PIN as its own service would therefore be a "switch to PIN" mode, not the single field properpin has now. GDM tried exactly that in 2013 (`gdm-pin`), never wired it into the shell, and deleted it in 2021.

None of these stacks has a persistent failure budget. pam_fprintd counts tries only within one call; GNOME Shell's `allowed-failures` does not apply at the lock screen at all. properpin's rules are stricter than anything here.

## GDM

### Which PAM services exist and where they are defined

Verified. GDM's build installs a per-distro set of service files chosen by `default-pam-config` (`meson_options.txt:4`: `autodetect, redhat, openembedded, exherbo, lfs, arch, none`), autodetected from release files (`meson.build:148-170`: `/etc/redhat-release` and `/etc/fedora-release` map to `redhat`, plus exherbo, arch, lfs). The map of which files each distro gets is `data/meson.build:58-93`:

| distro set | services shipped |
|---|---|
| redhat | gdm-autologin, gdm-launch-environment, gdm-fingerprint, gdm-smartcard, gdm-password, gdm-switchable-auth, plus generated `gdm-password-auth-substack`, `gdm-smartcard-auth-substack`, `gdm-fingerprint-auth-substack`, `gdm-switchable-auth-substack` |
| exherbo, lfs, arch | gdm-autologin, gdm-launch-environment, gdm-fingerprint, gdm-smartcard, gdm-password |
| openembedded | gdm-autologin, gdm-launch-environment, gdm-password |
| none | nothing (the distro ships its own, as Debian does) |

The files live in `data/pam-redhat/`, `data/pam-arch/`, `data/pam-exherbo/`, `data/pam-lfs/`, `data/pam-openembedded/`. They are installed into `pam_sys_services_dir`, which defaults to `<prefix>/lib/pam.d`, i.e. `/usr/lib/pam.d` (`meson.build:37`, `data/meson.build:95-101`), not `/etc/pam.d`; see the history below for why.

The Fedora/RHEL flavour delegates every credential check to the authselect-managed stacks through a generated wrapper:

- `data/pam-redhat/gdm-password.pam:1-2`: `pam_selinux_permit.so`, then `auth substack gdm-password-auth-substack`.
- `data/pam-redhat/gdm-fingerprint.pam:1`: `auth substack gdm-fingerprint-auth-substack`; `gdm-smartcard.pam:1` and `gdm-switchable-auth.pam:1` likewise.
- `data/pam-redhat/gdm-service-auth-substack.pam.in:1-5`: `auth include @PAM_SERVICE@` then `auth required pam_deny.so` (same for `password`), generated for `password-auth`, `smartcard-auth`, `fingerprint-auth`, `switchable-auth` (`data/meson.build:103-121`).

The Arch flavour calls the modules directly instead: `data/pam-arch/gdm-fingerprint.pam:3-9` (`pam_shells`, `pam_nologin`, `pam_faillock preauth`, `auth required pam_fprintd.so`, …) and `data/pam-arch/gdm-smartcard.pam:3-9` (`pam_pkcs11.so wait_for_card card_only`). `gdm-password.pam:3` includes `system-local-login`.

Debian (`gdm3`) builds without GDM's files and ships its own in `/etc/pam.d` (`debian:gdm3/debian/gdm3.gdm-password.pam`, `gdm3.gdm-fingerprint.pam`, `gdm3.gdm-autologin.pam`, `gdm3.gdm-launch-environment.pam`, and three smartcard variants). Its `gdm-fingerprint` calls `auth required pam_fprintd.so` directly, and `gdm-password` does `@include common-auth`. The three smartcard variants (`gdm-smartcard-sssd-exclusive`, `-sssd-or-password`, `-pkcs11-exclusive`) are selected with `update-alternatives` onto the single name `/etc/pam.d/gdm-smartcard` (`debian:gdm3/debian/gdm3.alternatives`, priorities 40/50/30). That is a neat precedent: one service name, several shipped variants, the distro's own switch picks one.

### How GDM finds a service, and refuses missing ones

Verified. Since July 2026 the session worker resolves the service file itself before calling `pam_start`: `/etc/pam.d/<service>` first, then `/usr/lib/pam.d/<service>` (`daemon/gdm-session-worker.c:1206-1221`). If neither exists it fails with `GDM_SESSION_WORKER_ERROR_SERVICE_UNAVAILABLE` and does not start PAM at all (`daemon/gdm-session-worker.c:1247-1262`). The point, per commit `e760c8e49` ("session-worker: Explicitly check and load gdm services"), is that "we are opening the service file we expect". Without it Linux-PAM would silently fall back to the `other` service, which is the same hazard properpin's installer guards against when it refuses to ever delete `/etc/pam.d/kde` (`packaging/install.sh`, header comment).

An existing file whose module is missing is also treated as "unavailable" rather than as a failed login: `PAM_MODULE_UNKNOWN` maps to `SERVICE_UNAVAILABLE` (`daemon/gdm-session-worker.c:1402-1410`, commit `0af973d39`, whose message names Debian, where "pam services may be sticking to a location so even though if a module it uses may have been removed"). `PAM_AUTHINFO_UNAVAIL` from `pam_authenticate` also means unavailable (`daemon/gdm-session-worker.c:1393-1400`), and `PAM_MAXTRIES` becomes `TOO_MANY_RETRIES` (`daemon/gdm-session-worker.c:1412-1418`). Both are reported to the greeter as `ServiceUnavailable` and the conversation is stopped (`daemon/gdm-session.c:213-238`); commit `504fec05f` says this is so a module that hit max tries "isn't marked as available again for the current session", with pam_fprintd as the example. Since commit `f04dc0418` (2025) an unavailable service is not counted as a failed login either (`daemon/gdm-session.c:255-278`).

Since 2026-10-07 (commit `3aad05f7b`) the greeter can only ask for services whose names start with `gdm-`, contain no `/`, and are not `gdm-autologin` or `gdm-launch-environment` (`daemon/gdm-session.c:1447-1470`). The commit explains the threat: "The session worker runs PAM as root, so a compromised greeter can pick a service whose auth stack passes without a password", such as `su`'s `pam_rootok`. Note the "runs PAM as root" part: unlike kscreenlocker, whose PAM runs as the user (which is why properpin needs a setgid pinchecker), GDM's worker is root, so a GNOME PIN module would not need a setgid helper to reach a protected hash.

### Conversations: how several services run in parallel

Verified, from the history. The design was laid down by Ray Strode in January 2009:

- `55a9a4130` "daemon: Make current pam conversation explicit throughout code": "We want to eventually support having multiple simultaneous PAM conversations in one login screen (so, e.g., username/password, smart card, and fingerprint all work at the same time)… The conversation is named by the pam service the login screen is talking to."
- `a4f5409c7` "daemon: Store multiple conversations in the session": conversations kept "keyed off of which PAM service is at the other end".
- `c48494034`: the greeter now says which PAM stack it wants; "When we support multiple PAM stacks, the greeter will call StartConversation for each stack, and will keep the UI associated with each stack disabled until the Ready signals come back one-by-one."
- `123ea3394` (2009-02-06) "greeter: Add fingerprint plugin" and `d96dbdfa9` the smartcard plugin, each shipping its own `.pam` file; `0e0aca600` (2011) moved them to `data/` because the new GNOME Shell greeter used them too.

Each conversation is a separate `gdm-session-worker [pam/<service>]` process (`daemon/gdm-session.c:2438`) with its own `pam_start`. Every D-Bus signal on the `UserVerifier` interface carries the service name (`daemon/gdm-session.xml:57-95`: `ConversationStarted`, `InfoQuery`, `SecretInfoQuery`, `ServiceUnavailable`, `VerificationFailed`, `VerificationComplete`…), so the daemon itself puts no limit on how many conversations, interactive or not, run at once. The limit is in the shell.

The lock screen uses the same machinery: `gnome-shell:js/ui/unlockDialog.js:877-878` builds an `AuthPrompt` in `UNLOCK_ONLY` mode, which sets `reauthenticationOnly` (`gnome-shell:js/gdm/authPrompt.js:176-182`), and the verifier opens a reauthentication channel to GDM for the user (`gnome-shell:js/gdm/userVerifier.js:320-340`; daemon side `daemon/gdm-manager.c:862-1030`). So GNOME's unlock is GDM's `gdm-password` / `gdm-fingerprint` / … services, run as root by GDM, not a PAM service of gnome-shell's own.

### How GNOME Shell decides what runs and who may ask questions

Verified in the gnome-shell snapshot.

- The legacy backend hard-codes three services: `gnome-shell:js/gdm/authServicesLegacy.js:17-19` (`gdm-password`, `gdm-smartcard`, `gdm-fingerprint`), each tied to a dconf key (`:21-40`). The SSSD backend uses only `gdm-switchable-auth` for password, smartcard, passkey and web login (`gnome-shell:js/gdm/authServicesSSSDSwitchable.js:11,42-45`). There is no way to add a service name by configuration; a `gdm-pin` would need a shell change.
- Only the selected mechanism can ask a question: `_handleOnInfoQuery` and `_handleOnSecretInfoQuery` return early unless `serviceName === this._selectedMechanism?.serviceName` (`gnome-shell:js/gdm/authServicesLegacy.js:244-269`), and answers go only to the selected one (`:80-89`).
- Only the selected mechanism, or fingerprint, is ever started: `_handleCanStartService` (`gnome-shell:js/gdm/authServicesLegacy.js:369-377`). Fingerprint is started only when a reader is found (`:161-175`), and its fingerprint manager is connected only in reauth mode (`:416-418`).
- Fingerprint's info messages are not shown; they are turned into the hint "(or place finger on reader)" under the password field (`gnome-shell:js/gdm/authServicesLegacy.js:177-201`). The comment says so: "We don't show fingerprint messages directly since it's not the main auth service."
- Failure counting: `allowed-failures` (default 3, `data/org.gnome.login-screen.gschema.xml:114-123`) feeds `_canRetry`, which is `this._userName && (this._reauthOnly || this._failCounter < this._allowedFailures)` (`gnome-shell:js/gdm/authServices.js:399-402`). At the lock screen (`_reauthOnly`) retries are therefore unlimited. For fingerprint the shell counts `Problem` messages itself, because "pam_fprintd allows the user to retry multiple (maybe even infinite!) times before failing the authentication conversation. We don't want this behavior to bypass the max-tries setting" (`gnome-shell:js/gdm/authServicesLegacy.js:215-241`).
- A service that reported `ServiceUnavailable` at start is remembered in `_unavailableServices` and not restarted (`gnome-shell:js/gdm/authServices.js:443-475`).

So the answer to "does GDM allow multiple interactive conversations?" is: the daemon does, the only shipping greeter does not. GNOME Shell runs one interactive conversation (the selected mechanism) plus at most one non-interactive background one (fingerprint), and the user switches interactive mechanisms through a menu (`authMenuButton.js`, `authList.js` in the same directory; not read in detail).

### How a service is enabled or disabled

Verified. Four layers, all of which must agree:

- **dconf keys** in `org.gnome.login-screen`: `enable-password-authentication`, `enable-fingerprint-authentication`, `enable-smartcard-authentication`, `enable-switchable-authentication`, all default `true` (`data/org.gnome.login-screen.gschema.xml:9-48`). The shell filters mechanisms by them (`gnome-shell:js/gdm/authServicesLegacy.js:59-63,161-165`).
- **existence of the service file**: the worker refuses a missing one (above), and `gdm-config` refuses to enable a method whose `gdm-<method>` file is absent in `/etc/pam.d` or `/usr/lib/pam.d` (`utils/gdm-config.c:1438-1458,1483-1487`).
- **the module's own answer**: a stack that returns `PAM_AUTHINFO_UNAVAIL` makes the method vanish for that session. On Fedora this is how "fingerprint off" is expressed: authselect's `fingerprint-auth` without the feature is the single line `auth required pam_debug.so auth=authinfo_unavail` (`authselect/profiles/local/fingerprint-auth:1-2`), and pam_fprintd itself returns `PAM_AUTHINFO_UNAVAIL` when the user has no prints (fprintd commit `df6ebef`, whose message says the alternative "will lead some auth systems (such as gdm) to keep retrying").
- **hardware presence**: the shell drops fingerprint if no reader is found (`gnome-shell:js/gdm/authServicesLegacy.js:167-169`).

`gdm-config` (`utils/gdm-config.c`, installed by `utils/meson.build:14-22`, added in commit `c6c95b769`, 2020, by Marco Trevisan of Canonical) is the admin tool on top. It writes locked keys into a dconf system database and creates a dconf profile override under `/etc` (`utils/gdm-config.c:971-1022`). Before that it runs a distro hook, `libexec/gdm-auth-config-<distro>` (`utils/gdm-config.c:546-640`; `utils/meson.build:40-53`). The Fedora hook `utils/gdm-auth-config-redhat` does not touch PAM files; it calls `authselect select <current features> with-fingerprint -f` (`:91-105,175-190`) and exits 19 to tell `gdm-config` it is done. The generic hook does nothing and says why: "We assume the default handler can manage this, as gdm already provides a PAM config file for this case" (`utils/gdm-auth-config-generic:61-63,77-79`). The commit message spells out the policy: "we want to disable some changes by default, unless ACK'ed by an hook". So even GDM's own configuration tool will not edit PAM text; on Fedora it asks authselect, elsewhere it relies on GDM's own shipped files.

### Does GDM edit other packages' files?

Verified: no. Its build only installs its own `gdm-*` files (and since July 2026 not even into `/etc`). Commit `19c544dd1` ("build: Install the gdm service files in the system pam config path", 2026-07-19): "Installing service files in /etc/pam.d it's not something that we should do since such path is meant to be used for configuration files and so potential sys admin overrides." What it does depend on is other packages' stacks (`password-auth`, `fingerprint-auth`, `system-local-login`, `common-auth`), always by `include`/`substack`, never by editing them.

### The history that matters for properpin

- **`gdm-pin`, 2013 to 2021.** Commit `63a34df6e` (Giovanni Campagna, 2013-02-16, GNOME bug 693968) added `gdm-pin.pam` for redhat, lfs, exherbo, openembedded. Its message: "Originally, the idea was to have pam-pin as an optional module in gdm-password, but since the PIN can easily get misconfigured, what we want here is to give the user a choice at the login screen, so we want two different conversations at the same time. The pin module is marked requisite, so if it fails we stop before touching the other modules and immediately report to the greeter (which then goes on with gdm-password)." The redhat file was `auth requisite pam_pin.so` followed by `auth substack password-auth`, and `password optional pam_pin.so` (shown by `git show 63a34df6e`): the PIN module was to decrypt the stored password into `PAM_AUTHTOK` so `password-auth` and the keyring could use it, and to re-encrypt on password change. Commit `bd1594deb` (Ray Strode, 2021-09-22, closes GDM issue 731) removed it: "gdm-pin was an experimental feature that was going to get added to gnome-shell many years ago. It never happened and these days it would probably be implemented a little different anyway. (It would probably use a gdm pam extension)". It also removed the PIN-specific messages "You reached the maximum PIN authentication attempts, please try another method". `pam_pin.so` itself was never in the GDM tree.
- **The pam_faillock lesson.** Commit `5e415bb1d` (Arch, 2021): `pam_faillock authfail/authsucc` were removed from `gdm-fingerprint` and `gdm-smartcard`, keeping only `preauth`, because "we need to make sure that the stack's error status is taken from the main auth module, i.e. pam_fprintd, otherwise GDM will not behave correctly", and because some return codes (no prints enrolled) should not count as failures. Ideally "we would check which return values we actually want to treat as a reason to lock the account… but that's much more effort." properpin has the same concern solved the expensive way, inside its own module.
- **Empty-file bypass, July 2026.** Commit `4c69cfb45`: "When an authselect-managed service file (e.g., switchable-auth) is missing or empty, a direct substack to it returns PAM_SUCCESS without checking any credentials, allowing unauthenticated session access." The fix is the `gdm-*-substack` wrappers ending in `pam_deny.so`. Inferred: Fedora's `/etc/pam.d/kde-fingerprint` and `kde-smartcard` on this machine (owned by `plasma-workspace-6.7.5-1.fc44`) still do a bare `auth substack fingerprint-auth` / `smartcard-auth`, the pre-fix GDM pattern; on an authselect system those files are never empty (the disabled form is `pam_debug auth=authinfo_unavail`), so this is latent rather than live.
- **Unified authentication, 2024.** Commit `d46a4f3db` added `gdm-switchable-auth`: "At the moment, every authentication mechanism gets its own separate PAM conversation. Some PAM modules, like pam_sss, support more than one way to authenticate the user. Rather than starting several conversations… this commit adds a new 'unified' authentication setting." The module announces mechanisms through GDM's CustomJSON PAM extension (`pam-extensions/gdm-custom-json-pam-extension.h:37`, added in `8c3fbd5dd`, 2023), and the shell renders a mechanism list, including PIN prompts for smartcards and passkeys (`gnome-shell:js/gdm/authServicesSSSDSwitchable.js:24-25,395-399,456-459`). This is the "gdm pam extension" route Ray Strode had in mind for a PIN.

## fprintd and pam_fprintd

### What is shipped and installed

Verified. Upstream builds `pam_fprintd.so` into `<prefix>/<libdir>/security` (`pam/meson.build:7-10,40-41`) and a man page from `data/pam_fprintd.pod` (`data/meson.build:48-70`). Nothing goes to `/etc/pam.d` or any distro profile directory; `grep` for `pam.d`, `pam-configs`, `pam-auth-update` and `authselect` across the tree finds only the README line below. There is no Debian directory in the repo.

### What the docs tell admins

Verified.

- `pam/README:4-9` (from 2008, commit `c1ec850`): "Modify the appropriate PAM configuration file (/etc/pam.d/system-auth-ac on Fedora systems), and add the line: `auth sufficient pam_fprintd.so` before the line `auth sufficient pam_unix.so ...`". That is "tell the admin to edit by hand", and it is stale: `system-auth-ac` is the authconfig era, long replaced by authselect.
- `pam/README:24-26`, the origin of the whole multi-conversation idea: "pam_fprintd doesn't support entering either the password or a fingerprint, as pam_thinkfinger does, because it's a gross hack, and could be fixed by having the login managers run 2 separate PAM stacks". GDM's conversation work started two months later.
- `data/pam_fprintd.pod:49-56`: "The PAM stack is by design a serialised authentication, so it is not possible for pam_fprintd to allow authentication through passwords and fingerprints at the same time. It is up to the application using the PAM services to implement separate PAM processes and run separate authentication stacks separately. This is the way multiple authentication methods are made available to users of gdm for example."

### How distros actually wire it

- **Fedora**, verified on this machine. The lines belong to authselect, not to fprintd: `authselect/profiles/local/system-auth:4` (`auth sufficient pam_fprintd.so {include if "with-fingerprint"}`) and `authselect/profiles/local/fingerprint-auth:1-10` (with the feature, `auth [success=done default=bad] pam_fprintd.so` then `pam_deny`; without it, `pam_debug auth=authinfo_unavail`). The `fprintd-pam` RPM has only a `%postun` (`rpm -q --scripts fprintd-pam`): on removal, `authselect disable-feature with-fingerprint || :`. It does not enable the feature on install; here `authselect current` shows `local` with `with-fingerprint` enabled, and who enabled it (image build, installer, user) is not verified. Fedora's `/etc/pam.d/sudo` does `auth include system-auth`, and `/etc/pam.d/system-auth:8` on this machine has `auth sufficient pam_fprintd.so`, so **on Aurora fingerprint already unlocks sudo**, not just the lock screen.
- **Debian**, verified through sources.debian.org. `libpam-fprintd` installs `debian/pam-configs/fprintd` to `/usr/share/pam-configs/` (`debian:fprintd/debian/libpam-fprintd.install`), whose content is `Name: Fingerprint authentication`, `Default: no`, `Priority: 260`, `Auth-Type: Primary`, `Auth: [success=end default=ignore] pam_fprintd.so max-tries=1 timeout=10`. `postinst` runs `pam-auth-update --package`, `prerm` runs `pam-auth-update --package --remove fprintd`. `Default: no` means the admin opts in through `pam-auth-update`. Note the Debian defaults: one try and ten seconds, so a `sudo` in a terminal is not stuck for 3 × 30 s. Debian's `gdm-fingerprint` calls `pam_fprintd.so` directly, without those options.
- **GDM's own files** call it directly on Arch (`gdm/data/pam-arch/gdm-fingerprint.pam:6`) and through `fingerprint-auth` on Fedora.
- **KDE** on Fedora: `/etc/pam.d/kde-fingerprint` (from `plasma-workspace`) is `auth substack fingerprint-auth` + `auth include postlogin`, line for line the shape of GDM's redhat `gdm-fingerprint.pam`. kscreenlocker's service names are compile-time cache variables, `kde`, `kde-fingerprint`, `kde-smartcard`, `kde-face`, `kde-u2f` (`kscreenlocker/greeter/worker/CMakeLists.txt:4-32`, Harald Sitter, 2026).

### Rate limiting, max tries, timeouts

Verified in `pam/pam_fprintd.c` and `data/pam_fprintd.pod`.

- `max-tries=N`, default 3 (`pam/pam_fprintd.c:76,85`), negative means unlimited, "but in such case it's suggested for the module loader to handle this" (`data/pam_fprintd.pod:25-31`; commit `81f5252`, 2020: "This can be handled by the module loader (i.e. GDM)"). `timeout=S`, default 30 s, minimum 1, negative means unlimited (`pam/pam_fprintd.c:77-78,899-913`).
- The counter is a field of a per-call struct (`data->max_tries = max_tries`, `pam/pam_fprintd.c:773`), decremented per no-match (`:631`); after the loop, `PAM_MAXTRIES` (`:634-635`, commit `affffaf`, 2020). A timeout returns `PAM_AUTHINFO_UNAVAIL` (`:607-610`), as do daemon errors and disconnects (`:617-624`), so a timeout makes GDM drop the method rather than count a failure.
- **Nothing persists.** Each `pam_authenticate` starts at N again; neither the module nor the daemon keeps a failure count (no counter in `src/*.c`; the daemon's only gate is polkit `net.reactivated.fprint.device.verify`, `allow_active yes`, in `data/net.reactivated.fprint.device.policy.in:12-18`). Throttling against repeated attempts is left to the caller (GNOME Shell's Problem counting above) and to `pam_faillock` in the surrounding stack, which on Fedora is `preauth`/`authfail` around pam_fprintd only when `with-faillock` is on (`authselect/profiles/local/fingerprint-auth:4,6`). Hardware-side, libfprint has overheat protection (fprintd `NEWS`, 1.94.1), which is not a security limit.

The parallel to properpin's failure budget is weak: pam_fprintd's `max-tries` is closest to properpin's "three consecutive failures", but it resets with every new PAM call, so an attacker at the lock screen just starts a new conversation. properpin's persistent consecutive count, day/week/lifetime budgets and password-only unpausing have no counterpart here.

### Lock screen versus sudo

Verified. pam_fprintd does not know or care which service called it. It looks only at remoteness: it returns `PAM_AUTHINFO_UNAVAIL` if `PAM_RHOST` is set and not `localhost`, or if `sd_session_is_remote()` says so (`pam/pam_fprintd.c:813-833,846-847`; commits `3274a31`, 2019, citing the Linux-PAM guide's `PAM_RHOST` convention, and `18d4aa6`, 2020). For terminals it handles Ctrl-C: a `signalfd` on `SIGINT` aborts verification with `PAM_AUTHINFO_UNAVAIL` (`pam/pam_fprintd.c:473-477,526-535`; NEWS 1.92.0 "Cancel authentication on SIGINT (e.g. ctrl+c with sudo)"). It never asks a question; it only sends `PAM_TEXT_INFO` and `PAM_ERROR_MSG` (`pam/pam_fprintd.c:115-144`), which is what lets greeters run it in the background. Which services get fingerprint is decided entirely by which PAM files include it, and on Fedora `system-auth` includes it, so sudo, su and anything else on `system-auth` accept a finger whenever the feature is on.

## Classification

| stack | how it plugs in | evidence |
|---|---|---|
| GDM upstream | Own separate PAM service the app selects (`gdm-password`, `gdm-fingerprint`, `gdm-smartcard`, `gdm-switchable-auth`), shipped by GDM, per distro, in `/usr/lib/pam.d` | `data/meson.build:58-121`, commit `19c544dd1` |
| GDM on Fedora | Same, with the credential lines owned by authselect and reached through `include`; `gdm-config` toggles them with `authselect select … -f` | `data/pam-redhat/*`, `utils/gdm-auth-config-redhat:91-190` |
| GDM on Debian | Own separate services shipped by the Debian package in `/etc/pam.d`, smartcard variants chosen with `update-alternatives` | `debian:gdm3/debian/gdm3.alternatives` |
| GNOME Shell | Picks services from a hard-coded list, filters by dconf keys and file presence | `gnome-shell:js/gdm/authServicesLegacy.js:17-40` |
| fprintd upstream | Tell the admin to edit by hand | `pam/README:4-9` |
| fprintd on Fedora | Profile owned by the distro mechanism (authselect feature `with-fingerprint`); the package only disables it on removal | `authselect/profiles/local/system-auth:4`, `rpm -q --scripts fprintd-pam` |
| fprintd on Debian | Package drops a profile into the distro mechanism (`/usr/share/pam-configs/fprintd`, `Default: no`) and calls `pam-auth-update` | `debian:fprintd/debian/pam-configs/fprintd`, `libpam-fprintd.postinst` |
| KDE 6.8 / Fedora | Own separate PAM services the app selects (`kde-fingerprint` …), shipped by plasma-workspace | `kscreenlocker/greeter/worker/CMakeLists.txt:4-32`, `/etc/pam.d/kde-fingerprint` |
| properpin today | Installer edits another package's file (`/etc/pam.d/kde`, owned by `plasma-workspace`) | `packaging/install.sh`, `packaging/kde-auth.pam` |

None of the stacks studied falls in properpin's category. The reasons visible in their history all point the same way: `/etc` is for the admin (GDM `19c544dd1`), the stack belongs to the distro's tool (GDM's redhat hook, Fedora's `fprintd-pam` scriptlet), and an alternative method should be a separate stack the app chooses because a PAM stack is serial (fprintd README and man page, GDM `55a9a4130`, `63a34df6e`).

## What properpin should learn

### Would a separate service, like gdm-fingerprint, fit a typed PIN?

Partly, and at a UX cost. Inferred from the code above.

- **The text field has one owner.** GNOME Shell lets only the selected mechanism ask questions, and kscreenlocker's `PamAuthenticators` likewise singles out fingerprint as the only "non-interactive authenticator" running beside the interactive one (`kscreenlocker/greeter/pamauthenticators.cpp:28-41,141-172` versus `:200-222`). A `kde-pin` service would be an interactive authenticator, so the user would have to switch to "PIN" (or switch away from it) instead of typing whichever they like into one field. Feeding the same keystrokes to two stacks at once is what GDM chose not to do; it would also hand every password to the PIN module and every PIN to `pam_unix`, which today's single stack already does by design (properpin forgives the user's own typos because of it), so it would buy nothing.
- **Pausing maps well onto the protocol.** A paused PIN can return `PAM_MAXTRIES` or `PAM_AUTHINFO_UNAVAIL`: GDM then reports `ServiceUnavailable`, never restarts that service in the session, and does not count it as a failed login (`daemon/gdm-session.c:213-238`, commits `504fec05f`, `f04dc0418`); kscreenlocker marks an authenticator unavailable on `PAM_AUTHINFO_UNAVAIL`/`PAM_MODULE_UNKNOWN` (`kscreenlocker/greeter/worker/main.cpp:335-338`). So "after three failures the PIN disappears and the password field is what's left" is natural in a separate-service design, arguably more so than in today's single field, where a paused PIN is silently ignored.
- **The password side still needs a hook.** properpin's third line runs only after a correct password, to forgive the user's failures and unpause the PIN. In a separate-service design the password is checked in `kde`, not in `kde-pin`, so something in `kde`'s stack still has to call PIN unpause. On Fedora `kde` does `auth include postlogin` after `password-auth`, and so does `kde-fingerprint`; a line there would also fire after a fingerprint unlock, and `postlogin` is an authselect-managed file shared with other services. A separate service shrinks the edit to one optional line; it does not remove it.
- **The service list is closed.** GNOME Shell hard-codes service names; kscreenlocker's are CMake cache variables with five fixed roles. Neither lets a third party add "PIN" without an upstream change. Squatting an existing slot (say `kde-u2f`) would be the same kind of trespass as editing `kde`, with a wrong label in the UI.
- **Fail-closed rules carry over.** If properpin ever ships its own service file it should end in `auth required pam_deny.so` after the PIN line, because a stack that falls through (missing or empty included file, every module ignoring) succeeds (GDM `4c69cfb45`), and the app must check the file exists, because otherwise PAM uses `other` (GDM `e760c8e49`).
- **Where to put it on Aurora.** GDM's choice is `/usr/lib/pam.d` for vendor files and `/etc/pam.d` for overrides. On an atomic system `/usr` is read-only unless properpin becomes a layered RPM or a sysext; for a locally installed tool, `/etc/pam.d/kde-pin` is the right place, and it is a new file properpin owns, which is a very different thing from editing `kde`.

### UI implications, if properpin went this way

Inferred. The user would see a mechanism switcher (GNOME's auth menu, KDE 6.8's authenticator choice). PIN could be preselected so the common path is still "type PIN, Enter", with the password one click away, and with the PIN entry vanishing once paused, which is clearer than the silent fallback of today. The cost is one extra action whenever the user wants the password, and a dependency on KDE accepting a "PIN" authenticator. GDM's own design discussion in 2013 chose exactly this ("give the user a choice at the login screen"), then never shipped it.

### Distro mechanisms do not fit the lock-screen-only goal

Verified on this machine. The authselect and `pam-auth-update` routes add lines to shared stacks. `password-auth` is included by `cups`, `kde`, `plasmalogin`, `ppp`, `remote`, `samba`, `sshd` and `vmtoolsd` here, and `system-auth` by `sudo`. A PIN placed there would be accepted by `sshd` and `sudo`, the opposite of properpin's scope, and is precisely how fingerprint already ended up unlocking sudo on Aurora. `/etc/pam.d/kde` itself is not authselect-managed (owned by `plasma-workspace`), so authselect has no feature to hook. A custom authselect profile could carry properpin's lines only by being specific to `kde`, which authselect profiles cannot express. So the realistic choices for properpin are "edit `kde` carefully, as now" or "own a `kde-pin` service and get KDE to select it", not a distro profile.

### Smaller lessons

- Keep the PIN module's error status the stack's error status: Arch's `5e415bb1d` shows what happens when a counting module after the real one changes the result. properpin's `[success=done default=ignore]` line 1 and its PIN unpause as `optional` after a `default=die` password line already follow this.
- pam_fprintd's "skip remote sessions" check (`PAM_RHOST`, `sd_session_is_remote`) is a cheap defence in depth properpin could add, so its lines do nothing if `kde` is ever reached remotely. Inferred value; properpin's service is lock-screen only already.
- Debian's choice of `max-tries=1 timeout=10` for the terminal profile is a reminder that a module meant for one context behaves badly in another; properpin's "not for sudo" scope avoids that question for now.

## Bonus: a PIN-like short secret with limits in these stacks?

What is new compared with `docs/chaos/competition.md` and `docs/chaos/lockscreen-pin-existing-implementations.md`, which already cover the `gdm-pin` service, the GNOME design page and `gdm-switchable-auth`:

- **What `gdm-pin` actually was.** Verified in `git show 63a34df6e`: a separate conversation running `auth requisite pam_pin.so` before `auth substack password-auth`, with `password optional pam_pin.so` to follow password changes, and its removal in `bd1594deb` with the stated reason that it never reached gnome-shell and would be redone as a GDM PAM extension. There were never any attempt limits in GDM for it, only the per-service message "You reached the maximum PIN authentication attempts". Our earlier docs say "still exists on Arch and Bluefin"; upstream has not shipped it since GDM 42 (removal in September 2021, NEWS updated in `3c9ee198c`, January 2022), so any `gdm-pin` file on a 2026 system is a distro leftover.
- **GDM-side limits are weaker than they look.** `allowed-failures` (3) sends the login screen back to user selection; at the lock screen `_canRetry` ignores it entirely (`gnome-shell:js/gdm/authServices.js:399-402`). GNOME's unlock has no failure limit of its own, for any mechanism.
- **The only real "short secret with limits" here is hardware-held.** `gdm-switchable-auth` with SSSD prompts for smartcard and passkey PINs (`gnome-shell:js/gdm/authServicesSSSDSwitchable.js:395-399,456-459`). Those PINs are limited by the token itself (smartcard PIN retry counters; FIDO2 authenticators block after repeated wrong PINs). That is better than properpin against an attacker at the keyboard, because the counter lives in tamper-resistant hardware, but it is a possession factor plus PIN, not a memorised PIN for the account, and the limits are the token's, not GDM's. The token-side numbers come from general knowledge of the standards, not from these repositories.
- **pam_fprintd's max-tries is not a budget.** Per call, reset on the next call, unlimited at GNOME's lock screen. Nothing in GDM, GNOME Shell or fprintd implements anything like properpin's consecutive count, daily/weekly/lifetime budgets, or the rule that only a password unlock unpauses the PIN.

## Recommendation

Keep editing `/etc/pam.d/kde` for now, but treat it as a stopgap and design the module so it can live in a separate service later. The evidence says the "right" integration, by the conventions of GDM, fprintd and KDE 6.8, is a separate service owned by properpin (`kde-pin`, ending in `pam_deny`), chosen by the locker, with the paused PIN returning `PAM_MAXTRIES`/`PAM_AUTHINFO_UNAVAIL` so the UI hides it. That needs an upstream "PIN" authenticator role in kscreenlocker, since the service list is closed, and it still needs one `after-password-auth` line in `kde` for the password-unpauses-PIN rule. Distro profiles (authselect, `pam-auth-update`) are the wrong tool, because they act on shared stacks and would leak the PIN to `sshd` and `sudo`. Concretely: make sure the PIN line's behaviour does not depend on sharing a stack with `pam_unix` (it already ignores rather than fails), return `PAM_MAXTRIES` or `PAM_AUTHINFO_UNAVAIL` rather than `PAM_IGNORE` when called from a service of its own, consider pam_fprintd's remote-session check, and raise a "PIN authenticator" proposal with KDE alongside the 6.8 work, citing GDM's `gdm-pin` history as the precedent and its fate as the warning.
