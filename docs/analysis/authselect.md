# authselect, Fedora's lock-screen PAM files, and properpin

Read-only analysis, 2026-10-17. It answers how authselect works, whether it touches `/etc/pam.d/kde`, what its features do to the stack properpin sits in front of, whether properpin could ship as an authselect feature or profile, and what Fedora ships for the lock screen. Every claim is marked as either verified (read in code, or observed on this machine) or inferred.

## Short answer

authselect does not own, generate, read or rewrite `/etc/pam.d/kde`. It owns exactly six PAM stack files (`system-auth`, `password-auth`, `fingerprint-auth`, `smartcard-auth`, `switchable-auth`, `postlogin`) plus `nsswitch.conf` and two dconf files, all generated into `/etc/authselect/` and symlinked from `/etc/pam.d/`. properpin's three marked lines therefore survive `authselect select`, `enable-feature`, `apply-changes`, `opt-out` and backups untouched. The danger runs the other way: authselect can silently change what sits *under* properpin's lines (the `password-auth` substack), and several of its features (`with-faillock`, `with-pam-u2f-2fa`, `with-systemd-homed`, `with-smartcard-required` in sssd, and the whole `sssd` and `winbind` profiles) interact badly with a PIN line that ends the stack before `password-auth` runs and a password line that calls `pam_unix` directly. authselect has no per-service scoping and no third-party drop-in mechanism, so making properpin an authselect feature would put it in a stack shared with sshd and the login manager, and a custom or vendor profile would make users switch profiles and freeze them off upstream profile fixes. The recommendation is to coexist: keep editing `/etc/pam.d/kde` only, but read authselect's current profile and features at `install` and `check` time and refuse (or warn loudly) on combinations that properpin would weaken.

On Fedora, the lock-screen PAM files are not shipped by kscreenlocker at all but by plasma-workspace: `/etc/pam.d/kde`, `kde-fingerprint` and `kde-smartcard`, all `%config(noreplace)` in `/etc`, not in `/usr/lib/pam.d`.

## Sources and how they were read

- authselect clone at `/var/home/shared/projects/pam-related/authselect`, HEAD `3084703` (2026-08-25, "profiles: Add support for oo7"), just after tag 1.8.0. Paths below are relative to that clone unless prefixed.
- Fedora dist-git for kscreenlocker at `/var/home/shared/projects/pam-related/fedora-rpm-kscreenlocker`, branch `rawhide` at `6f3a790` (6.8.0-2, 2026-10-12), plus the `origin/f44`, `f43`, `f42` and `epel9` branches.
- Upstream kscreenlocker at `/var/home/shared/projects/pam-related/kscreenlocker` (`v6.7.90-35-ge77531ae`), Linux-PAM at `/var/home/shared/projects/pam-related/linux-pam` (`v1.7.3-32`), debian-pam, pam-u2f and google-authenticator-libpam for comparison.
- This machine itself, which turned out to be Aurora 44 (`VERSION="44.20261013.1 (Kinoite)"`, `/run/ostree-booted` present), with `authselect-libs-1.7.1-1.fc44`, `plasma-workspace-6.7.5-1.fc44`, `pam-1.7.2-2.fc44`. Only read-only queries were run (`rpm -q*`, `cat`, `ls`, `authselect current`, `systemctl status`).
- secureblue at `/var/home/shared/projects/secureblue`, because it changes authselect features at image build time.

Nothing was built or modified in any clone. A Fedora plasma-workspace SRPM briefly appeared in the pam-related directory and was gone before it could be read, so the plasma-workspace packaging facts below come from the installed RPM's metadata rather than its spec.

## How authselect works

### Profile directories and lookup order

Verified. Three profile locations exist, set at build time in `src/conf_macros.m4:29-35` and `src/lib/paths.h:69-72`:

- `/usr/share/authselect/default/<name>`: profiles shipped with authselect (today `local`, `sssd`, `winbind`; `profiles/` in the clone; the NIS profile was removed in `fe90291`, 2026-08-06).
- `/usr/share/authselect/vendor/<name>`: "vendor-specific profiles that can override the ones in _default_ directory" (`src/man/authselect-profiles.5.adoc:21-23`).
- `/etc/authselect/custom/<name>`: administrator profiles, addressed as `custom/<name>` (`src/lib/constants.h:32`).

A plain profile id is looked up in vendor first, then default (`src/lib/profiles/read.c:40-44`), so a vendor profile named `local` shadows the default `local`. A `custom/` id is looked up only in the custom directory (`read.c:54-56`).

### What a profile contains and what authselect writes

Verified. A profile is a directory with a mandatory `README` and optional `REQUIREMENTS`, `system-auth`, `password-auth`, `fingerprint-auth`, `smartcard-auth`, `switchable-auth`, `postlogin`, `nsswitch.conf`, `dconf-db`, `dconf-locks` (`src/lib/paths.h:34-45`, `src/man/authselect-profiles.5.adoc:28-64`, `200-205`). The list is closed: `PROFILE_FILES` (`paths.h:113-125`) and `authselect_system_read_templates` (`src/lib/files/system.c:60-71`) read exactly those names and nothing else, so a profile cannot add a file for another PAM service.

On activation, each template is rendered and written to `/etc/authselect/<file>` (`GENERATED_FILES`, `paths.h:85-97`; atomic temp-file-and-rename in `system.c:199-255`), and these symlinks are (re)created (`SYMLINK_FILES`, `paths.h:140-150`; `src/lib/files/symlinks.c:30-67`, which unlinks whatever is at the link path first, line 44):

- `/etc/pam.d/system-auth` → `/etc/authselect/system-auth`
- `/etc/pam.d/password-auth` → `/etc/authselect/password-auth`
- `/etc/pam.d/fingerprint-auth` → `/etc/authselect/fingerprint-auth`
- `/etc/pam.d/smartcard-auth` → `/etc/authselect/smartcard-auth`
- `/etc/pam.d/switchable-auth` → `/etc/authselect/switchable-auth`
- `/etc/pam.d/postlogin` → `/etc/authselect/postlogin`
- `/etc/nsswitch.conf` → `/etc/authselect/nsswitch.conf`
- `/etc/dconf/db/distro.d/20-authselect` and its `locks/` twin → the dconf files

Every generated file starts with the preamble "Generated by authselect / Do not modify this file manually, use authselect instead. Any user changes will be overwritten." (`src/lib/util/template.c:550-559`). On this machine, `/etc/pam.d/{system,password,fingerprint,smartcard,switchable}-auth` and `postlogin` are exactly those symlinks, owned by `authselect-libs`.

The selected profile and features are stored as plain text in `/etc/authselect/authselect.conf`, profile id on the first line and one feature per line (`src/lib/files/config.c:39-62`). On this machine it reads `local`, `with-silent-lastlog`, `with-mdns4`, `with-fingerprint`. Fedora's default for new installs is `local` plus `with-silent-lastlog` (`rpm/authselect.conf.fedora:1-2`), applied as the `@system-default` preset (`src/cli/presets.c:31-34`).

### Templates, conditional lines and features

Verified. Each profile file is a template with these operators (`src/man/authselect-profiles.5.adoc:66-130`; regexes in `src/lib/util/template.c:40-43`, operator table `template.c:90-96`):

- `{continue if "f"}` and `{stop if "f"}`: keep or drop the rest of the file.
- `{include if "f"}` and `{exclude if "f"}`: keep or drop the one line carrying the operator.
- `{imply "g" if "f"}`: enabling f also enables g.
- `{if "f":a|b}` and `{if "f":a}`: inline substitution.
- Expressions with `and`, `or`, `not` and parentheses (`authselect-profiles.5.adoc:105-130`).

Features are not declared anywhere. `authselect_profile_features` collects every feature name that appears in any of the profile's templates (`src/lib/authselect_profile.c:118-167`, via `template_list_features`, `template.c:603`). `select` and `enable-feature` reject any name not found that way, suggesting the nearest match (`src/lib/authselect.c:32-69`, `95-98`). Consequence (verified): a feature exists only if the profile's own templates mention it. There is no feature registry, no drop-in directory, and no way for a third-party package to add `with-properpin` to the stock `local` profile without replacing or forking that profile.

The `local` profile's features (`profiles/local/README:10-79`) are `with-faillock`, `with-mkhomedir`, `with-ecryptfs`, `with-fingerprint`, `with-pam-gnome-keyring`, `with-pam-kwallet` (new, `a7611c9`, not yet in a tag), `with-pam-oo7`, `with-pam-u2f`, `with-pam-u2f-2fa`, `without-pam-u2f-nouserok`, `with-silent-lastlog`, `without-lastlog-showfailed`, `with-pamaccess`, `with-pwhistory`, `with-altfiles`, `with-group-merging`, `with-mdns4`, `with-mdns6`, `with-systemd-homed`, `with-libvirt`, `without-nullok`. The `sssd` profile adds smartcard (`with-smartcard`, `with-smartcard-required`, `with-smartcard-lock-on-removal`), `with-gssapi`, `with-files-access-provider`, `with-switchable-auth`, `with-gpupdate` and others.

### Commands and change detection

Verified, `src/cli/main.c` and `src/lib/authselect.c`:

- `select PROFILE [features] [--force]` activates a profile. Without `--force` it refuses only when `/etc/authselect/authselect.conf` is missing or unreadable, that is, when the system was never configured by authselect (`authselect.c:106-115`). If authselect's own files were modified, it prints "Changes to the authselect configuration were detected. These changes will be overwritten" and overwrites them anyway (`authselect.c:117-123`). `--force` makes a backup first unless `--nobackup` (`main.c:191-194`, `219-226`).
- `enable-feature` and `disable-feature` re-run activation with the feature list changed (`authselect.c:246-293`).
- `apply-changes [--upgrade]` re-renders the current profile. With `--upgrade` it does nothing when `/usr/share/authselect/checksum` equals the copy in `/var/lib/authselect/checksum` (`authselect.c:181-205`); otherwise it drops features the profile no longer has (`221-231`) and re-activates.
- `check` reports whether the configuration is authselect's (`src/man/authselect.8.adoc:119-134`).
- `opt-out` replaces each symlink with a regular copy of the generated file, then deletes `/etc/authselect` contents (`authselect.c:136-162`; `symlinks.c:162-198`; `system.c:320-348`).
- `backup-*` saves and restores only authselect's own files: `authselect.conf`, the six PAM stacks, nsswitch and dconf (`src/lib/authselect_backup.c:243-252`, `282-291`).

Change detection is deliberately weak since 1.4.0. Commit `4c4730e` ("lib: drop strict change detection", 2022-01-31) says: "any user changes made to configuration created by authselect are overwritten without requiring the *--force* parameter (files contents are no longer validated)", partly to "make authselect work on ostree". What remains is a check that each generated file is a regular file with mode 0644 and each symlink points at its target (`system.c:257-294`, `src/lib/util/file.c:136-144`, `symlinks.c:69-96`). The comment "Check that generated files exist and have proper content" in `config.c:124` is stale: content is not compared.

### Automatic re-application, especially on ostree

Verified in the upstream spec and on this machine:

- `authselect-apply-changes.service` runs `authselect apply-changes --upgrade` on every boot before user sessions (`systemd/authselect-apply-changes.service:1-14`, added in `7cfd9ab`, first released in 1.6.2). It is enabled on this Aurora machine and last ran successfully at boot on 2026-10-14. So when an image update ships changed authselect profiles, the six stacks in `/etc/authselect` are regenerated at the next boot without anyone running a command.
- `authselect-first-boot.service` runs `select @system-default --force --nobackup` when `/etc` is empty (`systemd/authselect-first-boot.service:1-19`, 1.8.0, not on this machine's 1.7.1).
- The libs `%posttrans` on any `/run/ostree-booted` system creates a vendor profile for every default profile, symlinking the PAM files back to the default ones and baking `with-altfiles` into nsswitch (`rpm/authselect.spec.in:211-219`), recomputes the checksum (`237-240`) and runs `apply-changes` (`242-243`). On this machine `/usr/share/authselect/vendor/{local,nis,sssd,winbind}` exist exactly like that (for example `vendor/local/password-auth -> /usr/share/authselect/default/local/password-auth`, `vendor/local/nsswitch.conf` a regular file).

Inferred: on an atomic system the vendor directory is already occupied by authselect's own generated `local` profile, and `/usr` is read-only at runtime, so a third party can only add a vendor profile at image build time or through a layered RPM. Since the checksum is computed only in authselect's own `%posttrans`, a vendor profile added later by another package would not change `/usr/share/authselect/checksum`, so `apply-changes --upgrade` would not notice its updates.

## Does authselect touch /etc/pam.d/kde?

No (verified). The complete set of paths authselect writes, links, validates, backs up or removes is the `GENERATED_FILES`, `SYMLINK_FILES` and backup tables quoted above (`paths.h:85-150`, `authselect_backup.c:243-291`), plus `authselect.conf`, `/var/lib/authselect/checksum` and backups. `kde` appears in authselect only as a string in one `pam_succeed_if` line inside the sssd profile (`profiles/sssd/system-auth:5`, added by `100817d`, 2021, "Add kde to the list of smartcard capable PAM services"). `authselect check` even says that "there might be other pam stacks in /etc/pam.d" it does not manage (`authselect.8.adoc:128-130`).

What this means for properpin (inferred from the above, consistent with how `/etc/pam.d/kde` is built): `authselect select`, `enable-feature`, `disable-feature`, `apply-changes` (manual or at boot), `opt-out` and `backup-restore` all leave properpin's block in `/etc/pam.d/kde` byte for byte, and `install.sh`'s marker-based removal keeps working. authselect also has no way to detect or refuse properpin's edit, because it never looks at `kde`. And properpin's install script does not look at authselect either: `packaging/install.sh` never mentions it; it only requires exactly one `auth substack password-auth` line, as `docs/chaos/current-concerns.md` notes.

The real exposure is that `/etc/pam.d/kde` substacks `password-auth`, which authselect regenerates. On this machine `kde` reads `auth substack password-auth` then `auth include postlogin`, and `password-auth` today is just `pam_env`, `pam_faildelay`, `pam_unix nullok`, `pam_deny` (`/etc/authselect/password-auth:6-9`). Any `authselect enable-feature`, profile switch, or authselect image update can change that, with no hook that tells properpin.

### Which services share password-auth and system-auth

Verified on this machine with `grep -l` over `/etc/pam.d` and `/usr/lib/pam.d`:

- `password-auth` is included by `kde`, `sshd`, `plasmalogin` (the Plasma login manager, in `/usr/lib/pam.d`), `remote`, `samba`, `cups`, `ppp`, `vmtoolsd`.
- `system-auth` is included by `sudo`, `su`, `login`, `passwd`, `chsh`, `chfn`, `config-util`, `vlock`, `kcheckpass`, `kscreensaver`, and `systemd-user`, `polkit-1`, `plasmalogin-autologin` from `/usr/lib/pam.d`.

So anything placed in `password-auth` reaches ssh and graphical login, and anything in `system-auth` reaches sudo and polkit. That is the exact opposite of properpin's lock-screen-only scope.

## How the features reach the stacks, and what each does under properpin's lines

Verified placement (from `profiles/local/*` and `profiles/sssd/*`):

- `with-fingerprint`: `pam_fprintd.so sufficient` in `system-auth` only (`local/system-auth:4`, `sssd/system-auth:7`), and turns on the `fingerprint-auth` stack (`local/fingerprint-auth:1-10`), which is otherwise a stub returning `authinfo_unavail` through `pam_debug` (`local/fingerprint-auth:1`). It is not in `password-auth`. At the lock screen, fingerprint reaches the user via `kde-fingerprint`, which substacks `fingerprint-auth`. Matches this machine: `/etc/authselect/system-auth:8` has `pam_fprintd`, `password-auth` does not.
- `with-pam-u2f`: `pam_u2f.so cue sufficient` in both `system-auth` and `password-auth` (`local/system-auth:5`, `local/password-auth:4`), so it applies to `kde`, sshd, plasmalogin, sudo and so on at once.
- `with-pam-u2f-2fa`: `pam_u2f.so cue nouserok required` before `pam_unix` in both stacks (`local/password-auth:5`).
- `with-smartcard` (sssd only): `pam_sss try_cert_auth` in `system-auth` (`sssd/system-auth:13`) and the `smartcard-auth` stack (`sssd/smartcard-auth:3-11`). In the `local` profile, `smartcard-auth` is always the `pam_debug auth=authinfo_unavail` stub (`local/smartcard-auth:1`), so `kde-smartcard` is inert there.
- `with-smartcard-required` (sssd): `pam_deny # Smartcard authentication is required` at the top of `password-auth` (`sssd/password-auth:3`) and `fingerprint-auth` (`sssd/fingerprint-auth:4`), and in `system-auth` a `pam_sss require_cert_auth` gated by a service list (`sssd/system-auth:5-6`).
- `with-faillock`: `pam_faillock preauth` before and `authfail` after `pam_unix` in every stack (`local/password-auth:3,8`).
- `with-systemd-homed`: `pam_systemd_home` before `pam_unix` (`local/password-auth:6`).
- `with-pam-kwallet`, `with-pam-gnome-keyring`, `with-pam-oo7`: optional modules after `pam_unix` (`local/password-auth:9-11`).

Single-service scoping: no authselect feature is scoped to one service; features toggle lines in stacks that every including service shares. The only scoping devices that appear in the profiles are PAM-level ones written into the shared stack: `pam_succeed_if.so service notin login:gdm:xdm:kdm:kde:xscreensaver:gnome-screensaver:kscreensaver` (`sssd/system-auth:5`), `pam_succeed_if.so service in crond` in the session stacks (`local/system-auth:33`), `service !~ gdm* service !~ su*` in `postlogin` (`local/postlogin:6`), and the keyring modules' own `only_if=login` argument. `pam_succeed_if` reads `PAM_SERVICE` for the `service` field (linux-pam `modules/pam_succeed_if/pam_succeed_if.c:328-330`). The per-device split (fingerprint, smartcard) works through separate stacks and separate service files (`kde-fingerprint`, `kde-smartcard`), which belong to the application, not to authselect.

### Interaction with properpin's three lines

properpin puts, above `auth substack password-auth` in `kde` (`packaging/kde-auth.pam`): the PIN with `[success=done default=ignore]`, then `pam_unix.so use_first_pass` with `[success=ok default=die]`, then the optional PIN unpause. These are inferences from reading the profiles against standard PAM control semantics (`done` and `die` end the stack; a `substack`'s `done` and `die` end only the substack, linux-pam `doc/man/pam.conf-syntax.xml:187-202`); none was run.

- Default Fedora/Aurora (`local`, `with-silent-lastlog`, possibly `with-fingerprint`, `with-mdns4`): fine. `password-auth` holds nothing the PIN path skips that matters.
- `with-faillock` (secureblue enables it at image build, `secureblue/files/scripts/authselect.sh:11`): two regressions. A correct PIN ends the stack before `pam_faillock preauth`, so a user locked by faillock can still unlock with the PIN. More seriously, a wrong *password* dies at properpin's `pam_unix` line before `password-auth` runs, so `pam_faillock authfail` never records it: faillock stops counting password guesses at the lock screen. properpin's own failure counter only covers PIN-shaped attempts. This should block `install` or be stated loudly.
- `with-pam-u2f-2fa`: the PIN bypasses the second factor entirely (the `required pam_u2f` lives in `password-auth`, which the PIN never reaches). The password path still requires the key. A PIN would turn two-factor unlock into one-factor. Should block `install`.
- `with-pam-u2f` (sufficient): harmless; the key remains an alternative after the password prompt.
- `with-systemd-homed`: `pam_systemd_home` sits before `pam_unix` in `password-auth` because homed users are not checked by `pam_unix`; properpin's direct `pam_unix` line would `die` for such users before the homed module ever runs, locking them out of the lock screen with the right password (likely; whether `pam_unix` can verify a homed user via nss-systemd shadow data was not checked). Should block `install`.
- `sssd` and `winbind` profiles: domain users are verified by `pam_sss`/`pam_winbind` after `pam_unix` (`sssd/password-auth:10-12`); properpin's `pam_unix` line dies for them. Already listed in `docs/chaos/current-concerns.md`. Should block `install`.
- `with-smartcard-required` (sssd): `password-auth` starts with `pam_deny`, so the password path still fails, but a PIN succeeds before reaching it, defeating the policy. Should block `install`.
- `with-pam-kwallet`, `with-pam-gnome-keyring`, `with-pam-oo7`, `with-ecryptfs`: a PIN unlock skips them (and `postlogin`'s `pam_ecryptfs`, `local/postlogin:1`). At the lock screen the wallet and home are normally already open, so the effect is minor; worth a sentence in the docs, like the `pam_systemd_home` note in `docs/chaos/why-pin-same-as-password-bad.md`.
- `without-nullok`, `with-pamaccess`, `with-pwhistory`, `with-mkhomedir`, lastlog and nsswitch features: no auth-path effect at the lock screen (the lock screen never runs the account, password or session stacks, per `docs/chaos/kscreenlocker-pam-contract.md`).

Note that `pam_faildelay delay=2000000` is in `password-auth` too and is skipped on the password-failure path, but `pam_unix` requests its own 2-second delay on failure unless given `nodelay` (standard pam_unix behaviour, not re-checked here), so the delay survives.

## Could properpin ship as an authselect feature or profile?

The options, each assessed against the lock-screen-only requirement:

- An upstream feature in the stock profiles (`with-properpin`). The only files a feature can touch are the shared stacks (verified above). The lines would have to live in `password-auth` (reached by `kde`) behind a `pam_succeed_if.so service = kde` gate, the same trick as `sssd/system-auth:5`. Inside a substack, properpin's `success=done` would end only `password-auth`, and the result would feed back to `kde`, so the semantics would change and properpin would have to be re-tested. It would also run (and be skipped by the gate) for sshd, plasmalogin, cups and the rest, so a gate bug becomes a login or ssh bug. It requires authselect upstream to accept a niche third-party module into Red Hat's default profiles. Technically possible, practically unrealistic, and it widens properpin's blast radius from one file to every password-auth service. Rejected.
- A custom profile (`authselect create-profile properpin -b local`, then `authselect select custom/properpin <features>`). Verified mechanics: `create-profile` copies or symlinks the base profile's files into `/etc/authselect/custom/<name>` (`src/lib/authselect_profile.c:514-609`, flags `--symlink-pam`, `--symlink-meta` etc., `main.c:891-898`), and selecting it rewrites the six stacks. Problems: the user must switch profile (disruptive, and it drops the selected features unless they are repeated); properpin would have to *copy* and edit `password-auth`, freezing it against upstream profile fixes forever (a symlinked file cannot be edited); the edit would still need the same service gate as above; and a later `authselect select local` by the admin or a tool silently removes properpin while its files remain, which is benign but surprising. Feasible, but strictly worse than editing `kde`.
- A vendor profile in `/usr/share/authselect/vendor/`. On atomic systems that directory already holds authselect's own generated vendor `local` (spec `211-219`, verified on this machine), so properpin would have to shadow it or use a new name (which again means switching profile). It can only be written at image build or by a layered RPM, and its later changes would not trigger `apply-changes --upgrade` (checksum computed only by authselect's scriptlet). Appropriate only for an image builder that bakes properpin in, and even then editing `kde` in the image is simpler.
- Third-party features without a custom profile: not supported. Features are derived from the selected profile's own templates (`authselect_profile.c:118-167`) and unknown names are rejected (`authselect.c:51-64`). There is no counterpart to Debian's `pam-auth-update`, which merges package-provided snippets from `/usr/share/pam-configs` (`debian-pam/debian/local/pam-auth-update:3-6,34`).

Conclusion (inferred from all of the above): authselect is fundamentally the wrong layer for properpin. It manages *shared* policy (identity source, factors for every service), while properpin is a policy for *one* service. The right layer is the per-service file `/etc/pam.d/kde`, which authselect explicitly leaves to the application package.

## What Fedora ships for the lock screen

### kscreenlocker ships no PAM files

Verified. Fedora's `kscreenlocker.spec` (rawhide 6.8.0-2) has no PAM sources and its `%files` list contains no `pam.d` path (`fedora-rpm-kscreenlocker/kscreenlocker.spec:79-98`); the only PAM reference is `BuildRequires: pam-devel` (`:51`), present since the first import of the split package in 2015 (`05a20fe`, "Plasma 5.4.95"). The f44, f43, f42 and epel9 branches are the same. `git log -G pam` over all branches finds nothing else. Upstream kscreenlocker installs no PAM file either; it only defines the service names it opens: `kde`, `kde-fingerprint`, `kde-smartcard`, and in 6.8 `kde-face` and `kde-u2f` (`kscreenlocker/greeter/worker/CMakeLists.txt:6-32`; used at `greeter/pamauthenticators.cpp:139,183-191`).

On Fedora 44 the f44 branch is at kscreenlocker 6.7.5; rawhide has 6.8.0 (`git log`, `fb3de72` 2026-10-09).

### plasma-workspace ships kde, kde-fingerprint and kde-smartcard

Verified on this machine with `rpm -qf`, `rpm -q --qf '[%{FILENAMES} %{FILEFLAGS:fflags}]'` and `rpm -V`:

- `/etc/pam.d/kde`, `/etc/pam.d/kde-fingerprint`, `/etc/pam.d/kde-smartcard` belong to `plasma-workspace-6.7.5-1.fc44`, flags `cn`, that is `%config(noreplace)`.
- They live in `/etc/pam.d`, not in `/usr/lib/pam.d`. The only `/usr/lib/pam.d` files on this machine are `plasmalogin`, `plasmalogin-autologin`, `plasmalogin-greeter` (plasma-login-manager), `polkit-1` and `systemd-user`, `systemd-run0` (systemd).
- No `kde-face` or `kde-u2f` exists yet; under 6.8 those services would fall through to `/etc/pam.d/other` (deny) until something ships them. What Fedora's 6.8 plasma-workspace will ship could not be checked (no plasma-workspace dist-git or SRPM was readable).
- Contents, identical for the three except the stack name: `auth substack <password-auth|fingerprint-auth|smartcard-auth>`, `auth include postlogin`, `account required pam_nologin.so`, `account include <stack>`, `password include <stack>`, then `session` lines `pam_selinux close`, `pam_loginuid`, `pam_selinux open`, `pam_keyinit force revoke`, `pam_namespace`, `session include <stack>`, `session include postlogin` (15 lines each).
- `rpm -q --changelog plasma-workspace` has no entry mentioning PAM in the 24 lines it keeps, so the history of these files is not recoverable here.

### vendordir

Verified. Linux-PAM looks up a service in `/etc/pam.d/<svc>`, then `/usr/lib/pam.d/<svc>`, then `VENDORDIR/pam.d/<svc>` only if built with a vendordir (`linux-pam/libpam/pam_private.h:29-35`, `libpam/pam_handlers.c:298-301`; meson option default `/usr/share/pam`, `meson_options.txt:90`). Fedora's `macros.pam` defines `%_pam_vendordir` as `%{_datadir}/pam.d` (`/usr/lib/rpm/macros.d/macros.pam:5`), but `/usr/share/pam.d` does not exist here and `libpam.so.0` contains only the `/etc/pam.d` and `/usr/lib/pam.d` strings (inferred from `strings`: Fedora's libpam is built without a vendordir, and `/usr/lib/pam.d` is the "dist" directory every libpam searches). Fedora 44 has not moved `kde` out of `/etc`.

### What happens to an edited /etc/pam.d/kde on update

- Classic RPM (inferred from `%config(noreplace)` semantics): if a plasma-workspace update ships an unchanged `kde`, nothing happens. If it ships a changed one, RPM keeps the edited file and writes the new one as `/etc/pam.d/kde.rpmnew`. properpin's lines survive; upstream fixes do not arrive until someone merges the `.rpmnew`.
- rpm-ostree / bootc (Aurora): the image's pristine copy sits in `/usr/etc/pam.d/kde` (verified: present, identical to `/etc/pam.d/kde` here, not owned by any RPM because ostree puts it there). The 3-way merge keeps a locally modified `/etc` file as is and never merges content (`docs/chaos/plasma-pin-unlock-aurora-deployment.md`, lines 145-147 and its references). So after properpin edits `kde`, image updates to `kde` are silently ignored. `ostree admin config-diff` lists it as modified. Rolling back a deployment does not roll back `/etc`.
- Either way, an edited `kde` does not stop changes beneath it: `password-auth` comes from authselect and is regenerated at boot by `authselect-apply-changes.service` when authselect's profiles change.

## Recommendation for properpin

Coexist with authselect; do not integrate with it, and do not ignore it.

- Keep the edit in `/etc/pam.d/kde` only. It is the only lock-screen-only place, authselect never touches it, and it survives every authselect command. Do not ship a feature, custom profile or vendor profile.
- Make `install.sh install` and `check` authselect-aware, read-only: run `authselect current --raw` (or read `/etc/authselect/authselect.conf`) and accept only the `local` profile (and its vendor twin on ostree) with an allow-list of features known to be safe under properpin's lines, for example `with-silent-lastlog`, `without-lastlog-showfailed`, `with-mdns4`, `with-mdns6`, `with-altfiles`, `with-group-merging`, `with-libvirt`, `with-fingerprint`, `with-pam-u2f`, `with-pamaccess`, `with-pwhistory`, `with-mkhomedir`, `without-nullok`, and with a warning `with-pam-kwallet`, `with-pam-gnome-keyring`, `with-pam-oo7`, `with-ecryptfs`. Refuse `sssd`, `winbind`, `with-faillock`, `with-pam-u2f-2fa`, `with-systemd-homed`, `with-smartcard-required`, and any unknown feature or `custom/` profile, with a message saying why. When authselect is absent or opted out (no `authselect.conf`), fall back to comparing the auth lines of `/etc/pam.d/password-auth` with the stock four. This fits the deferred fix in `docs/chaos/current-concerns.md`.
- Re-check after authselect changes, since they happen without the user running properpin: a small oneshot unit ordered `After=authselect-apply-changes.service`, or a check inside the module itself at each attempt (cheap: one small file read), that disables the PIN path (module returns `PAM_IGNORE`, so the stock password path still works) when the authselect profile or features leave the allow-list. Fail closed for the PIN, never for the password.
- Compare by content, not by authselect's own "valid" verdict. Since `4c4730e`, `authselect check` does not compare contents, so it cannot tell properpin whether `password-auth` was hand-edited (secureblue, for one, copies files straight into `/etc/authselect`, `secureblue/files/system/usr/libexec/secureblue/securebluecleanup:9-13`).
- Document the update story: on Aurora a modified `kde` freezes against image updates; `check` should diff the stock lines of `/etc/pam.d/kde` (outside properpin's markers) against `/usr/etc/pam.d/kde` on ostree, or against `rpm -q --dump plasma-workspace` digests on classic Fedora, and say so when the base file changed upstream.
- Worth evaluating in the design (an idea, not checked): the second line exists only so the PIN unpause runs after a correct password. If unpausing the PIN already re-verifies the password through `unix_chkpwd`, it could move *below* `auth substack password-auth` and the direct `pam_unix` line could go, which would let `with-faillock`, `with-systemd-homed`, U2F 2FA and sssd apply to the password path again. The PIN line would still bypass whatever `password-auth` enforces, so the refusals above would still be needed for 2FA and smartcard-required.
- Watch Plasma 6.8 on Fedora: if plasma-workspace starts shipping `kde-face` and `kde-u2f`, or moves `kde` to `/usr/lib/pam.d`, `install.sh` must handle a missing `/etc/pam.d/kde` by copying the dist file first (the Arch case in `docs/chaos/competition.md`).

## PIN-like and rate-limiting features seen along the way

- authselect `with-faillock` wraps every stack in `pam_faillock preauth`/`authfail` (`profiles/local/system-auth:3,9`); Linux-PAM's `faillock.conf` documents `deny`, `unlock_time`, `even_deny_root`, `root_unlock_time` (`linux-pam/modules/pam_faillock/faillock.conf:45-55`). It is per-account, not per-credential, so it cannot express "pause the PIN but keep the password", which is properpin's point.
- pam-u2f supports FIDO2 PIN verification (`pinverification`, or `+pin` in the key attributes, `pam-u2f/util.c:897-903`). The PIN and its retry counter are enforced by the token's hardware, which is the strongest PIN-with-lockout design in this set, but it needs a security key and is shared across all services through `password-auth`/`system-auth`.
- google-authenticator-libpam has a per-user `RATE_LIMIT` (N attempts per M seconds) stored in the secret file (`src/pam_google_authenticator.c:1002-1030`).
- authselect's `switchable-auth` stack (sssd, `with-switchable-auth`, `profiles/sssd/switchable-auth:1-19`) and the 2021 addition of `kde` to the smartcard-capable services list are the only lock-screen-aware pieces in authselect; neither involves a PIN.
- Nothing in authselect, Fedora's packaging or the other clones implements a lock-screen-only PIN; that matches `docs/chaos/lockscreen-pin-existing-implementations.md`.

## Verified versus inferred

Verified in code or on this machine: authselect's owned paths, profile lookup order, template operators, feature discovery, overwrite-without-force behaviour and its 2022 origin, the boot-time `apply-changes --upgrade` unit and its enabled state here, the ostree vendor-profile scriptlet and its result here, the profile contents and feature placement, which services include which stack here, plasma-workspace owning the three `kde*` files as `%config(noreplace)` in `/etc`, kscreenlocker shipping none, the 6.8 service names, Linux-PAM's lookup order, and secureblue enabling `with-faillock`.

Inferred and not run: every behavioural statement about properpin's lines under particular authselect features (derived from reading profiles against PAM control semantics), `.rpmnew` handling, the ostree merge behaviour (from the Aurora deployment notes), Fedora libpam having no vendordir (from `strings`), the unsuitability of a vendor profile for later updates (from where the checksum is computed), and what Fedora's 6.8 plasma-workspace will ship.
