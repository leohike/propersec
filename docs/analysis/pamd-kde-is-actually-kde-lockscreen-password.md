# /etc/pam.d/kde is the lock screen's password service

The question this note answers: what is `/etc/pam.d/kde` for, given that it isn't called "lockscreen", and what else could reach properpin's lines in it. The short answer: on this machine it is the KDE lock screen's password service and nothing else. An honest name would be `kde-lockscreen-password`; `kde` is history, from KDM, the login screen of KDE 3 and 4.

Written on 2026-10-18 on the Fedora 44 machine properpin is developed on (kscreenlocker 6.7.5, plasma-workspace 6.7.5, Plasma Login Manager). Claims are marked: "verified here" (observed on this machine), "verified in git" (the upstream kscreenlocker history in the reference clone at `/var/home/shared/projects/pam-related/kscreenlocker`, at `e77531ae`, 2026-10-09), "online" (the sources at the end), or "guessed" (reasoned, not checked). `docs/analysis/kscreenlocker-pam-service.md` covers how the lock screen opens its services in detail.

## The short version

- Only the lock screen opens `kde` on this machine, and only for the password (verified here). Fingerprint, smart card, and from Plasma 6.8 face and U2F each have a service of their own.
- The first login after boot, `sudo`, polkit, SSH and the TTY use other files, so the PIN never reaches them (verified here).
- The name comes from KDM, which used `kde` as KDE's common PAM service; the screen locker kept it when KDM was dropped in 2014 (online, and verified in git).
- properpin's lines belong in `kde` and nowhere else. Putting them into `password-auth` would offer the PIN to SSH and Samba.

## Who opens kde on this machine

Verified here:

- `rpm -qf` says `/etc/pam.d/kde`, `/etc/pam.d/kde-fingerprint` and `/etc/pam.d/kde-smartcard` belong to `plasma-workspace-6.7.5-1.fc44`.
- No file in `/etc/pam.d` or `/usr/lib/pam.d` pulls `kde` in with `include` or `substack`.
- Every program and library under `/usr/bin`, `/usr/sbin`, `/usr/libexec` and `/usr/lib64` that links libpam was searched for the bare string `kde`, both as plain text and as UTF-16, the way Qt stores string literals (a plain-text search alone misses them). Only `/usr/libexec/kscreenlocker_greet`, from `kscreenlocker-6.7.5-1.fc44`, has it, as UTF-16, next to `kde-fingerprint` and `kde-smartcard`. The only plain-text hit, in `qemu-system-x86_64`, has nothing to do with PAM.
- The PAM services on this machine are, in `/etc/pam.d`: `chfn chsh config-util cups fingerprint-auth kcheckpass kde kde-fingerprint kde-smartcard kscreensaver ksu login other passwd password-auth postlogin ppp remote runuser runuser-l samba smartcard-auth sshd sssd-shadowutils su su-l sudo sudo-i switchable-auth system-auth vlock vmtoolsd vpnc vpnc-disconnect xserver`; and in `/usr/lib/pam.d`: `plasmalogin plasmalogin-autologin plasmalogin-greeter polkit-1 systemd-run0 systemd-user`.

The search has limits: it covers what is installed today, and only names written out literally. A program could build the name at run time, and a future component, or a third-party app, could open `kde` too.

## The lock screen's services

| Service | Used for | Since |
|---|---|---|
| `kde` | The password, and anything else typed | KDE 3 and 4 as KDE's common service; hard-coded in the greeter until Plasma 6.0, a build option (`KSCREENLOCKER_PAM_SERVICE`, default `kde`) since |
| `kde-fingerprint` | A fingerprint reader, through `pam_fprintd` | Plasma 6.0 (commit `adfae584`, "Run multiple PAM sessions at once", 2023-10-26, first tag `v5.27.80`; verified in git) |
| `kde-smartcard` | A smart card | Plasma 6.0, the same commit |
| `kde-face` | Face recognition, such as Howdy | Plasma 6.8 (commit `a5ed9ca0`, "pam: flexible authenticator support", 2026-08-18, first tag `v6.7.90`; verified in git) |
| `kde-u2f` | A U2F security key | Plasma 6.8, the same commit |

From 6.8 each of the four extra services can be renamed, or turned off with the value `disabled`, when kscreenlocker is built (`KSCREENLOCKER_PAM_FINGERPRINT_SERVICE`, `KSCREENLOCKER_PAM_SMARTCARD_SERVICE`, `KSCREENLOCKER_PAM_FACE_SERVICE`, `KSCREENLOCKER_PAM_UNIVERSAL2FACTOR_SERVICE` in `greeter/worker/CMakeLists.txt`; verified in git). In 6.8 PAM also moves out of the greeter into a separate `kscreenlocker_worker` process.

Who ships the files differs between distributions: on Fedora, `plasma-workspace` puts them in `/etc/pam.d` (verified here); Arch and openSUSE ship them with kscreenlocker itself, in `/usr/lib/pam.d`, openSUSE "to not depend on a display manager being installed" (online).

## U2F and smart cards, briefly

- **U2F** ("Universal 2nd Factor") is a USB or NFC security key, such as a YubiKey. You plug it in and touch it; it holds a private key that never leaves the device. On Linux it works through `pam_u2f`, and at the lock screen it would mean "touch your key to unlock".
- **A smart card** is a chip card the size of a bank card, such as a company or government ID badge, holding a private key and a certificate. You put it in a reader and type the card's own PIN, which the card checks itself. Business laptops (ThinkPad, Latitude, EliteBook) often have an optional built-in slot, usually a USB device inside; other machines use an external USB reader. A USB token, such as a YubiKey in PIV mode or a Nitrokey, is card and reader in one stick, and the system sees it as a smart card. Some cards are contactless, with an NFC reader. On Linux all of them go through `pcscd`, and then PAM through `pam_pkcs11` or `sssd`.

## History

- **KDE 3 and 4, the 2000s to 2014.** `kde` was KDE's common PAM service. KDM, the login screen, used it, with a second service, `kde-np`, for automatic login without a password (online). The screen saver could use the same service or its own, usually `kscreensaver`, and checked passwords through `kcheckpass`, a small helper that ran with root rights, since checking a password needed root then. Build options could rename the services: kscreenlocker's `README.pam` still read, in 2016, "If PAM is found, KDE usually uses the PAM service "kde". You may override it for all KDE programs by using -DKDE4_COMMON_PAM_SERVICE=<service> and/or individually by using -DKSCREENSAVER_PAM_SERVICE=<service>. This was because other programs used to use PAM as well, like kdm.", and warned that misconfigured services mean "you will NOT be able to login via KDM and/or unlock a locked screen!" (verified in git, commit `e5727039`).
- **2014, Plasma 5.** KDM was dropped, and KDE recommended SDDM, which has its own `sddm` services (online: Wikipedia, Phoronix on 2014-11-03, David Edmundson's blog); Fedora 21 switched as well. The same year the lock screen was split out of the monolithic kde-workspace into kscreenlocker (the repository's first commit, "Initial import from the monolithic kde-workspace.", 2014-03-31; verified in git), and `kde` stayed with it.
- **2022, Plasma 5.25.** `kcheckpass` was removed and PAM moved into the lock screen's own process, on a thread: "historically we needed to be root to check passwords. This hasn't been true for tens of years" (online, MR 59; commit `132adacf`, "Cleanup kcheckpass", 2022-05-05, first tag `v5.24.90`, verified in git).
- **Plasma 6.0, early 2024.** The service name became the build option `KSCREENLOCKER_PAM_SERVICE`, default `kde`; until then the greeter used "kde" whatever the old options said (online, MR 131; commit `b932e60d`, 2023-03-03, first tag `v5.27.80`, verified in git). Fingerprint and smart card arrived as authenticators running beside the password, with `kde-fingerprint` and `kde-smartcard`.
- **2026.** Fedora 44 replaced SDDM with Plasma Login Manager, a fork of SDDM with its own `plasmalogin`, `plasmalogin-greeter` and `plasmalogin-autologin` services (online; verified here). Plasma 6.8 moves PAM into `kscreenlocker_worker` and adds `kde-face` and `kde-u2f` (verified in git).

Two leftovers on this machine: `/etc/pam.d/kscreensaver` and `/etc/pam.d/kcheckpass`, both from `kde-settings-44.0-1.fc44` and both `auth include system-auth` (verified here). Nothing installed opens them.

## Login, sudo and the rest

- **The first login after boot** goes through Plasma Login Manager's `plasmalogin`, not `kde`, so the PIN doesn't work there and the full password is needed (verified here as far as files go: the `plasmalogin` services are in place, and nothing but the lock screen names `kde`). Once logged in, every lock, the first after a reboot included, goes through `kde`, where the PIN works. With automatic login turned on (`plasmalogin-autologin`), no password is asked at login at all; properpin doesn't change that either way.
- **`password-auth` is shared.** On this machine `cups`, `kde`, `ppp`, `vmtoolsd`, `remote`, `samba` and `sshd` pull it in; `sudo`, `su`, `login`, `passwd`, `chfn`, `chsh`, `vlock`, `kscreensaver`, `kcheckpass` and `config-util` pull in `system-auth` instead (verified here). properpin's lines in `password-auth` would offer a short PIN to SSH and Samba, over the network. Both files are also authselect's: symlinks into `/etc/authselect/`, which authselect regenerates, so lines added there could silently disappear.
- **A second safety net.** The module refuses to run as root, and `sshd`, `sudo`, `su` and `login` check passwords as root, so even a line put into one of them by mistake would refuse the PIN. The container test checks the PIN refused by `sudo`, `su`, `login`, `system-auth`, `password-auth`, `passwd` and `other`.

## What if properpin's lines went into plasmalogin

Checked on 2026-10-18; `docs/why-not-loginscreen.md` has the details and the reasons properpin stays off the login screen.

- **Only graphical login would be reached** (verified here). Among the programs that link libpam, only `/usr/libexec/plasmalogin-helper` names `plasmalogin`, and no PAM file pulls it in. `sudo`, `sshd`, polkit, `run0` and the text console (`agetty` → `/bin/login` → `login` → `system-auth`) read their own files.
- **The PIN wouldn't work at login** (verified here). `plasmalogin-helper` checks the password as root, and both the module ("running as root; properpin belongs in the lock screen's stack only") and the pinchecker ("refused: root has no lock screen to unlock") refuse root. The PIN would always be refused, the password would still work, and each login would log an error.
- **Making it work** would need the pinchecker to accept a user name from root, would leave the wallet locked (`pam_kwallet` needs the real password at login), and would mean an `/etc/pam.d/plasmalogin` that hides Fedora's `/usr/lib/pam.d/plasmalogin` (reasoned).

## A possible hardening

The module could ask libpam which service called it, and refuse anything but `kde`, an idea already in `docs/analysis/summary.md`. That would close the gap the search above can't: a future component, or another program, opening `kde`, or the lines copied into another file. A distribution that renamed the service with `KSCREENLOCKER_PAM_SERVICE` would then need the module's expected name changed too. Not built as of 2026-10-18.

## Sources

- [KDE Display Manager (Wikipedia)](https://en.wikipedia.org/wiki/KDE_Display_Manager)
- [SDDM Is The Recommended Display Manager Of KDE Plasma 5 (Phoronix)](https://www.phoronix.com/news/MTgyOTU)
- [Display Managers In Plasma 5 (David Edmundson)](https://blog.davidedmundson.co.uk/blog/display-managers-in-plasma-5/)
- [Fedora change: SDDM instead of KDM](https://fedoraproject.org/wiki/Changes/SDDMinsteadOfKDM)
- [Fedora change: Plasma Login Manager](https://fedoraproject.org/wiki/Changes/PlasmaLoginManager)
- [Arch Wiki: Plasma Login Manager](https://wiki.archlinux.org/title/Plasma_login_manager)
- [Gentoo bug 33690, KDM autologin and kde-np](https://bugs.gentoo.org/33690)
- [FreeBSD ports commit installing kde-np](https://code.fizz.buzz/mirror/freebsd-ports/commit/1f49a8777b09e48cd56d3d0b1d1448752ce87537)
- [kscreenlocker MR 59, dropping kcheckpass](https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/59)
- [kscreenlocker MR 131, the configurable service name](https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/131)
- [kscreenlocker MR 318, flexible authenticator support](https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/318)
- [Arch kscreenlocker file list](https://archlinux.org/packages/extra/x86_64/kscreenlocker/files/)
- [openSUSE kscreenlocker6 spec](https://src.opensuse.org/pool/kscreenlocker6/src/branch/devel/kscreenlocker6.spec)
