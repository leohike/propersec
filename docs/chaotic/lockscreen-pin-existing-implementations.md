---
id: 2610010218EjVCo1bCnt
datetime: 2026 Oct 1, 02:18
ctime: "2026-10-01 02:18:51"
---



As of October 2026 I found no open-source Linux project that does exactly what you described: a lock-screen PIN that is disabled after 3 misses, comes back only after a successful full-password login, and optionally expires after N hours. One small PAM module, **saltnpepper97/pam_pinlock**, gets about 70% of the way there. A TPM-backed module, **RazeLighter777/pinpam**, has the strongest attempt counter. **nuvious/pam-duress** handles the duress part. Upstream desktops (KDE, GNOME, COSMIC) are adding switchable auth methods or PIN keypads, but none of them has a separate PIN credential with lockout and fallback.

## TL;DR
- **No full implementation exists.** The closest is pam_pinlock (C, MIT, release v1.2.1 in June 2026). It already does PIN → fallback to password, rate limiting and an optional timed lockout, and it ships hyprlock/KDE PAM recipes. It does not appear to re-arm after a password success, and it has no PIN expiry and no duress PIN.
- **Best foundations:** (1) fork pam_pinlock and add the re-arm and expiry logic, borrowing the preauth/authfail/authsucc split from pam_faillock; (2) use pinpam's TPM2 PinFail counter if you want the counter to hold up against root; (3) add pam-duress, or a few lines of your own, for the duress-PIN → poweroff/hibernate hook.
- **Upstream status:** KDE merged switchable lock-screen authenticators (kscreenlocker !318 / plasma-desktop !3689 / plasma-workspace !6542, landing in Plasma 6.8, which Phoronix says is due 14 October), but there is no PIN type. GNOME has had an unused `gdm-pin` PAM service and a PIN design page since 2013. COSMIC has a PIN *keypad* PR (#532, Sep 2026) that is UI only. ChromeOS is the one open-source system that implements your exact behaviour, and it is the design to copy.

## Key Findings

### (a) Full or near-full implementations
- **saltnpepper97/pam_pinlock**: github.com/saltnpepper97/pam_pinlock
  - What it does: a separate PIN stored as an Argon2id hash in `~/.pinlock`, or root-managed in `/var/lib/pinlock`. It is meant to sit in the stack as `auth sufficient pam_pinlock.so retries=1` before `system-auth`, so a wrong PIN, or a password typed at the PIN prompt, falls through to the normal password.\[1\]\[2\]
  - Attempt limiting: `max_attempts=5`, `rate_limit_window`, `lockout_window`. There is also an optional `enable_lockout` with `lockout_duration=900`, and `lockout_fails_auth=no` makes it fall back to the password instead of failing.\[1\]\[2\]
  - Gaps against your spec: the README only mentions clearing a lockout by timeout or with `pinlockctl unlock`. There is no sign of re-arming after a successful full password; since pam_pinlock runs *before* pam_unix and returns early, the password success probably never reaches it. I found no expiry option and no duress PIN. I could not check the source code itself, so the reset behaviour is my inference from the README.
  - Lockers: hyprlock and KDE (`/etc/pam.d/kde`) are documented; it works with any PAM locker. It notes that user-run lockers cannot read a root-owned 0700 store.\[2\]
  - Status: C, MIT, 22 commits, release v1.2.1 on Jun 15 2026.\[2\] The AUR package `pam_pinlock` is out of date at 1.0.0.\[3\] There is a fork, nikolainyegaard/pam_pinlock.\[1\] It is small and readable, which makes it the easiest base to fork.
- **RazeLighter777/pinpam**: github.com/RazeLighter777/pinpam
  - What it does: the PIN lives in TPM2 NVRAM and uses the TPM "PinFail" index. The failure counter is write-once, so "even root will be unable to bypass this protection without clearing the TPM." The limit is set with `pin_lockout_max_attempts`. It accepts `try_first_pass`/`use_first_pass`, so a single prompt can take either a PIN or a password. An optional `libpinpam_master_key.so` unlocks KWallet or GNOME Keyring even when you log in with a PIN.\[4\]
  - Gaps: it is the opposite of re-arm-on-password. "A locked out pin must be manually reset by root," and "You cannot reset a lockout without clearing the pin." There is no lockout duration, no expiry and no duress PIN.\[4\]\[5\]
  - Lockers and distros: the NixOS flake has `enableHyprlockPin`, `enableKdePin`, `enableLoginPin`, `enableSudoPin` and `enablePolkitPin`.\[4\] It is also on the AUR as `pinpam-git`.\[6\]
  - Status: Rust, GPL-3.0, 106 commits, v0.0.5 (master-key, swtpm tests), with a dev branch for new work.\[4\] Reuse the TPM counter logic. Its lockout model would need to change: re-create the PinFail index after a password success.

### (b) Partial implementations / pieces worth stealing
- **ChromeOS / ChromiumOS quick unlock** (open source; cryptohome in chromiumos/platform2). This is the reference design for your exact behaviour. Google's chromeos.dev post "Protecting user data in ChromeOS with passwords" says "ChromeOS relies on limiting the number of failed attempts before it completely locks the ability to sign-in with the PIN until a different credential, like password, is provided," and adds that "This attempt-limiting mechanism relies on custom features provided by Titan security modules used in modern Chromebooks." The PIN works on the lock screen only, and the password is required after a reboot.\[7\]\[8\] While a session is mounted, lock-screen checks run against the session object instead of the key material.\[9\] The code is tied to cryptohome, Chrome UI and the PinWeaver/TPM stack, so treat it as a spec rather than something you can lift.
- **pam_faillock** (linux-pam). Not a PIN module, but its preauth / authfail / authsucc pattern is exactly the per-credential counter you need:\[10\] a success line placed after pam_unix resets the PIN counter, which gives you re-arming. Copy the structure, not the module.
- **Classic pam_pwdfile recipe.** This is what you already knew: still circulating in 2025–2026 (for example the Linux Mint forum "Pin instead of Password to unlock screen" thread for cinnamon-screensaver), still with no lockout and no expiry.\[11\]
- **GNOME design page "Design/OS/ScreenLock/PinAuthentication".** Proposes a `gdm-pin` PAM stack with a `pam_gnome_shell_pin` module that uses the PIN as an AES key to decrypt the stored password and pass it down the stack.\[12\] That keeps the keyring unlocking. It is a useful idea for keyring compatibility, but it was never shipped.
- **KeePassXC PR #11520 (quick unlock with PIN fallback).** The PIN is set on first unlock, must be 4–8 digits, and the PIN hash plus a random IV encrypts the database credentials in memory.\[13\] Worth borrowing for UX ideas only.
- **Lock-screen UIs with PIN entry:** DenisKhay/kde-lockscreen (a Plasma 5 lock screen theme with "type-without-focus PIN"),\[14\] micha4w/kde-breeze-pin-sddm (already known), and COSMIC PR #532 (below). All of these are UI only.

### (c) Duress / panic shutdown pieces
- **nuvious/pam-duress**: github.com/nuvious/pam-duress. Duress passwords are each tied to a signed script in `~/.duress` or `/etc/duress.d`. It sits after pam_unix; if any script runs it returns PAM_SUCCESS, otherwise PAM_IGNORE.\[15\] A script containing `systemctl poweroff` or `systemctl hibernate` gives you the duress-PIN → disk-at-rest behaviour. C, LGPL-3.0, 1.4k stars and 43 forks on GitHub, 2 open issues, AUR `pam-duress` 0.3.0-1 (submitted 2025-07-14 by maintainer "blek", built from upstream commit 04e607f9). This is the most mature piece. Note that it is designed to *grant* access while the script runs;\[15\] for your case the script should power off. A lock screen running as the user also needs the global `/etc/duress.d` script and polkit or logind permission to power off.
- **pampanic/pam_panic**: a panic password or panic USB key that securely erases the LUKS header, or does reboot/poweroff (for example `auth requisite pam_panic.so password reboot serious=<UUID>`). It has a PPA (`ppa:bandie/pampanic`).\[16\] It is aimed more at login than lock screens, and the header wipe is destructive.
- **rafket/pam_duress → Lqp1/pam_duress fork**: PBKDF2-hashed user+password pairs that run panic scripts, with an `allow`/`disallow` argument.\[17\] It looks inactive (3 stars, issues disabled, nearby references date to around 2020–21).\[17\]\[18\]
- **Kicksecure emerg-shutdown**: a panic *key sequence* that powers off quickly,\[19\] paired with ram-wipe. Its dev to-do list asks for a configurable delay, including zero.\[20\] It is keyboard-triggered and not PAM-based, but it is a good poweroff path to reuse.
- **Linux Kodachi** (developer Warith Al Maawali; latest release 9.0.1, 26 Feb 2026) is described on Wikipedia as having "Two independent nuke systems, LUKS Nuke at boot and Dashboard Duress Protocol at login," which "ensure data destruction can be triggered using a duress code." This is distro-specific and the description traces back to the project's own feature claims.
- **BusKill** (USB dead-man cable; there is a LUKS self-destruct guide) and the **Kali LUKS nuke** (`cryptsetup-nuke-password`) work at a different layer, unplug or boot, so they are not lock-screen hooks. The Kali nuke installs "a small hook in the initrd" that "will call 'cryptsetup luksErase' on your LUKS container" when the nuke password is typed at boot (according to the Blkzer0/cryptsetup-nuke-keys README, which cites Kali's emergency self-destruction guide). I did not re-check BusKill's 2026 status in this pass.

### (d) Planned / in-progress upstream work
- **KDE kscreenlocker !318 "pam: flexible authenticator support" + plasma-desktop !3689 "lockscreen: implement authenticator switching"** (Harald Sitter). KDE's 22 Aug 2026 post "This Week in Plasma: UI and Performance Improvements" (blogs.kde.org) says Plasma 6.8 lets you "select on the lock screen which authentication type you want to use." It credits Harald Sitter with plasma-desktop MR #3689, plasma-workspace MR #6542 and kscreenlocker MR #318, and says "This is an experimental change that just landed, and there's no GUI yet to set up all the authentication types." Phoronix gives the Plasma 6.8.0 release date as 14 October. Authenticators are switched on in `kscreenlockerrc [Authenticators]` (Smartcard, Fingerprint, Face, Universal2Factor), and each one maps to its own `/etc/pam.d/kde-*` file.\[21\] There is **no PIN type**. This is the natural place to contribute a "PIN" authenticator backed by pam_pinlock or your own module. Bug 411698 is still the wishlist item.
- **GNOME/GDM**: a `gdm-pin` PAM service has existed since 2013, and distros such as Arch and Bluefin still ship `/etc/pam.d/gdm-pin`.\[22\]\[23\]\[24\]\[25\] In a January 2016 gdm-list reply ("Re: [gdm-list] How To: GDM: PAM PIN"), the answer to how to enable PIN authentication was: "You can't. The feature never fully landed, just some prep work for it." The new **`gdm-switchable-auth`** (gnome-shell issue #8513, documented in RHEL 10) lets you switch between Password, Smartcard, Passkey and Web Login using SSSD JSON messages.\[26\]\[27\] A PIN mechanism would fit there but has not been proposed. GDM issue #1043 asks for "different gdm-password functions for first logins and subsequent unlocks," which is your requirement #1/#2 phrased for fingerprint.\[28\]
- **COSMIC**: cosmic-greeter issue #75 is the feature request "Allow secondary easier methods to log in, such as a PIN."\[29\] PR #532 (Sep 3 2026, FreddyFunk) adds a PIN *keypad* and a config to make PIN input the default for postmarketOS. It still checks against the normal password, and the maintainer wants to wait for cosmic-osk integration.\[30\] Issue #547 (delay the PAM conversation until interaction) is related plumbing.\[31\]
- **systemd-homed**: `homectl lock`/`lock-all` on suspend drops the home encryption keys, and a FIDO2 token PIN can unlock it.\[32\]\[33\] It is a credential type, not a separate PIN with fallback. KDE bug 444639 (homed FIDO2 PIN in kscreenlocker) was closed as RESOLVED WORKSFORME.\[34\]

### (e) Dead ends (confirmed)
- **Phosh (Librem 5 / postmarketOS / Mobian)**: the "PIN" *is* the user password. postmarketOS tells you to use a digits-only password, with a keyboard button for non-numeric passwords.\[35\]\[36\] There is no separate credential and no lockout-to-password.
- **Plasma Mobile**: also uses the account password as the PIN, through kscreenlocker.\[37\]
- **Sailfish OS**: the security code has an attempt limit that ends in "This unit has been locked permanently," and the code doubles as the LUKS key. The devicelock plugin (`encsfa-fpd`) is closed source.\[38\]\[39\]\[40\] The idea is useful, the code is not available.
- **swaylock / hyprlock / gtklock / i3lock / xsecurelock**: plain PAM front-ends with no PIN logic. hyprlock's open issues cover prompt start and parallel fingerprint, not PIN.\[41\]\[42\] Use them with a PIN PAM module.
- **Omarchy / Bluefin**: Omarchy's lock screen has a `failedAttempts` counter on the password path, and Bluefin ships `gdm-pin`,\[24\]\[43\] but neither has a PIN feature.
- I did not reach Lomiri/Ubuntu Touch, Deepin, Cinnamon, XFCE, MATE, Budgie or elementary in this pass. Cinnamon only appears through the pam_pwdfile recipe.

## Recommendations
- **Build it as a PAM module, not as locker code**, so it works with every locker. Suggested stack for the lock-screen service only (`/etc/pam.d/kde`, `hyprlock`, `cosmic-greeter`, and so on), leaving login/DM on plain pam_unix:
  - `auth [success=done ignore=ignore default=bad] pam_pin.so check`: refuse the PIN if `fails >= 3`, or if `now − last_password_success > N h`, then return IGNORE so the stack falls through to the password.
  - Duress check inside the same module: if the duress hash matches, run `systemctl poweroff` or `hibernate` and return failure.
  - `auth sufficient pam_unix.so` followed by `auth optional pam_pin.so rearm`: reset the counter and stamp `last_password_success`. This is the faillock authsucc pattern.
- **Fork pam_pinlock** for the hashing, storage, CLI and recipes. Add the `rearm` mode, expiry and duress. Keep the state file writable by the user, since kscreenlocker and hyprlock authenticate as the user, or use a small setuid helper as pinpam does.
- **Optional hardening:** move the counter into pinpam's TPM PinFail index and re-create the index on `rearm`.
- **Upstream path:** propose a "PIN" authenticator for KDE's new switchable-authenticator framework (Plasma 6.8+), and a PIN mechanism for GNOME's `gdm-switchable-auth`.

## Caveats
- I took pam_pinlock's and pinpam's behaviour from their READMEs. I could not open the source files, so "no re-arm on password success" is an inference.
- Some 2026 items, such as the COSMIC PR and the KDE MR state, are recent and may change. The ChromeOS behaviour comes from Google's own descriptions, not from reading the code.
- A user-writable PIN state file can be reset by the user's own processes. That is acceptable for a convenience PIN but matters if you rely on the 3-attempt limit against malware running in the session.

## Sources

1. [GitHub - nikolainyegaard/pam\_pinlock: A PIN based password system for Linux using PAM · GitHub](https://github.com/nikolainyegaard/pam_pinlock)
2. [GitHub - saltnpepper97/pam\_pinlock: A PIN based password system for Linux using PAM](https://github.com/saltnpepper97/pam_pinlock)
3. [AUR (en) - pam\_pinlock](https://aur.archlinux.org/packages/pam_pinlock)
4. [GitHub - RazeLighter777/pinpam: Linux pluggable authentication module for pins, with nixos support](https://github.com/RazeLighter777/pinpam)
5. [GitHub - plugo1/pinpam: Linux pluggable authentication module for pins, with nixos support · GitHub](https://github.com/plugo1/pinpam)
6. [AUR (en) - pinpam-git - Arch Linux](https://aur.archlinux.org/packages/pinpam-git)
7. [How to enable the Chromebook PIN unlock - TechRepublic](https://www.techrepublic.com/article/how-to-enable-the-chromebook-pin-unlock/)
8. [Use Pin Instead of Password on a Chromebook](https://androidexperto.com/use-pin-instead-of-password-on-a-chromebook/)
9. [ChromiumOS Platform - Unlock](https://chromium.googlesource.com/chromiumos/platform2/+/refs/heads/main/cryptohome/docs/decrypt.md)
10. [pam\_faillock on RHEL: Lock Accounts After Failed SSH and Console Logins](https://www.golinuxcloud.com/pam-faillock-lock-user-account-linux/)
11. [\[SOLVED\] Pin instead of Password to unlock screen - Linux Mint Forums](https://forums.linuxmint.com/viewtopic.php?t=459422)
12. [Design/OS/ScreenLock/PinAuthentication](https://wiki.gnome.org/Design/OS/ScreenLock/PinAuthentication)
13. [github.com](https://github.com/keepassxreboot/keepassxc/pull/11520)
14. [GitHub - DenisKhay/kde-lockscreen: Custom KDE Plasma 5 lock screen for Kubuntu 24.04 — rotating backgrounds, fast PAM, type-without-focus PIN](https://github.com/DenisKhay/kde-lockscreen)
15. [GitHub - nuvious/pam-duress: A Pluggable Authentication Module (PAM) which allows the establishment of alternate passwords that can be used to perform actions to clear sensitive data, notify IT/Security staff, close off sensitive network connections, etc if a user is coerced into giving a threat actor a password. · GitHub](https://github.com/nuvious/pam-duress)
16. [github.com](https://github.com/pampanic/pam_panic/blob/db022333e1218c96ce3f4597abf21c5f79e48e72/README.md)
17. [pam duress](https://github.com/Lqp1/pam_duress)
18. [pam\_duress\_debianInst.sh · GitHub](https://gist.github.com/e5a6d9cc3a138ac70603b6fdda7ea588)
19. [Kicksecure - Secure by Default Operating System](https://www.kicksecure.com/)
20. [ToDo for Developers](https://www.kicksecure.com/wiki/Dev/todo)
21. [pam: flexible authenticator support (!318) · Merge requests · Plasma / KScreenLocker · GitLab](https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/318)
22. [\[gdm\] Add gdm-pin service files](https://mail.gnome.org/archives/commits-list/2013-February/msg07113.html)
23. [More GDM Pam configuration · Issue #59477 · NixOS/nixpkgs](https://github.com/NixOS/nixpkgs/issues/59477)
24. [Lock screen shows no password prompt: GNOME Shell 51 unlock dialog loops on mechanism switch, leaking \~25 gdm-session-worker/s until UID 0 hits max\_connections\_per\_user · Issue #1693 · projectbluefin/dakota](https://github.com/projectbluefin/dakota/issues/1693)
25. [Unlock the gnome-keyring when login in from the console (GNOME as DE) / Applications & Desktop Environments / Arch Linux Forums](https://bbs.archlinux.org/viewtopic.php?id=247542)
26. [Chapter 10. Enabling authentication mechanism selection in GDM using SSSD](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/administering_rhel_by_using_the_gnome_desktop_environment/authentication-mechanism-selection-in-gdm)
27. [Multiple authentication mechanisms on Login (#8513) · Issues · GNOME / gnome-shell · GitLab](https://gitlab.gnome.org/GNOME/gnome-shell/-/work_items/8513)
28. [GDM must have different gdm-password functions for first logins and subsequent unlocks (#1043) · Issues · GNOME / gdm · GitLab](https://gitlab.gnome.org/GNOME/gdm/-/work_items/1043)
29. [Feature Request: Allow secondary easier methods to log in, such as a PIN · Issue #75 · pop-os/cosmic-greeter](https://github.com/pop-os/cosmic-greeter/issues/75)
30. [feat: add PIN keypad input by FreddyFunk · Pull Request #532 · pop-os/cosmic-greeter](https://github.com/pop-os/cosmic-greeter/pull/532)
31. [I would like to propose delaying the start of the lock-screen PAM authentication conversation until the user interacts with the lock screen · Issue #547 · pop-os/cosmic-greeter](https://github.com/pop-os/cosmic-greeter/issues/547)
32. [homectl(1) — systemd-homed](https://manpages.opensuse.org/Tumbleweed/systemd-homed/homectl.1.en.html)
33. [homectl](https://www.freedesktop.org/software/systemd/man/latest/homectl.html)
34. [Full Text Bug Listing](https://bugs.kde.org/show_bug.cgi?format=multiple&id=444639)
35. [Phosh - Nura Wiki](https://wiki.nura.eco/wiki/Phosh)
36. [PinePhone Pin/password question](https://forum.pine64.org/showthread.php?tid=13510)
37. [465269](https://bugs.kde.org/show_bug.cgi?id=465269)
38. ["Too many attempts" Permanently locked device - General - Sailfish OS Forum](https://forum.sailfishos.org/t/too-many-attempts-permanently-locked-device/23096)
39. [Encryption of User Data](https://docs.sailfishos.org/Support/Help_Articles/Encryption_of_User_Data/)
40. [Allow to decouple LUKS password from used Security code - Bug Reports - Sailfish OS Forum](https://forum.sailfishos.org/t/allow-to-decouple-luks-password-from-used-security-code/7950)
41. [\[Feature Request\] Initialize pam module on click/enter (screen before password entry) · Issue #562 · hyprwm/hyprlock](https://github.com/hyprwm/hyprlock/issues/562)
42. [\[Feature\] Support parallel unlocking with fingerprint and password · Issue #258 · hyprwm/hyprlock](https://github.com/hyprwm/hyprlock/issues/258)
43. [Lock screen retries fingerprint auth every 250ms with no backoff when the reader is unavailable · Issue #13906 · omacom/omarchy](https://github.com/omacom/omarchy/issues/13906)
