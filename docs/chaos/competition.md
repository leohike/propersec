# Competition

What else gives a Linux desktop a PIN, and how properpin compares, written on 2026-10-15. It brings together a web search made that day and the wider sweep of 2026-10-01 in `docs/chaos/lockscreen-pin-existing-implementations.md`, which has more detail, the duress tools and the full source list. The point is positioning: anyone advanced enough to try properpin will ask "why not pinpam?" or "why not two lines of `pam_pwdfile`?", and the README should answer before they ask. Behaviour of other projects is taken from their READMEs and posts, not their source code, unless said otherwise.

## The short answer

Nothing else does what properpin does: a PIN for the lock screen only, paused after three consecutive failures until a password unlock, with the user's own typos forgiven, other people's failures limited over days and in total, and the hash out of reach of everything the user runs. The closest projects either limit attempts well but let the PIN work everywhere (pinpam, libpamtpmpin), or work at the lock screen with a timed lockout but nothing that brings the password back in (pam_pinlock). Until 2026-10-16 properpin also refused the PIN after every reboot and after 8 hours, and peppered its hash; `docs/chaos/security-target.md` says why those went. The hand-made `pam_pwdfile` recipe has none of it. Upstream desktops have the plumbing for switchable authenticators, but no PIN.

## The hand-made recipe: pam_pwdfile

The most common thing people actually run, found in threads on the Arch, CachyOS, Kubuntu, EndeavourOS, Linux Mint and FreeBSD forums. The PIN is hashed with `openssl passwd` (MD5 or SHA-512 crypt), stored as `user:hash` in a file such as `/etc/pin.passwd`, and checked by a line at the top of the lock screen's PAM file, `/etc/pam.d/kde` on KDE:

```
auth  sufficient  pam_pwdfile.so pwdfile=/etc/pin.passwd
auth  sufficient  pam_unix.so try_first_pass likeauth nullok
auth  requisite   pam_deny.so
```

As the Arch post puts it, this tells the locker "to check the input with your pin password first, but still allows unlocking on your user password". The threads are mostly about getting it to work at all: the PIN works at SDDM but not at the lock screen, because the lock screen has its own PAM service; on Arch-based systems the file has to be copied from `/usr/lib/pam.d/kde` to `/etc/pam.d/kde` first; Kubuntu 23.04 doesn't use the `kde` service name.

Against properpin's threat model (`docs/chaos/security-target.md`):

- **No attempt limit.** Someone at the keyboard can guess forever, slowed only by pam_unix's failure delay.
- **Always accepted,** right after a reboot too; nothing ever asks for the password again.
- **A cheap hash.** A four-digit PIN behind an MD5 or SHA-512 crypt falls offline in moments, from a backup, a disk image, or straight away if the file is readable by others. One Arch commenter called it "an extraordinary way to lower the bar".
- **Easy to lock oneself out,** with nothing that repairs a broken PAM file.

These users are properpin's clearest audience: they already want a PIN and accepted editing PAM to get one.

One more point, unverified: a crypt check takes only a few milliseconds, so if kscreenlocker 6.8 treats answers under 50 ms as coming from a broken authenticator, as `docs/chaos/kscreenlocker-pam-contract.md` reads it, these setups may stop working with Plasma 6.8. Check on the 6.8.0 tag before saying so publicly.

## pinpam

github.com/RazeLighter777/pinpam. The most visible competitor: a Show HN post about a year ago, an AUR package (`pinpam-git`), a NixOS flake, and a Fedora Discussion thread from March 2026 tagged for the security SIG, the Workstation working group, FESCo and the KDE team. Rust (built on rust-tss-esapi), GPL-3.0, about 27 stars and 10 forks, version 0.0.5.

- **The PIN lives in TPM2 NVRAM,** guarded by the TPM's PinFail index: the TPM itself counts failures, and the counter is write-once, so "even root will be unable to bypass this protection without clearing the TPM".
- **Locks out for good** after `pin_lockout_max_attempts` failures (5 in the example). "A locked out pin must be manually reset by root", and a lockout can't be reset without clearing the PIN. No lockout duration, no expiry.
- **Works with any PAM service:** the flake has switches for the KDE lock screen, hyprlock, login, sudo and polkit. It recommends `sufficient` with a password fallback.
- **An experimental master-key module** puts a TPM-bound token into `PAM_AUTHTOK`, so KWallet or GNOME Keyring unlock at a PIN login, once the wallet is re-keyed to that token.
- **Installing** needs the `tss` group, udev rules and a setgid or setuid `pinutil` outside NixOS; polkit may need manual setup.

## libpamtpmpin

github.com/0xr0bert/libpamtpmpin. Also Rust and TPM2, unrelated to pinpam: two NV indexes per user (a counter, and the PIN behind a PolicyNV), 5 tries by default, a `tpmpin` admin tool and a setuid `tpmpin-unblock-self` pinchecker. Its `unblock_on_success` option resets the counter after a successful login by other means, which is close to properpin's password unlock unpausing the PIN, and its own README warns that it weakens the lockout. On the AUR; 1 star.

## pam_pinlock

github.com/saltnpepper97/pam_pinlock. C, MIT, release 1.2.1 in June 2026, with an AUR package and a fork. Found in the 2026-10-01 sweep, which calls it the closest to properpin's rules.

- **An Argon2id hash** in `~/.pinlock`, or root-managed in `/var/lib/pinlock`. In the user's home, anything the user runs can read the hash, the insider leak `docs/chaos/threat-insider-hash-leak.md` describes.
- **Rate limiting and an optional timed lockout** (`max_attempts`, `rate_limit_window`, `lockout_duration=900`), cleared by time or `pinlockctl unlock`, with a fallback to the password.
- **No sign of the password resetting the PIN's failures,** no expiry, and nothing on reboots: since it returns before `pam_unix` runs, a password success probably never reaches it. Inferred from the README.
- **Documented for hyprlock and KDE,** and usable with any PAM locker.

## Upstream desktops

- **KDE.** Plasma 6.8 brings switchable lock screen authenticators (kscreenlocker !318, plasma-desktop !3689 and plasma-workspace !6542, by Harald Sitter): the user picks the authentication type at the lock screen, each type maps to its own `/etc/pam.d/kde-*` file, and they are switched on in `kscreenlockerrc` under `[Authenticators]` (smartcard, fingerprint, face, U2F). There is no PIN type, and no settings GUI yet. Bug 411698 is the open wishlist item for a PIN. This framework is the natural home for a PIN authenticator upstream, and it may change how properpin should plug in, since today properpin assumes the PIN and the password share one field in the `kde` service; check it against the 6.8.0 tag together with the 50 ms check.
- **GNOME.** A `gdm-pin` PAM service has shipped since 2013 and still exists on Arch and Bluefin, but the feature "never fully landed". The design page (now archived) limited the PIN to graphical login and unlock, never polkit, with the PIN decrypting the stored password to pass down the stack, and said a PIN "should be treated like auto-login from a security perspective" unless a TPM backs it. GDM's new `gdm-switchable-auth` has no PIN mechanism.
- **COSMIC.** A PIN keypad pull request (cosmic-greeter #532, September 2026), UI only: it still checks the normal password.
- **ChromeOS.** The one open-source system with properpin's behaviour: a PIN for the lock screen only, the password required after a reboot, and a limited number of failures before the password is required, backed by the Titan security chip. Tied to cryptohome and Google's hardware, so a design reference rather than code to reuse.
- **Windows Hello** is the PIN most users know, but a different model: the PIN unlocks a TPM-held key and works at sign-in after a reboot too.

## Side by side

| | properpin | pinpam | libpamtpmpin | pam_pinlock | pam_pwdfile recipe |
|---|---|---|---|---|---|
| Where the PIN works | The lock screen only | Any service configured, sudo included | Any service configured | Any service configured | Any service configured |
| After a reboot | Works | Works | Works | Works | Works |
| A password unlock resets the failures | Yes, the consecutive ones; never the budget | No | Optional, weakens the lockout | No, as far as the README says | Not applicable |
| Failure limits | 3 consecutive, then the password; your own typos forgiven; 10 a day, 25 a week, 60 per PIN disable it | 5, then locked until root clears the PIN | 5 by default | Rate limit, optional timed lockout | None |
| Who holds the counter | A setgid pinchecker's group; root can reset it | The TPM; root can't, short of clearing it | The TPM | A file | Nobody |
| A stolen hash | Out of reach of everything the user runs; a copy falls in seconds for a short PIN | Inside the TPM | Inside the TPM | Argon2id, crackable for short PINs | Fast crypt, falls in moments |
| Needs a TPM | No | Yes | Yes | No | No |
| Unlocks KWallet | No | Experimental | No | No | No |
| Packaged | Not yet | AUR, NixOS | AUR | AUR | Distribution packages of `pam_pwdfile` |

## What it means for properpin

- **The answer to "why not pinpam?"** is scope and lifetime. A PIN that works for `sudo` and polkit gives root to whoever watches it being typed; properpin's PIN unlocks the lock screen and nothing else, and only within hours of a password unlock. pinpam's TPM counter is stronger than anything properpin has, and the README should say so honestly; the plan's TPM-backed counter row is where properpin would close that gap.
- **The answer to "why not pam_pwdfile?"** is every bullet in its section above, and a tested way back out.
- **Talk to pinpam's author.** Two Rust PAM PIN modules exist; whether the right outcome is sharing code (the TPM counter as an option for properpin, the rules for when to accept the PIN as an option for pinpam) or two tools for two threat models, it is a better story to tell KDE than two strangers working in parallel.
- **KDE's authenticator framework** is the upstream opening, and also a compatibility question for 6.8; both belong with the 6.8 work in `docs/chaos/before-anybody-uses-this.md` and `docs/chaos/borrow-kde-tests.md`.
- **Keyring unlocking** is the one feature both pinpam and GNOME's design treat as part of the job and properpin doesn't. At the lock screen KWallet is already open, so it matters less for properpin's scope; worth one sentence in the README.

## Sources

- CachyOS, trying to add a PIN with pam_pwdfile: https://discuss.cachyos.org/t/trying-to-add-a-pin-code-using-pam-pwdfile/20072
- Arch Linux forums: https://bbs.archlinux.org/viewtopic.php?id=246734
- Kubuntu forums, PIN unlock set up but password still asked: https://www.kubuntuforums.net/forum/currently-supported-releases/kubuntu-23-04-lunar-lobster/desktop-environment-support-ab/671681-set-up-pin-unlock-but-password-authentication-still
- EndeavourOS, PIN unlocking for GNOME or KDE: https://forum.endeavouros.com/t/whats-the-best-way-to-set-an-pin-number-unlocking-for-my-password-for-logging-into-desktop-for-either-gnome-or-kde/21101
- FreeBSD forums, Enlightenment screen lock: https://forums.freebsd.org/threads/enlightenment-screen-lock-password.38385/post-212796
- pinpam: https://github.com/RazeLighter777/pinpam
- Show HN, pinpam: https://hn.svelte.dev/item/45721417
- Fedora Discussion, pinpam and pinutil: https://discussion.fedoraproject.org/t/pinpam-and-pinutil-pam-module-for-pin-auth-with-tpm2/182199
- libpamtpmpin: https://github.com/0xr0bert/libpamtpmpin
- pam_pinlock: https://github.com/saltnpepper97/pam_pinlock
- GNOME PIN design page: https://wiki.gnome.org/Design/OS/ScreenLock/PinAuthentication
- The 2026-10-01 sweep, with the KDE, COSMIC and ChromeOS sources: `docs/chaos/lockscreen-pin-existing-implementations.md`
