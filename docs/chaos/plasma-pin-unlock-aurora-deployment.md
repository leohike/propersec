---
id: 2609302355gXAkQH6q4F
datetime: 2026 Sep 30, 23:55
ctime: "2026-09-30 23:55:30"
---



**Recommendation: build the "gated PIN" yourself, but use pam_exec plus one small root-owned script instead of pam_pwdfile, edit only `/etc/pam.d/kde`, keep the state in `/run/user/$UID`, and bake it into your custom Aurora image once it works.** Nothing upstream does this today. KDE's feature request for a separate lock-screen PIN is still open, and every existing guide uses a plain `sufficient pam_pwdfile.so` line, which gives you a PIN but no timeout or lockout. Your proposed design (gate → PIN → fall back to the password → reset hook) is sound, with the corrections below. Most of the security risk is in the parts you already accept (a running, disk-unlocked machine), not in the PIN.

## TL;DR

- **It's doable and safe enough if you scope it tightly.** Put the gate, the PIN check, a failure counter and a reset hook in `/etc/pam.d/kde` only, the service kscreenlocker uses. Login (LUKS + SDDM), sudo and polkit keep the full password. Lock-screen PAM runs *as your user*, so the PIN hash and state are readable by your own processes. That's acceptable, because any process running as you can already unlock your session. The protection comes from the 3-strikes lockout and the N-hour expiry, not from the hash.
- **Skip pam_pwdfile on Aurora.** I found no pam_pwdfile in Fedora's repos: upstream is archived, and the only Fedora builds are unsupported OBS packages for F39/F40. A pam_exec script with `expose_authtok` plus `openssl passwd -6` does the same job with nothing to layer. `/etc` is writable and survives updates via ostree's 3-way merge, and `/usr/local` maps to `/var/usrlocal`.
- **Better hardware-backed options exist.** A FIDO2 key (pam_u2f) or fingerprint (the built-in `kde-fingerprint` service) gives you rate limits enforced by hardware, the Windows Hello model. Both can sit behind the same N-hour gate script. A Plasma change for switchable authenticators (kscreenlocker MR !318) is in progress but has no PIN type.

## Key Findings

### What already exists (all partial)

- **The pam_pwdfile "PIN" recipe is the de-facto standard, and it's minimal.** Guides on the Arch forums (i3lock), Ubuntu/GDM, Linux Mint (cinnamon-screensaver), CachyOS and a KDE-specific blog (fancypi.cn) all add one line such as `auth sufficient pam_pwdfile.so pwdfile=/etc/kde_unlock_pin` before the normal auth lines.\[1\]\[2\]\[3\]\[4\] The full password still works because the normal stack follows.\[1\] None of them has an expiry or a failure lockout.
  - Some recipes hash the PIN with `openssl passwd -1` (MD5-crypt).\[4\] That's weak, and a CachyOS user reported the fancypi command "did not work as expected".\[5\]
- **Upstream KDE has no feature for this.**
  - Bug 411698, "Allow setting custom password/PIN just for the screen locker", is CONFIRMED (wishlist), and duplicates such as 477758 were merged into it in June 2025. In 477758 the reporter describes the same pwdfile hack, edited into `/usr/lib/pam.d/kde`, and asks for a PIN prompt and a "use full password" button.\[6\]\[7\]
  - An earlier request (472297) was closed RESOLVED INTENTIONAL in 2023.\[8\]
  - A KDE Discuss Brainstorm thread ("PIN Code to unlock screen") points to bug 411698 and says it "will just require someone with the time, ability and interest to jump in and figure out how to implement"; it also links micha4w/kde-breeze-pin-sddm, an edited Breeze theme with a numeric PIN input.
- **Upstream is moving toward pluggable authenticators, but not PINs.**
  - kscreenlocker MR !318, "pam: flexible authenticator support" by Harald Sitter (opened Apr 30 2026, edited Aug 13 2026), lets the user pick between active authenticators (password, face/howdy, u2f, smartcard) through `~/.config/kscreenlockerrc` `[Authenticators]`, with fingerprint as a secondary option.\[9\]
  - Its companion plasma-workspace and plasma-desktop MRs are marked merged.\[9\] Watch it, but it defines no PIN authenticator and no expiry logic.
- **Rust fork of pwdfile.** libpam-pwdfile-rs (LiAlH4qwq fork, v0.4.2) adds yescrypt hashes, an RPM spec you build yourself, and a "SUID helper — Works with non-root PAM clients". Its examples target polkit and sudo,\[10\] which you should avoid for this use case. It's a one-person project, so check it carefully before relying on it.
- **Alternatives that solve the same problem:**
  - **FIDO2/YubiKey (pam_u2f):** works in `/etc/pam.d/kde` with a per-user authfile (`authfile=./.u2f_key`). A root-only system-wide mapping file failed from kscreenlocker; it had to be world-readable.\[11\] ArchWiki: for 1FA with a biometric key, use `kde-fingerprint` so no extra "Unlock" button appears. It also warns: "Do not use auth sufficient in /etc/pam.d/kde-fingerprint … This will cause failed authentication attempts to bypass the lock screen."\[12\]
  - **Fingerprint:** Plasma 6 runs `kde-fingerprint` in parallel with the password field (kscreenlocker MR !163, "run multiple pam sessions at once", fixed in 6.0).\[13\]\[14\] There are known quirks: vinoAuthFace issue #32 notes that "Plasma < 6.7 has a bug where a biometric unlock trips faillock (kscreenlocker 29d01bf7)", and mhdez.com's guide describes successful scans counted as failed attempts, locking the account for about 10 minutes after three within 15 minutes; users worked around it with `max-tries`/faillock tweaks.
  - **Face (howdy, vinoAuthFace on Atomic):** exists, but is weaker than a PIN against a determined attacker.
  - **How they fit your requirements:** none of them does "full password every N hours" by itself. You can put the same pam_exec gate in front of `pam_u2f` or `pam_fprintd`.

### How kscreenlocker uses PAM in Plasma 6

- **Services.** The default service is `kde`, and kscreenlocker "only uses the 'auth' entries".\[15\]\[16\] Plasma 6 also starts `kde-fingerprint` and `kde-smartcard` up front, non-interactively, in parallel with the password field.\[17\]
  - Arch's kscreenlocker 6.7.3 package ships all three as vendor files in `/usr/lib/pam.d/`.\[18\]
  - On Fedora, `kde` is `auth substack password-auth` + `auth include postlogin` (same for `kde-fingerprint` with `fingerprint-auth`), matching the template in MR !163.\[14\]\[19\]
  - Files in `/etc/pam.d/` override same-named files in `/usr/lib/pam.d/`, per pam(8).\[20\]\[21\]
- **PAM runs as your user, not root.** "kscreenlocker_greet runs as the session user as opposed to root" (yubico-pam #113),\[22\] and projects like vinoAuthFace had to add set-group-ID helpers because of it.\[23\] Consequences:
  - pam_exec runs its command "with the real user ID of the calling process", so your gate script runs as you.\[24\]
  - Every file the PIN path reads must be readable by you. A root-only file fails silently, as shown by the pam_u2f 640-permissions test.\[11\]
  - pam_unix checks the real password through the setuid `unix_chkpwd` helper. If that helper loses its setuid bit, the lock screen rejects correct passwords (Arch forum).\[25\]
- **Unlock-button quirk.** If authentication succeeds without any prompt, Plasma shows an extra "Unlock" button (bug 455712 and duplicates).\[26\] Your design always prompts, so this won't happen, but don't build a PIN-less "auto" path.
- **Recovery.** If the locker breaks, log in on a VT and run `loginctl unlock-session <id>`.\[27\] That's also proof that any process running as you can unlock your own session, which matters for the threat model below.
- **Testing.** Arch users test with `kscreenlocker_greet --testing`\[25\] (on Fedora the binary lives under `/usr/libexec`).\[26\] The authoritative test is still a real lock with a root shell open on a VT.

## Details: a corrected design

### Problems in the original sketch and fixes

- **Don't hang the reset hook after `substack password-auth`.** `substack` is itself the control value; it can't be given a `[success=… default=…]` clause (a real Fedora 44 regression in another project, tinkero #46).\[28\] A plain `optional` line after it runs even when the password failed, so the reset would fire on wrong passwords. Fix: call `pam_unix.so` directly with `[success=ok default=die]`, then the reset hook.
- **pam_faillock would lock the whole account, not just the PIN.** If `with-faillock` is enabled in your authselect profile, `password-auth` includes pam_faillock.\[29\] Wrong PINs that fall through to pam_unix then count as account failures and can lock out your full password too.
  - Calling pam_unix directly keeps the lock screen out of faillock. Your own counter does the 3-strikes logic for the PIN only, and pam_unix still adds its built-in failure delay, which its man page describes as "of the order of two seconds".
- **The SDDM reset hook must not run as root inside a user-writable directory.** A root process writing `/run/user/$UID/…` can be tricked by symlinks. Drop privileges with `setpriv` before writing, as in the script below, and use `optional` control so a hook failure can never block login.
- **Fail closed.** No state file, a different boot ID, a counter ≥ 3, an age ≥ N hours, or any script error all mean "PIN disabled": the gate skips the PIN lines and pam_unix asks for the full password. The full password always works.
- **Where the state lives.** Use `/run/user/$UID` (tmpfs, owned by you, wiped at reboot and at your last logout). Also store the boot ID, so a copied or stale file can't re-enable the PIN.
  - Wall-clock skew only shortens or lengthens the window. Someone at the keyboard can't change the clock without first unlocking.

### `/usr/local/libexec/pinlock` (root:root, 0755)

```bash
#!/bin/bash
# pinlock gate|check|fail|reset  — lock-screen PIN helper (runs as the user under kscreenlocker)
set -u; umask 077
MAX_AGE=$((8*3600)); MAX_FAIL=3
user="${PAM_USER:-$(id -un)}"; uid=$(id -u "$user") || exit 1
# never let root write into the user's tmpfs: drop to the user first
if [ "$(id -u)" = 0 ]; then
  exec setpriv --reuid="$uid" --regid="$(id -g "$user")" --init-groups -- "$0" "$@"
fi
state="/run/user/$uid/pinlock"; now=$(date +%s); boot=$(cat /proc/sys/kernel/random/boot_id)
last=0; fails=99; sboot=""
[ -r "$state" ] && read -r last fails sboot < "$state"
save() { printf '%s %s %s\n' "$1" "$2" "$boot" > "$state.tmp" && mv -f "$state.tmp" "$state"; }
case "${1:-}" in
  gate)  [ "$sboot" = "$boot" ] && [ "$fails" -lt "$MAX_FAIL" ] || exit 1
         age=$((now - last)); [ "$age" -ge 0 ] && [ "$age" -lt "$MAX_AGE" ] || exit 1 ;;
  check) pin=""; IFS= read -r -d '' pin || [ -n "$pin" ] || exit 1   # from expose_authtok
         hash=$(cut -d: -f2- "/etc/pinlock/$user" 2>/dev/null) || exit 1
         salt=$(printf '%s' "$hash" | cut -d'$' -f3)
         try=$(printf '%s' "$pin" | openssl passwd -6 -salt "$salt" -stdin) || exit 1
         [ -n "$hash" ] && [ "$try" = "$hash" ] || exit 1 ;;
  fail)  [ "$sboot" = "$boot" ] && save "$last" $((fails + 1)) ;;
  reset) save "$now" 0 ;;
  *) exit 1 ;;
esac
```

- **Creating the PIN:** `printf '%s:%s\n' "$USER" "$(openssl passwd -6)" | sudo tee /etc/pinlock/$USER`, then `sudo chown root:$USER /etc/pinlock/$USER && sudo chmod 0640 /etc/pinlock/$USER`. The file is readable only by you (the greeter runs with your group) and writable only by root.
- **Verify the stdin format on your system.** The man page only says the command "can read the password from stdin".\[30\] `read -d ''` handles both a trailing NUL and plain EOF. The PIN never appears in argv because `printf` is a shell builtin piped to `openssl -stdin`.

### `/etc/pam.d/kde`

```
#%PAM-1.0
auth     [success=ignore default=2]  pam_exec.so quiet /usr/local/libexec/pinlock gate
auth     [success=done default=ignore] pam_exec.so quiet expose_authtok /usr/local/libexec/pinlock check
auth     optional                    pam_exec.so quiet /usr/local/libexec/pinlock fail
auth     [success=ok default=die]    pam_unix.so try_first_pass
auth     optional                    pam_exec.so quiet /usr/local/libexec/pinlock reset
auth     include                     postlogin
account  include                     password-auth
password include                     password-auth
session  include                     password-auth
```

- **How it flows:**
  - If the gate passes, pam_exec prompts and checks the typed value as a PIN.
  - A match ends the stack with success (`done`).
  - A miss increments the counter and hands the same typed value to pam_unix (`try_first_pass`), so typing the full password always works and resets the counter and timestamp.
  - If pam_unix rejects the reused value, it may prompt once more in the same attempt, now for the password only. That's acceptable and arguably good UX.
  - If the gate fails, lines 2–3 are skipped and pam_unix prompts normally.
- **Arming right after login (optional).** Add `session optional pam_exec.so quiet /usr/local/libexec/pinlock reset` to `/etc/pam.d/sddm`, after `pam_systemd` has created `/run/user/$UID`. Without it, the first lock after each boot needs the full password once.
  - This depends on SDDM actually asking for your password. With autologin, the hook would arm the PIN without the full password ever being typed, so don't use both.
- **Scope check.** `grep -rn kde /etc/pam.d /usr/lib/pam.d` should show that no other service includes `kde`. sudo, polkit-1 and sddm use their own files, so the PIN can't reach them. Don't touch `password-auth`/`system-auth` (authselect regenerates them, and they're shared).\[29\]\[31\]
- **Leave `kde-fingerprint` and `kde-smartcard` alone.** A `sufficient` line in the parallel non-interactive services can turn failures into unlocks (ArchWiki warning).\[12\]

## Security analysis

- **The PIN hash is effectively readable by your own processes, and a 6-digit PIN falls in under a second offline: hashcat's benchmark for sha512crypt on a single RTX 4090 is 1146.6 kH/s (hashcat forum thread 11277), so all 10⁶ candidates take less than a second.** SHA-512-crypt is not memory-hard, and 10⁶ candidates is tiny.
  - This matters less than it seems. Any code running as you can already run `loginctl unlock-session`, read your unlocked home directory and keyrings, and edit the state file.
  - So the threat is "malware steals the PIN, then someone later gets physical access", and even that only buys a lock-screen unlock, not sudo.
  - Use a PIN you use nowhere else. The root-owned 0640 file at least stops malware from quietly *setting* a PIN.
- **A user-writable counter is acceptable.** The only party who can tamper with it already has a session-level foothold. The person at the keyboard gets exactly 3 tries, then needs the full password.
  - Odds of guessing within 3 tries: 3 in 1,000,000 for a random 6-digit PIN, 3 in 10,000 for 4 digits. Prefer 6+ digits, or a short 2-word passphrase if shoulder-surfing or smudges worry you.
- **The real weak point is the running machine, not the PIN.** While locked or suspended, LUKS is open and the key is in RAM. Cold-boot, DMA over Thunderbolt/USB4, or a locker crash attack ignore how strong the unlock secret is.
  - A 30-character password at the lock screen doesn't protect against these; only powered-off or hibernated-with-encrypted-swap does.
  - So the PIN weakens nothing beyond the lock screen. Leave the laptop shut down, not suspended, when it's out of your control, and enable Thunderbolt/IOMMU protections in firmware.
  - Optionally, have a systemd sleep hook delete the state file on suspend if you want the full password after every resume. This is a policy choice, not a meaningful gain against the attacks above.
- **Windows Hello comparison.** Microsoft says a Hello PIN is "backed by a Trusted Platform Module (TPM) chip" whose "anti-hammering features … thwart brute-force PIN attacks". It also says the claim "is not directed at the strength of the entropy used by the PIN".\[32\]
  - Elcomsoft's "Windows Hello: No TPM No Security" (August 2022) applies directly to your setup: "Without a TPM, a 4-digit or 6-digit PIN is nothing else than a very, very weak password," and it says all-digit PINs on such systems "can be broken in a matter of minutes".
  - Your design copies Hello's *online* rate limit in software, but not its offline protection. The Linux options with true hardware anti-hammering today are a FIDO2 key with a PIN or a fingerprint reader with match-on-chip.

## Pitfalls checklist

- **Lockout safety:**
  - Keep a root shell open (`sudo -i` in a VT) while editing.
  - Test lock and unlock with the PIN, a wrong PIN ×3, the full password, and the full password after lockout. Also run `sudo -k; sudo true` and a polkit prompt to confirm they still want the full password.
  - Undo: delete `/etc/pam.d/kde` to fall back to the vendor file, or `loginctl unlock-session` from a VT.
- **Updates:**
  - A local `/etc/pam.d/kde` permanently shadows the vendor file, so future Fedora or KDE fixes to it never reach you. The 3-way merge keeps locally modified or added files and never merges their content.\[33\]\[34\]
  - Record `sha256sum /usr/lib/pam.d/kde` and re-check after updates, the approach vinoAuthFace uses.\[35\] Also run `ostree admin config-diff` occasionally.\[36\]\[37\]
  - Rolling back an ostree deployment does not revert `/etc`.\[38\]
- **authselect** generates `system-auth`, `password-auth`, `fingerprint-auth`, `smartcard-auth` and `postlogin`, but not the `kde*` files. Your edit is outside its control, but `authselect apply-changes` still rewrites the files you include.\[29\]
- **SELinux:**
  - kscreenlocker_greet runs in your unconfined session domain, not in the greeter domain `xdm_t`. The only direct evidence is a 2015 Fedora audit line showing `unconfined_t`,\[39\] so confirm with `ps -eZ | grep kscreenlocker` while locked.
  - Reported pam_exec denials involve `xdm_t`/`local_login_t` (SDDM/login), not the lock screen.\[40\] That makes the optional SDDM hook the part most likely to hit an AVC.
  - After installing the script, run `restorecon -Rv /var/usrlocal` and check `ausearch -m avc -ts recent`.
- **Multiple users:** state is per UID and PIN files are per user. Each user needs their own `/etc/pinlock/<user>`.

## Aurora deployment

- **Fastest path, no image change:**
  1. `ls -l /etc/pam.d/kde /usr/lib/pam.d/kde; rpm -qf /usr/lib/pam.d/kde` to confirm where the vendor file lives. If only `/usr/lib/pam.d/kde` exists, `sudo cp` it to `/etc/pam.d/kde` as your starting point.
  2. `sudo install -d /usr/local/libexec /etc/pinlock` (`/usr/local` → `/var/usrlocal` on ostree), then `sudo install -m0755 -o root -g root pinlock /usr/local/libexec/pinlock`, then `sudo restorecon -Rv /var/usrlocal /etc/pinlock`.
  3. Confirm `openssl` and `setpriv` exist on the host (`command -v openssl setpriv`). Nothing needs layering, since pam_exec and pam_unix ship with Fedora's `pam`.
  4. Create the PIN file, write `/etc/pam.d/kde`, test as above, then add the optional SDDM hook last.
- **pam_pwdfile route (not recommended):** it's not in Fedora repos, so you'd have to layer an RPM you build yourself\[41\] (`rpm-ostree install ./pam_pwdfile*.rpm`) or build it in your Containerfile. The only win is not maintaining a script. The lockout and expiry logic still needs pam_exec.
- **Cleanest long-term: bake it into your custom image.**
  - In the Containerfile, `COPY` the script to `/usr/libexec/pinlock` (immutable, versioned, correctly labeled) and `COPY` `pam.d/kde` into `/etc/pam.d/kde`. bootc turns image `/etc` into the merge base, so future image builds keep updating it as long as you haven't modified it locally.\[38\]
  - Add a CI step that fails the build when upstream's `/usr/lib/pam.d/kde` changes, so you notice upstream PAM changes.
  - Keep the per-user PIN file local in `/etc/pinlock/`, and optionally add a `ujust` recipe to set or reset the PIN.
- **A systemd sysext is overkill** here: two text files and no binaries.

## Caveats

- I didn't find the exact Fedora spec for the `kde*` PAM files. The contents above come from a Fedora KDE 41 user's system and KDE's MR !163 template, so check your own file before copying lines.\[14\]\[19\]
- The pam_exec stdin format (NUL-terminated or not) and pam_unix's re-prompt behaviour vary a little between Linux-PAM versions. The script handles both stdin formats, but test on your build.
- MR !318's final state and whether it will ever gain a PIN type are unknown. Treat it as something to watch, not something to plan around.

## Sources

1. [Unlocking with pin password (à la Windows) / Programming & Scripting / Arch Linux Forums](https://bbs.archlinux.org/viewtopic.php?id=246734)
2. [\[SOLVED\] Pin instead of Password to unlock screen - Linux Mint Forums](https://forums.linuxmint.com/viewtopic.php?t=459422)
3. [Trying to add a pin code using pam\_pwdfile - Issues & Assistance - CachyOS Forum](https://discuss.cachyos.org/t/trying-to-add-a-pin-code-using-pam-pwdfile/20072)
4. [Pin\_login\_in\_kde -](https://blog.fancypi.cn/blog/pin_login_in_kde.html)
5. [Trying to add a pin code using pam\_pwdfile - #4 by Propheticus - Issues & Assistance - CachyOS Forum](https://discuss.cachyos.org/t/trying-to-add-a-pin-code-using-pam-pwdfile/20072/4)
6. [477758](https://bugs.kde.org/show_bug.cgi?id=477758)
7. [PIN Code to unlock screen - Brainstorm - KDE Discuss](https://discuss.kde.org/t/pin-code-to-unlock-screen/35651)
8. [472297](https://bugs.kde.org/show_bug.cgi?id=472297)
9. [pam: flexible authenticator support (!318) · Merge requests · Plasma / KScreenLocker · GitLab](https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/318)
10. [GitHub - LiAlH4qwq/libpam-pwdfile-rs: PAM module that allows you to authenticate against a password file](https://github.com/LiAlH4qwq/libpam-pwdfile-rs)
11. [\[SOLVED\] KDE Kscreenlocker with pam-u2f didn't work / Applications & Desktop Environments / Arch Linux Forums](https://bbs.archlinux.org/viewtopic.php?id=292700)
12. [Universal 2nd Factor - ArchWiki](https://wiki.archlinux.org/title/Universal_2nd_Factor)
13. [deploy.sh: KDE (kde-fingerprint) and COSMIC (cosmic-greeter) PAM targets · Issue #32 · karanshukla/vinoAuthFace](https://github.com/karanshukla/vinoAuthFace/issues/32)
14. [feat: run multiple pam sessions at once (!163) · Merge requests · Plasma / KScreenLocker · GitLab](https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/163)
15. [GitHub - KDE/kscreenlocker: Library and components for secure lock screen architecture · GitHub](https://github.com/KDE/kscreenlocker)
16. [github.com](https://github.com/kelna/kscreenlocker)
17. [KDE Plasma](https://gaze.gundulabs.com/guide/kde.html)
18. [Arch Linux - kscreenlocker 6.7.3-1 (x86\_64) - File List](https://archlinux.org/packages/extra/x86_64/kscreenlocker/files/)
19. [No fingerprint auth option when laptop wakes from sleep](https://forums.fedoraforum.org/showthread.php?334098-No-fingerprint-auth-option-when-laptop-wakes-from-sleep=&334098-No-fingerprint-auth-option-when-laptop-wakes-from-sleep=&p=1890540#post1890540)
20. [PAM(8) - Linux manual page](https://man7.org/linux/man-pages/man8/pam.8.html)
21. [www.nevis.columbia.edu](https://www.nevis.columbia.edu/cgi-bin/man.sh?man=8+PAM)
22. [\[BUG\] Locked screen fails unlock with YubiKey on Kubuntu (KDE-based Ubuntu) · Issue #113 · Yubico/yubico-pam](https://github.com/Yubico/yubico-pam/issues/113)
23. [Set-group-ID face-auth so the KDE lock screen and swaylock can match by karanshukla · Pull Request #44 · karanshukla/vinoAuthFace](https://github.com/karanshukla/vinoAuthFace/pull/44)
24. [pam\_exec(8) - Linux manual page](https://www.devdoc.net/linux/man7.org-20170728/man8/pam_exec.8.html)
25. [Can't unlock Plasma lock screen (kscreenlocker) - "unlocking failed" / Applications & Desktop Environments / Arch Linux Forums](https://bbs.archlinux.org/viewtopic.php?id=241046)
26. [455712](https://bugs.kde.org/show_bug.cgi?id=455712)
27. [\[RESPONDED\] Fedora KDE 39 - "The screen locker is broken" - Linux - Framework Community](https://community.frame.work/t/responded-fedora-kde-39-the-screen-locker-is-broken/46914)
28. [PAM: substack cannot take a bracketed control clause; both lock-screen variants fail to authenticate anyone · Issue #46 · dromeropa/tinkero](https://github.com/dromeropa/tinkero/issues/46)
29. [pam\_faillock on RHEL: Lock Accounts After Failed SSH and Console Logins](https://www.golinuxcloud.com/pam-faillock-lock-user-account-linux/)
30. [pam\_exec: PAM module which calls an external command](https://www.mankier.com/8/pam_exec)
31. [PAM by example: Use authconfig to modify PAM](https://www.redhat.com/en/blog/pam-authconfig)
32. [Windows Hello for Business Frequently Asked Questions (FAQ)](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/faq)
33. [Projects/OSTree/EverythingInEtcIsABug](https://wiki.gnome.org/Projects/OSTree/EverythingInEtcIsABug)
34. [Did You Know? How ostree update merges changes into etc and var - Bluefin - Universal Blue](https://universal-blue.discourse.group/t/did-you-know-how-ostree-update-merges-changes-into-etc-and-var/7233)
35. [uninstall.sh: keep a copied vendor PAM file the user edited · Issue #82 · karanshukla/vinoAuthFace](https://github.com/karanshukla/vinoAuthFace/issues/82)
36. [ostree(1) — ostree — Debian testing — Debian Manpages](https://manpages.debian.org/testing/ostree/ostree.1.en.html)
37. [Filesystem - bootc](https://bootc.dev/bootc/filesystem.html)
38. [What is an image mode 3-way merge?](https://developers.redhat.com/articles/2025/08/25/what-image-mode-3-way-merge)
39. [Installing the Proprietary AMD Catalyst 15.7 (fglrx 15.20) driver on Fedora 22 with Linux Kernel 4.1.3](https://bluehatrecord.wordpress.com/2015/08/11/installing-the-proprietary-amd-catalyst-15-7-fglrx-15-20-driver-on-fedora-22-with-linux-kernel-4-1-3/)
40. [npu build: likely SELinux denials from oneTBB (and maybe /dev/accel) inside pam\_exec domains · Issue #34 · karanshukla/vinoAuthFace](https://github.com/karanshukla/vinoAuthFace/issues/34)
41. <https://software.opensuse.org/package/pam_pwdfile?search_term=pam_pwdfile>
