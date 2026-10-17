---
id: 2610010339PMdZWrsToZ
datetime: 2026 Oct 1, 03:39
ctime: "2026-10-01 03:39:41"
---



**Working name:** TBD. Candidates are `lazypass` and `pampin`. Avoid `pinlock`, which collides with the existing `pam_pinlock`.
**Target:** KDE Plasma 6 on Fedora Atomic (Aurora), single or multi-user desktop.

---

## 1. Goal

Allow a strong (long) account password without hurting daily UX. A short secret ("PIN", digits or letters) unlocks the **lock screen only**, under strict limits. Everything else keeps requiring the full password.

## 2. Scope

**In scope**
- KDE lock screen (kscreenlocker, PAM service `kde`)
- A CLI for managing the short secret
- Documentation, install and uninstall steps, a test checklist

**Out of scope for v1**
- Boot or LUKS, SDDM login, sudo, polkit, TTY and SSH. These stay unchanged, full password only.
- `kde-fingerprint` and `kde-smartcard` PAM services. These are not touched.

## 3. Functional requirements

1. **Short secret at the lock screen:** a per-user short secret, digits or letters, is accepted at the KDE lock screen.
2. **Full password always works:** the full password is always accepted at the lock screen, typed into the same field.
3. **3-strikes lockout:** after 3 consecutive wrong attempts, the short secret is disabled until a successful full-password unlock.
4. **Expiry:** the short secret is disabled N hours after the last full-password unlock. N is configurable, default 8.
5. **Re-arming:** a successful full-password unlock resets the failure counter and restarts the N-hour window.
6. **After boot:** the short secret is disabled until the first full-password unlock at the lock screen. There is no login hook in v1.
7. **Management CLI:** `set`, `remove` and `status` commands.
   - `set` requires the full password (sudo or pkexec) and asks for the new secret twice.
   - There's no in-band change at the lock screen.
8. **Multi-user:** state, secrets, timers and counters are fully independent per user.

## 4. Security requirements

1. **Narrow PAM footprint:** only `/etc/pam.d/kde` is modified, and only by *adding* lines around the stock password check.
2. **Stock password check:** the full password is verified by stock `pam_unix`. Password checking is never reimplemented.
3. **No root code at runtime:** no setuid binaries, no daemons. Root is used only at install time and by `set`.
4. **No custom crypto:** hashing uses the system libxcrypt (yescrypt or sha512crypt). The script only re-hashes and compares.
5. **Fail closed:** any missing file, parse error, stale or mismatched state, expired window, reached strike limit or script error disables the short secret. The full password still works.
6. **Wrong passwords never reset state:** the stack must stop on a failed full password (`pam_unix` with `default=die`). The reset step runs only on success.
7. **No account lockout:** `pam_faillock` is not in this stack, so wrong short secrets must never lock the whole account.
8. **State storage:** in `/run/user/<UID>` (tmpfs, wiped at reboot), tagged with the boot ID. Writes are atomic.
9. **Secret storage:** the hash file lives in `/etc/<name>/<user>`, owned `root:<user's private group>`, mode `0640`. It must not be writable by the user or readable by other users.
10. **No hangs:** the unlock path is bounded by a timeout, makes no network calls and has no extra prompts.
11. **No leaks:** the secret never appears in argv, logs or environment variables.

## 5. Non-functional requirements

- **Small and auditable:** one short shell script plus a PAM snippet, readable in minutes.
- **Dependencies:** base system only (`pam_exec`, `pam_unix`, `openssl` or `mkpasswd`, coreutils). No compiled modules, no package layering.
- **Fast:** the unlock check completes well under a second.
- **Open source:** documentation states the threat model plainly, covering what it protects, what it doesn't, and its known limits.

## 6. Deployment (Aurora)

- **v1 needs no image change:** the script goes in `/usr/local/libexec/` (that is, `/var/usrlocal`), the PAM file in `/etc/pam.d/kde`, secrets in `/etc/<name>/`. Run `restorecon` on the new paths.
- **Updates:** documentation explains that a local `/etc/pam.d/kde` shadows the vendor file, and how to detect upstream changes (checksum of `/usr/lib/pam.d/kde`).
- **Uninstall:** removing `/etc/pam.d/kde` restores vendor behavior.
- **Later:** an optional path to bake the script and PAM file into a custom image.

## 7. Acceptance tests

Run all tests with a root shell open on a TTY.

- The correct short secret unlocks.
- A wrong short secret fails.
- 3 wrong attempts followed by the correct short secret is **refused**.
- The full password unlocks in every state and re-arms the short secret.
- After N hours, the short secret is refused.
- After a reboot, the short secret is refused until the first full-password unlock.
- Empty input, random strings and very long input fail.
- With the script missing or not executable, only the full password works.
- With the state file corrupted or deleted, only the full password works.
- A wrong full password never resets the counter or the window.
- sudo (`sudo -k; sudo true`), polkit prompts, SDDM and TTY login still require the full password.
- With two users, each one's state and secret is independent.
- No SELinux denials (`ausearch -m avc`).

## 8. Future (not v1)

- **v1.1:** a Plasma autostart entry that re-arms the short secret on graphical login, user-level only. It must refuse if SDDM autologin is enabled.
- Optional lock-screen UI hint (QML theme), such as a "Short password / Password" label.
- Optional duress secret that powers off the machine. This needs a polkit rule on multi-user systems.
- Optional FIDO2 (`pam_u2f` with `pinverification=1`) behind the same expiry gate.
- Possible upstreaming of the expiry and hard-lockout ideas to `pam_pinlock` or KDE (bug 411698).
