---
id: 2610010339yf9J1kSnpi
datetime: 2026 Oct 1, 03:39
ctime: "2026-10-01 03:39:50"
---



*An educational summary of a design discussion: why a lock-screen PIN makes sense, how Linux authentication works underneath, and the decisions behind a small, auditable implementation for Fedora Atomic (Aurora).*

---

## 1. Starting point: the perfect-setup trap

Chasing a perfect, synced, privacy-hardened Linux setup across several machines is a well-known time sink. The community consensus is simple: tinkering is fine while it's fun, but past a point it gives nothing back and often becomes procrastination. On the privacy side, the classic failure is the "gadget collection": stacking tools without knowing what they defend against, burning out on the friction, and abandoning everything.

Ways to keep it sane:

- **Write a threat model** (one paragraph): what you protect, from whom, and what happens if it fails. It tells you what to *skip*, not just what to do.
- **Solve sync once**, with dotfiles in git (chezmoi or a bare repo), and optionally declarative systems like Nix. Beware that Nix is its own rabbit hole.
- **Timebox it**, and keep a backlog so new ideas don't hijack the week.
- **Define "good enough"**: full-disk encryption, updates, firewall, password manager plus 2FA, backups, and a hardened browser. Everything beyond that is a hobby.

Encryption and supply chain in brief:

- **Two-level disk encryption with sane UX:** LUKS root, with the other partitions unlocked by keyfiles stored inside the encrypted root (`crypttab`). That gives you one passphrase at boot. TPM2 plus a PIN can shorten it further.
- **Supply chain:** an individual can't defend against a compromised upstream. What you *can* control is your exposure:
  - Stick to signed official repos.
  - Minimize the AUR, PPAs, `curl | bash` and random extensions.
  - Sandbox untrusted apps with Flatpak and untrusted dev work with containers or VMs.
  - Keep backups.

The lock-screen PIN discussion grew directly out of the encryption-vs-UX tension: **a strong password is a hassle to type, and typing it 30 times a day pushes people toward weak passwords.**

---

## 2. How Linux authentication actually works

### PAM: the authentication switchboard

**PAM (Pluggable Authentication Modules)** is the layer almost every Linux program uses to answer "is this really you?", whether that's login, sudo, SSH, polkit or the lock screen.

- Programs don't check passwords themselves. They ask PAM to authenticate a user *for a named service*.
- Each service has its own config file in `/etc/pam.d/` (falling back to vendor defaults in `/usr/lib/pam.d/`). Examples: `sddm` (login), `kde` (lock screen), `sudo`, `polkit-1`.
- Each file is a stack of lines processed top to bottom, in the form `type control module args`:
  - **Types:** `auth` (prove identity), `account` (is the account allowed right now), `password` (changing it), `session` (setup and teardown).
  - **Control values** decide what a module's result means:
    - `required` must pass, but the stack keeps running.
    - `sufficient` ends the stack with success when it passes.
    - `optional` mostly doesn't matter.
    - The bracket syntax, e.g. `[success=done default=ignore]`, gives fine-grained jumps and early exits.
  - `include` and `substack` pull in shared blocks such as Fedora's `password-auth`.
- **Modules** each do one job:
  - `pam_unix`: normal password
  - `pam_fprintd`: fingerprint
  - `pam_u2f`: FIDO2 keys
  - `pam_faillock`: account lockout
  - `pam_exec`: runs any program and treats exit code 0 as success

The key insight: **PAM knows nothing about PINs, counters or resets.** It only runs modules in order and routes on success or failure. Everything else is your own logic, plugged in with `pam_exec`.

### Password storage: `/etc/shadow`

Password hashes live in `/etc/shadow`, which only root can read. They were moved out of the world-readable `/etc/passwd` to prevent offline cracking. Since the lock screen runs as your user, `pam_unix` checks your password through a small setuid helper (`unix_chkpwd`) that reads shadow as root and answers only yes or no.

### Login screen vs lock screen: two different programs

- **SDDM** is KDE's display manager, the login screen after boot. It's a root system service, configured by `/etc/pam.d/sddm`. It authenticates you and then starts Plasma.
- **kscreenlocker** is the lock screen. It's part of your *running* Plasma session, runs **as your user**, and is configured by `/etc/pam.d/kde`. Plasma 6 also runs `kde-fingerprint` and `kde-smartcard` in parallel.

Because they're separate services with separate PAM files, you can require the full password at login while accepting a PIN at the lock screen.

### What runs before login

- **System services** start at boot as root or dedicated service users. Examples: `sshd`, NetworkManager, SDDM itself. That's why SSH works as a rescue path with nobody logged in.
- **User services** (`systemd --user`) start when you log in. Syncthing usually runs this way, unless you enable lingering (`loginctl enable-linger`) or run it as a system service.

### Virtual terminals

Ctrl+Alt+F3 switches to a text console with its own login, which uses a different PAM path from the lock screen. The graphical session keeps running, *unlocked*, on its own VT (usually F1 or F2 on Fedora), so switching away is not locking.

### UI layer: QML and themes

Plasma's visible pieces (panel, SDDM theme, lock screen) are written in **QML**, Qt's declarative UI language. Themes like the community "Breeze PIN" SDDM theme only change the *look*, such as a numeric keypad. They can't add any auth logic, which always lives in PAM.

---

## 3. The state of the world: why there's no real PIN yet

- **The popular "PIN" recipe is just a second password.** Forum and blog guides from 2019 add one `auth sufficient pam_pwdfile.so …` line before the normal stack. There's no failure limit and no expiry. The only brake is pam_unix's roughly 2-second failure delay, so all 10,000 four-digit PINs can be tried in a few hours.
- **The KDE feature request is open but unowned.** Bug 411698 is *CONFIRMED / wishlist*. In KDE Bugzilla terms, CONFIRMED means "valid, understood, not spam", and wishlist means "a feature request, nothing is broken". Neither means anyone is working on it.
- **Groundwork exists.** A kscreenlocker merge request for *switchable authenticators* lets the lock screen offer several PAM-backed methods (password, U2F, face, smartcard) and switch between them. It defines no PIN type, but it's where a proper one could plug in.

Why nobody built it properly:

- A software PIN has no hardware anchor. Windows Hello is safe because the **TPM** enforces anti-hammering.
- Tamper-proof rate limiting needs privileged code, which means security review and per-distro packaging.
- PAM configs belong to distros, not desktops.
- "Use fingerprint or FIDO2" is the default answer.
- It needs volunteer time nobody has put in.

The underrated point: a PIN's real security value is that it lets people *afford* a strong main password. The most interesting unbuilt piece is a **TPM-backed** lock-screen PIN, since most laptops already have the hardware.

---

## 4. The security model

### The core rule: state must be as privileged as what it guards

- **Lock screen:** it guards your user session. Anything that can tamper with user-level state (the PIN hash, the counters) is already code running as you, and that code can unlock the session directly (`loginctl unlock-session`), read your files, or keylog your password. **User-level state is therefore sufficient.** A root helper would add a privilege-escalation risk without stopping anything.
- **sudo:** it guards root against code running as you. A similar PIN scheme would need **root-owned** state and hashes. That's feasible, since sudo's PAM stack runs as root and sudo's own credential cache already works this way. But same-user malware can intercept sudo anyway (fake `sudo` in `PATH`, keylogging), so a PIN doesn't make it meaningfully weaker.
- **Sandboxed malware** (a compromised Flatpak app, a browser exploit) usually can't read the PIN files or state, so sandboxing still helps.
- **SSH is a master key.** Once you're logged in as the same user over SSH, `loginctl unlock-session <ID>` unlocks the screen without a password. Protect SSH keys: use passphrases or FIDO2-backed `ed25519-sk` keys, disable password auth, and don't expose sshd publicly.

### What the lock screen actually defends against

Lock-screen auth barely matters against remote attackers, who are already inside the session. Its job is **in-room threats**:

- **Fingerprint:** the weakest against someone with access to *you* (sleep, coercion, lifted prints, legal compulsion in some places).
- **FIDO2 key with its own PIN, carried on your keychain:** the strongest convenient option, with hardware-enforced lockout. Left plugged in without a PIN, it protects nothing.
- **Software PIN:** decent. Its weakness is shoulder-surfing, since 3 strikes stops guessing but not watching.
- **Long password:** the strongest against watching, and the reason a PIN is wanted in the first place.

### The irreducible weak spot

While the machine is running or suspended, LUKS is open and the keys are in RAM. Cold-boot and DMA attacks ignore the lock screen entirely, however strong the password. Only shutdown or hibernation with encrypted swap closes that gap.

---

## 5. Design decisions

### Add on top of the stock password path, never replace it

The full-password check stays with `pam_unix`: decades old, audited, and handling shadow, hash formats, the setuid helper and delays. The custom code only adds a PIN shortcut *before* it and bookkeeping *after* it. As a result:

- If the script breaks, the stock password path still works.
- Lockout of the *system* is very unlikely. At worst the lock screen misbehaves, which is fixable from a TTY or SSH.

### Scope: only `/etc/pam.d/kde`

Login (SDDM), sudo, polkit and TTY login keep their own files and the full password. Don't touch `kde-fingerprint`, because `sufficient` lines in parallel services can bypass the lock.

### pam_exec plus one small script, not pam_pwdfile and not setuid

- pam_pwdfile isn't in Fedora's repos and provides no lockout or expiry anyway.
- A pam_exec script runs as the user, with no new privileged code at runtime. Root is only needed at install time. This matters for an open-source release, where unnecessary root code is a dealbreaker for many people.
- Crypto is not reimplemented. Hashing uses the system's libxcrypt (`mkpasswd -m yescrypt` or `openssl passwd -6`), and the script only re-hashes and compares. `pam_userdb` may remove even that, if your PAM build ships it.
- The Rust fork `libpam-pwdfile-rs` (yescrypt plus a setuid helper that would hide the hash from user processes) was considered and rejected for v1. It's a one-person setuid project, it would require layering on Aurora, and the threat it addresses is marginal.

### Minimal stack: two custom calls around pam_unix

```
auth [success=done default=ignore] pam_exec.so quiet expose_authtok /usr/local/libexec/pinlock pin
auth [success=ok default=die]      pam_unix.so try_first_pass
auth optional                      pam_exec.so quiet /usr/local/libexec/pinlock reset
```

- **`pinlock pin`** does three things in one run. If the PIN is disabled (expired or 3 strikes), it fails without counting. If the input matches, it succeeds and unlocks. Otherwise it increments the counter and fails.
- **`pam_unix`** then checks the same input as the full password. The full password therefore always works, typed into the same field.
- **`pinlock reset`** zeroes the counter and stamps "last full password = now". "Reset" is not a PAM concept, just your script placed where PAM's control flow reaches it only on success.
- **Why not `include password-auth` before the reset:** a failed `required` module doesn't stop a PAM stack, and `include`/`substack` can't take custom control values. The reset would fire after *wrong* passwords too, silently giving unlimited guesses and an endless PIN window. Calling `pam_unix` directly with `default=die` prevents that. The tradeoff is losing Fedora's `password-auth` extras (faillock, network and homed accounts), which don't matter for a local account. Skipping faillock is actually desirable, since it would lock the whole account rather than just the PIN.
- **Why two calls, not one:** the script can't verify the full password itself, because that requires reading shadow. It has to learn the outcome from `pam_unix`, hence one call before and one after.

### State: ephemeral, per user, fail-closed

- The state lives in `/run/user/<UID>`: tmpfs, owned by the user, wiped at reboot. It also stores the boot ID, so stale files are ignored.
- **Fail closed:** a missing file, a mismatched boot ID, an expired window, 3+ failures or any script error all mean "PIN disabled, full password required".
- Keep the script fast and offline. `pam_exec` has no timeout, so a hanging script hangs the lock screen; wrap anything slow in `timeout`.

### PIN management happens outside the unlock path

The PIN file is root-owned, readable only by that user's private group (`root:<user> 0640`), and set by a separate `pinlock set` command that requires the full password. In-band tricks like typing `oldpin.newpin` at the lock screen were rejected for four reasons:

- They need a user-writable PIN file.
- There's no confirmation, so a typo sets a PIN you don't know.
- A full password that happens to start with `PIN.` could be misread as a change request.
- Anyone shoulder-surfing learns both PINs.

The principle: **keep the unlock path dumb, put the clever things in separate commands.**

### Arming the PIN after boot

- **v1:** no login hook. After boot, the first lock requires the full password once, and then the PIN works. This is intentionally strict and fine for a stolen laptop, where a thief would hit LUKS and SDDM first anyway.
- **Rejected:** a `pam_exec` hook in `/etc/pam.d/sddm`. It runs inside SDDM's root context, the one piece of root runtime code in the design.
- **v1.1:** a Plasma **autostart** entry (`~/.config/autostart/*.desktop`) that runs `pinlock reset` when the graphical session starts. It's user-level with no sudo, and equivalent in security because reaching the desktop required the full password at SDDM. **Never combine it with autologin.** The script can refuse to arm if SDDM autologin is enabled.

### Multiple users

Everything is per user: separate PIN files, state in each user's own `/run/user/<UID>`, and independent timers and counters. Make sure each PIN file's group is the user's *private* group, not a shared one like `users` or `wheel`. If accounts are separated *for security*, use different PINs and certainly different full passwords, since a compromised account can crack its own PIN hash. Switching back to an existing session lands on that session's lock screen, so the PIN works there. A new session goes through SDDM and the full password.

---

## 6. Extensions considered (not in v1)

`pam_exec` makes arbitrary logic possible. Any script whose exit code decides the outcome can gate the unlock. Ideas discussed:

- **Duress PIN → shutdown.** It closes LUKS and drops the keys from RAM.
  - The duress check must come first, so it works even when the normal PIN is disabled.
  - Use `systemctl poweroff --check-inhibitors=no`, and return failure so the screen stays locked.
  - **Multi-user gotcha:** with another user logged in, polkit requires admin rights to power off, so the path fails silently unless a polkit rule allows `power-off-multiple-sessions`.
  - Caveats: it's overt (a coercer sees it), useless against prepared adversaries who image RAM first, causes data loss on accidental triggers, and in some jurisdictions could raise obstruction concerns.
- **Rotating codes:** TOTP already exists (`pam_oath`, `google-authenticator-libpam`) and resists shoulder-surfing. Its seed is user-readable, the same tradeoff as the PIN hash.
- **The FIDO2 variant:** `pam_u2f` as `sufficient` with `pinverification=1` in `kde`. That's a hardware-enforced PIN, and the gate script can still sit in front for the N-hour rule. It can also be `required` alongside the password for 2FA, or replace passwords on other services entirely.
- **Lock-screen theming** (QML): a PIN keypad or a "PIN / Password" label. It's user-level, but can break on Plasma upgrades.

Going fully passwordless is possible in principle (FIDO2 or PIV signatures for login, sudo and the lock screen; FIDO2 or TPM2 for LUKS), but:
- Bluetooth "phone as key" is immature on Linux.
- Flash-drive schemes like `pam_usb` can be cloned.
- Keyrings often depend on the login password.
- You always need a strong offline recovery password.

Rules for any custom logic: fail closed, stay fast and offline, remember it runs as you, and keep it small, because complexity is where fail-open bugs hide.

---

## 7. Safety and testing

**Failure modes**, in order of concern:

- **Fails open:** anything unlocks the screen. This is the one to hunt for, because you won't notice it on your own.
- **Lock-screen lockout:** caused by a wrong control value, a malformed line, or a hanging script. Recover with Ctrl+Alt+F3, log in, then `loginctl unlock-session <ID>` and restore the file. SSH works as a backup path.
- **Flaky PIN:** harmless, since the full password still works.

**Test checklist** (keep a root shell open on a TTY while testing):

- The correct PIN works.
- A wrong PIN fails.
- 3 wrong PINs, then the correct PIN, is refused.
- The full password always works and re-arms the PIN.
- Empty input and random strings fail.
- With the script renamed or missing, only the full password works.
- After N hours, the PIN is refused.
- `sudo -k; sudo true` and a polkit prompt still demand the full password.

Keep a backup of the original file. Deleting `/etc/pam.d/kde` falls back to the vendor version.

---

## 8. Deploying on Aurora (Fedora Atomic)

- **No image change is required for v1:**
  - `/etc` is mutable and persists across updates via ostree's 3-way merge.
  - `/usr/local` maps to `/var/usrlocal`.
  - `pam_exec`, `pam_unix`, `openssl` and `setpriv` ship with the base system, so nothing needs layering.
- **Steps:**
  1. Copy the vendor `kde` file to `/etc/pam.d/` if needed.
  2. Install the script under `/usr/local/libexec/`.
  3. Create `/etc/pinlock/<user>`.
  4. Run `restorecon` on the new paths and check `ausearch -m avc` for SELinux denials.
  5. Test.
- **Ongoing:** a local `/etc/pam.d/kde` permanently shadows upstream's version. Record the vendor file's checksum and recheck after updates. Rolling back a deployment does not revert `/etc`.
- **Later:** bake the script (as `/usr/libexec/pinlock`) and the PAM file into your custom image, with a CI check that flags upstream changes to `/usr/lib/pam.d/kde`. Per-user PIN files stay local.

---

## 9. Glossary

- **PAM:** Linux's pluggable authentication framework; per-service stacks of modules.
- **pam_exec:** a PAM module that runs any program; exit code 0 means success.
- **`/etc/shadow`:** the root-only file holding password hashes. `unix_chkpwd` is the setuid helper that checks against it.
- **SDDM:** KDE's login screen (display manager), running as a root service.
- **kscreenlocker:** Plasma's lock screen, running as the user inside the session.
- **TTY / VT:** text consoles reachable with Ctrl+Alt+F-keys.
- **QML:** Qt's declarative UI language, used for Plasma themes.
- **Autostart:** programs Plasma launches when your graphical session starts.
- **Lingering:** lets user services run without an active login.
- **TPM:** the security chip that enables hardware-rate-limited PINs (Windows Hello's anchor).
- **FIDO2 / pam_u2f:** hardware keys that sign challenges and can enforce their own PIN.
- **CONFIRMED / wishlist:** KDE Bugzilla's "valid request" status and "feature, not bug" severity.
