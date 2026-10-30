# Why screenlock-pin is not offered at the login screen

The question: would it be bad to also accept the PIN at Plasma's login screen, the one after boot or after logging out, and not only at the lock screen? The short answer: not because a PIN there would be unsafe, but because it costs more than it gives. It would need screenlock-pin code running as root, it would leave the wallet locked, and the login screen is used once per boot.

Written on 2026-10-18 on the Fedora 44 machine screenlock-pin is developed on (Plasma Login Manager `plasma-login-manager-6.7.5-1.fc44`, kscreenlocker 6.7.5). Claims are marked "verified here" (observed on this machine) or "reasoned" (thought through, not tested).

## Two greeters, two PAM files

"Greeter" is the general word for the window that asks for your password. KDE has two, and they are separate programs that only look alike (verified here):

| | Login screen | Lock screen |
|---|---|---|
| Program | `/usr/libexec/plasma-login-greeter` | `/usr/libexec/kscreenlocker_greet` |
| Package | `plasma-login-manager` (a fork of SDDM) | `kscreenlocker` |
| Runs as | the system user `plasmalogin` (uid 967) | the locked user |
| Who checks the password | `/usr/libexec/plasmalogin-helper`, running as root | the greeter itself, as the user |
| PAM file | `plasmalogin` | `kde` |

The login greeter only draws the screen and sends what was typed over a socket to `plasmalogin-helper`, which runs PAM. The greeter window itself is started with a third file, `plasmalogin-greeter`, which is `pam_permit` ("always allow") and checks nobody's password. Automatic login uses a fourth, `plasmalogin-autologin`.

## Lines in plasmalogin would reach only the login screen

Verified here:

- Among every program and library that links libpam under `/usr/bin`, `/usr/sbin`, `/usr/libexec` and `/usr/lib64`, only `/usr/libexec/plasmalogin-helper` names the `plasmalogin` service.
- No file in `/etc/pam.d` or `/usr/lib/pam.d` pulls `plasmalogin` in with `include` or `substack`.
- The text console (tty3 and the others) goes `agetty` → `/bin/login`, which reads `login`, which pulls in `system-auth`. `sudo`, `sshd`, `polkit-1` and `systemd-run0` read their own files. None of them would see the lines.

So the lines would cover exactly graphical login: after boot, after logging out, and "switch user".

## As built, the PIN would always be refused there

`ps` shows `plasmalogin-helper` running as root while it logs a user in (verified here). Both halves of screenlock-pin refuse root:

- The module, in `crates/pam/src/run.rs`: "running as root; screenlock-pin belongs in the lock screen's stack only".
- The PIN checker, in `crates/checker/src/main.rs`: "refused: root has no lock screen to unlock".

The PIN checker decides whose PIN to check from the real uid of whoever runs it and never takes a user name from its caller, so as root it has no user to check. With screenlock-pin's lines in `plasmalogin`, the PIN would be refused, the password would still work through `use_first_pass`, and each login would log an error (reasoned).

On a correctly installed system nothing runs screenlock-pin as root: its lines are only in `kde`, only `kscreenlocker_greet` opens `kde`, and it runs as the user; `install.sh` runs as root but never runs the module or the PIN checker (verified here). The refusal matters only after a mistake, such as the lines copied into the wrong file.

## A PIN at login would be about as safe as at the lock screen

Reasoned. With perfect code, a PIN at the login screen would not be much weaker than at the lock screen:

- The pause after three wrong tries is kept on disk, in `/var/lib/screenlock-pin`, so it would hold at login too, across reboots; after it, only the password works.
- When the machine is off, the login screen is not the real barrier. With full-disk encryption the attacker first faces the disk passphrase; without it, they can boot from a USB stick and read the disk, and no login screen helps.

So the case against it is not that the PIN would be unsafe there.

## Why not anyway

- **More code running as root.** At login the password is checked by root. Supporting the PIN there means screenlock-pin's module running inside a root process, and a PIN checker that accepts "check user X" from root instead of only "check the user who runs me". That is a new trust model and new code to review.
- **The wallet would stay locked.** At login `pam_kwallet` passes the real password to the wallet (`ksecretd --pam-login` runs on this machine; verified here). A PIN login ending the stack with `success=done` would skip `pam_kwallet`, `pam_gnome_keyring` and `postlogin`, and even if they ran, they would get the PIN, not the password. The wallet would stay locked and ask for the password later. The same goes for anything else that needs the password at login, such as an encrypted home directory (reasoned).
- **It would replace Fedora's file.** The stock file is `/usr/lib/pam.d/plasmalogin`. Adding lines means creating `/etc/pam.d/plasmalogin`, which hides the vendor file completely, so later package updates to it would be silently ignored (reasoned, from how Linux-PAM looks in `/etc/pam.d` before `/usr/lib/pam.d`).
- **Little value.** The login screen is used once per boot; the lock screen many times a day. The PIN saves typing mainly at the lock screen.

So screenlock-pin stays a lock-screen feature: a PIN at login would cost a root code path and a working wallet for little gain.
