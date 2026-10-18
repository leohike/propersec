# How other projects add an unlock method, and what screenlock-pin should do

The five reports beside this one cover authselect, kscreenlocker's PAM services, GDM and fprintd, Debian's pam-auth-update with linux-pam, and howdy, pam-u2f and google-authenticator-libpam. All were read from clones in /var/home/shared/projects/pam-related on 2026-10-17. This page pulls them together. Each report says which claims it checked in code and which it inferred. Where two reports disagree, this page says so.

## The short answers

Supporting authselect makes no sense, but screenlock-pin has to coexist with it. authselect never touches /etc/pam.d/kde. It manages only the shared stacks (system-auth, password-auth, fingerprint-auth, smartcard-auth, switchable-auth and postlogin), and it accepts no features from third parties. Everything it can express goes into stacks shared with sshd, login, sudo and polkit, which is exactly where the PIN must never go. Making screenlock-pin a custom or vendor profile would force users to switch profile and would freeze a copy of password-auth. The authselect report covers this in detail.

A /etc/pam.d/screenlock-pin that kscreenlocker uses instead of kde is not possible without rebuilding KDE. The service names are CMake constants: kde, kde-fingerprint and kde-smartcard, plus kde-face and kde-u2f in 6.8. No environment variable or kscreenlockerrc key changes them. Taking over an existing slot is no better. In 6.7.5 the extra slots never receive the typed text, and in 6.8 only the smartcard slot has a password field, labelled "Smartcard". Its file belongs to plasma-workspace just as kde does. The kscreenlocker report has the details.

What is possible is a one-line edit: `auth include screenlock-pin-kde-auth` in kde, pointing at a file screenlock-pin owns that holds today's three lines. It must be `include`, never `substack`, because inside a substack `success=done` and `die` end only the substack. A correct PIN would then fall through to password-auth and be refused. With `include`, libpam builds exactly the same list of handlers as today. The kscreenlocker report and the linux-pam report agree on this.

The cost is a new kind of lockout. If the included file is missing, unreadable or mistyped, libpam puts in a line that always fails, so even the correct password is refused, and a leading `-` does not prevent it. Today, if the module is missing, the stack just falls through to the password.

## What the big projects do

| Project | How it reaches the stack | Scope |
|---|---|---|
| GDM, GNOME Shell | Its own PAM service per method (gdm-password, gdm-fingerprint, gdm-smartcard, gdm-switchable-auth), each run as a separate conversation; since July 2026 the files are in /usr/lib/pam.d | Only that app |
| kscreenlocker 6.8 | The same design as GDM: kde-fingerprint, kde-smartcard, kde-face and kde-u2f, fixed when built, and Fedora's files are copied from GDM's | Only the lock screen |
| fprintd | Upstream says to edit by hand. On Fedora, authselect's with-fingerprint; on Debian, a pam-auth-update profile (off by default) | Every service |
| pam-u2f | Manual. On Fedora, authselect's with-pam-u2f and with-pam-u2f-2fa | Every service |
| google-authenticator-libpam | Manual | Wherever the admin puts it |
| howdy | Until 2018 its installer edited common-auth after a `[y/N]`; it now ships a pam-auth-update profile with `Default: yes` | Every service, sudo included |
| screenlock-pin | install.sh edits a file owned by another package (kde), with markers, a diff and a yes | Only the lock screen |

Two patterns stand out. Projects that ship the login or lock screen give each method a PAM service of its own and let the app choose it. Modules shipped by other people go through the distro's mechanism (authselect or pam-auth-update) or are left to the admin. Both of those mechanisms only know the shared stacks. No project anywhere offers "add a module to one app's stack, without the app's help". That is the niche screenlock-pin is in, and no clean answer for it exists.

howdy is the only project whose installer edited another package's PAM file, which is what screenlock-pin does now. Its maintainer stopped in issue #107, calling the file "a dangerous file to edit" and the prompt "rather hostile to users not familiar with PAM modules". No lockout was cited. howdy's installer had no markers, no undo and no atomic write, all of which screenlock-pin has. What still applies to screenlock-pin is that it asks the user to approve a PAM diff they may not be able to judge.

## What screenlock-pin should do

For now, keep the marked block in /etc/pam.d/kde. The reports differ only on how far to go beyond that. The linux-pam report says to keep the block. The kscreenlocker report would switch to the one-line `include`. That switch would make the diff in kde smaller and let screenlock-pin update its lines without touching kde. Against that, it brings a new way to lock everyone out, which the block can never do. My recommendation is to keep the block. If the include is adopted later, do it the way the kscreenlocker report proposes:

- name the file screenlock-pin-kde-auth and make it 0644
- have the module refuse any PAM service other than kde
- on install, write the module first, then the included file, then the line in kde
- on uninstall, remove the line in kde first
- make install.sh check fail loudly when kde includes a file that is missing
- add a stack test that pins down the lockout when the file is missing

In the long run, the clean fit is a PIN authenticator in kscreenlocker, a kde-pin service like the others in 6.8. A paused PIN would then return PAM_MAXTRIES or PAM_AUTHINFO_UNAVAIL so the lock screen hides it. That needs KDE upstream to accept it. GDM's gdm-pin service is the precedent and the warning: shipped in 2013, never connected to GNOME Shell, removed in 2021. Even then, kde would keep one `after-password-auth` line so that a password unlock still unpauses the PIN. The user would also switch to a PIN mode rather than typing either secret into one field. The GDM and fprintd report has the UI details.

## New problems the reports found

These go beyond the original questions. Each needs checking before anything is changed.

- **Line 2 locks some accounts out.** The second of the three lines is `pam_unix.so use_first_pass` with `default=die`. Accounts that are not in /etc/shadow (sssd, winbind, LDAP, AD, systemd-homed) would have the correct password refused at the lock screen. Three reports reached this independently by reading the code; none tested it.
- **It weakens some authselect features.** On a system using with-faillock (secureblue turns it on), with-pam-u2f-2fa or with-smartcard-required, the PIN gets around faillock, the second factor or the smartcard requirement. Wrong passwords at the lock screen also stop being counted by faillock. The idea worth evaluating is the one in the authselect report: move the `after-password-auth` line below password-auth and drop the direct pam_unix line. That would also fix the first item. Otherwise, install and check should read `authselect current` and refuse profiles and features not on a list known to be safe.
- **authselect re-applies itself at every boot.** authselect-apply-changes.service runs on every boot and is enabled on this Aurora machine. The shared stacks under screenlock-pin's lines can change without anyone running a command.
- **kscreenlocker 6.8 removed the 50 ms check.** Commit 5d848610 removed it, and the commit message says it may come back. Keeping the 75 ms padding is harmless, but docs/chaos/kscreenlocker-pam-contract.md is out of date on this.
- **kscreenlocker 6.8 can disable the password field.** It has a new guard that does this after repeated failures less than 2 s apart, and it covers the password field too. screenlock-pin must never return a quick failure. Today only a correct PIN is delayed, and a wrong one goes on to pam_unix, which is slow anyway; the new guard needs testing against that.
- **Bugs from other modules to test against.** howdy's `wait()` reaped any child of the lock screen, so an unrelated child exiting with 0 unlocked it. pam-u2f and google-authenticator once returned PAM_SUCCESS for users with no credentials. pam-u2f's CVE-2025-23013 returned PAM_IGNORE on internal errors. All are worth stack tests.
- **The removal worry is unfounded.** The howdy report feared uninstall might restore the saved copy of kde and undo a distro update made since install. install.sh only restores that copy when the block can't be removed cleanly (the `restore` state in `without_screenlock_pin`). In the normal case it removes only the lines between the markers, so later changes to kde survive. I read the code but didn't test it.
- **Two notes about other distros.** On Debian, the `other` service includes common-* instead of denying, so install.sh's comment that deleting kde hands the lock screen to a service that "denies everyone" is true only on Fedora. And a Debian package must not edit another package's PAM file from its install scripts, so a later Debian port would need the admin to run screenlock-pin's own installer.

## The bonus question: has anyone done a PIN as well as screenlock-pin, or better?

Nobody among these projects has a PIN limited to the lock screen with a failure budget that persists. The closest are these:

- **pam-u2f with a FIDO2 PIN** is better than screenlock-pin where it matters most. The PIN never exists as a hash on disk, and the security key enforces the retry counter, which root can't reset. The cost is a key to carry, a reset that wipes the key once it is blocked, and no message about how many tries are left.
- **google-authenticator-libpam** has the only software rate limit (RATE_LIMIT, 3 in 30 s by default), and it writes its state carefully. But the seed and the counter live in the user's own writable file, which is exactly what screenlock-pin's setgid PIN checker avoids.
- **pam_faillock** locks the whole account, not just one factor. It keeps its counts under /run, so they are lost at reboot, and it silently does nothing when it can't write them, which the lock screen running as the user can't.
- **GDM's gdm-pin** never had any limit and was removed in 2021. GNOME's lock screen ignores allowed-failures.
- **howdy** has no attempt limit, and its face models are world-readable.

For a typed software PIN, screenlock-pin's design looks stronger than anything here: group-owned hashes and budgets that only a setgid PIN checker can reach. What would improve on it is hardware: a counter kept in a FIDO2 key or a TPM. That is the honest answer to the weakness the README already admits, a copied hash.
