# Where the installed files go, and why

Written on 2026-10-19. `packaging/install.sh` spreads screenlock-pin over seven directories besides `/etc/pam.d`. This doc asks three questions about that: whether each directory is needed, why everything shouldn't simply go into one directory, and whether symlinks (into PATH and into `/etc/pam.d`) would be better than copying the real files there. It ends with what could change. Claims are marked "verified" (read in the code, or seen on the development machine, a Fedora Atomic system like Aurora), "from the web" (with the source listed at the end) or "reasoned" (thought through, not tested).

## The short answer

The spread follows one real rule: screenlock-pin has three kinds of file (code, settings, data), each with a different writer, different rights and a different life, and the system reads a few files only from fixed places. Code could shrink from three directories to one, and the command in PATH could be a symlink. Settings and data must stay apart from code and from each other. `/etc/pam.d/screenlock-auth` should stay a real file, not a symlink, because a symlink there can lock the lock screen after an ostree rollback.

## What install puts where today

The paths are set in `packaging/install.sh`, lines 81 to 95 (verified).

| Directory | What screenlock-pin puts there | Owner and mode | Kind | Fixed, or a choice |
|---|---|---|---|---|
| `/usr/local/libexec/screenlock-pin/` | the real CLI binary and the setgid PIN checker | `root:root 0755`; the checker `root:screenlock-pin 2755` | code | code needs one place; which place is a choice |
| `/usr/local/lib64/security/` | `pam_screenlock_pin.so` | `root:root 0755` | code | a choice: the PAM lines name the module by its full path, so this directory is only a habit |
| `/usr/local/bin/` | a two-line wrapper script that passes the installed paths to the real CLI | `root:root 0755` | code | fixed only in the sense that a command must be in PATH |
| `/etc/screenlock-pin/` | `config`, `users/` with one hash file per user, `install.created-dirs` | `root:root 0755`; `users/` `root:screenlock-pin 0750` | settings (and the hashes, see the Open points section) | fixed: settings belong in `/etc` |
| `/var/lib/screenlock-pin/` | each user's budget and lock file | `root:screenlock-pin 1770` (sticky, group-writable); files `<uid>:screenlock-pin 0600` | data | fixed: data that changes while running belongs in `/var/lib` |
| `/etc/sysusers.d/` | `screenlock-pin.conf`, declaring the group | `root:root 0644` | system drop-in | a system directory; `/usr/local/lib/sysusers.d` would also do, as explained below |
| `/etc/tmpfiles.d/` | `screenlock-pin.conf`, keeping `/var/lib/screenlock-pin` in shape | `root:root 0644` | system drop-in | a system directory; `/usr/local/lib/tmpfiles.d` would also do |

Besides these, install writes `/etc/pam.d/screenlock-auth`, `integrate-into-pam.sh add` changes one word of `/etc/pam.d/kde`, and the group lands in `/etc/group` and `/etc/gshadow`.

So three directories are screenlock-pin's own (`/usr/local/libexec/screenlock-pin`, `/etc/screenlock-pin`, `/var/lib/screenlock-pin`), and in four shared directories it puts one file each. The "Files, once installed" table in `README-BIG.md` leaves out the module, the CLI binary, the wrapper and `install.created-dirs`.

## Three kinds of file

Each kind has its own writer, its own rights and its own fate on upgrade and uninstall:

- **Code** is written only by `install`, replaced wholesale on every upgrade, and removed by `uninstall`. Only root can write it, and nobody needs to.
- **Settings** are written by root, through `screenlock-pin set`, `remove` and `restore-defaults` or by hand, and kept through upgrades and through `uninstall`. The hashes must be readable by the PIN checker's group and by nobody else.
- **Data** is written by the setgid PIN checker on every unlock attempt, so its directory must be writable by the group (sticky, so each user's run can only replace that user's own files), and it is kept through `uninstall`.

The code relies on the kinds living apart (verified). `install` deletes everything else in `/usr/local/libexec/screenlock-pin` after putting the new files in place (`install.sh` line 301), and `uninstall` runs `rm -rf` on that directory (`install.sh` line 443). Both are safe only because no PIN or budget ever lives there. In one shared directory, a bug in either cleanup would delete every PIN. The same goes for the reverse direction: `screenlock-pin remove --all` deletes everything in the PIN and budget directories, which is safe only because no code lives there.

The rights point the same way (reasoned). The budget directory is the one place the PIN checker's group can write. If it sat above the code, or code sat inside it, an exploited PIN checker could replace code that root runs or that the lock screen loads. With separate trees that can't happen by construction. Inside one tree it would be a rule to remember forever.

## Places the system reads from fixed paths

Some places are not screenlock-pin's choice at all (verified unless marked):

- **`/etc/pam.d`**: libpam opens `/etc/pam.d/<service>` (and on Fedora `/usr/lib/pam.d/<service>`, under the read-only `/usr` on Atomic; `docs/analysis/kscreenlocker-pam-service.md` has the details).
- **sysusers and tmpfiles drop-ins**: systemd reads them from `/etc/sysusers.d` and `/etc/tmpfiles.d`, from the same names under `/run`, `/usr/local/lib` and `/usr/lib`, and nowhere else (verified in the man pages of systemd 259 on the development machine). `/usr/lib` is read-only on Atomic and `/run` is emptied at every boot, so the real choice is `/etc` or `/usr/local/lib`. In `/etc` the drop-ins roll back with the PAM file and the settings; in `/usr/local/lib`, which is on `/var` on Aurora, they would stay with the code. The Open points section below says what that would change for the group.
- **PATH**: a command has to be in a directory on PATH to be typed by name. `/usr/local/bin` is the admin's place for exactly that.
- **The PAM module directory**: libpam looks for a bare module name only in its own directory, `/usr/lib64/security`, which is read-only on Atomic. That is why the PAM lines spell out the full path, as `README-BIG.md` explains. It also means the module's directory is free to choose.

## Why not everything in one directory

### The kinds have different lives on Aurora

On an ostree system such as Aurora, the three kinds don't just have different writers: they live on different time lines (verified on the development machine, and from the web for the ostree docs):

- `/usr` is the read-only image.
- `/usr/local` is a symlink to `/var/usrlocal`, and `/opt` to `/var/opt`. `/var` is one directory shared by every deployment; ostree never touches it, so it is never rolled back.
- `/etc` is per deployment. On an upgrade, ostree builds the new deployment's `/etc` by a three-way merge of the current one. Changes made after that go only into the new deployment's `/etc`, and booting the older deployment brings back its older `/etc`.

The development machine shows it. Its booted deployment (44.20261013.1) has properpin, screenlock-pin's earlier name, installed: `/etc/properpin`, properpin's lines in `/etc/pam.d/kde` and the properpin group in `/etc/group`. Its previous deployment (44.20261006.1), which a rollback would boot, has the stock `/etc/pam.d/kde`, no `/etc/properpin` and no properpin group. `/usr/local/libexec/properpin`, the module in `/usr/local/lib64/security` and `/var/lib/properpin` are on `/var`, so they are there whichever deployment boots.

Settings in `/etc` therefore roll back with the PAM file that uses them, while code and data in `/var` don't. Any layout has to live with that split; a single directory would only hide it. It is also the reason behind the answer on `/etc/pam.d` symlinks in the Symlinks section below.

### SELinux labels files by their path

The label of a file comes from rules matched against its path, so moving a file changes its label (verified with `matchpathcon` on the development machine, SELinux enforcing):

| Path | Label |
|---|---|
| `/usr/local/lib64/security/pam_x.so` | `lib_t` |
| `/usr/local/libexec/screenlock-pin/screenlock-pin-checker` | `usr_t` |
| `/usr/local/libexec/screenlock-pin/pam_x.so` | `lib_t` |
| `/usr/local/bin/screenlock-pin` | `bin_t` |
| `/usr/libexec/x` | `bin_t` |
| `/opt/screenlock-pin/libexec/screenlock-pin-checker` | `bin_t` |
| `/opt/screenlock-pin/bin/screenlock-pin` | `bin_t` |
| `/opt/screenlock-pin/lib/pam_x.so` | `lib_t` |
| `/opt/screenlock-pin/etc/config` | `etc_t` |
| `/opt/screenlock-pin/var/lib/x` | `var_lib_t` |
| `/opt/screenlock-pin/share/screenlock-auth.pam` | `usr_t` |
| `/etc/pam.d/x`, `/etc/screenlock-pin/users/x` | `etc_t` |
| `/var/lib/screenlock-pin/x` | `var_lib_t` |

The policy treats `/var/opt` as `/opt` and `/var/usrlocal` as `/usr/local`, so the same labels apply on ostree. Three things follow. The setgid PIN checker in `/usr/local/libexec/screenlock-pin` gets the generic `usr_t`, not `bin_t`, the type the policy gives programs; it worked for an unconfined user on the Aurora VM, and `docs/chaos/concerns.md` already lists confined users as untested. Any file ending in `.so` gets `lib_t`, so the module keeps its label wherever it goes. And the policy already expects a package under `/opt` to split itself into `bin/`, `lib/`, `libexec/`, `etc/` and `var/lib/`, and labels each part as its kind: even the "one directory" layout splits by kind inside.

### Mount options

Hardening guides such as the CIS benchmarks recommend mounting `/var` with `nosuid` (from the web), which makes the kernel ignore setuid and setgid bits there. On a traditional Fedora, code under `/usr/local` is not on `/var`, so this doesn't touch it. On Aurora, any setgid program installed outside the image is on `/var`, under `/usr/local` or `/opt` alike, so such a mount would take the PIN checker's group away. That fails safe (reasoned): the PIN checker can't read the hash, the PIN is refused and the password works. Putting code into `/var/lib/screenlock-pin` on a traditional system would bring the same problem there.

### Backups and resets

The systemd project's idea of a stateless system is that deleting `/etc` and `/var` gives back the vendor's pristine state, because everything else is in `/usr` (from the web). Backup tools and habits follow the same lines: `/etc` and `/var/lib` hold what can't be rebuilt, code can be installed again. Mixing PINs into the code's directory, or code into a data directory, breaks those habits in both directions.

### What the one-directory idea gets right

One place to audit, one listing that shows everything installed, one directory to delete. That is worth having for the code, and it is available: code can go into one directory. The PINs and budgets are meant to outlive an uninstall anyway (`uninstall` keeps them on purpose, and prints the command that removes them), so they need a place of their own no matter what.

## How other tools do it

Security tools that need more rights than their callers all spread the same way, by kind:

- **pam_faillock** (verified, `rpm -ql pam` on the development machine): the module in `/usr/lib64/security/pam_faillock.so`, its settings in `/etc/security/faillock.conf`, its tool in `/usr/bin/faillock`, and its failure records in `/run/faillock`, created by a tmpfiles rule. It is the closest relative of screenlock-pin's budget.
- **sudo** (verified, `rpm -ql sudo`): the setuid program in `/usr/bin/sudo`, its plugins in `/usr/libexec/sudo`, its settings in `/etc/sudoers` and `/etc/sudoers.d`, its time stamps in `/run/sudo/ts` and the record of who saw the lecture in `/var/db/sudo/lectured`. Its tmpfiles rule creates `/run/sudo` because a directory sudo created itself would get the wrong SELinux label, its own comment says.
- **unix_chkpwd** (verified): pam_unix's helper, the model for the PIN checker, is one setuid file in `/usr/bin` (`/usr/sbin` is the same directory on Fedora); the data it reads is `/etc/shadow`.
- **The FHS rule for `/opt`** (from the web): a package may put its static files under `/opt/<package>`, but its settings must go into `/etc/opt/<package>` and its changing data into `/var/opt/<package>`. Even the standard's "self-contained" layout splits off settings and data.
- **Google Chrome** (from the web): its code and its setuid sandbox helper are in `/opt/google/chrome`, but the policies an admin sets are in `/etc/opt/chrome/policies`, which only root may write.
- **1Password** (from the web): its code in `/opt/1Password`, with a helper setgid to its own `onepassword` group, the same pattern as the PIN checker.
- **Wazuh** (from the web): everything under `/var/ossec`, the nearest thing to one directory, but its own SELinux documentation gives `bin`, `etc`, `logs` and `queue` different types, so it splits by kind inside its directory.

## Symlinks

The rule: a symlink is safe when the link and its target are created, upgraded, rolled back and deleted together, and every directory on the target's path is writable by root alone. It is a hazard when the two live on different time lines, as `/etc` and `/usr/local` do on Aurora (see The kinds have different lives on Aurora, above).

### The command in PATH: a symlink is better

The wrapper in `/usr/local/bin` exists only because the CLI requires `--etc`, `--budget` and `--pin-checker` (`crates/cli/src/main.rs`, lines 59 to 70). The module and the PIN checker already fall back to the installed paths in `crates/core/src/protocol.rs` (`crates/pam/src/args.rs` line 55, `crates/checker/src/main.rs` line 101). If the CLI took the same defaults, `/usr/local/bin/screenlock-pin` could be a symlink to the real binary, and `install.sh check` would no longer have to compare a generated script. The CLI's re-run through sudo uses `std::env::current_exe()`, which resolves to the real binary, so it would keep working. Both the link and its target are on `/var` on Aurora and under root's `/usr/local` elsewhere, so they share one life. Chrome links its command into `/usr/bin` from `/opt` the same way (reasoned from its packages; not checked here).

### The module and the PIN checker: no link needed

Each is called by its full path: the PAM lines name the module, and the module runs the PIN checker from the path compiled into it. A link adds a second thing that can go missing and gains nothing. The module could simply move next to the PIN checker, keeping its `lib_t` label.

### /etc/pam.d/screenlock-auth: keep a real file

Today the changed line in `/etc/pam.d/kde` and the file it names, `/etc/pam.d/screenlock-auth`, are both in `/etc`, so on Aurora they always roll back together. Take this sequence (reasoned from the ostree behaviour above and the failure modes `README-BIG.md` describes; not tested):

- screenlock-pin is installed and in `kde` in deployment A;
- the system upgrades to deployment B, whose `/etc` inherits all of it;
- in B, `remove-from-pam` and `uninstall` take everything out, code included (the code is on `/var`, so it is gone for every deployment);
- the user rolls back to A, for an unrelated reason such as a bad update.

A's `/etc` still has `kde` naming `screenlock-auth`. With a real file, `screenlock-auth` is there too, and it names a module that is gone: libpam skips a module it can't load, so only the PIN stops and the password works, as the uninstall cases showed. With a symlink from `/etc/pam.d/screenlock-auth` into `/usr/local` or `/opt`, the link is there but its target is gone, which is the same as a missing file: libpam fails every attempt at the lock screen, the password too. That is the one failure `integrate-into-pam.sh` and `uninstall` go out of their way to prevent.

authselect does link its PAM files (`/etc/pam.d/password-auth` points into `/etc/authselect/`), which may look like a counterexample, but its targets are in `/etc` too, so link and target share one life. That fits the rule above.

Two smaller reasons point the same way (verified). `install.sh check` treats a symlink where it expects a file as "not a file", as do the PIN checker's own trust rules for its files, so a link would need an exception in the very code that guards against tampering. And the file is three lines that are screenlock-pin's alone; copying it costs nothing, and `check` already compares its bytes with the shipped `packaging/screenlock-auth.pam`.

## What could change

- **Code in one directory.** Move the module next to the PIN checker, in `/usr/local/libexec/screenlock-pin`, and drop `/usr/local/lib64/security`. Or move all the code to `/opt/screenlock-pin/{bin,lib,libexec}`, which also gives the PIN checker `bin_t` instead of `usr_t`. Debian's policy reserves `/usr/local` for the admin (from the web); that fits, since an admin runs `install.sh` by hand, so either place is defensible. `/opt` is the one with the better label.
- **A symlink in PATH.** Give the CLI the installed paths as defaults, as the module and the PIN checker already have, and replace the wrapper with a symlink.
- **Keep the rest where it is.** `/etc/screenlock-pin`, `/var/lib/screenlock-pin`, the real file `/etc/pam.d/screenlock-auth`, and the drop-ins in `/etc/sysusers.d` and `/etc/tmpfiles.d`.
- **Fix the README table.** Add the module, the CLI binary, the wrapper (or link) and `install.created-dirs`.

With the first two changes, the install uses six directories instead of seven: one for code, one for settings, one for data, and three system directories it can't avoid, plus a link in PATH.

If screenlock-pin ever ships as an RPM or a system extension, the code would move into the image instead: the module to `/usr/lib64/security` (then named without a path), the binaries to `/usr/libexec` and `/usr/bin`, the PAM file to `/usr/lib/pam.d`, and the drop-ins to `/usr/lib/sysusers.d` and `/usr/lib/tmpfiles.d`. `/etc` would then hold only what the admin changed, and code would roll back with the image (reasoned).

## Open points

- **The PIN hashes roll back; the budgets don't.** The hashes are in `/etc`, so on Aurora a rollback brings back the hashes of that older deployment, while the budgets in `/var/lib` stay as they are (reasoned from the ostree behaviour verified above). A user who set a new PIN because someone saw the old one, and then rolls back for an unrelated reason, has the old PIN working again, paired with the new PIN's budget. The password in `/etc/shadow` rolls back the same way, so this matches the password, but the budget mismatch is screenlock-pin's own. Two ways out: record in the budget something that ties it to its hash (when the PIN was set, which `Budget::set` already holds, compared with the hash file), and refuse a mismatch as a foreign budget; or move `users/` to `/var/lib/screenlock-pin`, with the same `0750` group-readable mode, so hashes and budgets share one life. The second would also fit systemd's line between settings in `/etc` and state in `/var/lib`, since the hashes are written by a command, not by the admin.
- **A rollback to before the install leaves the PIN checker's group without a name.** In the older deployment, `/etc/group` has no screenlock-pin group, but the setgid PIN checker and the budget directory on `/var` still carry its number (seen on the development machine for properpin). That is harmless unless something in that deployment creates a new system group that gets the same number (reasoned). Two things could close it, neither tried. systemd-sysusers accepts an absolute path instead of `-` as the group's number, and then takes the number from that path's group, which its man page names as meant for setuid and setgid programs (verified in the man page); what it does while the path doesn't exist yet, on a first install, is unchecked. And a drop-in in `/usr/local/lib/sysusers.d` would be on `/var` on Aurora, so the group would be created again at the next boot of the older deployment.
- **Labels for confined users.** Whether `usr_t` instead of `bin_t` matters for the PIN checker under a confined SELinux user (`user_t`, `staff_t`) is untested, as `docs/chaos/concerns.md` says.
- **`/var` mounted `nosuid`.** Not tried. It should fail safe, as the Mount options section above reasons.

## Sources

- ostree: [atomic upgrades](https://ostreedev.github.io/ostree/atomic-upgrades/), [deployments](https://ostreedev.github.io/ostree/deployment/), [/var](https://ostreedev.github.io/ostree/var/); [Universal Blue: how ostree merges /etc and /var](https://universal-blue.discourse.group/t/did-you-know-how-ostree-update-merges-changes-into-etc-and-var/7233); [RHEL image mode: file systems](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/using_image_mode_for_rhel_to_build_deploy_and_manage_operating_systems/managing-file-systems-in-image-mode-for-rhel)
- [FHS 3.0](https://www-fastly.debian.org/doc/packaging-manuals/fhs/fhs-3.0.txt), [freedesktop FHS: /opt](https://specifications.freedesktop.org/fhs/latest/opt.html), [Debian Policy, The Operating System (/usr/local)](https://www.debian.org/doc/debian-policy/ch-opersys)
- [Lennart Poettering: stateless systems](https://lwn.net/Articles/602639/), [systemd-sysext(8)](https://man7.org/linux/man-pages/man8/systemd-sysext.8.html)
- [CIS benchmark items, including nosuid on /var (Entrust PKI Hub)](https://api.managed.entrust.com/pki/1.4/Linux-CIS-benchmarks.html)
- [Chromium: the Linux sandbox](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/linux/README.md), [Chrome: Linux quick start for administrators](https://www.chromium.org/administrators/linux-quick-start)
- [1Password community: BrowserSupport and the onepassword group](https://www.1password.community/discussions/1password/solved-browser-support-error-on-gentoo-linux/160461), [Universal Blue: 1Password on custom images](https://universal-blue.discourse.group/t/fix-faq-1password-browser-extension-and-cli-don-t-work-in-my-custom-image/187)
- [Wazuh: SELinux context](https://documentation.wazuh.com/4.13/development/selinux-wazuh-context.html)
