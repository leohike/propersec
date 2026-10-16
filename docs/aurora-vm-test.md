# First install on a real KDE: the Aurora VM

properpin installed, enabled and used at the real Plasma lock screen for the first time, on 2026-10-15, in a VM running Aurora. Everything earlier ran in `target/`, temporary directories and podman containers. This note records how it was done, what was tested, what the journal and the files showed, what was found, and what is still untested on a real system. The plan row "Verify on a real system" in `docs/plan.md` points here.

## Summary

properpin works at the real Plasma 6.7.5 lock screen under SELinux enforcing, through a reboot. The module loads in the greeter, the greeter starts the setgid helper, the password keeps working with properpin in the stack, the PIN unlocks only while armed, three failures in a row hand over to the password, the failure budget forgives typos and keeps unforgiven failures across a reboot, and the PIN is refused after boot until the first password unlock. No crash, no SELinux denial and no lock-out happened. Uninstall, the budget disabling the PIN, expiry and kscreenlocker 6.8 were not tested; the last section lists everything left.

## The machine

- A VM running Aurora 44 (Kinoite base, image `ghcr.io/leohike/aurora-max:latest`, version 44.20261013.1), host name `aurora-first`. An ostree system: `/usr` is read-only, `/usr/local` is a symlink to `/var/usrlocal`, and `/etc` is writable and kept across image updates by ostree's three-way merge. Automatic updates were set to stage, with their timer inactive, so no image changed during the test.
- kscreenlocker and plasma-workspace 6.7.5. In 6.7.5, PAM runs on a thread inside `kscreenlocker_greet`, not in 6.8's separate worker process, and the greeter keeps one PAM handle for its life.
- Linux-PAM 1.7.2, libxcrypt 4.5.2, kernel 7.2.5. SELinux enforcing with the targeted policy; auditd and sshd running; swap on zram only; `fs.protected_regular = 1`.
- `/etc/pam.d/kde` was the stock Fedora file, `auth substack password-auth` followed by `auth include postlogin`, which is what `install.sh enable` expects. Nothing else in `/etc/pam.d` includes `kde`. `password-auth` is authselect's default without `pam_faillock`: `pam_env`, `pam_faildelay delay=2000000`, `pam_unix nullok`, `pam_deny`.
- One user, `aragorn` (uid 1000, in `wheel`), with the graphical session on seat0 and an SSH session alongside it, for running the root steps and for recovery.

## The build

The VM had no Rust. `brew install rust` gave rustc and cargo 1.99.0 (Homebrew's build), above the declared `rust-version` of 1.98. The host already had gcc and libxcrypt's headers and `libcrypt.so`. The build was of commit ea03068 ("Make a correct PIN wait out a minimum before it unlocks") with a clean tree:

```
cargo build --release --locked -p pam_properpin -p properpin-helper -p properpin-cli
```

A Homebrew toolchain could have linked the binaries against libraries under `/home/linuxbrew`, which the user can write to; in a setgid helper or a module loaded by the lock screen, that would hand the user code running with the helper's group or inside the greeter. So the linkage was checked before installing, with `readelf -d`, `readelf -l` and `ldd`:

- `libpam_properpin.so` needs `libpam.so.0`, `libgcc_s.so.1`, `libc.so.6` and `ld-linux-x86-64.so.2`, all resolved from `/lib64`. Its flags are `BIND_NOW` and `NOW NODELETE`, so `-z nodelete` from `crates/pam/build.rs` is in place.
- `properpin-helper` and `properpin` need `libcrypt.so.2`, `libgcc_s.so.1` and `libc.so.6`, all from `/lib64`, with the interpreter `/lib64/ld-linux-x86-64.so.2`.
- None of the three has an RPATH or a RUNPATH.

The test suite was not run with this toolchain. CI builds and tests with Fedora's own Rust, and the container tests had already passed on this commit.

## The install

Run by hand as root from the SSH terminal, in the repo, after a copy of the PAM file was put aside as a last-resort fallback:

```
sudo cp -a /etc/pam.d/kde ~/kde.pam.orig
sudo products/pin/packaging/install.sh install
sudo products/pin/packaging/install.sh check
sudo products/pin/packaging/install.sh enable
```

`install` created the `properpin` group through `systemd-sysusers`; the audit log has `op=adding-group acct="properpin" exe="systemd-sysusers" … res=success` at 15:11:47, and the group got gid 948 with no members. `check` passed, including the SELinux labels and the group's locked password in `/etc/gshadow`, so `enable` went ahead, showed its diff and wrote the block after a yes. `/etc/pam.d/kde` then had properpin's block of three lines between its two markers, above the stock `auth substack password-auth`.

The installed files, with their labels:

| Path | Mode and owner | SELinux type |
|---|---|---|
| `/usr/local/lib64/security/pam_properpin.so` | `-rwxr-xr-x root root` | `lib_t` |
| `/usr/local/libexec/properpin/` | `drwxr-xr-x root root` | `usr_t` |
| `/usr/local/libexec/properpin/properpin` | `-rwxr-xr-x root root` | `usr_t` |
| `/usr/local/libexec/properpin/properpin-helper` | `-rwxr-sr-x root properpin` | `usr_t` |
| `/usr/local/bin/properpin` | the wrapper | `bin_t` |
| `/etc/properpin/` | `drwxr-xr-x root root` | `etc_t` |
| `/etc/properpin/users/` | `drwxr-x--- root properpin` | `etc_t` |
| `/etc/sysusers.d/properpin.conf`, `/etc/tmpfiles.d/properpin.conf` | `root root 0644` | `etc_t` |
| `/run/properpin/` | `drwxrwx--T root properpin` | `var_run_t` |
| `/var/lib/properpin/` | `drwxrwx--T root properpin` | `var_lib_t` |
| `/etc/pam.d/kde` | `-rw-r--r-- root root` | `etc_t` |

`/etc/sysusers.d` didn't exist on this Aurora image, so `install` created it and noted it in `/etc/properpin/install.created-dirs`, for `uninstall` to remove again once empty.

## The tests, in order

All times are local (UTC+01:00) on 2026-10-15. The excerpts are from `journalctl`, shortened to the time, the program and the message. Every lock started a new `kscreenlocker_greet` process (seven different greeter pids appear in the first boot's journal alone), which is why no restart of anything was needed after `enable`: each greeter reads `/etc/pam.d/kde` at its own `pam_start`.

### Enabled, no PIN set

The first stage left the user without a PIN, so the module and the helper ran on every attempt but could never unlock anything; the password alone decided. It was the test that properpin in the stack doesn't break the password.

```
15:12:59 properpin-helper: aragorn: no PIN is set, refused
15:12:59 properpin-helper: aragorn: no PIN is set, nothing to arm
15:13:07 properpin-helper: aragorn: no PIN is set, refused
15:13:07 properpin-helper: aragorn: no PIN is set, nothing to arm
15:14:49 properpin-helper: aragorn: no PIN is set, refused
15:14:49 unix_chkpwd: password check failed for user (aragorn)
15:14:49 kscreenlocker_greet: pam_unix(kde:auth): authentication failure; … user=aragorn
15:14:54 properpin-helper: aragorn: no PIN is set, refused
15:14:54 unix_chkpwd: password check failed for user (aragorn)
15:14:59 properpin-helper: aragorn: no PIN is set, refused
15:14:59 unix_chkpwd: password check failed for user (aragorn)
15:15:04 properpin-helper: aragorn: no PIN is set, refused
15:15:04 properpin-helper: aragorn: no PIN is set, nothing to arm
```

- Two unlocks with the right password, at 15:12:59 and 15:13:07. Each ran the whole chain: the module in the greeter, the setgid helper started from it (`refused`, no PIN), the direct `pam_unix` line accepting the password, the `arm` line after it (`nothing to arm`), then the stock substack.
- Three wrong passwords, then the right one, from 15:14:49 to 15:15:04: each wrong one refused by `unix_chkpwd` with no `arm` after it, about 5 seconds apart (pam_unix's 2-second delay plus typing), then the right one unlocking and reaching `arm`.

### A PIN set

`sudo properpin set` ran twice, at 15:16:32 and 15:16:39; the first run was given up or had two different PINs, and the second set the PIN (the PIN twice, then the password to seal the pepper). The PIN was armed at once.

```
15:17:49 properpin-helper: aragorn: not the PIN, failure 1 of 3
15:17:50 properpin-helper: aragorn: password accepted, PIN armed
15:17:54 properpin-helper: aragorn: not the PIN, failure 1 of 3
15:17:54 unix_chkpwd: password check failed for user (aragorn)
15:17:59 properpin-helper: aragorn: unlocked with the PIN
15:18:08 properpin-helper: aragorn: unlocked with the PIN
```

- **The password still unlocks:** at 15:17:49 the password, typed into the same field, is first checked as a PIN (`not the PIN, failure 1 of 3`), then `pam_unix` accepts it and `arm` re-arms the PIN a second later. That failure is forgiven by the password straight away, as designed.
- **A wrong PIN, then the right one:** at 15:17:54 the wrong PIN fails both as a PIN and as a password, and the right PIN unlocks at 15:17:59.
- **The PIN alone unlocks,** at 15:18:08 and many times after.

### Three failures in a row

```
15:18:26 properpin-helper: aragorn: not the PIN, failure 1 of 3
15:18:31 properpin-helper: aragorn: not the PIN, failure 2 of 3
15:18:37 properpin-helper: aragorn: not the PIN, failure 3 of 3, password required from now on
15:18:41 properpin-helper: aragorn: PIN refused, password required: 3 failures in a row
15:18:45 properpin-helper: aragorn: PIN refused, password required: 3 failures in a row
15:18:51 properpin-helper: aragorn: PIN refused, password required: 3 failures in a row
15:18:51 properpin-helper: aragorn: password accepted, PIN armed
15:18:59 properpin-helper: aragorn: unlocked with the PIN
```

After the third wrong PIN the right PIN is refused (15:18:41 and 15:18:45, each also refused by `unix_chkpwd` as a password), the password unlocks and re-arms it, and the PIN works again. The same pattern ran a second time from 15:19:09 to 15:19:55, with a 32-second pause in the middle.

### Other services

At 15:21:03 and 15:21:07 two `sudo` attempts failed through `unix_chkpwd`, and the third, at 15:21:11, succeeded through `pam_unix`. The user's report was that the PIN was typed to `sudo` first; the journal shows only that two inputs failed and the password worked. `sudo` uses `/etc/pam.d/sudo`, which properpin doesn't touch, so the PIN can't reach it.

### The failure budget

Every failure up to 15:20 was followed by a correct PIN within 45 seconds or the password within 90, so all were forgiven, and `properpin status` showed `concerning failures: 0 within 24 hours (of 10), 0 within 7 days (of 20), 0 since the PIN was set (of 100); 0 waiting to be forgiven`. The longest gap was 15:19:09 to 15:19:55, 46 seconds, ended by the password, within its 90.

To see a failure become concerning, a wrong PIN was left alone for longer than 90 seconds:

```
15:23:26 properpin-helper: aragorn: not the PIN, failure 1 of 3
15:26:03 properpin-helper: aragorn: 1 failure(s) not followed by an unlock in time, now concerning: 1 within 24 hours, 1 within 7 days, 1 since the PIN was set
15:26:03 properpin-helper: aragorn: unlocked with the PIN
```

The helper judged it at its next run, 2 minutes 37 seconds later, before unlocking with the PIN, and `properpin status` then showed 1 within 24 hours, 1 within 7 days and 1 in total.

### A reboot

The VM was rebooted at 15:33 (boot at 15:33:45).

```
15:43:43 properpin-helper: aragorn: PIN refused, password required: no password unlock since boot
15:43:48 properpin-helper: aragorn: PIN refused, password required: no password unlock since boot
15:43:54 properpin-helper: aragorn: PIN refused, password required: no password unlock since boot
15:43:55 properpin-helper: aragorn: password accepted, PIN armed
15:43:59 properpin-helper: aragorn: unlocked with the PIN
…
15:44:35 properpin-helper: aragorn: not the PIN, failure 1 of 3
15:44:40 properpin-helper: aragorn: not the PIN, failure 2 of 3
15:46:46 properpin-helper: aragorn: 2 failure(s) not followed by an unlock in time, now concerning: 3 within 24 hours, 3 within 7 days, 3 since the PIN was set
15:46:46 properpin-helper: aragorn: unlocked with the PIN
```

- **The PIN is refused after boot** until the first password unlock, then works.
- **The tmpfiles rule ran at a real boot** for the first time. Until now `install.sh` had always created `/run/properpin` itself. After the reboot it was back as `drwxrwx--T root properpin`, `var_run_t`, on the `/run` tmpfs; `systemd-tmpfiles --cat-config` lists properpin's two `d` lines, and `systemd-tmpfiles-setup` logged nothing about properpin (its only warnings were about `/home`, `/srv` and `/root`, which are symlinks on ostree).
- **The budget survived the reboot:** the concerning failure from before it was still counted, and two more wrong PINs left for two minutes made 3.

The files after the reboot, as root:

```
/etc/properpin/users:
-rw-r-----. 1 root    properpin 247 Oct 15 15:16 aragorn
/run/properpin:
-rw-------. 1 aragorn properpin   0 Oct 15 15:43 1000.lock
-rw-------. 1 aragorn properpin 149 Oct 15 15:46 1000.state
/var/lib/properpin:
-rw-------. 1 aragorn properpin  85 Oct 15 15:46 1000.budget
```

```
$ sudo cat /var/lib/properpin/1000.budget
pending = none
concerning = 1792074206 1792075475 1792075480
total = 3
disabled = no
```

The three timestamps are 15:23:26, 15:44:35 and 15:44:40, the three failures the journal reports as concerning. No stray `.1000.*` temporary files were in either directory. The state file and the PIN file were not printed: while the PIN is armed the state holds the pepper in clear text, and with the PIN file's hash that is enough to guess the PIN offline.

`properpin status` after the reboot:

```
user       aragorn
PIN        set, in /etc/properpin/users/aragorn
policy     armed for 8h after a password unlock, until 3 failures in a row
set rules  4 to 12 characters, yescrypt cost 5, pepper sealed at cost 8
note       a password change stops the PIN from working, and nothing can tell why; sudo properpin set makes a new one
budget     concerning failures: 3 within 24 hours (of 10), 3 within 7 days (of 20), 3 since the PIN was set (of 100); 0 waiting to be forgiven
right now  PIN armed for another 7h56m, 0 of 3 failures so far
```

### SELinux and crashes

`ausearch -m avc -ts today` before the reboot and `ausearch -m avc -ts boot` after it showed the same handful of denials, all at boot and none involving properpin: `bootupd_t` running `lsblk` and connecting to `systemd-machined`'s userdb socket (permissive for that domain), and `tuned_t` running `chcon` without `mac_admin`. Nothing from `kscreenlocker_greet`, `properpin-helper`, `/run/properpin` or `/var/lib/properpin`, though the helper ran about 60 times across the two boots. The journal shows no crash, segfault or coredump from the greeter in either boot.

## What was found

- **The SELinux labels came out right on ostree.** The worry before the install was that `matchpathcon` expects `lib_t` for `/usr/local/lib64/security/…` but `usr_t` for the same file through `/var/usrlocal/lib64/security/…`, so `restorecon` through the symlink could set one while `install.sh check` expected the other, and `enable` would refuse. It didn't happen: the module is `lib_t`, `matchpathcon -V` verifies it, and `check` passed.
- **No policy of its own was needed.** The lock screen runs unconfined, and the generic labels (`usr_t` for the helper, `var_run_t` and `var_lib_t` for the state and the budget) let it run the setgid helper and the helper write its files. A confined user (`user_t`, `staff_t`) is still untested, as `docs/concerns.md` says.
- **`systemd-sysusers` created the group on a real system,** and `check`'s reading of `/etc/gshadow` passed: no members, nobody's primary group, a locked password.
- **The tmpfiles rule is right,** shown by the first real boot after install.
- **kscreenlocker 6.7.5 behaves as `docs/kscreenlocker-pam-contract.md` read it:** one prompt per attempt, the PIN or the password in the same field, a new greeter per lock, and pam_unix's 2-second delay after each failure, wrong PINs included, since a wrong PIN also fails as a password.
- **Each wrong PIN costs a `unix_chkpwd` run,** logged as `password check failed`, because the direct `pam_unix` line checks every input the PIN didn't accept. `kscreenlocker_greet` itself logs `pam_unix(kde:auth): authentication failure` only for the first failure of each greeter, while `unix_chkpwd` logs every one.
- **A Homebrew toolchain builds usable binaries,** linked only against the system's libraries. That has to be checked for each build, since it isn't guaranteed.

Nothing was found that needs a code change.

## What remains untested on a real system

- **Uninstall on the real system:** `install.sh disable` and `uninstall`, their interactive diff and prompt, the relabelling of the restored `/etc/pam.d/kde`, and the leftovers matching what the uninstall cases allow. Nothing was uninstalled in this round.
- **The PIN disabled by the budget,** at 10 concerning failures in 24 hours (or a lower limit in `/etc/properpin/config` for the test), then refused even after the password, and `sudo properpin enable` bringing it back.
- **Expiry** after 8 hours armed.
- **A password change,** which should stop the PIN silently until the next `set`.
- **Suspend and resume** with the PIN armed.
- **Other services refusing the PIN,** beyond `sudo`: polkit, SDDM, a TTY login, SSH.
- **A repair from a text console** after a deliberately broken install, as `docs/uninstall-test-remaining-ideas.md` asks for.
- **kscreenlocker 6.8:** its worker process, the 50 ms timing check and the minimum wait before a PIN unlock, the "ms elapsed during pam_authenticate" warnings, and a PIN typed during the failure delay. Aurora ships 6.7.5; 6.8 will come with an image update, which replaces `/usr` but keeps the edited `/etc/pam.d/kde`.
- **An ostree image update with properpin enabled,** and `ostree admin config-diff` before and after uninstall.
- **The fingerprint and smartcard services** alongside the PIN; this VM has neither.
- **More than one user with a PIN,** and a confined SELinux user.
- **The build from Homebrew's Rust 1.99 against the test suite,** and an install built with Fedora's own toolchain on this VM.
