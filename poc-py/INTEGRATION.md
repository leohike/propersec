# Integration

This file records what the standalone tests cannot prove, what installing involves, and the checks to run on the real lock screen. Install with a root shell open on a TTY (Ctrl+Alt+F3) the whole time.

## The system it assumes

lazypass targets an image-based Fedora KDE desktop (Fedora Kinoite and its derivatives) running Plasma 6.7. Four facts about such systems shape it:

- **The vendor PAM file is `/usr/etc/pam.d/kde`.** `/etc/pam.d/kde` is the ostree-merged copy of it, and there is no `/usr/lib/pam.d/kde`. Advice to "delete `/etc/pam.d/kde` to fall back to the vendor file" is wrong here: it would hand the lock screen to the `other` service, which denies everyone. Uninstalling means restoring the file from `/usr/etc/pam.d/kde`, never deleting it.
- **Editing `/etc/pam.d/kde` freezes it.** Once it differs from the vendor copy, image updates to `/usr/etc/pam.d/kde` stop arriving. Record the vendor file's checksum at install time and compare it after updates.
- **Plasma 6.8 is due 2026-10-14.** It brings switchable lock-screen authenticators (kscreenlocker MR !318), each with its own `/etc/pam.d/kde-*` file. Re-check that the password field still authenticates through `kde` after the upgrade.
- **The greeter runs as the user.** Confirm its SELinux domain while locked: `ps -eZ | grep kscreenlocker`, expected `unconfined_t`.

## What the tests could not prove

- **The real pam_unix.** With `use_first_pass` on the added line, it must never prompt a second time, and the stock substack's pam_unix must reuse the typed input. Watch for exactly one prompt per attempt on the real greeter.
- **The service name.** The greeter must authenticate the password field through `kde`. Its binary names `kde-fingerprint` and `kde-smartcard`, which points to `kde` for the main field.
- **SELinux.** The greeter must be able to:
  - run `/usr/bin/python3` on a script in `/usr/local/libexec/lazypass`;
  - read `/etc/lazypass`;
  - write `/run/user/<uid>`.

  Check `ausearch -m avc -ts recent` afterwards.
- **A missing or non-executable hook.** Covered only by `just lazypass::test-all`, because pam_exec logs those failures to the journal.
- **Timing on the real greeter.** In tests the hook takes about 85 ms per attempt (median), and less than 210 ms at worst.
- **Two real users.** Each one's short_password, state and failed unlock count must stay independent.
- **The interactive `set`.** Its terminal prompt (getpass) is untested; the tests use stdin.

## Install steps

- **Code, data directories and labels:** `just lazypass deploy`. It runs the tests, then `sudo deploy.py install`, which puts the code in `/usr/local/libexec/lazypass/` (that is, `/var/usrlocal/...`), owned by root, directory 0755: `pam_hook.py` and `cli.py` 0755, `core.py` and `common.py` 0644. It links `/usr/local/bin/lazypass` to `cli.py`, which finds its modules through the link. It creates `/etc/lazypass` and `/etc/lazypass/users`, `root:root 0755`, and runs `restorecon -RF` on all of it. Modes are set explicitly, because the repo's copies are group-writable from the shared directory's umask. Each file is written beside its target and renamed over it, so deploying again over a running install is safe. A `config` (0644) is still yours to write, if one is wanted. `deploy` never touches `/etc/pam.d/kde`.
- **Check it:** `just lazypass check-deploy` lists anything missing, or with the wrong kind, owner, mode, content or SELinux label, or not part of lazypass. `just lazypass smoke` runs the deployed copy as you: the hook's `self-test` prints `hello lazypass` once its modules and libcrypt load, the hook refuses a `check` made outside PAM, and `lazypass status` runs through the link on PATH. `deploy` runs both at the end.
- **The short_password:** `sudo lazypass set`, then `lazypass status`. If sudo says the command isn't found, its `secure_path` leaves out `/usr/local/bin`; use the full path.
- **The PAM file:** `just lazypass deploy-pam`, with a root shell open on a TTY. It refuses unless `check-deploy` passes, and refuses when the image's `/usr/etc/pam.d/kde` no longer matches what `pam/kde` was built from (then `just lazypass render-pam`, review, commit, retry), so an image update is never silently undone. It makes `backup/kde` if there is none, shows the diff, asks, writes `pam/kde` beside `/etc/pam.d/kde` and renames it over, and runs `restorecon -F`. `check-deploy` then reports whether lazypass is active.
- **Acceptance tests,** on the real greeter (`journalctl -b -t lazypass` shows each decision):
  - the short_password only after a full_password unlock;
  - three failed unlocks, then the full_password is required;
  - the full_password works in every state;
  - after a reboot, the full_password is required until the first full_password unlock;
  - empty, random and very long input;
  - a corrupted or deleted state file;
  - `sudo -k; sudo true`, a polkit prompt, SDDM and TTY login all still want the full_password;
  - two users independent;
  - no AVC denials.
- **Recovery,** if the lock screen won't unlock: go to a TTY and run `loginctl unlock-session <id>`, then run `just lazypass restore-pam`. It puts `backup/kde` back, or the file you name; `just lazypass restore-pam /usr/etc/pam.d/kde` restores the image's vendor copy. It shows the diff, asks, writes the file beside the old one and renames it over, then runs `restorecon -F`, so owner, mode and label match the original exactly. `-f` restores even when the files already match, to try the command out.

## Deferred ideas

- **Require the full_password after suspend:** a systemd sleep hook that deletes the state file, so every resume needs the full_password.
- **A wider timeout:** wrap the hook in `/usr/bin/timeout` in the PAM line, which also covers interpreter startup.
- **Allow the short_password at login (v1.1):** a Plasma autostart entry that allows the short_password on graphical login. It must refuse when SDDM autologin is on.
