# Testing the uninstaller with a broken properpin

Written as an idea on 2026-10-03 and built the same day. The cases are in `crates/systest/src/uninstall.rs`, the broken builds in `crates/brokenpin`, and `just properpin podman-uninstall` and CI run them. What was left for later is in `docs/uninstall-test-remaining-ideas.md`.

## The idea

What is under test is the uninstaller, not properpin. If properpin breaks something on the live system, `install.sh uninstall` has to put it right. So each case installs a deliberately dysfunctional properpin and checks that one uninstall repairs the damage:

- **Before:** on the stock system, record what the lock screen, `sudo`, `su` and `login` answer to the right and to a wrong password. Also record every file in `/etc/pam.d` byte for byte, the kind, mode and owner of every path under properpin's directories (`/usr/local`, `/etc/sysusers.d`, `/etc/tmpfiles.d`, `/etc/properpin`, `/run/properpin`, `/var/lib/properpin`), and the groups.
- **Install broken:** install and enable a broken properpin through `install.sh`, under exactly the real names, and set a PIN. Some cases install the real properpin and then damage `/etc/pam.d/kde` instead.
- **Is it broken?** Check that the lock screen really breaks the way the case says, so no case can pass because the damage never happened, and that `sudo`, the way in for a repair, still works.
- **Uninstall:** `install.sh uninstall --yes`. It must succeed, leave no helper running, and leave a record matching the one from before, apart from what uninstall keeps on purpose: `/etc/properpin`, `/var/lib/properpin` and the `properpin` group.
- **Again:** a second uninstall changes nothing. Then the real properpin installs, the password arms it, the PIN unlocks, and uninstalling that matches the record too.

Each case runs in a fresh container, so no case inherits another's damage. An attempt still running after 30 seconds counts as hung and is killed.

## The cases

The broken builds come from `crates/brokenpin`, a test-only crate. `testing/podman/build-broken.sh` puts each variant in a directory of its own under `/opt/properpin/broken`, as the real build with one part swapped. `install.sh --from` then installs it exactly like the real thing.

| Case | What is broken | What the lock screen does |
|---|---|---|
| `module-panics` | The module panics inside `pam_sm_authenticate`; a panic can't unwind out of `extern "C"`, so Rust aborts the process | Dies on any attempt |
| `module-segfaults` | The module writes to an unmapped address | Dies |
| `module-sleeps` | The module sleeps for ten hours | Hangs |
| `module-says-yes` | The module returns success for everything | A wrong password unlocks |
| `module-missing-symbol` | A module without `pam_sm_authenticate` | The right password is refused |
| `module-garbage` | Text where the module should be | The right password is refused |
| `module-deleted` | The real module, deleted after enable | The right password is refused |
| `helper-says-yes` | The helper exits 0, yes, whatever it is asked | A wrong password unlocks |
| `helper-sleeps` | The helper sleeps for ten hours | The right password unlocks only after 20 seconds, the module's 10-second helper timeout twice |
| `kde-end-marker-deleted` | The block's end marker removed | `disable` gives up |
| `kde-block-twice` | The block repeated | `disable` gives up |
| `kde-markers-stripped` | The lines left in, both markers removed | `disable` gives up |
| `kde-cut-inside-block` | The file cut off after the PIN line | `disable` gives up, and the right password is refused |

The segfault is a real memory fault rather than `raise(SIGSEGV)`: the test's attempt process is a Rust program, and std's own SIGSEGV handler swallowed the raised signal, so the first version came back as a clean refusal.

## What the uninstaller had to learn

- **One command repairs everything.** `uninstall` used to refuse while properpin's lines were in `/etc/pam.d/kde`, sending the user to `disable` first. Now it takes them out itself.
- **It restores a damaged PAM file.** When the block can't be removed cleanly (one begin and one end marker, nothing of properpin's left outside them, the stock auth line still there), it puts back the copy saved at enable, after a diff and a yes, and keeps the damaged file as `/etc/properpin/kde.pam.damaged`. It does the same for a PAM file that is missing, or one that has lost its stock auth line while a saved copy exists. Without a saved copy it refuses and removes nothing, because deleting a module the PAM file still names is the one thing that must never happen.
- **It removes the directories install created.** The first run failed every case on three leftovers: `/usr/local/lib64/security`, `/etc/sysusers.d` and `/etc/tmpfiles.d` didn't exist in the stock image, so `install` created them and `uninstall` left them behind. `install` now notes each directory it creates in `/etc/properpin/install.created-dirs`, and `uninstall` removes those that are empty, deepest first.
- **It removes properpin's own directory whatever is in it,** instead of an `rmdir` that would stop a `set -e` script halfway on any extra file.

`disable` stays the gentler step. It still refuses a damaged block, and now says that `uninstall` restores the saved copy.

## What the cases showed about PAM

A module that the PAM file names but libpam can't load (deleted, garbage, or missing its entry point) fails the whole stack, even with properpin's `[success=done default=ignore]` control. The right password is refused, and the lock screen locks its user out. This is why the uninstaller must never delete the module while the PAM file still names it. The mutation check below shows the cases catch exactly that.

## Checked by breaking things on purpose

With `uninstall` made to skip the PAM file entirely, so it deletes the module but leaves the lines, the cases fail on "kde right: Unlocked before, Refused after uninstall". That is the lock-out itself, shown together with the PAM file's diff.

## What it can't show

The real lock screen and SELinux stay with the VM. A module that locks out or hangs the real greeter means repairing from a TTY or another session, which the container can only stand in for with `sudo`.
