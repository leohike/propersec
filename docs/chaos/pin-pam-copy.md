# Our copy of the typed PIN, and libpam's

An open question, written down when the module started wiping its own copies of secrets (2026-10-02).

**Later the same day, the PIN check moved into a setuid helper,** setgid only since 2026-10-03. The module still copies what was typed out of libpam, but now writes it into a pipe to `properpin-helper` and drops its copy when the helper answers; the helper reads it into a buffer of fixed size and wipes it on exit, and `arm` passes the password on to `unix_chkpwd` through another pipe. That adds a short-lived copy in a second process, which runs as the user with the `properpin` group added. The reasoning below still holds for both copies: each lives shorter than libpam's.

## The question

The module copies what was typed out of libpam (`pam_get_authtok`) into a buffer of its own, which wipes itself when the check is done. Is libpam ever expected to wipe its copy as soon as possible, ahead of the end of the attempt, in a way our copy would defeat? Put differently: does our copy ever make the secret live longer, or in more places, than it would without properpin?

## What is known, from Linux-PAM 1.7.2

- **libpam wipes every copy it lets go of.** `pam_get_authtok` (`libpam/pam_get_authtok.c`) takes the application's response from the conversation, stores it with `pam_set_item(PAM_AUTHTOK, ...)`, which copies it, and then overwrites and frees the response (`pam_overwrite_string`, `_pam_drop`). `pam_set_item` (`libpam/pam_item.c`) overwrites the previous `PAM_AUTHTOK` before replacing it. `pam_authenticate` (`libpam/pam_auth.c`) clears `PAM_AUTHTOK` before and after every attempt (`_pam_sanitize`).
- **libpam keeps its copy for the whole attempt, on purpose.** The stack depends on it: properpin's `check` line reads it, then `pam_unix use_first_pass` reads the same text to check it as the password, then the stock `password-auth` substack reads it again. It is wiped only when `pam_authenticate` returns, after `pam_unix`'s failure delay, so about 2 seconds after a wrong input.
- **Our copy lives for less time than libpam's.** It exists only while `check` runs (about 25 ms for a PIN, less for input that skips hashing), inside libpam's lifetime, and is wiped when it is dropped. It adds one more place in memory for that window, not more time.
- **The application has copies of its own** that neither libpam nor properpin can reach: kscreenlocker's text field, its `QByteArray` and `QString` conversions, and in 6.8 the D-Bus messages between the greeter and its PAM worker (see `kscreenlocker-pam-contract.md`).

## Could something tell PAM to wipe, and miss our copy?

The worry: something outside PAM (a security tool, the system, an "under attack" mode) tells PAM to wipe secrets from RAM at once, or kills PAM, while our module keeps its own copy alive because it never heard. Checked on 2026-10-02; it can't happen.

- **PAM is not a separate program.** libpam is a library loaded into the lock screen's process (in 6.8, into its PAM worker process), and properpin's module is loaded into the same process, as more code in the same memory. There is no PAM to signal or kill on its own: whatever happens to that process happens to libpam and the module together.
- **PAM has no wipe or event channel anyway.** libpam calls a module only for its operations (authenticate, setcred, account, session, password). The only other hook is the cleanup a module can register with `pam_set_data`, which runs at `pam_end`. Nothing in the API lets anything outside ask a module to wipe ([pam(3)](https://man7.org/linux/man-pages/man3/pam.3.html), [pam.d(5)](https://www.man7.org/linux/man-pages/man5/pam.d.5.html)).
- **The nearest real things are something else.**
  - [pam_panic](https://github.com/pampanic/pam_panic) is a module with a panic password or panic USB key that destroys the LUKS header and can reboot or shut down. It doesn't wipe RAM or signal other modules. This is the duress idea, which is in properpin's plan as its own item.
  - LUKS suspend (`cryptsetup luksSuspend`, cryptsetup-suspend) wipes disk encryption keys before sleep. It's a kernel and dm-crypt feature that never touches program memory, and it is still contested: a [systemd feature request](https://github.com/systemd/systemd/issues/5794), [LWN on securely suspending LUKS disks](https://lwn.net/Articles/1090568/), and a [report that it stopped wiping keys after Linux 6.9](https://discuss.privacyguides.net/t/since-linux-6-9-luks-suspend-stopped-wiping-disk-encryption-keys-from-memory/38949).
- **The outside events that do exist hit both copies the same way.**
  - **A kill or crash** (6.8 cancelling an attempt, the lock screen crashing): the whole process dies, with libpam's copy and ours in it. Neither owner wipes at that point: our wipe-on-drop doesn't run on SIGKILL, and neither does libpam's cleanup. The kernel takes the memory back unwiped. It clears pages before handing them to another process, so nothing leaks to other programs, but the bytes can sit in physical RAM until the page is reused.
  - **A core dump on a crash** captures both copies. 6.7.5 allows core dumps; 6.8's worker makes itself non-dumpable.
  - **Suspend or hibernate in the middle of an attempt:** RAM, or the hibernation image, holds both.
- **The one real "wipe it" mechanism is in the kernel.** The boot option `init_on_free=1` zeroes memory as soon as it is freed, including when a process dies. It covers libpam's copy and ours alike, with no cooperation from either. That makes it a system hardening choice, not something properpin can or should do.
- **Our copy can never be the last one standing.** It is made after libpam has its copy and wiped before control goes back to libpam. libpam can't interrupt a module mid-call, so there is no moment when libpam is in charge and our copy still exists. In every outcome (normal return, error, panic, kill), ours is gone by the time libpam's is, or both disappear in the same instant.

## What is still open

- Is there any PAM configuration or module in the `kde` stack that clears `PAM_AUTHTOK` early on purpose (for example a module that consumes it and sets it to NULL), whose intent our earlier copy would quietly undercut? None is known in Fedora's stock stack.
- Is there guidance, in the Linux-PAM module writers' guide or elsewhere, on modules keeping private copies of `PAM_AUTHTOK`? If modules are expected never to copy it, the alternative is to borrow libpam's buffer for the duration of the check, which removes our copy at the cost of unsafe code that reasons about how long libpam's pointer stays valid.
- Does the copy matter at all next to the application's copies? If kscreenlocker keeps the text in several unwiped places for longer, one short-lived, wiped copy in our module changes little in practice; this is about doing our part correctly, not about the overall exposure.

## Current decision

Copy into a buffer that wipes itself (`Secret` in `properpin-core`), chosen for reviewability. The worry about an outside wipe signal is settled: there is none, and our copy can't outlive libpam's. Revisit if any of the points under What is still open turns out to matter.
