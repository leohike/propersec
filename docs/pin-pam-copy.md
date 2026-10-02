# Our copy of the typed PIN, and libpam's

An open question, written down when the module started wiping its own copies of secrets (2026-10-02).

## The question

The module copies what was typed out of libpam (`pam_get_authtok`) into a buffer of its own, which wipes itself when the check is done. Is libpam ever expected to wipe its copy as soon as possible, ahead of the end of the attempt, in a way our copy would defeat? Put differently: does our copy ever make the secret live longer, or in more places, than it would without properpin?

## What is known, from Linux-PAM 1.7.2

- **libpam wipes every copy it lets go of.** `pam_get_authtok` (`libpam/pam_get_authtok.c`) takes the application's response from the conversation, stores it with `pam_set_item(PAM_AUTHTOK, ...)`, which copies it, and then overwrites and frees the response (`pam_overwrite_string`, `_pam_drop`). `pam_set_item` (`libpam/pam_item.c`) overwrites the previous `PAM_AUTHTOK` before replacing it. `pam_authenticate` (`libpam/pam_auth.c`) clears `PAM_AUTHTOK` before and after every attempt (`_pam_sanitize`).
- **libpam keeps its copy for the whole attempt, on purpose.** The stack depends on it: properpin's `check` line reads it, then `pam_unix use_first_pass` reads the same text to check it as the password, then the stock `password-auth` substack reads it again. It is wiped only when `pam_authenticate` returns, after `pam_unix`'s failure delay, so about 2 seconds after a wrong input.
- **Our copy lives for less time than libpam's.** It exists only while `check` runs (about 25 ms for a PIN, less for input that skips hashing), inside libpam's lifetime, and is wiped when it is dropped. It adds one more place in memory for that window, not more time.
- **The application has copies of its own** that neither libpam nor properpin can reach: kscreenlocker's text field, its `QByteArray` and `QString` conversions, and in 6.8 the D-Bus messages between the greeter and its PAM worker (see `kscreenlocker-pam-contract.md`).

## What is still open

- Is there any PAM configuration or module in the `kde` stack that clears `PAM_AUTHTOK` early on purpose (for example a module that consumes it and sets it to NULL), whose intent our earlier copy would quietly undercut? None is known in Fedora's stock stack.
- Is there guidance, in the Linux-PAM module writers' guide or elsewhere, on modules keeping private copies of `PAM_AUTHTOK`? If modules are expected never to copy it, the alternative is to borrow libpam's buffer for the duration of the check, which removes our copy at the cost of unsafe code that reasons about how long libpam's pointer stays valid.
- Does the copy matter at all next to the application's copies? If kscreenlocker keeps the text in several unwiped places for longer, one short-lived, wiped copy in our module changes little in practice; this is about doing our part correctly, not about the overall exposure.

## Current decision

Copy into a buffer that wipes itself (`Secret` in `properpin-core`), chosen for reviewability. Revisit if any of the open points above turns out to matter.
