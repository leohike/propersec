//! `pam_properpin.so`: properpin's PAM module, for the lock screen's `auth` stack only.
//!
//! Two lines of `/etc/pam.d/kde` call it, around a direct `pam_unix` line (see `pam/kde-auth.pam`):
//!
//! ```text
//! check  Is the typed input the PIN, and is the PIN armed right now? Success unlocks, but never
//!        sooner than min_milliseconds_before_pin_unlock after the module was called; anything
//!        else returns PAM_IGNORE at once, so pam_unix checks the same input as the password.
//! arm    The password just succeeded: arm the PIN, with no failures and a fresh window.
//! ```
//!
//! It decides nothing itself. The hashes and the counts belong to the `properpin` group, out of
//! the user's reach, and only the setgid helper `properpin-helper` reads them: the module hands it
//! what was typed through a pipe and reads its exit code, the way pam_unix uses `unix_chkpwd`.
//!
//! Arguments, all spelled out in the PAM line so nothing falls back to a real path by accident:
//!
//! ```text
//! helper=PATH    the helper (/usr/local/libexec/properpin/properpin-helper)   required
//! config=PATH    the global config (/etc/properpin/config), for how long a     required with check,
//!                correct PIN takes at least                                    refused with arm
//! log=FILE       append the module's own log lines here instead of syslog (tests)
//! test_panic     panic on purpose while SIGCHLD is changed, to prove a panic becomes PAM_IGNORE
//!                and puts SIGCHLD back (tests)
//! ```
//!
//! It runs inside the lock screen, as the locked user, never as root. Refusal is the default:
//! every error, panic or refusal ends in PAM_IGNORE, and only the helper's yes returns success.

// Stricter checks for shipped code (docs/plan-tools.md): every unsafe block explains why it is
// sound, nothing indexes or slices without a bounds check, and no cast silently drops bits.
#![warn(clippy::undocumented_unsafe_blocks, clippy::indexing_slicing, clippy::cast_possible_truncation)]
mod args;
mod pam;
mod run;

pub use args::{Args, Mode};
