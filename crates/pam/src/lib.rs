//! `pam_properpin.so`: properpin's PAM module, for the lock screen's `auth` stack only.
//!
//! Two lines of `/etc/pam.d/kde` call it, around the stock `auth substack password-auth` line,
//! which stays as it is (see `packaging/kde-auth.pam`):
//!
//! ```text
//! check         Is the typed input the PIN, and is the PIN enabled? Success unlocks, but never
//!               sooner than min_milliseconds_before_pin_unlock after the pinchecker started;
//!               anything else returns PAM_IGNORE at once, so the stock stack checks the same input
//!               as the password.
//! housekeeping  After the stock stack, whatever it answered: when the pinchecker finds the password
//!               right, forgive the failures of the last moments as the user's own, the password
//!               itself among them, and start the consecutive count over, which unpauses the PIN.
//! ```
//!
//! It decides nothing itself. The hashes and the counts belong to the `properpin` group, out of
//! the user's reach, and only the setgid pinchecker `properpin-pinchecker` reads them: the module hands it
//! what was typed through a pipe and reads its exit code, the way pam_unix uses `unix_chkpwd`.
//!
//! Arguments, none of them in the shipped lines:
//!
//! ```text
//! pinchecker=PATH  the pinchecker, instead of /usr/local/libexec/properpin/properpin-pinchecker (tests)
//! log=FILE         append the module's own log lines here instead of syslog (tests)
//! test_panic       panic on purpose while SIGCHLD is changed, to prove a panic becomes PAM_IGNORE
//!                  and puts SIGCHLD back (tests)
//! ```
//!
//! It runs inside the lock screen, as the locked user, never as root. Refusal is the default:
//! every error, panic or refusal ends in PAM_IGNORE, and only the pinchecker's yes returns success.

// Stricter checks for shipped code (docs/chaos/plan-tools.md): every unsafe block explains why it is
// sound, nothing indexes or slices without a bounds check, and no cast silently drops bits.
#![warn(clippy::undocumented_unsafe_blocks, clippy::indexing_slicing, clippy::cast_possible_truncation)]
mod args;
mod pam;
mod run;

pub use args::{Args, Mode};
