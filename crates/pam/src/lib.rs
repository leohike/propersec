//! `pam_screenlock_pin.so`: screenlock-pin's PAM module, for the lock screen's `auth` stack only.
//!
//! Two lines of `/etc/pam.d/screenlock-auth` call it, around the stock `auth substack password-auth`
//! line, and `/etc/pam.d/kde` pulls that file in where its stock stack had `password-auth` (see
//! `packaging/screenlock-auth.pam`):
//!
//! ```text
//! check         Is the typed input the PIN, and is the PIN enabled? Success unlocks, but never
//!               sooner than min_milliseconds_before_pin_unlock after the PIN checker started;
//!               anything else returns PAM_IGNORE at once, so the stock stack checks the same input
//!               as the password.
//! after-password-auth
//!               After a password unlock: forgive the failures of the last moments as the user's
//!               own, the password itself among them, and start the consecutive count over, which
//!               unpauses the PIN. Done in pam_sm_setcred, which libpam calls on this line only
//!               after the stock `password-auth` stack succeeded, never after a PIN unlock or a
//!               failure; no password is read.
//! ```
//!
//! It decides nothing itself. The hashes and the counts belong to the `screenlock-pin` group, out of
//! the user's reach, and only the setgid PIN checker `screenlock-pin-checker` reads them: the module hands it
//! what was typed through a pipe and reads its exit code, the way pam_unix uses `unix_chkpwd`.
//!
//! Arguments, none of them in the shipped lines:
//!
//! ```text
//! pin_checker=PATH  the PIN checker, instead of /usr/local/libexec/screenlock-pin/screenlock-pin-checker (tests)
//! log=FILE         append the module's own log lines here instead of syslog (tests)
//! test_panic       panic on purpose while SIGCHLD is changed, to prove a panic becomes PAM_IGNORE
//!                  and puts SIGCHLD back (tests)
//! ```
//!
//! It runs inside the lock screen, as the locked user, never as root. Refusal is the default:
//! every error, panic or refusal ends in PAM_IGNORE, and only the PIN checker's yes returns success.

// Stricter checks for shipped code (docs/chaos/plan-tools.md): every unsafe block explains why it is
// sound, nothing indexes or slices without a bounds check, and no cast silently drops bits.
#![warn(clippy::undocumented_unsafe_blocks, clippy::indexing_slicing, clippy::cast_possible_truncation)]
mod args;
mod pam;
mod run;

pub use args::{Args, Mode};
