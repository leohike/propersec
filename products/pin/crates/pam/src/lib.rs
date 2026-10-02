//! `pam_properpin.so`: properpin's PAM module, for the lock screen's `auth` stack only.
//!
//! Two lines of `/etc/pam.d/kde` call it, around a direct `pam_unix` line (see `pam/kde-auth.pam`):
//!
//! ```text
//! check  Is the typed input the PIN, and is the PIN armed right now? Success unlocks; anything
//!        else returns PAM_IGNORE, so pam_unix checks the same input as the password.
//! arm    The password just succeeded: arm the PIN, with no failures and a fresh window.
//! ```
//!
//! Arguments, all spelled out in the PAM line so nothing falls back to a real path by accident:
//!
//! ```text
//! etc=DIR        where config and users/ live (/etc/properpin)       required
//! run_base=DIR   parent of the per-uid runtime dirs (/run/user)      required
//! owner=UID      who must own the files under etc (default 0, root)
//! log=FILE       append log lines here instead of syslog (tests)
//! test_panic     panic on purpose, to prove a panic becomes PAM_IGNORE (tests)
//! ```
//!
//! It runs inside the lock screen, as the locked user, never as root. Refusal is the default:
//! every error, panic or refusal ends in PAM_IGNORE, and only a matching PIN returns success.

mod args;
mod pam;
mod run;

pub use args::{Args, Mode};
