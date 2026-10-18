//! properpin on a real machine. This crate implements `properpin-core`'s traits:
//!
//! - [`UserFiles`]: one user's settings, hash, budget and lock file, and the rules for trusting them;
//! - [`AllUsers`]: every user's files at once, for `properpin doctor`, `remove --all` and `restore-defaults`;
//! - [`Account`], [`group_by_name`] and [`shadow_hash`]: the passwd, group and shadow databases;
//! - [`Yescrypt`]: hashing through the system's libxcrypt, the library `/etc/shadow` uses;
//! - [`UnixChkpwd`]: the account password, checked the way pam_unix checks it;
//! - [`SystemClock`]: the wall clock, and [`local_time`] to show its times;
//! - [`FileLog`]: log lines to a file, for tests and the pinchecker's `--dev-log`.
//!
//! Nothing here names `/etc` or `/var`: every location comes in through [`UserFiles::new`] and
//! [`UserFiles::with_budget`].
//! The only `unsafe` code is the libxcrypt FFI, in `crypt.rs`, and glibc's local time, in `clock.rs`.

// Stricter checks for shipped code (docs/chaos/plan-tools.md): every unsafe block explains why it is
// sound, nothing indexes or slices without a bounds check, and no cast silently drops bits.
#![warn(clippy::undocumented_unsafe_blocks, clippy::indexing_slicing, clippy::cast_possible_truncation)]
mod accounts;
mod chkpwd;
mod clock;
mod crypt;
mod files;
mod log;

pub use accounts::{Account, current_egid, current_euid, current_gid, current_uid, group_by_name, shadow_hash};
pub use chkpwd::UnixChkpwd;
pub use clock::{SystemClock, local_time};
pub use crypt::Yescrypt;
pub use files::{AllUsers, UserFiles};
pub use log::FileLog;

use properpin_core::Error;

/// An error from the machine, with what it was about.
fn system(context: impl std::fmt::Display, error: impl std::fmt::Display) -> Error {
    Error::System(format!("{context}: {error}"))
}
