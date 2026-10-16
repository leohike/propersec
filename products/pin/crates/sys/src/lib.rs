//! properpin on a real machine. This crate implements `properpin-core`'s traits:
//!
//! - [`UserFiles`]: one user's settings, hash, budget and lock file, and the rules for trusting them;
//! - [`Account`], [`group_by_name`] and [`shadow_hash`]: the passwd, group and shadow databases;
//! - [`Yescrypt`]: hashing through the system's libxcrypt, the library `/etc/shadow` uses;
//! - [`UnixChkpwd`]: the account password, checked the way pam_unix checks it;
//! - [`SystemClock`]: the wall clock;
//! - [`FileLog`]: log lines to a file, for tests and the pinchecker's `--dev-log`.
//!
//! Nothing here names `/etc` or `/var`: every location comes in through [`UserFiles::new`] and
//! [`UserFiles::with_budget`].
//! The only `unsafe` code is the libxcrypt FFI, in `crypt.rs`.

// Stricter checks for shipped code (docs/plan-tools.md): every unsafe block explains why it is
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
pub use clock::SystemClock;
pub use crypt::Yescrypt;
pub use files::{UserFiles, global_settings};
pub use log::FileLog;

use properpin_core::Error;

/// An error from the machine, with what it was about.
fn system(context: impl std::fmt::Display, error: impl std::fmt::Display) -> Error {
    Error::System(format!("{context}: {error}"))
}
