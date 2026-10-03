//! properpin on a real machine. This crate implements `properpin-core`'s traits:
//!
//! - [`UserFiles`]: one user's settings, hash, state and lock file, and the rules for trusting them;
//! - [`Account`] and [`group_by_name`]: the passwd and group databases;
//! - [`Yescrypt`]: hashing through the system's libxcrypt, the library `/etc/shadow` uses, and
//!   sealing the pepper with a key derived from the password;
//! - [`UnixChkpwd`]: the account password, checked the way pam_unix checks it;
//! - [`BootClock`]: this boot's id, the seconds since boot, and the wall clock;
//! - [`FileLog`]: log lines to a file, for tests and the helper's `--dev-log`.
//!
//! Nothing here names `/etc` or `/run`: every location comes in through [`UserFiles::new`] and
//! [`UserFiles::with_runtime`].
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

pub use accounts::{Account, current_egid, current_euid, current_gid, current_uid, group_by_name};
pub use chkpwd::UnixChkpwd;
pub use clock::BootClock;
pub use crypt::{NewPin, Yescrypt};
pub use files::{UserFiles, global_settings};
pub use log::FileLog;

use properpin_core::Error;

/// An error from the machine, with what it was about.
fn system(context: impl std::fmt::Display, error: impl std::fmt::Display) -> Error {
    Error::System(format!("{context}: {error}"))
}
