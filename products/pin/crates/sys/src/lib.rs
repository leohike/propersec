//! properpin on a real machine. This crate implements `properpin-core`'s traits:
//!
//! - [`UserFiles`]: one user's settings, hash, state and lock file, and the rules for trusting them;
//! - [`Account`] and [`group_by_name`]: the passwd and group databases;
//! - [`Yescrypt`]: hashing through the system's libxcrypt, the library `/etc/shadow` uses;
//! - [`BootClock`]: this boot's id and the seconds since boot;
//! - [`FileLog`]: log lines to a file, for tests and the helper's `--dev-log`.
//!
//! Nothing here names `/etc` or `/run`: every location comes in through [`UserFiles::new`] and
//! [`UserFiles::with_runtime`].
//! The only `unsafe` code is the libxcrypt FFI, in `crypt.rs`.

mod accounts;
mod clock;
mod crypt;
mod files;
mod log;

pub use accounts::{Account, current_euid, current_uid, group_by_name};
pub use clock::BootClock;
pub use crypt::Yescrypt;
pub use files::UserFiles;
pub use log::FileLog;

use properpin_core::Error;

/// An error from the machine, with what it was about.
fn system(context: impl std::fmt::Display, error: impl std::fmt::Display) -> Error {
    Error::System(format!("{context}: {error}"))
}
