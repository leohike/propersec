//! properpin's rules: whether a PIN may unlock the lock screen right now.
//!
//! Two words run through all of it:
//!
//! - **password**: the account password. It works everywhere, always, and pam_unix checks it.
//! - **PIN**: a short extra secret, digits or letters, that unlocks the lock screen and nothing
//!   else, and only while it is *armed*: for some hours after a password unlock, and until too
//!   many failures in a row. Otherwise the password is required. Too many failures nobody forgave,
//!   across days and reboots, disable the PIN altogether ([`Budget`]).
//!
//! This crate decides and does nothing else: no files, no clock, no hashing, no PAM. Those come
//! in through the [`Store`], [`Clock`], [`Hasher`] and [`Log`] traits, which `properpin-sys`
//! implements for the real machine and the tests implement in memory. It also holds what the
//! setgid helper and its callers must agree on: the [`exit`] codes and [`MAX_INPUT_BYTES`].

#![forbid(unsafe_code)]

mod attempt;
mod budget;
mod error;
pub mod kv;
mod refusal;
mod secret;
mod settings;
mod state;

pub use attempt::{CheckOutcome, Clock, Hasher, Log, Store, Verdict, arm, check, usable_input};
pub use budget::{Budget, Counts, DAY, Disabled, Judged, Limit, WEEK};
pub use error::Error;
pub use refusal::{Refusal, describe_seconds};
pub use secret::Secret;
pub use settings::Settings;
pub use state::PinState;

/// A hard cap, in bytes, on input that is read and hashed, whatever the settings say.
/// libpam passes at most `PAM_MAX_RESP_SIZE` (512).
pub const MAX_PIN_BYTES: usize = 256;

/// Config, user and state files are a few lines; anything longer is not one of ours.
pub const MAX_FILE_BYTES: usize = 4096;

/// yescrypt, the same scheme `/etc/shadow` uses on Fedora.
pub const HASH_PREFIX: &str = "$y$";

/// The setting that holds the PIN hash. Only a user's own file may have it.
pub const HASH_KEY: &str = "hash";

/// The setgid helper's exit codes, which are all it answers: the PAM module and the CLI read them.
pub mod exit {
    /// `check`: the PIN unlocks. `arm`: the PIN is armed. `status`: printed.
    pub const YES: u8 = 0;
    /// `check`: not unlocked. `arm`: not armed. A clean "no", logged by the helper.
    pub const NO: u8 = 1;
    /// Bad arguments, or a refused environment: run as root, a terminal on stdin, `--dev-*` options
    /// under setgid.
    pub const USAGE: u8 = 2;
    /// Something is broken: a file, the clock, libxcrypt, `unix_chkpwd`. Logged by the helper.
    pub const BROKEN: u8 = 3;
}

/// The most the helper reads from stdin: libpam passes at most `PAM_MAX_RESP_SIZE` (512) bytes.
pub const MAX_INPUT_BYTES: usize = 512;
