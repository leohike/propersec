//! properpin's rules: whether a PIN may unlock the lock screen right now.
//!
//! Two words run through all of it:
//!
//! - **password**: the account password. It works everywhere, always, and pam_unix checks it.
//! - **PIN**: a short extra secret, of any characters, that unlocks the lock screen and nothing
//!   else. It is in one of three states:
//!   - *enabled*: the lock screen takes it, from boot on;
//!   - *paused* (password required): after too many consecutive failures, until the next password
//!     unlock;
//!   - *disabled*: after too many failures nobody forgave, across days and reboots ([`Budget`]),
//!     until root turns it back on or sets a new PIN.
//!
//! This crate decides and does nothing else: no files, no clock, no hashing, no PAM. Those come
//! in through the [`Store`], [`Clock`], [`Hasher`] and [`Log`] traits, which `properpin-sys`
//! implements for the real machine and the tests implement in memory. It also holds what the
//! setgid pinchecker and its callers must agree on: the [`exit`] codes and [`MAX_INPUT_BYTES`].

// Stricter checks for shipped code (docs/chaos/plan-tools.md): every unsafe block explains why it is
// sound, nothing indexes or slices without a bounds check, and no cast silently drops bits.
#![warn(clippy::undocumented_unsafe_blocks, clippy::indexing_slicing, clippy::cast_possible_truncation)]
#![forbid(unsafe_code)]

mod attempt;
mod budget;
mod error;
pub mod kv;
mod refusal;
mod secret;
mod settings;

pub use attempt::{
    Clock, Hasher, Log, PasswordCheck, Store, UnlockAttemptOutcome, Verdict, housekeeping_after_password_unlock, input_that_could_be_a_pin,
    try_unlock_with_pin,
};
pub use budget::{Budget, Counts, DAY, Disabled, Judged, Limit, WEEK};
pub use error::Error;
pub use refusal::Refusal;
pub use secret::Secret;
pub use settings::Settings;

/// The longest PIN `set` accepts, in characters. Not a setting: a PIN is a secret short enough to
/// type often, and this is only a sanity bound, said once when `set` asks for the PIN.
pub const MAX_PIN_CHARS: usize = 64;

/// A hard cap, in bytes, on input that is read and hashed: [`MAX_PIN_CHARS`] even at 4 bytes each.
/// libpam passes at most `PAM_MAX_RESP_SIZE` (512).
pub const MAX_PIN_BYTES: usize = 4 * MAX_PIN_CHARS;

/// Config, user and budget files are a few lines; anything longer is not one of ours.
pub const MAX_FILE_BYTES: usize = 4096;

/// yescrypt, the same scheme `/etc/shadow` uses on Fedora.
pub const HASH_PREFIX: &str = "$y$";

/// The setting that holds the PIN hash, the only one a user's own file may have.
pub const HASH_SETTING: &str = "hash";

/// The setgid pinchecker's exit codes, which are all it answers: the PAM module and the CLI read them.
pub mod exit {
    /// `check`: the PIN unlocks. `housekeeping`: done. `status`: printed.
    pub const YES: u8 = 0;
    /// `check`: not unlocked. `housekeeping`: a wrong password, or no PIN set. A clean "no", logged by
    /// the pinchecker.
    pub const NO: u8 = 1;
    /// Bad arguments, or a refused environment: run as root, a terminal on stdin, `--dev-*` options
    /// under setgid.
    pub const USAGE: u8 = 2;
    /// Something is broken: a file, the clock, libxcrypt, `unix_chkpwd`. Logged by the pinchecker.
    pub const BROKEN: u8 = 3;
}

/// The most the pinchecker reads from stdin: libpam passes at most `PAM_MAX_RESP_SIZE` (512) bytes.
pub const MAX_INPUT_BYTES: usize = 512;
