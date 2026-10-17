//! Test-only: a deliberately broken `pam_properpin.so`, so the container can check that
//! `install.sh uninstall` repairs a lock screen that a broken properpin has wrecked
//! (docs/install-uninstall-with-a-broken-properpin.md). One feature picks how it breaks:
//!
//! ```text
//! (none)      no pam_sm_authenticate at all, as a build missing a symbol would be
//! panics      panics inside pam_sm_authenticate, which aborts the lock screen's process
//! segfaults   dies of SIGSEGV
//! sleeps      sleeps for ten hours, hanging the lock screen
//! says-yes    unlocks whatever is typed
//! ```
//!
//! Nothing in the shipped crates depends on this one.

// The exported entry points need #[unsafe(no_mangle)], and the segfault a raw pointer write.
#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_void};

const PAM_IGNORE: c_int = 25;

#[cfg(any(feature = "panics", feature = "segfaults", feature = "sleeps", feature = "says-yes"))]
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(_pamh: *mut c_void, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> c_int {
    broken()
}

/// A panic can't unwind out of an `extern "C"` function, so Rust aborts the whole process.
#[cfg(feature = "panics")]
fn broken() -> c_int {
    panic!("brokenpin: a panic inside pam_sm_authenticate");
}

/// A real invalid memory access, not `raise(SIGSEGV)`: a Rust host's own SIGSEGV handler (std's
/// stack-overflow check) swallows a raised signal, but lets a real fault kill the process.
#[cfg(feature = "segfaults")]
fn broken() -> c_int {
    // SAFETY: none, on purpose: address 8 is never mapped, so this write faults and the process dies.
    unsafe { std::ptr::without_provenance_mut::<u8>(8).write_volatile(1) };
    PAM_IGNORE
}

#[cfg(feature = "sleeps")]
fn broken() -> c_int {
    std::thread::sleep(std::time::Duration::from_secs(10 * 3600));
    PAM_IGNORE
}

#[cfg(feature = "says-yes")]
fn broken() -> c_int {
    const PAM_SUCCESS: c_int = 0;
    PAM_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(_pamh: *mut c_void, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> c_int {
    PAM_IGNORE
}
