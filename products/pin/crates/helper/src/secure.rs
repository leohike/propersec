//! The setgid start-up, and syslog. All of the helper's `unsafe` code is in this file.
//!
//! A setgid program starts in a state its caller chose: open files, ignored or blocked signals, an
//! environment, a working directory, a umask, resource limits. Before anything else, `start_clean`
//! puts most of them back to a known value, the way `unix_chkpwd` and other setuid and setgid helpers
//! do. What the kernel and glibc already do for any elevated start, setgid included, and isn't
//! repeated here: the process can't be traced or dumped by its caller, and the dynamic loader ignores
//! `LD_PRELOAD`, `LD_LIBRARY_PATH` and similar variables.
#![allow(unsafe_code)]

use std::ffi::CString;

use properpin_core::Log;

/// Put the process into a known state. Call it first in `main`, before any other thread exists.
pub fn start_clean() {
    // SAFETY: each call below is a plain libc call with valid arguments; none of them touches memory
    // Rust owns. The process has one thread, so changing the environment, the signal handlers and
    // the file descriptors can't race with anything.
    unsafe {
        // stdin, stdout and stderr open, on /dev/null if the caller closed them, so a file the
        // helper opens later can never land on fd 0, 1 or 2 and receive what is meant for them.
        for fd in 0..=2 {
            if libc::fcntl(fd, libc::F_GETFD) == -1 {
                // open() returns the lowest free descriptor, which is `fd`.
                libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            }
        }
        // Every other descriptor the caller left open is closed: the helper uses none of them.
        libc::close_range(3, libc::c_uint::MAX, 0);
        // Every signal back to its default action, and none blocked. SIGPIPE stays ignored, so a
        // write to a closed pipe is an error to handle rather than a sudden death.
        for signal in 1..=64 {
            if signal != libc::SIGKILL && signal != libc::SIGSTOP {
                libc::signal(signal, if signal == libc::SIGPIPE { libc::SIG_IGN } else { libc::SIG_DFL });
            }
        }
        let mut none = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut none);
        libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
        // Nothing the caller set in the environment is read, by this code or by glibc.
        libc::clearenv();
        // New files are readable by their owner alone, and the working directory is nobody's choice.
        libc::umask(0o077);
        libc::chdir(c"/".as_ptr());
    }
}

/// Whether the kernel started this program with more rights than its caller has: setuid, setgid or
/// file capabilities. The dynamic loader asks the same question to decide whether to ignore
/// `LD_PRELOAD`.
pub fn elevated() -> bool {
    // SAFETY: getauxval only reads the auxiliary vector the kernel passed at exec.
    unsafe { libc::getauxval(libc::AT_SECURE) != 0 }
}

/// Logs to the authpriv facility as `properpin-helper`, like pam_unix and unix_chkpwd.
pub struct Syslog;

impl Syslog {
    pub fn open() -> Self {
        // SAFETY: the identity is a static string, as openlog requires: it keeps the pointer.
        unsafe { libc::openlog(c"properpin-helper".as_ptr(), libc::LOG_PID, libc::LOG_AUTHPRIV) };
        Self
    }
}

impl Log for Syslog {
    fn log(&self, line: &str) {
        let Ok(line) = CString::new(line) else { return };
        // SAFETY: a "%s" format with exactly one NUL-terminated argument.
        unsafe { libc::syslog(libc::LOG_NOTICE, c"%s".as_ptr(), line.as_ptr()) };
    }
}
