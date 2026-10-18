//! The C side: the two functions libpam calls, and the few libpam functions this module calls.
//! All of the module's `unsafe` code is in this file.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, MutexGuard, PoisonError};

use properpin_core::{Error, Log, Secret};
use properpin_sys::FileLog;

use crate::run::{Transaction, run, run_unlocked, unpause_by};
use crate::{Args, Mode};

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
const PAM_AUTHTOK: c_int = 6;
const PAM_SILENT: c_int = 0x8000;
const LOG_NOTICE: c_int = 5;

/// libpam's opaque `pam_handle_t`.
#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_get_authtok(pamh: *mut PamHandle, item: c_int, authtok: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
}

/// Called by libpam for each `auth` line naming this module.
///
/// # Safety
///
/// libpam's contract: `pamh` is a live handle, and `argv` holds `argc` NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(pamh: *mut PamHandle, _flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    let pam = Pam(pamh);
    // A panic must never unwind into libpam, or into the lock screen around it.
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: libpam passes `argc` valid C strings in `argv`.
        let words = unsafe { arguments(argc, argv) };
        let args = match Args::parse(words.iter().map(String::as_str)) {
            Ok(args) => args,
            Err(error) => {
                let line = format!("PIN refused: bad PAM line: {error}");
                // Honour log= even on a bad line, so tests never write to the journal.
                match words.iter().find_map(|word| word.strip_prefix("log=")) {
                    Some(file) => FileLog(file.into()).log(&line),
                    None => pam.log(&line),
                }
                // Asked for all the same, as `run` does first: a line after this one may only read
                // what was typed, as the `pam_unix.so use_first_pass` of versions before 2026-10-18
                // does, and finding nothing it would refuse the password too. So a line this
                // module can't read, such as an older version's after an upgrade, refuses the PIN
                // alone.
                drop(pam.typed());
                return PAM_IGNORE;
            }
        };
        let file_log = args.log.clone().map(FileLog);
        let log: &dyn Log = match &file_log {
            Some(file) => file,
            None => &pam,
        };
        // With pin_unpause_by = setcred, the housekeeping is pam_sm_setcred's alone, and what was
        // typed is never read here.
        if args.mode == Mode::Housekeeping && !unpause_by(&args, log).by_password_check() {
            return PAM_IGNORE;
        }
        if run_and_log(&pam, &args, log, run) { PAM_SUCCESS } else { PAM_IGNORE }
    }))
    .unwrap_or(PAM_IGNORE)
}

/// properpin sets no credentials, but a call here on the `housekeeping` line is the sign that the
/// lock screen was unlocked through the stock password stack. libpam calls `pam_sm_setcred` only
/// when the program calls `pam_setcred`, which kscreenlocker does only after a successful
/// `pam_authenticate`, and it replays the path `pam_authenticate` took (docs/current-setcred.md).
/// Any flag counts; it is logged. With `pin_unpause_by` at setcred or both the pinchecker then
/// does the housekeeping; at password-check this only logs. The `housekeeping` line answers
/// `PAM_IGNORE`, which kscreenlocker ignores anyway.
///
/// The `check` line answers `PAM_SUCCESS`, and must: that is what ends the replay there after a
/// PIN unlock. libpam's `done` action, which `sufficient` takes on success, ends the replay only
/// if the module's new answer is not `PAM_IGNORE`; with `PAM_IGNORE` it goes on down the lines
/// and would reach the `housekeeping` line after a PIN unlock too. After a password unlock the
/// `check` line's remembered answer was `PAM_IGNORE`, whose action is to go on, whatever is
/// answered here. crates/pam/tests/stack.rs shows both.
///
/// # Safety
///
/// libpam's contract: `pamh` is a live handle, and `argv` holds `argc` NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(pamh: *mut PamHandle, flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    let pam = Pam(pamh);
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: libpam passes `argc` valid C strings in `argv`.
        let words = unsafe { arguments(argc, argv) };
        // A bad line was logged by pam_sm_authenticate already.
        let Ok(args) = Args::parse(words.iter().map(String::as_str)) else { return PAM_IGNORE };
        if args.mode == Mode::Check {
            return PAM_SUCCESS;
        }
        let file_log = args.log.clone().map(FileLog);
        let log: &dyn Log = match &file_log {
            Some(file) => file,
            None => &pam,
        };
        let by = unpause_by(&args, log);
        log.log(&format!("pam_setcred({}) after a password unlock; pin_unpause_by is {by}", setcred_flag(flags)));
        if by.by_setcred() {
            run_and_log(&pam, &args, log, run_unlocked);
        }
        PAM_IGNORE
    }))
    .unwrap_or(PAM_IGNORE)
}

/// The flag kscreenlocker and other programs pass to `pam_setcred`, by name.
fn setcred_flag(flags: c_int) -> String {
    match flags & !PAM_SILENT {
        0x2 => "PAM_ESTABLISH_CRED".into(),
        0x4 => "PAM_DELETE_CRED".into(),
        0x8 => "PAM_REINITIALIZE_CRED".into(),
        0x10 => "PAM_REFRESH_CRED".into(),
        other => format!("{other:#x}"),
    }
}

/// The pinchecker logs every answer itself; the module logs only what went wrong on its side.
fn run_and_log(pam: &Pam, args: &Args, log: &dyn Log, run: fn(&Pam, &Args) -> Result<bool, Error>) -> bool {
    run(pam, args).unwrap_or_else(|error| {
        let what = match args.mode {
            Mode::Check => "PIN refused",
            Mode::Housekeeping => "housekeeping failed",
        };
        log.log(&format!("{what}: {error}"));
        false
    })
}

/// # Safety
///
/// `argv` holds `argc` NUL-terminated strings.
unsafe fn arguments(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    (0..usize::try_from(argc).unwrap_or(0))
        // SAFETY: within the `argc` entries libpam passed.
        .map(|i| unsafe { CStr::from_ptr(*argv.add(i)) }.to_string_lossy().into_owned())
        .collect()
}

/// SIGCHLD set to its default action for as long as this lives, and then put back as it was. Like
/// pam_unix around `unix_chkpwd`: a host that ignores SIGCHLD would have the pinchecker's exit status
/// discarded by the kernel, and the module couldn't read the answer.
///
/// The setting is process-wide. Two threads saving and restoring it at once can lose the host's
/// setting for good (the second saves the first's default, and restores it last), so properpin's
/// own attempts on different threads take turns here. Another module doing the same on another
/// thread at the same moment could still race with this, as it could with pam_unix; none in
/// Fedora's fingerprint or smartcard stacks does (docs/chaos/harness-closer-to-kscreenlocker.md).
pub(crate) struct DefaultSigchld {
    old: libc::sigaction,
    // Released after `drop` has put the old setting back.
    _turn: MutexGuard<'static, ()>,
}

/// Held while SIGCHLD is changed. A panic while holding it poisons it, which changes nothing here.
static TURN: Mutex<()> = Mutex::new(());

impl DefaultSigchld {
    pub(crate) fn set() -> Self {
        let turn = TURN.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: sigaction with a zeroed, default-action struct and a valid place for the old one.
        unsafe {
            let mut default: libc::sigaction = std::mem::zeroed();
            default.sa_sigaction = libc::SIG_DFL;
            libc::sigemptyset(&mut default.sa_mask);
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGCHLD, &default, &mut old);
            Self { old, _turn: turn }
        }
    }
}

impl Drop for DefaultSigchld {
    fn drop(&mut self) {
        // SAFETY: puts back exactly what `set` found.
        unsafe { libc::sigaction(libc::SIGCHLD, &self.old, std::ptr::null_mut()) };
    }
}

/// One PAM transaction, as the module sees it. Only built inside the entry points above.
struct Pam(*mut PamHandle);

impl Transaction for Pam {
    fn user(&self) -> Result<String, Error> {
        let mut user = std::ptr::null();
        // SAFETY: `self.0` is the live handle; libpam points `user` at a string it owns.
        let status = unsafe { pam_get_user(self.0, &mut user, std::ptr::null()) };
        if status != PAM_SUCCESS || user.is_null() {
            return Err(Error::System(format!("pam_get_user failed with {status}")));
        }
        // SAFETY: a non-null result is a NUL-terminated string owned by libpam.
        Ok(unsafe { CStr::from_ptr(user) }.to_string_lossy().into_owned())
    }

    fn typed(&self) -> Result<Secret, Error> {
        let mut typed = std::ptr::null();
        // SAFETY: as above; a null prompt means libpam's default prompt.
        let status = unsafe { pam_get_authtok(self.0, PAM_AUTHTOK, &mut typed, std::ptr::null()) };
        if status != PAM_SUCCESS || typed.is_null() {
            return Err(Error::System(format!("pam_get_authtok failed with {status}")));
        }
        // SAFETY: a non-null result is a NUL-terminated string owned by libpam. It is copied once,
        // into a Vec of exactly its length that `Secret` then owns and wipes.
        Ok(Secret::new(unsafe { CStr::from_ptr(typed) }.to_bytes().to_vec()))
    }
}

/// Logs through `pam_syslog`: authpriv facility, tagged with the service and module.
impl Log for Pam {
    fn log(&self, line: &str) {
        let Ok(line) = CString::new(line) else { return };
        // SAFETY: a live handle, and a "%s" format with exactly one NUL-terminated argument.
        unsafe { pam_syslog(self.0, LOG_NOTICE, c"%s".as_ptr(), line.as_ptr()) };
    }
}
