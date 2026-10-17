//! A minimal PAM client, so tests can run `pam_authenticate` for real, the way the lock screen does.
//!
//! `PamClient::new` uses `pam_start_confdir` (Linux-PAM 1.4+), which reads the service's files from
//! a directory of our choosing instead of `/etc/pam.d`. The real libpam and the real modules then
//! run the exact control lines under test, and nothing on the system is read for configuration or
//! changed. `PamClient::system` uses plain `pam_start`, as the lock screen does, for tests inside a
//! container whose `/etc/pam.d` is the one under test.
//!
//! Like kscreenlocker (docs/harness-closer-to-kscreenlocker.md), a `PamSession` keeps one PAM handle
//! for many attempts, calls `pam_setcred(PAM_REFRESH_CRED)` after each success and ignores what it
//! returns, and sets a `PAM_FAIL_DELAY` callback. The callback records the delay the stack asked for
//! instead of sleeping: what protects the PIN is its failure limit, not the delay.
//!
//! `host` changes the process-wide SIGCHLD setting the ways real PAM hosts do.
//!
//! Test-only: no shipped crate depends on this one.

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

pub const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_FAIL_DELAY: c_int = 10;
const PAM_REFRESH_CRED: c_int = 0x0010;

/// What one attempt came to, and everything PAM said along the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub status: c_int,
    /// What PAM asked for.
    pub prompts: Vec<String>,
    /// What PAM said without asking.
    pub messages: Vec<String>,
    /// The failure delays the stack asked for, in microseconds, which the lock screen would sleep.
    pub delays: Vec<u32>,
    /// What `pam_setcred(PAM_REFRESH_CRED)` returned after a success; kscreenlocker ignores it.
    pub setcred: Option<c_int>,
}

impl Attempt {
    pub fn unlocked(&self) -> bool {
        self.status == PAM_SUCCESS
    }
}

/// Authenticates one user for one service, reading the service's files from `confdir`, or from
/// the system's PAM directories when there is none.
#[derive(Debug, Clone)]
pub struct PamClient {
    confdir: Option<PathBuf>,
    service: String,
    user: String,
}

impl PamClient {
    pub fn new(confdir: impl AsRef<Path>, service: &str, user: &str) -> Self {
        Self { confdir: Some(confdir.as_ref().into()), service: service.into(), user: user.into() }
    }

    /// The system's own PAM configuration, exactly as any PAM application gets it.
    pub fn system(service: &str, user: &str) -> Self {
        Self { confdir: None, service: service.into(), user: user.into() }
    }

    /// One unlock attempt in a session of its own: `typed` answers every prompt, the way a
    /// greeter's one field does.
    pub fn authenticate(&self, typed: &str) -> Attempt {
        self.session().authenticate(typed)
    }

    /// A PAM session for any number of attempts, ended when dropped.
    pub fn session(&self) -> PamSession {
        let conversation = Box::new(Conversation::default());
        let handle = ffi::start(self.confdir.as_deref(), &self.service, &self.user, &conversation);
        PamSession { handle, conversation, last: PAM_SUCCESS }
    }
}

/// One PAM handle, as the lock screen keeps one per authenticator: `pam_start` once, then
/// `pam_authenticate` for every attempt, and `pam_end` when dropped. Stays on the thread that
/// opened it, as a raw handle can't be sent between threads.
pub struct PamSession {
    handle: *mut c_void,
    // Boxed so the address libpam was given stays the same however the session moves.
    conversation: Box<Conversation>,
    last: c_int,
}

impl PamSession {
    pub fn authenticate(&mut self, typed: &str) -> Attempt {
        self.conversation.start(typed);
        let (status, setcred) = ffi::authenticate(self.handle);
        self.last = status;
        let (prompts, messages, delays) = self.conversation.finish();
        Attempt { status, prompts, messages, delays, setcred }
    }
}

impl Drop for PamSession {
    fn drop(&mut self) {
        ffi::end(self.handle, self.last);
    }
}

#[derive(Default)]
struct Conversation {
    typed: RefCell<CString>,
    prompts: RefCell<Vec<String>>,
    messages: RefCell<Vec<String>>,
    delays: RefCell<Vec<u32>>,
}

impl Conversation {
    fn start(&self, typed: &str) {
        *self.typed.borrow_mut() = CString::new(typed).expect("typed input has no NUL");
        self.finish();
    }

    fn finish(&self) -> (Vec<String>, Vec<String>, Vec<u32>) {
        (self.prompts.take(), self.messages.take(), self.delays.take())
    }
}

#[allow(unsafe_code)]
mod ffi {
    use super::*;

    #[repr(C)]
    struct PamMessage {
        msg_style: c_int,
        msg: *const c_char,
    }

    #[repr(C)]
    struct PamResponse {
        resp: *mut c_char,
        resp_retcode: c_int,
    }

    type ConvFn = unsafe extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int;
    type DelayFn = unsafe extern "C" fn(c_int, c_uint, *mut c_void);

    #[repr(C)]
    struct PamConv {
        conv: ConvFn,
        appdata_ptr: *mut c_void,
    }

    unsafe extern "C" {
        fn pam_start_confdir(
            service: *const c_char,
            user: *const c_char,
            conv: *const PamConv,
            confdir: *const c_char,
            pamh: *mut *mut c_void,
        ) -> c_int;
        fn pam_start(service: *const c_char, user: *const c_char, conv: *const PamConv, pamh: *mut *mut c_void) -> c_int;
        fn pam_set_item(pamh: *mut c_void, item_type: c_int, item: *const c_void) -> c_int;
        fn pam_authenticate(pamh: *mut c_void, flags: c_int) -> c_int;
        fn pam_setcred(pamh: *mut c_void, flags: c_int) -> c_int;
        fn pam_end(pamh: *mut c_void, status: c_int) -> c_int;
    }

    /// `pam_start` with the conversation and the delay callback. libpam copies `PamConv`, so only
    /// the conversation it points to has to outlive the handle, which `PamSession` sees to.
    pub(super) fn start(confdir: Option<&Path>, service: &str, user: &str, conversation: &Conversation) -> *mut c_void {
        let c = |text: &str| CString::new(text).expect("no NUL in test strings");
        let (service, user) = (c(service), c(user));
        let confdir = confdir.map(|dir| c(dir.to_str().expect("UTF-8 path")));
        let conv = PamConv { conv: converse, appdata_ptr: std::ptr::from_ref(conversation).cast_mut().cast() };
        let mut handle = std::ptr::null_mut();
        // SAFETY: all strings are NUL-terminated and outlive the calls; libpam copies `conv`.
        unsafe {
            let started = match &confdir {
                Some(confdir) => pam_start_confdir(service.as_ptr(), user.as_ptr(), &conv, confdir.as_ptr(), &mut handle),
                None => pam_start(service.as_ptr(), user.as_ptr(), &conv, &mut handle),
            };
            assert_eq!(started, PAM_SUCCESS, "pam_start failed");
            let delay: DelayFn = record_delay;
            assert_eq!(pam_set_item(handle, PAM_FAIL_DELAY, delay as *const c_void), PAM_SUCCESS, "pam_set_item failed");
        }
        handle
    }

    /// One `pam_authenticate`, and `pam_setcred(PAM_REFRESH_CRED)` after a success.
    pub(super) fn authenticate(handle: *mut c_void) -> (c_int, Option<c_int>) {
        // SAFETY: `handle` came from `start` and `PamSession` hasn't ended it.
        unsafe {
            let status = pam_authenticate(handle, 0);
            let setcred = (status == PAM_SUCCESS).then(|| pam_setcred(handle, PAM_REFRESH_CRED));
            (status, setcred)
        }
    }

    pub(super) fn end(handle: *mut c_void, status: c_int) {
        // SAFETY: as above, and nothing uses `handle` after this.
        unsafe { pam_end(handle, status) };
    }

    /// Answers every prompt with the typed text, and records what PAM asked and said. libpam frees
    /// the responses itself, so they come from C's allocator.
    unsafe extern "C" fn converse(
        count: c_int,
        messages: *mut *const PamMessage,
        out: *mut *mut PamResponse,
        appdata: *mut c_void,
    ) -> c_int {
        let answer = || -> c_int {
            let count = usize::try_from(count).unwrap_or(0);
            // SAFETY: libpam passes `count` message pointers, `out` to write the response array to,
            // and back the appdata pointer set above, which points to a live Conversation.
            unsafe {
                let conversation = &*appdata.cast::<Conversation>();
                let responses = libc::calloc(count, size_of::<PamResponse>()).cast::<PamResponse>();
                if responses.is_null() {
                    return PAM_BUF_ERR;
                }
                for i in 0..count {
                    let message = &**messages.add(i);
                    let text =
                        if message.msg.is_null() { String::new() } else { CStr::from_ptr(message.msg).to_string_lossy().into_owned() };
                    if matches!(message.msg_style, PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON) {
                        conversation.prompts.borrow_mut().push(text);
                        (*responses.add(i)).resp = libc::strdup(conversation.typed.borrow().as_ptr());
                    } else {
                        conversation.messages.borrow_mut().push(text);
                    }
                }
                *out = responses;
            }
            PAM_SUCCESS
        };
        // A panic must not unwind into libpam.
        catch_unwind(AssertUnwindSafe(answer)).unwrap_or(PAM_CONV_ERR)
    }

    /// libpam calls this at the end of every `pam_authenticate`, with the conversation's appdata.
    /// kscreenlocker sleeps for the delay after a failure; this only writes it down.
    unsafe extern "C" fn record_delay(status: c_int, usec: c_uint, appdata: *mut c_void) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if status != PAM_SUCCESS && !appdata.is_null() {
                // SAFETY: the appdata pointer set in `start`, to a live Conversation.
                let conversation = unsafe { &*appdata.cast::<Conversation>() };
                conversation.delays.borrow_mut().push(usec);
            }
        }));
    }
}

/// The process-wide SIGCHLD settings real PAM hosts have, and a host thread that reaps every child.
/// Each changes the whole process, so a test using them runs in a process of its own.
#[allow(unsafe_code)]
pub mod host {
    use std::ffi::c_int;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static REAPED: AtomicUsize = AtomicUsize::new(0);
    static NOTICED: AtomicUsize = AtomicUsize::new(0);

    /// What SIGCHLD does in this process right now.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Sigchld {
        Default,
        Ignore,
        /// A handler, by address.
        Handler(usize),
    }

    pub fn sigchld() -> Sigchld {
        // SAFETY: sigaction with no new action only reads the current one.
        let current = unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut current);
            current.sa_sigaction
        };
        match current {
            libc::SIG_DFL => Sigchld::Default,
            libc::SIG_IGN => Sigchld::Ignore,
            handler => Sigchld::Handler(handler),
        }
    }

    /// The kernel then reaps every child itself and throws its exit status away.
    pub fn ignore_sigchld() {
        set(libc::SIG_IGN);
    }

    /// A handler that collects every child that has exited, as some daemons do.
    pub fn reap_on_sigchld() -> Sigchld {
        set(reap_all as extern "C" fn(c_int) as usize);
        Sigchld::Handler(reap_all as extern "C" fn(c_int) as usize)
    }

    /// A handler that only counts SIGCHLDs, leaving the reaping to whoever started the child.
    pub fn notice_sigchld() -> Sigchld {
        set(notice as extern "C" fn(c_int) as usize);
        Sigchld::Handler(notice as extern "C" fn(c_int) as usize)
    }

    /// How many children the `reap_on_sigchld` handler collected.
    pub fn reaped() -> usize {
        REAPED.load(Ordering::SeqCst)
    }

    /// How many SIGCHLDs the `notice_sigchld` handler saw.
    pub fn noticed() -> usize {
        NOTICED.load(Ordering::SeqCst)
    }

    /// Collect any one child of this process, waiting for one to exit: what a host thread looping on
    /// `waitpid(-1)` does. `None` when there is no child at all.
    pub fn reap_any_child() -> Option<i32> {
        let mut status = 0;
        // SAFETY: waitpid with a valid place for the status.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        (pid > 0).then_some(pid)
    }

    fn set(action: libc::sighandler_t) {
        // SAFETY: sigaction with a zeroed struct naming SIG_DFL, SIG_IGN or one of the handlers
        // below, all async-signal-safe; SA_RESTART so the rest of the process sees no EINTR.
        unsafe {
            let mut new: libc::sigaction = std::mem::zeroed();
            new.sa_sigaction = action;
            new.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut new.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGCHLD, &new, std::ptr::null_mut()), 0, "sigaction failed");
        }
    }

    extern "C" fn reap_all(_: c_int) {
        let mut status = 0;
        // SAFETY: waitpid and atomics are async-signal-safe.
        while unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) } > 0 {
            REAPED.fetch_add(1, Ordering::SeqCst);
        }
    }

    extern "C" fn notice(_: c_int) {
        NOTICED.fetch_add(1, Ordering::SeqCst);
    }
}
