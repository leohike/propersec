//! A minimal PAM client, so tests can run `pam_authenticate` for real.
//!
//! `pam_start_confdir` (Linux-PAM 1.4+) reads the service's files from a directory of our choosing
//! instead of `/etc/pam.d`. The real libpam and the real modules then run the exact control lines
//! under test, and nothing on the system is read for configuration or changed.
//!
//! Test-only: no shipped crate depends on this one.

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

pub const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;

/// What one attempt came to, and everything PAM said along the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub status: c_int,
    /// What PAM asked for.
    pub prompts: Vec<String>,
    /// What PAM said without asking.
    pub messages: Vec<String>,
}

impl Attempt {
    pub fn unlocked(&self) -> bool {
        self.status == PAM_SUCCESS
    }
}

/// Authenticates one user for one service, reading the service's files from `confdir`.
#[derive(Debug, Clone)]
pub struct PamClient {
    confdir: PathBuf,
    service: String,
    user: String,
}

impl PamClient {
    pub fn new(confdir: impl AsRef<Path>, service: &str, user: &str) -> Self {
        Self { confdir: confdir.as_ref().into(), service: service.into(), user: user.into() }
    }

    /// One unlock attempt: `typed` answers every prompt, the way a greeter's one field does.
    pub fn authenticate(&self, typed: &str) -> Attempt {
        let conversation = Conversation {
            typed: CString::new(typed).expect("typed input has no NUL"),
            prompts: RefCell::default(),
            messages: RefCell::default(),
        };
        let status = ffi::authenticate(&self.confdir, &self.service, &self.user, &conversation);
        Attempt { status, prompts: conversation.prompts.into_inner(), messages: conversation.messages.into_inner() }
    }
}

struct Conversation {
    typed: CString,
    prompts: RefCell<Vec<String>>,
    messages: RefCell<Vec<String>>,
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
        fn pam_authenticate(pamh: *mut c_void, flags: c_int) -> c_int;
        fn pam_end(pamh: *mut c_void, status: c_int) -> c_int;
    }

    pub(super) fn authenticate(confdir: &Path, service: &str, user: &str, conversation: &Conversation) -> c_int {
        let c = |text: &str| CString::new(text).expect("no NUL in test strings");
        let (service, user, confdir) = (c(service), c(user), c(confdir.to_str().expect("UTF-8 path")));
        let conv = PamConv { conv: converse, appdata_ptr: std::ptr::from_ref(conversation).cast_mut().cast() };
        let mut handle = std::ptr::null_mut();
        // SAFETY: all strings are NUL-terminated and outlive the transaction, as do `conv` and the
        // conversation it points to; `handle` is only used between pam_start_confdir and pam_end.
        unsafe {
            let started = pam_start_confdir(service.as_ptr(), user.as_ptr(), &conv, confdir.as_ptr(), &mut handle);
            assert_eq!(started, PAM_SUCCESS, "pam_start_confdir failed");
            let status = pam_authenticate(handle, 0);
            pam_end(handle, status);
            status
        }
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
                        (*responses.add(i)).resp = libc::strdup(conversation.typed.as_ptr());
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
}
