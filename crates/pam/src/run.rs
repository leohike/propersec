//! The module's work, in safe code: hand what was typed to the setgid PIN checker and read its answer.
//! `pam.rs` turns the result into a PAM return code.

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use screenlock_pin_core::{Answer, Error, Request, Secret};
use screenlock_pin_sys::{Account, current_euid, current_uid};

use crate::pam::DefaultSigchld;
use crate::{Args, Mode};

/// Far longer than the PIN checker ever takes (a hash, a lock it waits at most a
/// second for, and the wait before a correct PIN's answer, at most a second). After this it is
/// killed and the PIN refused, so the lock screen never hangs on it.
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

/// What the module needs from the PAM transaction.
pub trait Transaction {
    /// The user PAM is authenticating.
    fn user(&self) -> Result<String, Error>;
    /// What the user typed, asking for it if no module has yet. Stored by libpam as `PAM_AUTHTOK`,
    /// so pam_unix in the stock stack below reuses it instead of asking again. This is a copy of
    /// its own, wiped when dropped; libpam's stays for the rest of the stack, unless it was the
    /// PIN, and libpam wipes it itself (docs/chaos/pin-pam-copy.md).
    fn typed(&self) -> Result<Secret, Error>;
}

/// `check`: `Ok(true)` unlocks. Everything else refuses.
pub fn run(transaction: &impl Transaction, args: &Args) -> Result<bool, Error> {
    debug_assert_eq!(args.mode, Mode::Check);
    // Asked for before anything can refuse, so the lines after this one find it whatever happens
    // here (see the bad PAM line in `pam_sm_authenticate`).
    let typed = transaction.typed()?;
    calling_account(transaction)?;
    let code = ask_pin_checker(&args.pin_checker, args.mode.request(), &typed, args.test_panic)?;
    drop(typed);
    answer(args, code)
}

/// After a password unlock (`pam_sm_setcred` on the `after-password-auth` line): ask the PIN checker to
/// unpause the PIN, sending it nothing. `Ok(true)` when it did.
pub fn run_unpause(transaction: &impl Transaction, args: &Args) -> Result<bool, Error> {
    debug_assert_eq!(args.mode, Mode::AfterPasswordAuth);
    calling_account(transaction)?;
    let code = ask_pin_checker(&args.pin_checker, args.mode.request(), &Secret::new(Vec::new()), args.test_panic)?;
    answer(args, code)
}

fn answer(args: &Args, code: u8) -> Result<bool, Error> {
    match Answer::try_from(code) {
        Ok(Answer::Yes) => Ok(true),
        Ok(Answer::No) => Ok(false),
        _ => Err(Error::System(format!("{} answered {code}; its log says why", args.pin_checker.display()))),
    }
}

/// The user being unlocked, who must be both the user this process runs as and the user PAM is
/// authenticating. The lock screen runs as the locked user; anything else isn't the lock screen.
/// The PIN checker only ever answers about the user it runs for, so this check is about refusing early
/// and clearly, not about protecting the PIN.
fn calling_account(transaction: &impl Transaction) -> Result<Account, Error> {
    if current_uid() == 0 || current_euid() == 0 {
        return Err(Error::System("running as root; screenlock-pin belongs in the lock screen's stack only".into()));
    }
    let account = Account::by_uid(current_uid())?;
    let pam_user = transaction.user()?;
    if pam_user != account.name {
        return Err(Error::System(format!("PAM is authenticating {pam_user:?}, but this runs as {:?}", account.name)));
    }
    Ok(account)
}

/// Start the PIN checker with `request`, write `typed` to its stdin, and return its exit code. The way
/// pam_unix runs `unix_chkpwd`: an empty environment, `/` as the working directory, the default
/// SIGCHLD action while the PIN checker runs (so a host that ignores or reaps children can't take its
/// exit status away), and the read end of the pipe kept open here until the write is done.
/// `test_panic` panics while SIGCHLD is changed, to prove the panic puts it back.
fn ask_pin_checker(pin_checker: &Path, request: Request, typed: &Secret, test_panic: bool) -> Result<u8, Error> {
    let fail = |what: &str, error: std::io::Error| Error::System(format!("{}: {what}: {error}", pin_checker.display()));
    // std's pipes are close-on-exec: they reach the PIN checker as its stdin and nothing else.
    let (reader, mut writer) = std::io::pipe().map_err(|error| fail("pipe", error))?;
    let child_end = reader.try_clone().map_err(|error| fail("pipe", error))?;
    let _sigchld = DefaultSigchld::set();
    if test_panic {
        panic!("test_panic: a panic must become PAM_IGNORE and put SIGCHLD back");
    }
    let mut child = Command::new(pin_checker)
        .arg(request.as_str())
        .env_clear()
        .current_dir("/")
        .stdin(child_end)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| fail("start", error))?;
    // Never more than the pipe holds, so this doesn't block. With `reader` still open here, a PIN checker
    // that quits without reading can't make it raise SIGPIPE, which could kill the lock screen.
    let written = writer.write_all(typed.as_bytes());
    drop(writer);
    drop(reader);
    let status = wait(&mut child).map_err(|error| fail("wait", error))?;
    written.map_err(|error| fail("write", error))?;
    match status.code() {
        Some(code) => u8::try_from(code).map_err(|_| Error::System(format!("{}: exit code {code}", pin_checker.display()))),
        None => Err(Error::System(format!("{}: killed by {status}", pin_checker.display()))),
    }
}

/// Wait for `child`, killing it after [`HELPER_TIMEOUT`].
fn wait(child: &mut Child) -> std::io::Result<ExitStatus> {
    let deadline = Instant::now() + HELPER_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            child.wait()?;
            return Err(std::io::Error::other(format!("no answer within {HELPER_TIMEOUT:?}, killed")));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
