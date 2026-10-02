//! The module's work, in safe code: hand what was typed to the setuid helper and read its answer.
//! `pam.rs` turns the result into a PAM return code.

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use properpin_core::{Error, Secret, exit};
use properpin_sys::{Account, current_euid, current_uid};

use crate::Args;
use crate::pam::DefaultSigchld;

/// Far longer than the helper ever takes (a hash, or `unix_chkpwd`, and a lock it waits at most a
/// second for). After this it is killed and the PIN refused, so the lock screen never hangs on it.
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

/// What the module needs from the PAM transaction.
pub trait Transaction {
    /// The user PAM is authenticating.
    fn user(&self) -> Result<String, Error>;
    /// What the user typed, asking for it if no module has yet. Stored by libpam as `PAM_AUTHTOK`,
    /// so pam_unix reuses it with `use_first_pass` instead of asking again. This is a copy of its
    /// own, wiped when dropped; libpam's stays for the rest of the stack and libpam wipes it itself
    /// (docs/pin-pam-copy.md).
    fn typed(&self) -> Result<Secret, Error>;
}

/// `Ok(true)` unlocks (for `check`) or armed the PIN (for `arm`). Everything else refuses.
pub fn run(transaction: &impl Transaction, args: &Args) -> Result<bool, Error> {
    if args.test_panic {
        panic!("test_panic: a panic must become PAM_IGNORE");
    }
    calling_account(transaction)?;
    let typed = transaction.typed()?;
    let code = ask_helper(&args.helper, args.mode.request(), &typed)?;
    drop(typed);
    match code {
        exit::YES => Ok(true),
        exit::NO => Ok(false),
        other => Err(Error::System(format!("{} answered {other}; its log says why", args.helper.display()))),
    }
}

/// The user being unlocked, who must be both the user this process runs as and the user PAM is
/// authenticating. The lock screen runs as the locked user; anything else isn't the lock screen.
/// The helper only ever answers about the user it runs for, so this check is about refusing early
/// and clearly, not about protecting the PIN.
fn calling_account(transaction: &impl Transaction) -> Result<Account, Error> {
    if current_uid() == 0 || current_euid() == 0 {
        return Err(Error::System("running as root; properpin belongs in the lock screen's stack only".into()));
    }
    let account = Account::by_uid(current_uid())?;
    let pam_user = transaction.user()?;
    if pam_user != account.name {
        return Err(Error::System(format!("PAM is authenticating {pam_user:?}, but this runs as {:?}", account.name)));
    }
    Ok(account)
}

/// Start the helper with `request`, write `typed` to its stdin, and return its exit code. The way
/// pam_unix runs `unix_chkpwd`: an empty environment, `/` as the working directory, the default
/// SIGCHLD action while the helper runs (so a host that ignores or reaps children can't take its
/// exit status away), and the read end of the pipe kept open here until the write is done.
fn ask_helper(helper: &Path, request: &str, typed: &Secret) -> Result<u8, Error> {
    let fail = |what: &str, error: std::io::Error| Error::System(format!("{}: {what}: {error}", helper.display()));
    // std's pipes are close-on-exec: they reach the helper as its stdin and nothing else.
    let (reader, mut writer) = std::io::pipe().map_err(|error| fail("pipe", error))?;
    let child_end = reader.try_clone().map_err(|error| fail("pipe", error))?;
    let _sigchld = DefaultSigchld::set();
    let mut child = Command::new(helper)
        .arg(request)
        .env_clear()
        .current_dir("/")
        .stdin(child_end)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| fail("start", error))?;
    // Never more than the pipe holds, so this doesn't block. With `reader` still open here, a helper
    // that quits without reading can't make it raise SIGPIPE, which could kill the lock screen.
    let written = writer.write_all(typed.as_bytes());
    drop(writer);
    drop(reader);
    let status = wait(&mut child).map_err(|error| fail("wait", error))?;
    written.map_err(|error| fail("write", error))?;
    match status.code() {
        Some(code) => u8::try_from(code).map_err(|_| Error::System(format!("{}: exit code {code}", helper.display()))),
        None => Err(Error::System(format!("{}: killed by {status}", helper.display()))),
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
