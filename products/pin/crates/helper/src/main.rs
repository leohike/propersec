//! `properpin-helper`, the setuid program. See the library (`lib.rs`) for what it answers.
//!
//! ```text
//! properpin-helper check|arm|status
//! ```
//!
//! Installed setuid to the `properpin` account, with fixed locations: the hashes in `/etc/properpin`
//! (owned by root), the counts in `/run/properpin` (owned by the account it runs as), the password
//! checked by `/usr/sbin/unix_chkpwd`, and logs to syslog.
//!
//! For local tests, and only when started without elevated rights, these options replace them:
//!
//! ```text
//! --dev-etc DIR       instead of /etc/properpin                   required with any --dev option
//! --dev-run DIR       instead of /run/properpin                   required with any --dev option
//! --dev-owner UID     who must own the files under --dev-etc      default: the caller
//! --dev-chkpwd PATH   instead of /usr/sbin/unix_chkpwd
//! --dev-log FILE      append log lines here instead of syslog
//! ```
//!
//! Started with elevated rights (setuid, as installed), any `--dev` option is refused outright. Without
//! elevated rights the helper can do nothing its caller couldn't do directly, so letting the caller
//! choose the locations gives nothing away.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use properpin_core::{Log, Secret, exit};
use properpin_helper::{Context, Places, Request, UnixChkpwd, read_input, serve};
use properpin_sys::{Account, BootClock, FileLog, Yescrypt, current_euid, current_uid};

mod secure;

fn main() -> ExitCode {
    // A panic aborts at once: no unwinding through half-done work, and no backtrace, whose printing
    // would read RUST_BACKTRACE from the caller's environment. The attempt was already counted.
    std::panic::set_hook(Box::new(|_| std::process::abort()));
    secure::start_clean();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    ExitCode::from(run(&args))
}

fn run(args: &[OsString]) -> u8 {
    let options = match Options::parse(args) {
        Ok(options) => options,
        Err(why) => {
            secure::Syslog::open().log(&format!("refused: {why}"));
            return exit::USAGE;
        }
    };
    let log: Box<dyn Log> = match &options.dev {
        Some(Dev { log: Some(file), .. }) => Box::new(FileLog(file.clone())),
        _ => Box::new(secure::Syslog::open()),
    };
    let uid = current_uid();
    if options.dev.is_some() && secure::elevated() {
        log.log(&format!("uid {uid}: refused: --dev options while running with elevated rights"));
        return exit::USAGE;
    }
    if uid == 0 {
        log.log("refused: root has no lock screen to unlock");
        return exit::USAGE;
    }
    let caller = match Account::by_uid(uid) {
        Ok(caller) => caller,
        Err(error) => {
            log.log(&format!("uid {uid}: refused: {error}"));
            return exit::BROKEN;
        }
    };
    let typed = if options.request.reads_input() {
        // Like unix_chkpwd: meant to be fed by a program through a pipe, not typed into by hand.
        // This discourages casual use; it protects nothing, since anyone can use a pipe.
        if std::io::stdin().is_terminal() {
            log.log(&format!("{}: refused: stdin is a terminal", caller.name));
            return exit::USAGE;
        }
        match read_input(&mut std::io::stdin().lock()) {
            Ok(typed) => typed,
            Err(error) => {
                log.log(&format!("{}: refused: reading stdin: {error}", caller.name));
                return exit::BROKEN;
            }
        }
    } else {
        Secret::new(Vec::new())
    };
    let (places, password) = match &options.dev {
        None => (
            Places { etc: "/etc/properpin".into(), etc_owner: 0, run_dir: "/run/properpin".into(), run_owner: current_euid() },
            UnixChkpwd::system(),
        ),
        Some(dev) => (
            Places { etc: dev.etc.clone(), etc_owner: dev.owner.unwrap_or(uid), run_dir: dev.run.clone(), run_owner: current_euid() },
            dev.chkpwd.clone().map_or_else(UnixChkpwd::system, UnixChkpwd),
        ),
    };
    let context = Context { places: &places, hasher: &Yescrypt, clock: &BootClock, password: &password, log: log.as_ref() };
    let reply = serve(options.request, &caller, &typed, &context);
    drop(typed);
    // Nothing to do if stdout is gone: the exit code is the answer.
    let _ = std::io::stdout().write_all(reply.output.as_bytes());
    reply.code
}

struct Options {
    request: Request,
    dev: Option<Dev>,
}

struct Dev {
    etc: PathBuf,
    run: PathBuf,
    owner: Option<u32>,
    chkpwd: Option<PathBuf>,
    log: Option<PathBuf>,
}

impl Options {
    /// Exactly one request, and `--dev-*` options given as `--dev-x VALUE`. Anything else is refused.
    fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut request = None;
        let (mut etc, mut run, mut owner, mut chkpwd, mut log, mut any_dev) = (None, None, None, None, None, false);
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let word = arg.to_str().ok_or("an argument is not UTF-8")?;
            if let Some(name) = word.strip_prefix("--dev-") {
                any_dev = true;
                let value = PathBuf::from(args.next().ok_or(format!("{word} needs a value"))?);
                match name {
                    "etc" => etc = Some(value),
                    "run" => run = Some(value),
                    "owner" => owner = Some(value.to_str().and_then(|uid| uid.parse().ok()).ok_or(format!("{word} needs a uid"))?),
                    "chkpwd" => chkpwd = Some(value),
                    "log" => log = Some(value),
                    _ => return Err(format!("unknown option {word}")),
                }
            } else if request.is_none() {
                request = Some(Request::parse(word).ok_or(format!("unknown request {word:?}"))?);
            } else {
                return Err(format!("unexpected argument {word:?}"));
            }
        }
        let request = request.ok_or("no request: expected check, arm or status")?;
        let dev = match (any_dev, etc, run) {
            (false, ..) => None,
            (true, Some(etc), Some(run)) => Some(Dev { etc, run, owner, chkpwd, log }),
            (true, ..) => return Err("--dev options need both --dev-etc and --dev-run".into()),
        };
        Ok(Self { request, dev })
    }
}
