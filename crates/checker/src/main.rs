//! `screenlock-pin-checker`, the setgid program. See the library (`lib.rs`) for what it answers.
//!
//! ```text
//! screenlock-pin-checker check|unpause|status
//! ```
//!
//! Installed `root:screenlock-pin 2755`, setgid to the `screenlock-pin` group, with fixed locations: the
//! hashes in `/etc/screenlock-pin` (owned by root, readable by the group), the counts in
//! `/var/lib/screenlock-pin` (root's, sticky, writable by the group), and logs to syslog.
//!
//! For local tests, and only when started without elevated rights, these options replace them:
//!
//! ```text
//! --dev-etc DIR       instead of /etc/screenlock-pin                   required with any --dev option
//! --dev-budget DIR    instead of /var/lib/screenlock-pin               required with any --dev option
//! --dev-owner UID     who must own --dev-budget and the files under --dev-etc   default: the caller
//! --dev-log FILE      append log lines here instead of syslog
//! ```
//!
//! Started with elevated rights (setgid, as installed), any `--dev` option is refused outright; see
//! `dev_options_allowed` for the two checks. Without elevated rights the PIN checker can do nothing its
//! caller couldn't do directly, so letting the caller choose the locations gives nothing away.

// Stricter checks for shipped code (docs/chaos/plan-tools.md): every unsafe block explains why it is
// sound, nothing indexes or slices without a bounds check, and no cast silently drops bits.
#![warn(clippy::undocumented_unsafe_blocks, clippy::indexing_slicing, clippy::cast_possible_truncation)]
use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use screenlock_pin_checker::{Context, Places, Request, dev_options_allowed, read_input, serve};
use screenlock_pin_core::{Log, Secret, exit};
use screenlock_pin_sys::{Account, FileLog, SystemClock, Yescrypt, current_egid, current_euid, current_gid, current_uid};

mod secure;

fn main() -> ExitCode {
    // What a correct PIN's answer waits from (`Reply::not_before`).
    let started = Instant::now();
    // A panic aborts at once: no unwinding through half-done work, and no backtrace, whose printing
    // would read RUST_BACKTRACE from the caller's environment. The attempt was already counted.
    std::panic::set_hook(Box::new(|_| std::process::abort()));
    secure::start_clean();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    ExitCode::from(run(&args, started))
}

fn run(args: &[OsString], started: Instant) -> u8 {
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
    // status is asked by a person, who is told why; the other requests answer with the exit code.
    let refuse = |why: &str, code: u8| {
        log.log(why);
        if options.request == Request::Status {
            let _ = writeln!(std::io::stdout(), "{why}");
        }
        code
    };
    let uid = current_uid();
    if options.dev.is_some() && !dev_options_allowed(secure::elevated(), uid, current_euid(), current_gid(), current_egid()) {
        return refuse(&format!("uid {uid}: refused: --dev options while running with elevated rights"), exit::USAGE);
    }
    if uid == 0 {
        return refuse("refused: root has no lock screen to unlock", exit::USAGE);
    }
    let caller = match Account::by_uid(uid) {
        Ok(caller) => caller,
        Err(error) => return refuse(&format!("uid {uid}: refused: {error}"), exit::BROKEN),
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
    let places = match &options.dev {
        None => Places {
            etc: "/etc/screenlock-pin".into(),
            etc_owner: 0,
            budget_dir: "/var/lib/screenlock-pin".into(),
            budget_owner: 0,
            budget_group: current_egid(),
        },
        Some(dev) => Places {
            etc: dev.etc.clone(),
            etc_owner: dev.owner.unwrap_or(uid),
            budget_dir: dev.budget.clone(),
            budget_owner: dev.owner.unwrap_or(uid),
            budget_group: current_egid(),
        },
    };
    let context = Context { places: &places, hasher: &Yescrypt, clock: &SystemClock, log: log.as_ref() };
    let reply = serve(options.request, &caller, &typed, &context);
    drop(typed);
    // The budget is saved and its lock released by now, so the wait holds up no other attempt.
    std::thread::sleep(reply.not_before.saturating_sub(started.elapsed()));
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
    budget: PathBuf,
    owner: Option<u32>,
    log: Option<PathBuf>,
}

impl Options {
    /// Exactly one request, and `--dev-*` options given as `--dev-x VALUE`. Anything else is refused.
    fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut request = None;
        let (mut etc, mut budget, mut owner, mut log, mut any_dev) = (None, None, None, None, false);
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let word = arg.to_str().ok_or("an argument is not UTF-8")?;
            if let Some(name) = word.strip_prefix("--dev-") {
                any_dev = true;
                let value = PathBuf::from(args.next().ok_or(format!("{word} needs a value"))?);
                match name {
                    "etc" => etc = Some(value),
                    "budget" => budget = Some(value),
                    "owner" => owner = Some(value.to_str().and_then(|uid| uid.parse().ok()).ok_or(format!("{word} needs a uid"))?),
                    "log" => log = Some(value),
                    _ => return Err(format!("unknown option {word}")),
                }
            } else if request.is_none() {
                request = Some(Request::parse(word).ok_or(format!("unknown request {word:?}"))?);
            } else {
                return Err(format!("unexpected argument {word:?}"));
            }
        }
        let request = request.ok_or("no request: expected check, unpause or status")?;
        let dev = match (any_dev, etc, budget) {
            (false, ..) => None,
            (true, Some(etc), Some(budget)) => Some(Dev { etc, budget, owner, log }),
            (true, ..) => return Err("--dev options need --dev-etc and --dev-budget".into()),
        };
        Ok(Self { request, dev })
    }
}
