//! `properpin-pinchecker`: the only program that reads PIN hashes and keeps the failure counts.
//!
//! It is a setgid helper in the style of `unix_chkpwd`: installed owned by root and setgid to the
//! `properpin` group, like Debian's `unix_chkpwd` is setgid to `shadow`, so the hash files and the
//! counts can be readable by that group alone and stay out of reach of everything the user runs. The group has no members: running the pinchecker is the
//! only way to get it. The pinchecker keeps its caller's user id, so the caller can't change the pinchecker,
//! and each user's counts file is that user's own. The PAM module and the CLI start it, write what
//! was typed to its stdin, and read its exit code (`properpin_core::exit`); only `status` prints
//! anything.
//!
//! ```text
//! properpin-pinchecker check         stdin: what was typed. Exit 0 if it is the PIN and the PIN is
//!                                    enabled, no sooner than min_milliseconds_before_pin_unlock
//!                                    after the start
//! properpin-pinchecker housekeeping  stdin: what was typed at the lock screen, after the stock
//!                                    password stack, right or wrong. Checked as the password through
//!                                    unix_chkpwd; if right, the failures of the last moments are
//!                                    forgiven and the consecutive count starts over, which unpauses
//!                                    the PIN. Only when pin_unpause_by is password-check or both
//! properpin-pinchecker unlocked      stdin: nothing. The lock screen was just unlocked through the
//!                                    stock password stack (the module's pam_sm_setcred): the same
//!                                    housekeeping, with no password checked. Only when
//!                                    pin_unpause_by is setcred or both; otherwise nothing changes
//! properpin-pinchecker status        prints the caller's PIN settings, and whether the PIN is
//!                                    enabled, paused, disabled or refused, and why
//! ```
//!
//! The caller is always the real user id the kernel reports. The pinchecker never takes a user name or
//! a path from its caller, except through the `--dev-*` options, which `main.rs` accepts only when
//! [`dev_options_allowed`] says the pinchecker runs without elevated rights, and then it has no more
//! rights than its caller.
//!
//! This library is the decision part, with every location and outside check passed in, so the tests
//! drive it directly with temporary directories. `main.rs` is the setgid part: a clean start, the
//! fixed locations, and the real caller.

// Stricter checks for shipped code (docs/chaos/plan-tools.md): every unsafe block explains why it is
// sound, nothing indexes or slices without a bounds check, and no cast silently drops bits.
#![warn(clippy::undocumented_unsafe_blocks, clippy::indexing_slicing, clippy::cast_possible_truncation)]
#![forbid(unsafe_code)]

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

pub use properpin_core::PasswordCheck;
use properpin_core::{
    Clock, Error, Hasher, Judged, Log, MAX_INPUT_BYTES, Secret, Settings, Store, exit, housekeeping_after_password_unlock,
    try_unlock_with_pin,
};
pub use properpin_sys::UnixChkpwd;
use properpin_sys::{Account, UserFiles, local_time};

/// What the caller asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Check,
    Housekeeping,
    Unlocked,
    Status,
}

impl Request {
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "check" => Some(Self::Check),
            "housekeeping" => Some(Self::Housekeeping),
            "unlocked" => Some(Self::Unlocked),
            "status" => Some(Self::Status),
            _ => None,
        }
    }

    /// Whether it reads something typed from stdin.
    pub fn reads_input(self) -> bool {
        matches!(self, Self::Check | Self::Housekeeping)
    }
}

/// Where the files are, and who must own them.
#[derive(Debug, Clone)]
pub struct Places {
    /// `/etc/properpin` once installed.
    pub etc: PathBuf,
    /// Who must own the files under `etc`: root once installed.
    pub etc_owner: u32,
    /// `/var/lib/properpin` once installed: every user's budget, in one directory on disk.
    pub budget_dir: PathBuf,
    /// Who must own `budget_dir`: root once installed.
    pub budget_owner: u32,
    /// The group `budget_dir` must have: the one the pinchecker runs with, so a pinchecker installed
    /// without its setgid bit runs with the caller's group and refuses.
    pub budget_group: u32,
}

impl Places {
    fn files(&self, caller: &Account) -> Result<UserFiles, Error> {
        let files = UserFiles::new(&self.etc, self.etc_owner, &caller.name, caller.uid)?;
        Ok(files.with_budget(&self.budget_dir, self.budget_owner, self.budget_group))
    }
}

/// Whether the `--dev-*` options may be used: only when the pinchecker runs with no more rights than
/// its caller. Two independent signs must agree: the kernel didn't flag the start as elevated
/// (`AT_SECURE`), and the real and effective ids are the same, user and group both. A bug has to
/// defeat both before a caller could point the installed pinchecker at files or a checker of their own.
pub fn dev_options_allowed(at_secure: bool, uid: u32, euid: u32, gid: u32, egid: u32) -> bool {
    !at_secure && uid == euid && gid == egid
}

/// What the pinchecker answers: an exit code from `properpin_core::exit`, for `status` some text,
/// and for a correct PIN how soon it may answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u8,
    pub output: String,
    /// How long after the pinchecker started the answer may come at the earliest:
    /// `min_milliseconds_before_pin_unlock` for a correct PIN, and nothing for anything else, which
    /// goes on to the password at once. kscreenlocker 6.8 takes an answer within 50 ms for a broken
    /// authenticator, and a correct PIN is the one answer that ends the stack with properpin's time
    /// alone. Waiting leaks nothing, since the unlock shows anyway. `main.rs` waits it out, once the
    /// budget is saved and its lock released.
    pub not_before: Duration,
}

impl Reply {
    fn code(code: u8) -> Self {
        Self { code, output: String::new(), not_before: Duration::ZERO }
    }
}

/// Everything from outside that one request needs.
pub struct Context<'a, H, C, P, L: ?Sized> {
    pub places: &'a Places,
    pub hasher: &'a H,
    pub clock: &'a C,
    pub password: &'a P,
    pub log: &'a L,
}

/// Answer one request from `caller`. `typed` is what came on stdin, for `check` and `housekeeping`.
/// Every outcome is logged here, and every error is a refusal. `status` is asked by a person, so
/// it also prints why.
pub fn serve<H: Hasher, C: Clock, P: PasswordCheck, L: Log + ?Sized>(
    request: Request,
    caller: &Account,
    typed: &Secret,
    context: &Context<'_, H, C, P, L>,
) -> Reply {
    let broken = |what: &str, error: Error| {
        let line = format!("{}: {what}: {error}", caller.name);
        context.log.log(&line);
        let output = if request == Request::Status { line + "\n" } else { String::new() };
        Reply { output, ..Reply::code(exit::BROKEN) }
    };
    let files = match context.places.files(caller) {
        Ok(files) => files,
        Err(error) => return broken("refused", error),
    };
    let result = match request {
        Request::Check => check_pin(&files, caller, typed, context),
        Request::Housekeeping => housekeeping(&files, caller, typed, context),
        Request::Unlocked => unlocked(&files, caller, context),
        Request::Status => status(&files, context.hasher, context.clock).map(|output| Reply { output, ..Reply::code(exit::YES) }),
    };
    result.unwrap_or_else(|error| {
        let what = match request {
            Request::Check => "PIN refused",
            Request::Housekeeping | Request::Unlocked => "housekeeping failed",
            Request::Status => "status failed",
        };
        broken(what, error)
    })
}

fn check_pin<H: Hasher, C: Clock, P, L: Log + ?Sized>(
    files: &UserFiles,
    caller: &Account,
    typed: &Secret,
    context: &Context<'_, H, C, P, L>,
) -> Result<Reply, Error> {
    let outcome = try_unlock_with_pin(files, context.hasher, context.clock, typed.as_bytes())?;
    log_judged(&outcome.judged, caller, context.log);
    context.log.log(&format!("{}: {}", caller.name, outcome.verdict));
    if !outcome.verdict.unlocks() {
        return Ok(Reply::code(exit::NO));
    }
    // The attempt read the same config a moment ago, so this hardly fails; if it does, the PIN was
    // right all the same, so the default is waited out.
    let minimum = files.settings().map(|settings| settings.min_milliseconds_before_pin_unlock).unwrap_or_else(|error| {
        context.log.log(&format!("{}: waiting the default before the PIN unlocks: {error}", caller.name));
        Settings::default().min_milliseconds_before_pin_unlock
    });
    Ok(Reply { not_before: Duration::from_millis(minimum), ..Reply::code(exit::YES) })
}

fn log_judged<L: Log + ?Sized>(judged: &Judged, caller: &Account, log: &L) {
    for note in judged.notes() {
        log.log(&format!("{}: {note}", caller.name));
    }
}

/// After the lock screen's password stack, but only for the right password. The PAM line runs
/// this after a wrong one too, since the stock stack doesn't stop before it, and `housekeeping` is
/// open to everything the user runs anyway: without this check any program could unpause the PIN,
/// start its consecutive count over and forgive the budget's failures as often as it liked.
/// `unix_chkpwd` checks it, as pam_unix in the stock stack just did.
fn housekeeping<H, C: Clock, P: PasswordCheck, L: Log + ?Sized>(
    files: &UserFiles,
    caller: &Account,
    typed: &Secret,
    context: &Context<'_, H, C, P, L>,
) -> Result<Reply, Error> {
    let settings = files.settings()?;
    if settings.pin_hash.is_empty() {
        context.log.log(&format!("{}: no PIN is set, so there is nothing to do", caller.name));
        return Ok(Reply::code(exit::NO));
    }
    if typed.as_bytes().is_empty() || !context.password.matches(&caller.name, typed)? {
        context.log.log(&format!("{}: wrong password, nothing changed", caller.name));
        return Ok(Reply::code(exit::NO));
    }
    unpause(files, caller, "password correct", context)
}

/// After the lock screen's password stack succeeded, as the module's `pam_sm_setcred` tells it: the
/// housekeeping, without checking any password. Open to everything the user runs, which could
/// call it at will; docs/current-setcred.md says why that is acceptable. With `pin_unpause_by`
/// left at password-check it changes nothing, so the default keeps today's guarantee that only
/// the right password unpauses the PIN.
fn unlocked<H, C: Clock, P, L: Log + ?Sized>(
    files: &UserFiles,
    caller: &Account,
    context: &Context<'_, H, C, P, L>,
) -> Result<Reply, Error> {
    let settings = files.settings()?;
    if settings.pin_hash.is_empty() {
        context.log.log(&format!("{}: no PIN is set, so there is nothing to do", caller.name));
        return Ok(Reply::code(exit::NO));
    }
    if !settings.pin_unpause_by.by_setcred() {
        context
            .log
            .log(&format!("{}: unlock reported, but pin_unpause_by is {}, so nothing changed", caller.name, settings.pin_unpause_by));
        return Ok(Reply::code(exit::NO));
    }
    unpause(files, caller, "unlocked through the password stack (setcred)", context)
}

/// Forgive the recent failures and unpause the PIN; `why` starts the log line.
fn unpause<H, C: Clock, P, L: Log + ?Sized>(
    files: &UserFiles,
    caller: &Account,
    why: &str,
    context: &Context<'_, H, C, P, L>,
) -> Result<Reply, Error> {
    let judged = housekeeping_after_password_unlock(files, context.clock)?;
    log_judged(&judged, caller, context.log);
    match judged.disabled {
        Some(limit) => context.log.log(&format!(
            "{}: {why}, but the PIN stays disabled after {limit}; sudo properpin enable or set turns it back on",
            caller.name
        )),
        None => context.log.log(&format!("{}: {why}, PIN enabled", caller.name)),
    }
    Ok(Reply::code(exit::YES))
}

/// What is set, which rules apply, and whether the PIN is enabled, paused or disabled right now,
/// and since when, or refused whatever is typed, and why: every file an attempt reads, checked the
/// way it checks them.
fn status(files: &UserFiles, hasher: &impl Hasher, clock: &impl Clock) -> Result<String, Error> {
    const FIX: &str = "sudo properpin doctor says how to fix it";
    let line = |label: &str, value: &str| format!("{label:<22}{value}\n");
    let since = |at: u64| format!("since {}", local_time(at));
    let mut out = line("user", files.user());
    let settings = match files.settings() {
        Ok(settings) if settings.pin_hash.is_empty() => return Ok(out + &line("PIN", "none set") + &line("hash", "unset")),
        Ok(settings) => settings,
        Err(error) => return Ok(out + &line("PIN", &format!("refused whatever is typed: {error}; {FIX}"))),
    };
    let rules = format!("{}, yescrypt cost {}", settings.pin_rules(), settings.hash_cost);
    let path = files.user_file().display().to_string();
    if let Err(error) = hasher.verify("", &settings.pin_hash).and_then(|_| files.check_budget()) {
        out += &line("PIN", &format!("refused whatever is typed: {error}; {FIX}"));
        return Ok(out + &line("hash", &format!("set, in {path}")) + &line("rules for a new PIN", &rules));
    }
    // Judged as the next attempt would, without saving: status changes nothing.
    let mut budget = files.load_budget()?;
    let judged = budget.judge(clock.now()?, &settings);
    let state = match (judged.disabled, budget.disabled) {
        (Some(limit), Some(disabled)) => {
            format!("disabled {}, after {limit}; sudo properpin enable or set turns it back on", since(disabled.at))
        }
        _ if budget.paused(&settings) => format!(
            "paused {}, after {} consecutive failures; unlocking with the password resumes it",
            since(budget.since),
            budget.consecutive
        ),
        _ => format!("enabled {}", since(budget.since)),
    };
    out += &line("PIN", &state);
    out += &line("hash", &format!("set {}, in {path}", since(budget.set)));
    out += &line("rules for a new PIN", &rules);
    out += &line("consecutive failures", &format!("{}/{}", budget.consecutive, settings.max_failures));
    let counts = judged.counts;
    let of = |count: String, what: &str| format!("    {count:<7}{what}\n");
    out += "suspicious failures\n";
    out += &of(format!("{}/{}", counts.day, settings.max_suspicious_24h), "within 24 hours");
    out += &of(format!("{}/{}", counts.week, settings.max_suspicious_7d), "within 7 days");
    out += &of(format!("{}/{}", counts.total, settings.max_suspicious_total), "since this PIN was set");
    out += &of(counts.pending.to_string(), "waiting to be forgiven");
    out += "policy\n";
    out += &format!("    {} consecutive failures pause the PIN, until a password unlock\n", settings.max_failures);
    out += "    too many suspicious failures, as above, disable it, until sudo properpin enable or set\n";
    Ok(out)
}

/// Everything on `input`, up to [`MAX_INPUT_BYTES`]. The buffer is allocated once at its full size
/// and never grows, so no unwiped copy is left behind. Longer input comes back one byte over the
/// limit, which no PIN and no PAM response can be, so it is refused.
pub fn read_input(input: &mut impl Read) -> std::io::Result<Secret> {
    let mut buffer = vec![0; MAX_INPUT_BYTES + 1];
    let mut length = 0;
    // `length` never passes the buffer's end: each read fills at most what is left.
    while let Some(rest) = buffer.get_mut(length..).filter(|rest| !rest.is_empty()) {
        match input.read(rest) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                drop(Secret::new(buffer)); // wiped
                return Err(error);
            }
        }
    }
    buffer.truncate(length);
    Ok(Secret::new(buffer))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;

    use properpin_sys::{SystemClock, Yescrypt, current_egid, current_uid};

    use super::*;

    const PIN: &str = "4859";
    const PASSWORD: &str = "correct horse battery staple";
    /// When the sandbox's PIN was set.
    const SET_AT: u64 = 1_700_000_000;

    struct Sandbox {
        _dir: tempfile::TempDir,
        places: Places,
        caller: Account,
    }

    fn sandbox() -> Sandbox {
        let dir = tempfile::tempdir().unwrap();
        let uid = current_uid();
        let places = Places {
            etc: dir.path().join("etc"),
            etc_owner: uid,
            budget_dir: dir.path().join("var"),
            budget_owner: uid,
            budget_group: current_egid(),
        };
        fs::create_dir(&places.budget_dir).unwrap();
        fs::set_permissions(&places.budget_dir, Permissions::from_mode(0o1770)).unwrap();
        // alice is whoever runs the tests: her budget must be her own, and it is the test's.
        let caller = Account { name: "alice".into(), uid, gid: current_egid() };
        let sandbox = Sandbox { _dir: dir, places, caller };
        sandbox.write_user_file(&format!("hash = {}\n", Yescrypt.hash(PIN, 4).unwrap()));
        // The budget and lock file properpin set creates.
        sandbox.places.files(&sandbox.caller).unwrap().start_budget(&properpin_core::Budget::fresh(SET_AT)).unwrap();
        sandbox
    }

    impl Sandbox {
        fn write_user_file(&self, text: &str) {
            let path = self.places.etc.join("users").join(&self.caller.name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, text).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o640)).unwrap();
        }

        fn ask(&self, request: Request, typed: &str) -> (u8, String, String) {
            self.ask_as(&self.caller, request, typed)
        }

        fn ask_as(&self, caller: &Account, request: Request, typed: &str) -> (u8, String, String) {
            self.ask_with(&SystemClock, caller, request, typed)
        }

        fn ask_with(&self, clock: &impl Clock, caller: &Account, request: Request, typed: &str) -> (u8, String, String) {
            let log = Lines::default();
            let reply = self.reply_logged(clock, caller, request, typed, &log);
            (reply.code, reply.output, log.0.into_inner().join("\n"))
        }

        fn reply(&self, request: Request, typed: &str) -> Reply {
            self.reply_logged(&SystemClock, &self.caller, request, typed, &Lines::default())
        }

        fn reply_logged(&self, clock: &impl Clock, caller: &Account, request: Request, typed: &str, log: &Lines) -> Reply {
            let context = Context { places: &self.places, hasher: &Yescrypt, clock, password: &Password, log };
            serve(request, caller, &Secret::new(typed.as_bytes().to_vec()), &context)
        }

        fn write_config(&self, text: &str) {
            let path = self.places.etc.join("config");
            fs::write(&path, text).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        }

        fn budget_file(&self) -> std::path::PathBuf {
            self.places.budget_dir.join(format!("{}.budget", self.caller.uid))
        }
    }

    /// The real clock, moved on by `ahead` seconds.
    struct Later {
        ahead: u64,
    }

    impl Clock for Later {
        fn now(&self) -> Result<u64, Error> {
            Ok(SystemClock.now()? + self.ahead)
        }
    }

    #[derive(Default)]
    struct Lines(RefCell<Vec<String>>);

    impl Log for Lines {
        fn log(&self, line: &str) {
            self.0.borrow_mut().push(line.into());
        }
    }

    /// Accepts `PASSWORD` for alice, the way `unix_chkpwd` would.
    struct Password;

    impl PasswordCheck for Password {
        fn matches(&self, user: &str, password: &Secret) -> Result<bool, Error> {
            Ok(user == "alice" && password.as_bytes() == PASSWORD.as_bytes())
        }
    }

    #[test]
    fn the_whole_cycle() {
        let sandbox = sandbox();
        let (code, _, log) = sandbox.ask(Request::Check, PIN);
        assert_eq!((code, log.as_str()), (exit::YES, "alice: unlocked with the PIN"));
        for wrong in ["1111", "2222"] {
            assert_eq!(sandbox.ask(Request::Check, wrong).0, exit::NO);
        }
        let (code, _, log) = sandbox.ask(Request::Check, "3333");
        assert_eq!((code, log.as_str()), (exit::NO, "alice: not the PIN, consecutive failure 3 of 3; PIN paused, password required"));
        let (code, _, log) = sandbox.ask(Request::Check, PIN);
        assert_eq!((code, log.as_str()), (exit::NO, "alice: PIN paused after 3 consecutive failures, password required"));
        let (code, _, log) = sandbox.ask(Request::Housekeeping, PASSWORD);
        assert_eq!((code, log.as_str()), (exit::YES, "alice: password correct, PIN enabled"));
        assert_eq!(sandbox.ask(Request::Check, PIN).0, exit::YES);
    }

    /// A correct PIN answers no sooner than the config's minimum after the start, 75 ms by default;
    /// nothing else waits.
    #[test]
    fn only_a_correct_pin_asks_to_wait() {
        let sandbox = sandbox();
        assert_eq!(sandbox.reply(Request::Check, PIN).not_before, Duration::from_millis(75));
        sandbox.write_config("min_milliseconds_before_pin_unlock = 500\n");
        assert_eq!(sandbox.reply(Request::Check, PIN), Reply { not_before: Duration::from_millis(500), ..Reply::code(exit::YES) });
        for (request, typed) in [(Request::Check, "1111"), (Request::Housekeeping, PASSWORD), (Request::Status, "")] {
            assert_eq!(sandbox.reply(request, typed).not_before, Duration::ZERO, "{request:?} {typed:?}");
        }
    }

    #[test]
    fn the_budget_holds_the_consecutive_count_on_disk() {
        let sandbox = sandbox();
        sandbox.ask(Request::Check, "1111");
        assert!(fs::read_to_string(sandbox.budget_file()).unwrap().starts_with("consecutive = 1\n"));
    }

    #[test]
    fn a_wrong_password_changes_nothing() {
        let sandbox = sandbox();
        for wrong in ["1111", "2222", "3333"] {
            sandbox.ask(Request::Check, wrong);
        }
        for wrong in ["", "wrong", "correct horse battery stapl"] {
            let (code, _, log) = sandbox.ask(Request::Housekeeping, wrong);
            assert_eq!(code, exit::NO, "{wrong:?}");
            assert!(log.contains("wrong password, nothing changed"), "{log}");
        }
        assert_eq!(sandbox.ask(Request::Check, PIN).0, exit::NO, "a rejected password must not unpause the PIN");
    }

    #[test]
    fn without_a_pin_there_is_nothing_to_do() {
        let sandbox = sandbox();
        fs::remove_file(sandbox.places.etc.join("users/alice")).unwrap();
        let budget = sandbox.places.budget_dir.join(format!("{}.budget", sandbox.caller.uid));
        let before = fs::read(&budget).unwrap();
        let (code, _, log) = sandbox.ask(Request::Housekeeping, PASSWORD);
        assert_eq!((code, log.as_str()), (exit::NO, "alice: no PIN is set, so there is nothing to do"));
        assert_eq!(fs::read(&budget).unwrap(), before, "nothing written");
        assert_eq!(fs::read_dir(&sandbox.places.budget_dir).unwrap().count(), 2, "nothing created");
    }

    #[test]
    fn each_caller_gets_only_their_own_pin_and_counts() {
        let sandbox = sandbox();
        let bob = Account { name: "bob".into(), uid: sandbox.caller.uid + 1, gid: sandbox.caller.gid };
        let (code, _, log) = sandbox.ask_as(&bob, Request::Check, PIN);
        assert_eq!((code, log.as_str()), (exit::NO, "bob: no PIN is set, refused"));
        for wrong in ["1111", "2222", "3333"] {
            sandbox.ask_as(&bob, Request::Check, wrong);
        }
        assert_eq!(sandbox.ask(Request::Check, PIN).0, exit::YES, "bob's attempts touched alice's counts");
    }

    #[test]
    fn broken_files_refuse() {
        let sandbox = sandbox();
        fs::set_permissions(sandbox.places.etc.join("users/alice"), Permissions::from_mode(0o644)).unwrap();
        let (code, _, log) = sandbox.ask(Request::Check, PIN);
        assert_eq!(code, exit::BROKEN);
        assert!(log.contains("alice: PIN refused:") && log.contains("readable by others"), "{log}");

        let sandbox = self::sandbox();
        fs::set_permissions(&sandbox.places.budget_dir, Permissions::from_mode(0o755)).unwrap();
        let (code, _, log) = sandbox.ask(Request::Housekeeping, PASSWORD);
        assert_eq!(code, exit::BROKEN);
        assert!(log.contains("mode 0755, not 1770"), "{log}");
    }

    #[test]
    fn dev_options_need_both_guards_to_agree() {
        let (me, other) = (1000, 1001);
        assert!(dev_options_allowed(false, me, me, me, me));
        for (at_secure, uid, euid, gid, egid) in [
            (true, me, me, me, me),        // the kernel says elevated, the ids don't show it
            (false, me, other, me, me),    // setuid that AT_SECURE missed
            (false, me, me, me, other),    // setgid that AT_SECURE missed
            (false, other, me, other, me), // both
            (true, me, other, me, other),
        ] {
            assert!(!dev_options_allowed(at_secure, uid, euid, gid, egid), "{at_secure} {uid} {euid} {gid} {egid}");
        }
    }

    #[test]
    fn a_bad_user_name_is_refused_before_any_file() {
        let sandbox = sandbox();
        let sneaky = Account { name: "../alice".into(), ..sandbox.caller.clone() };
        let (code, _, log) = sandbox.ask_as(&sneaky, Request::Check, PIN);
        assert_eq!(code, exit::BROKEN);
        assert!(log.contains("not a usable user name"), "{log}");
    }

    #[test]
    fn status_reports_settings_and_counts() {
        let sandbox = sandbox();
        let (code, output, _) = sandbox.ask(Request::Status, "");
        assert_eq!(code, exit::YES);
        let path = sandbox.places.etc.join("users/alice");
        let set_at = local_time(SET_AT);
        let expected = format!(
            "user                  alice
PIN                   enabled since {set_at}
hash                  set since {set_at}, in {}
rules for a new PIN   4 to 64 characters, at least 3 of them not digits, yescrypt cost 5
consecutive failures  0/3
suspicious failures
    0/10   within 24 hours
    0/25   within 7 days
    0/60   since this PIN was set
    0      waiting to be forgiven
policy
    3 consecutive failures pause the PIN, until a password unlock
    too many suspicious failures, as above, disable it, until sudo properpin enable or set
",
            path.display()
        );
        assert_eq!(output, expected);
        for wrong in ["1111", "2222", "3333"] {
            sandbox.ask(Request::Check, wrong);
        }
        let output = sandbox.ask(Request::Status, "").1;
        // Recorded by the third failure.
        assert!(output.contains("PIN                   paused since 20"), "{output}");
        assert!(output.contains(", after 3 consecutive failures; unlocking with the password resumes it"), "{output}");
        fs::remove_file(sandbox.places.etc.join("users/alice")).unwrap();
        assert!(sandbox.ask(Request::Status, "").1.contains("none set"));
    }

    /// Whatever would refuse the PIN, status says, instead of failing; and what it can't answer
    /// at all, it prints too.
    #[test]
    fn status_says_why_the_pin_is_refused() {
        let sandbox = sandbox();
        fs::remove_file(sandbox.budget_file()).unwrap();
        let (code, output, _) = sandbox.ask(Request::Status, "");
        assert_eq!(code, exit::YES);
        assert!(output.contains("PIN                   refused whatever is typed: "), "{output}");
        assert!(output.contains(".budget: missing; sudo properpin doctor says how to fix it"), "{output}");
        sandbox.write_user_file("hash = not a hash\n");
        assert!(sandbox.ask(Request::Status, "").1.contains("not a yescrypt hash; sudo properpin doctor"));
        fs::set_permissions(sandbox.places.etc.join("users/alice"), Permissions::from_mode(0o644)).unwrap();
        let output = sandbox.ask(Request::Status, "").1;
        assert!(
            output.contains("PIN                   refused whatever is typed: ")
                && output.contains("readable by others; sudo properpin doctor"),
            "{output}"
        );
        let sneaky = Account { name: "../alice".into(), ..sandbox.caller.clone() };
        let (code, output, _) = sandbox.ask_as(&sneaky, Request::Status, "");
        assert_eq!(code, exit::BROKEN);
        assert!(output.contains("not a usable user name"), "{output}");
    }

    /// Guesses nobody forgives, a wrong password included, are judged later, logged, and disable
    /// the PIN; the password then doesn't bring it back.
    #[test]
    fn suspicious_failures_are_logged_and_disable_the_pin() {
        let sandbox = sandbox();
        let alice = &sandbox.caller;
        // Three failures in a row would pause the PIN, the wrong password among them, since it is
        // checked as a PIN too; this test is about the budget, not the pause.
        sandbox.write_config("max_failures = 4\n");
        for wrong in ["1111", "2222", "not the password at all"] {
            sandbox.ask(Request::Check, wrong);
        }
        // Two minutes on, the correct PIN comes too late to forgive them.
        let (code, _, log) = sandbox.ask_with(&Later { ahead: 120 }, alice, Request::Check, PIN);
        assert_eq!(code, exit::YES);
        assert!(log.contains("3 failure(s) not followed by an unlock in time, now suspicious: 3 within 24 hours"), "{log}");
        let output = sandbox.ask_with(&Later { ahead: 120 }, alice, Request::Status, "").1;
        assert!(output.contains("    3/10   within 24 hours\n    3/25   within 7 days\n    3/60   since this PIN was set\n"), "{output}");

        sandbox.write_config("max_suspicious_24h = 4\n");
        sandbox.ask_with(&Later { ahead: 120 }, alice, Request::Check, "3333");
        let (code, _, log) = sandbox.ask_with(&Later { ahead: 300 }, alice, Request::Check, PIN);
        assert_eq!(code, exit::NO);
        assert!(log.contains("PIN disabled after 4 suspicious failures within 24 hours; sudo properpin enable or set"), "{log}");
        assert!(log.contains("alice: PIN disabled after 4 suspicious failures within 24 hours, password required"), "{log}");
        let (code, _, log) = sandbox.ask_with(&Later { ahead: 300 }, alice, Request::Housekeeping, PASSWORD);
        assert_eq!((code, log.contains("password correct, but the PIN stays disabled after")), (exit::YES, true), "{log}");
        let output = sandbox.ask_with(&Later { ahead: 300 }, alice, Request::Status, "").1;
        assert!(
            output.contains("PIN                   disabled since ")
                && output.contains(", after 4 suspicious failures within 24 hours; sudo properpin enable"),
            "{output}"
        );
    }

    #[test]
    fn typos_followed_by_the_pin_or_the_password_are_forgiven() {
        let sandbox = sandbox();
        sandbox.ask(Request::Check, "1111");
        sandbox.ask(Request::Check, PIN);
        sandbox.ask(Request::Check, "correct horse battery stapl");
        sandbox.ask(Request::Check, PASSWORD);
        sandbox.ask(Request::Housekeeping, PASSWORD);
        let output = sandbox.ask_with(&Later { ahead: 3600 }, &sandbox.caller, Request::Status, "").1;
        assert!(output.contains("    0/60   since this PIN was set\n    0      waiting to be forgiven\n"), "{output}");
    }

    #[test]
    fn a_damaged_budget_refuses_the_pin() {
        let sandbox = sandbox();
        fs::write(sandbox.budget_file(), "garbage\n").unwrap();
        fs::set_permissions(sandbox.budget_file(), Permissions::from_mode(0o600)).unwrap();
        let (code, _, log) = sandbox.ask(Request::Check, PIN);
        assert_eq!(code, exit::BROKEN);
        assert!(log.contains("not a valid budget"), "{log}");
    }

    #[test]
    fn input_is_read_up_to_the_limit_only() {
        let typed = read_input(&mut &b"4859"[..]).unwrap();
        assert_eq!(typed.as_bytes(), b"4859");
        let long = vec![b'1'; MAX_INPUT_BYTES * 3];
        let typed = read_input(&mut &long[..]).unwrap();
        assert_eq!(typed.as_bytes().len(), MAX_INPUT_BYTES + 1);
        assert_eq!(properpin_core::input_that_could_be_a_pin(typed.as_bytes()), None);
    }

    #[test]
    fn requests_are_exact_words() {
        assert_eq!(Request::parse("check"), Some(Request::Check));
        assert_eq!(Request::parse("housekeeping"), Some(Request::Housekeeping));
        for word in ["Check", "check ", "", "--check", "set", "start-accepting-pin"] {
            assert_eq!(Request::parse(word), None, "{word:?}");
        }
    }
}
