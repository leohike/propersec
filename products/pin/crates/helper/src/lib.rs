//! `properpin-helper`: the only program that reads PIN hashes and keeps the failure counts.
//!
//! It is installed owned by root and setgid to the `properpin` group, like Debian's `unix_chkpwd` is
//! setgid to `shadow`, so the hash files and the counts can be readable by that group alone and stay
//! out of reach of everything the user runs. The group has no members: running the helper is the
//! only way to get it. The helper keeps its caller's user id, so the caller can't change the helper,
//! and each user's counts file is that user's own. The PAM module and the CLI start it, write what
//! was typed to its stdin, and read its exit code (`properpin_core::exit`); only `status` prints
//! anything.
//!
//! ```text
//! properpin-helper check    stdin: what was typed. Exit 0 if it is the PIN and the PIN is armed
//! properpin-helper arm      stdin: the password, just accepted by pam_unix. Checked again through
//!                           unix_chkpwd, then the PIN is armed
//! properpin-helper status   prints the caller's PIN settings and whether it is armed
//! ```
//!
//! The caller is always the real user id the kernel reports. The helper never takes a user name or
//! a path from its caller, except through the `--dev-*` options, which `main.rs` accepts only when
//! [`dev_options_allowed`] says the helper runs without elevated rights, and then it has no more
//! rights than its caller.
//!
//! This library is the decision part, with every location and outside check passed in, so the tests
//! drive it directly with temporary directories. `main.rs` is the setgid part: a clean start, the
//! fixed locations, and the real caller.

#![forbid(unsafe_code)]

use std::io::Read;
use std::path::PathBuf;

use properpin_core::{Clock, Error, Hasher, Judged, Log, MAX_INPUT_BYTES, Refusal, Secret, Store, arm, check, describe_seconds, exit};
use properpin_sys::{Account, UserFiles};

mod chkpwd;

pub use chkpwd::UnixChkpwd;

/// What the caller asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Check,
    Arm,
    Status,
}

impl Request {
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "check" => Some(Self::Check),
            "arm" => Some(Self::Arm),
            "status" => Some(Self::Status),
            _ => None,
        }
    }

    /// Whether it reads something typed from stdin.
    pub fn reads_input(self) -> bool {
        self != Self::Status
    }
}

/// Where the files are, and who must own them.
#[derive(Debug, Clone)]
pub struct Places {
    /// `/etc/properpin` once installed.
    pub etc: PathBuf,
    /// Who must own the files under `etc`: root once installed.
    pub etc_owner: u32,
    /// `/run/properpin` once installed: every user's state, in one directory.
    pub run_dir: PathBuf,
    /// Who must own `run_dir`: root once installed.
    pub run_owner: u32,
    /// The group `run_dir` must have: the one the helper runs with, so a helper installed without
    /// its setgid bit runs with the caller's group and refuses.
    pub run_group: u32,
    /// `/var/lib/properpin` once installed: every user's budget, on disk. Same owner and group as
    /// `run_dir`.
    pub budget_dir: PathBuf,
}

impl Places {
    fn files(&self, caller: &Account) -> Result<UserFiles, Error> {
        let files = UserFiles::new(&self.etc, self.etc_owner, &caller.name, caller.uid)?;
        Ok(files.with_runtime(&self.run_dir, self.run_owner, self.run_group).with_budget(&self.budget_dir, self.run_owner, self.run_group))
    }
}

/// Whether the `--dev-*` options may be used: only when the helper runs with no more rights than
/// its caller. Two independent signs must agree: the kernel didn't flag the start as elevated
/// (`AT_SECURE`), and the real and effective ids are the same, user and group both. A bug has to
/// defeat both before a caller could point the installed helper at files or a checker of their own.
pub fn dev_options_allowed(at_secure: bool, uid: u32, euid: u32, gid: u32, egid: u32) -> bool {
    !at_secure && uid == euid && gid == egid
}

/// Checks the account password, the way pam_unix does: through `unix_chkpwd` once installed.
pub trait PasswordCheck {
    fn matches(&self, user: &str, password: &Secret) -> Result<bool, Error>;
}

/// What the helper answers: an exit code from `properpin_core::exit`, and for `status` some text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u8,
    pub output: String,
}

impl Reply {
    fn code(code: u8) -> Self {
        Self { code, output: String::new() }
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

/// Answer one request from `caller`. `typed` is what came on stdin, for `check` and `arm`.
/// Every outcome is logged here, and every error is a refusal.
pub fn serve<H: Hasher, C: Clock, P: PasswordCheck, L: Log + ?Sized>(
    request: Request,
    caller: &Account,
    typed: &Secret,
    context: &Context<'_, H, C, P, L>,
) -> Reply {
    let files = match context.places.files(caller) {
        Ok(files) => files,
        Err(error) => {
            context.log.log(&format!("{}: refused: {error}", caller.name));
            return Reply::code(exit::BROKEN);
        }
    };
    let result = match request {
        Request::Check => check_pin(&files, caller, typed, context),
        Request::Arm => arm_pin(&files, caller, typed, context),
        Request::Status => status(&files, context.clock).map(|output| Reply { code: exit::YES, output }),
    };
    result.unwrap_or_else(|error| {
        let what = match request {
            Request::Check => "PIN refused",
            Request::Arm => "PIN not armed",
            Request::Status => "status failed",
        };
        context.log.log(&format!("{}: {what}: {error}", caller.name));
        Reply::code(exit::BROKEN)
    })
}

fn check_pin<H: Hasher, C: Clock, P, L: Log + ?Sized>(
    files: &UserFiles,
    caller: &Account,
    typed: &Secret,
    context: &Context<'_, H, C, P, L>,
) -> Result<Reply, Error> {
    let outcome = check(files, context.hasher, context.clock, typed.as_bytes())?;
    log_judged(&outcome.judged, caller, context.log);
    context.log.log(&format!("{}: {}", caller.name, outcome.verdict));
    Ok(Reply::code(if outcome.verdict.unlocks() { exit::YES } else { exit::NO }))
}

fn log_judged<L: Log + ?Sized>(judged: &Judged, caller: &Account, log: &L) {
    for note in judged.notes() {
        log.log(&format!("{}: {note}", caller.name));
    }
}

/// Arm the PIN, but only for the right password: `arm` is open to everything the user runs, so
/// without this check any program could arm the PIN at will, reset the failures in a row, and
/// forgive the budget's failures as often as it liked. `unix_chkpwd` checks it, as pam_unix just
/// did.
fn arm_pin<H, C: Clock, P: PasswordCheck, L: Log + ?Sized>(
    files: &UserFiles,
    caller: &Account,
    typed: &Secret,
    context: &Context<'_, H, C, P, L>,
) -> Result<Reply, Error> {
    if files.settings()?.pin_hash.is_empty() {
        context.log.log(&format!("{}: no PIN is set, nothing to arm", caller.name));
        return Ok(Reply::code(exit::NO));
    }
    if typed.as_bytes().is_empty() || !context.password.matches(&caller.name, typed)? {
        context.log.log(&format!("{}: the password was not accepted, PIN not armed", caller.name));
        return Ok(Reply::code(exit::NO));
    }
    let judged = arm(files, context.clock)?;
    log_judged(&judged, caller, context.log);
    if let Some(limit) = judged.disabled {
        context.log.log(&format!("{}: password accepted, PIN not armed: disabled after {limit}", caller.name));
        return Ok(Reply::code(exit::NO));
    }
    context.log.log(&format!("{}: password accepted, PIN armed", caller.name));
    Ok(Reply::code(exit::YES))
}

/// What is set, which rules apply, and whether the PIN is armed right now.
fn status(files: &UserFiles, clock: &impl Clock) -> Result<String, Error> {
    let mut out = format!("user       {}\n", files.user());
    let settings = match files.settings() {
        Ok(settings) if settings.pin_hash.is_empty() => return Ok(out + "PIN        none set\n"),
        Ok(settings) => settings,
        Err(error) => return Ok(out + &format!("PIN        unusable: {error}\n")),
    };
    out += &format!("PIN        set, in {}\n", files.user_file().display());
    out += &format!(
        "policy     armed for {}h after a password unlock, until {} failures in a row\n",
        settings.expiry_hours, settings.max_failures
    );
    let mut rules = format!("{} to {} characters", settings.min_pin_length, settings.max_pin_length);
    if settings.min_letters > 0 {
        rules += &format!(", {} English letters", settings.min_letters);
    }
    out += &format!("set rules  {rules}, yescrypt cost {}\n", settings.hash_cost);
    // Judged as the next attempt would, without saving: status changes nothing.
    let mut budget = files.load_budget()?;
    let judged = budget.judge(clock.wall()?, &settings);
    let counts = judged.counts;
    out += &format!(
        "budget     concerning failures: {} within 24 hours (of {}), {} within 7 days (of {}), {} since the PIN was set (of {}); \
         {} waiting to be forgiven\n",
        counts.day,
        settings.max_concerning_24h,
        counts.week,
        settings.max_concerning_7d,
        counts.total,
        settings.max_concerning_total,
        counts.pending
    );
    let state = files.load_state();
    let now = clock.now()?;
    let refusal = match judged.disabled {
        Some(limit) => Some(Refusal::Disabled(limit)),
        None => settings.refusal(state.as_ref(), &clock.boot_id()?, now),
    };
    match (refusal, state) {
        (Some(refusal @ Refusal::Disabled(_)), _) => {
            out += &format!("right now  password required: {refusal}; sudo properpin enable or set turns it back on\n")
        }
        (Some(refusal), _) => out += &format!("right now  password required: {refusal}\n"),
        (None, Some(state)) => {
            let left = (settings.expiry_seconds() as u64).saturating_sub(now - state.armed_at);
            out += &format!(
                "right now  PIN armed for another {}, {} of {} failures so far\n",
                describe_seconds(left),
                state.failures,
                settings.max_failures
            );
        }
        (None, None) => out += "right now  password required\n",
    }
    Ok(out)
}

/// Everything on `input`, up to [`MAX_INPUT_BYTES`]. The buffer is allocated once at its full size
/// and never grows, so no unwiped copy is left behind. Longer input comes back one byte over the
/// limit, which no PIN and no PAM response can be, so it is refused.
pub fn read_input(input: &mut impl Read) -> std::io::Result<Secret> {
    let mut buffer = vec![0; MAX_INPUT_BYTES + 1];
    let mut length = 0;
    while length < buffer.len() {
        match input.read(&mut buffer[length..]) {
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

    use properpin_sys::{BootClock, Yescrypt, current_egid, current_uid};

    use super::*;

    const PIN: &str = "4859";
    const PASSWORD: &str = "correct horse battery staple";

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
            run_dir: dir.path().join("run"),
            run_owner: uid,
            run_group: current_egid(),
            budget_dir: dir.path().join("var"),
        };
        for shared in [&places.run_dir, &places.budget_dir] {
            fs::create_dir(shared).unwrap();
            fs::set_permissions(shared, Permissions::from_mode(0o1770)).unwrap();
        }
        // alice is whoever runs the tests: her counts files must be her own, and they are the test's.
        let caller = Account { name: "alice".into(), uid, gid: current_egid() };
        let sandbox = Sandbox { _dir: dir, places, caller };
        sandbox.write_user_file(&format!("hash = {}\n", Yescrypt.hash(PIN, 4).unwrap()));
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
            self.ask_with(&BootClock, caller, request, typed)
        }

        fn ask_with(&self, clock: &impl Clock, caller: &Account, request: Request, typed: &str) -> (u8, String, String) {
            let log = Lines::default();
            let context = Context { places: &self.places, hasher: &Yescrypt, clock, password: &Password, log: &log };
            let reply = serve(request, caller, &Secret::new(typed.as_bytes().to_vec()), &context);
            (reply.code, reply.output, log.0.into_inner().join("\n"))
        }

        fn write_config(&self, text: &str) {
            let path = self.places.etc.join("config");
            fs::write(&path, text).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        }
    }

    /// The real boot clock, with the wall clock moved on by `ahead` seconds.
    struct Later {
        ahead: u64,
    }

    impl Clock for Later {
        fn boot_id(&self) -> Result<String, Error> {
            BootClock.boot_id()
        }
        fn now(&self) -> Result<u64, Error> {
            BootClock.now()
        }
        fn wall(&self) -> Result<u64, Error> {
            Ok(BootClock.wall()? + self.ahead)
        }
    }

    #[derive(Default)]
    struct Lines(RefCell<Vec<String>>);

    impl Log for Lines {
        fn log(&self, line: &str) {
            self.0.borrow_mut().push(line.into());
        }
    }

    /// Accepts exactly `PASSWORD` for alice, the way `unix_chkpwd` would.
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
        assert_eq!((code, log.as_str()), (exit::NO, "alice: PIN refused, password required: no password unlock since boot"));
        assert_eq!(sandbox.ask(Request::Arm, PASSWORD).0, exit::YES);
        let (code, _, log) = sandbox.ask(Request::Check, PIN);
        assert_eq!((code, log.as_str()), (exit::YES, "alice: unlocked with the PIN"));
        for wrong in ["1111", "2222", "3333"] {
            assert_eq!(sandbox.ask(Request::Check, wrong).0, exit::NO);
        }
        let (code, _, log) = sandbox.ask(Request::Check, PIN);
        assert_eq!((code, log.as_str()), (exit::NO, "alice: PIN refused, password required: 3 failures in a row"));
    }

    #[test]
    fn a_wrong_password_never_arms() {
        let sandbox = sandbox();
        for wrong in ["", "wrong", "correct horse battery stapl"] {
            let (code, _, log) = sandbox.ask(Request::Arm, wrong);
            assert_eq!(code, exit::NO, "{wrong:?}");
            assert!(log.contains("the password was not accepted, PIN not armed"), "{log}");
        }
        assert_eq!(sandbox.ask(Request::Check, PIN).0, exit::NO);
    }

    #[test]
    fn arming_after_failures_needs_the_password_too() {
        let sandbox = sandbox();
        sandbox.ask(Request::Arm, PASSWORD);
        for wrong in ["1111", "2222", "3333"] {
            sandbox.ask(Request::Check, wrong);
        }
        sandbox.ask(Request::Arm, "not the password");
        assert_eq!(sandbox.ask(Request::Check, PIN).0, exit::NO, "a rejected arm must not reset the failures");
        sandbox.ask(Request::Arm, PASSWORD);
        assert_eq!(sandbox.ask(Request::Check, PIN).0, exit::YES);
    }

    #[test]
    fn without_a_pin_there_is_nothing_to_arm() {
        let sandbox = sandbox();
        fs::remove_file(sandbox.places.etc.join("users/alice")).unwrap();
        let (code, _, log) = sandbox.ask(Request::Arm, PASSWORD);
        assert_eq!((code, log.as_str()), (exit::NO, "alice: no PIN is set, nothing to arm"));
        assert_eq!(fs::read_dir(&sandbox.places.run_dir).unwrap().count(), 0, "nothing written");
    }

    #[test]
    fn each_caller_gets_only_their_own_pin_and_counts() {
        let sandbox = sandbox();
        sandbox.ask(Request::Arm, PASSWORD);
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
        sandbox.ask(Request::Arm, PASSWORD);
        fs::set_permissions(sandbox.places.etc.join("users/alice"), Permissions::from_mode(0o644)).unwrap();
        let (code, _, log) = sandbox.ask(Request::Check, PIN);
        assert_eq!(code, exit::BROKEN);
        assert!(log.contains("alice: PIN refused:") && log.contains("readable by others"), "{log}");

        let sandbox = self::sandbox();
        fs::set_permissions(&sandbox.places.run_dir, Permissions::from_mode(0o755)).unwrap();
        let (code, _, log) = sandbox.ask(Request::Arm, PASSWORD);
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
        assert!(output.contains("PIN        set") && output.contains("no password unlock since boot"), "{output}");
        sandbox.ask(Request::Arm, PASSWORD);
        sandbox.ask(Request::Check, "1111");
        let output = sandbox.ask(Request::Status, "").1;
        assert!(
            output.contains("PIN armed for another 7h59m, 1 of 3 failures so far") || output.contains("PIN armed for another 8h00m"),
            "{output}"
        );
        fs::remove_file(sandbox.places.etc.join("users/alice")).unwrap();
        assert!(sandbox.ask(Request::Status, "").1.contains("none set"));
    }

    /// Guesses nobody forgives, a wrong password included, are judged later, logged, and disable
    /// the PIN; the password then no longer arms it.
    #[test]
    fn concerning_failures_are_logged_and_disable_the_pin() {
        let sandbox = sandbox();
        let alice = &sandbox.caller;
        sandbox.ask(Request::Arm, PASSWORD);
        for wrong in ["1111", "2222", "not the password at all"] {
            sandbox.ask(Request::Check, wrong);
        }
        // Two minutes on, the correct PIN comes too late to forgive them.
        let (code, _, log) = sandbox.ask_with(&Later { ahead: 120 }, alice, Request::Check, PIN);
        assert_eq!(code, exit::YES);
        assert!(log.contains("3 failure(s) not followed by an unlock in time, now concerning: 3 within 24 hours"), "{log}");
        let output = sandbox.ask_with(&Later { ahead: 120 }, alice, Request::Status, "").1;
        assert!(
            output.contains("concerning failures: 3 within 24 hours (of 10), 3 within 7 days (of 20), 3 since the PIN was set (of 100)"),
            "{output}"
        );

        sandbox.write_config("max_concerning_24h = 4\n");
        sandbox.ask_with(&Later { ahead: 120 }, alice, Request::Check, "3333");
        let (code, _, log) = sandbox.ask_with(&Later { ahead: 300 }, alice, Request::Check, PIN);
        assert_eq!(code, exit::NO);
        assert!(log.contains("PIN disabled after 4 concerning failures within 24 hours"), "{log}");
        assert!(log.contains("PIN refused, password required: the PIN is disabled after 4 concerning failures"), "{log}");
        let (code, _, log) = sandbox.ask_with(&Later { ahead: 300 }, alice, Request::Arm, PASSWORD);
        assert_eq!((code, log.contains("password accepted, PIN not armed: disabled after")), (exit::NO, true), "{log}");
        let output = sandbox.ask_with(&Later { ahead: 300 }, alice, Request::Status, "").1;
        assert!(output.contains("sudo properpin enable or set turns it back on"), "{output}");
    }

    #[test]
    fn typos_followed_by_the_pin_or_the_password_are_forgiven() {
        let sandbox = sandbox();
        sandbox.ask(Request::Arm, PASSWORD);
        sandbox.ask(Request::Check, "1111");
        sandbox.ask(Request::Check, PIN);
        sandbox.ask(Request::Check, "correct horse battery stapl");
        sandbox.ask(Request::Check, PASSWORD);
        sandbox.ask(Request::Arm, PASSWORD);
        let output = sandbox.ask_with(&Later { ahead: 3600 }, &sandbox.caller, Request::Status, "").1;
        assert!(output.contains("0 since the PIN was set (of 100); 0 waiting to be forgiven"), "{output}");
    }

    #[test]
    fn a_damaged_budget_refuses_the_pin() {
        let sandbox = sandbox();
        sandbox.ask(Request::Arm, PASSWORD);
        let budget = sandbox.places.budget_dir.join(format!("{}.budget", sandbox.caller.uid));
        fs::write(&budget, "garbage\n").unwrap();
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
        assert_eq!(properpin_core::usable_input(typed.as_bytes()), None);
    }

    #[test]
    fn requests_are_exact_words() {
        assert_eq!(Request::parse("check"), Some(Request::Check));
        for word in ["Check", "check ", "", "--check", "set"] {
            assert_eq!(Request::parse(word), None, "{word:?}");
        }
    }
}
