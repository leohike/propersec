//! `properpin-helper`: the only program that reads PIN hashes and keeps the failure counts.
//!
//! It is installed setuid to the `properpin` account, like `unix_chkpwd` is setuid to root, so the
//! hash files and the counts can belong to that account and stay out of reach of everything the
//! user runs. The PAM module and the CLI start it, write what was typed to its stdin, and read its
//! exit code (`properpin_core::exit`); only `status` prints anything.
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
//! the helper was started without elevated rights, and then it has no more rights than its caller.
//!
//! This library is the decision part, with every location and outside check passed in, so the tests
//! drive it directly with temporary directories. `main.rs` is the setuid part: a clean start, the
//! fixed locations, and the real caller.

#![forbid(unsafe_code)]

use std::io::Read;
use std::path::PathBuf;

use properpin_core::{Clock, Error, Hasher, Log, MAX_INPUT_BYTES, Secret, Store, arm, check, describe_seconds, exit, usable_input};
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
    /// Who must own `run_dir`: the account the helper runs as.
    pub run_owner: u32,
}

impl Places {
    fn files(&self, caller: &Account) -> Result<UserFiles, Error> {
        Ok(UserFiles::new(&self.etc, self.etc_owner, &caller.name, caller.uid)?.with_runtime(&self.run_dir, self.run_owner))
    }
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
    let verdict = check(files, context.hasher, context.clock, usable_input(typed.as_bytes()))?;
    context.log.log(&format!("{}: {verdict}", caller.name));
    Ok(Reply::code(if verdict.unlocks() { exit::YES } else { exit::NO }))
}

/// Arm the PIN, but only for the right password: `arm` is open to everything the user runs, so
/// without this check any program could arm the PIN at will and reset the failures as often as it
/// liked. `unix_chkpwd` checks it, as pam_unix just did.
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
    arm(files, context.clock)?;
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
    let state = files.load_state();
    let now = clock.now()?;
    match (settings.refusal(state.as_ref(), &clock.boot_id()?, now), state) {
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
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    use properpin_sys::{BootClock, Yescrypt, current_uid};

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
        let places = Places { etc: dir.path().join("etc"), etc_owner: uid, run_dir: dir.path().join("run"), run_owner: uid };
        fs::DirBuilder::new().mode(0o700).create(&places.run_dir).unwrap();
        fs::set_permissions(&places.run_dir, Permissions::from_mode(0o700)).unwrap();
        let caller = Account { name: "alice".into(), uid: 4242, gid: 4242 };
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
            let log = Lines::default();
            let context = Context { places: &self.places, hasher: &Yescrypt, clock: &BootClock, password: &Password, log: &log };
            let reply = serve(request, caller, &Secret::new(typed.as_bytes().to_vec()), &context);
            (reply.code, reply.output, log.0.into_inner().join("\n"))
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
        let bob = Account { name: "bob".into(), uid: 4343, gid: 4343 };
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
        assert!(log.contains("not a private directory"), "{log}");
    }

    #[test]
    fn a_bad_user_name_is_refused_before_any_file() {
        let sandbox = sandbox();
        let sneaky = Account { name: "../alice".into(), uid: 4242, gid: 4242 };
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

    #[test]
    fn input_is_read_up_to_the_limit_only() {
        let typed = read_input(&mut &b"4859"[..]).unwrap();
        assert_eq!(typed.as_bytes(), b"4859");
        let long = vec![b'1'; MAX_INPUT_BYTES * 3];
        let typed = read_input(&mut &long[..]).unwrap();
        assert_eq!(typed.as_bytes().len(), MAX_INPUT_BYTES + 1);
        assert_eq!(usable_input(typed.as_bytes()), None);
    }

    #[test]
    fn requests_are_exact_words() {
        assert_eq!(Request::parse("check"), Some(Request::Check));
        for word in ["Check", "check ", "", "--check", "set"] {
            assert_eq!(Request::parse(word), None, "{word:?}");
        }
    }
}
