//! The lock-screen stack, through the real libpam and the real `pam_screenlock_pin.so`.
//!
//! The PAM files come from a temporary directory (`pam_start_confdir`). The stack is `kde` as
//! `integrate-into-pam.sh add` leaves Fedora's, `auth substack screenlock-auth` and then `auth
//! include postlogin`, and the shipped `packaging/screenlock-auth.pam` with only two things swapped:
//! the module path points at the freshly built `.so`, given `pin_checker=` with a script that runs
//! the freshly built `screenlock-pin-checker` against the sandbox (through its `--dev-*` options,
//! which it accepts here because it isn't setgid), and the stock `password-auth` substack becomes one
//! of two stand-ins, `pam_permit` (the password was right) or `pam_deny` (it was wrong). The control
//! columns are the shipped ones.
//!
//! Attempts run the way kscreenlocker runs them: one PAM session kept for many attempts, with
//! `pam_setcred` after a success. The hosts below then misbehave the ways real PAM hosts do with
//! SIGCHLD, each in a process of its own, since SIGCHLD is one setting for the whole process
//! (docs/chaos/harness-closer-to-kscreenlocker.md).
//!
//! What this can't show: how the real pam_unix, the real setgid PIN checker and the real greeter
//! behave. The container test covers the first two.

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use pamharness::host::{self, Sigchld};
use pamharness::{Attempt, PamClient, PamSession};
use screenlock_pin_core::Budget;
use screenlock_pin_sys::{Account, AllUsers, Yescrypt, current_egid, current_uid};

const PIN: &str = "4859";
const PASSWORD: &str = "correct horse battery staple";
const SHIPPED: &str = include_str!("../../../packaging/screenlock-auth.pam");
/// Set in the environment of a test binary started again for one test alone; names that test.
const ALONE: &str = "SCREENLOCK_PIN_STACK_TEST_ALONE";

#[derive(Clone, Copy)]
enum Password {
    Right,
    Wrong,
}

struct Sandbox {
    dir: tempfile::TempDir,
    user: String,
}

impl Sandbox {
    /// A sandboxed `/etc/screenlock-pin` with a PIN set for the current user, an empty budget dir, a
    /// PIN checker that uses them, and a PAM config dir.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let user = Account::by_uid(current_uid()).unwrap().name;
        let sandbox = Self { dir, user };
        fs::create_dir(sandbox.path("var")).unwrap();
        // Set explicitly: the umask would strip the group's write bit from a mkdir mode.
        fs::set_permissions(sandbox.path("var"), Permissions::from_mode(0o1770)).unwrap();
        fs::create_dir_all(sandbox.path("etc/users")).unwrap();
        fs::create_dir_all(sandbox.path("pam.d")).unwrap();
        // libpam logs to the journal when a confdir has no "other" fallback service.
        fs::write(sandbox.path("pam.d/other"), "auth required pam_deny.so\n").unwrap();
        // The stock password-auth, which screenlock-auth goes on to, as each test needs it.
        fs::write(sandbox.path("pam.d/password-auth-right"), "auth required pam_permit.so\n").unwrap();
        fs::write(sandbox.path("pam.d/password-auth-wrong"), "auth required pam_deny.so\n").unwrap();
        // Fedora's postlogin has no auth lines.
        fs::write(sandbox.path("pam.d/postlogin"), "").unwrap();
        let user_file = sandbox.path("etc/users").join(&sandbox.user);
        fs::write(&user_file, format!("hash = {}\n", Yescrypt.hash(PIN, 4).unwrap())).unwrap();
        fs::set_permissions(&user_file, Permissions::from_mode(0o640)).unwrap();
        // The budget and lock file screenlock-pin set creates.
        let uid = current_uid();
        let all = AllUsers::new(sandbox.path("etc"), uid, sandbox.path("var"), uid, current_egid());
        all.user(&sandbox.user, uid).unwrap().start_budget(&Budget::default()).unwrap();
        sandbox.pin_checker("");
        // The two services sessions use, written once, so threads can open sessions at will.
        sandbox.stack_as("kde-right", Password::Right, "");
        sandbox.stack_as("kde-wrong", Password::Wrong, "");
        sandbox
    }

    /// The PIN checker: a script that runs `first` and then the built PIN checker against the sandbox.
    fn pin_checker(&self, first: &str) {
        let pin_checker = format!(
            "#!/bin/sh\n{first}\nexec {} \"$@\" --dev-etc {} --dev-budget {} --dev-log {}\n",
            built().join("screenlock-pin-checker").display(),
            self.path("etc").display(),
            self.path("var").display(),
            self.path("log").display()
        );
        self.script("pin-checker", &pin_checker);
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }

    fn script(&self, name: &str, text: &str) {
        fs::write(self.path(name), text).unwrap();
        fs::set_permissions(self.path(name), Permissions::from_mode(0o755)).unwrap();
    }

    fn log(&self) -> String {
        fs::read_to_string(self.path("log")).unwrap_or_default()
    }

    /// What was logged since `before`, the length of the log then.
    fn log_since(&self, before: usize) -> String {
        self.log().get(before..).unwrap_or_default().to_owned()
    }

    /// Write the `kde` service: the shipped lines, sandboxed, with `extra` added to both module lines.
    fn stack(&self, password: Password, extra: &str) {
        self.stack_as("kde", password, extra);
    }

    /// `service`, as `kde`, and the shipped `screenlock-auth` it names under a name of its own, so
    /// each service can have its own stand-in and module arguments.
    fn stack_as(&self, service: &str, password: Password, extra: &str) {
        let module = format!(
            "{} pin_checker={} log={} {extra} ",
            built().join("libpam_screenlock_pin.so").display(),
            self.path("pin-checker").display(),
            self.path("log").display()
        );
        let substack = match password {
            Password::Right => " password-auth-right\n",
            Password::Wrong => " password-auth-wrong\n",
        };
        let mut text: String = SHIPPED.lines().filter(|line| !line.starts_with('#')).map(|line| format!("{line}\n")).collect();
        for (old, new) in [("/usr/local/lib64/security/pam_screenlock_pin.so ", module.as_str()), (" password-auth\n", substack)] {
            // Fail loudly if the shipped file changes shape, rather than test something else.
            assert!(text.contains(old), "{old:?} is no longer in packaging/screenlock-auth.pam");
            text = text.replace(old, new);
        }
        let auth = format!("{service}.screenlock-auth");
        fs::write(self.path("pam.d").join(&auth), text).unwrap();
        let kde = format!("auth        substack      {auth}\nauth        include       postlogin\n");
        fs::write(self.path("pam.d").join(service), kde).unwrap();
    }

    /// A session on the shipped stack, for as many attempts as the test makes: the password stand-in
    /// either accepts everything or refuses everything, so a test keeps one of each.
    fn session(&self, password: Password) -> PamSession {
        self.session_of(match password {
            Password::Right => "kde-right",
            Password::Wrong => "kde-wrong",
        })
    }

    fn session_of(&self, service: &str) -> PamSession {
        PamClient::new(self.path("pam.d"), service, &self.user).session()
    }

    fn attempt(&self, password: Password, typed: &str) -> Attempt {
        self.stack(password, "");
        let attempt = PamClient::new(self.path("pam.d"), "kde", &self.user).authenticate(typed);
        // One field, one prompt: no input ever triggers a second question.
        assert_eq!(attempt.prompts.len(), 1, "{attempt:?}");
        attempt
    }

    /// Unlock with the password, which unpauses the PIN.
    fn unlock_with_password(&self) {
        assert!(self.attempt(Password::Right, PASSWORD).unlocked());
    }
}

/// The directory with a fresh `pam_screenlock_pin.so` and `screenlock-pin-checker`. `cargo test` rebuilds this
/// crate's rlib for the tests but not its cdylib, so build both here, once per test run, or the
/// tests would load a stale module.
fn built() -> PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let profile_dir = std::env::current_exe().unwrap().parent().and_then(Path::parent).unwrap().to_path_buf();
            let mut cargo = std::process::Command::new(env!("CARGO"));
            cargo.args([
                "build",
                "--quiet",
                "--package",
                "pam_screenlock_pin",
                "--package",
                "screenlock-pin-checker",
                "--manifest-path",
                concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            ]);
            if profile_dir.ends_with("release") {
                cargo.arg("--release");
            }
            assert!(cargo.status().unwrap().success(), "building pam_screenlock_pin and screenlock-pin-checker failed");
            profile_dir
        })
        .clone()
}

#[test]
fn the_pin_unlocks_from_the_start() {
    let sandbox = Sandbox::new();
    // pam_deny stands for any password: only the PIN can unlock.
    assert!(sandbox.attempt(Password::Wrong, PIN).unlocked());
    assert!(sandbox.log().contains("unlocked with the PIN"));
}

#[test]
fn the_password_unlocks_and_unpauses_the_pin() {
    let sandbox = Sandbox::new();
    sandbox.unlock_with_password();
    // The password is checked as a PIN first, whatever its length, and unpausing the PIN forgives it.
    assert!(sandbox.log().contains("not the PIN, consecutive failure 1 of 3"), "{}", sandbox.log());
    assert!(sandbox.log().contains("unlocked with the password, PIN enabled"), "{}", sandbox.log());
}

#[test]
fn a_wrong_password_never_unpauses_the_pin() {
    let sandbox = Sandbox::new();
    for wrong in ["1111", "2222", "3333"] {
        assert!(!sandbox.attempt(Password::Wrong, wrong).unlocked());
    }
    assert!(!sandbox.attempt(Password::Wrong, "a wrong password, long enough").unlocked());
    // A failed stack gets no pam_setcred, so the PIN is never unpaused, and nothing is logged.
    assert!(
        !sandbox.log().contains("unlocked with the password") && !sandbox.log().contains("unpausing the PIN failed"),
        "{}",
        sandbox.log()
    );
    assert!(!sandbox.attempt(Password::Wrong, PIN).unlocked());
    // The positive control: the right password logs what the wrong ones mustn't, found by the same matcher.
    sandbox.unlock_with_password();
    assert!(sandbox.log().contains("unlocked with the password"), "{}", sandbox.log());
}

const UNPAUSED: &str = "unlocked with the password, PIN enabled";

/// libpam calls the `after-password-auth` line's `pam_sm_setcred` after a password unlock only:
/// the replay of a PIN unlock ends `screenlock-auth` at the `check` line, which answers `PAM_SUCCESS`
/// for that, and a failed attempt gets no `pam_setcred` at all.
#[test]
fn setcred_reaches_the_after_password_auth_line_after_a_password_unlock_only() {
    let sandbox = Sandbox::new();
    let mut password = sandbox.session(Password::Right);
    let mut pin = sandbox.session(Password::Wrong);
    for (right, typed, unlocks, reaches) in
        [(false, PIN, true, false), (false, "1111", false, false), (true, PASSWORD, true, true), (true, PIN, true, false)]
    {
        let before = sandbox.log().len();
        let attempt = if right { password.authenticate(typed) } else { pin.authenticate(typed) };
        let said = sandbox.log_since(before);
        assert_eq!(attempt.unlocked(), unlocks, "{typed}: {said}");
        assert_eq!(said.contains(UNPAUSED), reaches, "{typed}: {said}");
    }
}

/// A correct PIN ends `screenlock-auth` alone, so `kde` goes on to `postlogin`, as after the
/// password. A line there finds no typed password after a correct PIN and has to ask, as after a
/// fingerprint unlock; after any other input it finds what was typed. `pam_exec expose_authtok`
/// stands for a module that keeps the password, and asks when there is none: that it asks shows
/// that it ran.
#[test]
fn postlogin_follows_a_correct_pin_and_finds_no_pin() {
    let sandbox = Sandbox::new();
    sandbox.script("reader", "#!/bin/sh\ncat >/dev/null\n");
    let reader = format!("auth required pam_exec.so quiet expose_authtok {}\n", sandbox.path("reader").display());
    fs::write(sandbox.path("pam.d/postlogin"), reader).unwrap();
    let client = PamClient::new(sandbox.path("pam.d"), "kde-right", &sandbox.user);
    for (typed, prompts) in [("1111", 1), (PIN, 2)] {
        let attempt = client.authenticate(typed);
        assert!(attempt.unlocked(), "{typed}: {attempt:?} {}", sandbox.log());
        assert_eq!(attempt.prompts.len(), prompts, "{typed}: {attempt:?}");
    }
    assert!(sandbox.log().contains("unlocked with the PIN"), "{}", sandbox.log());
}

#[test]
fn wrong_pins_fall_through_and_three_require_the_password() {
    let sandbox = Sandbox::new();
    for wrong in ["1111", "2222", "3333"] {
        assert!(!sandbox.attempt(Password::Wrong, wrong).unlocked());
    }
    assert!(sandbox.log().contains("consecutive failure 3 of 3; PIN paused, password required"), "{}", sandbox.log());
    assert!(!sandbox.attempt(Password::Wrong, PIN).unlocked());
    sandbox.unlock_with_password();
    assert!(sandbox.attempt(Password::Wrong, PIN).unlocked());
}

#[test]
fn the_pin_only_works_for_the_user_the_lock_screen_runs_as() {
    let sandbox = Sandbox::new();
    sandbox.stack(Password::Wrong, "");
    let attempt = PamClient::new(sandbox.path("pam.d"), "kde", "nobody").authenticate(PIN);
    assert!(!attempt.unlocked());
    assert!(sandbox.log().contains("PAM is authenticating \"nobody\""), "{}", sandbox.log());
}

/// A line the module can't read refuses the PIN alone. The module still asks for the input, once,
/// so lines after it that only read it, as `pam_unix.so use_first_pass` does, still find it.
#[test]
fn a_bad_pam_line_refuses_instead_of_guessing() {
    let sandbox = Sandbox::new();
    sandbox.stack(Password::Wrong, "no_such_option");
    assert!(!PamClient::new(sandbox.path("pam.d"), "kde", &sandbox.user).authenticate(PIN).unlocked());
    assert!(sandbox.log().contains("bad PAM line: unknown argument \"no_such_option\""), "{}", sandbox.log());
    sandbox.stack(Password::Right, "config=/etc/screenlock-pin/config");
    let attempt = PamClient::new(sandbox.path("pam.d"), "kde", &sandbox.user).authenticate(PASSWORD);
    assert!(attempt.unlocked() && attempt.prompts.len() == 1, "the module asks, once, even on a bad line: {attempt:?}");
    assert!(sandbox.log().contains("bad PAM line: unknown argument \"config=/etc/screenlock-pin/config\""), "{}", sandbox.log());
}

/// libpam loads and unloads the module on every transaction. Rust `.so`s have crashed on unload
/// (rust-lang/rust#91979), so run many transactions from threads that then exit.
#[test]
fn survives_many_loads_and_unloads_across_threads() {
    let sandbox = Sandbox::new();
    sandbox.stack(Password::Wrong, "");
    let client = PamClient::new(sandbox.path("pam.d"), "kde", &sandbox.user);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..25 {
                    assert!(client.authenticate(PIN).unlocked());
                }
            });
        }
    });
}

/// Whatever goes wrong with the PIN checker, the PIN is refused and the password still works.
#[test]
fn a_broken_pin_checker_fails_closed() {
    for (name, pin_checker) in [
        ("missing", None),
        ("exits with an odd code", Some("#!/bin/sh\nexit 3\n")),
        ("killed by a signal", Some("#!/bin/sh\nkill -9 $$\n")),
        ("quits without reading", Some("#!/bin/sh\nexit 0\n")),
    ] {
        let sandbox = Sandbox::new();
        match pin_checker {
            None => fs::remove_file(sandbox.path("pin-checker")).unwrap(),
            Some(text) => sandbox.script("pin-checker", text),
        }
        // "quits without reading" exits 0, a yes: the module trusts the PIN checker's answer, so that
        // one unlocks. The point there is that writing to it raises no SIGPIPE in the host.
        let unlocked = sandbox.attempt(Password::Wrong, PIN).unlocked();
        assert_eq!(unlocked, name == "quits without reading", "{name}: {}", sandbox.log());
        if name != "quits without reading" {
            assert!(sandbox.log().contains("PIN refused:"), "{name}: {}", sandbox.log());
        }
        assert!(sandbox.attempt(Password::Right, PASSWORD).unlocked(), "{name}: the password must still work");
    }
}

/// kscreenlocker keeps one PAM session for the greeter's whole life (6.7.5) or the worker's (6.8).
/// Every attempt asks for the input again, since libpam clears it after each one, and the counts
/// carry on across attempts on the same session.
#[test]
fn one_session_serves_many_attempts() {
    let sandbox = Sandbox::new();
    let mut password = sandbox.session(Password::Right);
    let mut pin = sandbox.session(Password::Wrong);
    let unlocked = password.authenticate(PASSWORD);
    assert!(unlocked.unlocked() && unlocked.setcred.is_some(), "{unlocked:?}");
    for (typed, unlocks) in [(PIN, true), ("1111", false), (PIN, true), ("1111", false), ("2222", false), ("3333", false), (PIN, false)] {
        let attempt = pin.authenticate(typed);
        assert_eq!(attempt.unlocked(), unlocks, "{typed}: {attempt:?}\n{}", sandbox.log());
        assert_eq!(attempt.prompts.len(), 1, "asked once, every time: {attempt:?}");
        assert_eq!(attempt.setcred.is_some(), unlocks, "pam_setcred after a success only");
    }
    assert!(sandbox.log().contains("consecutive failure 3 of 3; PIN paused, password required"), "{}", sandbox.log());
    assert!(password.authenticate(PASSWORD).unlocked());
    assert!(pin.authenticate(PIN).unlocked(), "the PIN's session works again once the password unpaused it");
    // The PIN on the session whose password would pass: the check line ends screenlock-auth first.
    assert!(password.authenticate(PIN).unlocked());
    assert!(sandbox.log().contains("unlocked with the PIN"));
}

/// A correct PIN never unlocks sooner than the config's minimum, counted from when the PIN checker
/// starts, 75 ms by default; a wrong PIN and the password go on at once. The stand-ins for the
/// stock stack and its failure delay take no time, so whatever waits here is the PIN checker.
#[test]
fn only_a_correct_pin_waits_out_the_minimum() {
    let sandbox = Sandbox::new();
    let timed = |password, typed| {
        let started = Instant::now();
        let unlocked = sandbox.attempt(password, typed).unlocked();
        (unlocked, started.elapsed())
    };
    let (unlocked, took) = timed(Password::Wrong, PIN);
    assert!(unlocked && took >= Duration::from_millis(75), "the default minimum: {took:?}");
    let config = sandbox.path("etc/config");
    fs::write(&config, "min_milliseconds_before_pin_unlock = 1000\n").unwrap();
    fs::set_permissions(&config, Permissions::from_mode(0o644)).unwrap();
    let (unlocked, took) = timed(Password::Wrong, PIN);
    assert!(unlocked && took >= Duration::from_secs(1), "the configured minimum: {took:?}");
    // A busy machine, such as one running the other tests, can slow down one attempt past the
    // minimum, but hardly all of three.
    for (password, typed, unlocks) in [(Password::Wrong, "1111", false), (Password::Right, PASSWORD, true)] {
        let fastest = (0..3)
            .map(|_| {
                let (unlocked, took) = timed(password, typed);
                assert_eq!(unlocked, unlocks, "{typed}: {}", sandbox.log());
                took
            })
            .min()
            .unwrap();
        assert!(fastest < Duration::from_secs(1), "{typed} took {fastest:?} at the fastest");
    }
}

/// Tests that change SIGCHLD change it for every test running in the same process, so each starts
/// the test binary again with only itself selected and a variable saying so. Returns `None` in that
/// process of its own, where the test then runs; returns what it printed in the first process,
/// after checking it passed.
fn in_own_process(test: &str) -> Option<String> {
    if std::env::var(ALONE).is_ok_and(|name| name == test) {
        return None;
    }
    built();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads", "1"])
        .env(ALONE, test)
        .output()
        .unwrap();
    let said = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success() && said.contains("1 passed"), "{test}, in a process of its own:\n{said}");
    Some(said)
}

/// What every host must still get: the password unlocks and unpauses the PIN, the PIN unlocks and a wrong one doesn't.
fn the_usual_answers(sandbox: &Sandbox) {
    let mut password = sandbox.session(Password::Right);
    let mut pin = sandbox.session(Password::Wrong);
    assert!(password.authenticate(PASSWORD).unlocked());
    assert!(sandbox.log().contains("unlocked with the password, PIN enabled"), "{}", sandbox.log());
    assert!(pin.authenticate(PIN).unlocked(), "{}", sandbox.log());
    assert!(!pin.authenticate("1111").unlocked());
    assert!(pin.authenticate(PIN).unlocked(), "{}", sandbox.log());
}

/// With SIGCHLD ignored, the kernel would reap the PIN checker and throw its answer away; the module
/// sets the default while the PIN checker runs, and puts "ignore" back.
#[test]
fn a_host_that_ignores_sigchld_still_gets_answers() {
    if in_own_process("a_host_that_ignores_sigchld_still_gets_answers").is_some() {
        return;
    }
    let sandbox = Sandbox::new();
    host::ignore_sigchld();
    the_usual_answers(&sandbox);
    assert_eq!(host::sigchld(), Sigchld::Ignore);
}

/// A handler that reaps every child can't run while the module has SIGCHLD at its default, so it
/// never takes the PIN checker, and it is back afterwards.
#[test]
fn a_host_that_reaps_every_child_still_gets_answers() {
    if in_own_process("a_host_that_reaps_every_child_still_gets_answers").is_some() {
        return;
    }
    let sandbox = Sandbox::new();
    let handler = host::reap_on_sigchld();
    the_usual_answers(&sandbox);
    assert_eq!(host::sigchld(), handler);
    assert_eq!(host::reaped(), 0, "the host's handler reaped a PIN checker");
}

/// A host thread looping on `waitpid(-1)` takes the PIN checker's exit status whatever SIGCHLD is set
/// to. The module then has no answer and refuses: the PIN may fail, a wrong PIN never unlocks, and
/// the password still works. A known limit, documented here rather than fixed.
#[test]
fn a_host_thread_that_reaps_every_child_fails_closed() {
    if in_own_process("a_host_thread_that_reaps_every_child_fails_closed").is_some() {
        return;
    }
    let sandbox = Sandbox::new();
    let mut password = sandbox.session(Password::Right);
    assert!(password.authenticate(PASSWORD).unlocked());
    let (stop, stolen) = (AtomicBool::new(false), AtomicUsize::new(0));
    let mut refused = 0;
    thread::scope(|scope| {
        scope.spawn(|| {
            while !stop.load(Ordering::SeqCst) {
                match host::reap_any_child() {
                    Some(_) => {
                        stolen.fetch_add(1, Ordering::SeqCst);
                    }
                    None => thread::sleep(Duration::from_micros(100)),
                }
            }
        });
        let mut pin = sandbox.session(Password::Wrong);
        for _ in 0..5 {
            refused += usize::from(!pin.authenticate(PIN).unlocked());
            assert!(!pin.authenticate("1111").unlocked(), "a wrong PIN unlocked");
        }
        assert!(password.authenticate(PASSWORD).unlocked(), "the password must still work");
        stop.store(true, Ordering::SeqCst);
    });
    if refused > 0 {
        assert!(sandbox.log().contains("PIN refused:") && sandbox.log().contains("wait"), "{}", sandbox.log());
    }
    println!("the host thread took {} exit statuses; {refused} of 5 correct PINs were refused", stolen.load(Ordering::SeqCst));
}

/// While the module has SIGCHLD at its default, a child of the host's own can exit without the
/// host's handler hearing of it. The host must still be able to collect its exit status, and its
/// handler must be back and hearing of children afterwards.
#[test]
fn the_hosts_own_children_survive_an_attempt() {
    if in_own_process("the_hosts_own_children_survive_an_attempt").is_some() {
        return;
    }
    let sandbox = Sandbox::new();
    let handler = host::notice_sigchld();
    assert!(sandbox.session(Password::Right).authenticate(PASSWORD).unlocked());
    // The PIN checker starts late, so the host's child exits while the module is waiting for it.
    sandbox.pin_checker("sleep 0.3");
    let mut own = Command::new("sh").args(["-c", "sleep 0.1; exit 7"]).spawn().unwrap();
    assert!(sandbox.session(Password::Wrong).authenticate(PIN).unlocked(), "{}", sandbox.log());
    assert_eq!(own.wait().unwrap().code(), Some(7), "the host lost its own child's exit status");
    assert_eq!(host::sigchld(), handler);
    let before = host::noticed();
    Command::new("true").status().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while host::noticed() == before {
        assert!(Instant::now() < deadline, "the host's handler no longer hears of its children");
        thread::sleep(Duration::from_millis(1));
    }
}

/// Attempts on several threads at once, each on its own session, as kscreenlocker 6.7.5 runs its
/// authenticators, while the host has a SIGCHLD handler: every answer right, and the handler
/// still there at the end.
#[test]
fn attempts_on_several_threads_keep_the_hosts_handler() {
    if in_own_process("attempts_on_several_threads_keep_the_hosts_handler").is_some() {
        return;
    }
    let sandbox = Sandbox::new();
    let handler = host::notice_sigchld();
    assert!(sandbox.session(Password::Right).authenticate(PASSWORD).unlocked());
    thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                let mut pin = sandbox.session(Password::Wrong);
                for _ in 0..10 {
                    assert!(pin.authenticate(PIN).unlocked(), "{}", sandbox.log());
                }
            });
        }
    });
    assert_eq!(host::sigchld(), handler, "the host's SIGCHLD handler was lost");
}

/// A panic while the module has SIGCHLD changed: PAM_IGNORE, the host's handler back, and the
/// password still works.
#[test]
fn a_panic_puts_sigchld_back_and_the_password_still_works() {
    if let Some(said) = in_own_process("a_panic_puts_sigchld_back_and_the_password_still_works") {
        assert!(said.contains("test_panic: a panic must become PAM_IGNORE and put SIGCHLD back"), "it never panicked:\n{said}");
        return;
    }
    let sandbox = Sandbox::new();
    sandbox.stack_as("panic-right", Password::Right, "test_panic");
    sandbox.stack_as("panic-wrong", Password::Wrong, "test_panic");
    let handler = host::notice_sigchld();
    assert!(sandbox.session_of("panic-right").authenticate(PASSWORD).unlocked());
    assert!(!sandbox.session_of("panic-wrong").authenticate(PIN).unlocked());
    assert_eq!(host::sigchld(), handler, "the panic left SIGCHLD changed");
}
