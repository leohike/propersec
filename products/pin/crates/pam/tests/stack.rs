//! The lock-screen stack, through the real libpam and the real `pam_properpin.so`.
//!
//! The PAM files come from a temporary directory (`pam_start_confdir`). The stack is the shipped
//! `pam/kde-auth.pam` with only three things swapped: the module path points at the freshly built
//! `.so`, the pinchecker path at a script that runs the freshly built `properpin-pinchecker` against the
//! sandbox (through its `--dev-*` options, which it accepts here because it isn't setgid), and
//! `pam_unix` becomes `pam_permit` (the password was right) or `pam_deny` (it was wrong). The
//! control columns are the shipped ones.
//!
//! Attempts run the way kscreenlocker runs them: one PAM session kept for many attempts, with
//! `pam_setcred` after a success. The hosts below then misbehave the ways real PAM hosts do with
//! SIGCHLD, each in a process of its own, since SIGCHLD is one setting for the whole process
//! (docs/harness-closer-to-kscreenlocker.md).
//!
//! What this can't show: how the real pam_unix, the real setgid pinchecker and the real greeter
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
use properpin_core::Budget;
use properpin_sys::{Account, UserFiles, Yescrypt, current_egid, current_uid};

const PIN: &str = "4859";
const PASSWORD: &str = "correct horse battery staple";
const SHIPPED: &str = include_str!("../../../pam/kde-auth.pam");
/// Set in the environment of a test binary started again for one test alone; names that test.
const ALONE: &str = "PROPERPIN_STACK_TEST_ALONE";

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
    /// A sandboxed `/etc/properpin` with a PIN set for the current user, an empty budget dir, a
    /// pinchecker that uses them, a stand-in for `unix_chkpwd`, and a PAM config dir.
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
        let user_file = sandbox.path("etc/users").join(&sandbox.user);
        fs::write(&user_file, format!("hash = {}\n", Yescrypt.hash(PIN, 4).unwrap())).unwrap();
        fs::set_permissions(&user_file, Permissions::from_mode(0o640)).unwrap();
        // The budget and lock file properpin set creates.
        let uid = current_uid();
        let files = UserFiles::new(sandbox.path("etc"), uid, &sandbox.user, uid).unwrap();
        files.with_budget(sandbox.path("var"), uid, current_egid()).start_budget(&Budget::default()).unwrap();
        // unix_chkpwd's protocol: the password on stdin, ending in a NUL; exit 0 for a match.
        let chkpwd = format!("#!/bin/bash\nIFS= read -r -d '' password\n[[ $1 == \"$(id -un)\" && $password == '{PASSWORD}' ]]\n");
        sandbox.script("unix_chkpwd", &chkpwd);
        sandbox.pinchecker("");
        // The two services sessions use, written once, so threads can open sessions at will.
        sandbox.stack_as("kde-right", Password::Right, "");
        sandbox.stack_as("kde-wrong", Password::Wrong, "");
        sandbox
    }

    /// The pinchecker: a script that runs `first` and then the built pinchecker against the sandbox.
    fn pinchecker(&self, first: &str) {
        let pinchecker = format!(
            "#!/bin/sh\n{first}\nexec {} \"$@\" --dev-etc {} --dev-budget {} --dev-chkpwd {} --dev-log {}\n",
            built().join("properpin-pinchecker").display(),
            self.path("etc").display(),
            self.path("var").display(),
            self.path("unix_chkpwd").display(),
            self.path("log").display()
        );
        self.script("pinchecker", &pinchecker);
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

    /// Write the `kde` service: the shipped lines, sandboxed, with `extra` added to both module lines.
    fn stack(&self, password: Password, extra: &str) {
        self.stack_as("kde", password, extra);
    }

    fn stack_as(&self, service: &str, password: Password, extra: &str) {
        let module = format!("{} {extra}", built().join("libpam_properpin.so").display());
        let pinchecker = format!("pinchecker={} log={}", self.path("pinchecker").display(), self.path("log").display());
        let config = format!("config={}", self.path("etc/config").display());
        let unix = match password {
            Password::Right => "pam_permit.so",
            Password::Wrong => "pam_deny.so",
        };
        let mut text = SHIPPED.to_owned();
        for (old, new) in [
            ("/usr/local/lib64/security/pam_properpin.so", module.as_str()),
            ("pinchecker=/usr/local/libexec/properpin/properpin-pinchecker", pinchecker.as_str()),
            ("config=/etc/properpin/config", config.as_str()),
            ("pam_unix.so use_first_pass", unix),
        ] {
            // Fail loudly if the shipped file changes shape, rather than test something else.
            assert!(text.contains(old), "{old:?} is no longer in pam/kde-auth.pam");
            text = text.replace(old, new);
        }
        fs::write(self.path("pam.d").join(service), text).unwrap();
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

/// The directory with a fresh `pam_properpin.so` and `properpin-pinchecker`. `cargo test` rebuilds this
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
                "pam_properpin",
                "--package",
                "properpin-pinchecker",
                "--manifest-path",
                concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            ]);
            if profile_dir.ends_with("release") {
                cargo.arg("--release");
            }
            assert!(cargo.status().unwrap().success(), "building pam_properpin and properpin-pinchecker failed");
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
fn the_password_unlocks_and_does_the_housekeeping() {
    let sandbox = Sandbox::new();
    sandbox.unlock_with_password();
    // The password is checked as a PIN first, whatever its length, and the housekeeping forgives it.
    assert!(sandbox.log().contains("not the PIN, consecutive failure 1 of 3"), "{}", sandbox.log());
    assert!(sandbox.log().contains("password correct, PIN enabled"), "{}", sandbox.log());
}

#[test]
fn a_wrong_password_never_unpauses_the_pin() {
    let sandbox = Sandbox::new();
    for wrong in ["1111", "2222", "3333"] {
        assert!(!sandbox.attempt(Password::Wrong, wrong).unlocked());
    }
    assert!(!sandbox.attempt(Password::Wrong, "a wrong password, long enough").unlocked());
    // The stack stops at the password line, so the housekeeping never even hears of it: neither
    // of its answers is logged, nor its failure.
    let housekeeping = ["password correct", "wrong password, nothing changed", "housekeeping failed"];
    for line in housekeeping {
        assert!(!sandbox.log().contains(line), "{line:?}: {}", sandbox.log());
    }
    assert!(!sandbox.attempt(Password::Wrong, PIN).unlocked());
    // The positive controls: with a stack whose password line lets anything through, the
    // housekeeping does hear a wrong password and a right one, and the same matchers find both.
    sandbox.attempt(Password::Right, "a wrong password, long enough");
    sandbox.unlock_with_password();
    for line in &housekeeping[..2] {
        assert!(sandbox.log().contains(line), "{line:?}: {}", sandbox.log());
    }
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

#[test]
fn a_bad_pam_line_refuses_instead_of_guessing() {
    let sandbox = Sandbox::new();
    sandbox.stack(Password::Wrong, "no_such_option");
    assert!(!PamClient::new(sandbox.path("pam.d"), "kde", &sandbox.user).authenticate(PIN).unlocked());
    assert!(sandbox.log().contains("bad PAM line: unknown argument \"no_such_option\""), "{}", sandbox.log());
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

/// Whatever goes wrong with the pinchecker, the PIN is refused and the password still works.
#[test]
fn a_broken_pinchecker_fails_closed() {
    for (name, pinchecker) in [
        ("missing", None),
        ("exits with an odd code", Some("#!/bin/sh\nexit 3\n")),
        ("killed by a signal", Some("#!/bin/sh\nkill -9 $$\n")),
        ("quits without reading", Some("#!/bin/sh\nexit 0\n")),
    ] {
        let sandbox = Sandbox::new();
        match pinchecker {
            None => fs::remove_file(sandbox.path("pinchecker")).unwrap(),
            Some(text) => sandbox.script("pinchecker", text),
        }
        // "quits without reading" exits 0, a yes: the module trusts the pinchecker's answer, so that
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
    // The PIN on the session whose password would pass: the check line ends the stack first.
    assert!(password.authenticate(PIN).unlocked());
    assert!(sandbox.log().contains("unlocked with the PIN"));
}

/// A correct PIN never unlocks sooner than the config's minimum, counted from when the module is
/// called, 75 ms by default; a wrong PIN and the password go on at once. The stand-ins for
/// pam_unix and its failure delay take no time, so whatever waits here is the module.
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
    fs::write(&config, "min_milliseconds_before_pin_unlock = 500\n").unwrap();
    fs::set_permissions(&config, Permissions::from_mode(0o644)).unwrap();
    for (password, typed, unlocks) in [(Password::Wrong, PIN, true), (Password::Wrong, "1111", false), (Password::Right, PASSWORD, true)] {
        let (unlocked, took) = timed(password, typed);
        assert_eq!(unlocked, unlocks, "{typed}: {}", sandbox.log());
        assert_eq!(took >= Duration::from_millis(500), typed == PIN, "{typed} took {took:?}");
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

/// What every host must still get: the password unlocks and does the housekeeping, the PIN unlocks and a wrong one doesn't.
fn the_usual_answers(sandbox: &Sandbox) {
    let mut password = sandbox.session(Password::Right);
    let mut pin = sandbox.session(Password::Wrong);
    assert!(password.authenticate(PASSWORD).unlocked());
    assert!(sandbox.log().contains("password correct, PIN enabled"), "{}", sandbox.log());
    assert!(pin.authenticate(PIN).unlocked(), "{}", sandbox.log());
    assert!(!pin.authenticate("1111").unlocked());
    assert!(pin.authenticate(PIN).unlocked(), "{}", sandbox.log());
}

/// With SIGCHLD ignored, the kernel would reap the pinchecker and throw its answer away; the module
/// sets the default while the pinchecker runs, and puts "ignore" back.
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
/// never takes the pinchecker, and it is back afterwards.
#[test]
fn a_host_that_reaps_every_child_still_gets_answers() {
    if in_own_process("a_host_that_reaps_every_child_still_gets_answers").is_some() {
        return;
    }
    let sandbox = Sandbox::new();
    let handler = host::reap_on_sigchld();
    the_usual_answers(&sandbox);
    assert_eq!(host::sigchld(), handler);
    assert_eq!(host::reaped(), 0, "the host's handler reaped a pinchecker");
}

/// A host thread looping on `waitpid(-1)` takes the pinchecker's exit status whatever SIGCHLD is set
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
    // The pinchecker starts late, so the host's child exits while the module is waiting for it.
    sandbox.pinchecker("sleep 0.3");
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
