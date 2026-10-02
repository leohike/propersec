//! properpin's system test: the installed module in a stock Fedora, through the real `/etc/pam.d`,
//! the real `pam_unix` and its setuid helper `unix_chkpwd`.
//!
//! It runs as root inside the container built from `testing/podman/Containerfile` (run it with
//! `just properpin podman`), never on a real machine: it installs properpin, enables it in
//! `/etc/pam.d/kde`, sets a PIN, and tampers with files as root.
//!
//! ```text
//! properpin-systest run                    every scenario in order; exit 1 if any fails
//! properpin-systest attempt SERVICE USER   one pam_authenticate, typing stdin, printing the outcome
//! ```
//!
//! `run` does each PAM attempt by starting `attempt` as the test user, the way the lock screen runs
//! as the locked user. It listens on `/dev/log` itself, so what the module and `pam_unix` log through
//! syslog comes back to the scenario that caused it.

#![forbid(unsafe_code)]

use std::fs::{self, Permissions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{PermissionsExt, chown, symlink};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use pamharness::PamClient;
use properpin_core::PinState;
use properpin_sys::Account;

/// Where the Containerfile puts the build, `packaging/` and `pam/`.
const PRODUCT: &str = "/opt/properpin";
const USER: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";
const PIN: &str = "4859";
const KDE: &str = "/etc/pam.d/kde";
const SYSLOG: &str = "/dev/log";
/// Longer than any attempt takes, failure delays included; a hung attempt is killed after this.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);

type Outcome<T = ()> = Result<T, String>;
type Scenario = fn(&World) -> Outcome;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["run"] => run(),
        ["attempt", service, user] => attempt_here(service, user),
        _ => {
            eprintln!("usage: properpin-systest run | attempt SERVICE USER");
            ExitCode::from(2)
        }
    }
}

// --- one attempt, in the test user's own process

fn attempt_here(service: &str, user: &str) -> ExitCode {
    let mut typed = String::new();
    std::io::stdin().read_to_string(&mut typed).expect("typed input on stdin");
    let attempt = PamClient::system(service, user).authenticate(&typed);
    println!("status {}", attempt.status);
    for prompt in &attempt.prompts {
        println!("prompt {prompt}");
    }
    for message in &attempt.messages {
        println!("message {message}");
    }
    ExitCode::SUCCESS
}

// --- the scenarios

fn run() -> ExitCode {
    let world = match World::set_up() {
        Ok(world) => world,
        Err(error) => {
            println!("FAILED  setting up: {error}");
            return ExitCode::FAILURE;
        }
    };
    let scenarios: &[(&str, Scenario)] = &[
        ("after boot only the password works", after_boot_only_the_password_works),
        ("the password arms the PIN, and the PIN unlocks", the_password_arms_the_pin),
        ("a wrong password never arms the PIN", a_wrong_password_never_arms_the_pin),
        ("three wrong PINs require the password", three_wrong_pins_require_the_password),
        ("the PIN works at the lock screen only", the_pin_works_at_the_lock_screen_only),
        ("a user file others can read is refused", a_user_file_others_can_read),
        ("a user file the user owns is refused", a_user_file_the_user_owns),
        ("a symlinked user file is refused", a_symlinked_user_file),
        ("a corrupt config is refused", a_corrupt_config),
        ("a hash in the global config is refused", a_hash_in_the_global_config),
        ("a shared runtime directory is refused", a_shared_runtime_directory),
        ("a corrupt state means not armed", a_corrupt_state),
        ("state from an earlier boot is refused", state_from_an_earlier_boot),
        ("an arming time in the future is refused", an_arming_time_in_the_future),
        ("an expired PIN is refused", an_expired_pin),
        ("concurrent wrong PINs are all counted", concurrent_wrong_pins_are_all_counted),
        ("disable and uninstall leave PAM as it was", disable_and_uninstall),
    ];
    let mut failed = 0;
    for (name, scenario) in scenarios {
        match world.reset().and_then(|()| scenario(&world)) {
            Ok(()) => println!("ok      {name}"),
            Err(error) => {
                failed += 1;
                println!("FAILED  {name}\n        {}", error.replace('\n', "\n        "));
            }
        }
    }
    println!("\n{} passed, {failed} failed", scenarios.len() - failed);
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

fn after_boot_only_the_password_works(world: &World) -> Outcome {
    world.pin_refused(PIN, "no password unlock since boot")?;
    world.password_unlocks()
}

fn the_password_arms_the_pin(world: &World) -> Outcome {
    world.arm()?;
    world.pin_unlocks()?;
    world.pin_unlocks()
}

fn a_wrong_password_never_arms_the_pin(world: &World) -> Outcome {
    let wrong = world.kde("a wrong password, long enough")?;
    expect(!wrong.unlocked && !wrong.log.contains("PIN armed"), "a wrong password unlocked or armed", &wrong)?;
    world.pin_refused(PIN, "no password unlock since boot")
}

fn three_wrong_pins_require_the_password(world: &World) -> Outcome {
    world.arm()?;
    world.pin_refused("1111", "not the PIN, failure 1 of 3")?;
    world.pin_refused("2222", "not the PIN, failure 2 of 3")?;
    world.pin_refused("3333", "failure 3 of 3, password required from now on")?;
    world.pin_refused(PIN, "3 failures in a row")?;
    world.arm()?;
    world.pin_unlocks()
}

/// Every other service on the system checks only the password, armed PIN or not, and never even
/// loads the module.
fn the_pin_works_at_the_lock_screen_only(world: &World) -> Outcome {
    world.arm()?;
    for service in ["sudo", "su", "login", "system-auth", "password-auth", "passwd", "other"] {
        let pin = world.attempt(service, PIN)?;
        expect(!pin.unlocked, &format!("the PIN unlocked {service}"), &pin)?;
        expect(!pin.log.contains("pam_properpin"), &format!("{service} loaded pam_properpin"), &pin)?;
    }
    for service in ["sudo", "su", "login"] {
        let password = world.attempt(service, PASSWORD)?;
        expect(password.unlocked, &format!("the password didn't unlock {service}"), &password)?;
    }
    world.pin_unlocks()
}

fn a_user_file_others_can_read(world: &World) -> Outcome {
    world.arm()?;
    fs::set_permissions(world.user_file(), Permissions::from_mode(0o644)).map_err(message)?;
    world.fails_closed("readable by others")
}

fn a_user_file_the_user_owns(world: &World) -> Outcome {
    world.arm()?;
    chown(world.user_file(), Some(world.user.uid), None).map_err(message)?;
    world.fails_closed("not 0")
}

fn a_symlinked_user_file(world: &World) -> Outcome {
    world.arm()?;
    let real = world.user_file().with_extension("real");
    fs::rename(world.user_file(), &real).map_err(message)?;
    symlink(&real, world.user_file()).map_err(message)?;
    world.fails_closed("symbolic links")
}

fn a_corrupt_config(world: &World) -> Outcome {
    world.arm()?;
    write_file(&world.config(), "this is not a setting\n", 0, 0, 0o644)?;
    world.fails_closed("expected 'key = value'")
}

fn a_hash_in_the_global_config(world: &World) -> Outcome {
    world.arm()?;
    let user_file = String::from_utf8_lossy(&world.pin_file).into_owned();
    write_file(&world.config(), &user_file, 0, 0, 0o644)?;
    world.fails_closed("only a user's own file may hold a PIN hash")
}

fn a_shared_runtime_directory(world: &World) -> Outcome {
    world.arm()?;
    fs::set_permissions(world.run_dir(), Permissions::from_mode(0o755)).map_err(message)?;
    world.fails_closed("not a private directory")
}

fn a_corrupt_state(world: &World) -> Outcome {
    world.arm()?;
    fs::write(world.state_file(), "garbage\n").map_err(message)?;
    world.pin_refused(PIN, "no password unlock since boot")
}

fn state_from_an_earlier_boot(world: &World) -> Outcome {
    world.arm()?;
    world.edit_state(|state| state.boot_id = "00000000-0000-4000-8000-000000000000".into())?;
    world.pin_refused(PIN, "the state is from an earlier boot")?;
    world.arm()?;
    world.pin_unlocks()
}

fn an_arming_time_in_the_future(world: &World) -> Outcome {
    world.arm()?;
    world.edit_state(|state| state.armed_at += 3600)?;
    world.pin_refused(PIN, "the arming time is in the future")
}

fn an_expired_pin(world: &World) -> Outcome {
    // 0.01 hours is 36 seconds; the PIN was armed a minute ago.
    let user_file = format!("{}expiry_hours = 0.01\n", String::from_utf8_lossy(&world.pin_file));
    write_file(&world.user_file(), &user_file, 0, world.user.gid, 0o640)?;
    world.arm()?;
    world.edit_state(|state| state.armed_at = state.armed_at.saturating_sub(60))?;
    world.pin_refused(PIN, "the last password unlock was 0h01m ago")
}

/// Three wrong PINs at once: each is counted, none is lost to another's write, and the PIN is then
/// refused.
fn concurrent_wrong_pins_are_all_counted(world: &World) -> Outcome {
    world.arm()?;
    let children: Vec<Child> = ["1111", "2222", "3333"].into_iter().map(|wrong| world.spawn("kde", wrong)).collect::<Outcome<_>>()?;
    let mut log = String::new();
    for child in children {
        let attempt = world.finish(child)?;
        expect(!attempt.unlocked, "a wrong PIN unlocked", &attempt)?;
        log += &attempt.log;
    }
    for count in 1..=3 {
        if !log.contains(&format!("failure {count} of 3")) {
            return Err(format!("no attempt was counted as failure {count} of 3\n{log}"));
        }
    }
    world.pin_refused(PIN, "3 failures in a row")
}

fn disable_and_uninstall(world: &World) -> Outcome {
    world.arm()?;
    install_sh(&["disable", "--yes"])?;
    let kde = fs::read_to_string(KDE).map_err(message)?;
    if kde != world.stock_kde {
        return Err(format!("{KDE} after disable differs from before enable:\n{kde}"));
    }
    let pin = world.kde(PIN)?;
    expect(!pin.unlocked && !pin.log.contains("pam_properpin"), "the PIN still works after disable", &pin)?;
    world.password_unlocks()?;
    install_sh(&["uninstall"])?;
    for gone in ["/usr/local/lib64/security/pam_properpin.so", "/usr/local/libexec/properpin", "/usr/local/bin/properpin"] {
        if Path::new(gone).exists() {
            return Err(format!("{gone} is still there after uninstall"));
        }
    }
    if !world.user_file().exists() {
        return Err("uninstall deleted the user's PIN file".into());
    }
    Ok(())
}

// --- the world the scenarios run in

struct World {
    user: Account,
    syslog: Syslog,
    /// `/etc/pam.d/kde` before enable.
    stock_kde: String,
    /// The user file `properpin set` wrote.
    pin_file: Vec<u8>,
}

/// What one attempt came to, and everything logged through syslog while it ran.
#[derive(Debug)]
struct Attempt {
    unlocked: bool,
    prompts: usize,
    log: String,
}

impl World {
    /// Listen on syslog, install and enable properpin, give the user a runtime directory, and set
    /// the PIN through the installed command.
    fn set_up() -> Outcome<Self> {
        if !Path::new("/run/.containerenv").exists() {
            return Err("not in a container; this test changes /etc/pam.d, so it runs in podman only".into());
        }
        let user = Account::by_name(USER).map_err(message)?;
        let syslog = Syslog::listen()?;
        let stock_kde = fs::read_to_string(KDE).map_err(message)?;

        install_sh(&["install"])?;
        install_sh(&["enable", "--yes"])?;
        let run_dir = PathBuf::from(format!("/run/user/{}", user.uid));
        fs::create_dir_all(&run_dir).map_err(message)?;
        chown(&run_dir, Some(user.uid), Some(user.gid)).map_err(message)?;

        let set = Command::new("/usr/local/bin/properpin")
            .args(["set", "--user", USER])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                child.stdin.take().expect("piped").write_all(format!("{PIN}\n{PIN}\n").as_bytes())?;
                child.wait_with_output()
            })
            .map_err(message)?;
        if !set.status.success() {
            return Err(format!("properpin set failed: {}", String::from_utf8_lossy(&set.stderr)));
        }
        let checked = install_sh(&["check"])?;
        if !checked.contains("has properpin's lines") {
            return Err(format!("install.sh check after set:\n{checked}"));
        }
        let pin_file = fs::read(format!("/etc/properpin/users/{USER}")).map_err(message)?;
        Ok(Self { user, syslog, stock_kde, pin_file })
    }

    fn user_file(&self) -> PathBuf {
        PathBuf::from(format!("/etc/properpin/users/{USER}"))
    }

    fn config(&self) -> PathBuf {
        PathBuf::from("/etc/properpin/config")
    }

    fn run_dir(&self) -> PathBuf {
        PathBuf::from(format!("/run/user/{}", self.user.uid))
    }

    fn state_file(&self) -> PathBuf {
        self.run_dir().join("properpin.state")
    }

    /// Back to just after set-up: the PIN set, not armed, nothing tampered with.
    fn reset(&self) -> Outcome {
        for path in [self.state_file(), self.run_dir().join("properpin.lock"), self.config(), self.user_file().with_extension("real")] {
            match fs::remove_file(&path) {
                Err(error) if error.kind() != ErrorKind::NotFound => return Err(format!("{}: {error}", path.display())),
                _ => {}
            }
        }
        let _ = fs::remove_file(self.user_file());
        write_file(&self.user_file(), &String::from_utf8_lossy(&self.pin_file), 0, self.user.gid, 0o640)?;
        chown(self.run_dir(), Some(self.user.uid), Some(self.user.gid)).map_err(message)?;
        fs::set_permissions(self.run_dir(), Permissions::from_mode(0o700)).map_err(message)?;
        self.syslog.take();
        Ok(())
    }

    /// Start one attempt as the test user, in their own process.
    fn spawn(&self, service: &str, typed: &str) -> Outcome<Child> {
        let mut child = Command::new(std::env::current_exe().map_err(message)?)
            .args(["attempt", service, USER])
            .uid(self.user.uid)
            .gid(self.user.gid)
            .env_clear()
            .env("PATH", "/usr/bin")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(message)?;
        child.stdin.take().expect("piped").write_all(typed.as_bytes()).map_err(message)?;
        Ok(child)
    }

    fn finish(&self, mut child: Child) -> Outcome<Attempt> {
        let deadline = Instant::now() + ATTEMPT_TIMEOUT;
        while child.try_wait().map_err(message)?.is_none() {
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("the attempt hung for {ATTEMPT_TIMEOUT:?} and was killed; it logged:\n{}", self.syslog.take()));
            }
            thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().map_err(message)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let status = stdout.lines().find_map(|line| line.strip_prefix("status ")).and_then(|status| status.parse::<i32>().ok());
        let Some(status) = status else {
            return Err(format!("the attempt didn't finish: {}{}", stdout, String::from_utf8_lossy(&output.stderr)));
        };
        let prompts = stdout.lines().filter(|line| line.starts_with("prompt ")).count();
        Ok(Attempt { unlocked: status == pamharness::PAM_SUCCESS, prompts, log: self.syslog.take() })
    }

    fn attempt(&self, service: &str, typed: &str) -> Outcome<Attempt> {
        self.finish(self.spawn(service, typed)?)
    }

    /// One attempt at the lock screen, which always asks exactly once.
    fn kde(&self, typed: &str) -> Outcome<Attempt> {
        let attempt = self.attempt("kde", typed)?;
        expect(attempt.prompts == 1, &format!("{} prompts, not 1", attempt.prompts), &attempt)?;
        Ok(attempt)
    }

    /// Unlock the lock screen with the password, which arms the PIN.
    fn arm(&self) -> Outcome {
        let attempt = self.kde(PASSWORD)?;
        expect(attempt.unlocked && attempt.log.contains("password accepted, PIN armed"), "the password didn't arm the PIN", &attempt)
    }

    fn password_unlocks(&self) -> Outcome {
        let attempt = self.kde(PASSWORD)?;
        expect(attempt.unlocked, "the password didn't unlock", &attempt)
    }

    fn pin_unlocks(&self) -> Outcome {
        let attempt = self.kde(PIN)?;
        expect(attempt.unlocked && attempt.log.contains("unlocked with the PIN"), "the PIN didn't unlock", &attempt)
    }

    fn pin_refused(&self, typed: &str, why: &str) -> Outcome {
        let attempt = self.kde(typed)?;
        expect(!attempt.unlocked && attempt.log.contains(why), &format!("{typed} wasn't refused with {why:?}"), &attempt)
    }

    /// Something is wrong with the files: the PIN is refused for `why`, the password still works.
    fn fails_closed(&self, why: &str) -> Outcome {
        self.pin_refused(PIN, why)?;
        self.password_unlocks()
    }

    fn edit_state(&self, change: impl FnOnce(&mut PinState)) -> Outcome {
        let text = fs::read_to_string(self.state_file()).map_err(message)?;
        let mut state = PinState::parse(&text).ok_or("the state file doesn't parse")?;
        change(&mut state);
        // Written in place: the file keeps its owner and mode.
        fs::write(self.state_file(), state.format()).map_err(message)
    }
}

/// `/dev/log`, read by a thread of its own as fast as anything logs. Read only between attempts,
/// its queue of 10 datagrams would fill up during concurrent attempts, and then everything logging
/// through syslog (the module, `pam_unix`, `unix_chkpwd`) would block, waiting for the test.
struct Syslog {
    received: Arc<(Mutex<Vec<String>>, Condvar)>,
    marks: AtomicU64,
}

impl Syslog {
    fn listen() -> Outcome<Self> {
        let _ = fs::remove_file(SYSLOG);
        let socket = UnixDatagram::bind(SYSLOG).map_err(message)?;
        fs::set_permissions(SYSLOG, Permissions::from_mode(0o666)).map_err(message)?;
        let received = Arc::new((Mutex::new(Vec::new()), Condvar::new()));
        let sink = Arc::clone(&received);
        thread::spawn(move || {
            let mut buffer = [0; 8192];
            while let Ok(size) = socket.recv(&mut buffer) {
                let (lines, arrived) = &*sink;
                lines.lock().unwrap().push(String::from_utf8_lossy(&buffer[..size]).into_owned());
                arrived.notify_all();
            }
        });
        Ok(Self { received, marks: AtomicU64::new(0) })
    }

    /// Everything logged since the last call. It first sends a mark through the same socket, which
    /// queues it behind everything already logged, and waits for the mark to arrive: by then nothing
    /// logged before this call is still on its way.
    fn take(&self) -> String {
        let mark = format!("properpin-systest mark {}", self.marks.fetch_add(1, Ordering::Relaxed));
        let sent = UnixDatagram::unbound().and_then(|socket| socket.send_to(mark.as_bytes(), SYSLOG));
        let (lines, arrived) = &*self.received;
        let mut lines = lines.lock().unwrap();
        if sent.is_ok() {
            lines = arrived.wait_timeout_while(lines, Duration::from_secs(10), |lines| !lines.contains(&mark)).unwrap().0;
        }
        lines.drain(..).filter(|line| !line.starts_with("properpin-systest mark ")).map(|line| line + "\n").collect()
    }
}

fn expect(holds: bool, what: &str, attempt: &Attempt) -> Outcome {
    if holds { Ok(()) } else { Err(format!("{what}: {attempt:?}")) }
}

/// Run `packaging/install.sh` against the real root, from the container's build.
fn install_sh(args: &[&str]) -> Outcome<String> {
    let output = Command::new("bash")
        .arg(format!("{PRODUCT}/packaging/install.sh"))
        .args(args)
        .args(["--from", &format!("{PRODUCT}/build")])
        .stdin(Stdio::null())
        .output()
        .map_err(message)?;
    let said = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    if output.status.success() { Ok(said) } else { Err(format!("install.sh {}:\n{said}", args.join(" "))) }
}

fn write_file(path: &Path, text: &str, uid: u32, gid: u32, mode: u32) -> Outcome {
    fs::write(path, text).map_err(message)?;
    chown(path, Some(uid), Some(gid)).map_err(message)?;
    fs::set_permissions(path, Permissions::from_mode(mode)).map_err(message)
}

fn message(error: impl std::fmt::Display) -> String {
    error.to_string()
}
