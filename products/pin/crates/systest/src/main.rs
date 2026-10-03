//! properpin's system test: the installed module and its setgid helper in a stock Fedora, through
//! the real `/etc/pam.d`, the real `pam_unix` and its own setuid helper `unix_chkpwd`.
//!
//! It runs as root inside the container built from `testing/podman/Containerfile` (run it with
//! `just properpin podman`), never on a real machine: it installs properpin, enables it in
//! `/etc/pam.d/kde`, sets a PIN, and tampers with files as root.
//!
//! ```text
//! properpin-systest run                    every scenario in order; exit 1 if any fails
//! properpin-systest attempt SERVICE USER   one pam_authenticate, typing stdin, printing the outcome
//! properpin-systest worker SERVICE USER    one PAM session, an attempt for each line of stdin
//! ```
//!
//! `run` does each PAM attempt by starting `attempt` as the test user, the way the lock screen runs
//! as the locked user, and checks that the process exited cleanly. `worker` stands in for
//! kscreenlocker 6.8's `kscreenlocker_worker`: one session for many attempts, killed when the greeter
//! cancels. `run` listens on `/dev/log` itself, so what the module and `pam_unix` log through syslog
//! comes back to the scenario that caused it. After every scenario no helper may still be running.

#![forbid(unsafe_code)]

use std::fs::{self, Permissions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{PermissionsExt, chown, symlink};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use pamharness::PamClient;
use properpin_core::{Budget, Clock, PinState, exit};
use properpin_sys::{Account, BootClock, Yescrypt, group_by_name};

/// Where the Containerfile puts the build, `packaging/` and `pam/`.
const PRODUCT: &str = "/opt/properpin";
const USER: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";
const PIN: &str = "4859";
const KDE: &str = "/etc/pam.d/kde";
const HELPER: &str = "/usr/local/libexec/properpin/properpin-helper";
/// The group the helper runs with, created by install.sh.
const HELPER_GROUP: &str = "properpin";
const RUN_DIR: &str = "/run/properpin";
const BUDGET_DIR: &str = "/var/lib/properpin";
/// Where scenarios that play the attacker keep their files; emptied between scenarios.
const SCRATCH: &str = "/tmp/properpin-scratch";
const SYSLOG: &str = "/dev/log";
/// Longer than any attempt takes, failure delays included; a hung attempt is killed after this.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);
/// A helper whose attempt was killed finishes on its own: at most a second waiting for the lock,
/// then a hash or `unix_chkpwd`. Still running after this, it is a bug.
const HELPER_LINGER: Duration = Duration::from_secs(5);
/// What the kernel calls the helper: its name cut to 15 bytes.
const HELPER_COMM: &str = "properpin-helpe";

type Outcome<T = ()> = Result<T, String>;
type Scenario = fn(&World) -> Outcome;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["run"] => run(),
        ["attempt", service, user] => attempt_here(service, user),
        ["worker", service, user] => worker_here(service, user),
        _ => {
            eprintln!("usage: properpin-systest run | attempt SERVICE USER | worker SERVICE USER");
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

/// Like `kscreenlocker_worker`: one PAM session, an attempt for each line typed, each answered with
/// one line as soon as it is done, and `pam_end` before exiting at the end of the input.
fn worker_here(service: &str, user: &str) -> ExitCode {
    let mut session = PamClient::system(service, user).session();
    let mut out = std::io::stdout().lock();
    for typed in std::io::stdin().lines() {
        let typed = typed.expect("typed input on stdin");
        let started = Instant::now();
        let attempt = session.authenticate(&typed);
        let ms = started.elapsed().as_millis();
        let delays = attempt.delays.len();
        writeln!(out, "status {} prompts {} delays {delays} ms {ms}", attempt.status, attempt.prompts.len()).expect("stdout");
        out.flush().expect("stdout");
    }
    drop(session);
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
        ("the user can't read their hash or touch their counts", the_user_cannot_reach_the_files),
        ("another user can't use or spend someone's PIN", another_user_gets_nothing),
        ("--dev options are refused under setgid", dev_options_are_refused_under_setgid),
        ("a poisoned start changes nothing", a_poisoned_start_changes_nothing),
        ("arming checks the password itself", arming_checks_the_password_itself),
        ("a missing helper fails closed", a_missing_helper_fails_closed),
        ("status shows your own PIN only", status_shows_your_own_pin),
        ("the helper's group can't change the helper", the_group_cannot_change_the_helper),
        ("one user's helper can't touch another's counts", one_users_helper_cannot_touch_anothers_counts),
        ("counts planted in another user's name are refused", planted_counts_are_refused),
        ("the helper's group stays empty and locked, with no account", the_group_stays_empty_and_locked),
        ("typos followed by the PIN or the password are forgiven", typos_are_forgiven),
        ("the slow attack: a guess, the user's PIN much later, again", the_slow_attack_is_stopped),
        ("guesses nobody forgives disable the PIN, across a reboot", unforgiven_guesses_disable_the_pin),
        ("the lifetime limit takes a new PIN", the_lifetime_limit_takes_a_new_pin),
        ("a damaged or planted budget refuses the PIN", a_damaged_or_planted_budget),
        ("a corrupt state means not armed", a_corrupt_state),
        ("state from an earlier boot is refused", state_from_an_earlier_boot),
        ("an arming time in the future is refused", an_arming_time_in_the_future),
        ("an expired PIN is refused", an_expired_pin),
        ("concurrent wrong PINs are all counted", concurrent_wrong_pins_are_all_counted),
        ("one session serves many attempts, and the worker exits cleanly", one_session_serves_many_attempts),
        ("a killed worker never unlocks and loses no count", a_killed_worker_loses_no_count),
        ("disable and uninstall leave PAM as it was", disable_and_uninstall),
    ];
    let mut failed = 0;
    for (name, scenario) in scenarios {
        match world.reset().and_then(|()| scenario(&world)).and_then(|()| no_helper_left()) {
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
        expect(!pin.log.contains("properpin-helper"), &format!("{service} ran the helper"), &pin)?;
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
    fs::set_permissions(RUN_DIR, Permissions::from_mode(0o1777)).map_err(message)?;
    world.fails_closed("mode 1777, not 1770")
}

/// The point of the helper: nothing the user runs can read the hash, or reset the counts.
fn the_user_cannot_reach_the_files(world: &World) -> Outcome {
    world.arm()?;
    for wrong in ["1111", "2222", "3333"] {
        world.pin_refused(wrong, "not the PIN")?;
    }
    let state = world.state_file().display().to_string();
    let user_file = world.user_file().display().to_string();
    for (what, script) in [
        ("read the hash", format!("cat {user_file}")),
        ("list the PIN files", "ls /etc/properpin/users".to_owned()),
        ("list the counts", format!("ls {RUN_DIR}")),
        ("read the counts", format!("cat {state}")),
        ("delete the counts", format!("rm -f {state}")),
        ("replace the counts", format!("echo garbage > {state}")),
    ] {
        let output = world.as_user(USER, &["sh", "-c", &script], b"")?;
        if output.status.success() {
            return Err(format!("{USER} could {what}: {}", String::from_utf8_lossy(&output.stdout)));
        }
    }
    world.pin_refused(PIN, "3 failures in a row")
}

/// bob has no PIN. Whatever he sends, he gets nothing about alice's, and spends none of her tries.
fn another_user_gets_nothing(world: &World) -> Outcome {
    world.arm()?;
    for args in [&["check"][..], &["check", USER], &["status", USER]] {
        let output = world.as_user("bob", &[HELPER].iter().chain(args).copied().collect::<Vec<_>>(), PIN.as_bytes())?;
        if output.status.code() == Some(exit::YES.into()) && args[0] == "check" {
            return Err(format!("bob's {args:?} said yes"));
        }
    }
    let bob = world.as_user("bob", &[HELPER, "check"], b"1111")?;
    expect_code(&bob, exit::NO, "bob's wrong PIN")?;
    let log = world.syslog.take();
    if !log.contains("bob: no PIN is set, refused") {
        return Err(format!("the helper didn't answer for bob:\n{log}"));
    }
    world.pin_unlocks()
}

/// The attack the --dev options would allow: point the helper at files the caller made, holding a
/// hash of a PIN they chose. Under setgid it must refuse before reading anything.
fn dev_options_are_refused_under_setgid(world: &World) -> Outcome {
    let user = &world.user;
    let fake = Path::new(SCRATCH);
    fs::create_dir_all(fake.join("etc/users")).map_err(message)?;
    fs::create_dir_all(fake.join("run")).map_err(message)?;
    fs::create_dir_all(fake.join("var")).map_err(message)?;
    write_file(
        &fake.join("etc/users").join(USER),
        &format!("hash = {}\n", Yescrypt.hash("0000", 4).map_err(message)?),
        user.uid,
        user.gid,
        0o640,
    )?;
    for dir in [fake.to_path_buf(), fake.join("etc"), fake.join("etc/users"), fake.join("run"), fake.join("var")] {
        chown(&dir, Some(user.uid), Some(user.gid)).map_err(message)?;
        fs::set_permissions(&dir, Permissions::from_mode(0o700)).map_err(message)?;
    }
    let dev = [
        "--dev-etc",
        &format!("{SCRATCH}/etc"),
        "--dev-run",
        &format!("{SCRATCH}/run"),
        "--dev-budget",
        &format!("{SCRATCH}/var"),
        "--dev-owner",
        &user.uid.to_string(),
        "--dev-chkpwd",
        "/usr/bin/true",
    ];
    let arm = world.as_user(USER, &[&[HELPER, "arm"][..], &dev].concat(), b"anything")?;
    expect_code(&arm, exit::USAGE, "arm with --dev options under setgid")?;
    let check = world.as_user(USER, &[&[HELPER, "check"][..], &dev].concat(), b"0000")?;
    expect_code(&check, exit::USAGE, "check with --dev options under setgid")?;
    let log = world.syslog.take();
    if !log.contains("refused: --dev options while running with elevated rights") {
        return Err(format!("the refusal wasn't logged:\n{log}"));
    }
    Ok(())
}

/// Closed stdout and stderr, an extra open file, and a hostile environment, including a preloaded
/// library that would hijack an ordinary program: the helper answers as always.
fn a_poisoned_start_changes_nothing(world: &World) -> Outcome {
    world.arm()?;
    let script = format!(
        "exec 7</etc/hostname; LD_PRELOAD={SCRATCH}/evil.so LD_LIBRARY_PATH={SCRATCH} RUST_BACKTRACE=full LANG=xx_XX TZ=../../etc/shadow exec {HELPER} check >&- 2>&-"
    );
    fs::create_dir_all(SCRATCH).map_err(message)?;
    fs::write(format!("{SCRATCH}/evil.so"), "not a library").map_err(message)?;
    let right = world.as_user(USER, &["sh", "-c", &script], PIN.as_bytes())?;
    expect_code(&right, exit::YES, "the right PIN with a poisoned start")?;
    let wrong = world.as_user(USER, &["sh", "-c", &script], b"1111")?;
    expect_code(&wrong, exit::NO, "a wrong PIN with a poisoned start")?;
    let log = world.syslog.take();
    if !log.contains("not the PIN, failure 1 of 3") {
        return Err(format!("the wrong PIN wasn't counted:\n{log}"));
    }
    Ok(())
}

/// Anything the user runs can ask the helper to arm; only the real password does it, checked by the
/// real unix_chkpwd.
fn arming_checks_the_password_itself(world: &World) -> Outcome {
    for wrong in ["", "wrong", "correct horse battery stapl"] {
        let arm = world.as_user(USER, &[HELPER, "arm"], wrong.as_bytes())?;
        expect_code(&arm, exit::NO, &format!("arm with {wrong:?}"))?;
    }
    world.pin_refused(PIN, "no password unlock since boot")?;
    let arm = world.as_user(USER, &[HELPER, "arm"], PASSWORD.as_bytes())?;
    expect_code(&arm, exit::YES, "arm with the password")?;
    world.pin_unlocks()
}

fn a_missing_helper_fails_closed(world: &World) -> Outcome {
    world.arm()?;
    fs::rename(HELPER, format!("{HELPER}.away")).map_err(message)?;
    let pin = world.kde(PIN);
    let password = world.kde(PASSWORD);
    fs::rename(format!("{HELPER}.away"), HELPER).map_err(message)?;
    let (pin, password) = (pin?, password?);
    expect(!pin.unlocked && pin.log.contains("PIN refused:"), "the PIN worked without the helper", &pin)?;
    expect(password.unlocked && password.log.contains("PIN not armed:"), "the password didn't unlock", &password)
}

fn status_shows_your_own_pin(world: &World) -> Outcome {
    world.arm()?;
    let mine = world.as_user(USER, &["/usr/local/bin/properpin", "status"], b"")?;
    let text = String::from_utf8_lossy(&mine.stdout);
    if !mine.status.success() || !text.contains("PIN        set") || !text.contains("PIN armed for another") {
        return Err(format!("alice's status: {text}{}", String::from_utf8_lossy(&mine.stderr)));
    }
    let bob = world.as_user("bob", &["/usr/local/bin/properpin", "status"], b"")?;
    if !String::from_utf8_lossy(&bob.stdout).contains("none set") {
        return Err(format!("bob's status: {}", String::from_utf8_lossy(&bob.stdout)));
    }
    let root = Command::new("/usr/local/bin/properpin").arg("status").output().map_err(message)?;
    if root.status.success() {
        return Err("status ran as root".into());
    }
    // The helper itself refuses root too, whoever calls it.
    let helper = Command::new(HELPER).arg("status").stdin(Stdio::null()).output().map_err(message)?;
    expect_code(&helper, exit::USAGE, "the helper run by root")
}

/// bob with the helper's group stands in for bob having exploited a bug in the helper: whatever he
/// then does, the helper itself stays root's, unchanged.
fn the_group_cannot_change_the_helper(world: &World) -> Outcome {
    let before = fs::read(HELPER).map_err(message)?;
    for (what, script) in [
        ("append to the helper", format!("echo evil >> {HELPER}")),
        ("chmod the helper", format!("chmod 777 {HELPER}")),
        ("rename the helper", format!("mv {HELPER} {HELPER}.moved")),
        ("delete the helper", format!("rm -f {HELPER}")),
        ("replace the helper", format!("cp /usr/bin/true {HELPER}")),
    ] {
        let output = world.as_helper_group("bob", &["sh", "-c", &script])?;
        if output.status.success() {
            return Err(format!("bob with group {HELPER_GROUP} could {what}"));
        }
    }
    if fs::read(HELPER).map_err(message)? != before {
        return Err("the helper's bytes changed".into());
    }
    install_sh(&["check"]).map(drop)
}

/// Each user's counts file is that user's own, in a sticky directory: bob running the helper, or
/// exploiting it, can't read, change, delete or replace alice's.
fn one_users_helper_cannot_touch_anothers_counts(world: &World) -> Outcome {
    world.arm()?;
    world.pin_refused("1111", "not the PIN, failure 1 of 3")?;
    let state = world.state_file().display().to_string();
    for (what, script) in [
        ("read alice's counts", format!("cat {state}")),
        ("overwrite alice's counts", format!("echo garbage > {state}")),
        ("delete alice's counts", format!("rm -f {state}")),
        ("rename alice's counts", format!("mv {state} {RUN_DIR}/stolen")),
        ("replace alice's counts", format!("echo garbage > {RUN_DIR}/mine && mv -f {RUN_DIR}/mine {state}")),
    ] {
        let output = world.as_helper_group("bob", &["sh", "-c", &script])?;
        if output.status.success() {
            return Err(format!("bob with group {HELPER_GROUP} could {what}"));
        }
    }
    let _ = fs::remove_file(format!("{RUN_DIR}/mine"));
    world.pin_refused("2222", "not the PIN, failure 2 of 3")
}

/// Before alice's first attempt of the boot, bob with the helper's group creates her lock file,
/// writable by anyone, and a state that says her PIN is armed. Her PIN is refused, and the log says
/// whose lock file it is. The password still works.
fn planted_counts_are_refused(world: &World) -> Outcome {
    let bob = Account::by_name("bob").map_err(message)?;
    let armed = PinState::armed(&BootClock.boot_id().map_err(message)?, BootClock.now().map_err(message)?);
    let lock = format!("{RUN_DIR}/{}.lock", world.user.uid);
    let script = format!("umask 0 && touch {lock} && chmod 666 {lock} && cat > {}", world.state_file().display());
    let planted = world.as_identity(bob.uid, world.helper_gid, &["sh", "-c", &script], armed.format().as_bytes())?;
    if !planted.status.success() {
        return Err(format!("couldn't plant the files: {}", String::from_utf8_lossy(&planted.stderr)));
    }
    // With fs.protected_regular=2 the kernel refuses alice's open of bob's lock file even sooner.
    let protected = fs::read_to_string("/proc/sys/fs/protected_regular").map_err(message)?.trim() == "2";
    let attempt = world.kde(PIN)?;
    let why = format!("owned by uid {}, not {}", bob.uid, world.user.uid);
    let refused = attempt.log.contains(&why) || (protected && attempt.log.contains("Permission denied"));
    expect(!attempt.unlocked && refused, &format!("the PIN wasn't refused with {why:?}"), &attempt)?;
    world.password_unlocks()
}

/// Anyone with the helper's group can read every hash and change every count, so install.sh check
/// insists nobody has it: no members, and a locked password so newgrp can't give it. No account.
fn the_group_stays_empty_and_locked(_world: &World) -> Outcome {
    if Account::by_name(HELPER_GROUP).is_ok() {
        return Err(format!("a user named {HELPER_GROUP} exists"));
    }
    install_sh(&["check"])?;
    let (group, gshadow) = (fs::read("/etc/group").map_err(message)?, fs::read("/etc/gshadow").map_err(message)?);
    let result = (|| {
        let added = Command::new("usermod").args(["-aG", HELPER_GROUP, "bob"]).status().map_err(message)?;
        if !added.success() {
            return Err("usermod failed".to_owned());
        }
        match install_sh(&["check"]) {
            Err(said) if said.contains("has members (bob)") => {}
            other => return Err(format!("check accepted a member: {other:?}")),
        }
        fs::write("/etc/group", &group).map_err(message)?;
        fs::write("/etc/gshadow", &gshadow).map_err(message)?;
        install_sh(&["check"])?;
        // gshadow is name:password:admins:members; an empty password lets members use newgrp.
        let unlocked: String = String::from_utf8_lossy(&gshadow)
            .lines()
            .map(|line| {
                let mut fields: Vec<&str> = line.split(':').collect();
                if fields[0] == HELPER_GROUP && fields.len() > 1 {
                    fields[1] = "";
                }
                fields.join(":") + "\n"
            })
            .collect();
        fs::write("/etc/gshadow", unlocked).map_err(message)?;
        match install_sh(&["check"]) {
            Err(said) if said.contains("isn't locked") => Ok(()),
            other => Err(format!("check accepted an empty group password: {other:?}")),
        }
    })();
    fs::write("/etc/group", &group).map_err(message)?;
    fs::write("/etc/gshadow", &gshadow).map_err(message)?;
    result?;
    install_sh(&["check"]).map(drop)
}

/// The user's own mistakes never count: a wrong PIN, then the right one; a wrong password, then
/// the right one. Nothing is left waiting, nothing is concerning.
fn typos_are_forgiven(world: &World) -> Outcome {
    world.arm()?;
    world.pin_refused("1111", "not the PIN, failure 1 of 3")?;
    world.pin_unlocks()?;
    let wrong = world.kde("a wrong password, long enough")?;
    expect(!wrong.unlocked, "a wrong password unlocked", &wrong)?;
    world.arm()?;
    let budget = world.budget()?;
    if !budget.pending.is_empty() || budget.total != 0 {
        return Err(format!("typos were kept: {budget:?}"));
    }
    Ok(())
}

/// The repeated-access attack: a guess while the user is away, then the user's own correct PIN
/// two minutes later, which wipes the failures in a row but can't forgive the guess. With the
/// daily limit at 3, the third round finds the PIN disabled.
fn the_slow_attack_is_stopped(world: &World) -> Outcome {
    write_file(&world.config(), "max_concerning_24h = 3\n", 0, 0, 0o644)?;
    world.arm()?;
    for round in 1..=2 {
        world.pin_refused("1111", "not the PIN, failure 1 of 3")?;
        world.edit_budget(|budget| budget.pending.iter_mut().for_each(|at| *at -= 120))?;
        world.pin_unlocks().map_err(|error| format!("round {round}: {error}"))?;
    }
    world.pin_refused("1111", "not the PIN, failure 1 of 3")?;
    world.edit_budget(|budget| budget.pending.iter_mut().for_each(|at| *at -= 120))?;
    world.pin_refused(PIN, "the PIN is disabled after 3 concerning failures within 24 hours")?;
    world.password_unlocks()
}

/// Nine concerning failures already today, and one more guess the user never forgives: the PIN is
/// disabled, stays disabled after a reboot even for the password, and comes back with `enable`.
fn unforgiven_guesses_disable_the_pin(world: &World) -> Outcome {
    world.arm()?;
    let now = BootClock.wall().map_err(message)?;
    world.edit_budget(|budget| {
        budget.concerning = (1..=9).map(|hour| now - hour * 600).rev().collect();
        budget.total = 9;
    })?;
    world.pin_refused("1111", "not the PIN, failure 1 of 3")?;
    // Two minutes pass before the user comes back: too late to forgive the guess.
    world.edit_budget(|budget| budget.pending.iter_mut().for_each(|at| *at -= 120))?;
    let attempt = world.kde(PIN)?;
    let why = "the PIN is disabled after 10 concerning failures within 24 hours";
    expect(!attempt.unlocked && attempt.log.contains("PIN disabled after") && attempt.log.contains(why), why, &attempt)?;
    // A reboot: the per-boot state is gone, the budget isn't.
    world.forget_this_boot()?;
    let password = world.kde(PASSWORD)?;
    expect(password.unlocked && password.log.contains("PIN not armed: disabled after"), "the password armed a disabled PIN", &password)?;
    world.pin_refused(PIN, why)?;
    let enabled = properpin_as_root(&["enable", "--user", USER], "")?;
    if !enabled.contains("PIN enabled again") {
        return Err(format!("properpin enable said: {enabled}"));
    }
    world.arm()?;
    world.pin_unlocks()
}

/// The total since the PIN was set has its own limit, which `enable` can't lift: only a new PIN.
fn the_lifetime_limit_takes_a_new_pin(world: &World) -> Outcome {
    world.arm()?;
    world.edit_budget(|budget| budget.total = 99)?;
    world.pin_refused("1111", "not the PIN")?;
    world.edit_budget(|budget| budget.pending.iter_mut().for_each(|at| *at -= 120))?;
    world.pin_refused(PIN, "the PIN is disabled after 100 concerning failures since the PIN was set")?;
    match properpin_as_root(&["enable", "--user", USER], "") {
        Err(said) if said.contains("choose a new one with: properpin set") => {}
        other => return Err(format!("enable lifted the lifetime limit: {other:?}")),
    }
    properpin_as_root(&["set", "--user", USER], &format!("{PIN}\n{PIN}\n"))?;
    world.arm()?;
    world.pin_unlocks()
}

/// A budget that can't be trusted is never read as a fresh one.
fn a_damaged_or_planted_budget(world: &World) -> Outcome {
    world.arm()?;
    overwrite(&world.budget_file(), "garbage\n")?;
    world.fails_closed("not a valid budget")?;
    // Planted by bob's helper: private to bob, it can't even be opened; readable, its owner is wrong.
    let bob = Account::by_name("bob").map_err(message)?;
    write_file(&world.budget_file(), &Budget::default().format(), bob.uid, world.helper_gid, 0o600)?;
    world.fails_closed(&format!("{}: Permission denied", world.budget_file().display()))?;
    write_file(&world.budget_file(), &Budget::default().format(), bob.uid, world.helper_gid, 0o644)?;
    world.fails_closed(&format!("owned by uid {}, not {}", bob.uid, world.user.uid))
}

fn a_corrupt_state(world: &World) -> Outcome {
    world.arm()?;
    overwrite(&world.state_file(), "garbage\n")?;
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
    write_file(&world.user_file(), &user_file, 0, world.helper_gid, 0o640)?;
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

/// The 6.8 worker's way: one session, the password, the PIN, a wrong PIN and the PIN again, each
/// asking once, the failure asking for pam_unix's delay, and the worker exiting cleanly after
/// `pam_end`, where a Rust module that had been unloaded would crash.
fn one_session_serves_many_attempts(world: &World) -> Outcome {
    let mut worker = world.start(&["worker", "kde", USER])?;
    let mut stdin = worker.stdin.take().expect("piped");
    for typed in [PASSWORD, PIN, "1111", PIN] {
        writeln!(stdin, "{typed}").map_err(message)?;
    }
    drop(stdin);
    let output = world.wait_for(worker)?;
    let log = world.syslog.take();
    let answers = Answer::all(&output);
    let said = || format!("{answers:?}\n{log}");
    let statuses: Vec<bool> = answers.iter().map(|answer| answer.status == pamharness::PAM_SUCCESS).collect();
    if statuses != [true, true, false, true] {
        return Err(format!("unlocked {statuses:?}, not [true, true, false, true]: {}", said()));
    }
    if answers.iter().any(|answer| answer.prompts != 1) {
        return Err(format!("every attempt asks once: {}", said()));
    }
    if answers.iter().map(|answer| answer.delays > 0).collect::<Vec<_>>() != [false, false, true, false] {
        return Err(format!("only the failure asks for a delay: {}", said()));
    }
    if !log.contains("password accepted, PIN armed") || log.matches("unlocked with the PIN").count() != 2 || !log.contains("failure 1 of 3")
    {
        return Err(format!("the log doesn't show arming, two PIN unlocks and one failure: {}", said()));
    }
    // What the minimum-duration row in docs/plan.md will turn into an assertion.
    println!(
        "        note: a correct PIN took {} and {} ms; kscreenlocker 6.8 calls 50 ms or less too quick",
        answers[1].ms, answers[3].ms
    );
    Ok(())
}

/// The 6.8 greeter cancels by killing its worker: SIGTERM and SIGKILL 25 ms later, or SIGKILL at
/// once. A wrong PIN typed into a worker killed at chosen and random moments: no unlock, the helper
/// finishes on its own and its count is kept, a fresh attempt right after gets the lock and is
/// counted, and the counts and the budget agree.
fn a_killed_worker_loses_no_count(world: &World) -> Outcome {
    let seed = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(message)?.subsec_nanos() | 1;
    let mut random = u64::from(seed);
    let mut next = move || {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        random
    };
    let chosen = [0, 2, 5, 10, 20, 40, 80, 150];
    let mut reached = 0;
    for round in 0..16 {
        let after = chosen.get(round).copied().unwrap_or_else(|| next() % 250);
        let gently = round % 2 == 1;
        let counted = world.kill_a_worker(Duration::from_millis(after), gently).map_err(|error| {
            let how = if gently { "SIGTERM, then SIGKILL" } else { "SIGKILL" };
            format!("round {round}, seed {seed}: {how} after {after} ms: {error}")
        })?;
        reached += usize::from(counted == 2);
    }
    println!("        note: the killed worker's guess reached the helper, and was counted, in {reached} of 16 rounds");
    Ok(())
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
    for gone in [
        "/usr/local/lib64/security/pam_properpin.so",
        "/usr/local/libexec/properpin",
        "/usr/local/bin/properpin",
        "/etc/sysusers.d/properpin.conf",
        "/etc/tmpfiles.d/properpin.conf",
        RUN_DIR,
    ] {
        if Path::new(gone).exists() {
            return Err(format!("{gone} is still there after uninstall"));
        }
    }
    if !world.user_file().exists() {
        return Err("uninstall deleted the user's PIN file".into());
    }
    group_by_name(HELPER_GROUP).map_err(|_| "uninstall removed the group the kept PIN files belong to")?;
    if Account::by_name(HELPER_GROUP).is_ok() {
        return Err(format!("a user named {HELPER_GROUP} exists"));
    }
    if !world.budget_file().exists() {
        return Err("uninstall deleted the user's budget".into());
    }
    Ok(())
}

// --- the world the scenarios run in

struct World {
    user: Account,
    /// The group the helper runs with.
    helper_gid: u32,
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

/// One attempt's line from a worker.
#[derive(Debug)]
struct Answer {
    status: i32,
    prompts: usize,
    delays: usize,
    ms: u64,
}

impl Answer {
    fn all(output: &Output) -> Vec<Self> {
        let parse = |line: &str| -> Option<Self> {
            let words: Vec<&str> = line.split(' ').collect();
            match words[..] {
                ["status", status, "prompts", prompts, "delays", delays, "ms", ms] => Some(Self {
                    status: status.parse().ok()?,
                    prompts: prompts.parse().ok()?,
                    delays: delays.parse().ok()?,
                    ms: ms.parse().ok()?,
                }),
                _ => None,
            }
        };
        String::from_utf8_lossy(&output.stdout).lines().filter_map(parse).collect()
    }
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
        let helper_gid = group_by_name(HELPER_GROUP).map_err(message)?;

        properpin_as_root(&["set", "--user", USER], &format!("{PIN}\n{PIN}\n"))?;
        let checked = install_sh(&["check"])?;
        if !checked.contains("has properpin's lines") {
            return Err(format!("install.sh check after set:\n{checked}"));
        }
        let pin_file = fs::read(format!("/etc/properpin/users/{USER}")).map_err(message)?;
        Ok(Self { user, helper_gid, syslog, stock_kde, pin_file })
    }

    fn user_file(&self) -> PathBuf {
        PathBuf::from(format!("/etc/properpin/users/{USER}"))
    }

    fn config(&self) -> PathBuf {
        PathBuf::from("/etc/properpin/config")
    }

    fn state_file(&self) -> PathBuf {
        PathBuf::from(format!("{RUN_DIR}/{}.state", self.user.uid))
    }

    fn budget_file(&self) -> PathBuf {
        PathBuf::from(format!("{BUDGET_DIR}/{}.budget", self.user.uid))
    }

    fn budget(&self) -> Outcome<Budget> {
        let text = fs::read_to_string(self.budget_file()).map_err(message)?;
        Budget::parse(&text).ok_or_else(|| format!("the budget doesn't parse: {text}"))
    }

    fn edit_budget(&self, change: impl FnOnce(&mut Budget)) -> Outcome {
        let mut budget = self.budget()?;
        change(&mut budget);
        overwrite(&self.budget_file(), &budget.format())
    }

    /// What a reboot does to properpin: `/run` starts empty. The budget on disk stays.
    fn forget_this_boot(&self) -> Outcome {
        for entry in fs::read_dir(RUN_DIR).map_err(message)? {
            fs::remove_file(entry.map_err(message)?.path()).map_err(message)?;
        }
        Ok(())
    }

    /// Back to just after set-up: the PIN set, not armed, nothing tampered with.
    fn reset(&self) -> Outcome {
        let lock = PathBuf::from(format!("{RUN_DIR}/{}.lock", self.user.uid));
        for path in [self.state_file(), lock, self.budget_file(), self.config(), self.user_file().with_extension("real")] {
            match fs::remove_file(&path) {
                Err(error) if error.kind() != ErrorKind::NotFound => return Err(format!("{}: {error}", path.display())),
                _ => {}
            }
        }
        let _ = fs::remove_file(self.user_file());
        write_file(&self.user_file(), &String::from_utf8_lossy(&self.pin_file), 0, self.helper_gid, 0o640)?;
        for dir in [RUN_DIR, BUDGET_DIR] {
            chown(dir, Some(0), Some(self.helper_gid)).map_err(message)?;
            fs::set_permissions(dir, Permissions::from_mode(0o1770)).map_err(message)?;
        }
        let _ = fs::remove_dir_all(SCRATCH);
        self.syslog.take();
        Ok(())
    }

    /// Run `argv` as `user`, the way anything that user runs would: their uid and gid, a bare
    /// environment, `typed` on stdin.
    fn as_user(&self, user: &str, argv: &[&str], typed: &[u8]) -> Outcome<std::process::Output> {
        let account = Account::by_name(user).map_err(message)?;
        self.as_identity(account.uid, account.gid, argv, typed)
    }

    /// Run `argv` as `user` with the helper's group: what an exploited helper started by `user` could do.
    fn as_helper_group(&self, user: &str, argv: &[&str]) -> Outcome<std::process::Output> {
        let account = Account::by_name(user).map_err(message)?;
        self.as_identity(account.uid, self.helper_gid, argv, b"")
    }

    fn as_identity(&self, uid: u32, gid: u32, argv: &[&str], typed: &[u8]) -> Outcome<std::process::Output> {
        let mut child = Command::new(argv[0])
            .args(&argv[1..])
            .uid(uid)
            .gid(gid)
            .env_clear()
            .env("PATH", "/usr/bin")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(message)?;
        let _ = child.stdin.take().expect("piped").write_all(typed);
        child.wait_with_output().map_err(message)
    }

    /// Start one attempt as the test user, in their own process.
    fn spawn(&self, service: &str, typed: &str) -> Outcome<Child> {
        let mut child = self.start(&["attempt", service, USER])?;
        child.stdin.take().expect("piped").write_all(typed.as_bytes()).map_err(message)?;
        Ok(child)
    }

    /// Start this program with `args` as the test user, the way the lock screen runs as the
    /// locked user.
    fn start(&self, args: &[&str]) -> Outcome<Child> {
        Command::new(std::env::current_exe().map_err(message)?)
            .args(args)
            .uid(self.user.uid)
            .gid(self.user.gid)
            .env_clear()
            .env("PATH", "/usr/bin")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(message)
    }

    fn finish(&self, child: Child) -> Outcome<Attempt> {
        let output = self.wait_for(child)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let status = stdout.lines().find_map(|line| line.strip_prefix("status ")).and_then(|status| status.parse::<i32>().ok());
        let Some(status) = status else {
            return Err(format!("the attempt didn't finish: {}{}", stdout, String::from_utf8_lossy(&output.stderr)));
        };
        let prompts = stdout.lines().filter(|line| line.starts_with("prompt ")).count();
        Ok(Attempt { unlocked: status == pamharness::PAM_SUCCESS, prompts, log: self.syslog.take() })
    }

    /// Wait for a process started by `start`, which must exit by itself, cleanly: a crash after
    /// `pam_end`, as Rust modules have had at exit, would otherwise go unnoticed.
    fn wait_for(&self, mut child: Child) -> Outcome<Output> {
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
        if !output.status.success() {
            let said = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return Err(format!("the attempt process ended with {}, not exit 0:\n{said}{}", output.status, self.syslog.take()));
        }
        Ok(output)
    }

    /// One round of `a_killed_worker_loses_no_count`, with the PIN armed and no failures yet.
    /// Returns how many failures were counted: 2 when the killed worker's guess reached the helper.
    fn kill_a_worker(&self, after: Duration, gently: bool) -> Outcome<usize> {
        self.arm()?;
        let mut worker = self.start(&["worker", "kde", USER])?;
        // Kept open, so the worker waits for more rather than exiting.
        let mut stdin = worker.stdin.take().expect("piped");
        writeln!(stdin, "1111").map_err(message)?;
        thread::sleep(after);
        if gently {
            let pid = worker.id().to_string();
            Command::new("/usr/bin/kill").args(["-s", "TERM", &pid]).status().map_err(message)?;
            thread::sleep(Duration::from_millis(25));
        }
        let _ = worker.kill();
        let output = worker.wait_with_output().map_err(message)?;
        drop(stdin);
        if Answer::all(&output).iter().any(|answer| answer.status == pamharness::PAM_SUCCESS) {
            return Err(format!("the wrong PIN unlocked: {}", String::from_utf8_lossy(&output.stdout)));
        }
        let fresh = self.kde("2222")?;
        expect(!fresh.unlocked, "the fresh wrong PIN unlocked", &fresh)?;
        no_helper_left()?;
        let log = fresh.log + &self.syslog.take();
        if log.contains("PIN refused:") || log.contains("PIN not armed") {
            return Err(format!("an attempt got no answer from the helper:\n{log}"));
        }
        let counted = log.matches("not the PIN, failure").count();
        let text = fs::read_to_string(self.state_file()).map_err(message)?;
        let state = PinState::parse(&text).ok_or_else(|| format!("the state doesn't parse: {text}"))?;
        let budget = self.budget()?;
        if !(1..=2).contains(&counted) || state.failures as usize != counted || budget.pending.len() != counted {
            return Err(format!(
                "{counted} failures logged, {} in a row in the state, {} pending in the budget; they must agree, at 1 or 2:\n{log}",
                state.failures,
                budget.pending.len()
            ));
        }
        Ok(counted)
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
        overwrite(&self.state_file(), &state.format())
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

fn expect_code(output: &std::process::Output, code: u8, what: &str) -> Outcome {
    if output.status.code() == Some(code.into()) {
        return Ok(());
    }
    Err(format!(
        "{what}: exit {:?}, not {code}\n{}{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// No helper is still running, within the time one whose attempt was killed takes to finish.
/// Exited helpers nobody has reaped yet don't count.
fn no_helper_left() -> Outcome {
    let deadline = Instant::now() + HELPER_LINGER;
    loop {
        let running = running_helpers()?;
        if running.is_empty() {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!("helpers still running after {HELPER_LINGER:?}: pids {running:?}"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn running_helpers() -> Outcome<Vec<u32>> {
    let mut running = Vec::new();
    for entry in fs::read_dir("/proc").map_err(message)? {
        let Ok(pid) = entry.map_err(message)?.file_name().to_string_lossy().parse::<u32>() else { continue };
        // "pid (comm) state ...", where comm may itself contain ") ".
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(") ")) else { continue };
        let state = stat[close + 2..].chars().next();
        if &stat[open + 1..close] == HELPER_COMM && state != Some('Z') {
            running.push(pid);
        }
    }
    Ok(running)
}

/// Run the installed `properpin` command as root, `typed` on stdin.
fn properpin_as_root(args: &[&str], typed: &str) -> Outcome<String> {
    let output = Command::new("/usr/local/bin/properpin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().expect("piped").write_all(typed.as_bytes())?;
            child.wait_with_output()
        })
        .map_err(message)?;
    let said = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    if output.status.success() { Ok(said) } else { Err(format!("properpin {}: {said}", args.join(" "))) }
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

/// A new file with this owner and mode, replacing any file there. The old one is deleted first:
/// opening it with `O_CREAT` would fail even for root under `fs.protected_regular=2` (GitHub's
/// runners) when it is someone else's file in a sticky, group-writable directory.
fn write_file(path: &Path, text: &str, uid: u32, gid: u32, mode: u32) -> Outcome {
    match fs::remove_file(path) {
        Err(error) if error.kind() != ErrorKind::NotFound => return Err(format!("{}: {error}", path.display())),
        _ => {}
    }
    fs::write(path, text).map_err(message)?;
    chown(path, Some(uid), Some(gid)).map_err(message)?;
    fs::set_permissions(path, Permissions::from_mode(mode)).map_err(message)
}

/// Rewrite an existing file in place, so it keeps its owner and mode. Opened without `O_CREAT`,
/// which `fs.protected_regular=2` refuses even to root for another user's file in a sticky,
/// group-writable directory such as `/run/properpin`.
fn overwrite(path: &Path, text: &str) -> Outcome {
    let mut file = fs::OpenOptions::new().write(true).truncate(true).open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(text.as_bytes()).map_err(message)
}

fn message(error: impl std::fmt::Display) -> String {
    error.to_string()
}
