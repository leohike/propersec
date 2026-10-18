//! screenlock-pin's system test: the installed module and its setgid PIN checker in a stock Fedora, through
//! the real `/etc/pam.d`, the real `pam_unix` and its own setuid helper `unix_chkpwd`.
//!
//! It runs as root inside the container built from `testing/podman/Containerfile` (run it with
//! `just podman`), never on a real machine: it installs screenlock-pin, puts its line into
//! `/etc/pam.d/kde` with `integrate-into-pam.sh`, sets a PIN, and tampers with files as root.
//!
//! ```text
//! screenlock-pin-systest run                    every scenario in order; exit 1 if any fails
//! screenlock-pin-systest attempt SERVICE USER   one pam_authenticate, typing stdin, printing the outcome
//! screenlock-pin-systest worker SERVICE USER    one PAM session, an attempt for each line of stdin
//! screenlock-pin-systest uninstall-cases        the names of the uninstall cases, one per line
//! screenlock-pin-systest uninstall-case NAME    install a broken screenlock-pin, uninstall it, check the repair
//! ```
//!
//! `run` does each PAM attempt by starting `attempt` as the test user, the way the lock screen runs
//! as the locked user, and checks that the process exited cleanly. `worker` stands in for
//! kscreenlocker 6.8's `kscreenlocker_worker`: one session for many attempts, killed when the greeter
//! cancels. `run` listens on `/dev/log` itself, so what the module and `pam_unix` log through syslog
//! comes back to the scenario that caused it. After every scenario no PIN checker may still be running.
//!
//! The uninstall cases (`uninstall.rs`) each run in a fresh container: they install a deliberately
//! broken screenlock-pin and check that `integrate-into-pam.sh remove` and `install.sh uninstall` put the
//! system back as it was.

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
use screenlock_pin_core::{Budget, Clock, Settings, exit};
use screenlock_pin_sys::{Account, SystemClock, Yescrypt, group_by_name};

mod uninstall;

/// Where the Containerfile puts the build, `packaging/` and `pam/`.
const PRODUCT: &str = "/opt/screenlock-pin";
const USER: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";
const PIN: &str = "cat4859";
const KDE: &str = "/etc/pam.d/kde";
/// screenlock-pin's own PAM file, which `kde` names once `integrate-into-pam.sh add` has run.
const AUTH: &str = "/etc/pam.d/screenlock-auth";
const PIN_CHECKER: &str = "/usr/local/libexec/screenlock-pin/screenlock-pin-checker";
const MODULE: &str = "/usr/local/lib64/security/pam_screenlock_pin.so";
/// The group the PIN checker runs with, created by install.sh.
const PIN_CHECKER_GROUP: &str = "screenlock-pin";
const BUDGET_DIR: &str = "/var/lib/screenlock-pin";
/// Where scenarios that play the attacker keep their files; emptied between scenarios.
const SCRATCH: &str = "/tmp/screenlock-pin-scratch";
const SYSLOG: &str = "/dev/log";
/// Longer than any attempt takes, failure delays included; a hung attempt is killed after this.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);
/// A PIN checker whose attempt was killed finishes on its own: at most a second waiting for the lock,
/// then a hash. Still running after this, it is a bug.
const PIN_CHECKER_LINGER: Duration = Duration::from_secs(5);
/// What unpausing the PIN logs after a password unlock, through the `after-password-auth` line's
/// `pam_sm_setcred`, and never after a PIN unlock or a failure.
const UNPAUSED: &str = "unlocked with the password";

type Outcome<T = ()> = Result<T, String>;
type Scenario = fn(&World) -> Outcome;

// --- what the checks for absence look for. Each is derived from the installed paths, so a rename
// can't leave one stale, and each is shown to find its target in the same run (see the positive
// controls below), so a matcher that has gone wrong anyway fails instead of finding nothing and
// passing.

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().expect("a path")
}

/// What the kernel calls the PIN checker: its file name cut to 15 bytes (TASK_COMM_LEN, less the NUL).
fn pin_checker_comm() -> &'static str {
    let name = file_name(PIN_CHECKER);
    &name[..name.len().min(15)]
}

/// How every line the PIN checker logs begins: openlog's identity, its file name, and the pid.
fn pin_checker_log() -> String {
    format!("{}[", file_name(PIN_CHECKER))
}

/// How every line the module logs begins: pam_syslog puts the module's name, its file name without
/// `.so`, before the service and the call.
fn module_log() -> String {
    format!("{}(", file_name(MODULE).trim_end_matches(".so"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["run"] => run(),
        ["attempt", service, user] => attempt_here(service, user),
        ["worker", service, user] => worker_here(service, user),
        ["uninstall-cases"] => uninstall::list(),
        ["uninstall-case", name] => uninstall::run(name),
        _ => {
            eprintln!(
                "usage: screenlock-pin-systest run | attempt SERVICE USER | worker SERVICE USER | uninstall-cases | uninstall-case NAME"
            );
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
        ("the check for leftover PIN checkers sees one running", the_leftover_check_sees_a_running_pin_checker),
        ("the PIN unlocks from the start, with no password first", the_pin_unlocks_from_the_start),
        ("the password unlocks and unpauses the PIN", the_password_unpauses_the_pin),
        ("three wrong PINs pause the PIN until the password, on disk", three_wrong_pins_pause_the_pin),
        ("a wrong password never unpauses the PIN", a_wrong_password_never_unpauses_the_pin),
        ("set refuses the password as a PIN, and the PIN works at once", set_refuses_the_password_and_the_pin_works_at_once),
        ("setting the same PIN again asks first", setting_the_same_pin_again_asks_first),
        ("a password change leaves the PIN working", a_password_change_leaves_the_pin_working),
        ("the PIN works at the lock screen only", the_pin_works_at_the_lock_screen_only),
        ("a user file others can read is refused", a_user_file_others_can_read),
        ("a user file the user owns is refused", a_user_file_the_user_owns),
        ("a symlinked user file is refused", a_symlinked_user_file),
        ("a corrupt config is refused", a_corrupt_config),
        ("a hash in the global config is refused", a_hash_in_the_global_config),
        ("a shared budget directory is refused", a_shared_budget_directory),
        ("a user file its group can't read is refused, and doctor, as root, sees why", a_user_file_its_group_cannot_read),
        ("a lock file its owner can't open is refused, and doctor, as root, sees why", a_lock_file_its_owner_cannot_open),
        ("the user can't read their hash or touch their counts", the_user_cannot_reach_the_files),
        ("another user can't use or spend someone's PIN", another_user_gets_nothing),
        ("--dev options are refused under setgid", dev_options_are_refused_under_setgid),
        ("a poisoned start changes nothing", a_poisoned_start_changes_nothing),
        ("unpause asked for directly unpauses the PIN, as accepted", unpausing_needs_no_password),
        ("pam_setcred reaches the after-password-auth line after a password unlock only", setcred_follows_a_password_unlock_only),
        ("a missing PIN checker fails closed", a_missing_pin_checker_fails_closed),
        ("status shows your own PIN only", status_shows_your_own_pin),
        ("the PIN checker's group can't change the PIN checker", the_group_cannot_change_the_pin_checker),
        ("one user's PIN checker can't touch another's counts", one_users_pin_checker_cannot_touch_anothers_counts),
        ("counts planted in another user's name are refused", planted_counts_are_refused),
        ("the PIN checker's group stays empty and locked, with no account", the_group_stays_empty_and_locked),
        ("typed on a terminal without root, the command runs itself through sudo", the_command_runs_itself_through_sudo),
        ("typos followed by the PIN or the password are forgiven", typos_are_forgiven),
        ("the slow attack: a guess, the user's PIN much later, again", the_slow_attack_is_stopped),
        ("guesses nobody forgives disable the PIN, and the password can't help", unforgiven_guesses_disable_the_pin),
        ("the lifetime limit takes a new PIN", the_lifetime_limit_takes_a_new_pin),
        ("a damaged or planted budget refuses the PIN", a_damaged_or_planted_budget),
        ("concurrent wrong PINs are all counted", concurrent_wrong_pins_are_all_counted),
        ("one session serves many attempts, and the worker exits cleanly", one_session_serves_many_attempts),
        ("a killed worker never unlocks and loses no count", a_killed_worker_loses_no_count),
        ("a correct PIN waits out the minimum, and a kill meanwhile unlocks nothing", a_correct_pin_waits_out_the_minimum),
        ("installing again keeps the PIN and the line", installing_again_keeps_the_pin),
        ("kde naming a deleted screenlock-auth refuses everyone, and install mends it", a_deleted_screenlock_auth_refuses_everyone),
        ("install refuses a build that loads code from elsewhere", install_refuses_a_build_that_loads_code_from_elsewhere),
        ("uninstall leaves PAM as it was", uninstall_leaves_pam_as_it_was),
    ];
    let mut failed = 0;
    for (name, scenario) in scenarios {
        match world.reset().and_then(|()| scenario(&world)).and_then(|()| no_pin_checker_left()) {
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

fn the_pin_unlocks_from_the_start(world: &World) -> Outcome {
    world.pin_unlocks()?;
    world.pin_unlocks()?;
    world.password_unlocks()
}

fn the_password_unpauses_the_pin(world: &World) -> Outcome {
    world.unlock_with_password()?;
    world.pin_unlocks()
}

/// Three wrong PINs pause the PIN, and the count is in the budget on disk, so a reboot changes
/// nothing: nothing of screenlock-pin's is in /run any more. Only the password unpauses it.
fn three_wrong_pins_pause_the_pin(world: &World) -> Outcome {
    world.pin_refused("1111", "not the PIN, consecutive failure 1 of 3")?;
    world.pin_refused("2222", "not the PIN, consecutive failure 2 of 3")?;
    world.pin_refused("3333", "consecutive failure 3 of 3; PIN paused, password required")?;
    world.pin_refused(PIN, "PIN paused after 3 consecutive failures, password required")?;
    let consecutive = world.budget()?.consecutive;
    if consecutive != 3 {
        return Err(format!("{consecutive} consecutive in the budget, not 3"));
    }
    world.unlock_with_password()?;
    world.pin_unlocks()
}

/// The stock stack fails a wrong password, so the lock screen calls no `pam_setcred`, and the
/// PIN is never unpaused.
fn a_wrong_password_never_unpauses_the_pin(world: &World) -> Outcome {
    for wrong in ["1111", "2222", "3333"] {
        world.pin_refused(wrong, "not the PIN")?;
    }
    let wrong = world.kde("a wrong password, long enough")?;
    expect(!wrong.unlocked && !wrong.log.contains(UNPAUSED), "a wrong password unlocked or unpaused the PIN", &wrong)?;
    world.pin_refused(PIN, "PIN paused after 3 consecutive failures")?;
    // The positive control: the right password does log what the wrong one mustn't.
    world.unlock_with_password()
}

/// `set` compares the PIN with alice's hash in the real /etc/shadow, as root, so it never asks for
/// the password, and the new PIN works at once.
fn set_refuses_the_password_and_the_pin_works_at_once(world: &World) -> Outcome {
    match screenlock_pin_as_root(&["set", "--user", USER], &format!("{PASSWORD}\n{PASSWORD}\n")) {
        Err(said) if said.contains("the PIN must not be the password") => {}
        other => return Err(format!("set took the password as a PIN: {other:?}")),
    }
    let said = screenlock_pin_as_root(&["set", "--user", USER], "cat4860\ncat4860\n")?;
    if !said.contains("The lock screen takes it from now on") {
        return Err(format!("set said: {said}"));
    }
    world.pin_refused(PIN, "not the PIN, consecutive failure 1 of 3")?;
    let attempt = world.kde("cat4860")?;
    expect(attempt.unlocked && attempt.log.contains("unlocked with the PIN"), "the new PIN didn't unlock", &attempt)
}

/// The same PIN again would start its budget over, guesses and all, so set asks; without a
/// terminal it refuses unless --yes.
fn setting_the_same_pin_again_asks_first(world: &World) -> Outcome {
    match screenlock_pin_as_root(&["set", "--user", USER], &format!("{PIN}\n{PIN}\n")) {
        Err(said) if said.contains("This is the PIN already set") && said.contains("--yes skips the question") => {}
        other => return Err(format!("set didn't ask before keeping the same PIN: {other:?}")),
    }
    screenlock_pin_as_root(&["set", "--user", USER, "--yes"], &format!("{PIN}\n{PIN}\n"))?;
    world.pin_unlocks()
}

/// The PIN no longer depends on the password: after a password change both work.
fn a_password_change_leaves_the_pin_working(world: &World) -> Outcome {
    const NEW: &str = "a brand new password for alice";
    let _restore = Password::change(NEW)?;
    let new = world.kde(NEW)?;
    expect(new.unlocked && new.log.contains(&format!("{UNPAUSED}, PIN enabled")), "the new password didn't unlock", &new)?;
    world.pin_unlocks()
}

/// Every other service on the system checks only the password, and never even loads the module.
fn the_pin_works_at_the_lock_screen_only(world: &World) -> Outcome {
    world.module_and_pin_checker_log()?;
    for service in ["sudo", "su", "login", "system-auth", "password-auth", "passwd", "other"] {
        let pin = world.attempt(service, PIN)?;
        expect(!pin.unlocked, &format!("the PIN unlocked {service}"), &pin)?;
        expect(!pin.log.contains(&module_log()), &format!("{service} loaded the module"), &pin)?;
        expect(!pin.log.contains(&pin_checker_log()), &format!("{service} ran the PIN checker"), &pin)?;
    }
    for service in ["sudo", "su", "login"] {
        let password = world.attempt(service, PASSWORD)?;
        expect(password.unlocked, &format!("the password didn't unlock {service}"), &password)?;
    }
    world.pin_unlocks()
}

fn a_user_file_others_can_read(world: &World) -> Outcome {
    fs::set_permissions(world.user_file(), Permissions::from_mode(0o644)).map_err(message)?;
    world.fails_closed("readable by others")
}

fn a_user_file_the_user_owns(world: &World) -> Outcome {
    chown(world.user_file(), Some(world.user.uid), None).map_err(message)?;
    world.fails_closed("not 0")
}

fn a_symlinked_user_file(world: &World) -> Outcome {
    let real = world.user_file().with_extension("real");
    fs::rename(world.user_file(), &real).map_err(message)?;
    symlink(&real, world.user_file()).map_err(message)?;
    world.fails_closed("symbolic links")
}

fn a_corrupt_config(world: &World) -> Outcome {
    write_file(&world.config(), "this is not a setting\n", 0, 0, 0o644)?;
    world.fails_closed("expected 'key = value'")
}

fn a_hash_in_the_global_config(world: &World) -> Outcome {
    let user_file = String::from_utf8_lossy(&world.pin_file).into_owned();
    write_file(&world.config(), &user_file, 0, 0, 0o644)?;
    world.fails_closed("only a user's own file may hold hash")
}

fn a_shared_budget_directory(world: &World) -> Outcome {
    fs::set_permissions(BUDGET_DIR, Permissions::from_mode(0o1777)).map_err(message)?;
    world.fails_closed("mode 1777, not 1770")
}

/// The PIN checker can't open these, so it never sees why; doctor reads everything, as root, and
/// must find them all the same.
fn a_user_file_its_group_cannot_read(world: &World) -> Outcome {
    chown(world.user_file(), None, Some(0)).map_err(message)?;
    world.fails_closed_for(
        &format!("{}: Permission denied", world.user_file().display()),
        &format!("group 0, not {}", world.pin_checker_gid),
    )
}

fn a_lock_file_its_owner_cannot_open(world: &World) -> Outcome {
    let lock = format!("{BUDGET_DIR}/{}.lock", world.user.uid);
    fs::set_permissions(&lock, Permissions::from_mode(0o400)).map_err(message)?;
    world.fails_closed_for(&format!("{lock}: Permission denied"), "not readable and writable by its owner")
}

/// The point of the PIN checker: nothing the user runs can read the hash, or reset the counts.
fn the_user_cannot_reach_the_files(world: &World) -> Outcome {
    for wrong in ["1111", "2222", "3333"] {
        world.pin_refused(wrong, "not the PIN")?;
    }
    let state = world.budget_file().display().to_string();
    let user_file = world.user_file().display().to_string();
    for (what, script) in [
        ("read the hash", format!("cat {user_file}")),
        ("list the PIN files", "ls /etc/screenlock-pin/users".to_owned()),
        ("list the counts", format!("ls {BUDGET_DIR}")),
        ("read the counts", format!("cat {state}")),
        ("delete the counts", format!("rm -f {state}")),
        ("replace the counts", format!("echo garbage > {state}")),
    ] {
        let output = world.as_user(USER, &["sh", "-c", &script], b"")?;
        if output.status.success() {
            return Err(format!("{USER} could {what}: {}", String::from_utf8_lossy(&output.stdout)));
        }
    }
    world.pin_refused(PIN, "PIN paused after 3 consecutive failures")
}

/// bob has no PIN. Whatever he sends, he gets nothing about alice's, and spends none of her tries.
fn another_user_gets_nothing(world: &World) -> Outcome {
    for args in [&["check"][..], &["check", USER], &["status", USER]] {
        let output = world.as_user("bob", &[PIN_CHECKER].iter().chain(args).copied().collect::<Vec<_>>(), PIN.as_bytes())?;
        if output.status.code() == Some(exit::YES.into()) && args[0] == "check" {
            return Err(format!("bob's {args:?} said yes"));
        }
    }
    let bob = world.as_user("bob", &[PIN_CHECKER, "check"], b"1111")?;
    expect_code(&bob, exit::NO, "bob's wrong PIN")?;
    let log = world.syslog.take();
    if !log.contains("bob: no PIN is set, refused") {
        return Err(format!("the PIN checker didn't answer for bob:\n{log}"));
    }
    world.pin_unlocks()
}

/// The attack the --dev options would allow: point the PIN checker at files the caller made, holding a
/// hash of a PIN they chose. Under setgid it must refuse before reading anything.
fn dev_options_are_refused_under_setgid(world: &World) -> Outcome {
    let user = &world.user;
    let fake = Path::new(SCRATCH);
    fs::create_dir_all(fake.join("etc/users")).map_err(message)?;
    fs::create_dir_all(fake.join("var")).map_err(message)?;
    write_file(
        &fake.join("etc/users").join(USER),
        &format!("hash = {}\n", Yescrypt.hash("0000", 4).map_err(message)?),
        user.uid,
        user.gid,
        0o640,
    )?;
    for dir in [fake.to_path_buf(), fake.join("etc"), fake.join("etc/users"), fake.join("var")] {
        chown(&dir, Some(user.uid), Some(user.gid)).map_err(message)?;
        fs::set_permissions(&dir, Permissions::from_mode(0o700)).map_err(message)?;
    }
    let dev = ["--dev-etc", &format!("{SCRATCH}/etc"), "--dev-budget", &format!("{SCRATCH}/var"), "--dev-owner", &user.uid.to_string()];
    let started = world.as_user(USER, &[&[PIN_CHECKER, "unpause"][..], &dev].concat(), b"anything")?;
    expect_code(&started, exit::USAGE, "unpause with --dev options under setgid")?;
    let check = world.as_user(USER, &[&[PIN_CHECKER, "check"][..], &dev].concat(), b"0000")?;
    expect_code(&check, exit::USAGE, "check with --dev options under setgid")?;
    let log = world.syslog.take();
    if !log.contains("refused: --dev options while running with elevated rights") {
        return Err(format!("the refusal wasn't logged:\n{log}"));
    }
    Ok(())
}

/// Closed stdout and stderr, an extra open file, and a hostile environment, including a preloaded
/// library that would hijack an ordinary program: the PIN checker answers as always.
fn a_poisoned_start_changes_nothing(world: &World) -> Outcome {
    let script = format!(
        "exec 7</etc/hostname; LD_PRELOAD={SCRATCH}/evil.so LD_LIBRARY_PATH={SCRATCH} RUST_BACKTRACE=full LANG=xx_XX TZ=../../etc/shadow exec {PIN_CHECKER} check >&- 2>&-"
    );
    fs::create_dir_all(SCRATCH).map_err(message)?;
    fs::write(format!("{SCRATCH}/evil.so"), "not a library").map_err(message)?;
    let right = world.as_user(USER, &["sh", "-c", &script], PIN.as_bytes())?;
    expect_code(&right, exit::YES, "the right PIN with a poisoned start")?;
    let wrong = world.as_user(USER, &["sh", "-c", &script], b"1111")?;
    expect_code(&wrong, exit::NO, "a wrong PIN with a poisoned start")?;
    let log = world.syslog.take();
    if !log.contains("not the PIN, consecutive failure 1 of 3") {
        return Err(format!("the wrong PIN wasn't counted:\n{log}"));
    }
    Ok(())
}

/// Anything the user runs can ask the PIN checker to unpause the PIN, with no password, and it
/// unpauses the PIN: docs/chaos/security-target.md accepts that, since code running as the user can
/// unlock the session and keylog the PIN anyway.
fn unpausing_needs_no_password(world: &World) -> Outcome {
    for wrong in ["1111", "2222", "3333"] {
        world.pin_refused(wrong, "not the PIN")?;
    }
    world.pin_refused(PIN, "PIN paused after 3 consecutive failures")?;
    let done = world.as_user(USER, &[PIN_CHECKER, "unpause"], b"")?;
    expect_code(&done, exit::YES, "unpause asked for directly")?;
    world.pin_unlocks()
}

/// libpam calls the `after-password-auth` line's `pam_sm_setcred` after a password unlock through the real
/// pam_unix, and never after a PIN unlock or a wrong input.
fn setcred_follows_a_password_unlock_only(world: &World) -> Outcome {
    let pin = world.kde(PIN)?;
    expect(pin.unlocked && !pin.log.contains(UNPAUSED), "the PIN was unpaused after a PIN unlock", &pin)?;
    let wrong = world.kde("a wrong password, long enough")?;
    expect(!wrong.unlocked && !wrong.log.contains(UNPAUSED), "the PIN was unpaused after a wrong password", &wrong)?;
    // The positive control, with the same matcher.
    world.unlock_with_password()
}

fn a_missing_pin_checker_fails_closed(world: &World) -> Outcome {
    fs::rename(PIN_CHECKER, format!("{PIN_CHECKER}.away")).map_err(message)?;
    let pin = world.kde(PIN);
    let password = world.kde(PASSWORD);
    fs::rename(format!("{PIN_CHECKER}.away"), PIN_CHECKER).map_err(message)?;
    let (pin, password) = (pin?, password?);
    expect(!pin.unlocked && pin.log.contains("PIN refused:"), "the PIN worked without the PIN checker", &pin)?;
    expect(password.unlocked && password.log.contains("unpausing the PIN failed:"), "the password didn't unlock", &password)
}

fn status_shows_your_own_pin(world: &World) -> Outcome {
    let mine = world.as_user(USER, &["/usr/local/bin/screenlock-pin", "status"], b"")?;
    let text = String::from_utf8_lossy(&mine.stdout);
    if !mine.status.success()
        || !text.contains("hash                  set since ")
        || !text.contains("PIN                   enabled since ")
    {
        return Err(format!("alice's status: {text}{}", String::from_utf8_lossy(&mine.stderr)));
    }
    let bob = world.as_user("bob", &["/usr/local/bin/screenlock-pin", "status"], b"")?;
    if !String::from_utf8_lossy(&bob.stdout).contains("none set") {
        return Err(format!("bob's status: {}", String::from_utf8_lossy(&bob.stdout)));
    }
    let root = Command::new("/usr/local/bin/screenlock-pin").arg("status").output().map_err(message)?;
    if root.status.success() {
        return Err("status ran as root".into());
    }
    // The PIN checker itself refuses root too, whoever calls it.
    let pin_checker = Command::new(PIN_CHECKER).arg("status").stdin(Stdio::null()).output().map_err(message)?;
    expect_code(&pin_checker, exit::USAGE, "the PIN checker run by root")
}

/// bob with the PIN checker's group stands in for bob having exploited a bug in the PIN checker: whatever he
/// then does, the PIN checker itself stays root's, unchanged.
fn the_group_cannot_change_the_pin_checker(world: &World) -> Outcome {
    let before = fs::read(PIN_CHECKER).map_err(message)?;
    for (what, script) in [
        ("append to the PIN checker", format!("echo evil >> {PIN_CHECKER}")),
        ("chmod the PIN checker", format!("chmod 777 {PIN_CHECKER}")),
        ("rename the PIN checker", format!("mv {PIN_CHECKER} {PIN_CHECKER}.moved")),
        ("delete the PIN checker", format!("rm -f {PIN_CHECKER}")),
        ("replace the PIN checker", format!("cp /usr/bin/true {PIN_CHECKER}")),
    ] {
        let output = world.as_pin_checker_group("bob", &["sh", "-c", &script])?;
        if output.status.success() {
            return Err(format!("bob with group {PIN_CHECKER_GROUP} could {what}"));
        }
    }
    if fs::read(PIN_CHECKER).map_err(message)? != before {
        return Err("the PIN checker's bytes changed".into());
    }
    install_sh(&["check"]).map(drop)
}

/// Each user's counts file is that user's own, in a sticky directory: bob running the PIN checker, or
/// exploiting it, can't read, change, delete or replace alice's.
fn one_users_pin_checker_cannot_touch_anothers_counts(world: &World) -> Outcome {
    world.pin_refused("1111", "not the PIN, consecutive failure 1 of 3")?;
    let state = world.budget_file().display().to_string();
    for (what, script) in [
        ("read alice's counts", format!("cat {state}")),
        ("overwrite alice's counts", format!("echo garbage > {state}")),
        ("delete alice's counts", format!("rm -f {state}")),
        ("rename alice's counts", format!("mv {state} {BUDGET_DIR}/stolen")),
        ("replace alice's counts", format!("echo garbage > {BUDGET_DIR}/mine && mv -f {BUDGET_DIR}/mine {state}")),
    ] {
        let output = world.as_pin_checker_group("bob", &["sh", "-c", &script])?;
        if output.status.success() {
            return Err(format!("bob with group {PIN_CHECKER_GROUP} could {what}"));
        }
    }
    let _ = fs::remove_file(format!("{BUDGET_DIR}/mine"));
    world.pin_refused("2222", "not the PIN, consecutive failure 2 of 3")
}

/// `set` creates alice's lock file and budget, so while they are there bob with the PIN checker's
/// group can't plant his own in her name. Once they are gone (deleted here as root), he creates her
/// lock file, writable by anyone, and a fresh budget. Her PIN is refused, and the log says whose
/// lock file it is. The password still works, and `set` replaces them.
fn planted_counts_are_refused(world: &World) -> Outcome {
    let bob = Account::by_name("bob").map_err(message)?;
    let lock = format!("{BUDGET_DIR}/{}.lock", world.user.uid);
    let script = format!("umask 0 && touch {lock} && chmod 666 {lock} && cat > {}", world.budget_file().display());
    let planted = world.as_identity(bob.uid, world.pin_checker_gid, &["sh", "-c", &script], Budget::default().format().as_bytes())?;
    if planted.status.success() {
        return Err("bob could plant files over alice's".into());
    }
    for path in [PathBuf::from(&lock), world.budget_file()] {
        fs::remove_file(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    let planted = world.as_identity(bob.uid, world.pin_checker_gid, &["sh", "-c", &script], Budget::default().format().as_bytes())?;
    if !planted.status.success() {
        return Err(format!("couldn't plant the files: {}", String::from_utf8_lossy(&planted.stderr)));
    }
    // With fs.protected_regular=2 the kernel refuses alice's open of bob's lock file even sooner.
    let protected = fs::read_to_string("/proc/sys/fs/protected_regular").map_err(message)?.trim() == "2";
    let attempt = world.kde(PIN)?;
    let why = format!("owned by uid {}, not {}", bob.uid, world.user.uid);
    let refused = attempt.log.contains(&why) || (protected && attempt.log.contains("Permission denied"));
    expect(!attempt.unlocked && refused, &format!("the PIN wasn't refused with {why:?}"), &attempt)?;
    world.password_unlocks()?;
    // On disk the planted lock file would refuse the PIN for good; set clears it.
    screenlock_pin_as_root(&["set", "--user", USER, "--yes"], &format!("{PIN}\n{PIN}\n"))?;
    world.pin_unlocks()
}

/// Typed on a terminal without root, the command runs itself again through sudo, which would ask for
/// the password as typing sudo does; here it doesn't, since the scenario lets alice use sudo without
/// one, and only while it runs. `script` gives the command a terminal. Without one, the command
/// never starts sudo, and says to run it with sudo.
fn the_command_runs_itself_through_sudo(world: &World) -> Outcome {
    let piped = world.as_user(USER, &["/usr/local/bin/screenlock-pin", "doctor"], b"")?;
    let said = String::from_utf8_lossy(&piped.stderr);
    if piped.status.success() || !said.contains("run it with sudo") || said.contains("through sudo") {
        return Err(format!("without a terminal, doctor said: {said}"));
    }
    let sudoers = Path::new("/etc/sudoers.d/screenlock-pin-systest");
    write_file(sudoers, &format!("{USER} ALL=(root) NOPASSWD: ALL\n"), 0, 0, 0o440)?;
    let typed = world.as_user(USER, &["script", "-qec", "/usr/local/bin/screenlock-pin doctor", "/dev/null"], b"");
    fs::remove_file(sudoers).map_err(message)?;
    let typed = typed?;
    let said = format!("{}{}", String::from_utf8_lossy(&typed.stdout), String::from_utf8_lossy(&typed.stderr));
    if !typed.status.success()
        || !said.contains("runs again through sudo")
        || !said.contains(&format!("no problems; a PIN is set for {USER}"))
    {
        return Err(format!("on a terminal, doctor said: {said}"));
    }
    Ok(())
}

/// Anyone with the PIN checker's group can read every hash and change every count, so install.sh check
/// insists nobody has it: no members, and a locked password so newgrp can't give it. No account.
fn the_group_stays_empty_and_locked(_world: &World) -> Outcome {
    if Account::by_name(PIN_CHECKER_GROUP).is_ok() {
        return Err(format!("a user named {PIN_CHECKER_GROUP} exists"));
    }
    install_sh(&["check"])?;
    let (group, gshadow) = (fs::read("/etc/group").map_err(message)?, fs::read("/etc/gshadow").map_err(message)?);
    let result = (|| {
        let added = Command::new("usermod").args(["-aG", PIN_CHECKER_GROUP, "bob"]).status().map_err(message)?;
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
                if fields[0] == PIN_CHECKER_GROUP && fields.len() > 1 {
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
/// the right one. Nothing is left waiting, nothing is suspicious.
fn typos_are_forgiven(world: &World) -> Outcome {
    world.pin_refused("1111", "not the PIN, consecutive failure 1 of 3")?;
    world.pin_unlocks()?;
    let wrong = world.kde("a wrong password, long enough")?;
    expect(!wrong.unlocked, "a wrong password unlocked", &wrong)?;
    world.unlock_with_password()?;
    let budget = world.budget()?;
    if !budget.pending.is_empty() || budget.total != 0 {
        return Err(format!("typos were kept: {budget:?}"));
    }
    Ok(())
}

/// The repeated-access attack: a guess while the user is away, then the user's own correct PIN
/// two minutes later, which starts the consecutive count over but can't forgive the guess. With
/// the daily limit at 3, the third round finds the PIN disabled.
fn the_slow_attack_is_stopped(world: &World) -> Outcome {
    write_file(&world.config(), "max_suspicious_24h = 3\n", 0, 0, 0o644)?;
    for round in 1..=2 {
        world.pin_refused("1111", "not the PIN, consecutive failure 1 of 3")?;
        world.edit_budget(|budget| budget.pending.iter_mut().for_each(|at| *at -= 120))?;
        world.pin_unlocks().map_err(|error| format!("round {round}: {error}"))?;
    }
    world.pin_refused("1111", "not the PIN, consecutive failure 1 of 3")?;
    world.edit_budget(|budget| budget.pending.iter_mut().for_each(|at| *at -= 120))?;
    world.pin_refused(PIN, "PIN disabled after 3 suspicious failures within 24 hours")?;
    world.password_unlocks()
}

/// Nine suspicious failures already today, and one more guess the user never forgives: the PIN is
/// disabled, the password doesn't bring it back, and `enable`, after asking, does at once.
fn unforgiven_guesses_disable_the_pin(world: &World) -> Outcome {
    let now = SystemClock.now().map_err(message)?;
    world.edit_budget(|budget| {
        budget.suspicious = (1..=9).map(|hour| now - hour * 600).rev().collect();
        budget.total = 9;
    })?;
    world.pin_refused("1111", "not the PIN, consecutive failure 1 of 3")?;
    // Two minutes pass before the user comes back: too late to forgive the guess.
    world.edit_budget(|budget| budget.pending.iter_mut().for_each(|at| *at -= 120))?;
    let attempt = world.kde(PIN)?;
    let why = "PIN disabled after 10 suspicious failures within 24 hours";
    expect(!attempt.unlocked && attempt.log.contains("sudo screenlock-pin enable or set") && attempt.log.contains(why), why, &attempt)?;
    let password = world.kde(PASSWORD)?;
    expect(
        password.unlocked && password.log.contains("the PIN stays disabled after"),
        "the password brought a disabled PIN back",
        &password,
    )?;
    world.pin_refused(PIN, why)?;
    match screenlock_pin_as_root(&["enable", "--user", USER], "") {
        Err(said) if said.contains("may have been someone guessing it") && said.contains("--yes skips the question") => {}
        other => return Err(format!("enable didn't ask first: {other:?}")),
    }
    let enabled = screenlock_pin_as_root(&["enable", "--user", USER, "--yes"], "")?;
    if !enabled.contains("PIN enabled again") {
        return Err(format!("screenlock-pin enable said: {enabled}"));
    }
    world.pin_unlocks()
}

/// The total since the PIN was set has its own limit, which `enable` can't lift: only a new PIN.
fn the_lifetime_limit_takes_a_new_pin(world: &World) -> Outcome {
    world.edit_budget(|budget| budget.total = 59)?;
    world.pin_refused("1111", "not the PIN")?;
    world.edit_budget(|budget| budget.pending.iter_mut().for_each(|at| *at -= 120))?;
    world.pin_refused(PIN, "PIN disabled after 60 suspicious failures since the PIN was set")?;
    match screenlock_pin_as_root(&["enable", "--user", USER, "--yes"], "") {
        Err(said) if said.contains("choose a new one with: screenlock-pin set") => {}
        other => return Err(format!("enable lifted the lifetime limit: {other:?}")),
    }
    screenlock_pin_as_root(&["set", "--user", USER], "cat4860\ncat4860\n")?;
    let attempt = world.kde("cat4860")?;
    expect(attempt.unlocked, "the new PIN didn't unlock", &attempt)
}

/// A budget that can't be trusted is never read as a fresh one.
fn a_damaged_or_planted_budget(world: &World) -> Outcome {
    world.budget()?;
    overwrite(&world.budget_file(), "garbage\n")?;
    world.fails_closed("not a valid budget")?;
    // Planted by bob's PIN checker: private to bob, it can't even be opened; readable, its owner is wrong.
    let bob = Account::by_name("bob").map_err(message)?;
    write_file(&world.budget_file(), &Budget::default().format(), bob.uid, world.pin_checker_gid, 0o600)?;
    let owner = format!("owned by uid {}, not {}", bob.uid, world.user.uid);
    world.fails_closed_for(&format!("{}: Permission denied", world.budget_file().display()), &owner)?;
    write_file(&world.budget_file(), &Budget::default().format(), bob.uid, world.pin_checker_gid, 0o644)?;
    world.fails_closed(&format!("owned by uid {}, not {}", bob.uid, world.user.uid))
}

/// Three wrong PINs at once: each is counted, none is lost to another's write, and the PIN is then
/// paused.
fn concurrent_wrong_pins_are_all_counted(world: &World) -> Outcome {
    let children: Vec<Child> = ["1111", "2222", "3333"].into_iter().map(|wrong| world.spawn("kde", wrong)).collect::<Outcome<_>>()?;
    let mut log = String::new();
    for child in children {
        let attempt = world.finish(child)?;
        expect(!attempt.unlocked, "a wrong PIN unlocked", &attempt)?;
        log += &attempt.log;
    }
    for count in 1..=3 {
        if !log.contains(&format!("consecutive failure {count} of 3")) {
            return Err(format!("no attempt was counted as consecutive failure {count} of 3\n{log}"));
        }
    }
    world.pin_refused(PIN, "PIN paused after 3 consecutive failures")
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
    if !log.contains(&format!("{UNPAUSED}, PIN enabled"))
        || log.matches("unlocked with the PIN").count() != 2
        || !log.contains("consecutive failure 1 of 3")
    {
        return Err(format!("the log doesn't show the unpause, two PIN unlocks and one failure: {}", said()));
    }
    // kscreenlocker 6.8 takes an answer within 50 ms for a broken authenticator; the PIN checker makes
    // a correct PIN wait out min_milliseconds_before_pin_unlock, 75 ms with no config.
    let minimum = Settings::default().min_milliseconds_before_pin_unlock;
    if answers[1].ms < minimum || answers[3].ms < minimum {
        return Err(format!("a correct PIN took {} and {} ms, under the {minimum} ms minimum: {}", answers[1].ms, answers[3].ms, said()));
    }
    println!("        note: a correct PIN took {} and {} ms, with a minimum of {minimum}", answers[1].ms, answers[3].ms);
    Ok(())
}

/// With `min_milliseconds_before_pin_unlock` raised to a second, a correct PIN takes at least that
/// through the real stack. Killed while it waits, as the 6.8 greeter cancels, the worker unlocks
/// nothing; the PIN checker had already taken the PIN, so the consecutive count is reset as after any
/// correct PIN, its PIN checker is gone, and the PIN unlocks again afterwards.
fn a_correct_pin_waits_out_the_minimum(world: &World) -> Outcome {
    write_file(&world.config(), "min_milliseconds_before_pin_unlock = 1000\n", 0, 0, 0o644)?;
    let mut worker = world.start(&["worker", "kde", USER])?;
    writeln!(worker.stdin.take().expect("piped"), "{PIN}").map_err(message)?;
    let output = world.wait_for(worker)?;
    match Answer::all(&output)[..] {
        [Answer { status: pamharness::PAM_SUCCESS, ms, .. }] if ms >= 1000 => {}
        _ => return Err(format!("not one unlock after at least 1000 ms: {}", String::from_utf8_lossy(&output.stdout))),
    }
    world.pin_refused("1111", "not the PIN, consecutive failure 1 of 3")?;
    let mut worker = world.start(&["worker", "kde", USER])?;
    // Kept open, so the worker waits for more rather than exiting.
    let mut stdin = worker.stdin.take().expect("piped");
    writeln!(stdin, "{PIN}").map_err(message)?;
    thread::sleep(Duration::from_millis(500));
    let _ = worker.kill();
    let output = worker.wait_with_output().map_err(message)?;
    drop(stdin);
    if !Answer::all(&output).is_empty() {
        return Err(format!("the killed worker answered: {}", String::from_utf8_lossy(&output.stdout)));
    }
    no_pin_checker_left()?;
    let log = world.syslog.take();
    let consecutive = world.budget()?.consecutive;
    if !log.contains("unlocked with the PIN") || consecutive != 0 {
        return Err(format!("the PIN checker should have taken the PIN and reset the count, {consecutive} consecutive now:\n{log}"));
    }
    world.pin_unlocks()
}

/// The 6.8 greeter cancels by killing its worker: SIGTERM and SIGKILL 25 ms later, or SIGKILL at
/// once. A wrong PIN typed into a worker killed at chosen and random moments: no unlock, the PIN checker
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
    println!("        note: the killed worker's guess reached the PIN checker, and was counted, in {reached} of 16 rounds");
    Ok(())
}

/// An upgrade is the same install again: `kde` stays as it is, and so do the PIN and the budget.
fn installing_again_keeps_the_pin(world: &World) -> Outcome {
    let kde = fs::read_to_string(KDE).map_err(message)?;
    world.pin_refused("1111", "not the PIN, consecutive failure 1 of 3")?;
    // What an earlier version could leave: a program nothing uses any more.
    let stale = "/usr/local/libexec/screenlock-pin/screenlock-pin-old";
    fs::copy(PIN_CHECKER, stale).map_err(message)?;
    match install_sh(&["check"]) {
        Err(said) if said.contains(&format!("{stale}: not installed by this version")) => {}
        other => return Err(format!("check accepted {stale}: {other:?}")),
    }
    let said = install_sh(&["install"])?;
    if Path::new(stale).exists() {
        return Err(format!("install again left {stale}"));
    }
    if !said.contains("has screenlock-pin's line") || fs::read_to_string(KDE).map_err(message)? != kde {
        return Err(format!("install again changed {KDE}:\n{said}"));
    }
    if !said.contains(&format!("no problems; a PIN is set for {USER}")) {
        return Err(format!("install didn't print what screenlock-pin doctor found:\n{said}"));
    }
    world.pin_refused("2222", "not the PIN, consecutive failure 2 of 3")?;
    world.pin_unlocks()?;
    install_sh(&["check"]).map(drop)
}

/// The one new way to lock the lock screen: `kde` naming a `screenlock-auth` that is gone. libpam
/// then fails every attempt before any module asks for anything, the password too, while `sudo`,
/// the way in for a repair, works; check says so, and installing again puts the file back.
fn a_deleted_screenlock_auth_refuses_everyone(world: &World) -> Outcome {
    world.pin_unlocks()?;
    fs::remove_file(AUTH).map_err(message)?;
    let password = world.attempt("kde", PASSWORD)?;
    let missing = password.log.contains("unable to open config for screenlock-auth");
    expect(!password.unlocked && password.prompts == 0 && missing, "the password got further than libpam", &password)?;
    let sudo = world.attempt("sudo", PASSWORD)?;
    expect(sudo.unlocked, "sudo refused the password", &sudo)?;
    match integrate(&["check"]) {
        Err(said) if said.contains("is missing, so the lock screen refuses everyone") => {}
        other => return Err(format!("check didn't name the missing file: {other:?}")),
    }
    install_sh(&["install"])?;
    world.pin_unlocks()?;
    world.password_unlocks()
}

/// A build whose binaries would load libraries from outside the system's directories, such as from
/// a Homebrew toolchain's, is refused before install changes anything.
fn install_refuses_a_build_that_loads_code_from_elsewhere(world: &World) -> Outcome {
    let kde = fs::read(KDE).map_err(message)?;
    let pin_checker = fs::read(PIN_CHECKER).map_err(message)?;
    let from = Path::new(SCRATCH).join("bad-build");
    let _ = fs::remove_dir_all(&from);
    fs::create_dir_all(&from).map_err(message)?;
    for file in ["libpam_screenlock_pin.so", "screenlock-pin", "screenlock-pin-checker"] {
        fs::copy(format!("{PRODUCT}/build/{file}"), from.join(file)).map_err(message)?;
    }
    fs::copy(format!("{PRODUCT}/pin-checker-with-runpath"), from.join("screenlock-pin-checker")).map_err(message)?;
    fs::write(from.join("libpam_screenlock_pin.so"), "this is not a shared library\n").map_err(message)?;
    let from = from.to_str().ok_or("a scratch path that isn't UTF-8")?;
    let said = match install_sh_from(from, &["install"]) {
        Err(said) => said,
        Ok(said) => return Err(format!("install accepted the build:\n{said}")),
    };
    for expected in [
        "screenlock-pin-checker: has a library search path of its own, RUNPATH /home/linuxbrew/.linuxbrew/lib",
        "libpam_screenlock_pin.so: not a binary that loads the system's libraries",
        "nothing was changed",
    ] {
        if !said.contains(expected) {
            return Err(format!("install didn't say {expected:?}:\n{said}"));
        }
    }
    if fs::read(KDE).map_err(message)? != kde || fs::read(PIN_CHECKER).map_err(message)? != pin_checker {
        return Err(format!("install refused the build, but changed something:\n{said}"));
    }
    install_sh_from(from, &["check-build"]).map_or(Ok(()), |said| Err(format!("check-build accepted the build:\n{said}")))?;
    world.pin_unlocks()?;
    install_sh(&["check-build"])?;
    install_sh(&["check"]).map(drop)
}

/// Uninstall waits until remove has changed screenlock-pin's line back, since `kde` naming a deleted
/// `screenlock-auth` locks the lock screen; then the two together leave PAM as it was.
fn uninstall_leaves_pam_as_it_was(world: &World) -> Outcome {
    world.pin_unlocks()?;
    let installed = [
        AUTH,
        MODULE,
        "/usr/local/libexec/screenlock-pin",
        "/usr/local/bin/screenlock-pin",
        "/etc/sysusers.d/screenlock-pin.conf",
        "/etc/tmpfiles.d/screenlock-pin.conf",
    ];
    // The positive controls: what must be gone afterwards is there now, and logs as it should.
    if let Some(missing) = installed.iter().find(|path| !Path::new(path).exists()) {
        return Err(format!("{missing} isn't there before uninstall, so its absence afterwards would prove nothing"));
    }
    world.module_and_pin_checker_log()?;
    match install_sh(&["uninstall"]) {
        Err(said) if said.contains("uninstall waits until") && said.contains("nothing was removed") => {}
        other => return Err(format!("uninstall didn't wait for screenlock-pin's line to come out: {other:?}")),
    }
    if let Some(gone) = installed.iter().find(|path| !Path::new(path).exists()) {
        return Err(format!("uninstall refused, but removed {gone}"));
    }
    world.pin_unlocks()?;
    integrate(&["remove", "--yes"])?;
    install_sh(&["uninstall"])?;
    let kde = fs::read_to_string(KDE).map_err(message)?;
    if kde != world.stock_kde {
        return Err(format!("{KDE} after uninstall differs from before install:\n{kde}"));
    }
    let pin = world.kde(PIN)?;
    let screenlock_pin_ran = pin.log.contains(&module_log()) || pin.log.contains(&pin_checker_log());
    expect(!pin.unlocked && !screenlock_pin_ran, "the PIN still works after uninstall", &pin)?;
    world.password_unlocks()?;
    for gone in &installed {
        if Path::new(gone).exists() {
            return Err(format!("{gone} is still there after uninstall"));
        }
    }
    if !world.user_file().exists() {
        return Err("uninstall deleted the user's PIN file".into());
    }
    group_by_name(PIN_CHECKER_GROUP).map_err(|_| "uninstall removed the group the kept PIN files belong to")?;
    if Account::by_name(PIN_CHECKER_GROUP).is_ok() {
        return Err(format!("a user named {PIN_CHECKER_GROUP} exists"));
    }
    if !world.budget_file().exists() {
        return Err("uninstall deleted the user's budget".into());
    }
    Ok(())
}

// --- the world the scenarios run in

struct World {
    user: Account,
    /// The group the PIN checker runs with.
    pin_checker_gid: u32,
    syslog: Syslog,
    /// `/etc/pam.d/kde` before install.
    stock_kde: String,
    /// `/etc/pam.d/kde` once `integrate-into-pam.sh add` has put screenlock-pin's line in.
    integrated_kde: String,
    /// The user file `screenlock-pin set` wrote.
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
    /// Listen on syslog, install screenlock-pin, give the user a runtime directory, and set
    /// the PIN through the installed command.
    fn set_up() -> Outcome<Self> {
        if !Path::new("/run/.containerenv").exists() {
            return Err("not in a container; this test changes /etc/pam.d, so it runs in podman only".into());
        }
        let user = Account::by_name(USER).map_err(message)?;
        let syslog = Syslog::listen()?;
        let stock_kde = fs::read_to_string(KDE).map_err(message)?;

        install_sh(&["install"])?;
        if fs::read_to_string(KDE).map_err(message)? != stock_kde {
            return Err(format!("install changed {KDE}"));
        }
        integrate(&["add", "--yes"])?;
        let integrated_kde = fs::read_to_string(KDE).map_err(message)?;
        let pin_checker_gid = group_by_name(PIN_CHECKER_GROUP).map_err(message)?;

        screenlock_pin_as_root(&["set", "--user", USER], &format!("{PIN}\n{PIN}\n"))?;
        let checked = install_sh(&["check"])?;
        if !checked.contains("has screenlock-pin's line") {
            return Err(format!("install.sh check after set:\n{checked}"));
        }
        // The positive control for every scenario's doctor_finds: a clean system, judged clean.
        let doctor = screenlock_pin_as_root(&["doctor"], "")?;
        if !doctor.contains(&format!("no problems; a PIN is set for {USER}")) {
            return Err(format!("screenlock-pin doctor after set:\n{doctor}"));
        }
        let pin_file = fs::read(format!("/etc/screenlock-pin/users/{USER}")).map_err(message)?;
        Ok(Self { user, pin_checker_gid, syslog, stock_kde, integrated_kde, pin_file })
    }

    fn user_file(&self) -> PathBuf {
        PathBuf::from(format!("/etc/screenlock-pin/users/{USER}"))
    }

    fn config(&self) -> PathBuf {
        PathBuf::from("/etc/screenlock-pin/config")
    }

    fn budget_file(&self) -> PathBuf {
        PathBuf::from(format!("{BUDGET_DIR}/{}.budget", self.user.uid))
    }

    /// alice's budget, which `set` creates.
    fn budget(&self) -> Outcome<Budget> {
        let text = fs::read_to_string(self.budget_file()).map_err(message)?;
        Budget::parse(&text).ok_or_else(|| format!("the budget doesn't parse: {text}"))
    }

    fn edit_budget(&self, change: impl FnOnce(&mut Budget)) -> Outcome {
        let mut budget = self.budget()?;
        change(&mut budget);
        overwrite(&self.budget_file(), &budget.format())
    }

    /// Back to just after set-up: the PIN set and enabled, screenlock-pin's line in `kde` and its
    /// file next to it, nothing tampered with.
    fn reset(&self) -> Outcome {
        if fs::read_to_string(KDE).map_err(message)? != self.integrated_kde {
            fs::write(KDE, &self.integrated_kde).map_err(message)?;
        }
        if !Path::new(AUTH).exists() {
            install_sh(&["install"])?;
        }
        for path in [self.config(), self.user_file().with_extension("real")] {
            match fs::remove_file(&path) {
                Err(error) if error.kind() != ErrorKind::NotFound => return Err(format!("{}: {error}", path.display())),
                _ => {}
            }
        }
        let _ = fs::remove_file(self.user_file());
        write_file(&self.user_file(), &String::from_utf8_lossy(&self.pin_file), 0, self.pin_checker_gid, 0o640)?;
        chown(BUDGET_DIR, Some(0), Some(self.pin_checker_gid)).map_err(message)?;
        fs::set_permissions(BUDGET_DIR, Permissions::from_mode(0o1770)).map_err(message)?;
        // What screenlock-pin set leaves: an empty lock file and a fresh budget, both the user's.
        let lock = PathBuf::from(format!("{BUDGET_DIR}/{}.lock", self.user.uid));
        write_file(&lock, "", self.user.uid, self.pin_checker_gid, 0o600)?;
        let now = SystemClock.now().map_err(message)?;
        write_file(&self.budget_file(), &Budget::fresh(now).format(), self.user.uid, self.pin_checker_gid, 0o600)?;
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

    /// Run `argv` as `user` with the PIN checker's group: what an exploited PIN checker started by `user` could do.
    fn as_pin_checker_group(&self, user: &str, argv: &[&str]) -> Outcome<std::process::Output> {
        let account = Account::by_name(user).map_err(message)?;
        self.as_identity(account.uid, self.pin_checker_gid, argv, b"")
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

    /// One round of `a_killed_worker_loses_no_count`, after a password unlock, so with no failures yet.
    /// Returns how many failures were counted: 2 when the killed worker's guess reached the PIN checker.
    fn kill_a_worker(&self, after: Duration, gently: bool) -> Outcome<usize> {
        self.unlock_with_password()?;
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
        no_pin_checker_left()?;
        let log = fresh.log + &self.syslog.take();
        if log.contains("PIN refused:") || log.contains("unpausing the PIN failed") {
            return Err(format!("an attempt got no answer from the PIN checker:\n{log}"));
        }
        let counted = log.matches("not the PIN, consecutive failure").count();
        let budget = self.budget()?;
        if !(1..=2).contains(&counted) || budget.consecutive as usize != counted || budget.pending.len() != counted {
            return Err(format!(
                "{counted} failures logged, {} consecutive and {} pending in the budget; they must agree, at 1 or 2:\n{log}",
                budget.consecutive,
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

    /// Unlock the lock screen with the password, which unpauses the PIN.
    fn unlock_with_password(&self) -> Outcome {
        let attempt = self.kde(PASSWORD)?;
        expect(
            attempt.unlocked && attempt.log.contains(&format!("{UNPAUSED}, PIN enabled")),
            "the password didn't unpause the PIN",
            &attempt,
        )
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

    /// The positive control for the checks that something logs nothing of screenlock-pin's: an attempt
    /// at the lock screen that both the module and the PIN checker log, found with the same
    /// matchers. A setting the PIN checker doesn't know makes it log why it can't answer, and the
    /// module then logs that the PIN was refused.
    fn module_and_pin_checker_log(&self) -> Outcome {
        write_file(&self.config(), "no_such_setting = 1\n", 0, 0, 0o644)?;
        let attempt = self.kde(PIN);
        fs::remove_file(self.config()).map_err(message)?;
        let attempt = attempt?;
        let (module, pin_checker) = (module_log(), pin_checker_log());
        let found = attempt.log.contains(&module) && attempt.log.contains(&pin_checker);
        expect(!attempt.unlocked && found, &format!("{module:?} and {pin_checker:?} didn't both find a line"), &attempt)
    }

    /// Something is wrong with the files: the PIN is refused for `why`, the password still works,
    /// and doctor says the same.
    fn fails_closed(&self, why: &str) -> Outcome {
        self.fails_closed_for(why, why)
    }

    /// The same, for a file the PIN checker can't open, so that only doctor, which reads it as root,
    /// sees what is wrong with it: `doctor_why`.
    fn fails_closed_for(&self, why: &str, doctor_why: &str) -> Outcome {
        self.pin_refused(PIN, why)?;
        self.password_unlocks()?;
        doctor_finds(doctor_why)
    }
}

/// alice's password changed, and changed back when dropped, so a failing scenario doesn't leave
/// the next ones with the wrong password.
struct Password;

impl Password {
    fn change(new: &str) -> Outcome<Self> {
        chpasswd(new)?;
        Ok(Self)
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        if let Err(error) = chpasswd(PASSWORD) {
            println!("        could not put alice's password back: {error}");
        }
    }
}

fn chpasswd(password: &str) -> Outcome {
    let mut child = Command::new("chpasswd").stdin(Stdio::piped()).spawn().map_err(message)?;
    child.stdin.take().expect("piped").write_all(format!("{USER}:{password}\n").as_bytes()).map_err(message)?;
    let status = child.wait().map_err(message)?;
    if status.success() { Ok(()) } else { Err(format!("chpasswd: {status}")) }
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
        let mark = format!("screenlock-pin-systest mark {}", self.marks.fetch_add(1, Ordering::Relaxed));
        let sent = UnixDatagram::unbound().and_then(|socket| socket.send_to(mark.as_bytes(), SYSLOG));
        let (lines, arrived) = &*self.received;
        let mut lines = lines.lock().unwrap();
        if sent.is_ok() {
            lines = arrived.wait_timeout_while(lines, Duration::from_secs(10), |lines| !lines.contains(&mark)).unwrap().0;
        }
        lines.drain(..).filter(|line| !line.starts_with("screenlock-pin-systest mark ")).map(|line| line + "\n").collect()
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

/// No PIN checker is still running, within the time one whose attempt was killed takes to finish.
/// Exited PIN checkers nobody has reaped yet don't count.
/// The positive control for [`no_pin_checker_left`], which runs after every scenario: it does find
/// a PIN checker that is still running, here one waiting for its input. When the name it looks for
/// went stale after a rename, it found nothing, and so passed, whatever was running.
fn the_leftover_check_sees_a_running_pin_checker(world: &World) -> Outcome {
    let mut waiting = Command::new(PIN_CHECKER)
        .arg("check")
        .uid(world.user.uid)
        .gid(world.user.gid)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(message)?;
    let deadline = Instant::now() + PIN_CHECKER_LINGER;
    let seen = loop {
        match running_pin_checkers() {
            Ok(running) if running.contains(&waiting.id()) => break Ok(true),
            Ok(_) if Instant::now() > deadline => break Ok(false),
            Ok(_) => thread::sleep(Duration::from_millis(10)),
            Err(error) => break Err(error),
        }
    };
    // End of input: an empty one, which it refuses at once.
    drop(waiting.stdin.take());
    waiting.wait().map_err(message)?;
    match seen? {
        true => Ok(()),
        false => Err(format!("no process named {:?} found while a PIN checker was running", pin_checker_comm())),
    }
}

fn no_pin_checker_left() -> Outcome {
    let deadline = Instant::now() + PIN_CHECKER_LINGER;
    loop {
        let running = running_pin_checkers()?;
        if running.is_empty() {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!("PIN checkers still running after {PIN_CHECKER_LINGER:?}: pids {running:?}"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn running_pin_checkers() -> Outcome<Vec<u32>> {
    let mut running = Vec::new();
    for entry in fs::read_dir("/proc").map_err(message)? {
        let Ok(pid) = entry.map_err(message)?.file_name().to_string_lossy().parse::<u32>() else { continue };
        // "pid (comm) state ...", where comm may itself contain ") ".
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(") ")) else { continue };
        let state = stat[close + 2..].chars().next();
        if &stat[open + 1..close] != pin_checker_comm() || state == Some('Z') {
            continue;
        }
        // The cut name also fits other programs, this one among them (screenlock-pin-systest), so
        // the whole name is taken from argv[0], which the module sets to the installed path.
        let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else { continue };
        let argv0 = String::from_utf8_lossy(cmdline.split(|&byte| byte == 0).next().unwrap_or_default()).into_owned();
        if file_name(&argv0) == file_name(PIN_CHECKER) {
            running.push(pid);
        }
    }
    Ok(running)
}

/// Run the installed `screenlock-pin` command as root, `typed` on stdin.
fn screenlock_pin_as_root(args: &[&str], typed: &str) -> Outcome<String> {
    let output = Command::new("/usr/local/bin/screenlock-pin")
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
    if output.status.success() { Ok(said) } else { Err(format!("screenlock-pin {}: {said}", args.join(" "))) }
}

/// `screenlock-pin doctor`, as root, finds `why`: judged by the PIN checker's rules, with root's eyes.
fn doctor_finds(why: &str) -> Outcome {
    match screenlock_pin_as_root(&["doctor"], "") {
        Ok(said) => Err(format!("screenlock-pin doctor found nothing wrong:\n{said}")),
        Err(said) if said.contains(why) => Ok(()),
        Err(said) => Err(format!("screenlock-pin doctor didn't say {why:?}:\n{said}")),
    }
}

/// Run `packaging/integrate-into-pam.sh` against the real root.
fn integrate(args: &[&str]) -> Outcome<String> {
    let output = Command::new("bash")
        .arg(format!("{PRODUCT}/packaging/integrate-into-pam.sh"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(message)?;
    let said = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    if output.status.success() { Ok(said) } else { Err(format!("integrate-into-pam.sh {}:\n{said}", args.join(" "))) }
}

/// Run `packaging/install.sh` against the real root, from the container's build.
fn install_sh(args: &[&str]) -> Outcome<String> {
    install_sh_from(&format!("{PRODUCT}/build"), args)
}

/// The same, installing the build in `from`.
fn install_sh_from(from: &str, args: &[&str]) -> Outcome<String> {
    let output = Command::new("bash")
        .arg(format!("{PRODUCT}/packaging/install.sh"))
        .args(args)
        .args(["--from", from])
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
/// group-writable directory such as `/var/lib/screenlock-pin`.
fn overwrite(path: &Path, text: &str) -> Outcome {
    let mut file = fs::OpenOptions::new().write(true).truncate(true).open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(text.as_bytes()).map_err(message)
}

fn message(error: impl std::fmt::Display) -> String {
    error.to_string()
}
