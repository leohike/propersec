//! The real `properpin-helper` binary, run as a subprocess without setgid, so its `--dev-*` options
//! point it at a sandbox owned by whoever runs the tests. `unix_chkpwd` is replaced by a script
//! that accepts one password. What needs real setgid (the dev options refused, other users kept
//! out) is in the container test.

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use properpin_core::{MAX_INPUT_BYTES, exit};
use properpin_sys::{Account, Yescrypt, current_uid};

const HELPER: &str = env!("CARGO_BIN_EXE_properpin-helper");
const PIN: &str = "4859";
const PASSWORD: &str = "correct horse battery staple";

struct Sandbox {
    dir: tempfile::TempDir,
}

/// What one run of the helper came to.
#[derive(Debug)]
struct Run {
    code: Option<i32>,
    stdout: String,
}

impl Sandbox {
    fn new() -> Self {
        let sandbox = Self { dir: tempfile::tempdir().unwrap() };
        for shared in ["run", "var"] {
            fs::create_dir(sandbox.path(shared)).unwrap();
            // Set explicitly: the umask would strip the group's write bit from a mkdir mode.
            fs::set_permissions(sandbox.path(shared), Permissions::from_mode(0o1770)).unwrap();
        }
        let user = Account::by_uid(current_uid()).unwrap().name;
        let user_file = sandbox.path("etc/users").join(&user);
        fs::create_dir_all(user_file.parent().unwrap()).unwrap();
        fs::write(&user_file, format!("hash = {}\n", Yescrypt.hash(PIN, 4).unwrap())).unwrap();
        fs::set_permissions(&user_file, Permissions::from_mode(0o640)).unwrap();
        let chkpwd = sandbox.path("unix_chkpwd");
        let script = format!("#!/bin/bash\nIFS= read -r -d '' password\n[[ $1 == \"$(id -un)\" && $password == '{PASSWORD}' ]]\n");
        fs::write(&chkpwd, script).unwrap();
        fs::set_permissions(&chkpwd, Permissions::from_mode(0o755)).unwrap();
        sandbox
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }

    fn dev_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for (option, path) in
            [("--dev-etc", "etc"), ("--dev-run", "run"), ("--dev-budget", "var"), ("--dev-chkpwd", "unix_chkpwd"), ("--dev-log", "log")]
        {
            args.extend([option.to_owned(), self.path(path).display().to_string()]);
        }
        args
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(HELPER);
        command.args(args).args(self.dev_args());
        command
    }

    fn run(&self, args: &[&str], stdin: &[u8]) -> Run {
        run(self.command(args), stdin)
    }

    fn check(&self, typed: &str) -> Option<i32> {
        self.run(&["check"], typed.as_bytes()).code
    }

    fn arm(&self) {
        assert_eq!(self.run(&["arm"], PASSWORD.as_bytes()).code, Some(exit::YES.into()));
    }

    fn log(&self) -> String {
        fs::read_to_string(self.path("log")).unwrap_or_default()
    }

    fn status(&self) -> String {
        self.run(&["status"], b"").stdout
    }
}

fn run(mut command: Command, stdin: &[u8]) -> Run {
    let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    // A helper that refuses its arguments exits without reading, so the pipe may already be closed.
    match std::io::Write::write_all(&mut child.stdin.take().unwrap(), stdin) {
        Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => panic!("{error}"),
        _ => {}
    }
    let output = child.wait_with_output().unwrap();
    Run { code: output.status.code(), stdout: String::from_utf8_lossy(&output.stdout).into_owned() }
}

const YES: Option<i32> = Some(exit::YES as i32);
const NO: Option<i32> = Some(exit::NO as i32);
const USAGE: Option<i32> = Some(exit::USAGE as i32);

#[test]
fn the_whole_cycle_through_the_binary() {
    let sandbox = Sandbox::new();
    assert_eq!(sandbox.check(PIN), NO);
    assert!(sandbox.log().contains("PIN refused, password required: no password unlock since boot"), "{}", sandbox.log());
    sandbox.arm();
    assert_eq!(sandbox.check(PIN), YES);
    for wrong in ["1111", "2222", "3333"] {
        assert_eq!(sandbox.check(wrong), NO);
    }
    assert_eq!(sandbox.check(PIN), NO);
    assert!(sandbox.status().contains("password required: 3 failures in a row"), "{}", sandbox.status());
}

#[test]
fn a_wrong_password_never_arms() {
    let sandbox = Sandbox::new();
    assert_eq!(sandbox.run(&["arm"], b"not the password").code, NO);
    assert_eq!(sandbox.check(PIN), NO);
    assert!(sandbox.log().contains("the password was not accepted, PIN not armed"), "{}", sandbox.log());
}

#[test]
fn input_that_cannot_be_a_pin_is_refused_and_not_counted() {
    let sandbox = Sandbox::new();
    sandbox.arm();
    let long = vec![b'1'; MAX_INPUT_BYTES * 4];
    for typed in [&b""[..], b"48\x0059", b"\xff\xfe", &long] {
        assert_eq!(sandbox.run(&["check"], typed).code, NO);
    }
    assert!(sandbox.status().contains("0 of 3 failures so far"), "{}", sandbox.status());
}

#[test]
fn anything_unexpected_on_the_command_line_is_refused() {
    let sandbox = Sandbox::new();
    let dev = sandbox.dev_args();
    let dev: Vec<&str> = dev.iter().map(String::as_str).collect();
    for args in [
        &[][..],
        &["frobnicate"],
        &["check", "check"],
        &["check", "alice"],
        &["--check"],
        &["check", "--dev-etc"],
        &["check", "--dev-etc", "/tmp"],
        &["check", "--dev-owner", "root", "--dev-etc", "/tmp", "--dev-run", "/tmp"],
        &["check", "--dev-everything", "/tmp"],
    ] {
        let mut command = Command::new(HELPER);
        command.args(args);
        if args.first() == Some(&"frobnicate") {
            command.args(&dev);
        }
        assert_eq!(run(command, PIN.as_bytes()).code, USAGE, "{args:?}");
    }
}

/// Closed stdin, stdout and stderr, a hostile environment, odd open files: the same answers.
#[test]
fn a_poisoned_start_changes_nothing() {
    let sandbox = Sandbox::new();
    sandbox.arm();
    let hostile = |mut command: Command| {
        command
            .env("RUST_BACKTRACE", "full")
            .env("LANG", "xx_XX.garbage")
            .env("TZ", "../../../etc/passwd")
            .env("PATH", "/nonexistent")
            .env("HOME", "/nonexistent")
            .env("MALLOC_PERTURB_", "165");
        command
    };
    assert_eq!(run(hostile(sandbox.command(&["check"])), PIN.as_bytes()).code, YES);
    assert_eq!(run(hostile(sandbox.command(&["check"])), b"1111").code, NO);

    // Closed stdout and stderr, and an extra file left open, through the shell.
    let mut shell = Command::new("sh");
    shell.args(["-c", "exec 7</dev/null; exec \"$0\" check \"$@\" >&- 2>&-", HELPER]).args(sandbox.dev_args());
    assert_eq!(run(shell, PIN.as_bytes()).code, YES);
    // Closed stdin reads as nothing typed.
    let mut shell = Command::new("sh");
    shell.args(["-c", "exec \"$0\" check \"$@\" <&-", HELPER]).args(sandbox.dev_args());
    assert_eq!(run(shell, b"").code, NO);
    // The wrong PIN was counted, the right one reset it, and nothing typed isn't counted.
    assert!(sandbox.status().contains("0 of 3 failures so far"), "{}", sandbox.status());
    assert!(sandbox.log().contains("not the PIN, failure 1 of 3"), "{}", sandbox.log());
}

#[test]
fn files_it_cannot_trust_are_refused() {
    let sandbox = Sandbox::new();
    sandbox.arm();
    fs::set_permissions(sandbox.path("run"), Permissions::from_mode(0o755)).unwrap();
    assert_eq!(sandbox.check(PIN), Some(exit::BROKEN.into()));
    assert!(sandbox.log().contains("mode 0755, not 1770"), "{}", sandbox.log());

    let sandbox = Sandbox::new();
    let mut command = sandbox.command(&["check"]);
    command.args(["--dev-owner", &(current_uid() + 1).to_string()]);
    assert_eq!(run(command, PIN.as_bytes()).code, Some(exit::BROKEN.into()));
    assert!(sandbox.log().contains("owned by uid"), "{}", sandbox.log());
}

#[test]
fn the_password_checker_must_exist() {
    let sandbox = Sandbox::new();
    fs::remove_file(sandbox.path("unix_chkpwd")).unwrap();
    assert_eq!(sandbox.run(&["arm"], PASSWORD.as_bytes()).code, Some(exit::BROKEN.into()));
    assert_eq!(sandbox.check(PIN), NO);
}

#[test]
fn status_needs_no_input_and_prints_the_rules() {
    let sandbox = Sandbox::new();
    let status = sandbox.status();
    assert!(status.contains("PIN        set") && status.contains("policy     armed for 8h"), "{status}");
    assert!(!Path::new(&sandbox.path("run")).read_dir().unwrap().any(|_| true), "status wrote nothing");
}
