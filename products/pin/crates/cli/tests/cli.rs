//! The `properpin` command, run as a subprocess against a sandboxed `--etc` and `--run-base` owned
//! by whoever runs the tests.

use std::fs::{self, Permissions};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;

use assert_cmd::Command;
use properpin_sys::current_uid;

struct Sandbox(tempfile::TempDir);

impl Sandbox {
    fn new() -> Self {
        let sandbox = Self(tempfile::tempdir().unwrap());
        let run_dir = sandbox.0.path().join("run").join(current_uid().to_string());
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&run_dir).unwrap();
        fs::set_permissions(&run_dir, Permissions::from_mode(0o700)).unwrap();
        sandbox
    }

    fn properpin(&self, args: &[&str], stdin: &str) -> assert_cmd::assert::Assert {
        let root = self.0.path();
        Command::cargo_bin("properpin")
            .unwrap()
            .env_remove("SUDO_USER")
            .env_remove("PKEXEC_UID")
            .args(["--etc", root.join("etc").to_str().unwrap(), "--run-base", root.join("run").to_str().unwrap()])
            .args(["--owner", &current_uid().to_string()])
            .args(args)
            .write_stdin(stdin)
            .assert()
    }

    fn user_files(&self) -> Vec<PathBuf> {
        fs::read_dir(self.0.path().join("etc/users")).map(|dir| dir.map(|entry| entry.unwrap().path()).collect()).unwrap_or_default()
    }
}

fn stdout(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

#[test]
fn set_then_status_then_remove() {
    let sandbox = Sandbox::new();
    sandbox.properpin(&["set"], "4859\n4859\n").success();
    let [file] = &sandbox.user_files()[..] else { panic!("expected one user file") };
    assert_eq!(fs::metadata(file).unwrap().mode() & 0o777, 0o640);
    assert!(fs::read_to_string(file).unwrap().starts_with("hash = $y$"));

    let status = stdout(&sandbox.properpin(&["status"], "").success());
    assert!(status.contains("PIN        set"), "{status}");
    assert!(status.contains("password required: no password unlock since boot"), "{status}");

    sandbox.properpin(&["remove"], "").success();
    sandbox.properpin(&["remove"], "").failure();
    assert!(stdout(&sandbox.properpin(&["status"], "").success()).contains("none set"));
}

#[test]
fn set_refuses_mismatches_and_weak_pins() {
    let sandbox = Sandbox::new();
    says(&sandbox.properpin(&["set"], "4859\n4860\n").failure(), "the two entries differ");
    says(&sandbox.properpin(&["set"], "48\n48\n").failure(), "at least 4 characters");
    assert!(sandbox.user_files().is_empty());
}

#[test]
fn dev_commands_walk_the_lock_screen_rules() {
    let sandbox = Sandbox::new();
    sandbox.properpin(&["set"], "4859\n4859\n").success();
    says(&sandbox.properpin(&["dev", "check"], "4859\n").failure(), "no password unlock since boot");
    sandbox.properpin(&["dev", "arm"], "").success();
    says(&sandbox.properpin(&["dev", "check"], "4859\n").success(), "unlocked with the PIN");
    for wrong in ["1111\n", "2222\n", "3333\n"] {
        sandbox.properpin(&["dev", "check"], wrong).failure();
    }
    says(&sandbox.properpin(&["dev", "check"], "4859\n").failure(), "3 failures in a row");
    assert!(stdout(&sandbox.properpin(&["status"], "").success()).contains("password required: 3 failures in a row"));
}

#[test]
fn paths_are_never_defaulted() {
    Command::cargo_bin("properpin").unwrap().arg("status").assert().failure();
}

/// Whether the command said `needle`, on stdout or stderr.
fn says(assert: &assert_cmd::assert::Assert, needle: &str) {
    let output = assert.get_output();
    let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(text.contains(needle), "expected {needle:?} in {text:?}");
}
