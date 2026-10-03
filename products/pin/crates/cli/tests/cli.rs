//! The `properpin` command, run as a subprocess against a sandboxed `--etc` owned by whoever runs
//! the tests, with `--helper` pointing at a script that runs the freshly built `properpin-helper`
//! against the same sandbox (through its `--dev-*` options, accepted because it isn't setgid).

use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use assert_cmd::Command;
use properpin_sys::current_uid;

const PASSWORD: &str = "correct horse battery staple";

struct Sandbox(tempfile::TempDir);

impl Sandbox {
    fn new() -> Self {
        let sandbox = Self(tempfile::tempdir().unwrap());
        let root = sandbox.0.path();
        fs::create_dir(root.join("run")).unwrap();
        // Set explicitly: the umask would strip the group's write bit from a mkdir mode.
        fs::set_permissions(root.join("run"), Permissions::from_mode(0o1770)).unwrap();
        let chkpwd = format!("#!/bin/bash\nIFS= read -r -d '' password\n[[ $password == '{PASSWORD}' ]]\n");
        script(&root.join("unix_chkpwd"), &chkpwd);
        let helper = format!(
            "#!/bin/sh\nexec {} \"$@\" --dev-etc {root}/etc --dev-run {root}/run --dev-chkpwd {root}/unix_chkpwd --dev-log {root}/log\n",
            built_helper().display(),
            root = root.display()
        );
        script(&root.join("helper"), &helper);
        sandbox
    }

    fn properpin(&self, args: &[&str], stdin: &str) -> assert_cmd::assert::Assert {
        let root = self.0.path();
        Command::cargo_bin("properpin")
            .unwrap()
            .env_remove("SUDO_USER")
            .env_remove("PKEXEC_UID")
            .args(["--etc", root.join("etc").to_str().unwrap(), "--helper", root.join("helper").to_str().unwrap()])
            .args(["--owner", &current_uid().to_string(), "--group", &helper_gid().to_string()])
            .args(args)
            .write_stdin(stdin)
            .assert()
    }

    /// What the lock screen's arm line does after a correct password.
    fn arm(&self) {
        let status = std::process::Command::new(self.0.path().join("helper"))
            .arg("arm")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                std::io::Write::write_all(&mut child.stdin.take().unwrap(), PASSWORD.as_bytes())?;
                child.wait()
            })
            .unwrap();
        assert!(status.success());
    }

    fn user_files(&self) -> Vec<PathBuf> {
        fs::read_dir(self.0.path().join("etc/users")).map(|dir| dir.map(|entry| entry.unwrap().path()).collect()).unwrap_or_default()
    }
}

fn stdout(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

fn script(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o755)).unwrap();
}

/// The test user's primary group, which stands in for the helper's.
fn helper_gid() -> u32 {
    properpin_sys::Account::by_uid(current_uid()).unwrap().gid
}

/// The directory with a fresh `properpin-helper`, built once per test run.
fn built_helper() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let profile_dir = std::env::current_exe().unwrap().parent().and_then(Path::parent).unwrap().to_path_buf();
        let mut cargo = std::process::Command::new(env!("CARGO"));
        cargo.args([
            "build",
            "--quiet",
            "--package",
            "properpin-helper",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
        ]);
        if profile_dir.ends_with("release") {
            cargo.arg("--release");
        }
        assert!(cargo.status().unwrap().success(), "building properpin-helper failed");
        profile_dir.join("properpin-helper")
    })
}

#[test]
fn set_then_status_then_remove() {
    let sandbox = Sandbox::new();
    sandbox.properpin(&["set"], "4859\n4859\n").success();
    let [file] = &sandbox.user_files()[..] else { panic!("expected one user file") };
    assert_eq!(fs::metadata(file).unwrap().mode() & 0o777, 0o640);
    assert_eq!(fs::metadata(file).unwrap().gid(), helper_gid(), "readable by the helper's group");
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
fn status_shows_what_the_helper_sees() {
    let sandbox = Sandbox::new();
    sandbox.properpin(&["set"], "4859\n4859\n").success();
    sandbox.arm();
    let status = stdout(&sandbox.properpin(&["status"], "").success());
    assert!(status.contains("PIN armed for another"), "{status}");
    fs::remove_file(sandbox.0.path().join("helper")).unwrap();
    says(&sandbox.properpin(&["status"], "").failure(), "helper");
}

#[test]
fn set_needs_the_helper_group_to_exist() {
    let sandbox = Sandbox::new();
    let assert = Command::cargo_bin("properpin")
        .unwrap()
        .args(["--etc", sandbox.0.path().join("etc").to_str().unwrap(), "--helper", "/nonexistent"])
        .args(["--owner", &current_uid().to_string(), "--group", "no-such-group-properpin", "set"])
        .write_stdin("4859\n4859\n")
        .assert()
        .failure();
    says(&assert, "no group named");
    assert!(sandbox.user_files().is_empty());
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
