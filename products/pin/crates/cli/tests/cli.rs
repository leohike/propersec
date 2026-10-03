//! The `properpin` command, run as a subprocess against a sandboxed `--etc` owned by whoever runs
//! the tests, with `--helper` pointing at a script that runs the freshly built `properpin-helper`
//! against the same sandbox (through its `--dev-*` options, accepted because it isn't setgid).

use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use assert_cmd::Command;
use properpin_core::{Budget, Disabled, Limit};
use properpin_sys::current_uid;

const PASSWORD: &str = "correct horse battery staple";

struct Sandbox(tempfile::TempDir);

impl Sandbox {
    fn new() -> Self {
        let sandbox = Self(tempfile::tempdir().unwrap());
        let root = sandbox.0.path();
        for shared in ["run", "var"] {
            fs::create_dir(root.join(shared)).unwrap();
            // Set explicitly: the umask would strip the group's write bit from a mkdir mode.
            fs::set_permissions(root.join(shared), Permissions::from_mode(0o1770)).unwrap();
        }
        let chkpwd = format!("#!/bin/bash\nIFS= read -r -d '' password\n[[ $password == '{PASSWORD}' ]]\n");
        script(&root.join("unix_chkpwd"), &chkpwd);
        let helper = format!(
            "#!/bin/sh\nexec {} \"$@\" --dev-etc {root}/etc --dev-run {root}/run --dev-budget {root}/var --dev-chkpwd {root}/unix_chkpwd --dev-log {root}/log\n",
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
            .args(["--budget", root.join("var").to_str().unwrap(), "--run", root.join("run").to_str().unwrap()])
            .args(["--chkpwd", root.join("unix_chkpwd").to_str().unwrap()])
            .args(["--owner", &current_uid().to_string(), "--group", &helper_gid().to_string()])
            .args(args)
            .write_stdin(stdin)
            .assert()
    }

    /// What the lock screen's arm line does after a correct password. It must arm the PIN.
    fn arm(&self) {
        assert!(self.try_arm(), "the password didn't arm the PIN");
    }

    fn try_arm(&self) -> bool {
        let status = std::process::Command::new(self.0.path().join("helper"))
            .arg("arm")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                std::io::Write::write_all(&mut child.stdin.take().unwrap(), PASSWORD.as_bytes())?;
                child.wait()
            })
            .unwrap();
        status.success()
    }

    /// Replace the user's budget with `budget`, the way the helper would have written it.
    fn write_budget(&self, budget: &Budget) {
        let path = self.0.path().join(format!("var/{}.budget", current_uid()));
        fs::write(&path, budget.format()).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    }

    fn user_files(&self) -> Vec<PathBuf> {
        fs::read_dir(self.0.path().join("etc/users")).map(|dir| dir.map(|entry| entry.unwrap().path()).collect()).unwrap_or_default()
    }
}

/// What `set` reads: the PIN, the same again, and the password.
fn new_pin(pin: &str, again: &str) -> String {
    format!("{pin}\n{again}\n{PASSWORD}\n")
}

/// What the lock screen's PIN line does: whether `pin` unlocks right now.
fn unlocks(sandbox: &Sandbox, pin: &str) -> bool {
    let mut child =
        std::process::Command::new(sandbox.0.path().join("helper")).arg("check").stdin(std::process::Stdio::piped()).spawn().unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), pin.as_bytes()).unwrap();
    child.wait().unwrap().success()
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
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
    let [file] = &sandbox.user_files()[..] else { panic!("expected one user file") };
    assert_eq!(fs::metadata(file).unwrap().mode() & 0o777, 0o640);
    assert_eq!(fs::metadata(file).unwrap().gid(), helper_gid(), "readable by the helper's group");
    let text = fs::read_to_string(file).unwrap();
    assert!(
        text.starts_with("hash = $y$")
            && text.contains("\ncleartext_salt_for_deriving_pepper_decryption_key = $y$jCT$")
            && text.contains("\nencrypted_pepper = "),
        "{text}"
    );

    // Armed at once: set had the password, so it had the pepper.
    let status = stdout(&sandbox.properpin(&["status"], "").success());
    assert!(status.contains("PIN        set"), "{status}");
    assert!(status.contains("PIN armed for another"), "{status}");
    assert!(unlocks(&sandbox, "4859"));
    assert!(!unlocks(&sandbox, "4860"));

    let state = sandbox.0.path().join(format!("run/{}.state", current_uid()));
    assert!(state.exists());
    sandbox.properpin(&["remove"], "").success();
    assert!(!state.exists(), "remove leaves no pepper in memory");
    sandbox.properpin(&["remove"], "").failure();
    assert!(stdout(&sandbox.properpin(&["status"], "").success()).contains("none set"));
}

#[test]
fn set_refuses_mismatches_and_weak_pins() {
    let sandbox = Sandbox::new();
    says(&sandbox.properpin(&["set"], &new_pin("4859", "4860")).failure(), "the two entries differ");
    says(&sandbox.properpin(&["set"], &new_pin("48", "48")).failure(), "at least 4 characters");
    says(&sandbox.properpin(&["set"], "4859\n4859\nnot the password\n").failure(), "that is not the password of");
    says(&sandbox.properpin(&["set"], "4859\n4859\n\n").failure(), "that is not the password of");
    assert!(sandbox.user_files().is_empty());
    assert_eq!(fs::read_dir(sandbox.0.path().join("run")).unwrap().count(), 0, "nothing armed");
}

#[test]
fn the_pin_may_not_be_the_password() {
    let sandbox = Sandbox::new();
    let config = sandbox.0.path().join("etc/config");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "max_pin_length = 64\n").unwrap();
    says(&sandbox.properpin(&["set"], &format!("{PASSWORD}\n{PASSWORD}\n{PASSWORD}\n")).failure(), "the PIN must not be the password");
    assert!(sandbox.user_files().is_empty());
}

/// Seal cost 8 is the default; one PIN set at it unseals and unlocks like any other.
#[test]
fn a_set_pin_survives_a_reboot_through_the_password() {
    let sandbox = Sandbox::new();
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
    // A reboot empties the run directory.
    for entry in fs::read_dir(sandbox.0.path().join("run")).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    assert!(!unlocks(&sandbox, "4859"));
    sandbox.arm();
    assert!(unlocks(&sandbox, "4859"));
}

#[test]
fn status_shows_what_the_helper_sees() {
    let sandbox = Sandbox::new();
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
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
        .args([
            "--etc",
            sandbox.0.path().join("etc").to_str().unwrap(),
            "--helper",
            "/nonexistent",
            "--budget",
            "/nonexistent",
            "--run",
            "/nonexistent",
        ])
        .args(["--owner", &current_uid().to_string(), "--group", "no-such-group-properpin", "set"])
        .write_stdin(new_pin("4859", "4859"))
        .assert()
        .failure();
    says(&assert, "no group named");
    assert!(sandbox.user_files().is_empty());
}

/// A PIN disabled by its budget: `enable` brings the same PIN back, until the total since it was
/// set reaches its limit; then only `set` does, and starts the budget over.
#[test]
fn enable_and_set_bring_a_disabled_pin_back() {
    let sandbox = Sandbox::new();
    says(&sandbox.properpin(&["enable"], "").failure(), "no PIN is set");
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
    let disabled = Some(Disabled { limit: Limit::Day(10), at: 1_800_000_000 });
    sandbox.write_budget(&Budget { concerning: vec![1_800_000_000], total: 10, disabled, ..Budget::default() });
    assert!(!sandbox.try_arm(), "a disabled PIN is never armed");
    says(&sandbox.properpin(&["status"], "").success(), "the PIN is disabled after 10 concerning failures within 24 hours");

    says(&sandbox.properpin(&["enable"], "").success(), "PIN enabled again");
    sandbox.arm();
    let status = stdout(&sandbox.properpin(&["status"], "").success());
    assert!(status.contains("PIN armed for another") && status.contains("10 since the PIN was set (of 100)"), "{status}");
    says(&sandbox.properpin(&["enable"], "").success(), "wasn't disabled");

    sandbox.write_budget(&Budget {
        total: 100,
        disabled: Some(Disabled { limit: Limit::Total(100), at: 1_800_000_000 }),
        ..Budget::default()
    });
    says(&sandbox.properpin(&["enable"], "").failure(), "choose a new one with: properpin set");
    sandbox.properpin(&["set"], &new_pin("4860", "4860")).success();
    sandbox.arm();
    let status = stdout(&sandbox.properpin(&["status"], "").success());
    assert!(status.contains("PIN armed for another") && status.contains("0 since the PIN was set"), "{status}");

    sandbox.properpin(&["remove"], "").success();
    assert!(!sandbox.0.path().join(format!("var/{}.budget", current_uid())).exists(), "remove leaves no budget behind");
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
