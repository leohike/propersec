//! The `properpin` command, run as a subprocess against a sandboxed `--etc` owned by whoever runs
//! the tests, with `--pinchecker` pointing at a script that runs the freshly built `properpin-pinchecker`
//! against the same sandbox (through its `--dev-*` options, accepted because it isn't setgid).

use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use assert_cmd::Command;
use properpin_core::{Budget, Disabled, Limit};
use properpin_sys::{Yescrypt, current_uid};

const PASSWORD: &str = "correct horse battery staple";

struct Sandbox(tempfile::TempDir);

impl Sandbox {
    fn new() -> Self {
        let sandbox = Self(tempfile::tempdir().unwrap());
        let root = sandbox.0.path();
        fs::create_dir(root.join("var")).unwrap();
        // Set explicitly: the umask would strip the group's write bit from a mkdir mode.
        fs::set_permissions(root.join("var"), Permissions::from_mode(0o1770)).unwrap();
        let chkpwd = format!("#!/bin/bash\nIFS= read -r -d '' password\n[[ $password == '{PASSWORD}' ]]\n");
        script(&root.join("unix_chkpwd"), &chkpwd);
        let pinchecker = format!(
            "#!/bin/sh\nexec {} \"$@\" --dev-etc {root}/etc --dev-budget {root}/var --dev-chkpwd {root}/unix_chkpwd --dev-log {root}/log\n",
            built_pinchecker().display(),
            root = root.display()
        );
        script(&root.join("pinchecker"), &pinchecker);
        let shadow = format!("root:!:20000::::::\n{}:{}:20000:0:99999:7:::\n", user(), Yescrypt.hash(PASSWORD, 4).unwrap());
        fs::write(root.join("shadow"), shadow).unwrap();
        sandbox
    }

    fn properpin(&self, args: &[&str], stdin: &str) -> assert_cmd::assert::Assert {
        let root = self.0.path();
        Command::cargo_bin("properpin")
            .unwrap()
            .env_remove("SUDO_USER")
            .env_remove("PKEXEC_UID")
            .args(["--etc", root.join("etc").to_str().unwrap(), "--pinchecker", root.join("pinchecker").to_str().unwrap()])
            .args(["--budget", root.join("var").to_str().unwrap(), "--shadow", root.join("shadow").to_str().unwrap()])
            .args(["--owner", &current_uid().to_string(), "--group", &pinchecker_gid().to_string()])
            .args(args)
            .write_stdin(stdin)
            .assert()
    }

    /// What the lock screen's housekeeping line does after a correct password. It must succeed.
    fn housekeeping(&self) {
        let status = std::process::Command::new(self.0.path().join("pinchecker"))
            .arg("housekeeping")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                std::io::Write::write_all(&mut child.stdin.take().unwrap(), PASSWORD.as_bytes())?;
                child.wait()
            })
            .unwrap();
        assert!(status.success(), "the housekeeping after the password failed");
    }

    /// Replace the user's budget with `budget`, the way the pinchecker would have written it.
    fn write_budget(&self, budget: &Budget) {
        let path = self.0.path().join(format!("var/{}.budget", current_uid()));
        fs::write(&path, budget.format()).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    }

    fn user_files(&self) -> Vec<PathBuf> {
        fs::read_dir(self.0.path().join("etc/users")).map(|dir| dir.map(|entry| entry.unwrap().path()).collect()).unwrap_or_default()
    }
}

/// What `set` reads: the PIN, and the same again.
fn new_pin(pin: &str, again: &str) -> String {
    format!("{pin}\n{again}\n")
}

/// What the lock screen's PIN line does: whether `pin` unlocks right now.
fn unlocks(sandbox: &Sandbox, pin: &str) -> bool {
    let mut child =
        std::process::Command::new(sandbox.0.path().join("pinchecker")).arg("check").stdin(std::process::Stdio::piped()).spawn().unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), pin.as_bytes()).unwrap();
    child.wait().unwrap().success()
}

fn user() -> String {
    properpin_sys::Account::by_uid(current_uid()).unwrap().name
}

fn stdout(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

fn script(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o755)).unwrap();
}

/// The test user's primary group, which stands in for the pinchecker's.
fn pinchecker_gid() -> u32 {
    properpin_sys::Account::by_uid(current_uid()).unwrap().gid
}

/// The directory with a fresh `properpin-pinchecker`, built once per test run.
fn built_pinchecker() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let profile_dir = std::env::current_exe().unwrap().parent().and_then(Path::parent).unwrap().to_path_buf();
        let mut cargo = std::process::Command::new(env!("CARGO"));
        cargo.args([
            "build",
            "--quiet",
            "--package",
            "properpin-pinchecker",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
        ]);
        if profile_dir.ends_with("release") {
            cargo.arg("--release");
        }
        assert!(cargo.status().unwrap().success(), "building properpin-pinchecker failed");
        profile_dir.join("properpin-pinchecker")
    })
}

#[test]
fn set_then_status_then_remove() {
    let sandbox = Sandbox::new();
    says(&sandbox.properpin(&["set"], &new_pin("4859", "4859")).success(), "The lock screen takes it from now on");
    let [file] = &sandbox.user_files()[..] else { panic!("expected one user file") };
    assert_eq!(fs::metadata(file).unwrap().mode() & 0o777, 0o640);
    assert_eq!(fs::metadata(file).unwrap().gid(), pinchecker_gid(), "readable by the pinchecker's group");
    let text = fs::read_to_string(file).unwrap();
    assert!(text.starts_with("hash = $y$j9T$") && text.lines().count() == 1, "{text}");

    // The PIN works at once, with no password unlock first.
    let status = stdout(&sandbox.properpin(&["status"], "").success());
    assert!(status.contains("PIN        set") && status.contains("right now  enabled"), "{status}");
    assert!(unlocks(&sandbox, "4859"));
    assert!(!unlocks(&sandbox, "4860"));

    sandbox.properpin(&["remove"], "").success();
    sandbox.properpin(&["remove"], "").failure();
    assert!(stdout(&sandbox.properpin(&["status"], "").success()).contains("none set"));
    assert!(!unlocks(&sandbox, "4859"));
}

#[test]
fn set_refuses_mismatches_and_weak_pins() {
    let sandbox = Sandbox::new();
    says(&sandbox.properpin(&["set"], &new_pin("4859", "4860")).failure(), "the two entries differ");
    says(&sandbox.properpin(&["set"], &new_pin("48", "48")).failure(), "at least 4 characters");
    assert!(sandbox.user_files().is_empty());
}

#[test]
fn the_pin_may_not_be_the_password() {
    let sandbox = Sandbox::new();
    let config = sandbox.0.path().join("etc/config");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "max_pin_length = 64\n").unwrap();
    says(&sandbox.properpin(&["set"], &new_pin(PASSWORD, PASSWORD)).failure(), "the PIN must not be the password");
    assert!(sandbox.user_files().is_empty());
}

/// Without a shadow entry, as with LDAP or systemd-homed, set warns and goes on.
#[test]
fn without_a_shadow_entry_the_pin_is_not_compared() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.0.path().join("shadow"), "root:!:20000::::::\n").unwrap();
    says(&sandbox.properpin(&["set"], &new_pin("4859", "4859")).success(), "wasn't compared with the password");
    assert!(unlocks(&sandbox, "4859"));
}

/// The same PIN again starts its budget over, so set asks first; without a terminal, only --yes
/// goes on.
#[test]
fn setting_the_same_pin_again_asks_first() {
    let sandbox = Sandbox::new();
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
    sandbox.write_budget(&Budget { total: 7, ..Budget::default() });
    let assert = sandbox.properpin(&["set"], &new_pin("4859", "4859")).failure();
    says(&assert, "This is the PIN already set");
    says(&assert, "forgets its 7 concerning failures");
    says(&assert, "--yes skips the question");
    assert!(stdout(&sandbox.properpin(&["status"], "").success()).contains("7 since the PIN was set"));
    sandbox.properpin(&["set", "--yes"], &new_pin("4859", "4859")).success();
    assert!(stdout(&sandbox.properpin(&["status"], "").success()).contains("0 since the PIN was set"));
    // A different PIN needs no question.
    sandbox.properpin(&["set"], &new_pin("4860", "4860")).success();
}

/// The PIN works right after set, and after a reboot too: nothing about it lives in memory.
#[test]
fn a_reboot_changes_nothing() {
    let sandbox = Sandbox::new();
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
    for wrong in ["1111", "2222", "3333"] {
        assert!(!unlocks(&sandbox, wrong));
    }
    // Paused, and still paused whatever happens to memory; the password unpauses it.
    assert!(!unlocks(&sandbox, "4859"));
    sandbox.housekeeping();
    assert!(unlocks(&sandbox, "4859"));
}

#[test]
fn status_shows_what_the_pinchecker_sees() {
    let sandbox = Sandbox::new();
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
    let status = stdout(&sandbox.properpin(&["status"], "").success());
    assert!(status.contains("enabled, 0 of 3 consecutive failures so far"), "{status}");
    fs::remove_file(sandbox.0.path().join("pinchecker")).unwrap();
    says(&sandbox.properpin(&["status"], "").failure(), "pinchecker");
}

#[test]
fn set_needs_the_pinchecker_group_to_exist() {
    let sandbox = Sandbox::new();
    let assert = Command::cargo_bin("properpin")
        .unwrap()
        .args(["--etc", sandbox.0.path().join("etc").to_str().unwrap(), "--pinchecker", "/nonexistent", "--budget", "/nonexistent"])
        .args(["--owner", &current_uid().to_string(), "--group", "no-such-group-properpin", "set"])
        .write_stdin(new_pin("4859", "4859"))
        .assert()
        .failure();
    says(&assert, "no group named");
    assert!(sandbox.user_files().is_empty());
}

/// A PIN disabled by its budget: `enable` brings the same PIN back after asking, until the total
/// since it was set reaches its limit; then only `set` does, and starts the budget over.
#[test]
fn enable_and_set_bring_a_disabled_pin_back() {
    let sandbox = Sandbox::new();
    says(&sandbox.properpin(&["enable"], "").failure(), "no PIN is set");
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
    let disabled = Some(Disabled { limit: Limit::Day(10), at: 1_800_000_000 });
    sandbox.write_budget(&Budget { concerning: vec![1_800_000_000], total: 10, disabled, ..Budget::default() });
    assert!(!unlocks(&sandbox, "4859"), "a disabled PIN never unlocks");
    sandbox.housekeeping();
    assert!(!unlocks(&sandbox, "4859"), "the password doesn't bring a disabled PIN back");
    says(&sandbox.properpin(&["status"], "").success(), "disabled after 10 concerning failures within 24 hours");

    let assert = sandbox.properpin(&["enable"], "").failure();
    says(&assert, "may have been someone guessing it");
    says(&assert, "--yes skips the question");
    assert!(!unlocks(&sandbox, "4859"));
    says(&sandbox.properpin(&["enable", "--yes"], "").success(), "PIN enabled again");
    assert!(unlocks(&sandbox, "4859"), "enable brings the same PIN back at once");
    let status = stdout(&sandbox.properpin(&["status"], "").success());
    assert!(status.contains("right now  enabled") && status.contains("10 since the PIN was set (of 60)"), "{status}");
    says(&sandbox.properpin(&["enable"], "").success(), "wasn't disabled");

    sandbox.write_budget(&Budget {
        total: 60,
        disabled: Some(Disabled { limit: Limit::Total(60), at: 1_800_000_000 }),
        ..Budget::default()
    });
    says(&sandbox.properpin(&["enable", "--yes"], "").failure(), "choose a new one with: properpin set");
    sandbox.properpin(&["set"], &new_pin("4860", "4860")).success();
    let status = stdout(&sandbox.properpin(&["status"], "").success());
    assert!(status.contains("right now  enabled") && status.contains("0 since the PIN was set"), "{status}");

    let (budget, lock) =
        (sandbox.0.path().join(format!("var/{}.budget", current_uid())), sandbox.0.path().join(format!("var/{}.lock", current_uid())));
    assert!(budget.exists() && lock.exists(), "set leaves a budget and a lock file, or their absence below would prove nothing");
    sandbox.properpin(&["remove"], "").success();
    assert!(!budget.exists() && !lock.exists(), "remove leaves no budget or lock file behind");
}

/// Doctor finds whatever an attempt would refuse, and names the command that fixes it; status
/// says why too, and both agree with what the lock screen does.
#[test]
fn doctor_and_status_say_why_a_pin_is_refused() {
    let sandbox = Sandbox::new();
    let me = user();
    says(&sandbox.properpin(&["doctor"], "").success(), "no problems; no PIN is set");
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
    says(&sandbox.properpin(&["doctor"], "").success(), &format!("no problems; a PIN is set for {me}"));

    let file = sandbox.0.path().join("etc/users").join(&me);
    fs::set_permissions(&file, Permissions::from_mode(0o644)).unwrap();
    assert!(!unlocks(&sandbox, "4859"));
    let doctor = sandbox.properpin(&["doctor"], "").failure();
    says(&doctor, &format!("users/{me}: readable by others\n    the lock screen refuses {me}'s PIN\n"));
    says(&doctor, &format!("fix: sudo properpin remove --user {me}, then a new PIN with: sudo properpin set --user {me}"));
    says(&doctor, &format!("1 problem; a PIN is set for {me}"));
    says(&sandbox.properpin(&["status"], "").success(), "readable by others; sudo properpin doctor says how to fix it");
    says(&sandbox.properpin(&["set"], &new_pin("4860", "4860")).failure(), "readable by others; sudo properpin doctor says how to fix it");
    sandbox.properpin(&["remove", "--user", &me], "").success();
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
    assert!(unlocks(&sandbox, "4859"), "the fix doctor named works");

    let budget = sandbox.0.path().join(format!("var/{}.budget", current_uid()));
    fs::remove_file(&budget).unwrap();
    assert!(!unlocks(&sandbox, "4859"));
    let doctor = sandbox.properpin(&["doctor"], "").failure();
    says(&doctor, &format!("{}: missing", budget.display()));
    says(&doctor, &format!("fix: sudo properpin set --user {me}, with the same PIN or a new one"));
    says(&sandbox.properpin(&["status"], "").success(), "right now  refused, whatever is typed:");
    sandbox.properpin(&["set", "--yes"], &new_pin("4859", "4859")).success();

    sandbox.write_budget(&Budget { disabled: Some(Disabled { limit: Limit::Day(10), at: 1_800_000_000 }), ..Budget::default() });
    let doctor = sandbox.properpin(&["doctor"], "").failure();
    says(&doctor, &format!("{me}'s PIN is disabled after 10 concerning failures within 24 hours"));
    says(&doctor, &format!("fix: sudo properpin enable --user {me} keeps the PIN"));
    sandbox.properpin(&["enable", "--yes"], "").success();

    fs::write(&file, "hash = not a hash\n").unwrap();
    fs::set_permissions(&file, Permissions::from_mode(0o640)).unwrap();
    says(&sandbox.properpin(&["doctor"], "").failure(), "not a yescrypt hash");
    says(&sandbox.properpin(&["status"], "").success(), "not a yescrypt hash");
    sandbox.properpin(&["remove"], "").success();
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();

    // The config refuses everyone's PIN, and is reported once, not once per user.
    let config = sandbox.0.path().join("etc/config");
    fs::write(&config, "expiry_hours = 4\n").unwrap();
    fs::set_permissions(&config, Permissions::from_mode(0o644)).unwrap();
    assert!(!unlocks(&sandbox, "4859"));
    let doctor = sandbox.properpin(&["doctor"], "").failure();
    says(&doctor, "unknown setting \"expiry_hours\"\n    the lock screen refuses every PIN\n");
    says(&doctor, "1 problem;");
    sandbox.properpin(&["restore-defaults", "--yes"], "").success();
    assert!(unlocks(&sandbox, "4859"));

    // A file whose account is gone: nobody's PIN, until an account takes the name.
    let ghost = sandbox.0.path().join("etc/users/no-such-user-properpin");
    fs::copy(&file, &ghost).unwrap();
    says(&sandbox.properpin(&["doctor"], "").failure(), "no account is named no-such-user-properpin");
    says(&sandbox.properpin(&["remove", "--user", "no-such-user-properpin"], "").success(), "PIN removed for no-such-user-properpin");
    assert!(!ghost.exists());
    says(&sandbox.properpin(&["doctor"], "").success(), "no problems");
}

/// `remove` takes whatever is there, and only says no when there is nothing at all.
#[test]
fn remove_takes_whatever_is_left() {
    let sandbox = Sandbox::new();
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
    fs::remove_file(sandbox.0.path().join("etc/users").join(user())).unwrap();
    says(&sandbox.properpin(&["remove"], "").success(), "had no PIN; its budget and lock file are removed");
    assert_eq!(fs::read_dir(sandbox.0.path().join("var")).unwrap().count(), 0);
    says(&sandbox.properpin(&["remove"], "").failure(), "nothing was changed");
}

/// The blank page: every PIN and budget gone, after a question; and the config, separately.
#[test]
fn remove_all_and_restore_defaults_ask_first() {
    let sandbox = Sandbox::new();
    sandbox.properpin(&["set"], &new_pin("4859", "4859")).success();
    fs::write(sandbox.0.path().join("etc/users/.leftover"), "").unwrap();
    let config = sandbox.0.path().join("etc/config");
    fs::write(&config, "max_failures = 5\n").unwrap();
    fs::set_permissions(&config, Permissions::from_mode(0o644)).unwrap();

    let assert = sandbox.properpin(&["remove", "--all"], "").failure();
    says(&assert, &format!("This removes the PINs of {}", user()));
    says(&assert, "--yes skips the question");
    assert!(unlocks(&sandbox, "4859"), "nothing changed without a yes");
    says(&sandbox.properpin(&["remove", "--all", "--yes"], "").success(), "Every PIN is removed");
    for dir in ["etc/users", "var"] {
        assert_eq!(fs::read_dir(sandbox.0.path().join(dir)).unwrap().count(), 0, "{dir} isn't empty");
    }
    assert!(!unlocks(&sandbox, "4859"));
    says(&sandbox.properpin(&["remove", "--all"], "").success(), "No PIN was set");
    sandbox.properpin(&["remove", "--all", "--user", &user()], "").failure();

    assert!(config.exists(), "remove --all keeps the config");
    let assert = sandbox.properpin(&["restore-defaults"], "").failure();
    says(&assert, "max_failures = 5");
    says(&assert, "--yes skips the question");
    assert!(config.exists());
    says(&sandbox.properpin(&["restore-defaults", "--yes"], "").success(), "Every setting has its default");
    assert!(!config.exists());
    says(&sandbox.properpin(&["restore-defaults"], "").success(), "already has its default");
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
