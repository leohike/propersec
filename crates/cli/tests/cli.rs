//! The `screenlock-pin` command, run as a subprocess against a sandboxed `--etc` owned by whoever runs
//! the tests, with `--pin-checker` pointing at a script that runs the freshly built `screenlock-pin-checker`
//! against the same sandbox (through its `--dev-*` options, accepted because it isn't setgid).

use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use assert_cmd::Command;
use screenlock_pin_core::{Budget, Disabled, Limit};
use screenlock_pin_sys::{Yescrypt, current_uid};

const PASSWORD: &str = "correct horse battery staple";

struct Sandbox(tempfile::TempDir);

impl Sandbox {
    fn new() -> Self {
        let sandbox = Self(tempfile::tempdir().unwrap());
        let root = sandbox.0.path();
        fs::create_dir(root.join("var")).unwrap();
        // Set explicitly: the umask would strip the group's write bit from a mkdir mode.
        fs::set_permissions(root.join("var"), Permissions::from_mode(0o1770)).unwrap();
        let pin_checker = format!(
            "#!/bin/sh\nexec {} \"$@\" --dev-etc {root}/etc --dev-budget {root}/var --dev-log {root}/log\n",
            built_pin_checker().display(),
            root = root.display()
        );
        script(&root.join("pin-checker"), &pin_checker);
        let shadow = format!("root:!:20000::::::\n{}:{}:20000:0:99999:7:::\n", user(), Yescrypt.hash(PASSWORD, 4).unwrap());
        fs::write(root.join("shadow"), shadow).unwrap();
        sandbox
    }

    fn screenlock_pin(&self, args: &[&str], stdin: &str) -> assert_cmd::assert::Assert {
        let root = self.0.path();
        Command::cargo_bin("screenlock-pin")
            .unwrap()
            .env_remove("SUDO_USER")
            .env_remove("PKEXEC_UID")
            .args(["--etc", root.join("etc").to_str().unwrap(), "--pin-checker", root.join("pin-checker").to_str().unwrap()])
            .args(["--budget", root.join("var").to_str().unwrap(), "--shadow", root.join("shadow").to_str().unwrap()])
            .args(["--owner", &current_uid().to_string(), "--group", &pin_checker_gid().to_string()])
            .args(args)
            .write_stdin(stdin)
            .assert()
    }

    /// What the lock screen's `after-password-auth` line has the PIN checker do after a password unlock. It must succeed.
    fn unpause(&self) {
        let status = std::process::Command::new(self.0.path().join("pin-checker"))
            .arg("unpause")
            .stdin(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "unpausing the PIN after the password failed");
    }

    /// Replace the user's budget with `budget`, the way the PIN checker would have written it.
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
        std::process::Command::new(sandbox.0.path().join("pin-checker")).arg("check").stdin(std::process::Stdio::piped()).spawn().unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), pin.as_bytes()).unwrap();
    child.wait().unwrap().success()
}

fn user() -> String {
    screenlock_pin_sys::Account::by_uid(current_uid()).unwrap().name
}

fn stdout(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

fn script(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o755)).unwrap();
}

/// The test user's primary group, which stands in for the PIN checker's.
fn pin_checker_gid() -> u32 {
    screenlock_pin_sys::Account::by_uid(current_uid()).unwrap().gid
}

/// The directory with a fresh `screenlock-pin-checker`, built once per test run.
fn built_pin_checker() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let profile_dir = std::env::current_exe().unwrap().parent().and_then(Path::parent).unwrap().to_path_buf();
        let mut cargo = std::process::Command::new(env!("CARGO"));
        cargo.args([
            "build",
            "--quiet",
            "--package",
            "screenlock-pin-checker",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
        ]);
        if profile_dir.ends_with("release") {
            cargo.arg("--release");
        }
        assert!(cargo.status().unwrap().success(), "building screenlock-pin-checker failed");
        profile_dir.join("screenlock-pin-checker")
    })
}

#[test]
fn set_then_status_then_remove() {
    let sandbox = Sandbox::new();
    says(&sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).success(), "The lock screen takes it from now on");
    let [file] = &sandbox.user_files()[..] else { panic!("expected one user file") };
    assert_eq!(fs::metadata(file).unwrap().mode() & 0o777, 0o640);
    assert_eq!(fs::metadata(file).unwrap().gid(), pin_checker_gid(), "readable by the PIN checker's group");
    let text = fs::read_to_string(file).unwrap();
    assert!(text.starts_with("hash = $y$j9T$") && text.lines().count() == 1, "{text}");

    // The PIN works at once, with no password unlock first.
    let status = stdout(&sandbox.screenlock_pin(&["status"], "").success());
    assert!(status.contains("hash                  set since ") && status.contains("PIN                   enabled since "), "{status}");
    assert!(unlocks(&sandbox, "cat4859"));
    assert!(!unlocks(&sandbox, "cat4860"));

    sandbox.screenlock_pin(&["remove"], "").success();
    sandbox.screenlock_pin(&["remove"], "").failure();
    assert!(stdout(&sandbox.screenlock_pin(&["status"], "").success()).contains("none set"));
    assert!(!unlocks(&sandbox, "cat4859"));
}

#[test]
fn set_refuses_mismatches_and_weak_pins() {
    let sandbox = Sandbox::new();
    says(&sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4860")).failure(), "the two entries differ");
    says(&sandbox.screenlock_pin(&["set"], &new_pin("48", "48")).failure(), "at least 4 characters");
    assert!(sandbox.user_files().is_empty());
}

/// The rules are said before the PIN is typed, and a PIN that breaks them is refused at once,
/// without asking for it a second time.
#[test]
fn set_says_the_rules_first_and_refuses_a_weak_pin_at_once() {
    let sandbox = Sandbox::new();
    let asked = sandbox.screenlock_pin(&["set"], "4859\n").failure();
    says(&asked, "4 to 64 characters, at least 3 of them not digits");
    says(&asked, "the PIN needs at least 3 characters that aren't digits; nothing was changed");
    assert!(sandbox.user_files().is_empty());
}

#[test]
fn the_pin_may_not_be_the_password() {
    let sandbox = Sandbox::new();
    says(&sandbox.screenlock_pin(&["set"], &new_pin(PASSWORD, PASSWORD)).failure(), "the PIN must not be the password");
    assert!(sandbox.user_files().is_empty());
}

/// Without a shadow entry, as with LDAP or systemd-homed, set warns and goes on.
#[test]
fn without_a_shadow_entry_the_pin_is_not_compared() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.0.path().join("shadow"), "root:!:20000::::::\n").unwrap();
    says(&sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).success(), "wasn't compared with the password");
    assert!(unlocks(&sandbox, "cat4859"));
}

/// The same PIN again starts its budget over, so set asks first; without a terminal, only --yes
/// goes on.
#[test]
fn setting_the_same_pin_again_asks_first() {
    let sandbox = Sandbox::new();
    sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).success();
    sandbox.write_budget(&Budget { total: 7, ..Budget::default() });
    let assert = sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).failure();
    says(&assert, "This is the PIN already set");
    says(&assert, "forgets its 7 suspicious failures");
    says(&assert, "--yes skips the question");
    assert!(stdout(&sandbox.screenlock_pin(&["status"], "").success()).contains("7/60   since this PIN was set"));
    sandbox.screenlock_pin(&["set", "--yes"], &new_pin("cat4859", "cat4859")).success();
    assert!(stdout(&sandbox.screenlock_pin(&["status"], "").success()).contains("0/60   since this PIN was set"));
    // A different PIN needs no question.
    sandbox.screenlock_pin(&["set"], &new_pin("cat4860", "cat4860")).success();
}

/// The PIN works right after set, and after a reboot too: nothing about it lives in memory.
#[test]
fn a_reboot_changes_nothing() {
    let sandbox = Sandbox::new();
    sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).success();
    for wrong in ["1111", "2222", "3333"] {
        assert!(!unlocks(&sandbox, wrong));
    }
    // Paused, and still paused whatever happens to memory; the password unpauses it.
    assert!(!unlocks(&sandbox, "cat4859"));
    sandbox.unpause();
    assert!(unlocks(&sandbox, "cat4859"));
}

#[test]
fn status_shows_what_the_pin_checker_sees() {
    let sandbox = Sandbox::new();
    sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).success();
    let status = stdout(&sandbox.screenlock_pin(&["status"], "").success());
    assert!(status.contains("consecutive failures  0/3"), "{status}");
    fs::remove_file(sandbox.0.path().join("pin-checker")).unwrap();
    says(&sandbox.screenlock_pin(&["status"], "").failure(), "pin-checker");
}

/// Without a terminal nothing could answer sudo's question, so a command that needs root never
/// starts sudo, and says to run it with sudo instead. On a terminal it runs itself again through
/// sudo, which the container test shows, since that needs a real sudo.
#[test]
fn without_a_terminal_it_says_to_run_it_with_sudo() {
    if current_uid() == 0 {
        return;
    }
    let sandbox = Sandbox::new();
    let root = sandbox.0.path();
    for command in ["set", "enable", "remove", "restore-defaults", "doctor"] {
        // No --owner: root owns the files, as once installed.
        let assert = Command::cargo_bin("screenlock-pin")
            .unwrap()
            .env_remove("SUDO_USER")
            .env_remove("PKEXEC_UID")
            .args(["--etc", root.join("etc").to_str().unwrap(), "--pin-checker", root.join("pin-checker").to_str().unwrap()])
            .args(["--budget", root.join("var").to_str().unwrap(), command])
            .write_stdin(new_pin("cat4859", "cat4859"))
            .assert()
            .failure();
        says(&assert, "this changes files only root may change; run it with sudo");
        let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
        assert!(!stderr.contains("through sudo"), "{command}: {stderr}");
    }
    assert!(sandbox.user_files().is_empty());
}

#[test]
fn set_needs_the_pin_checker_group_to_exist() {
    let sandbox = Sandbox::new();
    let assert = Command::cargo_bin("screenlock-pin")
        .unwrap()
        .args(["--etc", sandbox.0.path().join("etc").to_str().unwrap(), "--pin-checker", "/nonexistent", "--budget", "/nonexistent"])
        .args(["--owner", &current_uid().to_string(), "--group", "no-such-group-screenlock-pin", "set"])
        .write_stdin(new_pin("cat4859", "cat4859"))
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
    says(&sandbox.screenlock_pin(&["enable"], "").failure(), "no PIN is set");
    sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).success();
    let disabled = Some(Disabled { limit: Limit::Day(10), at: 1_800_000_000 });
    sandbox.write_budget(&Budget { suspicious: vec![1_800_000_000], total: 10, disabled, ..Budget::default() });
    assert!(!unlocks(&sandbox, "cat4859"), "a disabled PIN never unlocks");
    sandbox.unpause();
    assert!(!unlocks(&sandbox, "cat4859"), "the password doesn't bring a disabled PIN back");
    says(&sandbox.screenlock_pin(&["status"], "").success(), ", after 10 suspicious failures within 24 hours");

    let assert = sandbox.screenlock_pin(&["enable"], "").failure();
    says(&assert, "may have been someone guessing it");
    says(&assert, "--yes skips the question");
    assert!(!unlocks(&sandbox, "cat4859"));
    says(&sandbox.screenlock_pin(&["enable", "--yes"], "").success(), "PIN enabled again");
    assert!(unlocks(&sandbox, "cat4859"), "enable brings the same PIN back at once");
    let status = stdout(&sandbox.screenlock_pin(&["status"], "").success());
    assert!(status.contains("PIN                   enabled since ") && status.contains("10/60  since this PIN was set"), "{status}");
    says(&sandbox.screenlock_pin(&["enable"], "").success(), "wasn't disabled");

    sandbox.write_budget(&Budget {
        total: 60,
        disabled: Some(Disabled { limit: Limit::Total(60), at: 1_800_000_000 }),
        ..Budget::default()
    });
    says(&sandbox.screenlock_pin(&["enable", "--yes"], "").failure(), "choose a new one with: screenlock-pin set");
    sandbox.screenlock_pin(&["set"], &new_pin("cat4860", "cat4860")).success();
    let status = stdout(&sandbox.screenlock_pin(&["status"], "").success());
    assert!(status.contains("PIN                   enabled since ") && status.contains("0/60   since this PIN was set"), "{status}");

    let (budget, lock) =
        (sandbox.0.path().join(format!("var/{}.budget", current_uid())), sandbox.0.path().join(format!("var/{}.lock", current_uid())));
    assert!(budget.exists() && lock.exists(), "set leaves a budget and a lock file, or their absence below would prove nothing");
    sandbox.screenlock_pin(&["remove"], "").success();
    assert!(!budget.exists() && !lock.exists(), "remove leaves no budget or lock file behind");
}

/// Doctor finds whatever an attempt would refuse, and names the command that fixes it; status
/// says why too, and both agree with what the lock screen does.
#[test]
fn doctor_and_status_say_why_a_pin_is_refused() {
    let sandbox = Sandbox::new();
    let me = user();
    says(&sandbox.screenlock_pin(&["doctor"], "").success(), "no problems; no PIN is set");
    sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).success();
    says(&sandbox.screenlock_pin(&["doctor"], "").success(), &format!("no problems; a PIN is set for {me}"));

    let file = sandbox.0.path().join("etc/users").join(&me);
    fs::set_permissions(&file, Permissions::from_mode(0o644)).unwrap();
    assert!(!unlocks(&sandbox, "cat4859"));
    let doctor = sandbox.screenlock_pin(&["doctor"], "").failure();
    says(&doctor, &format!("users/{me}: readable by others\n    the lock screen refuses {me}'s PIN\n"));
    says(&doctor, &format!("fix: sudo screenlock-pin remove --user {me}, then a new PIN with: sudo screenlock-pin set --user {me}"));
    says(&doctor, &format!("1 problem; a PIN is set for {me}"));
    says(&sandbox.screenlock_pin(&["status"], "").success(), "readable by others; sudo screenlock-pin doctor says how to fix it");
    says(
        &sandbox.screenlock_pin(&["set"], &new_pin("cat4860", "cat4860")).failure(),
        "readable by others; sudo screenlock-pin doctor says how to fix it",
    );
    sandbox.screenlock_pin(&["remove", "--user", &me], "").success();
    sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).success();
    assert!(unlocks(&sandbox, "cat4859"), "the fix doctor named works");

    let budget = sandbox.0.path().join(format!("var/{}.budget", current_uid()));
    fs::remove_file(&budget).unwrap();
    assert!(!unlocks(&sandbox, "cat4859"));
    let doctor = sandbox.screenlock_pin(&["doctor"], "").failure();
    says(&doctor, &format!("{}: missing", budget.display()));
    says(&doctor, &format!("fix: sudo screenlock-pin set --user {me}, with the same PIN or a new one"));
    says(&sandbox.screenlock_pin(&["status"], "").success(), "PIN                   refused whatever is typed:");
    sandbox.screenlock_pin(&["set", "--yes"], &new_pin("cat4859", "cat4859")).success();

    sandbox.write_budget(&Budget { disabled: Some(Disabled { limit: Limit::Day(10), at: 1_800_000_000 }), ..Budget::default() });
    let doctor = sandbox.screenlock_pin(&["doctor"], "").failure();
    says(&doctor, &format!("{me}'s PIN is disabled after 10 suspicious failures within 24 hours"));
    says(&doctor, &format!("fix: sudo screenlock-pin enable --user {me} keeps the PIN"));
    sandbox.screenlock_pin(&["enable", "--yes"], "").success();

    fs::write(&file, "hash = not a hash\n").unwrap();
    fs::set_permissions(&file, Permissions::from_mode(0o640)).unwrap();
    says(&sandbox.screenlock_pin(&["doctor"], "").failure(), "not a yescrypt hash");
    says(&sandbox.screenlock_pin(&["status"], "").success(), "not a yescrypt hash");
    sandbox.screenlock_pin(&["remove"], "").success();
    sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).success();

    // The config refuses everyone's PIN, and is reported once, not once per user.
    let config = sandbox.0.path().join("etc/config");
    fs::write(&config, "expiry_hours = 4\n").unwrap();
    fs::set_permissions(&config, Permissions::from_mode(0o644)).unwrap();
    assert!(!unlocks(&sandbox, "cat4859"));
    let doctor = sandbox.screenlock_pin(&["doctor"], "").failure();
    says(&doctor, "unknown setting \"expiry_hours\"\n    the lock screen refuses every PIN\n");
    says(&doctor, "1 problem;");
    sandbox.screenlock_pin(&["restore-defaults", "--yes"], "").success();
    assert!(unlocks(&sandbox, "cat4859"));

    // A file whose account is gone: nobody's PIN, until an account takes the name.
    let ghost = sandbox.0.path().join("etc/users/no-such-user-screenlock-pin");
    fs::copy(&file, &ghost).unwrap();
    says(&sandbox.screenlock_pin(&["doctor"], "").failure(), "no account is named no-such-user-screenlock-pin");
    says(
        &sandbox.screenlock_pin(&["remove", "--user", "no-such-user-screenlock-pin"], "").success(),
        "PIN removed for no-such-user-screenlock-pin",
    );
    assert!(!ghost.exists());
    says(&sandbox.screenlock_pin(&["doctor"], "").success(), "no problems");
}

/// `remove` takes whatever is there, and only says no when there is nothing at all.
#[test]
fn remove_takes_whatever_is_left() {
    let sandbox = Sandbox::new();
    sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).success();
    fs::remove_file(sandbox.0.path().join("etc/users").join(user())).unwrap();
    says(&sandbox.screenlock_pin(&["remove"], "").success(), "had no PIN; its budget and lock file are removed");
    assert_eq!(fs::read_dir(sandbox.0.path().join("var")).unwrap().count(), 0);
    says(&sandbox.screenlock_pin(&["remove"], "").failure(), "nothing was changed");
}

/// The blank page: every PIN and budget gone, after a question; and the config, separately.
#[test]
fn remove_all_and_restore_defaults_ask_first() {
    let sandbox = Sandbox::new();
    sandbox.screenlock_pin(&["set"], &new_pin("cat4859", "cat4859")).success();
    fs::write(sandbox.0.path().join("etc/users/.leftover"), "").unwrap();
    let config = sandbox.0.path().join("etc/config");
    fs::write(&config, "max_failures = 5\n").unwrap();
    fs::set_permissions(&config, Permissions::from_mode(0o644)).unwrap();

    let assert = sandbox.screenlock_pin(&["remove", "--all"], "").failure();
    says(&assert, &format!("This removes the PINs of {}", user()));
    says(&assert, "--yes skips the question");
    assert!(unlocks(&sandbox, "cat4859"), "nothing changed without a yes");
    says(&sandbox.screenlock_pin(&["remove", "--all", "--yes"], "").success(), "Every PIN is removed");
    for dir in ["etc/users", "var"] {
        assert_eq!(fs::read_dir(sandbox.0.path().join(dir)).unwrap().count(), 0, "{dir} isn't empty");
    }
    assert!(!unlocks(&sandbox, "cat4859"));
    says(&sandbox.screenlock_pin(&["remove", "--all"], "").success(), "No PIN was set");
    sandbox.screenlock_pin(&["remove", "--all", "--user", &user()], "").failure();

    assert!(config.exists(), "remove --all keeps the config");
    let assert = sandbox.screenlock_pin(&["restore-defaults"], "").failure();
    says(&assert, "max_failures = 5");
    says(&assert, "--yes skips the question");
    assert!(config.exists());
    says(&sandbox.screenlock_pin(&["restore-defaults", "--yes"], "").success(), "Every setting has its default");
    assert!(!config.exists());
    says(&sandbox.screenlock_pin(&["restore-defaults"], "").success(), "already has its default");
}

#[test]
fn paths_are_never_defaulted() {
    Command::cargo_bin("screenlock-pin").unwrap().arg("status").assert().failure();
}

/// Whether the command said `needle`, on stdout or stderr.
fn says(assert: &assert_cmd::assert::Assert, needle: &str) {
    let output = assert.get_output();
    let text = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(text.contains(needle), "expected {needle:?} in {text:?}");
}
