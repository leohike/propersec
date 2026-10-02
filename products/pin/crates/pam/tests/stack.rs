//! The lock-screen stack, through the real libpam and the real `pam_properpin.so`.
//!
//! The PAM files come from a temporary directory (`pam_start_confdir`). The stack is the shipped
//! `pam/kde-auth.pam` with only three things swapped: the module path points at the freshly built
//! `.so`, the helper path at a script that runs the freshly built `properpin-helper` against the
//! sandbox (through its `--dev-*` options, which it accepts here because it isn't setuid), and
//! `pam_unix` becomes `pam_permit` (the password was right) or `pam_deny` (it was wrong). The
//! control columns are the shipped ones.
//!
//! What this can't show: how the real pam_unix, the real setuid helper and the real greeter
//! behave. The container test covers the first two.

use std::fs::{self, Permissions};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use pamharness::{Attempt, PamClient};
use properpin_sys::{Account, Yescrypt, current_uid};

const PIN: &str = "4859";
const PASSWORD: &str = "correct horse battery staple";
const SHIPPED: &str = include_str!("../../../pam/kde-auth.pam");

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
    /// A sandboxed `/etc/properpin` with a PIN set for the current user, an empty runtime dir, a
    /// helper that uses them, a stand-in for `unix_chkpwd`, and a PAM config dir.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let user = Account::by_uid(current_uid()).unwrap().name;
        let sandbox = Self { dir, user };
        fs::DirBuilder::new().mode(0o700).create(sandbox.run_dir()).unwrap();
        fs::set_permissions(sandbox.run_dir(), Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(sandbox.path("etc/users")).unwrap();
        fs::create_dir_all(sandbox.path("pam.d")).unwrap();
        // libpam logs to the journal when a confdir has no "other" fallback service.
        fs::write(sandbox.path("pam.d/other"), "auth required pam_deny.so\n").unwrap();
        let user_file = sandbox.path("etc/users").join(&sandbox.user);
        fs::write(&user_file, format!("hash = {}\n", Yescrypt.hash(PIN, 4).unwrap())).unwrap();
        fs::set_permissions(&user_file, Permissions::from_mode(0o640)).unwrap();
        // unix_chkpwd's protocol: the password on stdin, ending in a NUL; exit 0 for a match.
        let chkpwd = format!("#!/bin/bash\nIFS= read -r -d '' password\n[[ $1 == \"$(id -un)\" && $password == '{PASSWORD}' ]]\n");
        sandbox.script("unix_chkpwd", &chkpwd);
        let helper = format!(
            "#!/bin/sh\nexec {} \"$@\" --dev-etc {} --dev-run {} --dev-chkpwd {} --dev-log {}\n",
            built().join("properpin-helper").display(),
            sandbox.path("etc").display(),
            sandbox.run_dir().display(),
            sandbox.path("unix_chkpwd").display(),
            sandbox.path("log").display()
        );
        sandbox.script("helper", &helper);
        sandbox
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }

    fn script(&self, name: &str, text: &str) {
        fs::write(self.path(name), text).unwrap();
        fs::set_permissions(self.path(name), Permissions::from_mode(0o755)).unwrap();
    }

    fn run_dir(&self) -> PathBuf {
        self.path("run")
    }

    fn log(&self) -> String {
        fs::read_to_string(self.path("log")).unwrap_or_default()
    }

    /// Write the `kde` service: the shipped lines, sandboxed, with `extra` added to the check line.
    fn stack(&self, password: Password, extra: &str) {
        let module = format!("{} {extra}", built().join("libpam_properpin.so").display());
        let helper = format!("helper={} log={}", self.path("helper").display(), self.path("log").display());
        let unix = match password {
            Password::Right => "pam_permit.so",
            Password::Wrong => "pam_deny.so",
        };
        let mut text = SHIPPED.to_owned();
        for (old, new) in [
            ("/usr/local/lib64/security/pam_properpin.so", module.as_str()),
            ("helper=/usr/local/libexec/properpin/properpin-helper", helper.as_str()),
            ("pam_unix.so use_first_pass", unix),
        ] {
            // Fail loudly if the shipped file changes shape, rather than test something else.
            assert!(text.contains(old), "{old:?} is no longer in pam/kde-auth.pam");
            text = text.replace(old, new);
        }
        fs::write(self.path("pam.d/kde"), text).unwrap();
    }

    fn attempt(&self, password: Password, typed: &str) -> Attempt {
        self.stack(password, "");
        let attempt = PamClient::new(self.path("pam.d"), "kde", &self.user).authenticate(typed);
        // One field, one prompt: no input ever triggers a second question.
        assert_eq!(attempt.prompts.len(), 1, "{attempt:?}");
        attempt
    }

    /// Unlock with the password, which arms the PIN.
    fn unlock_with_password(&self) {
        assert!(self.attempt(Password::Right, PASSWORD).unlocked());
    }
}

/// The directory with a fresh `pam_properpin.so` and `properpin-helper`. `cargo test` rebuilds this
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
                "properpin-helper",
                "--manifest-path",
                concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            ]);
            if profile_dir.ends_with("release") {
                cargo.arg("--release");
            }
            assert!(cargo.status().unwrap().success(), "building pam_properpin and properpin-helper failed");
            profile_dir
        })
        .clone()
}

#[test]
fn after_boot_only_the_password_works() {
    let sandbox = Sandbox::new();
    assert!(!sandbox.attempt(Password::Wrong, PIN).unlocked());
    assert!(sandbox.log().contains("PIN refused, password required: no password unlock since boot"), "{}", sandbox.log());
}

#[test]
fn the_password_arms_the_pin_and_the_pin_unlocks() {
    let sandbox = Sandbox::new();
    sandbox.unlock_with_password();
    assert!(sandbox.log().contains("longer than 12 characters, so not the PIN"), "{}", sandbox.log());
    assert!(sandbox.log().contains("password accepted, PIN armed"));
    // pam_deny now stands for any password: only the PIN can unlock.
    assert!(sandbox.attempt(Password::Wrong, PIN).unlocked());
    assert!(sandbox.log().contains("unlocked with the PIN"));
}

#[test]
fn a_wrong_password_never_arms_the_pin() {
    let sandbox = Sandbox::new();
    assert!(!sandbox.attempt(Password::Wrong, "a wrong password, long enough").unlocked());
    assert!(!sandbox.run_dir().join(format!("{}.state", current_uid())).exists());
    assert!(!sandbox.attempt(Password::Wrong, PIN).unlocked());
}

#[test]
fn wrong_pins_fall_through_and_three_disarm() {
    let sandbox = Sandbox::new();
    sandbox.unlock_with_password();
    for wrong in ["1111", "2222", "3333"] {
        assert!(!sandbox.attempt(Password::Wrong, wrong).unlocked());
    }
    assert!(sandbox.log().contains("failure 3 of 3, password required from now on"), "{}", sandbox.log());
    assert!(!sandbox.attempt(Password::Wrong, PIN).unlocked());
    sandbox.unlock_with_password();
    assert!(sandbox.attempt(Password::Wrong, PIN).unlocked());
}

#[test]
fn the_pin_only_works_for_the_user_the_lock_screen_runs_as() {
    let sandbox = Sandbox::new();
    sandbox.unlock_with_password();
    sandbox.stack(Password::Wrong, "");
    let attempt = PamClient::new(sandbox.path("pam.d"), "kde", "nobody").authenticate(PIN);
    assert!(!attempt.unlocked());
    assert!(sandbox.log().contains("PAM is authenticating \"nobody\""), "{}", sandbox.log());
}

#[test]
fn a_panic_becomes_pam_ignore_and_the_password_still_works() {
    let sandbox = Sandbox::new();
    sandbox.stack(Password::Right, "test_panic");
    assert!(PamClient::new(sandbox.path("pam.d"), "kde", &sandbox.user).authenticate(PASSWORD).unlocked());
    sandbox.stack(Password::Wrong, "test_panic");
    assert!(!PamClient::new(sandbox.path("pam.d"), "kde", &sandbox.user).authenticate(PIN).unlocked());
}

#[test]
fn a_bad_pam_line_refuses_instead_of_guessing() {
    let sandbox = Sandbox::new();
    sandbox.unlock_with_password();
    sandbox.stack(Password::Wrong, "no_such_option");
    assert!(!PamClient::new(sandbox.path("pam.d"), "kde", &sandbox.user).authenticate(PIN).unlocked());
    assert!(sandbox.log().contains("bad PAM line: unknown argument \"no_such_option\""), "{}", sandbox.log());
}

/// libpam loads and unloads the module on every transaction. Rust `.so`s have crashed on unload
/// (rust-lang/rust#91979), so run many transactions from threads that then exit.
#[test]
fn survives_many_loads_and_unloads_across_threads() {
    let sandbox = Sandbox::new();
    sandbox.unlock_with_password();
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

/// Whatever goes wrong with the helper, the PIN is refused and the password still works.
#[test]
fn a_broken_helper_fails_closed() {
    for (name, helper) in [
        ("missing", None),
        ("exits with an odd code", Some("#!/bin/sh\nexit 3\n")),
        ("killed by a signal", Some("#!/bin/sh\nkill -9 $$\n")),
        ("quits without reading", Some("#!/bin/sh\nexit 0\n")),
    ] {
        let sandbox = Sandbox::new();
        sandbox.unlock_with_password();
        match helper {
            None => fs::remove_file(sandbox.path("helper")).unwrap(),
            Some(text) => sandbox.script("helper", text),
        }
        // "quits without reading" exits 0, a yes: the module trusts the helper's answer, so that
        // one unlocks. The point there is that writing to it raises no SIGPIPE in the host.
        let unlocked = sandbox.attempt(Password::Wrong, PIN).unlocked();
        assert_eq!(unlocked, name == "quits without reading", "{name}: {}", sandbox.log());
        if name != "quits without reading" {
            assert!(sandbox.log().contains("PIN refused:"), "{name}: {}", sandbox.log());
        }
        assert!(sandbox.attempt(Password::Right, PASSWORD).unlocked(), "{name}: the password must still work");
    }
}
