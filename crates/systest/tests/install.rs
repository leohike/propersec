//! `packaging/install.sh` and `packaging/integrate-into-pam.sh` against a fake root (`--root`), owned
//! by whoever runs the tests.
//!
//! What this can't show: root ownership and SELinux labels, which need the real thing. The
//! container test (`just podman`) runs the same scripts as root into a real `/`.

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

const INSTALL_SH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/install.sh");
const INTEGRATE_SH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/integrate-into-pam.sh");
const SHIPPED_AUTH: &str = include_str!("../../../packaging/screenlock-auth.pam");

/// Fedora 44's `/etc/pam.d/kde`, from plasma-workspace, as the lock screen reads it.
const STOCK_KDE: &str = "\
auth        substack      password-auth
auth        include       postlogin

account     required      pam_nologin.so
account     include       password-auth

password    include       password-auth

session     required      pam_selinux.so close
session     required      pam_loginuid.so
session     required      pam_selinux.so open
session     optional      pam_keyinit.so force revoke
session     required      pam_namespace.so
session     include       password-auth
session     include       postlogin
";

struct FakeRoot {
    dir: tempfile::TempDir,
}

impl FakeRoot {
    /// An empty root holding only a stock `/etc/pam.d/kde`.
    fn new() -> Self {
        let root = Self { dir: tempfile::tempdir().unwrap() };
        fs::create_dir_all(root.path("etc/pam.d")).unwrap();
        fs::write(root.kde(), STOCK_KDE).unwrap();
        root
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }

    fn kde(&self) -> PathBuf {
        self.path("etc/pam.d/kde")
    }

    fn run(&self, command: &str) -> Output {
        Command::new("bash")
            .arg(INSTALL_SH)
            .arg(command)
            .arg("--root")
            .arg(self.dir.path())
            .args(["--owner", &whoami(), "--pin-checker-group", &group()])
            .arg("--from")
            .arg(built())
            .output()
            .unwrap()
    }

    /// Run `command`, which must succeed, and return what it printed.
    fn ok(&self, command: &str) -> String {
        let output = self.run(command);
        let text = says(&output);
        assert!(output.status.success(), "install.sh {command} failed:\n{text}");
        text
    }

    /// Run `command`, which must fail, and return what it printed.
    fn refused(&self, command: &str) -> String {
        let output = self.run(command);
        let text = says(&output);
        assert!(!output.status.success(), "install.sh {command} should have failed:\n{text}");
        text
    }

    /// Run integrate-into-pam.sh `command`, and return its exit code and what it printed.
    fn pam(&self, command: &str) -> (Option<i32>, String) {
        let output = Command::new("bash").arg(INTEGRATE_SH).arg(command).arg("--root").arg(self.dir.path()).output().unwrap();
        (output.status.code(), says(&output))
    }

    /// Run integrate-into-pam.sh `command`, which must succeed, and return what it printed.
    fn pam_ok(&self, command: &str) -> String {
        let (code, said) = self.pam(command);
        assert_eq!(code, Some(0), "integrate-into-pam.sh {command} failed:\n{said}");
        said
    }

    /// Run integrate-into-pam.sh `command`, which must fail and change nothing in the PAM file, and
    /// return what it printed.
    fn pam_refused(&self, command: &str) -> String {
        let before = fs::read(self.kde()).ok();
        let (code, said) = self.pam(command);
        assert_eq!(code, Some(1), "integrate-into-pam.sh {command} should have failed:\n{said}");
        assert_eq!(fs::read(self.kde()).ok(), before, "integrate-into-pam.sh {command} failed, but changed {}", self.kde().display());
        said
    }

    fn kde_text(&self) -> String {
        fs::read_to_string(self.kde()).unwrap()
    }

    fn auth(&self) -> PathBuf {
        self.path("etc/pam.d/screenlock-auth")
    }
}

fn says(output: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))
}

fn whoami() -> String {
    String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout).unwrap().trim().into()
}

fn group() -> String {
    String::from_utf8(Command::new("id").arg("-gn").output().unwrap().stdout).unwrap().trim().into()
}

/// The directory holding a fresh debug build of the module and the command, built once per run.
fn built() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        let status = Command::new(env!("CARGO"))
            .args([
                "build",
                "--quiet",
                "--package",
                "pam_screenlock_pin",
                "--package",
                "screenlock-pin-checker",
                "--package",
                "screenlock-pin-cli",
            ])
            .args(["--manifest-path", manifest])
            .status()
            .unwrap();
        assert!(status.success(), "building the module, the PIN checker and the command failed");
        std::env::current_exe().unwrap().parent().and_then(Path::parent).unwrap().to_path_buf()
    })
}

/// The stock line in `kde`, and screenlock-pin's, which differ in one word.
const STOCK_LINE: &str = "auth        substack      password-auth\n";
const OWN_LINE: &str = "auth        substack      screenlock-auth\n";

/// `kde` with screenlock-pin's line in place of its stock substack line.
fn integrated(kde: &str) -> String {
    assert_eq!(kde.matches(STOCK_LINE).count(), 1, "{kde}");
    kde.replacen(STOCK_LINE, OWN_LINE, 1)
}

/// install puts screenlock-pin's own PAM file in place, which nothing uses yet, never touches
/// `kde`, and says what to run to change it.
#[test]
fn install_leaves_kde_alone_and_says_what_to_run() {
    let root = FakeRoot::new();
    let said = root.ok("install");
    assert_eq!(root.kde_text(), STOCK_KDE);
    assert_eq!(fs::read_to_string(root.auth()).unwrap(), SHIPPED_AUTH);
    assert_eq!(fs::metadata(root.auth()).unwrap().permissions().mode() & 0o7777, 0o644);
    assert!(said.contains("has no screenlock-pin line") && said.contains("just integrate-into-pam"), "{said}");
    let checked = root.ok("check");
    assert!(checked.contains("all screenlock-pin files in place") && checked.contains("has no screenlock-pin line"), "{checked}");
    assert_eq!(root.pam("check").0, Some(3));
}

#[test]
fn add_remove_and_uninstall_leave_pam_as_it_was() {
    let root = FakeRoot::new();
    root.ok("install");
    assert!(root.pam_ok("add").contains("has screenlock-pin's line"));
    assert_eq!(root.kde_text(), integrated(STOCK_KDE));
    assert!(root.pam_ok("check").contains("has screenlock-pin's line, auth substack screenlock-auth"));
    assert!(root.ok("check").contains("has screenlock-pin's line"));

    // The fake root had only etc/pam.d: every directory install had to create goes again, except
    // those holding what is kept. Each is there now, or its absence afterwards would prove nothing.
    let installed = [
        "etc/pam.d/screenlock-auth",
        "usr/local/lib64/security/pam_screenlock_pin.so",
        "usr/local/libexec/screenlock-pin",
        "usr/local/bin/screenlock-pin",
        "etc/sysusers.d/screenlock-pin.conf",
        "etc/tmpfiles.d/screenlock-pin.conf",
        "usr",
        "etc/sysusers.d",
        "etc/tmpfiles.d",
    ];
    for path in installed {
        assert!(root.path(path).exists(), "{path} isn't there after install");
    }
    // kde naming a deleted screenlock-auth would lock the lock screen, so uninstall waits for remove.
    let said = root.refused("uninstall");
    assert!(
        said.contains("has screenlock-pin's line")
            && said.contains("uninstall waits until")
            && said.contains("just remove-from-pam")
            && said.contains("nothing was removed"),
        "{said}"
    );
    assert!(installed.iter().all(|path| root.path(path).exists()), "uninstall refused, but removed something");
    assert!(root.pam_ok("remove").contains("changed /etc/pam.d/kde back to auth substack password-auth"));
    assert_eq!(root.kde_text(), STOCK_KDE);
    assert_eq!(root.pam("check").0, Some(3));
    root.ok("uninstall");
    assert_eq!(root.kde_text(), STOCK_KDE);
    for gone in installed {
        assert!(!root.path(gone).exists(), "{gone} is still there");
    }
    assert!(root.path("etc/pam.d").is_dir(), "the PAM directory stays");
    assert!(root.path("etc/screenlock-pin/users").is_dir(), "PINs are kept");
    assert!(root.path("var/lib/screenlock-pin").is_dir(), "budgets are kept");
    assert!(root.pam_ok("remove").contains("nothing to do"));
}

#[test]
fn adding_twice_is_harmless() {
    let root = FakeRoot::new();
    root.ok("install");
    root.pam_ok("add");
    assert!(root.pam_ok("add").contains("already has screenlock-pin's line"));
    assert_eq!(root.kde_text(), integrated(STOCK_KDE), "the line changes once");
    root.ok("install");
    assert_eq!(root.kde_text(), integrated(STOCK_KDE), "installing again leaves it as it is");
}

/// kde must never name a file that isn't there, nor screenlock-auth a module that isn't.
#[test]
fn add_refuses_until_screenlock_pin_is_installed() {
    let root = FakeRoot::new();
    assert!(root.pam_refused("add").contains("screenlock-pin isn't installed"));
    for missing in ["etc/pam.d/screenlock-auth", "usr/local/lib64/security/pam_screenlock_pin.so"] {
        let root = FakeRoot::new();
        root.ok("install");
        fs::remove_file(root.path(missing)).unwrap();
        assert!(root.pam_refused("add").contains("screenlock-pin isn't installed"), "{missing}");
    }
}

#[test]
fn add_refuses_an_unexpected_pam_file_and_changes_nothing() {
    for (kde, why) in [
        ("auth include postlogin\n", "has 0 'auth substack password-auth' lines"),
        ("auth substack password-auth\nauth substack password-auth\n", "has 2 'auth substack password-auth' lines"),
    ] {
        let root = FakeRoot::new();
        root.ok("install");
        fs::write(root.kde(), kde).unwrap();
        let said = root.pam_refused("add");
        assert!(said.contains(why), "{said}");
        // What to do, for whoever does it by hand.
        assert!(said.contains("change password-auth to screenlock-auth on that line"), "{said}");
    }
    let root = FakeRoot::new();
    root.ok("install");
    fs::remove_file(root.kde()).unwrap();
    assert!(root.pam_refused("add").contains("missing"));
    assert!(!root.kde().exists(), "add must never create the file");
    fs::write(root.path("etc/pam.d/kde-real"), integrated(STOCK_KDE)).unwrap();
    std::os::unix::fs::symlink(root.path("etc/pam.d/kde-real"), root.kde()).unwrap();
    assert!(root.pam_refused("add").contains("symbolic link"));
    assert!(root.pam_refused("remove").contains("symbolic link"));
    assert!(root.kde().is_symlink(), "the link stays a link");
}

/// add changes one word and remove changes it back, so whatever spacing and comment the stock line
/// has, and whatever an admin added elsewhere, the file comes back byte for byte.
#[test]
fn remove_gives_back_the_file_byte_for_byte() {
    for stock in [STOCK_KDE.to_owned(), STOCK_KDE.replace(STOCK_LINE, "auth\tsubstack password-auth   # the password\n")] {
        let root = FakeRoot::new();
        root.ok("install");
        fs::write(root.kde(), &stock).unwrap();
        root.pam_ok("add");
        // The stock substack line is the file's first.
        assert_eq!(root.kde_text(), stock.replacen("password-auth", "screenlock-auth", 1));
        assert_eq!(root.pam("check").0, Some(0), "{}", root.kde_text());
        let edited = format!("{}# added by an admin\n", root.kde_text());
        fs::write(root.kde(), &edited).unwrap();
        assert!(root.pam_ok("add").contains("already has screenlock-pin's line"));
        assert_eq!(root.kde_text(), edited);
        root.pam_ok("remove");
        assert_eq!(root.kde_text(), format!("{stock}# added by an admin\n"));
    }
}

/// This version installs only where nothing older is, and changes only a stock `kde` or its own
/// line: properpin's lines, an earlier screenlock-pin's, which named the module in `kde` itself, and
/// hand edits of screenlock-pin's line are refused, and left as they are.
#[test]
fn older_lines_and_hand_edits_are_refused_and_left_alone() {
    let properpin = "\
# properpin begin: added by install.sh install; install.sh uninstall removes everything down to the end marker
auth  [success=done default=ignore]  /usr/local/lib64/security/pam_properpin.so check
auth  [success=ok default=die]       pam_unix.so use_first_pass
# properpin end
";
    let earlier = "auth        sufficient    /usr/local/lib64/security/pam_screenlock_pin.so check\n";
    for (kde, why, install_refuses) in [
        (format!("{properpin}{STOCK_KDE}"), "has lines of properpin", true),
        (format!("{earlier}{STOCK_KDE}"), "names pam_screenlock_pin.so itself", true),
        (format!("{OWN_LINE}{STOCK_KDE}"), "edited by hand", false),
        (format!("{}{OWN_LINE}", integrated(STOCK_KDE)), "edited by hand", false),
        (STOCK_KDE.replace(STOCK_LINE, "auth        include       screenlock-auth\n"), "edited by hand", false),
    ] {
        let root = FakeRoot::new();
        root.ok("install");
        fs::write(root.kde(), &kde).unwrap();
        let (code, said) = root.pam("check");
        assert!(code == Some(1) && said.contains(why) && said.contains("put it back as stock by hand"), "{kde}\n{said}");
        assert!(root.pam_refused("add").contains(why), "{kde}");
        assert!(root.pam_refused("remove").contains(why), "{kde}");
        assert!(root.refused("uninstall").contains("nothing was removed"), "{kde}");
        assert!(root.refused("check").contains(why), "{kde}");
        if install_refuses {
            let said = root.refused("install");
            assert!(said.contains("installs only where neither is") && said.contains("nothing was changed"), "{said}");
            let fresh = FakeRoot::new();
            fs::write(fresh.kde(), &kde).unwrap();
            fresh.refused("install");
            assert!(!fresh.path("usr").exists() && !fresh.auth().exists(), "install refused, but changed something");
        }
        assert_eq!(root.kde_text(), kde);
    }
    let root = FakeRoot::new();
    fs::create_dir_all(root.path("usr/local/libexec/properpin")).unwrap();
    let said = root.refused("install");
    assert!(said.contains("/usr/local/libexec/properpin") && said.contains("nothing was changed"), "{said}");
    assert!(!root.auth().exists() && !root.path("usr/local/bin").exists());
}

/// kde naming a missing screenlock-auth makes the lock screen refuse everyone, the password too:
/// check says so, install puts the file back, and remove still works.
#[test]
fn a_missing_screenlock_auth_is_named_and_mended() {
    let root = FakeRoot::new();
    root.ok("install");
    root.pam_ok("add");
    fs::remove_file(root.auth()).unwrap();
    let (code, said) = root.pam("check");
    assert!(code == Some(1) && said.contains("is missing, so the lock screen refuses everyone, the password too"), "{said}");
    let problems = root.refused("check");
    assert!(problems.contains("/etc/pam.d/screenlock-auth: missing") && problems.contains("refuses everyone"), "{problems}");
    root.ok("install");
    assert_eq!(root.pam("check").0, Some(0));
    fs::remove_file(root.auth()).unwrap();
    root.pam_ok("remove");
    assert_eq!(root.kde_text(), STOCK_KDE);
    root.ok("uninstall");
}

#[test]
fn install_puts_everything_in_place_and_twice_is_harmless() {
    let root = FakeRoot::new();
    root.ok("install");
    root.ok("install");
    let check = root.ok("check");
    assert!(check.contains("all screenlock-pin files in place"), "{check}");
    let command = fs::read_to_string(root.path("usr/local/bin/screenlock-pin")).unwrap();
    assert!(
        command.contains(
            "exec /usr/local/libexec/screenlock-pin/screenlock-pin --etc /etc/screenlock-pin --budget /var/lib/screenlock-pin --pin-checker /usr/local/libexec/screenlock-pin/screenlock-pin-checker \"$@\""
        ),
        "{command}"
    );
    let mode = |path: &str| fs::metadata(root.path(path)).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode("usr/local/libexec/screenlock-pin/screenlock-pin-checker"), 0o2755, "the PIN checker is setgid only");
    assert_eq!(mode("etc/pam.d/screenlock-auth"), 0o644);
    assert_eq!(fs::read_to_string(root.auth()).unwrap(), SHIPPED_AUTH);
    assert_eq!(mode("etc/screenlock-pin/users"), 0o750);
    assert!(!root.path("run").exists(), "nothing in /run any more");
    assert_eq!(mode("var/lib/screenlock-pin"), 0o1770);
    let sysusers = fs::read_to_string(root.path("etc/sysusers.d/screenlock-pin.conf")).unwrap();
    assert!(sysusers.lines().any(|line| line == format!("g {} -", group())), "{sysusers}");
    assert!(!sysusers.lines().any(|line| line.starts_with("u ")), "no account: {sysusers}");
    let tmpfiles = fs::read_to_string(root.path("etc/tmpfiles.d/screenlock-pin.conf")).unwrap();
    assert!(tmpfiles.contains(&format!("d /var/lib/screenlock-pin 1770 {} {} -", whoami(), group())), "{tmpfiles}");
    assert!(!tmpfiles.contains("/run"), "{tmpfiles}");
    assert_eq!(
        fs::read(root.path("usr/local/lib64/security/pam_screenlock_pin.so")).unwrap(),
        fs::read(built().join("libpam_screenlock_pin.so")).unwrap()
    );
    // What an earlier version could leave: a program nothing uses any more.
    fs::write(root.path("usr/local/libexec/screenlock-pin/screenlock-pin-old"), "old").unwrap();
    assert!(root.refused("check").contains("screenlock-pin-old: not installed by this version"));
    root.ok("install");
    assert!(!root.path("usr/local/libexec/screenlock-pin/screenlock-pin-old").exists());
    assert!(root.path("usr/local/libexec/screenlock-pin/screenlock-pin-checker").exists());
}

#[test]
fn check_finds_what_is_wrong() {
    let root = FakeRoot::new();
    root.ok("install");
    fs::set_permissions(root.path("usr/local/lib64/security/pam_screenlock_pin.so"), Permissions::from_mode(0o777)).unwrap();
    fs::write(root.path("usr/local/libexec/screenlock-pin/screenlock-pin"), "not the build").unwrap();
    fs::remove_dir(root.path("etc/screenlock-pin/users")).unwrap();
    fs::write(root.auth(), format!("{SHIPPED_AUTH}auth optional pam_permit.so\n")).unwrap();
    let problems = root.refused("check");
    assert!(problems.contains("pam_screenlock_pin.so: is 777"), "{problems}");
    assert!(problems.contains("/etc/pam.d/screenlock-auth: differs from"), "{problems}");
    assert!(problems.contains("libexec/screenlock-pin/screenlock-pin: differs from"), "{problems}");
    assert!(problems.contains("/etc/screenlock-pin/users: missing"), "{problems}");

    for (pin_checker, budget_dir) in [(0o755, 0o755), (0o4755, 0o700), (0o6755, 0o1777)] {
        root.ok("install");
        fs::set_permissions(root.path("usr/local/libexec/screenlock-pin/screenlock-pin-checker"), Permissions::from_mode(pin_checker))
            .unwrap();
        fs::set_permissions(root.path("var/lib/screenlock-pin"), Permissions::from_mode(budget_dir)).unwrap();
        fs::write(root.path("etc/tmpfiles.d/screenlock-pin.conf"), "d /var/lib/screenlock-pin 0777 root root -\n").unwrap();
        fs::write(root.path("etc/sysusers.d/screenlock-pin.conf"), "u screenlock-pin - \"an account\" - -\n").unwrap();
        let problems = root.refused("check");
        assert!(problems.contains(&format!("screenlock-pin-checker: is {pin_checker:o}")), "{problems}");
        assert!(problems.contains(&format!("/var/lib/screenlock-pin: is {budget_dir:o}")), "{problems}");
        assert!(problems.contains("tmpfiles.d/screenlock-pin.conf: not what install.sh writes"), "{problems}");
        assert!(problems.contains("sysusers.d/screenlock-pin.conf: not what install.sh writes"), "{problems}");
    }
}

/// A user's file, a budget or the config that doctor finds fault with refuses the PINs it concerns
/// and no others, so install never judges them: it installs, and prints what doctor found.
#[test]
fn install_leaves_the_pins_and_the_config_to_doctor() {
    let root = FakeRoot::new();
    root.ok("install");
    let user_file = root.path("etc/screenlock-pin/users").join(whoami());
    fs::write(&user_file, "hash = $y$x\n").unwrap();
    fs::set_permissions(&user_file, Permissions::from_mode(0o644)).unwrap();
    let said = root.ok("install");
    assert!(said.contains(&format!("users/{}: readable by others", whoami())), "{said}");
    assert!(said.contains(&format!("fix: sudo screenlock-pin remove --user {}, then a new PIN", whoami())), "{said}");
    assert!(said.contains(&format!("1 problem; a PIN is set for {}", whoami())), "{said}");
    root.ok("check");

    // What versions with a pepper left: a PIN with settings that are gone, and a config with
    // settings that are gone. Both stay where they are, named by doctor.
    fs::write(&user_file, "hash = $y$x\nencrypted_pepper = 00\n").unwrap();
    fs::set_permissions(&user_file, Permissions::from_mode(0o640)).unwrap();
    fs::write(root.path("etc/screenlock-pin/config"), "expiry_hours = 4\n").unwrap();
    fs::set_permissions(root.path("etc/screenlock-pin/config"), Permissions::from_mode(0o644)).unwrap();
    let said = root.ok("install");
    assert!(said.contains("unknown setting \"encrypted_pepper\"") && said.contains("unknown setting \"expiry_hours\""), "{said}");
    assert!(said.contains("restore-defaults"), "{said}");
    assert!(user_file.exists() && root.path("etc/screenlock-pin/config").exists());
    assert_eq!(root.kde_text(), STOCK_KDE);
}

#[test]
fn check_wants_the_group() {
    let root = FakeRoot::new();
    root.ok("install");
    let output = Command::new("bash")
        .arg(INSTALL_SH)
        .args(["check", "--root"])
        .arg(root.dir.path())
        .args(["--owner", &whoami(), "--pin-checker-group", "no-such-group-screenlock-pin"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(says(&output).contains("no group named no-such-group-screenlock-pin"), "{}", says(&output));
}

/// An install that fails halfway leaves the PAM file as it was, lines and all, and the next good
/// install finishes the job.
#[test]
fn a_failed_install_leaves_pam_alone() {
    let root = FakeRoot::new();
    root.ok("install");
    root.pam_ok("add");
    // Where install's directory must go, so install fails halfway.
    let users = root.path("etc/screenlock-pin/users");
    fs::remove_dir(&users).unwrap();
    fs::write(&users, "").unwrap();
    root.refused("install");
    assert_eq!(root.kde_text(), integrated(STOCK_KDE));
    fs::remove_file(&users).unwrap();
    root.ok("install");
    root.ok("check");
}

#[test]
fn bad_arguments_change_nothing() {
    let root = FakeRoot::new();
    for args in [&["frobnicate"][..], &["install", "check"], &["enable"], &["disable"], &["install", "--yes"], &[]] {
        let output = Command::new("bash").arg(INSTALL_SH).args(args).arg("--root").arg(root.dir.path()).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}: {}", says(&output));
    }
    assert!(!root.path("usr").exists());
    for args in [&["frobnicate"][..], &["add", "remove"], &["install"], &[]] {
        let output = Command::new("bash").arg(INTEGRATE_SH).args(args).arg("--root").arg(root.dir.path()).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}: {}", says(&output));
    }
    assert_eq!(root.kde_text(), STOCK_KDE);
}

/// Whatever else ended up in screenlock-pin's own directory, and whatever is already missing.
#[test]
fn uninstall_copes_with_extra_and_missing_files() {
    let root = FakeRoot::new();
    root.ok("install");
    fs::write(root.path("usr/local/libexec/screenlock-pin/left-behind"), "junk").unwrap();
    fs::remove_file(root.path("usr/local/bin/screenlock-pin")).unwrap();
    fs::remove_file(root.path("usr/local/lib64/security/pam_screenlock_pin.so")).unwrap();
    fs::remove_file(root.auth()).unwrap();
    root.ok("uninstall");
    assert!(!root.path("usr/local/libexec/screenlock-pin").exists());
    root.ok("uninstall");
}
