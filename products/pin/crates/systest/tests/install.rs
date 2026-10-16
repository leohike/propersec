//! `packaging/install.sh` against a fake root (`--root`), owned by whoever runs the tests.
//!
//! What this can't show: root ownership and SELinux labels, which need the real thing. The
//! container test (`just properpin podman`) runs the same script as root into a real `/`.

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

const INSTALL_SH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/install.sh");

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
            .args(["--owner", &whoami(), "--pinchecker-group", &group()])
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
            .args(["build", "--quiet", "--package", "pam_properpin", "--package", "properpin-pinchecker", "--package", "properpin-cli"])
            .args(["--manifest-path", manifest])
            .status()
            .unwrap();
        assert!(status.success(), "building the module, the pinchecker and the command failed");
        std::env::current_exe().unwrap().parent().and_then(Path::parent).unwrap().to_path_buf()
    })
}

/// The PAM file once install has put properpin's lines in, the same for every fake root.
fn installed_kde() -> String {
    let root = FakeRoot::new();
    root.ok("install");
    fs::read_to_string(root.kde()).unwrap()
}

/// properpin's lines as a version before 2026-10-17 wrote them: another text after the begin
/// marker, and arguments the module now rejects.
const OLD_BLOCK: &str = "\
# properpin begin: added by install.sh enable; install.sh disable removes everything down to the end marker
auth  [success=done default=ignore]  /usr/local/lib64/security/pam_properpin.so check helper=/usr/local/libexec/properpin/properpin-helper config=/etc/properpin/config
auth  [success=ok default=die]       pam_unix.so use_first_pass
auth  optional                       /usr/local/lib64/security/pam_properpin.so start-accepting-pin helper=/usr/local/libexec/properpin/properpin-helper
# properpin end
";

#[test]
fn install_and_uninstall_leave_pam_as_it_was() {
    let root = FakeRoot::new();
    root.ok("install");
    let enabled = fs::read_to_string(root.kde()).unwrap();
    let lines: Vec<&str> = enabled.lines().collect();
    assert!(lines[0].starts_with("# properpin begin"), "{enabled}");
    assert!(
        lines[1]
            .contains("pam_properpin.so check pinchecker=/usr/local/libexec/properpin/properpin-pinchecker config=/etc/properpin/config")
    );
    assert!(lines[2].contains("pam_unix.so use_first_pass"));
    assert!(lines[3].contains("pam_properpin.so housekeeping"));
    assert_eq!(lines[4], "# properpin end");
    assert!(enabled.ends_with(STOCK_KDE), "everything stock stays, below the block");
    assert!(root.ok("check").contains("has the lines this version ships"));
    assert_eq!(fs::read_to_string(root.path("etc/properpin/kde.pam.without-properpin")).unwrap(), STOCK_KDE);

    assert!(root.ok("uninstall").contains("took properpin's lines out"));
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), STOCK_KDE);
    for gone in [
        "usr/local/lib64/security/pam_properpin.so",
        "usr/local/libexec/properpin",
        "usr/local/bin/properpin",
        "etc/sysusers.d/properpin.conf",
        "etc/tmpfiles.d/properpin.conf",
    ] {
        assert!(!root.path(gone).exists(), "{gone} is still there");
    }
    assert!(root.path("etc/properpin/users").is_dir(), "PINs are kept");
    assert!(root.path("var/lib/properpin").is_dir(), "budgets are kept");
    // The fake root had only etc/pam.d: every directory install had to create goes again, except
    // those holding what is kept.
    for gone in ["usr", "run", "etc/sysusers.d", "etc/tmpfiles.d"] {
        assert!(!root.path(gone).exists(), "{gone} is still there");
    }
}

#[test]
fn install_puts_everything_in_place_and_twice_is_harmless() {
    let root = FakeRoot::new();
    root.ok("install");
    assert!(root.ok("install").contains("already has the lines this version ships"));
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), installed_kde(), "the lines go in once");
    let check = root.ok("check");
    assert!(check.contains("all properpin files in place"), "{check}");
    let command = fs::read_to_string(root.path("usr/local/bin/properpin")).unwrap();
    assert!(
        command.contains(
            "exec /usr/local/libexec/properpin/properpin --etc /etc/properpin --budget /var/lib/properpin --pinchecker /usr/local/libexec/properpin/properpin-pinchecker \"$@\""
        ),
        "{command}"
    );
    let mode = |path: &str| fs::metadata(root.path(path)).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode("usr/local/libexec/properpin/properpin-pinchecker"), 0o2755, "the pinchecker is setgid only");
    assert_eq!(mode("etc/properpin/users"), 0o750);
    assert!(!root.path("run").exists(), "nothing in /run any more");
    assert_eq!(mode("var/lib/properpin"), 0o1770);
    let sysusers = fs::read_to_string(root.path("etc/sysusers.d/properpin.conf")).unwrap();
    assert!(sysusers.lines().any(|line| line == format!("g {} -", group())), "{sysusers}");
    assert!(!sysusers.lines().any(|line| line.starts_with("u ")), "no account: {sysusers}");
    let tmpfiles = fs::read_to_string(root.path("etc/tmpfiles.d/properpin.conf")).unwrap();
    assert!(tmpfiles.contains(&format!("d /var/lib/properpin 1770 {} {} -", whoami(), group())), "{tmpfiles}");
    assert!(!tmpfiles.contains("/run"), "{tmpfiles}");
    assert_eq!(
        fs::read(root.path("usr/local/lib64/security/pam_properpin.so")).unwrap(),
        fs::read(built().join("libpam_properpin.so")).unwrap()
    );
}

#[test]
fn check_finds_what_is_wrong() {
    let root = FakeRoot::new();
    root.ok("install");
    fs::set_permissions(root.path("usr/local/lib64/security/pam_properpin.so"), Permissions::from_mode(0o777)).unwrap();
    fs::write(root.path("usr/local/libexec/properpin/properpin"), "not the build").unwrap();
    fs::remove_dir(root.path("etc/properpin/users")).unwrap();
    let user_file = root.path("etc/properpin/users").join(group());
    let problems = root.refused("check");
    assert!(problems.contains("pam_properpin.so: is 777"), "{problems}");
    assert!(problems.contains("libexec/properpin/properpin: differs from"), "{problems}");
    assert!(problems.contains("/etc/properpin/users: missing"), "{problems}");

    root.ok("install");
    fs::write(&user_file, "hash = $y$x\n").unwrap();
    fs::set_permissions(&user_file, Permissions::from_mode(0o644)).unwrap();
    let problems = root.refused("check");
    assert!(problems.contains(&format!("users/{}: is 644", group())), "{problems}");
    fs::set_permissions(&user_file, Permissions::from_mode(0o640)).unwrap();

    for (pinchecker, budget_dir) in [(0o755, 0o755), (0o4755, 0o700), (0o6755, 0o1777)] {
        root.ok("install");
        fs::set_permissions(root.path("usr/local/libexec/properpin/properpin-pinchecker"), Permissions::from_mode(pinchecker)).unwrap();
        fs::set_permissions(root.path("var/lib/properpin"), Permissions::from_mode(budget_dir)).unwrap();
        fs::write(root.path("etc/tmpfiles.d/properpin.conf"), "d /var/lib/properpin 0777 root root -\n").unwrap();
        fs::write(root.path("etc/sysusers.d/properpin.conf"), "u properpin - \"an account\" - -\n").unwrap();
        let problems = root.refused("check");
        assert!(problems.contains(&format!("properpin-pinchecker: is {pinchecker:o}")), "{problems}");
        assert!(problems.contains(&format!("/var/lib/properpin: is {budget_dir:o}")), "{problems}");
        assert!(problems.contains("tmpfiles.d/properpin.conf: not what install.sh writes"), "{problems}");
        assert!(problems.contains("sysusers.d/properpin.conf: not what install.sh writes"), "{problems}");
    }
}

/// PINs set while properpin had a pepper can't be converted, so install removes them, and every
/// budget from then, and the per-boot directory those versions kept.
#[test]
fn install_removes_what_versions_with_a_pepper_left() {
    let root = FakeRoot::new();
    root.ok("install");
    let users = root.path("etc/properpin/users");
    fs::write(users.join("old"), "hash = $y$x\ncleartext_salt_for_deriving_pepper_decryption_key = $y$s\nencrypted_pepper = 00\n").unwrap();
    fs::write(users.join("new"), "hash = $y$x\n").unwrap();
    fs::set_permissions(users.join("new"), Permissions::from_mode(0o640)).unwrap();
    let budgets = root.path("var/lib/properpin");
    fs::write(budgets.join("1000.budget"), "pending = none\nconcerning = none\ntotal = 0\ndisabled = no\n").unwrap();
    fs::write(budgets.join("1001.budget"), "consecutive = 0\npending = none\nconcerning = none\ntotal = 0\ndisabled = no\n").unwrap();
    fs::create_dir_all(root.path("run/properpin")).unwrap();
    fs::write(root.path("etc/properpin/config"), "expiry_hours = 4\n").unwrap();
    let said = root.ok("install");
    assert!(said.contains("removed the PIN of old") && said.contains("sudo properpin set"), "{said}");
    assert!(said.contains("sets expiry_hours or seal_cost, which no longer exist"), "{said}");
    assert!(!users.join("old").exists() && users.join("new").exists());
    assert!(!budgets.join("1000.budget").exists() && budgets.join("1001.budget").exists());
    assert!(!root.path("run/properpin").exists());
}

#[test]
fn check_wants_the_group() {
    let root = FakeRoot::new();
    root.ok("install");
    let output = Command::new("bash")
        .arg(INSTALL_SH)
        .args(["check", "--root"])
        .arg(root.dir.path())
        .args(["--owner", &whoami(), "--pinchecker-group", "no-such-group-properpin"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(says(&output).contains("no group named no-such-group-properpin"), "{}", says(&output));
}

#[test]
fn install_refuses_an_unexpected_pam_file_and_changes_nothing() {
    for (kde, why) in [
        ("auth include postlogin\n", "has 0 'auth substack password-auth' lines"),
        ("auth substack password-auth\nauth substack password-auth\n", "has 2 'auth substack password-auth' lines"),
        ("# properpin begin: left over\nauth substack password-auth\n", "no copy saved at install"),
    ] {
        let root = FakeRoot::new();
        fs::write(root.kde(), kde).unwrap();
        let said = root.refused("install");
        assert!(said.contains(why), "{said}");
        assert_eq!(fs::read_to_string(root.kde()).unwrap(), kde);
        assert!(!root.path("usr").exists(), "nothing installed: {said}");
    }
    let root = FakeRoot::new();
    fs::remove_file(root.kde()).unwrap();
    assert!(root.refused("install").contains("missing"));
    assert!(!root.kde().exists(), "install must never create the file");
}

/// An install over an older version's lines replaces them with this version's, and takes over the
/// copy that version saved under its old name.
#[test]
fn install_replaces_an_older_versions_lines() {
    let root = FakeRoot::new();
    root.ok("install");
    fs::write(root.kde(), format!("{OLD_BLOCK}{STOCK_KDE}")).unwrap();
    fs::rename(root.path("etc/properpin/kde.pam.without-properpin"), root.path("etc/properpin/kde.pam.before-enable")).unwrap();
    assert!(root.refused("check").contains("not the ones this version ships"));
    assert!(root.ok("install").contains("took properpin's lines out"));
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), installed_kde());
    assert!(!root.path("etc/properpin/kde.pam.before-enable").exists());
    assert_eq!(fs::read_to_string(root.path("etc/properpin/kde.pam.without-properpin")).unwrap(), STOCK_KDE);
    root.ok("check");
}

/// An install that fails its check leaves properpin's lines out, so the lock screen takes the
/// password only, and the next good install puts them back.
#[test]
fn a_failed_install_leaves_the_lines_out() {
    let root = FakeRoot::new();
    root.ok("install");
    let config = root.path("etc/properpin/config");
    fs::write(&config, "").unwrap();
    fs::set_permissions(&config, Permissions::from_mode(0o600)).unwrap();
    let said = root.refused("install");
    assert!(said.contains("config: is 600") && said.contains("left without properpin's lines"), "{said}");
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), STOCK_KDE);
    assert!(root.refused("check").contains("has no properpin lines"));
    fs::set_permissions(&config, Permissions::from_mode(0o644)).unwrap();
    root.ok("install");
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), installed_kde());
}

#[test]
fn install_keeps_changes_made_outside_the_block() {
    let root = FakeRoot::new();
    root.ok("install");
    let edited = format!("{}# added by an admin\n", fs::read_to_string(root.kde()).unwrap());
    fs::write(root.kde(), &edited).unwrap();
    root.ok("install");
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), edited);
    assert_eq!(
        fs::read_to_string(root.path("etc/properpin/kde.pam.without-properpin")).unwrap(),
        format!("{STOCK_KDE}# added by an admin\n"),
        "the copy is of the file as it is now, without properpin's lines"
    );
}

/// A block that can't be taken out cleanly: check says so, and install, like uninstall, starts
/// from the copy it saved, keeping the damaged file.
#[test]
fn install_repairs_a_damaged_block() {
    let root = FakeRoot::new();
    root.ok("install");
    let damaged = fs::read_to_string(root.kde()).unwrap().replace("# properpin end\n", "");
    fs::write(root.kde(), &damaged).unwrap();
    assert!(root.refused("check").contains("damaged around properpin's lines"));
    assert!(root.ok("install").contains("goes back to the copy saved at install"));
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), installed_kde());
    assert_eq!(fs::read_to_string(root.path("etc/properpin/kde.pam.damaged")).unwrap(), damaged);
}

#[test]
fn bad_arguments_change_nothing() {
    let root = FakeRoot::new();
    for args in [&["frobnicate"][..], &["install", "check"], &["enable"], &["disable"], &[]] {
        let output = Command::new("bash").arg(INSTALL_SH).args(args).arg("--root").arg(root.dir.path()).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}: {}", says(&output));
    }
    assert!(!root.path("usr").exists());
}

/// One command is the way out: uninstall takes properpin's lines out of PAM itself.
#[test]
fn uninstall_takes_the_lines_out_first() {
    let root = FakeRoot::new();
    root.ok("install");
    let edited = format!("{}# added by an admin\n", fs::read_to_string(root.kde()).unwrap());
    fs::write(root.kde(), &edited).unwrap();
    assert!(root.ok("uninstall").contains("took properpin's lines out"));
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), format!("{STOCK_KDE}# added by an admin\n"), "edits outside the block stay");
    assert!(!root.path("usr/local/lib64/security/pam_properpin.so").exists());
}

/// A block that can't be taken out cleanly, or a file without its stock auth line: uninstall puts
/// back the copy saved at install, and keeps the damaged file.
#[test]
fn uninstall_restores_a_damaged_pam_file() {
    let enabled = installed_kde();
    let block_end = enabled.find("# properpin end\n").unwrap() + "# properpin end\n".len();
    let first_line_end = enabled.find('\n').unwrap() + 1;
    let second_line_end = first_line_end + enabled[first_line_end..].find('\n').unwrap() + 1;
    let damaged = [
        ("the end marker deleted", enabled.replace("# properpin end\n", "")),
        ("the block twice", format!("{}{enabled}", &enabled[..block_end])),
        ("the markers stripped", enabled.lines().filter(|line| !line.starts_with("# properpin")).map(|line| format!("{line}\n")).collect()),
        ("cut off inside the block", enabled[..second_line_end].to_owned()),
        ("emptied", String::new()),
    ];
    for (what, text) in damaged {
        let root = FakeRoot::new();
        root.ok("install");
        fs::write(root.kde(), &text).unwrap();
        root.refused("check");
        let said = root.ok("uninstall");
        assert!(said.contains("again exactly as it was before properpin's lines went in"), "{what}: {said}");
        assert_eq!(fs::read_to_string(root.kde()).unwrap(), STOCK_KDE, "{what}");
        assert_eq!(fs::read_to_string(root.path("etc/properpin/kde.pam.damaged")).unwrap(), text, "{what}");
        assert!(!root.path("usr/local/libexec/properpin").exists(), "{what}");
    }
}

#[test]
fn uninstall_restores_a_deleted_pam_file() {
    let root = FakeRoot::new();
    root.ok("install");
    fs::remove_file(root.kde()).unwrap();
    root.ok("uninstall");
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), STOCK_KDE);
}

/// Without a copy to go back to, uninstall leaves everything in place rather than delete a module
/// the PAM file still names.
#[test]
fn uninstall_without_a_saved_copy_removes_nothing() {
    let root = FakeRoot::new();
    root.ok("install");
    let damaged = fs::read_to_string(root.kde()).unwrap().replace("# properpin end\n", "");
    fs::write(root.kde(), &damaged).unwrap();
    fs::remove_file(root.path("etc/properpin/kde.pam.without-properpin")).unwrap();
    assert!(root.refused("uninstall").contains("nothing was changed"));
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), damaged);
    assert!(root.path("usr/local/lib64/security/pam_properpin.so").exists());
}

/// Whatever else ended up in properpin's own directory, and whatever is already missing.
#[test]
fn uninstall_copes_with_extra_and_missing_files() {
    let root = FakeRoot::new();
    root.ok("install");
    fs::write(root.path("usr/local/libexec/properpin/left-behind"), "junk").unwrap();
    fs::remove_file(root.path("usr/local/bin/properpin")).unwrap();
    fs::remove_file(root.path("usr/local/lib64/security/pam_properpin.so")).unwrap();
    root.ok("uninstall");
    assert!(!root.path("usr/local/libexec/properpin").exists());
    root.ok("uninstall");
}
