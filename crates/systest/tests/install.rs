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

    fn copy(&self) -> PathBuf {
        self.path("etc/properpin/kde.pam.without-properpin")
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

/// properpin's two lines, as `packaging/kde-auth.pam` ships them, and the stock line they go around.
const CHECK_LINE: &str = "auth        sufficient    /usr/local/lib64/security/pam_properpin.so check\n";
const STOCK_LINE: &str = "auth        substack      password-auth\n";
const HOUSEKEEPING_LINE: &str = "auth        optional      /usr/local/lib64/security/pam_properpin.so housekeeping\n";

/// `kde` with properpin's lines put in around its stock substack line.
fn integrated(kde: &str) -> String {
    kde.replacen(STOCK_LINE, &format!("{CHECK_LINE}{STOCK_LINE}{HOUSEKEEPING_LINE}"), 1)
}

/// properpin's lines as versions before 2026-10-18 wrote them, the latest first: between markers, with
/// a pam_unix line of their own, and arguments the module now rejects.
const OLD_BLOCKS: [&str; 2] = [
    "\
# properpin begin: added by install.sh install; install.sh uninstall removes everything down to the end marker
auth  [success=done default=ignore]  /usr/local/lib64/security/pam_properpin.so check pinchecker=/usr/local/libexec/properpin/properpin-pinchecker config=/etc/properpin/config
auth  [success=ok default=die]       pam_unix.so use_first_pass
auth  optional                       /usr/local/lib64/security/pam_properpin.so housekeeping pinchecker=/usr/local/libexec/properpin/properpin-pinchecker
# properpin end
",
    "\
# properpin begin: added by install.sh enable; install.sh disable removes everything down to the end marker
auth  [success=done default=ignore]  /usr/local/lib64/security/pam_properpin.so check helper=/usr/local/libexec/properpin/properpin-helper config=/etc/properpin/config
auth  [success=ok default=die]       pam_unix.so use_first_pass
auth  optional                       /usr/local/lib64/security/pam_properpin.so start-accepting-pin helper=/usr/local/libexec/properpin/properpin-helper
# properpin end
",
];

/// install never touches the PAM file, and says what to run to put properpin's lines in.
#[test]
fn install_leaves_pam_alone_and_says_what_to_run() {
    let root = FakeRoot::new();
    let said = root.ok("install");
    assert_eq!(root.kde_text(), STOCK_KDE);
    assert!(said.contains("has no properpin lines") && said.contains("just integrate-into-pam"), "{said}");
    let checked = root.ok("check");
    assert!(checked.contains("all properpin files in place") && checked.contains("has no properpin lines"), "{checked}");
    assert_eq!(root.pam("check").0, Some(3));
    assert!(!root.copy().exists(), "nothing saved, since nothing changed");
}

#[test]
fn add_remove_and_uninstall_leave_pam_as_it_was() {
    let root = FakeRoot::new();
    root.ok("install");
    assert!(root.pam_ok("add").contains("has properpin's lines"));
    assert_eq!(root.kde_text(), integrated(STOCK_KDE));
    assert_eq!(fs::read_to_string(root.copy()).unwrap(), STOCK_KDE, "the copy is the file without properpin's lines");
    assert!(root.pam_ok("check").contains("has the lines this version ships"));
    assert!(root.ok("check").contains("has the lines this version ships"));

    // The fake root had only etc/pam.d: every directory install had to create goes again, except
    // those holding what is kept. Each is there now, or its absence afterwards would prove nothing.
    let installed = [
        "usr/local/lib64/security/pam_properpin.so",
        "usr/local/libexec/properpin",
        "usr/local/bin/properpin",
        "etc/sysusers.d/properpin.conf",
        "etc/tmpfiles.d/properpin.conf",
        "usr",
        "etc/sysusers.d",
        "etc/tmpfiles.d",
    ];
    for path in installed {
        assert!(root.path(path).exists(), "{path} isn't there after install");
    }
    // Lines naming a deleted module would lock the lock screen, so uninstall waits for remove.
    let said = root.refused("uninstall");
    assert!(
        said.contains("still has properpin's lines") && said.contains("just remove-from-pam") && said.contains("nothing was removed"),
        "{said}"
    );
    assert!(installed.iter().all(|path| root.path(path).exists()), "uninstall refused, but removed something");
    assert!(root.pam_ok("remove").contains("took properpin's lines out"));
    assert_eq!(root.kde_text(), STOCK_KDE);
    assert_eq!(root.pam("check").0, Some(3));
    root.ok("uninstall");
    assert_eq!(root.kde_text(), STOCK_KDE);
    for gone in installed {
        assert!(!root.path(gone).exists(), "{gone} is still there");
    }
    assert!(root.path("etc/properpin/users").is_dir(), "PINs are kept");
    assert!(root.copy().exists(), "the copy is kept, for whoever wants it");
    assert!(root.path("var/lib/properpin").is_dir(), "budgets are kept");
    assert!(root.pam_ok("remove").contains("nothing to do"));
}

#[test]
fn adding_twice_is_harmless() {
    let root = FakeRoot::new();
    root.ok("install");
    root.pam_ok("add");
    assert!(root.pam_ok("add").contains("already has the lines this version ships"));
    assert_eq!(root.kde_text(), integrated(STOCK_KDE), "the lines go in once");
    root.ok("install");
    assert_eq!(root.kde_text(), integrated(STOCK_KDE), "installing again leaves them as they are");
}

/// An older version's lines stay where they are through install, which says so, and add replaces
/// them, markers and pam_unix line included.
#[test]
fn add_replaces_an_older_versions_lines() {
    for old in OLD_BLOCKS {
        let root = FakeRoot::new();
        fs::write(root.kde(), format!("{old}{STOCK_KDE}")).unwrap();
        let said = root.ok("install");
        assert!(said.contains("not exactly the ones this version ships") && said.contains("just integrate-into-pam"), "{said}");
        assert_eq!(root.kde_text(), format!("{old}{STOCK_KDE}"), "install left them alone");
        assert!(root.refused("check").contains("not exactly the ones this version ships"));
        assert_eq!(root.pam("check").0, Some(1));
        root.pam_ok("add");
        assert_eq!(root.kde_text(), integrated(STOCK_KDE));
        assert_eq!(fs::read_to_string(root.copy()).unwrap(), STOCK_KDE);
        root.ok("check");
    }
}

#[test]
fn add_refuses_until_properpin_is_installed() {
    let root = FakeRoot::new();
    assert!(root.pam_refused("add").contains("properpin isn't installed"));
    assert!(!root.copy().exists());
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
        // The lines, for whoever puts them in by hand.
        assert!(said.contains(CHECK_LINE) && said.contains(HOUSEKEEPING_LINE), "{said}");
        assert!(!root.copy().exists());
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

/// Whatever properpin's lines look like after hand edits, remove takes out exactly them.
#[test]
fn remove_takes_out_every_properpin_line_and_nothing_else() {
    let root = FakeRoot::new();
    root.ok("install");
    let own = "auth        sufficient    pam_unix.so try_first_pass\n# an admin's note\n";
    let messy = format!(
        "{HOUSEKEEPING_LINE}{CHECK_LINE}{own}{}{CHECK_LINE}auth   [success=ok default=die]   pam_unix.so use_first_pass\n# properpin end\n",
        integrated(STOCK_KDE)
    );
    fs::write(root.kde(), &messy).unwrap();
    assert_eq!(root.pam("check").0, Some(1));
    root.pam_ok("remove");
    assert_eq!(root.kde_text(), format!("{own}{STOCK_KDE}"));
}

#[test]
fn add_keeps_changes_made_elsewhere() {
    let root = FakeRoot::new();
    root.ok("install");
    root.pam_ok("add");
    let edited = format!("{}# added by an admin\n", root.kde_text());
    fs::write(root.kde(), &edited).unwrap();
    assert!(root.pam_ok("add").contains("already has the lines this version ships"));
    assert_eq!(root.kde_text(), edited);
    fs::write(root.kde(), format!("{}{STOCK_KDE}# added by an admin\n", OLD_BLOCKS[0])).unwrap();
    root.pam_ok("add");
    assert_eq!(root.kde_text(), integrated(&format!("{STOCK_KDE}# added by an admin\n")));
    assert_eq!(
        fs::read_to_string(root.copy()).unwrap(),
        format!("{STOCK_KDE}# added by an admin\n"),
        "the copy is of the file as it is now, without properpin's lines"
    );
}

#[test]
fn install_puts_everything_in_place_and_twice_is_harmless() {
    let root = FakeRoot::new();
    root.ok("install");
    root.ok("install");
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
    // What a version before the pinchecker's rename left: a setgid helper nothing uses any more.
    fs::write(root.path("usr/local/libexec/properpin/properpin-helper"), "old").unwrap();
    assert!(root.refused("check").contains("properpin-helper: not installed by this version"));
    root.ok("install");
    assert!(!root.path("usr/local/libexec/properpin/properpin-helper").exists());
    assert!(root.path("usr/local/libexec/properpin/properpin-pinchecker").exists());
}

#[test]
fn check_finds_what_is_wrong() {
    let root = FakeRoot::new();
    root.ok("install");
    fs::set_permissions(root.path("usr/local/lib64/security/pam_properpin.so"), Permissions::from_mode(0o777)).unwrap();
    fs::write(root.path("usr/local/libexec/properpin/properpin"), "not the build").unwrap();
    fs::remove_dir(root.path("etc/properpin/users")).unwrap();
    let problems = root.refused("check");
    assert!(problems.contains("pam_properpin.so: is 777"), "{problems}");
    assert!(problems.contains("libexec/properpin/properpin: differs from"), "{problems}");
    assert!(problems.contains("/etc/properpin/users: missing"), "{problems}");

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

/// A user's file, a budget or the config that doctor finds fault with refuses the PINs it concerns
/// and no others, so install never judges them: it installs, and prints what doctor found.
#[test]
fn install_leaves_the_pins_and_the_config_to_doctor() {
    let root = FakeRoot::new();
    root.ok("install");
    let user_file = root.path("etc/properpin/users").join(whoami());
    fs::write(&user_file, "hash = $y$x\n").unwrap();
    fs::set_permissions(&user_file, Permissions::from_mode(0o644)).unwrap();
    let said = root.ok("install");
    assert!(said.contains(&format!("users/{}: readable by others", whoami())), "{said}");
    assert!(said.contains(&format!("fix: sudo properpin remove --user {}, then a new PIN", whoami())), "{said}");
    assert!(said.contains(&format!("1 problem; a PIN is set for {}", whoami())), "{said}");
    root.ok("check");

    // What versions with a pepper left: a PIN with settings that are gone, and a config with
    // settings that are gone. Both stay where they are, named by doctor.
    fs::write(&user_file, "hash = $y$x\nencrypted_pepper = 00\n").unwrap();
    fs::set_permissions(&user_file, Permissions::from_mode(0o640)).unwrap();
    fs::write(root.path("etc/properpin/config"), "expiry_hours = 4\n").unwrap();
    fs::set_permissions(root.path("etc/properpin/config"), Permissions::from_mode(0o644)).unwrap();
    fs::create_dir_all(root.path("run/properpin")).unwrap();
    let said = root.ok("install");
    assert!(said.contains("unknown setting \"encrypted_pepper\"") && said.contains("unknown setting \"expiry_hours\""), "{said}");
    assert!(said.contains("restore-defaults"), "{said}");
    assert!(user_file.exists() && root.path("etc/properpin/config").exists());
    assert!(!root.path("run/properpin").exists(), "/run/properpin was install's own, so it goes");
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
        .args(["--owner", &whoami(), "--pinchecker-group", "no-such-group-properpin"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(says(&output).contains("no group named no-such-group-properpin"), "{}", says(&output));
}

/// An install that fails halfway leaves the PAM file as it was, lines and all, and the next good
/// install finishes the job.
#[test]
fn a_failed_install_leaves_pam_alone() {
    let root = FakeRoot::new();
    root.ok("install");
    root.pam_ok("add");
    // Where install's directory must go, so install fails halfway.
    let users = root.path("etc/properpin/users");
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
