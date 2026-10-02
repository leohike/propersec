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
            .args(["--owner", &whoami()])
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
            .args(["build", "--quiet", "--package", "pam_properpin", "--package", "properpin-cli", "--manifest-path", manifest])
            .status()
            .unwrap();
        assert!(status.success(), "building the module and the command failed");
        std::env::current_exe().unwrap().parent().and_then(Path::parent).unwrap().to_path_buf()
    })
}

#[test]
fn install_enable_disable_uninstall_leaves_pam_as_it_was() {
    let root = FakeRoot::new();
    root.ok("install");
    assert!(root.ok("check").contains("no properpin lines"));
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), STOCK_KDE, "install must not touch PAM");

    root.ok("enable");
    let enabled = fs::read_to_string(root.kde()).unwrap();
    let lines: Vec<&str> = enabled.lines().collect();
    assert!(lines[0].starts_with("# properpin begin"), "{enabled}");
    assert!(lines[1].contains("pam_properpin.so check etc=/etc/properpin run_base=/run/user"));
    assert!(lines[2].contains("pam_unix.so use_first_pass"));
    assert!(lines[3].contains("pam_properpin.so arm"));
    assert_eq!(lines[4], "# properpin end");
    assert!(enabled.ends_with(STOCK_KDE), "everything stock stays, below the block");
    assert!(root.ok("check").contains("has properpin's lines"));
    assert_eq!(fs::read_to_string(root.path("etc/properpin/kde.pam.before-enable")).unwrap(), STOCK_KDE);

    assert!(root.refused("uninstall").contains("run install.sh disable first"));
    assert!(root.ok("disable").contains("exactly as it was before enable"));
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), STOCK_KDE);
    assert!(root.ok("disable").contains("nothing to do"));

    root.ok("uninstall");
    for gone in ["usr/local/lib64/security/pam_properpin.so", "usr/local/libexec/properpin", "usr/local/bin/properpin"] {
        assert!(!root.path(gone).exists(), "{gone} is still there");
    }
    assert!(root.path("etc/properpin/users").is_dir(), "PINs are kept");
}

#[test]
fn install_puts_everything_in_place_and_twice_is_harmless() {
    let root = FakeRoot::new();
    root.ok("install");
    root.ok("install");
    let check = root.ok("check");
    assert!(check.contains("all properpin files in place"), "{check}");
    let command = fs::read_to_string(root.path("usr/local/bin/properpin")).unwrap();
    assert!(command.contains("exec /usr/local/libexec/properpin/properpin --etc /etc/properpin --run-base /run/user \"$@\""), "{command}");
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
}

#[test]
fn enable_refuses_anything_unexpected_and_leaves_the_file_alone() {
    let root = FakeRoot::new();
    assert!(root.refused("enable").contains("don't check out"), "enable before install");
    root.ok("install");
    for (kde, why) in [
        ("auth include postlogin\n", "has 0 'auth substack password-auth' lines"),
        ("auth substack password-auth\nauth substack password-auth\n", "has 2 'auth substack password-auth' lines"),
        ("# properpin begin: left over\nauth substack password-auth\n", "stray properpin marker"),
    ] {
        fs::write(root.kde(), kde).unwrap();
        let said = root.refused("enable");
        assert!(said.contains(why), "{said}");
        assert_eq!(fs::read_to_string(root.kde()).unwrap(), kde);
    }
    fs::remove_file(root.kde()).unwrap();
    assert!(root.refused("enable").contains("missing"));
    assert!(!root.kde().exists(), "enable must never create the file");

    fs::write(root.kde(), STOCK_KDE).unwrap();
    root.ok("enable");
    assert!(root.refused("enable").contains("already has properpin's lines"));
}

#[test]
fn disable_keeps_changes_made_outside_the_block() {
    let root = FakeRoot::new();
    root.ok("install");
    root.ok("enable");
    let edited = format!("{}# added by an admin\n", fs::read_to_string(root.kde()).unwrap());
    fs::write(root.kde(), &edited).unwrap();
    assert!(root.ok("disable").contains("changed in between"));
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), format!("{STOCK_KDE}# added by an admin\n"));
}

#[test]
fn disable_refuses_a_damaged_block() {
    let root = FakeRoot::new();
    root.ok("install");
    root.ok("enable");
    let damaged = fs::read_to_string(root.kde()).unwrap().replace("# properpin end\n", "");
    fs::write(root.kde(), &damaged).unwrap();
    assert!(root.refused("disable").contains("fix it by hand"));
    assert_eq!(fs::read_to_string(root.kde()).unwrap(), damaged);
}

#[test]
fn bad_arguments_change_nothing() {
    let root = FakeRoot::new();
    for args in [&["frobnicate"][..], &["install", "enable"], &[]] {
        let output = Command::new("bash").arg(INSTALL_SH).args(args).arg("--root").arg(root.dir.path()).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}: {}", says(&output));
    }
    assert!(!root.path("usr").exists());
}
