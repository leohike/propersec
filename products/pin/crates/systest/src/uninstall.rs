//! The uninstall cases: what is under test is `install.sh uninstall`, not properpin. Each case, in
//! a fresh container of its own:
//!
//! - records the stock system: what the lock screen, `sudo`, `su` and `login` answer to the right
//!   and a wrong password, every file in `/etc/pam.d` byte for byte, the files properpin's paths
//!   hold, and the groups;
//! - installs a deliberately broken properpin, through `install.sh` and under exactly the real
//!   names (the variants come from `crates/brokenpin`, built by `testing/podman/build-broken.sh`),
//!   or a real one followed by a damaged `/etc/pam.d/kde`;
//! - checks that it really broke the lock screen the way the case says, and that `sudo`, the way
//!   in for a repair, still works;
//! - runs `install.sh uninstall --yes`, and checks that the record matches again, apart from what
//!   uninstall keeps on purpose (`/etc/properpin`, `/var/lib/properpin`, the `properpin` group);
//! - runs uninstall again, which must change nothing, then installs the real properpin and checks
//!   that the PIN works and that uninstalling it also leaves the record.
//!
//! docs/install-uninstall-with-a-broken-properpin.md has the reasoning.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;

use super::*;

/// Where the Containerfile puts the broken variants, one directory each.
const BROKEN: &str = "/opt/properpin/broken";
/// An attempt still running after this is dead: the lock screen would hang on it.
const DEAD_AFTER: Duration = Duration::from_secs(30);
/// The module waits ten seconds for a helper before killing it.
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);
/// Kept by uninstall on purpose, with the PINs and the budgets.
const KEPT: [&str; 2] = ["/etc/properpin", "/var/lib/properpin"];
/// Where anything of properpin's could be; recorded before and after.
const WATCHED: [&str; 6] = ["/usr/local", "/etc/sysusers.d", "/etc/tmpfiles.d", "/etc/properpin", RUN_DIR, BUDGET_DIR];

/// What a broken properpin does to the lock screen.
#[derive(Debug, Clone, Copy)]
enum Breaks {
    /// The right password kills the lock screen's process.
    Dies,
    /// The right password never gets an answer.
    Hangs,
    /// A wrong password unlocks the lock screen.
    LetsAnyoneIn,
    /// The right password unlocks, but only after the module's helper timeout, twice over.
    Slows,
    /// The right password is refused.
    LocksOut,
    /// `install.sh disable` gives up on the PAM file, so only uninstall can repair it.
    DisableGivesUp,
}

struct Case {
    name: &'static str,
    /// The build to install: a directory under `BROKEN`, or `None` for the real one.
    variant: Option<&'static str>,
    /// Done as root after install, enable and set.
    damage: fn() -> Outcome,
    breaks: &'static [Breaks],
}

fn no_damage() -> Outcome {
    Ok(())
}

const CASES: &[Case] = &[
    Case { name: "module-panics", variant: Some("module-panics"), damage: no_damage, breaks: &[Breaks::Dies] },
    Case { name: "module-segfaults", variant: Some("module-segfaults"), damage: no_damage, breaks: &[Breaks::Dies] },
    Case { name: "module-sleeps", variant: Some("module-sleeps"), damage: no_damage, breaks: &[Breaks::Hangs] },
    Case { name: "module-says-yes", variant: Some("module-says-yes"), damage: no_damage, breaks: &[Breaks::LetsAnyoneIn] },
    Case { name: "module-missing-symbol", variant: Some("module-missing-symbol"), damage: no_damage, breaks: &[Breaks::LocksOut] },
    Case { name: "module-garbage", variant: Some("module-garbage"), damage: no_damage, breaks: &[Breaks::LocksOut] },
    Case { name: "module-deleted", variant: None, damage: delete_the_module, breaks: &[Breaks::LocksOut] },
    Case { name: "helper-says-yes", variant: Some("helper-says-yes"), damage: no_damage, breaks: &[Breaks::LetsAnyoneIn] },
    Case { name: "helper-sleeps", variant: Some("helper-sleeps"), damage: no_damage, breaks: &[Breaks::Slows] },
    Case { name: "kde-end-marker-deleted", variant: None, damage: delete_the_end_marker, breaks: &[Breaks::DisableGivesUp] },
    Case { name: "kde-block-twice", variant: None, damage: repeat_the_block, breaks: &[Breaks::DisableGivesUp] },
    Case { name: "kde-markers-stripped", variant: None, damage: strip_the_markers, breaks: &[Breaks::DisableGivesUp] },
    Case { name: "kde-cut-inside-block", variant: None, damage: cut_inside_the_block, breaks: &[Breaks::DisableGivesUp, Breaks::LocksOut] },
];

fn delete_the_module() -> Outcome {
    fs::remove_file("/usr/local/lib64/security/pam_properpin.so").map_err(message)
}

fn edit_kde(change: impl FnOnce(&str) -> String) -> Outcome {
    let text = fs::read_to_string(KDE).map_err(message)?;
    fs::write(KDE, change(&text)).map_err(message)
}

fn delete_the_end_marker() -> Outcome {
    edit_kde(|text| text.lines().filter(|line| *line != "# properpin end").map(|line| format!("{line}\n")).collect())
}

/// As if enable had run twice on a file that already had the block.
fn repeat_the_block() -> Outcome {
    edit_kde(|text| {
        let block: String = text.lines().take_while(|line| *line != "# properpin end").map(|line| format!("{line}\n")).collect();
        format!("{block}# properpin end\n{text}")
    })
}

/// The lines left in, their markers gone, as a careless hand edit could leave them.
fn strip_the_markers() -> Outcome {
    edit_kde(|text| text.lines().filter(|line| !line.starts_with("# properpin")).map(|line| format!("{line}\n")).collect())
}

/// A half-written file: the begin marker and the PIN line, and nothing after them.
fn cut_inside_the_block() -> Outcome {
    edit_kde(|text| text.lines().take(2).map(|line| format!("{line}\n")).collect())
}

pub(super) fn list() -> ExitCode {
    for case in CASES {
        println!("{}", case.name);
    }
    ExitCode::SUCCESS
}

pub(super) fn run(name: &str) -> ExitCode {
    let Some(case) = CASES.iter().find(|case| case.name == name) else {
        println!("FAILED  uninstall: no case named {name}");
        return ExitCode::from(2);
    };
    match Bench::set_up().and_then(|bench| bench.case(case)) {
        Ok(()) => {
            println!("ok      uninstall: {name}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("FAILED  uninstall: {name}\n        {}", error.replace('\n', "\n        "));
            ExitCode::FAILURE
        }
    }
}

/// How one attempt went, in the test user's own process.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ran {
    Unlocked,
    Refused,
    /// Ended by a signal, or anything else but a clean exit.
    Died(String),
    /// Still running after `DEAD_AFTER`, and killed.
    Hung,
}

#[derive(Debug)]
struct Probe {
    ran: Ran,
    took: Duration,
}

/// Everything recorded about the system, before the install and after the uninstall.
#[derive(Debug, PartialEq, Eq)]
struct Record {
    /// "kde right" and so on: each service's answer to the right and a wrong password.
    answers: BTreeMap<String, Ran>,
    /// Every file in `/etc/pam.d`, with its bytes.
    pam: BTreeMap<String, Vec<u8>>,
    /// Every path under `WATCHED`, with its kind, mode and owner.
    paths: BTreeMap<String, String>,
    groups: BTreeSet<String>,
}

struct Bench {
    user: Account,
    syslog: Syslog,
}

impl Bench {
    fn set_up() -> Outcome<Self> {
        if !Path::new("/run/.containerenv").exists() {
            return Err("not in a container; this test breaks /etc/pam.d, so it runs in podman only".into());
        }
        Ok(Self { user: Account::by_name(USER).map_err(message)?, syslog: Syslog::listen()? })
    }

    fn case(&self, case: &Case) -> Outcome {
        let before = self.record()?;
        let wanted =
            [("kde right", Ran::Unlocked), ("kde wrong", Ran::Refused), ("sudo right", Ran::Unlocked), ("sudo wrong", Ran::Refused)];
        for (what, ran) in wanted {
            if before.answers.get(what) != Some(&ran) {
                return Err(format!("before anything was installed, {what} gave {:?}: {before:?}", before.answers.get(what)));
            }
        }

        let from = case.variant.map_or(format!("{PRODUCT}/build"), |variant| format!("{BROKEN}/{variant}"));
        install_sh_from(&from, &["install"])?;
        install_sh_from(&from, &["enable", "--yes"])?;
        properpin_as_root(&["set", "--user", USER], &format!("{PIN}\n{PIN}\n"))?;
        (case.damage)()?;
        self.is_broken(case).map_err(|error| format!("the broken install didn't break as expected: {error}"))?;

        let said = install_sh(&["uninstall", "--yes"]).map_err(|error| format!("uninstall failed: {error}"))?;
        no_helper_left()?;
        self.matches(&before, "after uninstall").map_err(|error| format!("{error}\nuninstall said:\n{said}"))?;

        install_sh(&["uninstall", "--yes"]).map_err(|error| format!("a second uninstall failed: {error}"))?;
        self.matches(&before, "after a second uninstall")?;

        // properpin itself still installs and works afterwards, and goes again just as cleanly.
        install_sh(&["install"])?;
        install_sh(&["enable", "--yes"])?;
        properpin_as_root(&["set", "--user", USER], &format!("{PIN}\n{PIN}\n"))?;
        self.expect("kde", PASSWORD, &Ran::Unlocked, "the password, reinstalled")?;
        self.expect("kde", PIN, &Ran::Unlocked, "the PIN, reinstalled")?;
        install_sh(&["uninstall", "--yes"])?;
        self.matches(&before, "after installing the real properpin and uninstalling it")
    }

    /// The case's breakage, seen the way the lock screen would see it, while `sudo` stays usable.
    fn is_broken(&self, case: &Case) -> Outcome {
        for breaks in case.breaks {
            match breaks {
                Breaks::Dies => {
                    let probe = self.probe("kde", PASSWORD)?;
                    if !matches!(probe.ran, Ran::Died(_)) {
                        return Err(format!("the right password should kill the attempt: {probe:?}"));
                    }
                }
                Breaks::Hangs => {
                    let probe = self.probe("kde", PASSWORD)?;
                    if probe.ran != Ran::Hung {
                        return Err(format!("the right password should hang: {probe:?}"));
                    }
                }
                Breaks::LetsAnyoneIn => self.expect("kde", "not the password", &Ran::Unlocked, "a wrong password")?,
                Breaks::Slows => {
                    let probe = self.probe("kde", PASSWORD)?;
                    if probe.ran != Ran::Unlocked || probe.took < HELPER_TIMEOUT * 2 {
                        return Err(format!("the right password should unlock after two helper timeouts: {probe:?}"));
                    }
                }
                Breaks::LocksOut => self.expect("kde", PASSWORD, &Ran::Refused, "the right password")?,
                Breaks::DisableGivesUp => {
                    let gave_up = Command::new("bash")
                        .arg(format!("{PRODUCT}/packaging/install.sh"))
                        .args(["disable", "--yes"])
                        .output()
                        .map_err(message)?;
                    let said = String::from_utf8_lossy(&gave_up.stderr);
                    if gave_up.status.success() || !said.contains("fix it by hand") {
                        return Err(format!("disable should give up on the damaged PAM file: {said}"));
                    }
                }
            }
        }
        self.expect("sudo", PASSWORD, &Ran::Unlocked, "sudo, the way in for a repair")
    }

    fn expect(&self, service: &str, typed: &str, ran: &Ran, what: &str) -> Outcome {
        let probe = self.probe(service, typed)?;
        if probe.ran == *ran { Ok(()) } else { Err(format!("{what} at {service}: {probe:?}, not {ran:?}")) }
    }

    /// The record matches `before`, apart from what uninstall keeps on purpose.
    fn matches(&self, before: &Record, when: &str) -> Outcome {
        let after = self.record()?;
        let mut differences = Vec::new();
        for (what, ran) in &before.answers {
            if after.answers.get(what) != Some(ran) {
                differences.push(format!("{what}: {ran:?} before, {:?} {when}", after.answers.get(what)));
            }
        }
        for name in before.pam.keys().chain(after.pam.keys()).collect::<BTreeSet<_>>() {
            if before.pam.get(name) != after.pam.get(name) {
                let text = |bytes: Option<&Vec<u8>>| bytes.map_or("(missing)".into(), |bytes| String::from_utf8_lossy(bytes).into_owned());
                differences.push(format!(
                    "{name} differs:\nbefore:\n{}\n{when}:\n{}",
                    text(before.pam.get(name)),
                    text(after.pam.get(name))
                ));
            }
        }
        let kept = |path: &str| KEPT.iter().any(|kept| path == *kept || path.starts_with(&format!("{kept}/")));
        for path in before.paths.keys().chain(after.paths.keys()).collect::<BTreeSet<_>>() {
            match (before.paths.get(path), after.paths.get(path)) {
                (None, Some(_)) if kept(path) => {}
                (old, new) if old != new => differences.push(format!("{path}: {old:?} before, {new:?} {when}")),
                _ => {}
            }
        }
        for group in before.groups.symmetric_difference(&after.groups) {
            if group != HELPER_GROUP {
                differences.push(format!("group {group}: there only before or only {when}"));
            }
        }
        if differences.is_empty() { Ok(()) } else { Err(format!("the system isn't as it was:\n{}", differences.join("\n"))) }
    }

    fn record(&self) -> Outcome<Record> {
        let mut answers = BTreeMap::new();
        for service in ["kde", "sudo", "su", "login"] {
            for (label, typed) in [("right", PASSWORD), ("wrong", "not the password")] {
                answers.insert(format!("{service} {label}"), self.probe(service, typed)?.ran);
            }
        }
        let mut pam = BTreeMap::new();
        for entry in fs::read_dir("/etc/pam.d").map_err(message)? {
            let path = entry.map_err(message)?.path();
            pam.insert(path.display().to_string(), fs::read(&path).map_err(message)?);
        }
        let mut paths = BTreeMap::new();
        for top in WATCHED {
            walk(Path::new(top), &mut paths)?;
        }
        let group = fs::read_to_string("/etc/group").map_err(message)?;
        let groups = group.lines().filter_map(|line| line.split(':').next()).map(str::to_owned).collect();
        Ok(Record { answers, pam, paths, groups })
    }

    /// One attempt as the test user, in a process of its own, as the lock screen runs.
    fn probe(&self, service: &str, typed: &str) -> Outcome<Probe> {
        let started = Instant::now();
        let mut child = Command::new(std::env::current_exe().map_err(message)?)
            .args(["attempt", service, USER])
            .uid(self.user.uid)
            .gid(self.user.gid)
            .env_clear()
            .env("PATH", "/usr/bin")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(message)?;
        // A module that dies before reading leaves nobody to read this.
        let _ = child.stdin.take().expect("piped").write_all(typed.as_bytes());
        while child.try_wait().map_err(message)?.is_none() {
            if started.elapsed() > DEAD_AFTER {
                let _ = child.kill();
                let _ = child.wait();
                self.syslog.take();
                return Ok(Probe { ran: Ran::Hung, took: started.elapsed() });
            }
            thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().map_err(message)?;
        let took = started.elapsed();
        self.syslog.take();
        if !output.status.success() {
            return Ok(Probe { ran: Ran::Died(output.status.to_string()), took });
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let ran = match stdout.lines().find_map(|line| line.strip_prefix("status ")) {
            Some(status) if status == pamharness::PAM_SUCCESS.to_string() => Ran::Unlocked,
            Some(_) => Ran::Refused,
            None => Ran::Died(format!("no answer: {stdout}")),
        };
        Ok(Probe { ran, took })
    }
}

/// Every path under `path`, not following symlinks, with its kind, mode and owner.
fn walk(path: &Path, into: &mut BTreeMap<String, String>) -> Outcome {
    let info = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        result => result.map_err(message)?,
    };
    let kind = if info.is_dir() {
        "dir"
    } else if info.file_type().is_symlink() {
        "symlink"
    } else {
        "file"
    };
    into.insert(path.display().to_string(), format!("{kind} {:o} {}:{}", info.mode() & 0o7777, info.uid(), info.gid()));
    if info.is_dir() {
        for entry in fs::read_dir(path).map_err(message)? {
            walk(&entry.map_err(message)?.path(), into)?;
        }
    }
    Ok(())
}
