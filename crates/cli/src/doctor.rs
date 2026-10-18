//! `screenlock-pin doctor`: what makes the lock screen refuse a PIN, for every user, and the command that
//! fixes it. Every file is judged by the same code the PIN checker uses (`screenlock_pin_sys`), so doctor
//! finds what an attempt would refuse, and nothing it wouldn't. It runs as root, which can read every
//! file, so those rules also check that the PIN checker, running as the user, could read each one.
//!
//! It changes nothing. Its fixes are `screenlock-pin` commands: `remove`, `set`, `enable` and
//! `restore-defaults`, or installing again for the directories install makes.

use anyhow::Result;
use screenlock_pin_core::{Clock, Hasher, Store};
use screenlock_pin_sys::{Account, AllUsers};

/// One thing wrong: what, what it does at the lock screen, and what fixes it.
#[derive(Debug)]
pub struct Problem {
    pub what: String,
    pub so: String,
    pub fix: String,
}

/// What doctor found: the problems, and the users who have a PIN set, usable or not, including
/// those whose file can't be read.
#[derive(Debug, Default)]
pub struct Findings {
    pub problems: Vec<Problem>,
    pub pins: Vec<String>,
}

/// Look at every user's files, and at what they all share.
pub fn examine(all: &AllUsers, hasher: &impl Hasher, clock: &impl Clock) -> Result<Findings> {
    let mut found = Findings::default();
    let mut problem = |what: String, so: &str, fix: String| found.problems.push(Problem { what, so: so.into(), fix });
    let again = "install screenlock-pin again, which puts the directory right".to_string();
    let config = all.config_settings();
    if let Err(error) = &config {
        let fix = "correct it by hand, or delete the config, which brings back every default: sudo screenlock-pin restore-defaults";
        problem(error.to_string(), "the lock screen refuses every PIN", fix.into());
    }
    let budget_dir = all.check_budget_dir();
    if let Err(error) = &budget_dir {
        problem(error.to_string(), "the lock screen refuses every PIN", again.clone());
    }
    if let Err(error) = all.check_users_dir() {
        problem(error.to_string(), "it isn't as install makes it, so the PIN checker may not reach the files in it", again);
    }
    for name in all.names()? {
        let path = all.users_dir().join(&name);
        let account = match Account::by_name(&name) {
            Ok(account) if account.uid != 0 => account,
            Ok(_) => {
                let what = format!("{}: root has no lock screen to unlock", path.display());
                problem(what, "nobody's PIN", format!("sudo screenlock-pin remove --user {name}"));
                continue;
            }
            Err(_) => {
                let what = format!("{}: no account is named {name}", path.display());
                let so = "nobody's PIN, but an account made later with that name would get it";
                problem(what, so, format!("sudo screenlock-pin remove --user {name}"));
                continue;
            }
        };
        let files = all.user(&name, account.uid)?;
        let refused = format!("the lock screen refuses {name}'s PIN");
        let new_pin = format!("sudo screenlock-pin remove --user {name}, then a new PIN with: sudo screenlock-pin set --user {name}");
        // A file that can't be read counts as a PIN: it is one, almost always.
        let settings = files.user_settings();
        if settings.as_ref().is_ok_and(|settings| settings.pin_hash.is_empty()) {
            continue;
        }
        found.pins.push(name.clone());
        let settings = match settings {
            Ok(settings) => settings,
            Err(error) => {
                problem(error.to_string(), &refused, new_pin);
                continue;
            }
        };
        if let Err(error) = hasher.verify("", &settings.pin_hash) {
            problem(format!("{}: {error}", path.display()), &refused, new_pin);
            continue;
        }
        if budget_dir.is_err() {
            continue;
        }
        if let Err(error) = files.check_budget() {
            let fix = format!("sudo screenlock-pin set --user {name}, with the same PIN or a new one, which starts both over");
            problem(error.to_string(), &refused, fix);
            continue;
        }
        if config.is_err() {
            continue;
        }
        if let Some(limit) = files.load_budget()?.judge(clock.now()?, &files.settings()?).disabled {
            let what = format!("{name}'s PIN is disabled after {limit}");
            let fix = format!("sudo screenlock-pin enable --user {name} keeps the PIN; sudo screenlock-pin set --user {name} replaces it");
            problem(what, &format!("{refused} until it is enabled again or replaced"), fix);
        }
    }
    Ok(found)
}

/// What doctor prints: each problem in three lines, then a summary.
pub fn report(found: &Findings) -> String {
    let mut out = String::new();
    for Problem { what, so, fix } in &found.problems {
        out += &format!("{what}\n    {so}\n    fix: {fix}\n");
    }
    let pins = match found.pins.as_slice() {
        [] => "no PIN is set".to_string(),
        [one] => format!("a PIN is set for {one}"),
        [rest @ .., last] => format!("PINs are set for {} and {last}", rest.join(", ")),
    };
    out += &match found.problems.len() {
        0 => format!("no problems; {pins}\n"),
        1 => format!("1 problem; {pins}\n"),
        count => format!("{count} problems; {pins}\n"),
    };
    out
}
