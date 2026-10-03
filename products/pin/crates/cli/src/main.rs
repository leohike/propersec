//! `properpin`: manage the PIN that unlocks the KDE lock screen.
//!
//! ```text
//! sudo properpin set      choose a new PIN, typed twice
//! sudo properpin remove   delete it; the lock screen takes the password only
//! properpin status        your PIN: what is set, which rules apply, and whether it is armed now
//! ```
//!
//! `set` and `remove` change files only root may change, so they run under sudo or pkexec, and
//! getting there takes the password. That's the point: someone at an unlocked desk must not be able
//! to plant a PIN they know. The PIN is read from the terminal, or from stdin when it isn't one,
//! never from the command line, where other users could see it in the process list.
//!
//! The hash file is written readable by the helper's group only, so the user can't read it either:
//! `status` asks the setgid helper, which is the only program that reads hashes and counts.

#![forbid(unsafe_code)]

use std::io::{BufRead, IsTerminal, Read, stdin};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use properpin_core::{MAX_PIN_BYTES, Secret, Store, exit};
use properpin_sys::{Account, UserFiles, Yescrypt, current_euid, current_uid, group_by_name};

/// Manage the PIN that unlocks the KDE lock screen.
#[derive(Debug, Parser)]
#[command(name = "properpin", version)]
struct Cli {
    /// Where config and users/ live; /etc/properpin once installed
    #[arg(long, value_name = "DIR")]
    etc: PathBuf,
    /// The setgid helper, which status asks; /usr/local/libexec/properpin/properpin-helper once installed
    #[arg(long, value_name = "PATH")]
    helper: PathBuf,
    /// Who must own the files under --etc
    #[arg(long, value_name = "UID", default_value_t = 0)]
    owner: u32,
    /// The helper's group, the only one that may read hash files
    #[arg(long, value_name = "GROUP", default_value = "properpin")]
    group: String,
    #[command(subcommand)]
    command: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Choose a new PIN, typed twice
    Set(Target),
    /// Delete the PIN; the lock screen takes the password only
    Remove(Target),
    /// Show your PIN: what is set and whether it is armed right now
    Status,
}

#[derive(Debug, Args)]
struct Target {
    /// Whose PIN; default: the sudo or pkexec caller, or you
    #[arg(long)]
    user: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("properpin: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// `Ok(false)` is a clean "no".
fn run(cli: &Cli) -> Result<bool> {
    match &cli.command {
        Action::Set(target) => set(cli, &target_account(target)?)?,
        Action::Remove(target) => remove(cli, &target_account(target)?)?,
        Action::Status => return status(cli),
    }
    Ok(true)
}

fn files(cli: &Cli, account: &Account) -> Result<UserFiles> {
    Ok(UserFiles::new(&cli.etc, cli.owner, &account.name, account.uid)?)
}

/// Whose PIN: the one named, else whoever called sudo or pkexec, else whoever runs this.
fn target_account(target: &Target) -> Result<Account> {
    let account = match (&target.user, std::env::var("SUDO_USER"), std::env::var("PKEXEC_UID")) {
        (Some(name), _, _) => Account::by_name(name)?,
        (None, Ok(name), _) => Account::by_name(&name)?,
        (None, _, Ok(uid)) => Account::by_uid(uid.parse().context("PKEXEC_UID is not a uid")?)?,
        _ => Account::by_uid(current_uid())?,
    };
    if account.uid == 0 {
        bail!("root has no lock screen to unlock; name the user with --user");
    }
    Ok(account)
}

fn set(cli: &Cli, account: &Account) -> Result<()> {
    require_owner(cli.owner)?;
    let group = group_by_name(&cli.group)?;
    let files = files(cli, account)?;
    let settings = files.settings()?;
    let pin = ask_pin_twice()?;
    let pin = std::str::from_utf8(pin.as_bytes()).context("the PIN is not valid UTF-8")?;
    let problems = settings.pin_problems(pin);
    if !problems.is_empty() {
        bail!("the PIN needs {}", problems.join(", "));
    }
    // Only the hash changes. Per-user settings already in the file are kept.
    files.save_pin_hash(&Yescrypt.hash(pin, settings.hash_cost)?, group)?;
    println!("PIN set for {}. It works after the next password unlock at the lock screen.", account.name);
    Ok(())
}

fn remove(cli: &Cli, account: &Account) -> Result<()> {
    require_owner(cli.owner)?;
    if !files(cli, account)?.remove_pin()? {
        bail!("no PIN is set for {}", account.name);
    }
    println!("PIN removed for {}. The lock screen takes the password only.", account.name);
    Ok(())
}

/// The helper prints the status: only it can read the hash file and the counts.
fn status(cli: &Cli) -> Result<bool> {
    if current_uid() == 0 {
        bail!("status shows your own PIN; run it as yourself, without sudo");
    }
    let output = Command::new(&cli.helper)
        .arg("status")
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {}", cli.helper.display()))?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    match output.status.code().and_then(|code| u8::try_from(code).ok()) {
        Some(exit::YES) => Ok(true),
        _ => bail!("{} failed ({}); the system log says why", cli.helper.display(), output.status),
    }
}

fn require_owner(owner: u32) -> Result<()> {
    match current_euid() {
        euid if euid == owner => Ok(()),
        _ if owner == 0 => bail!("this changes files only root may change; run it with sudo"),
        _ => bail!("this must run as uid {owner}, the owner given with --owner"),
    }
}

/// The new PIN, typed twice. Both entries are wiped when dropped. rpassword's own buffers, and
/// the terminal's, are beyond reach; each String it returns is taken over without a copy.
fn ask_pin_twice() -> Result<Secret> {
    let (first, second) = if stdin().is_terminal() {
        let prompt = |text| rpassword::prompt_password(text).map(|typed| Secret::new(typed.into_bytes()));
        (prompt("New PIN: ")?, prompt("Same again: ")?)
    } else {
        let mut input = stdin().lock();
        (read_secret_line(&mut input)?, read_secret_line(&mut input)?)
    };
    if first.as_bytes() != second.as_bytes() {
        bail!("the two entries differ; nothing was changed");
    }
    Ok(first)
}

/// One line of `input`, without its newline. The buffer is sized once and the read is capped to
/// fit it, so it never grows (growing would leave an unwiped copy behind). A line longer than
/// any PIN comes back too long to be one, and its rest stays unread.
fn read_secret_line(input: &mut impl BufRead) -> Result<Secret> {
    let limit = MAX_PIN_BYTES + 2;
    let mut line = Vec::with_capacity(limit);
    input.take(limit as u64).read_until(b'\n', &mut line)?;
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    Ok(Secret::new(line))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_one_line_at_a_time_without_the_newline() {
        let mut input = &b"4859\n1234\nlast"[..];
        assert_eq!(read_secret_line(&mut input).unwrap().as_bytes(), b"4859");
        assert_eq!(read_secret_line(&mut input).unwrap().as_bytes(), b"1234");
        assert_eq!(read_secret_line(&mut input).unwrap().as_bytes(), b"last");
        assert_eq!(read_secret_line(&mut input).unwrap().as_bytes(), b"");
    }

    #[test]
    fn a_long_line_is_capped_too_long_to_be_a_pin() {
        let long = vec![b'1'; MAX_PIN_BYTES * 3];
        let typed = read_secret_line(&mut &long[..]).unwrap();
        assert_eq!(typed.as_bytes().len(), MAX_PIN_BYTES + 2);
        assert_eq!(properpin_core::usable_input(typed.as_bytes()), None);
    }
}
