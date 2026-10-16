//! `properpin`: manage the PIN that unlocks the KDE lock screen.
//!
//! ```text
//! sudo properpin set      choose a new PIN, typed twice; the lock screen takes it at once, and
//!                         its budget of failures starts over
//! sudo properpin enable   turn a PIN disabled by too many concerning failures back on
//! sudo properpin remove   delete it; the lock screen takes the password only
//! properpin status        your PIN: what is set, which rules apply, and whether it is enabled,
//!                         paused or disabled
//! ```
//!
//! `set`, `enable` and `remove` change files only root may change, so they run under sudo or pkexec, and
//! getting there takes the password. That's the point: someone at an unlocked desk must not be able
//! to plant a PIN they know. The PIN is read from the terminal, or from stdin when it isn't one,
//! never from the command line, where other users could see it in the process list.
//!
//! The hash file is written readable by the pinchecker's group only, so the user can't read it either:
//! `status` asks the setgid pinchecker, which is the only program that reads hashes and counts.
//!
//! `set` refuses a PIN that is the user's password, comparing it, as root, with the user's hash in
//! `/etc/shadow`, so it never asks for the password. `set` with the PIN already set, and `enable`
//! of a disabled PIN, keep a PIN that may have been guessed, so they ask first; `--yes` skips the
//! question.

// Stricter checks for shipped code (docs/plan-tools.md): every unsafe block explains why it is
// sound, nothing indexes or slices without a bounds check, and no cast silently drops bits.
#![warn(clippy::undocumented_unsafe_blocks, clippy::indexing_slicing, clippy::cast_possible_truncation)]
#![forbid(unsafe_code)]

use std::io::{BufRead, IsTerminal, Read, Write, stdin};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use properpin_core::{Clock, Hasher, MAX_PIN_BYTES, Secret, Store, exit};
use properpin_sys::{Account, SystemClock, UserFiles, Yescrypt, current_euid, current_uid, group_by_name, shadow_hash};

/// Manage the PIN that unlocks the KDE lock screen.
#[derive(Debug, Parser)]
#[command(name = "properpin", version)]
struct Cli {
    /// Where config and users/ live; /etc/properpin once installed
    #[arg(long, value_name = "DIR")]
    etc: PathBuf,
    /// Where each user's budget of failures lives; /var/lib/properpin once installed
    #[arg(long, value_name = "DIR")]
    budget: PathBuf,
    /// The shadow file set compares a new PIN with, to refuse the password as a PIN
    #[arg(long, value_name = "PATH", default_value = "/etc/shadow")]
    shadow: PathBuf,
    /// The setgid pinchecker, which status asks; /usr/local/libexec/properpin/properpin-pinchecker once installed
    #[arg(long, value_name = "PATH")]
    pinchecker: PathBuf,
    /// Who must own the files under --etc, and the --budget directory
    #[arg(long, value_name = "UID", default_value_t = 0)]
    owner: u32,
    /// The pinchecker's group, the only one that may read hash files
    #[arg(long, value_name = "GROUP", default_value = "properpin")]
    group: String,
    #[command(subcommand)]
    command: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Choose a new PIN, typed twice; the lock screen takes it at once, and its budget of failures
    /// starts over
    Set(Confirmable),
    /// Turn a PIN disabled by too many concerning failures back on, keeping it
    Enable(Confirmable),
    /// Delete the PIN; the lock screen takes the password only
    Remove(Target),
    /// Show your PIN: what is set, and whether it is enabled, paused or disabled right now
    Status,
}

#[derive(Debug, Args)]
struct Target {
    /// Whose PIN; default: the sudo or pkexec caller, or you
    #[arg(long)]
    user: Option<String>,
}

#[derive(Debug, Args)]
struct Confirmable {
    #[command(flatten)]
    target: Target,
    /// Don't ask before keeping a PIN that may have been guessed
    #[arg(long)]
    yes: bool,
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
        Action::Set(asked) => set(cli, &target_account(&asked.target)?, asked.yes)?,
        Action::Enable(asked) => enable(cli, &target_account(&asked.target)?, asked.yes)?,
        Action::Remove(target) => remove(cli, &target_account(target)?)?,
        Action::Status => return status(cli),
    }
    Ok(true)
}

fn files(cli: &Cli, account: &Account) -> Result<UserFiles> {
    let group = group_by_name(&cli.group)?;
    let files = UserFiles::new(&cli.etc, cli.owner, &account.name, account.uid)?;
    Ok(files.with_budget(&cli.budget, cli.owner, group))
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

fn set(cli: &Cli, account: &Account, yes: bool) -> Result<()> {
    require_owner(cli.owner)?;
    let group = group_by_name(&cli.group)?;
    let files = files(cli, account)?;
    let settings = files.settings()?;
    let mut input = stdin().lock();
    let pin = ask_pin_twice(&mut input)?;
    let pin = std::str::from_utf8(pin.as_bytes()).context("the PIN is not valid UTF-8")?;
    let problems = settings.pin_problems(pin);
    if !problems.is_empty() {
        bail!("the PIN needs {}", problems.join(", "));
    }
    match shadow_hash(&cli.shadow, &account.name)? {
        None => {
            eprintln!("Warning: {} has no entry in {}, so the PIN wasn't compared with the password.", account.name, cli.shadow.display())
        }
        Some(shadow) => match Yescrypt.is_password(pin, &shadow)? {
            Some(true) => bail!("the PIN must not be the password; nothing was changed"),
            Some(false) => {}
            None => eprintln!(
                "Warning: {} has no password hash in {}, so there was nothing to compare with.",
                account.name,
                cli.shadow.display()
            ),
        },
    }
    if !settings.pin_hash.is_empty() && Yescrypt.verify(pin, &settings.pin_hash)? {
        let total = files.load_budget().map(|budget| budget.total).unwrap_or_default();
        confirm(
            &mut input,
            yes,
            &format!(
                "This is the PIN already set. Setting it again starts its budget over, and forgets its {total} concerning failures \
                 since it was set, which may have been someone guessing it."
            ),
        )?;
    }
    let hash = Yescrypt.hash(pin, settings.hash_cost)?;
    // Only the hash changes. Per-user settings already in the file are kept.
    files.save_pin(&[(properpin_core::HASH_SETTING, &hash)], group)?;
    // A new PIN, so no failure against the old one counts any more, and nothing stays paused or disabled.
    files.remove_budget()?;
    println!("PIN set for {}. The lock screen takes it from now on.", account.name);
    Ok(())
}

/// The same PIN back on, with its recent failures forgotten. The total since it was set is kept,
/// so its limit still holds: once reached, only a new PIN will do.
fn enable(cli: &Cli, account: &Account, yes: bool) -> Result<()> {
    require_owner(cli.owner)?;
    let files = files(cli, account)?;
    let settings = files.settings()?;
    if settings.pin_hash.is_empty() {
        bail!("no PIN is set for {}", account.name);
    }
    let mut budget = files.load_budget()?;
    let judged = budget.judge(SystemClock.now()?, &settings);
    if budget.total >= settings.max_concerning_total {
        bail!(
            "{} concerning failures since this PIN was set, and {} are allowed; choose a new one with: properpin set",
            budget.total,
            settings.max_concerning_total
        );
    }
    if let Some(limit) = judged.disabled {
        confirm(
            &mut stdin().lock(),
            yes,
            &format!(
                "The PIN was disabled after {limit}. They may have been someone guessing it; sudo properpin set chooses a new one \
                 instead."
            ),
        )?;
    }
    files.save_budget(&budget.enabled())?;
    match judged.disabled {
        Some(limit) => println!("PIN enabled again for {}; it was disabled after {limit}.", account.name),
        None => println!("The PIN for {} wasn't disabled; its recent failures are forgotten.", account.name),
    }
    Ok(())
}

fn remove(cli: &Cli, account: &Account) -> Result<()> {
    require_owner(cli.owner)?;
    let files = files(cli, account)?;
    if !files.remove_pin()? {
        bail!("no PIN is set for {}", account.name);
    }
    files.remove_budget()?;
    println!("PIN removed for {}. The lock screen takes the password only.", account.name);
    Ok(())
}

/// The pinchecker prints the status: only it can read the hash file and the counts.
fn status(cli: &Cli) -> Result<bool> {
    if current_uid() == 0 {
        bail!("status shows your own PIN; run it as yourself, without sudo");
    }
    let output = Command::new(&cli.pinchecker)
        .arg("status")
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {}", cli.pinchecker.display()))?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    match output.status.code().and_then(|code| u8::try_from(code).ok()) {
        Some(exit::YES) => Ok(true),
        _ => bail!("{} failed ({}); the system log says why", cli.pinchecker.display(), output.status),
    }
}

fn require_owner(owner: u32) -> Result<()> {
    match current_euid() {
        euid if euid == owner => Ok(()),
        _ if owner == 0 => bail!("this changes files only root may change; run it with sudo"),
        _ => bail!("this must run as uid {owner}, the owner given with --owner"),
    }
}

/// Say `warning` and ask whether to go on, on the terminal. `yes` answers for the user; without a
/// terminal and without it, the answer is no.
fn confirm(input: &mut impl BufRead, yes: bool, warning: &str) -> Result<()> {
    eprintln!("{warning}");
    if yes {
        return Ok(());
    }
    if !stdin().is_terminal() {
        bail!("no terminal to confirm on; nothing was changed (--yes skips the question)");
    }
    eprint!("Go on anyway? [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    if answer.trim() != "y" {
        bail!("nothing was changed");
    }
    Ok(())
}

/// The new PIN, typed twice. Both entries are wiped when dropped.
fn ask_pin_twice(input: &mut impl BufRead) -> Result<Secret> {
    let first = ask_secret(input, "Choose a PIN (it should differ from your password): ", MAX_PIN_BYTES)?;
    let second = ask_secret(input, "Same again: ", MAX_PIN_BYTES)?;
    if first.as_bytes() != second.as_bytes() {
        bail!("the two entries differ; nothing was changed");
    }
    Ok(first)
}

/// One secret, prompted for on the terminal, or the next line of `input` when stdin isn't one.
/// rpassword's own buffers, and the terminal's, are beyond reach; each String it returns is taken
/// over without a copy.
fn ask_secret(input: &mut impl BufRead, prompt: &str, max: usize) -> Result<Secret> {
    if stdin().is_terminal() {
        return Ok(Secret::new(rpassword::prompt_password(prompt)?.into_bytes()));
    }
    read_secret_line(input, max)
}

/// One line of `input`, without its newline. The buffer is sized once and the read is capped to
/// fit it, so it never grows (growing would leave an unwiped copy behind). A line longer than
/// `max` bytes comes back too long, and its rest stays unread.
fn read_secret_line(input: &mut impl BufRead, max: usize) -> Result<Secret> {
    let limit = max + 2;
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
        assert_eq!(read_secret_line(&mut input, MAX_PIN_BYTES).unwrap().as_bytes(), b"4859");
        assert_eq!(read_secret_line(&mut input, MAX_PIN_BYTES).unwrap().as_bytes(), b"1234");
        assert_eq!(read_secret_line(&mut input, MAX_PIN_BYTES).unwrap().as_bytes(), b"last");
        assert_eq!(read_secret_line(&mut input, MAX_PIN_BYTES).unwrap().as_bytes(), b"");
    }

    #[test]
    fn a_long_line_is_capped_too_long_to_be_a_pin() {
        let long = vec![b'1'; MAX_PIN_BYTES * 3];
        let typed = read_secret_line(&mut &long[..], MAX_PIN_BYTES).unwrap();
        assert_eq!(typed.as_bytes().len(), MAX_PIN_BYTES + 2);
        assert_eq!(properpin_core::input_that_could_be_a_pin(typed.as_bytes()), None);
    }
}
