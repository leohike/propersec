//! `properpin`: manage the PIN that unlocks the KDE lock screen.
//!
//! ```text
//! sudo properpin set      choose a new PIN, typed twice, then your password; arms it at once and
//!                         starts its budget of failures over
//! sudo properpin enable   turn a PIN disabled by too many concerning failures back on
//! sudo properpin remove   delete it; the lock screen takes the password only
//! properpin status        your PIN: what is set, which rules apply, and whether it is armed now
//! ```
//!
//! `set`, `enable` and `remove` change files only root may change, so they run under sudo or pkexec, and
//! getting there takes the password. That's the point: someone at an unlocked desk must not be able
//! to plant a PIN they know. The PIN is read from the terminal, or from stdin when it isn't one,
//! never from the command line, where other users could see it in the process list.
//!
//! The hash file is written readable by the helper's group only, so the user can't read it either:
//! `status` asks the setgid helper, which is the only program that reads hashes and counts.
//!
//! `set` also asks for the user's password, checks it through `unix_chkpwd`, and seals a fresh
//! random pepper with a key derived from it (`docs/pepper-terminology.md`). The PIN is hashed with
//! that pepper, so the hash file alone gives an attacker nothing to brute-force a few digits
//! against. Each password unlock decrypts the pepper again; a password change stops the PIN until
//! the next `set`.

#![forbid(unsafe_code)]

use std::io::{BufRead, IsTerminal, Read, stdin};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use properpin_core::{Clock, MAX_INPUT_BYTES, MAX_PIN_BYTES, PasswordCheck, Secret, Store, arm, exit};
use properpin_sys::{Account, BootClock, UnixChkpwd, UserFiles, Yescrypt, current_euid, current_uid, group_by_name};

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
    /// Where each user's per-boot state lives, which set arms and remove deletes; /run/properpin
    /// once installed
    #[arg(long, value_name = "DIR")]
    run: PathBuf,
    /// The password checker set asks
    #[arg(long, value_name = "PATH", default_value = "/usr/sbin/unix_chkpwd")]
    chkpwd: PathBuf,
    /// The setgid helper, which status asks; /usr/local/libexec/properpin/properpin-helper once installed
    #[arg(long, value_name = "PATH")]
    helper: PathBuf,
    /// Who must own the files under --etc, and the --budget directory
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
    /// Choose a new PIN, typed twice, then your password; arms it at once and starts its budget of
    /// failures over
    Set(Target),
    /// Turn a PIN disabled by too many concerning failures back on, keeping it
    Enable(Target),
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
        Action::Enable(target) => enable(cli, &target_account(target)?)?,
        Action::Remove(target) => remove(cli, &target_account(target)?)?,
        Action::Status => return status(cli),
    }
    Ok(true)
}

fn files(cli: &Cli, account: &Account) -> Result<UserFiles> {
    let group = group_by_name(&cli.group)?;
    let files = UserFiles::new(&cli.etc, cli.owner, &account.name, account.uid)?;
    Ok(files.with_budget(&cli.budget, cli.owner, group).with_runtime(&cli.run, cli.owner, group))
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
    let mut input = stdin().lock();
    let pin = ask_pin_twice(&mut input)?;
    let pin = std::str::from_utf8(pin.as_bytes()).context("the PIN is not valid UTF-8")?;
    let problems = settings.pin_problems(pin);
    if !problems.is_empty() {
        bail!("the PIN needs {}", problems.join(", "));
    }
    // The password seals the pepper, so a mistyped one would leave a PIN that never arms.
    let password = ask_secret(&mut input, &format!("Password for {}: ", account.name), MAX_INPUT_BYTES)?;
    if password.as_bytes().is_empty() || !UnixChkpwd(cli.chkpwd.clone()).matches(&account.name, &password)? {
        bail!("that is not the password of {}; nothing was changed", account.name);
    }
    if password.as_bytes() == pin.as_bytes() {
        bail!("the PIN must not be the password; nothing was changed");
    }
    let new = Yescrypt.new_pin(pin, password.as_bytes(), settings.hash_cost, settings.seal_cost)?;
    drop(password);
    // Only the hash and the encrypted pepper change. Per-user settings already in the file are kept.
    files.save_pin(&new.pairs(), group)?;
    // A new PIN, so no failure against the old one counts any more, and nothing stays disabled.
    files.remove_budget()?;
    // Armed now, as a password unlock would: the password was just typed, and the pepper is at hand.
    match arm(&files, &BootClock, new.pepper) {
        Ok(_) => println!("PIN set for {}, and armed now. After it expires, a password unlock arms it again.", account.name),
        Err(error) => println!("PIN set for {}. It works after the next password unlock at the lock screen ({error}).", account.name),
    }
    if files.runtime_on_tmpfs() == Some(false) {
        println!("Warning: {} is not on tmpfs, so the armed PIN's pepper may be written to a disk.", cli.run.display());
    }
    Ok(())
}

/// The same PIN back on, with its recent failures forgotten. The total since it was set is kept,
/// so its limit still holds: once reached, only a new PIN will do.
fn enable(cli: &Cli, account: &Account) -> Result<()> {
    require_owner(cli.owner)?;
    let files = files(cli, account)?;
    let settings = files.settings()?;
    if settings.pin_hash.is_empty() {
        bail!("no PIN is set for {}", account.name);
    }
    let mut budget = files.load_budget()?;
    let judged = budget.judge(BootClock.wall()?, &settings);
    if budget.total >= settings.max_concerning_total {
        bail!(
            "{} concerning failures since this PIN was set, and {} are allowed; choose a new one with: properpin set",
            budget.total,
            settings.max_concerning_total
        );
    }
    let was = judged.disabled;
    files.save_budget(&budget.enabled())?;
    match was {
        Some(limit) => println!("PIN enabled again for {}; it was disabled after {limit}.", account.name),
        None => println!("The PIN for {} wasn't disabled; its recent failures are forgotten.", account.name),
    }
    println!("It works after the next password unlock at the lock screen.");
    Ok(())
}

fn remove(cli: &Cli, account: &Account) -> Result<()> {
    require_owner(cli.owner)?;
    let files = files(cli, account)?;
    if !files.remove_pin()? {
        bail!("no PIN is set for {}", account.name);
    }
    files.remove_budget()?;
    files.remove_state()?;
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

/// The new PIN, typed twice. Both entries are wiped when dropped.
fn ask_pin_twice(input: &mut impl BufRead) -> Result<Secret> {
    let first = ask_secret(input, "New PIN: ", MAX_PIN_BYTES)?;
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
        assert_eq!(properpin_core::usable_input(typed.as_bytes()), None);
    }
}
