//! `properpin`: manage the PIN that unlocks the KDE lock screen.
//!
//! ```text
//! sudo properpin set      choose a new PIN, typed twice
//! sudo properpin remove   delete it; the lock screen takes the password only
//! properpin status        what is set, which rules apply, and whether the PIN is armed now
//! properpin dev check     do what the lock screen's check line does, with the PIN from stdin
//! properpin dev arm       do what the lock screen does after a correct password
//! ```
//!
//! `set` and `remove` change files only root may change, so they run under sudo or pkexec, and
//! getting there takes the password. That's the point: someone at an unlocked desk must not be able
//! to plant a PIN they know. The PIN is read from the terminal, or from stdin when it isn't one,
//! never from the command line, where other users could see it in the process list.

#![forbid(unsafe_code)]

use std::io::{BufRead, IsTerminal, stdin};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use properpin_core::{Clock, Store, arm, check, describe_seconds, usable_input};
use properpin_sys::{Account, BootClock, UserFiles, Yescrypt, current_euid, current_uid, private_group};

/// Manage the PIN that unlocks the KDE lock screen.
#[derive(Debug, Parser)]
#[command(name = "properpin", version)]
struct Cli {
    /// Where config and users/ live; /etc/properpin once installed
    #[arg(long, value_name = "DIR")]
    etc: PathBuf,
    /// Parent of the per-uid runtime dirs; /run/user once installed
    #[arg(long, value_name = "DIR")]
    run_base: PathBuf,
    /// Who must own the files under --etc
    #[arg(long, value_name = "UID", default_value_t = 0)]
    owner: u32,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Choose a new PIN, typed twice
    Set(Target),
    /// Delete the PIN; the lock screen takes the password only
    Remove(Target),
    /// Show what is set and whether the PIN is armed right now
    Status(Target),
    /// Simulate the lock screen, for demos and tests
    #[command(subcommand)]
    Dev(Dev),
}

#[derive(Debug, Args)]
struct Target {
    /// Whose PIN; default: the sudo or pkexec caller, or you
    #[arg(long)]
    user: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Dev {
    /// Do what the lock screen's check line does, with the typed input from stdin; exit 0 unlocks
    Check,
    /// Do what the lock screen does after a correct password: arm the PIN
    Arm,
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

/// `Ok(false)` is a clean "no": a refused `dev check`.
fn run(cli: &Cli) -> Result<bool> {
    match &cli.command {
        Command::Set(target) => set(cli, &target_account(target)?)?,
        Command::Remove(target) => remove(cli, &target_account(target)?)?,
        Command::Status(target) => status(&files(cli, &target_account(target)?)?)?,
        Command::Dev(Dev::Check) => return dev_check(&files(cli, &Account::by_uid(current_uid())?)?),
        Command::Dev(Dev::Arm) => {
            arm(&files(cli, &Account::by_uid(current_uid())?)?, &BootClock)?;
            println!("password accepted, PIN armed");
        }
    }
    Ok(true)
}

fn files(cli: &Cli, account: &Account) -> Result<UserFiles> {
    Ok(UserFiles::new(&cli.etc, &cli.run_base, cli.owner, &account.name, account.uid)?)
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
    let group = private_group(account)?;
    let files = files(cli, account)?;
    let settings = files.settings()?;
    let pin = ask_pin_twice()?;
    let problems = settings.pin_problems(&pin);
    if !problems.is_empty() {
        bail!("the PIN needs {}", problems.join(", "));
    }
    // Only the hash changes. Per-user settings already in the file are kept.
    files.save_pin_hash(&Yescrypt.hash(&pin, settings.hash_cost)?, group)?;
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

fn status(files: &UserFiles) -> Result<()> {
    println!("user       {}", files.user());
    let settings = match files.settings() {
        Ok(settings) if settings.pin_hash.is_empty() => {
            println!("PIN        none set");
            return Ok(());
        }
        Ok(settings) => settings,
        Err(error) => {
            println!("PIN        unusable: {error}");
            return Ok(());
        }
    };
    println!("PIN        set, in {}", files.user_file().display());
    println!("policy     armed for {}h after a password unlock, until {} failures in a row", settings.expiry_hours, settings.max_failures);
    let mut rules = format!("{} to {} characters", settings.min_pin_length, settings.max_pin_length);
    if settings.min_letters > 0 {
        rules += &format!(", {} English letters", settings.min_letters);
    }
    println!("set rules  {rules}, yescrypt cost {}", settings.hash_cost);
    let state = files.load_state();
    let now = BootClock.now()?;
    match (settings.refusal(state.as_ref(), &BootClock.boot_id()?, now), state) {
        (Some(refusal), _) => println!("right now  password required: {refusal}"),
        (None, Some(state)) => {
            let left = settings.expiry_seconds() as u64 - (now - state.armed_at);
            println!(
                "right now  PIN armed for another {}, {} of {} failures so far",
                describe_seconds(left),
                state.failures,
                settings.max_failures
            );
        }
        (None, None) => unreachable!("no state is always a refusal"),
    }
    Ok(())
}

fn dev_check(files: &UserFiles) -> Result<bool> {
    let mut typed = String::new();
    stdin().lock().read_line(&mut typed)?;
    let typed = typed.strip_suffix('\n').unwrap_or(&typed);
    let verdict = check(files, &Yescrypt, &BootClock, usable_input(typed.as_bytes()))?;
    println!("{verdict}");
    Ok(verdict.unlocks())
}

fn require_owner(owner: u32) -> Result<()> {
    match current_euid() {
        euid if euid == owner => Ok(()),
        _ if owner == 0 => bail!("this changes files only root may change; run it with sudo"),
        _ => bail!("this must run as uid {owner}, the owner given with --owner"),
    }
}

fn ask_pin_twice() -> Result<String> {
    let (first, second) = if stdin().is_terminal() {
        (rpassword::prompt_password("New PIN: ")?, rpassword::prompt_password("Same again: ")?)
    } else {
        let mut lines = stdin().lock().lines();
        let mut next = || lines.next().transpose().map(Option::unwrap_or_default);
        (next()?, next()?)
    };
    if first != second {
        bail!("the two entries differ; nothing was changed");
    }
    Ok(first)
}
