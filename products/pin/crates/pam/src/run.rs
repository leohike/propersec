//! The module's work, in safe code. `pam.rs` turns the result into a PAM return code.

use properpin_core::{Error, Log, Secret, arm, check, usable_input};
use properpin_sys::{Account, BootClock, UserFiles, Yescrypt, current_euid, current_uid};

use crate::{Args, Mode};

/// What the module needs from the PAM transaction.
pub trait Transaction {
    /// The user PAM is authenticating.
    fn user(&self) -> Result<String, Error>;
    /// What the user typed, asking for it if no module has yet. Stored by libpam as `PAM_AUTHTOK`,
    /// so pam_unix reuses it with `use_first_pass` instead of asking again. This is a copy of its
    /// own, wiped when dropped; libpam's stays for the rest of the stack and libpam wipes it itself
    /// (docs/pin-pam-copy.md).
    fn typed(&self) -> Result<Secret, Error>;
}

/// `Ok(true)` unlocks (for `check`) or armed the PIN (for `arm`). Everything else refuses.
pub fn run(transaction: &impl Transaction, args: &Args, log: &impl Log) -> Result<bool, Error> {
    if args.test_panic {
        panic!("test_panic: a panic must become PAM_IGNORE");
    }
    let account = calling_account(transaction)?;
    let files = UserFiles::new(&args.etc, &args.run_base, args.owner, &account.name, account.uid)?;
    match args.mode {
        Mode::Check => {
            // The copy of what was typed is wiped as soon as the check is done, before logging.
            let verdict = {
                let typed = transaction.typed()?;
                check(&files, &Yescrypt, &BootClock, usable_input(typed.as_bytes()))?
            };
            log.log(&format!("{}: {verdict}", account.name));
            Ok(verdict.unlocks())
        }
        Mode::Arm => {
            arm(&files, &BootClock)?;
            log.log(&format!("{}: password accepted, PIN armed", account.name));
            Ok(true)
        }
    }
}

/// The user being unlocked, who must be both the user this process runs as and the user PAM is
/// authenticating. The lock screen runs as the locked user; anything else isn't the lock screen.
fn calling_account(transaction: &impl Transaction) -> Result<Account, Error> {
    if current_uid() == 0 || current_euid() == 0 {
        return Err(Error::System("running as root; properpin belongs in the lock screen's stack only".into()));
    }
    let account = Account::by_uid(current_uid())?;
    let pam_user = transaction.user()?;
    if pam_user != account.name {
        return Err(Error::System(format!("PAM is authenticating {pam_user:?}, but this runs as {:?}", account.name)));
    }
    Ok(account)
}
