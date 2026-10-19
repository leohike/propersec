use std::path::PathBuf;

use screenlock_pin_core::Request;
use screenlock_pin_core::protocol::INSTALLED_PIN_CHECKER;

/// What the module is asked to do: one PAM line's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub mode: Mode,
    /// The setgid PIN checker that holds the hashes and the counts: the installed one unless the
    /// PAM line says `pin_checker=`. Only root can write a PAM line, so only root can point it
    /// elsewhere.
    pub pin_checker: PathBuf,
    pub log: Option<PathBuf>,
    pub test_panic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Before the password stack: is the typed input the PIN, and is the PIN enabled?
    Check,
    /// After the stock `password-auth` stack, named after it: `pam_sm_setcred` on this line is the
    /// sign that it unlocked the screen. Asks the PIN checker to unpause the PIN, which also forgives
    /// the user's own recent failures. `pam_sm_authenticate` does nothing here.
    AfterPasswordAuth,
}

impl Mode {
    /// The PIN checker request for this mode.
    pub fn request(self) -> Request {
        match self {
            Self::Check => Request::Check,
            Self::AfterPasswordAuth => Request::Unpause,
        }
    }
}

impl Args {
    /// Parse a PAM line's arguments. Anything unknown is an error, never ignored: a typo in the
    /// PAM line must not quietly change what the module does.
    pub fn parse<'a>(words: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let (mut mode, mut pin_checker, mut log, mut test_panic) = (None, None, None, false);
        for word in words {
            match word.split_once('=') {
                None if word == "check" => mode = Some(Mode::Check),
                None if word == "after-password-auth" => mode = Some(Mode::AfterPasswordAuth),
                None if word == "test_panic" => test_panic = true,
                Some(("pin_checker", path)) if path.starts_with('/') => pin_checker = Some(PathBuf::from(path)),
                Some(("pin_checker", path)) => return Err(format!("pin_checker={path} is not an absolute path")),
                Some(("log", file)) => log = Some(PathBuf::from(file)),
                _ => return Err(format!("unknown argument {word:?}")),
            }
        }
        let mode = mode.ok_or("no mode: expected check or after-password-auth")?;
        Ok(Self { mode, pin_checker: pin_checker.unwrap_or_else(|| INSTALLED_PIN_CHECKER.into()), log, test_panic })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_shipped_lines() {
        let args = Args::parse(["check"]).unwrap();
        assert_eq!(args, Args { mode: Mode::Check, pin_checker: INSTALLED_PIN_CHECKER.into(), log: None, test_panic: false });
        let args = Args::parse(["after-password-auth"]).unwrap();
        assert_eq!((args.mode, args.pin_checker), (Mode::AfterPasswordAuth, INSTALLED_PIN_CHECKER.into()));
    }

    #[test]
    fn pin_checker_points_elsewhere() {
        let args = Args::parse("check pin_checker=/tmp/sandbox/pin-checker log=/tmp/sandbox/log".split(' ')).unwrap();
        assert_eq!((args.pin_checker, args.log), ("/tmp/sandbox/pin-checker".into(), Some("/tmp/sandbox/log".into())));
    }

    #[test]
    fn a_relative_pin_checker_is_named_as_such() {
        assert_eq!(Args::parse(["check", "pin_checker=pin-checker"]), Err("pin_checker=pin-checker is not an absolute path".into()));
    }

    #[test]
    fn refuses_anything_unclear() {
        for line in [
            "pin_checker=/h",
            "",
            "check pin_checker=h",
            "check etc=/etc/screenlock-pin",
            // The module reads no config; the PIN checker does.
            "after-password-auth settings=/etc/screenlock-pin/config",
            "check debug",
            "check config=/etc/screenlock-pin/config",
            // Earlier names of the after-password-auth line's mode.
            "start-accepting-pin",
            "housekeeping",
            // The PIN checker request that line makes, which is not a PAM line's mode.
            "unpause",
        ] {
            assert!(Args::parse(line.split(' ').filter(|word| !word.is_empty())).is_err(), "{line}");
        }
    }
}
