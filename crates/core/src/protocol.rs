//! What the setgid PIN checker and its callers, the PAM module and the CLI, must agree on: the
//! requests, the answers, and where everything is installed.

use std::fmt;
use std::str::FromStr;

/// Where `install.sh` puts the config and the users' files.
pub const INSTALLED_ETC: &str = "/etc/screenlock-pin";
/// Where `install.sh` puts every user's budget, on disk.
pub const INSTALLED_BUDGET_DIR: &str = "/var/lib/screenlock-pin";
/// Where `install.sh` puts the PIN checker.
pub const INSTALLED_PIN_CHECKER: &str = "/usr/local/libexec/screenlock-pin/screenlock-pin-checker";

/// What to run when a file stops the PIN from working.
pub const SEE_DOCTOR: &str = "sudo screenlock-pin doctor says how to fix it";
/// What turns a disabled PIN back on.
pub const ENABLE_OR_SET: &str = "sudo screenlock-pin enable or set turns it back on";

/// What the PIN checker is asked to do: its one argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// stdin: what was typed. Is it the PIN, and is the PIN enabled?
    Check,
    /// stdin: nothing. The lock screen was just unlocked with the password.
    Unpause,
    /// Print the caller's PIN settings and state.
    Status,
}

impl Request {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Unpause => "unpause",
            Self::Status => "status",
        }
    }

    /// Whether it reads something typed from stdin.
    pub fn reads_input(self) -> bool {
        self == Self::Check
    }

    /// What it failing means, for the log.
    pub fn failed(self) -> &'static str {
        match self {
            Self::Check => "PIN refused",
            Self::Unpause => "unpausing the PIN failed",
            Self::Status => "status failed",
        }
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Exact words only: no other case, no spaces, no dashes.
impl FromStr for Request {
    type Err = String;

    fn from_str(word: &str) -> Result<Self, String> {
        [Self::Check, Self::Unpause, Self::Status]
            .into_iter()
            .find(|request| request.as_str() == word)
            .ok_or_else(|| format!("unknown request {word:?}"))
    }
}

/// The PIN checker's exit code, which is all it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Answer {
    /// `check`: the PIN unlocks. `unpause`: done. `status`: printed.
    Yes = 0,
    /// `check`: not unlocked. `unpause`: no PIN set. A clean "no", logged by the PIN checker.
    No = 1,
    /// Bad arguments, or a refused environment: run as root, a terminal on stdin, `--dev-*` options
    /// under setgid.
    Usage = 2,
    /// Something is broken: a file, the clock, libxcrypt. Logged by the PIN checker.
    Broken = 3,
}

impl Answer {
    pub fn code(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for Answer {
    type Error = u8;

    fn try_from(code: u8) -> Result<Self, u8> {
        [Self::Yes, Self::No, Self::Usage, Self::Broken].into_iter().find(|answer| answer.code() == code).ok_or(code)
    }
}

impl From<Answer> for std::process::ExitCode {
    fn from(answer: Answer) -> Self {
        Self::from(answer.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_exact_words() {
        for request in [Request::Check, Request::Unpause, Request::Status] {
            assert_eq!(request.as_str().parse(), Ok(request));
        }
        for word in ["Check", "check ", "", "--check", "set", "start-accepting-pin", "unlocked"] {
            assert!(word.parse::<Request>().is_err(), "{word:?}");
        }
    }

    #[test]
    fn answers_round_trip_through_their_codes() {
        for answer in [Answer::Yes, Answer::No, Answer::Usage, Answer::Broken] {
            assert_eq!(Answer::try_from(answer.code()), Ok(answer));
        }
        assert_eq!((Answer::Yes.code(), Answer::Broken.code()), (0, 3));
        assert_eq!(Answer::try_from(4), Err(4));
    }
}
