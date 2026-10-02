use std::path::PathBuf;

/// What the module is asked to do: one PAM line's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub mode: Mode,
    pub etc: PathBuf,
    pub run_base: PathBuf,
    pub owner: u32,
    pub log: Option<PathBuf>,
    pub test_panic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Before pam_unix: is the typed input the PIN, and is the PIN armed?
    Check,
    /// After a successful pam_unix: arm the PIN.
    Arm,
}

impl Args {
    /// Parse a PAM line's arguments. Anything unknown is an error, never ignored: a typo in the
    /// PAM line must not quietly change what the module does.
    pub fn parse<'a>(words: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let (mut mode, mut etc, mut run_base, mut owner, mut log, mut test_panic) = (None, None, None, 0, None, false);
        for word in words {
            match word.split_once('=') {
                None if word == "check" => mode = Some(Mode::Check),
                None if word == "arm" => mode = Some(Mode::Arm),
                None if word == "test_panic" => test_panic = true,
                Some(("etc", dir)) => etc = Some(PathBuf::from(dir)),
                Some(("run_base", dir)) => run_base = Some(PathBuf::from(dir)),
                Some(("owner", uid)) => owner = uid.parse().map_err(|_| format!("owner={uid} is not a uid"))?,
                Some(("log", file)) => log = Some(PathBuf::from(file)),
                _ => return Err(format!("unknown argument {word:?}")),
            }
        }
        Ok(Self {
            mode: mode.ok_or("no mode: expected check or arm")?,
            etc: etc.ok_or("etc= is required")?,
            run_base: run_base.ok_or("run_base= is required")?,
            owner,
            log,
            test_panic,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_shipped_line() {
        let args = Args::parse("check etc=/etc/properpin run_base=/run/user".split(' ')).unwrap();
        assert_eq!(
            args,
            Args { mode: Mode::Check, etc: "/etc/properpin".into(), run_base: "/run/user".into(), owner: 0, log: None, test_panic: false }
        );
    }

    #[test]
    fn refuses_anything_unclear() {
        for line in [
            "etc=/e run_base=/r",
            "check run_base=/r",
            "check etc=/e",
            "check etc=/e run_base=/r owner=root",
            "check etc=/e run_base=/r debug",
        ] {
            assert!(Args::parse(line.split(' ')).is_err(), "{line}");
        }
    }
}
