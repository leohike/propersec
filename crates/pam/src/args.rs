use std::path::PathBuf;

/// Where `install.sh` puts the pinchecker, and where the module runs it from unless the PAM line
/// says `pinchecker=`. Only root can write a PAM line, so only root can point it elsewhere.
pub const INSTALLED_PINCHECKER: &str = "/usr/local/libexec/properpin/properpin-pinchecker";

/// What the module is asked to do: one PAM line's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub mode: Mode,
    /// The setgid pinchecker that holds the hashes and the counts.
    pub pinchecker: PathBuf,
    pub log: Option<PathBuf>,
    pub test_panic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Before the password stack: is the typed input the PIN, and is the PIN enabled?
    Check,
    /// After the stock `password-auth` stack, named after it: `pam_sm_setcred` on this line is the
    /// sign that it unlocked the screen. Asks the pinchecker to unpause the PIN, which also forgives
    /// the user's own recent failures. `pam_sm_authenticate` does nothing here.
    AfterPasswordAuth,
}

impl Mode {
    /// The pinchecker request for this mode.
    pub fn request(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::AfterPasswordAuth => "unpause",
        }
    }
}

impl Args {
    /// Parse a PAM line's arguments. Anything unknown is an error, never ignored: a typo in the
    /// PAM line must not quietly change what the module does.
    pub fn parse<'a>(words: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let (mut mode, mut pinchecker, mut log, mut test_panic) = (None, None, None, false);
        for word in words {
            match word.split_once('=') {
                None if word == "check" => mode = Some(Mode::Check),
                None if word == "after-password-auth" => mode = Some(Mode::AfterPasswordAuth),
                None if word == "test_panic" => test_panic = true,
                Some(("pinchecker", path)) if path.starts_with('/') => pinchecker = Some(PathBuf::from(path)),
                Some(("pinchecker", path)) => return Err(format!("pinchecker={path} is not an absolute path")),
                Some(("log", file)) => log = Some(PathBuf::from(file)),
                _ => return Err(format!("unknown argument {word:?}")),
            }
        }
        let mode = mode.ok_or("no mode: expected check or after-password-auth")?;
        Ok(Self { mode, pinchecker: pinchecker.unwrap_or_else(|| INSTALLED_PINCHECKER.into()), log, test_panic })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_shipped_lines() {
        let args = Args::parse(["check"]).unwrap();
        assert_eq!(args, Args { mode: Mode::Check, pinchecker: INSTALLED_PINCHECKER.into(), log: None, test_panic: false });
        let args = Args::parse(["after-password-auth"]).unwrap();
        assert_eq!((args.mode, args.pinchecker), (Mode::AfterPasswordAuth, INSTALLED_PINCHECKER.into()));
    }

    #[test]
    fn pinchecker_points_elsewhere() {
        let args = Args::parse("check pinchecker=/tmp/sandbox/pinchecker log=/tmp/sandbox/log".split(' ')).unwrap();
        assert_eq!((args.pinchecker, args.log), ("/tmp/sandbox/pinchecker".into(), Some("/tmp/sandbox/log".into())));
    }

    #[test]
    fn refuses_anything_unclear() {
        for line in [
            "pinchecker=/h",
            "",
            "check pinchecker=h",
            "check etc=/etc/properpin",
            // What the tests of the branch with both ways to unpause passed; the module reads no config.
            "housekeeping settings=/etc/properpin/config",
            "check debug",
            // What the lines of versions before 2026-10-18 passed, which the pinchecker now reads itself.
            "check config=/etc/properpin/config",
            "start-accepting-pin",
            // The after-password-auth line's argument until 2026-10-18.
            "housekeeping",
            // The pinchecker request that line makes, which is not a PAM line's mode.
            "unpause",
        ] {
            assert!(Args::parse(line.split(' ').filter(|word| !word.is_empty())).is_err(), "{line}");
        }
    }
}
