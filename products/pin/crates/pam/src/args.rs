use std::path::PathBuf;

/// What the module is asked to do: one PAM line's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub mode: Mode,
    /// The setgid pinchecker that holds the hashes and the counts.
    pub pinchecker: PathBuf,
    /// The global config, for how long a correct PIN takes at least. `check` only, and required there.
    pub config: Option<PathBuf>,
    pub log: Option<PathBuf>,
    pub test_panic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Before pam_unix: is the typed input the PIN, and is the PIN enabled?
    Check,
    /// After a successful pam_unix: forgive the user's own recent failures, and unpause the PIN.
    Housekeeping,
}

impl Mode {
    /// The pinchecker request for this mode.
    pub fn request(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Housekeeping => "housekeeping",
        }
    }
}

impl Args {
    /// Parse a PAM line's arguments. Anything unknown is an error, never ignored: a typo in the
    /// PAM line must not quietly change what the module does.
    pub fn parse<'a>(words: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let (mut mode, mut pinchecker, mut config, mut log, mut test_panic) = (None, None, None, None, false);
        for word in words {
            match word.split_once('=') {
                None if word == "check" => mode = Some(Mode::Check),
                None if word == "housekeeping" => mode = Some(Mode::Housekeeping),
                None if word == "test_panic" => test_panic = true,
                Some(("pinchecker", path)) if path.starts_with('/') => pinchecker = Some(PathBuf::from(path)),
                Some(("pinchecker", path)) => return Err(format!("pinchecker={path} is not an absolute path")),
                Some(("config", path)) if path.starts_with('/') => config = Some(PathBuf::from(path)),
                Some(("config", path)) => return Err(format!("config={path} is not an absolute path")),
                Some(("log", file)) => log = Some(PathBuf::from(file)),
                _ => return Err(format!("unknown argument {word:?}")),
            }
        }
        let mode = mode.ok_or("no mode: expected check or housekeeping")?;
        match (mode, &config) {
            (Mode::Check, None) => return Err("config= is required with check".into()),
            (Mode::Housekeeping, Some(_)) => return Err("config= is for check only".into()),
            _ => {}
        }
        Ok(Self { mode, pinchecker: pinchecker.ok_or("pinchecker= is required")?, config, log, test_panic })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_shipped_line() {
        let args =
            Args::parse("check pinchecker=/usr/local/libexec/properpin/properpin-pinchecker config=/etc/properpin/config".split(' '))
                .unwrap();
        assert_eq!(
            args,
            Args {
                mode: Mode::Check,
                pinchecker: "/usr/local/libexec/properpin/properpin-pinchecker".into(),
                config: Some("/etc/properpin/config".into()),
                log: None,
                test_panic: false
            }
        );
        let args = Args::parse("housekeeping pinchecker=/usr/local/libexec/properpin/properpin-pinchecker".split(' ')).unwrap();
        assert_eq!((args.mode, args.config), (Mode::Housekeeping, None));
    }

    #[test]
    fn refuses_anything_unclear() {
        for line in [
            "pinchecker=/h config=/c",
            "check config=/c",
            "check pinchecker=h config=/c",
            "check pinchecker=/h config=/c etc=/etc/properpin",
            "check pinchecker=/h config=/c debug",
            "check pinchecker=/h",
            "check pinchecker=/h config=c",
            "housekeeping pinchecker=/h config=/c",
            "start-accepting-pin pinchecker=/h",
        ] {
            assert!(Args::parse(line.split(' ')).is_err(), "{line}");
        }
    }
}
