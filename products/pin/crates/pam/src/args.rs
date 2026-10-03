use std::path::PathBuf;

/// What the module is asked to do: one PAM line's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub mode: Mode,
    /// The setgid helper that holds the hashes and the counts.
    pub helper: PathBuf,
    /// The global config, for how long a correct PIN takes at least. `check` only, and required there.
    pub config: Option<PathBuf>,
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

impl Mode {
    /// The helper request for this mode.
    pub fn request(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Arm => "arm",
        }
    }
}

impl Args {
    /// Parse a PAM line's arguments. Anything unknown is an error, never ignored: a typo in the
    /// PAM line must not quietly change what the module does.
    pub fn parse<'a>(words: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let (mut mode, mut helper, mut config, mut log, mut test_panic) = (None, None, None, None, false);
        for word in words {
            match word.split_once('=') {
                None if word == "check" => mode = Some(Mode::Check),
                None if word == "arm" => mode = Some(Mode::Arm),
                None if word == "test_panic" => test_panic = true,
                Some(("helper", path)) if path.starts_with('/') => helper = Some(PathBuf::from(path)),
                Some(("helper", path)) => return Err(format!("helper={path} is not an absolute path")),
                Some(("config", path)) if path.starts_with('/') => config = Some(PathBuf::from(path)),
                Some(("config", path)) => return Err(format!("config={path} is not an absolute path")),
                Some(("log", file)) => log = Some(PathBuf::from(file)),
                _ => return Err(format!("unknown argument {word:?}")),
            }
        }
        let mode = mode.ok_or("no mode: expected check or arm")?;
        match (mode, &config) {
            (Mode::Check, None) => return Err("config= is required with check".into()),
            (Mode::Arm, Some(_)) => return Err("config= is for check only".into()),
            _ => {}
        }
        Ok(Self { mode, helper: helper.ok_or("helper= is required")?, config, log, test_panic })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_shipped_line() {
        let args =
            Args::parse("check helper=/usr/local/libexec/properpin/properpin-helper config=/etc/properpin/config".split(' ')).unwrap();
        assert_eq!(
            args,
            Args {
                mode: Mode::Check,
                helper: "/usr/local/libexec/properpin/properpin-helper".into(),
                config: Some("/etc/properpin/config".into()),
                log: None,
                test_panic: false
            }
        );
        let args = Args::parse("arm helper=/usr/local/libexec/properpin/properpin-helper".split(' ')).unwrap();
        assert_eq!((args.mode, args.config), (Mode::Arm, None));
    }

    #[test]
    fn refuses_anything_unclear() {
        for line in [
            "helper=/h config=/c",
            "check config=/c",
            "check helper=h config=/c",
            "check helper=/h config=/c etc=/etc/properpin",
            "check helper=/h config=/c debug",
            "check helper=/h",
            "check helper=/h config=c",
            "arm helper=/h config=/c",
        ] {
            assert!(Args::parse(line.split(' ')).is_err(), "{line}");
        }
    }
}
