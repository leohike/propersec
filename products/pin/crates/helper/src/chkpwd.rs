use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use properpin_core::{Error, Secret};

use crate::PasswordCheck;

/// The account password, checked by `unix_chkpwd`, pam_unix's own setuid-root helper, the same way
/// pam_unix checks it. `unix_chkpwd` answers only about the user its caller really is, which is
/// also the user the helper serves: the helper keeps its caller's real uid, so the two agree.
#[derive(Debug, Clone)]
pub struct UnixChkpwd(pub PathBuf);

impl UnixChkpwd {
    /// Where Fedora installs it.
    pub fn system() -> Self {
        Self("/usr/sbin/unix_chkpwd".into())
    }
}

impl PasswordCheck for UnixChkpwd {
    fn matches(&self, user: &str, password: &Secret) -> Result<bool, Error> {
        let fail = |error: std::io::Error| Error::System(format!("{}: {error}", self.0.display()));
        // pam_unix's protocol: the user and "nonull" as arguments, the password on stdin ending in a
        // NUL, and exit code 0 for a match. An empty environment, as pam_unix gives it.
        let mut child = Command::new(&self.0)
            .args([user, "nonull"])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(fail)?;
        let mut stdin = child.stdin.take().expect("piped");
        // A write error means unix_chkpwd quit early; its exit code below says what happened.
        let _ = stdin.write_all(password.as_bytes()).and_then(|()| stdin.write_all(b"\0"));
        drop(stdin);
        let status = child.wait().map_err(fail)?;
        Ok(status.code() == Some(0))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// A stand-in for `unix_chkpwd` that accepts "right" for "alice", reading the same protocol.
    fn fake(dir: &std::path::Path) -> UnixChkpwd {
        let path = dir.join("unix_chkpwd");
        std::fs::write(
            &path,
            "#!/bin/bash\nIFS= read -r -d '' password\n[[ $# == 2 && $1 == alice && $2 == nonull && $password == right ]]\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        UnixChkpwd(path)
    }

    #[test]
    fn speaks_pam_unix_protocol() {
        let dir = tempfile::tempdir().unwrap();
        let chkpwd = fake(dir.path());
        assert!(chkpwd.matches("alice", &Secret::new(b"right".to_vec())).unwrap());
        assert!(!chkpwd.matches("alice", &Secret::new(b"wrong".to_vec())).unwrap());
        assert!(!chkpwd.matches("bob", &Secret::new(b"right".to_vec())).unwrap());
    }

    #[test]
    fn a_missing_checker_is_an_error_not_a_no() {
        assert!(UnixChkpwd("/nonexistent/unix_chkpwd".into()).matches("alice", &Secret::new(b"x".to_vec())).is_err());
    }
}
