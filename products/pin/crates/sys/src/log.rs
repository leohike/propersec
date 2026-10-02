use std::io::Write;
use std::path::PathBuf;

use properpin_core::Log;

/// Appends one line per event to a file. Used by tests and the CLI's dev commands; the PAM module
/// logs through `pam_syslog` instead.
#[derive(Debug, Clone)]
pub struct FileLog(pub PathBuf);

impl Log for FileLog {
    fn log(&self, line: &str) {
        // A log that can't be written must never change an unlock decision.
        let _ = std::fs::OpenOptions::new().create(true).append(true).open(&self.0).and_then(|mut file| writeln!(file, "{line}"));
    }
}
