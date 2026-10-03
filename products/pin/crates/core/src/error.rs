/// Something is wrong enough that the PIN must not be used. The password still works.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{file} line {line}: expected 'key = value'")]
    Syntax { file: String, line: usize },
    #[error("{file} line {line}: {key} is given twice")]
    Duplicate { file: String, line: usize, key: String },
    #[error("{file}: unknown setting {key:?}")]
    UnknownSetting { file: String, key: String },
    #[error("{file}: {key} must be {expected}, not {raw:?}")]
    BadValue { file: String, key: String, expected: String, raw: String },
    #[error("{file}: only a user's own file may hold a PIN hash")]
    HashOutsideUserFile { file: String },
    #[error("{file}: {key} may only be set in the global config")]
    GlobalOnly { file: String, key: String },
    #[error("the stored hash is not a yescrypt hash")]
    NotYescrypt,
    /// Anything the machine reports: a file, the clock, libxcrypt. Kept as text, so this crate
    /// needs to know nothing about where it came from.
    #[error("{0}")]
    System(String),
}
