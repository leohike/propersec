use std::fmt;

use crate::Limit;

/// Why the PIN is refused without being checked. Either way the password is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Paused: too many consecutive failures, until the next password unlock.
    Paused { consecutive: u32 },
    /// Disabled: too many suspicious failures, until root turns it back on or sets a new PIN.
    Disabled(Limit),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Paused { consecutive } => write!(f, "PIN paused after {consecutive} consecutive failures, password required"),
            Self::Disabled(limit) => write!(f, "PIN disabled after {limit}, password required"),
        }
    }
}
