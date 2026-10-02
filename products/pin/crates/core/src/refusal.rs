use std::fmt;

/// Why the PIN is refused without being checked. Every one means "the password is required".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No password unlock since boot, or no state at all.
    NotArmed,
    /// The state belongs to an earlier boot.
    OtherBoot,
    /// The arming time is later than now, which a sane state never is.
    ArmedInFuture,
    /// The PIN was armed `age` seconds ago, which is too long.
    Expired { age: u64 },
    /// Too many failures in a row since the PIN was armed or last used.
    TooManyFailures { failures: u32 },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotArmed => write!(f, "no password unlock since boot"),
            Self::OtherBoot => write!(f, "the state is from an earlier boot"),
            Self::ArmedInFuture => write!(f, "the arming time is in the future"),
            Self::Expired { age } => write!(f, "the last password unlock was {} ago", describe_seconds(*age)),
            Self::TooManyFailures { failures } => write!(f, "{failures} failures in a row"),
        }
    }
}

/// `seconds` as hours and minutes, like `8h01m`.
pub fn describe_seconds(seconds: u64) -> String {
    let minutes = seconds / 60;
    format!("{}h{:02}m", minutes / 60, minutes % 60)
}
