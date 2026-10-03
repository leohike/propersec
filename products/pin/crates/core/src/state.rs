use crate::kv;

/// Whether the PIN is armed: what the last password unlock set, and what happened since.
/// Kept in the user's runtime directory as `key = value` lines, one per field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinState {
    /// The boot this state belongs to; any other boot's state is ignored.
    pub boot_id: String,
    /// `CLOCK_BOOTTIME` seconds at the last password unlock.
    pub armed_at: u64,
    /// Inputs in a row that weren't the PIN, since arming or since the last PIN unlock. A mistyped
    /// password counts too, when it is short enough to be a PIN.
    pub failures: u32,
}

impl PinState {
    /// The state a password unlock leaves behind: this boot, this moment, nothing failed yet.
    pub fn armed(boot_id: &str, now: u64) -> Self {
        Self { boot_id: boot_id.into(), armed_at: now, failures: 0 }
    }

    /// The state in `text`, or `None` unless it parses exactly.
    ///
    /// Anything unexpected reads as "no state", which means "password required": a damaged file can
    /// only take the PIN away, never hand out extra attempts.
    pub fn parse(text: &str) -> Option<Self> {
        let pairs = kv::parse(text, "state").ok()?;
        let get = |key: &str| pairs.iter().find(|(name, _)| name == key).map(|(_, value)| value.as_str());
        if pairs.len() != 3 {
            return None;
        }
        Some(Self { boot_id: get("boot_id")?.into(), armed_at: digits(get("armed_at")?)?, failures: digits(get("failures")?)? })
    }

    pub fn format(&self) -> String {
        format!("boot_id = {}\narmed_at = {}\nfailures = {}\n", self.boot_id, self.armed_at, self.failures)
    }
}

/// Plain ASCII digits only: no sign, no spaces, no "²".
pub(crate) fn digits<T: std::str::FromStr>(text: &str) -> Option<T> {
    text.bytes().all(|byte| byte.is_ascii_digit()).then(|| text.parse().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "boot_id = b\narmed_at = 100\nfailures = 0\n";

    #[test]
    fn round_trips() {
        let state = PinState { boot_id: "b".into(), armed_at: 100, failures: 2 };
        assert_eq!(PinState::parse(&state.format()), Some(state));
        assert!(PinState::parse(VALID).is_some());
    }

    #[test]
    fn anything_unexpected_reads_as_no_state() {
        // Each case is the valid text with exactly one thing wrong.
        for text in [
            "",
            "boot_id = b\narmed_at = 100\n",
            "boot_id = b\narmed_at = 100\nfailures = 0\nextra = 1\n",
            "boot_id = b\narmed_at = 100\nfailures = 0\nfailures = 0\n",
            "boot_id = b\narmed_at = -100\nfailures = 0\n",
            "boot_id = b\narmed_at = +100\nfailures = 0\n",
            "boot_id = b\narmed_at = 1²\nfailures = 0\n",
            "boot_id = b\narmed_at = 100\nfailures = 99999999999\n",
            "boot_id = b\narmed_at = 100\nfailure = 0\n",
        ] {
            assert_eq!(PinState::parse(text), None, "{text:?}");
        }
    }
}
