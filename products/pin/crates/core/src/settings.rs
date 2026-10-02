use std::fmt;
use std::str::FromStr;

use crate::kv::Pairs;
use crate::{Error, HASH_KEY, PinState, Refusal};

/// Everything that decides one user's PIN: its hash, and the rules for it.
///
/// Built in layers: these defaults, then the global config, then the user's own file, each
/// [`Settings::apply`] winning over the layer before. Only the user's own file may hold the hash.
/// Like a line of `/etc/shadow`, that file keeps the secret and the rules for it together, where
/// only root can change them.
///
/// The unlock path uses the hash and the next three fields; `set` uses the last four.
#[derive(Clone, PartialEq)]
pub struct Settings {
    /// Empty: no PIN is set.
    pub pin_hash: String,
    /// How long the PIN stays armed after a password unlock.
    pub expiry_hours: f64,
    /// Failures in a row after which the password is required.
    pub max_failures: u32,
    /// Longest PIN, in characters. Longer input is never hashed or counted.
    pub max_pin_length: usize,
    /// Shortest PIN `set` accepts.
    pub min_pin_length: usize,
    /// English letters `set` requires; 0 turns the rule off.
    pub min_letters: usize,
    /// yescrypt cost `set` hashes with: 5 takes about 20 ms, 8 about 160 ms.
    pub hash_cost: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            pin_hash: String::new(),
            expiry_hours: 8.0,
            max_failures: 3,
            max_pin_length: 12,
            min_pin_length: 4,
            min_letters: 0,
            hash_cost: 5,
        }
    }
}

// The hash stays out of debug output and logs.
impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("pin_hash", &if self.pin_hash.is_empty() { "<none>" } else { "<set>" })
            .field("expiry_hours", &self.expiry_hours)
            .field("max_failures", &self.max_failures)
            .field("max_pin_length", &self.max_pin_length)
            .field("min_pin_length", &self.min_pin_length)
            .field("min_letters", &self.min_letters)
            .field("hash_cost", &self.hash_cost)
            .finish()
    }
}

impl Settings {
    /// Take over each of `pairs`, checking every value against its range. `source` names the file,
    /// for errors. A value outside its range is an error, never clamped: a typo must not quietly
    /// allow 50 failures.
    ///
    /// Only a user's own file may set the hash (`may_set_hash`). Anywhere else, one line would give
    /// every user the same PIN.
    pub fn apply(&mut self, pairs: &Pairs, source: &str, may_set_hash: bool) -> Result<(), Error> {
        for (key, raw) in pairs {
            let key = key.as_str();
            match key {
                HASH_KEY if may_set_hash => self.pin_hash.clone_from(raw),
                HASH_KEY => return Err(Error::HashOutsideUserFile { file: source.into() }),
                "expiry_hours" => self.expiry_hours = in_range(source, key, raw, 0.01, 168.0)?,
                "max_failures" => self.max_failures = in_range(source, key, raw, 1, 10)?,
                // 64 characters fit MAX_PIN_BYTES even at 4 bytes each.
                "max_pin_length" => self.max_pin_length = in_range(source, key, raw, 1, 64)?,
                "min_pin_length" => self.min_pin_length = in_range(source, key, raw, 1, 64)?,
                "min_letters" => self.min_letters = in_range(source, key, raw, 0, 64)?,
                "hash_cost" => self.hash_cost = in_range(source, key, raw, 1, 11)?,
                _ => return Err(Error::UnknownSetting { file: source.into(), key: key.into() }),
            }
        }
        Ok(())
    }

    pub fn expiry_seconds(&self) -> f64 {
        self.expiry_hours * 3600.0
    }

    /// What a proposed PIN is missing, phrased to follow "the PIN needs".
    pub fn pin_problems(&self, pin: &str) -> Vec<String> {
        let length = pin.chars().count();
        let letters = pin.chars().filter(char::is_ascii_alphabetic).count();
        let mut problems = Vec::new();
        if length < self.min_pin_length {
            problems.push(format!("at least {} characters", self.min_pin_length));
        }
        if length > self.max_pin_length {
            problems.push(format!("at most {} characters", self.max_pin_length));
        }
        if letters < self.min_letters {
            problems.push(format!("at least {} English letters", self.min_letters));
        }
        if pin.chars().any(char::is_control) {
            problems.push("no control characters".into());
        }
        problems
    }

    /// Why the PIN must be refused right now without even checking it, which means the password
    /// is required; or `None` while the PIN is armed.
    ///
    /// `boot_id` and `now` (seconds since boot) are passed in, so tests can try every case
    /// without a real clock or a reboot.
    pub fn refusal(&self, state: Option<&PinState>, boot_id: &str, now: u64) -> Option<Refusal> {
        let Some(state) = state else { return Some(Refusal::NotArmed) };
        if state.boot_id != boot_id {
            return Some(Refusal::OtherBoot);
        }
        let Some(age) = now.checked_sub(state.armed_at) else { return Some(Refusal::ArmedInFuture) };
        if age as f64 >= self.expiry_seconds() {
            return Some(Refusal::Expired { age });
        }
        if state.failures >= self.max_failures {
            return Some(Refusal::TooManyFailures { failures: state.failures });
        }
        None
    }
}

/// `raw` as a `T` within `min..=max`. NaN fails both comparisons, so it is refused too.
fn in_range<T>(source: &str, key: &str, raw: &str, min: T, max: T) -> Result<T, Error>
where
    T: FromStr + PartialOrd + fmt::Display,
{
    match raw.parse::<T>() {
        Ok(value) if min <= value && value <= max => Ok(value),
        _ => Err(Error::BadValue {
            file: source.into(),
            key: key.into(),
            expected: format!("a number from {min} to {max}"),
            raw: raw.into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv;

    fn apply(text: &str, may_set_hash: bool) -> Result<Settings, Error> {
        let mut settings = Settings::default();
        settings.apply(&kv::parse(text, "f")?, "f", may_set_hash)?;
        Ok(settings)
    }

    #[test]
    fn layers_win_over_defaults() {
        let settings = apply("expiry_hours = 4\nmax_failures = 5\n", false).unwrap();
        assert_eq!((settings.expiry_hours, settings.max_failures, settings.min_pin_length), (4.0, 5, 4));
    }

    #[test]
    fn refuses_out_of_range_never_clamps() {
        for text in ["max_failures = 11", "max_failures = 0", "expiry_hours = nan", "expiry_hours = inf", "hash_cost = -1"] {
            assert!(matches!(apply(text, false), Err(Error::BadValue { .. })), "{text}");
        }
        let error = apply("max_failures = 11", false).unwrap_err().to_string();
        assert_eq!(error, "f: max_failures must be a number from 1 to 10, not \"11\"");
    }

    #[test]
    fn refuses_unknown_settings() {
        assert!(matches!(apply("max_short_password_len = 5", false), Err(Error::UnknownSetting { .. })));
    }

    #[test]
    fn only_the_user_file_may_hold_the_hash() {
        assert!(matches!(apply("hash = $y$j9T$abc$def", false), Err(Error::HashOutsideUserFile { .. })));
        assert_eq!(apply("hash = $y$j9T$abc$def", true).unwrap().pin_hash, "$y$j9T$abc$def");
    }

    #[test]
    fn counts_characters_not_bytes() {
        // Twelve Cyrillic letters are 24 bytes and still fit the default 12.
        assert!(Settings::default().pin_problems("абвгдежзийкл").is_empty());
        assert_eq!(Settings::default().pin_problems("абвгдежзийклм"), ["at most 12 characters"]);
    }

    #[test]
    fn lists_every_problem() {
        let settings = Settings { min_letters: 2, ..Settings::default() };
        assert_eq!(settings.pin_problems("1\t"), ["at least 4 characters", "at least 2 English letters", "no control characters"]);
    }

    #[test]
    fn debug_output_hides_the_hash() {
        let settings = Settings { pin_hash: "$y$secret".into(), ..Settings::default() };
        assert!(!format!("{settings:?}").contains("secret"));
    }
}
