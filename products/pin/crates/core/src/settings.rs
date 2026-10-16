use std::fmt;
use std::str::FromStr;

use crate::kv::Pairs;
use crate::{Error, HASH_SETTING, USER_ONLY};

/// Everything that decides one user's PIN: its hash, and the rules for it.
///
/// Built in layers: these defaults, then the global config, then the user's own file, each
/// [`Settings::apply`] winning over the layer before. Only the user's own file may hold the hash.
/// Like a line of `/etc/shadow`, that file keeps the secret and the rules for it together, where
/// only root can change them.
///
/// The unlock path uses the hash, the next two fields and the budget's five; `set` uses the three
/// in between. The PAM module itself reads `min_milliseconds_before_pin_unlock`. The budget's
/// settings and `min_milliseconds_before_pin_unlock` may only come from the global config.
#[derive(Clone, PartialEq)]
pub struct Settings {
    /// Empty: no PIN is set. Otherwise the PIN's yescrypt hash.
    pub pin_hash: String,
    /// Consecutive failures that pause the PIN until the next password unlock.
    pub max_failures: u32,
    /// Longest PIN, in characters. Longer input is never hashed or counted.
    pub max_pin_length: usize,
    /// Shortest PIN `set` accepts.
    pub min_pin_length: usize,
    /// English letters `set` requires; 0 turns the rule off.
    pub min_letters: usize,
    /// yescrypt cost `set` hashes with: 5 takes about 20 ms, 8 about 160 ms.
    pub hash_cost: u32,
    /// Seconds before a correct PIN in which failures are forgiven as the user's own typos.
    pub forgive_before_correct_pin: u64,
    /// The same before a correct password.
    pub forgive_before_correct_password: u64,
    /// Concerning failures within 24 hours that disable the PIN.
    pub max_concerning_24h: u32,
    /// Concerning failures within 7 days that disable the PIN.
    pub max_concerning_7d: u32,
    /// Concerning failures since the PIN was set that disable it.
    pub max_concerning_total: u64,
    /// The shortest time a correct PIN takes to unlock, counted from when the PAM module is called;
    /// the module waits out the rest. kscreenlocker 6.8 takes an answer within 50 ms for a broken
    /// authenticator, so below that the PIN stops unlocking. Only a correct PIN waits: anything
    /// else goes on to pam_unix, which is slow anyway. The PAM module reads it, as the user, so it
    /// may only come from the global config, which everyone can read.
    pub min_milliseconds_before_pin_unlock: u64,
}

/// The budget's settings (one policy for the machine, never per user), and the PAM module's wait,
/// which the module reads as the user, who can't read their own file.
const GLOBAL_ONLY: &[&str] = &[
    "forgive_before_correct_pin",
    "forgive_before_correct_password",
    "max_concerning_24h",
    "max_concerning_7d",
    "max_concerning_total",
    "min_milliseconds_before_pin_unlock",
];

impl Default for Settings {
    fn default() -> Self {
        Self {
            pin_hash: String::new(),
            max_failures: 3,
            max_pin_length: 12,
            min_pin_length: 4,
            min_letters: 0,
            hash_cost: 5,
            forgive_before_correct_pin: 45,
            forgive_before_correct_password: 90,
            max_concerning_24h: 10,
            max_concerning_7d: 25,
            max_concerning_total: 60,
            min_milliseconds_before_pin_unlock: 75,
        }
    }
}

// The hash stays out of debug output and logs.
impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("pin_hash", &if self.pin_hash.is_empty() { "<none>" } else { "<set>" })
            .field("max_failures", &self.max_failures)
            .field("max_pin_length", &self.max_pin_length)
            .field("min_pin_length", &self.min_pin_length)
            .field("min_letters", &self.min_letters)
            .field("hash_cost", &self.hash_cost)
            .field("forgive_before_correct_pin", &self.forgive_before_correct_pin)
            .field("forgive_before_correct_password", &self.forgive_before_correct_password)
            .field("max_concerning_24h", &self.max_concerning_24h)
            .field("max_concerning_7d", &self.max_concerning_7d)
            .field("max_concerning_total", &self.max_concerning_total)
            .field("min_milliseconds_before_pin_unlock", &self.min_milliseconds_before_pin_unlock)
            .finish()
    }
}

impl Settings {
    /// Take over each of `pairs`, checking every value against its range. `source` names the file,
    /// for errors. A value outside its range is an error, never clamped: a typo must not quietly
    /// allow 50 failures.
    ///
    /// Only a user's own file may set the hash (`may_set_hash`). Anywhere else, one
    /// line would give every user the same PIN. The user's own file may not set the budget's
    /// settings.
    pub fn apply(&mut self, pairs: &Pairs, source: &str, may_set_hash: bool) -> Result<(), Error> {
        for (key, raw) in pairs {
            let key = key.as_str();
            if may_set_hash && GLOBAL_ONLY.contains(&key) {
                return Err(Error::GlobalOnly { file: source.into(), key: key.into() });
            }
            match key {
                _ if !may_set_hash && USER_ONLY.contains(&key) => {
                    return Err(Error::OutsideUserFile { file: source.into(), key: key.into() });
                }
                HASH_SETTING => self.pin_hash.clone_from(raw),
                "max_failures" => self.max_failures = in_range(source, key, raw, 1, 10)?,
                // 64 characters fit MAX_PIN_BYTES even at 4 bytes each.
                "max_pin_length" => self.max_pin_length = in_range(source, key, raw, 1, 64)?,
                "min_pin_length" => self.min_pin_length = in_range(source, key, raw, 1, 64)?,
                "min_letters" => self.min_letters = in_range(source, key, raw, 0, 64)?,
                "hash_cost" => self.hash_cost = in_range(source, key, raw, 1, 11)?,
                "forgive_before_correct_pin" => self.forgive_before_correct_pin = in_range(source, key, raw, 0, 3600)?,
                "forgive_before_correct_password" => self.forgive_before_correct_password = in_range(source, key, raw, 0, 3600)?,
                // The budget keeps at most MAX_CONCERNING concerning failures, so no limit may need more.
                "max_concerning_24h" => self.max_concerning_24h = in_range(source, key, raw, 1, 100)?,
                "max_concerning_7d" => self.max_concerning_7d = in_range(source, key, raw, 1, 200)?,
                "max_concerning_total" => self.max_concerning_total = in_range(source, key, raw, 1, 100_000)?,
                // Under 50 ms breaks the PIN on kscreenlocker 6.8; allowed, for other lock screens.
                "min_milliseconds_before_pin_unlock" => self.min_milliseconds_before_pin_unlock = in_range(source, key, raw, 0, 1000)?,
                _ => return Err(Error::UnknownSetting { file: source.into(), key: key.into() }),
            }
        }
        Ok(())
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
}

/// `raw` as a `T` within `min..=max`.
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
        let settings = apply("hash_cost = 6\nmax_failures = 5\n", false).unwrap();
        assert_eq!((settings.hash_cost, settings.max_failures, settings.min_pin_length), (6, 5, 4));
    }

    #[test]
    fn every_setting_is_read() {
        let text = "max_failures = 5\nmax_pin_length = 8\nmin_pin_length = 6\nmin_letters = 1\nhash_cost = 6\n\
                    forgive_before_correct_pin = 30\nforgive_before_correct_password = 60\nmax_concerning_24h = 5\n\
                    max_concerning_7d = 15\nmax_concerning_total = 50\nmin_milliseconds_before_pin_unlock = 200\n";
        let expected = Settings {
            max_failures: 5,
            max_pin_length: 8,
            min_pin_length: 6,
            min_letters: 1,
            hash_cost: 6,
            forgive_before_correct_pin: 30,
            forgive_before_correct_password: 60,
            max_concerning_24h: 5,
            max_concerning_7d: 15,
            max_concerning_total: 50,
            min_milliseconds_before_pin_unlock: 200,
            ..Settings::default()
        };
        assert_eq!(apply(text, false).unwrap(), expected);
    }

    #[test]
    fn refuses_out_of_range_never_clamps() {
        for text in [
            "max_failures = 11",
            "max_failures = 0",
            "max_failures = nan",
            "max_failures = 1.5",
            "hash_cost = -1",
            "min_milliseconds_before_pin_unlock = 1001",
        ] {
            assert!(matches!(apply(text, false), Err(Error::BadValue { .. })), "{text}");
        }
        let error = apply("max_failures = 11", false).unwrap_err().to_string();
        assert_eq!(error, "f: max_failures must be a number from 1 to 10, not \"11\"");
    }

    #[test]
    fn the_budget_is_set_globally_only() {
        assert_eq!(apply("max_concerning_24h = 5\nforgive_before_correct_pin = 30\n", false).unwrap().max_concerning_24h, 5);
        for text in [
            "max_concerning_24h = 50",
            "forgive_before_correct_password = 10",
            "max_concerning_total = 1000",
            "min_milliseconds_before_pin_unlock = 0",
        ] {
            assert!(matches!(apply(text, true), Err(Error::GlobalOnly { .. })), "{text}");
        }
        assert!(matches!(apply("max_concerning_7d = 201", false), Err(Error::BadValue { .. })));
    }

    #[test]
    fn refuses_unknown_settings() {
        assert!(matches!(apply("max_short_password_len = 5", false), Err(Error::UnknownSetting { .. })));
    }

    #[test]
    fn only_the_user_file_may_hold_the_hash() {
        assert!(matches!(apply("hash = $y$j9T$abc$def", false), Err(Error::OutsideUserFile { .. })));
        assert_eq!(apply("hash = $y$j9T$abc$def\n", true).unwrap().pin_hash, "$y$j9T$abc$def");
    }

    #[test]
    fn counts_characters_not_bytes() {
        // Twelve Cyrillic letters are 24 bytes and still fit the default 12.
        assert!(Settings::default().pin_problems("абвгдежзийкл").is_empty());
        assert_eq!(Settings::default().pin_problems("абвгдежзийклм"), ["at most 12 characters"]);
    }

    #[test]
    fn a_pin_of_exactly_the_shortest_length_is_accepted() {
        assert!(Settings::default().pin_problems("4859").is_empty());
        assert_eq!(Settings::default().pin_problems("485"), ["at least 4 characters"]);
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
