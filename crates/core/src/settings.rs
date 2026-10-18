use std::fmt;
use std::str::FromStr;

use crate::kv::Pairs;
use crate::{Error, HASH_SETTING, MAX_PIN_CHARS};

/// Everything that decides one user's PIN: its hash, and the rules for it.
///
/// Built in layers: these defaults, then the global config, the one place for every rule, then the
/// user's own file, which holds the hash and nothing else. Each [`Settings::apply`] wins over the
/// layer before.
///
/// The unlock path uses the hash, `max_failures`, the budget's five and
/// `min_milliseconds_before_pin_unlock`; `set` uses the three in between.
#[derive(Clone, PartialEq)]
pub struct Settings {
    /// Empty: no PIN is set. Otherwise the PIN's yescrypt hash.
    pub pin_hash: String,
    /// Consecutive failures that pause the PIN until the next password unlock.
    pub max_failures: u32,
    /// Shortest PIN `set` accepts, in characters. The longest is [`MAX_PIN_CHARS`].
    pub min_pin_length: usize,
    /// Characters other than the digits 0 to 9 that `set` requires, whitespace included; 0 turns
    /// the rule off.
    pub required_non_digits_count: usize,
    /// yescrypt cost `set` hashes with: 5 takes about 20 ms, 8 about 160 ms.
    pub hash_cost: u32,
    /// Seconds before a correct PIN in which failures are forgiven as the user's own typos.
    pub forgive_before_correct_pin: u64,
    /// The same before a correct password.
    pub forgive_before_correct_password: u64,
    /// Suspicious failures within 24 hours that disable the PIN.
    pub max_suspicious_24h: u32,
    /// Suspicious failures within 7 days that disable the PIN.
    pub max_suspicious_7d: u32,
    /// Suspicious failures since the PIN was set that disable it.
    pub max_suspicious_total: u64,
    /// The shortest time a correct PIN takes to unlock, counted from when the pinchecker starts;
    /// the pinchecker waits out the rest before it answers. kscreenlocker 6.8 takes an answer
    /// within 50 ms for a broken authenticator, so below that the PIN stops unlocking. Only a
    /// correct PIN waits: anything else goes on to the password stack, which is slow anyway.
    pub min_milliseconds_before_pin_unlock: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            pin_hash: String::new(),
            max_failures: 3,
            min_pin_length: 4,
            required_non_digits_count: 3,
            hash_cost: 5,
            forgive_before_correct_pin: 45,
            forgive_before_correct_password: 90,
            max_suspicious_24h: 10,
            max_suspicious_7d: 25,
            max_suspicious_total: 60,
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
            .field("min_pin_length", &self.min_pin_length)
            .field("required_non_digits_count", &self.required_non_digits_count)
            .field("hash_cost", &self.hash_cost)
            .field("forgive_before_correct_pin", &self.forgive_before_correct_pin)
            .field("forgive_before_correct_password", &self.forgive_before_correct_password)
            .field("max_suspicious_24h", &self.max_suspicious_24h)
            .field("max_suspicious_7d", &self.max_suspicious_7d)
            .field("max_suspicious_total", &self.max_suspicious_total)
            .field("min_milliseconds_before_pin_unlock", &self.min_milliseconds_before_pin_unlock)
            .finish()
    }
}

impl Settings {
    /// Take over each of `pairs`, checking every value against its range. `source` names the file,
    /// for errors. A value outside its range is an error, never clamped: a typo must not quietly
    /// allow 50 failures.
    ///
    /// A user's own file (`user_file`) holds the hash and nothing else: the rules are one policy
    /// for the machine. Anywhere else the hash is refused, since one line would give every user the
    /// same PIN.
    pub fn apply(&mut self, pairs: &Pairs, source: &str, user_file: bool) -> Result<(), Error> {
        for (key, raw) in pairs {
            let key = key.as_str();
            match key {
                HASH_SETTING if user_file => self.pin_hash.clone_from(raw),
                HASH_SETTING => return Err(Error::OutsideUserFile { file: source.into(), key: key.into() }),
                _ if user_file => {
                    // A real setting is in the wrong file; anything else, like a key a version with
                    // a pepper left, is unknown wherever it is.
                    let known = Settings::default().apply(&vec![(key.to_owned(), raw.clone())], source, false);
                    return Err(match known {
                        Err(Error::UnknownSetting { .. }) => Error::UnknownSetting { file: source.into(), key: key.into() },
                        _ => Error::OnlyTheHash { file: source.into(), key: key.into() },
                    });
                }
                "max_failures" => self.max_failures = in_range(source, key, raw, 1, 10)?,
                "min_pin_length" => self.min_pin_length = in_range(source, key, raw, 1, MAX_PIN_CHARS)?,
                "required_non_digits_count" => self.required_non_digits_count = in_range(source, key, raw, 0, MAX_PIN_CHARS)?,
                "hash_cost" => self.hash_cost = in_range(source, key, raw, 1, 11)?,
                "forgive_before_correct_pin" => self.forgive_before_correct_pin = in_range(source, key, raw, 0, 3600)?,
                "forgive_before_correct_password" => self.forgive_before_correct_password = in_range(source, key, raw, 0, 3600)?,
                // The budget keeps at most MAX_SUSPICIOUS suspicious failures, so no limit may need more.
                "max_suspicious_24h" => self.max_suspicious_24h = in_range(source, key, raw, 1, 100)?,
                "max_suspicious_7d" => self.max_suspicious_7d = in_range(source, key, raw, 1, 200)?,
                "max_suspicious_total" => self.max_suspicious_total = in_range(source, key, raw, 1, 100_000)?,
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
        let non_digits = pin.chars().filter(|c| !c.is_ascii_digit()).count();
        let mut problems = Vec::new();
        if length < self.min_pin_length {
            problems.push(format!("at least {} characters", self.min_pin_length));
        }
        if length > MAX_PIN_CHARS {
            problems.push(format!("at most {MAX_PIN_CHARS} characters"));
        }
        if non_digits < self.required_non_digits_count {
            problems.push(format!("at least {} characters that aren't digits", self.required_non_digits_count));
        }
        if pin.chars().any(char::is_control) {
            problems.push("no control characters".into());
        }
        problems
    }

    /// The rules [`pin_problems`](Self::pin_problems) holds a PIN to, said before it is typed.
    pub fn pin_rules(&self) -> String {
        let length = format!("{} to {MAX_PIN_CHARS} characters", self.min_pin_length);
        match self.required_non_digits_count {
            0 => length,
            1 => format!("{length}, at least one of them not a digit"),
            count => format!("{length}, at least {count} of them not digits"),
        }
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
        let text = "max_failures = 5\nmin_pin_length = 6\nrequired_non_digits_count = 1\nhash_cost = 6\n\
                    forgive_before_correct_pin = 30\nforgive_before_correct_password = 60\nmax_suspicious_24h = 5\n\
                    max_suspicious_7d = 15\nmax_suspicious_total = 50\nmin_milliseconds_before_pin_unlock = 200\n";
        let expected = Settings {
            max_failures: 5,
            min_pin_length: 6,
            required_non_digits_count: 1,
            hash_cost: 6,
            forgive_before_correct_pin: 30,
            forgive_before_correct_password: 60,
            max_suspicious_24h: 5,
            max_suspicious_7d: 15,
            max_suspicious_total: 50,
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
    fn a_user_file_holds_the_hash_and_no_rule() {
        for text in ["max_failures = 2", "min_pin_length = 6", "max_suspicious_24h = 50", "min_milliseconds_before_pin_unlock = 0"] {
            assert!(matches!(apply(text, true), Err(Error::OnlyTheHash { .. })), "{text}");
        }
        let error = apply("hash = $y$j9T$abc$def\nmax_failures = 2\n", true).unwrap_err().to_string();
        assert_eq!(error, "f: holds max_failures, but a user's own file may only hold the hash; the setting belongs in the config");
        assert!(matches!(apply("max_suspicious_7d = 201", false), Err(Error::BadValue { .. })));
        assert!(matches!(apply("hash = $y$x\nencrypted_pepper = 00\n", true), Err(Error::UnknownSetting { .. })));
    }

    #[test]
    fn refuses_unknown_and_removed_settings() {
        for text in ["max_short_password_len = 5", "max_pin_length = 12", "min_letters = 1"] {
            assert!(matches!(apply(text, false), Err(Error::UnknownSetting { .. })), "{text}");
        }
    }

    #[test]
    fn only_the_user_file_may_hold_the_hash() {
        assert!(matches!(apply("hash = $y$j9T$abc$def", false), Err(Error::OutsideUserFile { .. })));
        assert_eq!(apply("hash = $y$j9T$abc$def\n", true).unwrap().pin_hash, "$y$j9T$abc$def");
    }

    #[test]
    fn counts_characters_not_bytes() {
        // 64 Cyrillic letters are 128 bytes and still fit.
        let longest = "ж".repeat(MAX_PIN_CHARS);
        assert!(Settings::default().pin_problems(&longest).is_empty());
        assert_eq!(Settings::default().pin_problems(&format!("{longest}ж")), ["at most 64 characters"]);
        assert_eq!(Settings::default().pin_problems("жж1"), ["at least 4 characters", "at least 3 characters that aren't digits"]);
    }

    #[test]
    fn everything_but_a_digit_counts_as_a_non_digit() {
        // Letters of any script, punctuation, and whitespace, spaces between words included.
        for pin in ["ab1c", "жы!7", "1 2 3 4", "\u{a0}-x9", "glider panorama"] {
            assert!(Settings::default().pin_problems(pin).is_empty(), "{pin:?}");
        }
        // Only 0 to 9 are digits; other scripts' digits are not.
        assert!(Settings::default().pin_problems("٣٤٥1").is_empty());
        assert_eq!(Settings::default().pin_problems("12ab"), ["at least 3 characters that aren't digits"]);
        let numeric = Settings { required_non_digits_count: 0, ..Settings::default() };
        assert!(numeric.pin_problems("4859").is_empty());
    }

    #[test]
    fn the_rules_name_what_pin_problems_checks() {
        assert_eq!(Settings::default().pin_rules(), "4 to 64 characters, at least 3 of them not digits");
        let one = Settings { required_non_digits_count: 1, ..Settings::default() };
        assert_eq!(one.pin_rules(), "4 to 64 characters, at least one of them not a digit");
        let numeric = Settings { min_pin_length: 6, required_non_digits_count: 0, ..Settings::default() };
        assert_eq!(numeric.pin_rules(), "6 to 64 characters");
    }

    #[test]
    fn a_pin_of_exactly_the_shortest_length_is_accepted() {
        assert!(Settings::default().pin_problems("abc9").is_empty());
        assert_eq!(Settings::default().pin_problems("abc"), ["at least 4 characters"]);
    }

    #[test]
    fn lists_every_problem() {
        let settings = Settings { required_non_digits_count: 2, ..Settings::default() };
        assert_eq!(
            settings.pin_problems("1\t"),
            ["at least 4 characters", "at least 2 characters that aren't digits", "no control characters"]
        );
    }

    #[test]
    fn debug_output_hides_the_hash() {
        let settings = Settings { pin_hash: "$y$secret".into(), ..Settings::default() };
        assert!(!format!("{settings:?}").contains("secret"));
    }
}
