use std::fmt;
use std::str::FromStr;

use crate::kv::Pairs;
use crate::{
    CLEARTEXT_SALT_FOR_DERIVING_PEPPER_DECRYPTION_KEY_SETTING, ENCRYPTED_PEPPER_SETTING, Error, HASH_SETTING, PinState, Refusal, USER_ONLY,
};

/// Everything that decides one user's PIN: its hash and encrypted pepper, and the rules for it.
///
/// Built in layers: these defaults, then the global config, then the user's own file, each
/// [`Settings::apply`] winning over the layer before. Only the user's own file may hold the hash.
/// Like a line of `/etc/shadow`, that file keeps the secret and the rules for it together, where
/// only root can change them.
///
/// The unlock path uses the hash, the next three fields and the budget's five; `set` uses the
/// four in between, and `seal_cost`; arming uses the cleartext salt for deriving the pepper decryption key and the
/// encrypted pepper. The PAM module itself reads `min_milliseconds_before_pin_unlock`. The
/// budget's settings, `seal_cost` and `min_milliseconds_before_pin_unlock` may only come from the
/// global config.
#[derive(Clone, PartialEq)]
pub struct Settings {
    /// Empty: no PIN is set. The hash of the pepper's hex digits followed by the PIN
    /// (`hash_of_peppered_pin`).
    pub pin_hash: String,
    /// The yescrypt setting the pepper's key is derived from the password with, salt and cost
    /// both. Empty only for a PIN set before peppers, which can never be armed.
    pub cleartext_salt_for_deriving_pepper_decryption_key: String,
    /// The pepper XORed with that key, as 64 hex digits.
    pub encrypted_pepper: String,
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
    /// yescrypt cost `set` derives the pepper's key with. Every password unlock pays it, while the
    /// lock screen waits; whoever steals the files pays it for every password they guess.
    pub seal_cost: u32,
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

/// The budget's settings (one policy for the machine, never per user), `seal_cost`, and the PAM
/// module's wait, which the module reads as the user, who can't read their own file.
const GLOBAL_ONLY: &[&str] = &[
    "forgive_before_correct_pin",
    "forgive_before_correct_password",
    "max_concerning_24h",
    "max_concerning_7d",
    "max_concerning_total",
    "seal_cost",
    "min_milliseconds_before_pin_unlock",
];

impl Default for Settings {
    fn default() -> Self {
        Self {
            pin_hash: String::new(),
            cleartext_salt_for_deriving_pepper_decryption_key: String::new(),
            encrypted_pepper: String::new(),
            expiry_hours: 8.0,
            max_failures: 3,
            max_pin_length: 12,
            min_pin_length: 4,
            min_letters: 0,
            hash_cost: 5,
            seal_cost: 8,
            forgive_before_correct_pin: 45,
            forgive_before_correct_password: 90,
            max_concerning_24h: 10,
            max_concerning_7d: 20,
            max_concerning_total: 100,
            min_milliseconds_before_pin_unlock: 75,
        }
    }
}

// The hash and the pepper stay out of debug output and logs.
impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("pin_hash", &if self.pin_hash.is_empty() { "<none>" } else { "<set>" })
            .field("encrypted_pepper", &if self.encrypted_pepper.is_empty() { "<none>" } else { "<set>" })
            .field("expiry_hours", &self.expiry_hours)
            .field("max_failures", &self.max_failures)
            .field("max_pin_length", &self.max_pin_length)
            .field("min_pin_length", &self.min_pin_length)
            .field("min_letters", &self.min_letters)
            .field("hash_cost", &self.hash_cost)
            .field("seal_cost", &self.seal_cost)
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
    /// Only a user's own file may set the hash and the pepper (`may_set_hash`). Anywhere else, one
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
                CLEARTEXT_SALT_FOR_DERIVING_PEPPER_DECRYPTION_KEY_SETTING => {
                    self.cleartext_salt_for_deriving_pepper_decryption_key.clone_from(raw)
                }
                ENCRYPTED_PEPPER_SETTING => self.encrypted_pepper.clone_from(raw),
                "expiry_hours" => self.expiry_hours = in_range(source, key, raw, 0.01, 168.0)?,
                "max_failures" => self.max_failures = in_range(source, key, raw, 1, 10)?,
                // 64 characters fit MAX_PIN_BYTES even at 4 bytes each.
                "max_pin_length" => self.max_pin_length = in_range(source, key, raw, 1, 64)?,
                "min_pin_length" => self.min_pin_length = in_range(source, key, raw, 1, 64)?,
                "min_letters" => self.min_letters = in_range(source, key, raw, 0, 64)?,
                "hash_cost" => self.hash_cost = in_range(source, key, raw, 1, 11)?,
                "seal_cost" => self.seal_cost = in_range(source, key, raw, 1, 11)?,
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

    pub fn expiry_seconds(&self) -> f64 {
        self.expiry_hours * 3600.0
    }

    /// The same, in whole seconds, rounded down.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "apply() keeps expiry_hours within 0.01 to 168, so this is at most 604,800 seconds; a float-to-integer cast saturates anyway"
    )]
    pub fn expiry_whole_seconds(&self) -> u64 {
        self.expiry_seconds() as u64
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
        if state.pepper.is_none() {
            return Some(Refusal::NoPepper);
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
    fn every_setting_is_read() {
        let text = "expiry_hours = 2\nmax_failures = 5\nmax_pin_length = 8\nmin_pin_length = 6\nmin_letters = 1\nhash_cost = 6\n\
                    seal_cost = 9\nforgive_before_correct_pin = 30\nforgive_before_correct_password = 60\nmax_concerning_24h = 5\n\
                    max_concerning_7d = 15\nmax_concerning_total = 50\nmin_milliseconds_before_pin_unlock = 200\n";
        let expected = Settings {
            expiry_hours: 2.0,
            max_failures: 5,
            max_pin_length: 8,
            min_pin_length: 6,
            min_letters: 1,
            hash_cost: 6,
            seal_cost: 9,
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
            "expiry_hours = nan",
            "expiry_hours = inf",
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
            "seal_cost = 5",
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
        for text in ["hash = $y$j9T$abc$def", "cleartext_salt_for_deriving_pepper_decryption_key = $y$j9T$abc", "encrypted_pepper = 00"] {
            assert!(matches!(apply(text, false), Err(Error::OutsideUserFile { .. })), "{text}");
        }
        let settings =
            apply("hash = $y$j9T$abc$def\ncleartext_salt_for_deriving_pepper_decryption_key = $y$jBT$xyz\nencrypted_pepper = 00\n", true)
                .unwrap();
        assert_eq!(
            (
                settings.pin_hash.as_str(),
                settings.cleartext_salt_for_deriving_pepper_decryption_key.as_str(),
                settings.encrypted_pepper.as_str()
            ),
            ("$y$j9T$abc$def", "$y$jBT$xyz", "00")
        );
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
