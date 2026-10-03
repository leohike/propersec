//! The failures that outlive a boot, and the limits that disable the PIN.
//!
//! Every input typed at the lock screen that doesn't unlock is a failure, wrong passwords included,
//! except an empty one. A failure is forgiven when the correct PIN follows within
//! `forgive_before_correct_pin` seconds, or the correct password within
//! `forgive_before_correct_password`: that was the user, mistyping. A failure nothing forgave in
//! time is *concerning*. Too many concerning failures within 24 hours, within 7 days, or since the
//! PIN was set, and the PIN is disabled until root turns it back on (`properpin enable`) or sets a
//! new one. Rebooting changes nothing: the budget is kept on disk.
//!
//! This bounds the slow attack the failures in a row can't: two wrong guesses, then waiting for
//! the user's next correct PIN to wipe them, again and again. The user's PIN comes too late to
//! forgive the guesses, so each one counts.
//!
//! Times are wall-clock seconds, the only clock that survives a reboot. Whoever can set it (root,
//! or the firmware) could age concerning failures out of the 24-hour and 7-day windows, but never
//! out of the total.

use std::fmt;

use crate::Settings;
use crate::state::digits;

pub const DAY: u64 = 24 * 3600;
pub const WEEK: u64 = 7 * DAY;
/// A failure stamped further than this in the future means the clock went back. It is judged
/// concerning at once, instead of waiting for the clock to catch up.
const CLOCK_SLACK: u64 = 60;
/// The most failures kept waiting for judgement; beyond that, the oldest is judged concerning.
pub const MAX_PENDING: usize = 50;
/// The most concerning failures kept, more than any limit may ask for. The total keeps counting.
pub const MAX_CONCERNING: usize = 200;

/// Which limit disabled the PIN, with the number it was set to at the time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Day(u32),
    Week(u32),
    Total(u64),
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Day(count) => write!(f, "{count} concerning failures within 24 hours"),
            Self::Week(count) => write!(f, "{count} concerning failures within 7 days"),
            Self::Total(count) => write!(f, "{count} concerning failures since the PIN was set"),
        }
    }
}

/// When the PIN was disabled, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disabled {
    pub limit: Limit,
    pub at: u64,
}

/// One user's failures across boots. Kept as `key = value` lines; see [`Budget::format`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Budget {
    /// Failures not yet forgiven or judged, oldest first.
    pub pending: Vec<u64>,
    /// Concerning failures of the last 7 days, oldest first.
    pub concerning: Vec<u64>,
    /// Concerning failures since the PIN was set. Never goes down; only `set` starts it over.
    pub total: u64,
    pub disabled: Option<Disabled>,
}

/// How many concerning failures there are, as of one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub day: usize,
    pub week: usize,
    pub total: u64,
    /// Failures still waiting to be forgiven or judged.
    pub pending: usize,
}

/// What [`Budget::judge`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Judged {
    /// Failures that became concerning just now.
    pub newly_concerning: usize,
    pub counts: Counts,
    /// Whether the PIN is disabled, now or from before.
    pub disabled: Option<Limit>,
    /// Whether it was disabled just now.
    pub disabled_now: bool,
}

impl Judged {
    /// Lines for the log, if anything changed.
    pub fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.newly_concerning > 0 {
            let Counts { day, week, total, .. } = self.counts;
            notes.push(format!(
                "{} failure(s) not followed by an unlock in time, now concerning: {day} within 24 hours, {week} within 7 days, \
                 {total} since the PIN was set",
                self.newly_concerning
            ));
        }
        if let (true, Some(limit)) = (self.disabled_now, self.disabled) {
            notes.push(format!("PIN disabled after {limit}; sudo properpin enable or set turns it back on"));
        }
        notes
    }
}

impl Budget {
    /// Judge the failures waiting longer than either window allows, drop concerning failures older
    /// than 7 days, and disable the PIN if a limit is reached. Call it first, every time.
    pub fn judge(&mut self, now: u64, settings: &Settings) -> Judged {
        let wait = settings.forgive_before_correct_pin.max(settings.forgive_before_correct_password);
        let (due, waiting): (Vec<u64>, Vec<u64>) =
            self.pending.iter().partition(|&&at| now > at.saturating_add(wait) || at > now.saturating_add(CLOCK_SLACK));
        self.pending = waiting;
        let newly_concerning = due.len();
        self.add_concerning(&due);
        // Stamped in the future, they stay until the clock passes them: setting the clock back
        // doesn't make them go away sooner.
        self.concerning.retain(|&at| at.saturating_add(WEEK) > now);
        let counts = self.counts(now);
        let reached = if counts.day >= settings.max_concerning_24h as usize {
            Some(Limit::Day(settings.max_concerning_24h))
        } else if counts.week >= settings.max_concerning_7d as usize {
            Some(Limit::Week(settings.max_concerning_7d))
        } else if counts.total >= settings.max_concerning_total {
            Some(Limit::Total(settings.max_concerning_total))
        } else {
            None
        };
        let disabled_now = self.disabled.is_none() && reached.is_some();
        if let (true, Some(limit)) = (disabled_now, reached) {
            self.disabled = Some(Disabled { limit, at: now });
        }
        Judged { newly_concerning, counts, disabled: self.disabled.map(|disabled| disabled.limit), disabled_now }
    }

    pub fn counts(&self, now: u64) -> Counts {
        let within = |span: u64| self.concerning.iter().filter(|&&at| at.saturating_add(span) > now).count();
        Counts { day: within(DAY), week: within(WEEK), total: self.total, pending: self.pending.len() }
    }

    /// One more failure, waiting to be forgiven or judged.
    pub fn record_failure(&mut self, now: u64) {
        self.pending.push(now);
        self.pending.sort_unstable();
        if self.pending.len() > MAX_PENDING {
            let oldest = self.pending.remove(0);
            self.add_concerning(&[oldest]);
        }
    }

    /// A correct PIN or password at `now` forgives the failures of the last `window` seconds.
    /// Returns how many.
    pub fn forgive(&mut self, now: u64, window: u64) -> usize {
        let before = self.pending.len();
        self.pending.retain(|&at| at.saturating_add(window) < now);
        before - self.pending.len()
    }

    /// What `properpin enable` leaves behind: not disabled, nothing pending or concerning, and the
    /// total kept, so the lifetime limit still holds for this PIN.
    pub fn enabled(&self) -> Self {
        Self { total: self.total, ..Self::default() }
    }

    fn add_concerning(&mut self, failures: &[u64]) {
        self.concerning.extend_from_slice(failures);
        self.concerning.sort_unstable();
        let excess = self.concerning.len().saturating_sub(MAX_CONCERNING);
        self.concerning.drain(..excess);
        self.total = self.total.saturating_add(failures.len() as u64);
    }

    /// The budget in `text`, or `None` unless it parses exactly. Unlike the per-boot state, a
    /// damaged budget is an error for the caller: reading it as empty would hand out a fresh one.
    pub fn parse(text: &str) -> Option<Self> {
        let pairs = crate::kv::parse(text, "budget").ok()?;
        let get = |key: &str| pairs.iter().find(|(name, _)| name == key).map(|(_, value)| value.as_str());
        if pairs.len() != 4 {
            return None;
        }
        let pending = times(get("pending")?, MAX_PENDING)?;
        let concerning = times(get("concerning")?, MAX_CONCERNING)?;
        let disabled = match get("disabled")?.split(' ').collect::<Vec<_>>()[..] {
            ["no"] => None,
            [kind, count, at] => {
                let limit = match kind {
                    "day" => Limit::Day(digits(count)?),
                    "week" => Limit::Week(digits(count)?),
                    "total" => Limit::Total(digits(count)?),
                    _ => return None,
                };
                Some(Disabled { limit, at: digits(at)? })
            }
            _ => return None,
        };
        Some(Self { pending, concerning, total: digits(get("total")?)?, disabled })
    }

    pub fn format(&self) -> String {
        let list = |times: &[u64]| match times {
            [] => "none".to_owned(),
            _ => times.iter().map(u64::to_string).collect::<Vec<_>>().join(" "),
        };
        let disabled = match self.disabled {
            None => "no".to_owned(),
            Some(Disabled { limit: Limit::Day(count), at }) => format!("day {count} {at}"),
            Some(Disabled { limit: Limit::Week(count), at }) => format!("week {count} {at}"),
            Some(Disabled { limit: Limit::Total(count), at }) => format!("total {count} {at}"),
        };
        format!(
            "pending = {}\nconcerning = {}\ntotal = {}\ndisabled = {disabled}\n",
            list(&self.pending),
            list(&self.concerning),
            self.total
        )
    }
}

/// `none`, or up to `max` times separated by single spaces, oldest first.
fn times(text: &str, max: usize) -> Option<Vec<u64>> {
    if text == "none" {
        return Some(Vec::new());
    }
    let times = text.split(' ').map(digits).collect::<Option<Vec<u64>>>()?;
    (times.len() <= max && times.is_sorted()).then_some(times)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const T: u64 = 1_800_000_000;

    fn settings() -> Settings {
        Settings::default()
    }

    #[test]
    fn a_correct_pin_forgives_only_the_last_45_seconds() {
        let mut budget = Budget::default();
        for at in [T, T + 10, T + 54, T + 55, T + 99] {
            budget.record_failure(at);
        }
        // T+55 is exactly 45 seconds back and is forgiven; T+54, 46 seconds back, isn't.
        assert_eq!(budget.forgive(T + 100, 45), 2);
        assert_eq!(budget.pending, [T, T + 10, T + 54]);
    }

    #[test]
    fn the_password_forgives_90_seconds_and_judging_waits_for_it() {
        let mut budget = Budget::default();
        budget.record_failure(T);
        // At 90 seconds the failure still waits: the password could still forgive it.
        assert_eq!(budget.judge(T + 90, &settings()).newly_concerning, 0);
        assert_eq!(budget.forgive(T + 90, 90), 1);
        budget.record_failure(T);
        assert_eq!(budget.judge(T + 91, &settings()).newly_concerning, 1);
        assert_eq!((budget.total, budget.concerning.as_slice()), (1, &[T][..]));
    }

    #[test]
    fn a_correct_pin_too_late_leaves_the_failure_to_become_concerning() {
        let mut budget = Budget::default();
        budget.record_failure(T);
        budget.judge(T + 60, &settings());
        assert_eq!(budget.forgive(T + 60, 45), 0);
        assert_eq!(budget.judge(T + 120, &settings()).newly_concerning, 1);
    }

    #[test]
    fn each_limit_disables_and_stays_disabled() {
        let day = Settings::default().max_concerning_24h as u64;
        let mut budget = Budget::default();
        for i in 0..day {
            budget.record_failure(T + i * 100);
        }
        let judged = budget.judge(T + day * 100 + 1000, &settings());
        assert_eq!((judged.disabled, judged.disabled_now), (Some(Limit::Day(10)), true));
        // Days later the counts are gone from the window, and it stays disabled.
        let judged = budget.judge(T + 3 * DAY, &settings());
        assert_eq!((judged.counts.day, judged.disabled, judged.disabled_now), (0, Some(Limit::Day(10)), false));

        // Nine a day stays under the daily limit, and reaches the weekly one on the third day.
        let mut budget = Budget::default();
        let mut disabled = None;
        for day in 0..3 {
            for i in 0..9 {
                budget.record_failure(T + day * DAY + i * 100);
            }
            disabled = disabled.or(budget.judge(T + day * DAY + 2000, &settings()).disabled);
        }
        assert_eq!(disabled, Some(Limit::Week(20)));

        let mut budget = Budget { total: 99, ..Budget::default() };
        budget.record_failure(T);
        assert_eq!(budget.judge(T + 1000, &settings()).disabled, Some(Limit::Total(100)));
    }

    #[test]
    fn a_clock_set_back_neither_hides_nor_delays_failures() {
        let mut budget = Budget::default();
        budget.record_failure(T);
        budget.concerning.push(T);
        // The clock goes back an hour: the pending failure is judged at once, the concerning one stays.
        let judged = budget.judge(T - 3600, &settings());
        assert_eq!((judged.newly_concerning, judged.counts.day, judged.counts.week), (1, 2, 2));
        // A small step back, as NTP may make, just waits.
        let mut budget = Budget::default();
        budget.record_failure(T);
        assert_eq!(budget.judge(T - 30, &settings()).newly_concerning, 0);
    }

    #[test]
    fn a_flood_of_failures_is_judged_rather_than_dropped() {
        let mut budget = Budget::default();
        for i in 0..MAX_PENDING as u64 + 5 {
            budget.record_failure(T + i);
        }
        assert_eq!((budget.pending.len(), budget.total), (MAX_PENDING, 5));
        assert!(budget.format().len() < crate::MAX_FILE_BYTES);
        let mut budget = Budget::default();
        for i in 0..1000 {
            budget.add_concerning(&[T + i]);
        }
        assert_eq!((budget.concerning.len(), budget.total), (MAX_CONCERNING, 1000));
    }

    #[test]
    fn enabling_keeps_only_the_total() {
        let budget = Budget { pending: vec![T], concerning: vec![T], total: 12, disabled: Some(Disabled { limit: Limit::Day(10), at: T }) };
        assert_eq!(budget.enabled(), Budget { total: 12, ..Budget::default() });
    }

    #[test]
    fn round_trips_and_refuses_anything_else() {
        let budget = Budget {
            pending: vec![T, T + 1],
            concerning: vec![T - 5],
            total: 7,
            disabled: Some(Disabled { limit: Limit::Week(20), at: T }),
        };
        assert_eq!(Budget::parse(&budget.format()), Some(budget));
        assert_eq!(Budget::parse(&Budget::default().format()), Some(Budget::default()));
        let valid = "pending = none\nconcerning = none\ntotal = 0\ndisabled = no\n";
        assert!(Budget::parse(valid).is_some());
        for text in [
            "",
            "pending = none\nconcerning = none\ntotal = 0\n",
            "pending = none\nconcerning = none\ntotal = 0\ndisabled = no\nextra = 1\n",
            "pending = 2 1\nconcerning = none\ntotal = 0\ndisabled = no\n",
            "pending = 1  2\nconcerning = none\ntotal = 0\ndisabled = no\n",
            "pending = none\nconcerning = -1\ntotal = 0\ndisabled = no\n",
            "pending = none\nconcerning = none\ntotal = x\ndisabled = no\n",
            "pending = none\nconcerning = none\ntotal = 0\ndisabled = yes\n",
            "pending = none\nconcerning = none\ntotal = 0\ndisabled = month 1 2\n",
        ] {
            assert_eq!(Budget::parse(text), None, "{text:?}");
        }
    }

    #[derive(Debug, Clone)]
    enum Event {
        Failure,
        CorrectPin,
        CorrectPassword,
        Wait(u64),
    }

    fn event() -> impl Strategy<Value = Event> {
        prop_oneof![
            3 => Just(Event::Failure),
            1 => Just(Event::CorrectPin),
            1 => Just(Event::CorrectPassword),
            2 => (0..2 * DAY).prop_map(Event::Wait),
        ]
    }

    proptest! {
        /// Whatever happens, the total never goes down and once disabled the PIN stays disabled,
        /// and every failure ends up forgiven, pending or counted: none is lost.
        #[test]
        fn nothing_is_ever_lost(events in prop::collection::vec(event(), 0..200)) {
            let settings = settings();
            let (mut budget, mut now) = (Budget::default(), T);
            let (mut failures, mut forgiven, mut was_disabled) = (0u64, 0u64, false);
            for event in events {
                let total = budget.total;
                budget.judge(now, &settings);
                match event {
                    Event::Failure => { budget.record_failure(now); failures += 1 }
                    Event::CorrectPin => forgiven += budget.forgive(now, settings.forgive_before_correct_pin) as u64,
                    Event::CorrectPassword => forgiven += budget.forgive(now, settings.forgive_before_correct_password) as u64,
                    Event::Wait(seconds) => now += seconds,
                }
                prop_assert!(budget.total >= total);
                prop_assert!(!was_disabled || budget.disabled.is_some());
                was_disabled = budget.disabled.is_some();
                prop_assert_eq!(failures, forgiven + budget.pending.len() as u64 + budget.total);
            }
        }

        /// The attack the budget exists for: a guess or two, then the user's correct PIN later on,
        /// again and again. However the attacker paces it, the PIN is disabled by the total limit
        /// at the latest, so they never get more guesses than it allows, plus the two or three
        /// still waiting to be judged when it is reached.
        #[test]
        fn a_slow_attacker_is_stopped(gaps in prop::collection::vec(46..3 * DAY, 1..400)) {
            let settings = settings();
            let (mut budget, mut now, mut guesses) = (Budget::default(), T, 0u64);
            for gap in gaps {
                if budget.judge(now, &settings).disabled.is_some() {
                    break;
                }
                budget.record_failure(now);
                guesses += 1;
                now += gap;
                budget.judge(now, &settings);
                budget.forgive(now, settings.forgive_before_correct_pin);
            }
            prop_assert!(guesses <= settings.max_concerning_total + 3);
        }
    }
}
