//! One user's failures, the only state screenlock-pin keeps: the consecutive count that pauses the PIN,
//! and the limits that disable it. Kept on disk, so rebooting changes nothing.
//!
//! Every input typed at the lock screen while the PIN is enabled that doesn't unlock is a failure,
//! wrong passwords included, except an empty one. While the PIN is paused or disabled nothing is
//! checked, so nothing is recorded. A failure is forgiven when the correct PIN follows within
//! `forgive_before_correct_pin` seconds, or the correct password within
//! `forgive_before_correct_password`: that was the user, mistyping. A failure nothing forgave in
//! time is *suspicious*. Too many suspicious failures within 24 hours, within 7 days, or since the
//! PIN was set, and the PIN is disabled until root turns it back on (`screenlock-pin enable`) or sets a
//! new one.
//!
//! This bounds the slow attack the consecutive count can't: two wrong guesses, then waiting for
//! the user's next correct PIN to wipe them, again and again. The user's PIN comes too late to
//! forgive the guesses, so each one counts.
//!
//! Times are wall-clock seconds, the only clock that survives a reboot. Whoever can set it (root,
//! or the firmware) could age suspicious failures out of the 24-hour and 7-day windows, but never
//! out of the total.

use std::fmt;

use crate::Settings;
use crate::kv::digits;

pub const DAY: u64 = 24 * 3600;
pub const WEEK: u64 = 7 * DAY;
/// The most failures kept waiting for judgement; beyond that, the oldest is judged suspicious.
pub const MAX_PENDING: usize = 50;
/// The most suspicious failures kept, more than any limit may ask for. The total keeps counting.
pub const MAX_SUSPICIOUS: usize = 200;

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
            Self::Day(count) => write!(f, "{count} suspicious failures within 24 hours"),
            Self::Week(count) => write!(f, "{count} suspicious failures within 7 days"),
            Self::Total(count) => write!(f, "{count} suspicious failures since the PIN was set"),
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
    /// Inputs checked against the hash, one after another, that weren't the PIN, since the last PIN unlock or
    /// the last password unlock. At `max_failures`, the PIN is paused. A mistyped password counts
    /// too, when it is short enough to be a PIN.
    pub consecutive: u32,
    /// Failures not yet forgiven or judged, oldest first.
    pub pending: Vec<u64>,
    /// Suspicious failures of the last 7 days, oldest first.
    pub suspicious: Vec<u64>,
    /// Suspicious failures since the PIN was set. Never goes down; only `set` starts it over.
    pub total: u64,
    pub disabled: Option<Disabled>,
    /// When the PIN was set.
    pub set: u64,
    /// When the PIN last became enabled or paused, for `screenlock-pin status`. Disabled has its own
    /// time, in [`Disabled::at`].
    pub since: u64,
}

/// How many suspicious failures there are, as of one moment.
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
    /// Failures that became suspicious just now.
    pub newly_suspicious: usize,
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
        if self.newly_suspicious > 0 {
            let Counts { day, week, total, .. } = self.counts;
            notes.push(format!(
                "{} failure(s) not followed by an unlock in time, now suspicious: {day} within 24 hours, {week} within 7 days, \
                 {total} since the PIN was set",
                self.newly_suspicious
            ));
        }
        if let (true, Some(limit)) = (self.disabled_now, self.disabled) {
            notes.push(format!("PIN disabled after {limit}; sudo screenlock-pin enable or set turns it back on"));
        }
        notes
    }
}

impl Budget {
    /// Judge the failures waiting longer than either window allows, drop suspicious failures older
    /// than 7 days, and disable the PIN if a limit is reached. Call it first, every time.
    pub fn judge(&mut self, now: u64, settings: &Settings) -> Judged {
        let wait = settings.forgive_before_correct_pin.max(settings.forgive_before_correct_password);
        let (due, waiting): (Vec<u64>, Vec<u64>) = self.pending.iter().partition(|&&at| now > at.saturating_add(wait));
        self.pending = waiting;
        let newly_suspicious = due.len();
        self.add_suspicious(&due);
        self.suspicious.retain(|&at| at.saturating_add(WEEK) > now);
        let counts = self.counts(now);
        let reached = if counts.day >= settings.max_suspicious_24h as usize {
            Some(Limit::Day(settings.max_suspicious_24h))
        } else if counts.week >= settings.max_suspicious_7d as usize {
            Some(Limit::Week(settings.max_suspicious_7d))
        } else if counts.total >= settings.max_suspicious_total {
            Some(Limit::Total(settings.max_suspicious_total))
        } else {
            None
        };
        let disabled_now = self.disabled.is_none() && reached.is_some();
        if let (true, Some(limit)) = (disabled_now, reached) {
            self.disabled = Some(Disabled { limit, at: now });
        }
        Judged { newly_suspicious, counts, disabled: self.disabled.map(|disabled| disabled.limit), disabled_now }
    }

    pub fn counts(&self, now: u64) -> Counts {
        let within = |span: u64| self.suspicious.iter().filter(|&&at| at.saturating_add(span) > now).count();
        Counts { day: within(DAY), week: within(WEEK), total: self.total, pending: self.pending.len() }
    }

    /// One more failure, waiting to be forgiven or judged.
    pub fn record_failure(&mut self, now: u64) {
        self.pending.push(now);
        self.pending.sort_unstable();
        if self.pending.len() > MAX_PENDING {
            let oldest = self.pending.remove(0);
            self.add_suspicious(&[oldest]);
        }
    }

    /// A correct PIN or password at `now` forgives the failures of the last `window` seconds.
    /// Returns how many.
    pub fn forgive(&mut self, now: u64, window: u64) -> usize {
        let before = self.pending.len();
        self.pending.retain(|&at| at.saturating_add(window) < now);
        before - self.pending.len()
    }

    /// Whether the PIN is paused: `max_failures` consecutive failures, until a password unlock.
    pub fn paused(&self, settings: &Settings) -> bool {
        self.consecutive >= settings.max_failures
    }

    /// The budget of a PIN set at `now`: enabled, with nothing counted.
    pub fn fresh(now: u64) -> Self {
        Self { set: now, since: now, ..Self::default() }
    }

    /// What `screenlock-pin enable` leaves behind at `now`: not disabled or paused, nothing pending or
    /// suspicious, and the total kept, so the lifetime limit still holds for this PIN.
    pub fn enabled(&self, now: u64) -> Self {
        Self { total: self.total, set: self.set, since: now, ..Self::default() }
    }

    fn add_suspicious(&mut self, failures: &[u64]) {
        self.suspicious.extend_from_slice(failures);
        self.suspicious.sort_unstable();
        let excess = self.suspicious.len().saturating_sub(MAX_SUSPICIOUS);
        self.suspicious.drain(..excess);
        self.total = self.total.saturating_add(failures.len() as u64);
    }

    /// The budget in `text`, or `None` unless it parses exactly. A damaged budget is an error for
    /// the caller: reading it as empty would hand out a fresh one.
    pub fn parse(text: &str) -> Option<Self> {
        let pairs = crate::kv::parse(text, "budget").ok()?;
        let get = |key: &str| pairs.iter().find(|(name, _)| name == key).map(|(_, value)| value.as_str());
        if pairs.len() != 7 {
            return None;
        }
        let (set, since) = (digits(get("set")?)?, digits(get("since")?)?);
        let pending = times(get("pending")?, MAX_PENDING)?;
        let suspicious = times(get("suspicious")?, MAX_SUSPICIOUS)?;
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
        Some(Self { consecutive: digits(get("consecutive")?)?, pending, suspicious, total: digits(get("total")?)?, disabled, set, since })
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
            "consecutive = {}\npending = {}\nsuspicious = {}\ntotal = {}\ndisabled = {disabled}\nset = {}\nsince = {}\n",
            self.consecutive,
            list(&self.pending),
            list(&self.suspicious),
            self.total,
            self.set,
            self.since
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
        assert_eq!(budget.judge(T + 90, &settings()).newly_suspicious, 0);
        assert_eq!(budget.forgive(T + 90, 90), 1);
        budget.record_failure(T);
        assert_eq!(budget.judge(T + 91, &settings()).newly_suspicious, 1);
        assert_eq!((budget.total, budget.suspicious.as_slice()), (1, &[T][..]));
    }

    #[test]
    fn a_correct_pin_too_late_leaves_the_failure_to_become_suspicious() {
        let mut budget = Budget::default();
        budget.record_failure(T);
        budget.judge(T + 60, &settings());
        assert_eq!(budget.forgive(T + 60, 45), 0);
        assert_eq!(budget.judge(T + 120, &settings()).newly_suspicious, 1);
    }

    #[test]
    fn each_limit_disables_and_stays_disabled() {
        let day = Settings::default().max_suspicious_24h as u64;
        let mut budget = Budget::default();
        for i in 0..day {
            budget.record_failure(T + i * 100);
        }
        let judged = budget.judge(T + day * 100 + 1000, &settings());
        assert_eq!((judged.disabled, judged.disabled_now), (Some(Limit::Day(10)), true));
        // Judged again while still over the limit, it stays disabled from the first time.
        let judged = budget.judge(T + day * 100 + 2000, &settings());
        assert_eq!((judged.disabled_now, budget.disabled.map(|disabled| disabled.at)), (false, Some(T + day * 100 + 1000)));
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
        assert_eq!(disabled, Some(Limit::Week(25)));

        let mut budget = Budget { total: 59, ..Budget::default() };
        budget.record_failure(T);
        assert_eq!(budget.judge(T + 1000, &settings()).disabled, Some(Limit::Total(60)));
    }

    #[test]
    fn a_suspicious_failure_counts_for_24_hours_and_is_kept_for_7_days() {
        let mut budget = Budget { suspicious: vec![T], total: 1, ..Budget::default() };
        assert_eq!(budget.counts(T + 23 * 3600).day, 1);
        assert_eq!(budget.counts(T + 24 * 3600).day, 0);
        budget.judge(T + 7 * 24 * 3600 - 1, &settings());
        assert_eq!(budget.suspicious, [T]);
        budget.judge(T + 7 * 24 * 3600, &settings());
        assert_eq!((budget.suspicious.len(), budget.total), (0, 1));
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
            budget.add_suspicious(&[T + i]);
        }
        assert_eq!((budget.suspicious.len(), budget.total), (MAX_SUSPICIOUS, 1000));
    }

    #[test]
    fn enabling_keeps_only_the_total() {
        let budget = Budget {
            consecutive: 3,
            pending: vec![T],
            suspicious: vec![T],
            total: 12,
            disabled: Some(Disabled { limit: Limit::Day(10), at: T }),
            set: T - 100,
            since: T - 50,
        };
        assert_eq!(budget.enabled(T + 1), Budget { total: 12, set: T - 100, since: T + 1, ..Budget::default() });
    }

    #[test]
    fn round_trips_and_refuses_anything_else() {
        let budget = Budget {
            consecutive: 2,
            pending: vec![T, T + 1],
            suspicious: vec![T - 5],
            total: 7,
            disabled: Some(Disabled { limit: Limit::Week(25), at: T }),
            set: T - 9,
            since: T - 3,
        };
        assert_eq!(Budget::parse(&budget.format()), Some(budget));
        assert_eq!(Budget::parse(&Budget::default().format()), Some(Budget::default()));
        assert_eq!(Budget::parse(&Budget::fresh(T).format()), Some(Budget::fresh(T)));
        for limit in [Limit::Day(10), Limit::Week(25), Limit::Total(60)] {
            let disabled = Budget { disabled: Some(Disabled { limit, at: T }), ..Budget::default() };
            assert_eq!(Budget::parse(&disabled.format()), Some(disabled));
        }
        let valid = "consecutive = 0\npending = none\nsuspicious = none\ntotal = 0\ndisabled = no\nset = 1\nsince = 2\n";
        assert_eq!(Budget::parse(valid), Some(Budget { set: 1, since: 2, ..Budget::default() }));
        for text in [
            "",
            // Older budgets, without set and since.
            "consecutive = 0\npending = none\nsuspicious = none\ntotal = 0\ndisabled = no\n",
            "consecutive = 0\npending = none\nsuspicious = none\ntotal = 0\ndisabled = no\nset = unknown\nsince = 2\n",
            "consecutive = 0\npending = none\nsuspicious = none\ntotal = 0\ndisabled = no\nset = 1\nsince = -1\n",
            "consecutive = 0\npending = none\nsuspicious = none\ntotal = 0\ndisabled = no\nset = 1\n",
            "pending = none\nsuspicious = none\ntotal = 0\ndisabled = no\nset = 1\nsince = 2\n",
            "consecutive = -1\npending = none\nsuspicious = none\ntotal = 0\ndisabled = no\nset = 1\nsince = 2\n",
            "consecutive = 0\npending = none\nsuspicious = none\ntotal = 0\nset = 1\nsince = 2\n",
            "consecutive = 0\npending = none\nsuspicious = none\ntotal = 0\ndisabled = no\nextra = 1\nset = 1\nsince = 2\n",
            "consecutive = 0\npending = 2 1\nsuspicious = none\ntotal = 0\ndisabled = no\nset = 1\nsince = 2\n",
            "consecutive = 0\npending = 1  2\nsuspicious = none\ntotal = 0\ndisabled = no\nset = 1\nsince = 2\n",
            "consecutive = 0\npending = none\nsuspicious = -1\ntotal = 0\ndisabled = no\nset = 1\nsince = 2\n",
            "consecutive = 0\npending = none\nsuspicious = none\ntotal = x\ndisabled = no\nset = 1\nsince = 2\n",
            "consecutive = 0\npending = none\nsuspicious = none\ntotal = 0\ndisabled = yes\nset = 1\nsince = 2\n",
            "consecutive = 0\npending = none\nsuspicious = none\ntotal = 0\ndisabled = month 1 2\nset = 1\nsince = 2\n",
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
            prop_assert!(guesses <= settings.max_suspicious_total + 3);
        }
    }
}
