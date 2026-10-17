//! One unlock attempt, and the housekeeping after a password unlock. Refusal is the default: the
//! only [`Verdict::Unlock`] comes from a matching PIN while the PIN is enabled.

use std::fmt;

use crate::{Budget, Error, Judged, MAX_PIN_BYTES, Refusal, Secret, Settings};

/// Where one user's settings and budget live, and the rules for trusting them.
pub trait Store {
    /// Held for one read-decide-write cycle of the budget; released when dropped.
    type Lock;
    /// The defaults, then the global config, then the user's own file with the hash.
    fn settings(&self) -> Result<Settings, Error>;
    /// An exclusive lock, so two attempts can't interleave.
    fn lock(&self) -> Result<Self::Lock, Error>;
    /// The user's failures: an empty budget when there is none yet, an error when it can't be
    /// trusted, since reading a damaged budget as empty would hand out a fresh one.
    fn load_budget(&self) -> Result<Budget, Error>;

    /// Replace the budget atomically, and durably: it must survive a power cut.
    fn save_budget(&self, budget: &Budget) -> Result<(), Error>;
}

/// The time of day.
pub trait Clock {
    /// Seconds since 1970: the only clock that survives a reboot, so the budget uses it.
    fn now(&self) -> Result<u64, Error>;
}

/// Checks a typed PIN against the stored hash.
pub trait Hasher {
    fn verify(&self, pin: &str, hash: &str) -> Result<bool, Error>;
}

/// Checks the account password, the way pam_unix does: through `unix_chkpwd` once installed.
pub trait PasswordCheck {
    fn matches(&self, user: &str, password: &Secret) -> Result<bool, Error>;
}

/// One line per event. Never pass a PIN, a password, or anything derived from one.
pub trait Log {
    fn log(&self, line: &str);
}

/// What one unlock attempt came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The PIN matched while it was enabled. The only outcome that unlocks.
    Unlock,
    /// Nothing was typed. Not a failure of any kind.
    Empty,
    /// No PIN is set for this user. Not a failure of any kind.
    NoPinSet,
    /// Input that can never be a PIN (see [`input_that_could_be_a_pin`]). Not counted as
    /// consecutive.
    Unusable,
    /// The PIN is paused or disabled; the input wasn't checked, or recorded.
    Refused(Refusal),
    /// Checked, and not the PIN.
    WrongPin { consecutive: u32, max: u32 },
}

/// What [`try_unlock_with_pin`] came to. `Unusable` and `WrongPin` are also failures in
/// the budget, waiting to be forgiven; `judged` says what the budget looked like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockAttemptOutcome {
    pub verdict: Verdict,
    pub judged: Judged,
}

impl Verdict {
    pub fn unlocks(&self) -> bool {
        *self == Self::Unlock
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlock => write!(f, "unlocked with the PIN"),
            Self::Empty => write!(f, "nothing typed, refused"),
            Self::NoPinSet => write!(f, "no PIN is set, refused"),
            Self::Unusable => write!(f, "input that can't be a PIN, refused; not counted as consecutive"),
            Self::Refused(refusal) => write!(f, "{refusal}"),
            Self::WrongPin { consecutive, max } => {
                write!(f, "not the PIN, consecutive failure {consecutive} of {max}")?;
                if consecutive >= max {
                    write!(f, "; PIN paused, password required")?;
                }
                Ok(())
            }
        }
    }
}

/// What the user typed, or `None` when it can't possibly be a PIN: empty, longer than
/// [`MAX_PIN_BYTES`], holding a NUL, or not UTF-8. Such input never counts as consecutive.
pub fn input_that_could_be_a_pin(raw: &[u8]) -> Option<&str> {
    if raw.is_empty() || raw.len() > MAX_PIN_BYTES || raw.contains(&0) {
        return None;
    }
    std::str::from_utf8(raw).ok()
}

/// One unlock attempt with `typed`, everything the lock screen passed on.
///
/// An `Err` means something is broken (a file, the clock, libxcrypt); the caller treats it like
/// any other refusal, so the password is checked next.
pub fn try_unlock_with_pin(
    store: &impl Store,
    hasher: &impl Hasher,
    clock: &impl Clock,
    typed: &[u8],
) -> Result<UnlockAttemptOutcome, Error> {
    let plain = |verdict| Ok(UnlockAttemptOutcome { verdict, judged: Judged::default() });
    if typed.is_empty() {
        return plain(Verdict::Empty);
    }
    let settings = store.settings()?;
    if settings.pin_hash.is_empty() {
        return plain(Verdict::NoPinSet);
    }
    let _lock = store.lock()?;
    let now = clock.now()?;
    let mut budget = store.load_budget()?;
    let loaded = budget.clone();
    let judged = budget.judge(now, &settings);
    // Paused or disabled: refused without a look. Nothing is checked, so nothing is guessed, and
    // nothing is recorded: the password typed next can't add to the budget. Only what judging
    // changed by itself is saved, if anything: failures it moved or dropped, the PIN it disabled.
    let refusal = match judged.disabled {
        Some(limit) => Some(Refusal::Disabled(limit)),
        None if budget.paused(&settings) => Some(Refusal::Paused { consecutive: budget.consecutive }),
        None => None,
    };
    if let Some(refusal) = refusal {
        if budget != loaded {
            store.save_budget(&budget)?;
        }
        return Ok(UnlockAttemptOutcome { verdict: Verdict::Refused(refusal), judged });
    }
    // Whatever could be a PIN is checked as one, the password included: a PIN may be as long as
    // a passphrase, so length says nothing about which of the two was typed.
    let pin = input_that_could_be_a_pin(typed).ok_or(Verdict::Unusable);
    // Every input is a failure until it unlocks, and an input about to be checked is also one more
    // consecutive failure, both saved before the hash is checked, and taken back on a match. An
    // attempt abandoned halfway (Plasma 6.8 cancels authenticators it switches away from) still
    // counts. A correct password forgives it moments later, through
    // [`housekeeping_after_password_unlock`].
    budget.record_failure(now);
    if pin.is_ok() {
        budget.consecutive = budget.consecutive.saturating_add(1);
    }
    store.save_budget(&budget)?;
    let pin = match pin {
        Ok(pin) => pin,
        Err(verdict) => return Ok(UnlockAttemptOutcome { verdict, judged }),
    };
    if !hasher.verify(pin, &settings.pin_hash)? {
        return Ok(UnlockAttemptOutcome {
            verdict: Verdict::WrongPin { consecutive: budget.consecutive, max: settings.max_failures },
            judged,
        });
    }
    budget.consecutive = 0;
    budget.forgive(now, settings.forgive_before_correct_pin);
    store.save_budget(&budget)?;
    Ok(UnlockAttemptOutcome { verdict: Verdict::Unlock, judged })
}

/// After a password unlock: forgive the recent failures as the user's own (the password itself
/// among them, when it was short enough to be checked as a PIN), and start the consecutive count
/// over, which unpauses the PIN. A disabled PIN stays disabled; `judged.disabled` says so.
pub fn housekeeping_after_password_unlock(store: &impl Store, clock: &impl Clock) -> Result<Judged, Error> {
    let settings = store.settings()?;
    let _lock = store.lock()?;
    let now = clock.now()?;
    let mut budget = store.load_budget()?;
    let judged = budget.judge(now, &settings);
    budget.forgive(now, settings.forgive_before_correct_password);
    budget.consecutive = 0;
    store.save_budget(&budget)?;
    Ok(judged)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use proptest::prelude::*;

    use super::*;

    const PIN: &str = "4859";

    struct MemoryStore {
        settings: Settings,
        budget: RefCell<Budget>,
        saves: Cell<usize>,
    }

    impl MemoryStore {
        fn with_pin() -> Self {
            let settings = Settings { pin_hash: format!("plain:{PIN}"), ..Settings::default() };
            Self { settings, budget: RefCell::default(), saves: Cell::new(0) }
        }

        fn pending(&self) -> usize {
            self.budget.borrow().pending.len()
        }

        fn consecutive(&self) -> u32 {
            self.budget.borrow().consecutive
        }
    }

    impl Store for MemoryStore {
        type Lock = ();
        fn settings(&self) -> Result<Settings, Error> {
            Ok(self.settings.clone())
        }
        fn lock(&self) -> Result<(), Error> {
            Ok(())
        }
        fn load_budget(&self) -> Result<Budget, Error> {
            Ok(self.budget.borrow().clone())
        }
        fn save_budget(&self, budget: &Budget) -> Result<(), Error> {
            *self.budget.borrow_mut() = budget.clone();
            self.saves.set(self.saves.get() + 1);
            Ok(())
        }
    }

    struct FakeClock(Cell<u64>);

    impl FakeClock {
        fn new() -> Self {
            Self(Cell::new(1_800_000_000))
        }
        fn advance(&self, seconds: u64) {
            self.0.set(self.0.get() + seconds);
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Result<u64, Error> {
            Ok(self.0.get())
        }
    }

    /// "Hashes" are `plain:<pin>`, so tests stay instant.
    struct PlainHasher;

    impl Hasher for PlainHasher {
        fn verify(&self, pin: &str, hash: &str) -> Result<bool, Error> {
            Ok(hash.strip_prefix("plain:") == Some(pin))
        }
    }

    struct BrokenHasher;

    impl Hasher for BrokenHasher {
        fn verify(&self, _: &str, _: &str) -> Result<bool, Error> {
            Err(Error::System("libxcrypt is gone".into()))
        }
    }

    fn try_pin(store: &MemoryStore, clock: &FakeClock, typed: &str) -> Verdict {
        try_unlock_with_pin(store, &PlainHasher, clock, typed.as_bytes()).unwrap().verdict
    }

    fn enabled() -> (MemoryStore, FakeClock) {
        (MemoryStore::with_pin(), FakeClock::new())
    }

    #[test]
    fn the_pin_works_from_the_start_without_a_password_unlock() {
        let (store, clock) = enabled();
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
    }

    #[test]
    fn unusable_input_is_never_consecutive_but_waits_in_the_budget() {
        let (store, clock) = enabled();
        for raw in [&b"48\x0059"[..], b"\xff\xfe", &[b'1'; MAX_PIN_BYTES + 1]] {
            assert_eq!(try_unlock_with_pin(&store, &PlainHasher, &clock, raw).unwrap().verdict, Verdict::Unusable);
        }
        assert_eq!((store.consecutive(), store.pending()), (0, 3));
    }

    #[test]
    fn nothing_typed_and_no_pin_are_no_failures_at_all() {
        let (store, clock) = enabled();
        assert_eq!(try_pin(&store, &clock, ""), Verdict::Empty);
        let without = MemoryStore { settings: Settings::default(), ..MemoryStore::with_pin() };
        assert_eq!(try_pin(&without, &clock, PIN), Verdict::NoPinSet);
        assert_eq!((store.pending(), without.pending()), (0, 0));
    }

    #[test]
    fn long_input_is_checked_as_a_pin() {
        let (store, clock) = enabled();
        assert_eq!(try_pin(&store, &clock, "correct horse battery staple"), Verdict::WrongPin { consecutive: 1, max: 3 });
        // The longest PIN set allows, 64 characters of four bytes each, fills MAX_PIN_BYTES.
        let longest = "\u{10348}".repeat(crate::MAX_PIN_CHARS);
        assert_eq!(longest.len(), MAX_PIN_BYTES);
        assert_eq!(try_pin(&store, &clock, &longest), Verdict::WrongPin { consecutive: 2, max: 3 });
    }

    #[test]
    fn typos_before_a_correct_pin_or_password_are_forgiven() {
        let (store, clock) = enabled();
        try_pin(&store, &clock, "1111");
        clock.advance(30);
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
        assert_eq!(store.pending(), 0);
        // A mistyped password, then the right one: the attempt sees both, the password unlock forgives both.
        try_pin(&store, &clock, "correct horse battery stapl");
        clock.advance(60);
        try_pin(&store, &clock, "correct horse battery staple");
        housekeeping_after_password_unlock(&store, &clock).unwrap();
        assert_eq!(store.pending(), 0);
        clock.advance(3600);
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
        assert_eq!(store.budget.borrow().total, 0);
    }

    /// The password is checked as a PIN and counts as consecutive, until the password unlock that
    /// follows takes it back.
    #[test]
    fn the_password_costs_nothing_once_it_unlocks() {
        let (store, clock) = enabled();
        try_pin(&store, &clock, "1111");
        try_pin(&store, &clock, "2222");
        assert_eq!(try_pin(&store, &clock, "hunter2"), Verdict::WrongPin { consecutive: 3, max: 3 });
        housekeeping_after_password_unlock(&store, &clock).unwrap();
        assert_eq!((store.consecutive(), store.pending()), (0, 0));
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
    }

    /// The repeated-access attack: two guesses while the user is away, the user's own PIN much
    /// later, and again. The user's PIN never forgives the guesses, and the budget runs out.
    #[test]
    fn guesses_the_user_never_forgives_disable_the_pin() {
        let (store, clock) = enabled();
        let mut rounds = 0;
        while rounds < 20 && try_pin(&store, &clock, PIN) == Verdict::Unlock {
            rounds += 1;
            try_pin(&store, &clock, "1111");
            try_pin(&store, &clock, "2222");
            clock.advance(600);
        }
        // Five rounds of two guesses; the next correct PIN finds 10 concerning failures within 24 hours.
        assert_eq!(rounds, 5);
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::Disabled(crate::Limit::Day(10))));
        // The password doesn't bring it back.
        assert_eq!(housekeeping_after_password_unlock(&store, &clock).unwrap().disabled, Some(crate::Limit::Day(10)));
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::Disabled(crate::Limit::Day(10))));
        // Root turning it back on: the same PIN works again at once.
        let enabled = store.budget.borrow().enabled();
        *store.budget.borrow_mut() = enabled;
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
    }

    #[test]
    fn a_damaged_budget_refuses_and_the_password_changes_nothing() {
        struct Damaged(MemoryStore);
        impl Store for Damaged {
            type Lock = ();
            fn settings(&self) -> Result<Settings, Error> {
                self.0.settings()
            }
            fn lock(&self) -> Result<(), Error> {
                Ok(())
            }
            fn load_budget(&self) -> Result<Budget, Error> {
                Err(Error::System("damaged".into()))
            }
            fn save_budget(&self, _: &Budget) -> Result<(), Error> {
                panic!("a damaged budget must never be overwritten")
            }
        }
        let store = Damaged(MemoryStore::with_pin());
        let clock = FakeClock::new();
        assert!(housekeeping_after_password_unlock(&store, &clock).is_err());
        assert!(try_unlock_with_pin(&store, &PlainHasher, &clock, PIN.as_bytes()).is_err());
    }

    #[test]
    fn wrong_pins_count_up_to_the_limit_and_a_right_pin_resets() {
        let (store, clock) = enabled();
        assert_eq!(try_pin(&store, &clock, "1111"), Verdict::WrongPin { consecutive: 1, max: 3 });
        assert_eq!(try_pin(&store, &clock, "2222"), Verdict::WrongPin { consecutive: 2, max: 3 });
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
        assert_eq!(store.consecutive(), 0);
    }

    #[test]
    fn paused_even_the_right_pin_is_refused_until_the_password() {
        let (store, clock) = enabled();
        for wrong in ["1111", "2222", "3333"] {
            try_pin(&store, &clock, wrong);
        }
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::Paused { consecutive: 3 }));
        // A reboot changes nothing: the count is in the budget, on disk. Only the password helps.
        clock.advance(7 * 24 * 3600);
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::Paused { consecutive: 3 }));
        housekeeping_after_password_unlock(&store, &clock).unwrap();
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
    }

    /// Paused or disabled, input isn't checked, so it isn't a guess: nothing is recorded, and
    /// someone typing at a paused PIN can't push it on to disabled.
    #[test]
    fn a_paused_or_disabled_pin_records_nothing() {
        let (store, clock) = enabled();
        for wrong in ["1111", "2222", "3333"] {
            try_pin(&store, &clock, wrong);
        }
        let before = store.budget.borrow().clone();
        for typed in ["4444", "correct horse battery staple", PIN] {
            assert!(matches!(try_pin(&store, &clock, typed), Verdict::Refused(Refusal::Paused { .. })));
        }
        assert_eq!(*store.budget.borrow(), before);

        let (store, clock) = enabled();
        store.budget.borrow_mut().disabled = Some(crate::Disabled { limit: crate::Limit::Day(10), at: clock.0.get() });
        for typed in ["4444", PIN] {
            assert!(matches!(try_pin(&store, &clock, typed), Verdict::Refused(Refusal::Disabled(_))));
        }
        assert_eq!((store.consecutive(), store.pending()), (0, 0));
    }

    /// A refused attempt writes nothing, unless judging changed the budget by itself: here, the
    /// three failures nobody forgave turn concerning once the forgiveness windows have passed.
    #[test]
    fn a_refused_attempt_saves_only_what_judging_changed() {
        let (store, clock) = enabled();
        for wrong in ["1111", "2222", "3333"] {
            try_pin(&store, &clock, wrong);
        }
        let saves = store.saves.get();
        try_pin(&store, &clock, PIN);
        assert_eq!(store.saves.get(), saves, "nothing changed, nothing written");
        clock.advance(store.settings.forgive_before_correct_pin.max(store.settings.forgive_before_correct_password) + 1);
        try_pin(&store, &clock, PIN);
        assert_eq!(store.saves.get(), saves + 1, "the failures turned concerning, and that is saved");
        assert_eq!((store.pending(), store.budget.borrow().total), (0, 3));
        try_pin(&store, &clock, PIN);
        assert_eq!(store.saves.get(), saves + 1);
    }

    #[test]
    fn a_failure_is_saved_before_the_hash_is_checked() {
        let (store, clock) = enabled();
        assert!(try_unlock_with_pin(&store, &BrokenHasher, &clock, PIN.as_bytes()).is_err());
        assert_eq!((store.consecutive(), store.pending()), (1, 1));
    }

    /// Checks like `PlainHasher`, and records the consecutive count the store holds at the moment
    /// it is asked: what would be on disk if the attempt were killed right there.
    struct WitnessHasher<'a> {
        store: &'a MemoryStore,
        seen: RefCell<Vec<u32>>,
    }

    impl Hasher for WitnessHasher<'_> {
        fn verify(&self, pin: &str, hash: &str) -> Result<bool, Error> {
            self.seen.borrow_mut().push(self.store.consecutive());
            PlainHasher.verify(pin, hash)
        }
    }

    /// No attempt is ever checked before it is counted, right or wrong: an attempt killed while
    /// the hash is checked (Plasma 6.8 kills its PAM worker on cancel) still counts.
    #[test]
    fn every_check_happens_with_its_attempt_already_counted() {
        let (store, clock) = enabled();
        let hasher = WitnessHasher { store: &store, seen: RefCell::default() };
        for typed in ["1111", "2222", PIN, "3333"] {
            try_unlock_with_pin(&store, &hasher, &clock, typed.as_bytes()).unwrap();
        }
        // Two wrong, then the right PIN seen as the third attempt and taken back, then one wrong.
        assert_eq!(*hasher.seen.borrow(), [1, 2, 3, 1]);
        assert_eq!(store.consecutive(), 1);
    }

    #[test]
    fn log_lines_say_what_happened() {
        assert_eq!(
            Verdict::WrongPin { consecutive: 3, max: 3 }.to_string(),
            "not the PIN, consecutive failure 3 of 3; PIN paused, password required"
        );
        assert_eq!(
            Verdict::Refused(Refusal::Paused { consecutive: 3 }).to_string(),
            "PIN paused after 3 consecutive failures, password required"
        );
        assert_eq!(
            Verdict::Refused(Refusal::Disabled(crate::Limit::Day(10))).to_string(),
            "PIN disabled after 10 concerning failures within 24 hours, password required"
        );
    }

    #[derive(Debug, Clone)]
    enum Event {
        PasswordUnlock,
        RightPin,
        WrongPin,
        Wait(u64),
    }

    fn event() -> impl Strategy<Value = Event> {
        prop_oneof![Just(Event::PasswordUnlock), Just(Event::RightPin), Just(Event::WrongPin), (0..4 * 3600u64).prop_map(Event::Wait),]
    }

    proptest! {
        /// A tiny model of the rules, run against the real `try_unlock_with_pin` and
        /// `housekeeping_after_password_unlock`: the right PIN unlocks exactly when the model says
        /// the PIN isn't paused, and a wrong PIN never does.
        #[test]
        fn the_pin_unlocks_exactly_when_the_model_says_so(events in prop::collection::vec(event(), 0..60)) {
            // The budget is tested on its own; here its limits are out of reach.
            let mut store = MemoryStore::with_pin();
            store.settings = Settings { max_concerning_24h: 100, max_concerning_7d: 200, max_concerning_total: 100_000, ..store.settings };
            let clock = FakeClock::new();
            let limit = store.settings.max_failures;
            let mut consecutive = 0;
            for event in events {
                let allowed = consecutive < limit;
                match event {
                    Event::PasswordUnlock => {
                        housekeeping_after_password_unlock(&store, &clock).unwrap();
                        consecutive = 0;
                    }
                    Event::RightPin => {
                        prop_assert_eq!(try_pin(&store, &clock, PIN).unlocks(), allowed);
                        if allowed { consecutive = 0 }
                    }
                    Event::WrongPin => {
                        prop_assert!(!try_pin(&store, &clock, "0000").unlocks());
                        if allowed { consecutive += 1 }
                    }
                    Event::Wait(seconds) => clock.advance(seconds),
                }
            }
        }
    }
}
