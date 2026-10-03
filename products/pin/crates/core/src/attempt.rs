//! One unlock attempt, and arming after a password unlock. Refusal is the default: the only
//! [`Verdict::Unlock`] comes from a matching PIN while the PIN is armed and not disabled.
//!
//! The pepper the PIN is hashed with stays in the state only while the PIN is armed: any refusal
//! wipes it (expired, too many failures in a row, disabled), and only the password brings it back.

use std::fmt;

use crate::{Budget, Error, Judged, MAX_PIN_BYTES, Pepper, PinState, Refusal, Secret, Settings};

/// Where one user's settings and state live, and the rules for trusting them.
pub trait Store {
    /// Held for one read-decide-write cycle of the state; released when dropped.
    type Lock;
    /// The defaults, then the global config, then the user's own file with the hash.
    fn settings(&self) -> Result<Settings, Error>;
    /// An exclusive lock, so two attempts can't interleave. Also where the runtime directory is
    /// checked: no lock, no state.
    fn lock(&self) -> Result<Self::Lock, Error>;
    /// The saved state, or `None` when there is none or it can't be trusted.
    fn load_state(&self) -> Option<PinState>;
    /// Replace the state atomically: a reader sees the old state or the new, never half.
    fn save_state(&self, state: &PinState) -> Result<(), Error>;
    /// The failures that outlive a boot: an empty budget when there is none yet, an error when it
    /// can't be trusted, since reading a damaged budget as empty would hand out a fresh one.
    fn load_budget(&self) -> Result<Budget, Error>;
    /// Replace the budget atomically, and durably: it must survive a power cut.
    fn save_budget(&self, budget: &Budget) -> Result<(), Error>;
}

/// This boot, the time within it, and the time of day.
pub trait Clock {
    fn boot_id(&self) -> Result<String, Error>;
    /// Seconds since boot, suspend included. Changing the wall clock doesn't move it.
    fn now(&self) -> Result<u64, Error>;
    /// Seconds since 1970: the only clock that survives a reboot, so the budget uses it.
    fn wall(&self) -> Result<u64, Error>;
}

/// Checks a typed PIN, already peppered, against the stored hash.
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
    /// The PIN matched while armed. The only outcome that unlocks.
    Unlock,
    /// Nothing was typed. Not a failure of any kind.
    Empty,
    /// No PIN is set for this user. Not a failure of any kind.
    NoPinSet,
    /// Input that can never be a PIN (see [`usable_input`]). Not counted in a row.
    Unusable,
    /// Longer than any PIN may be: almost always the password. Not hashed, not counted in a row.
    TooLong { max: usize },
    /// The PIN isn't armed, or is disabled; the input wasn't even checked.
    Refused(Refusal),
    /// Checked, and not the PIN. Counted in a row.
    WrongPin { failures: u32, max: u32 },
}

/// What [`check`] came to. Every outcome but `Unlock`, `Empty` and `NoPinSet` is also a failure in
/// the budget, waiting to be forgiven; `judged` says what the budget looked like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
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
            Self::Unusable => write!(f, "input that can't be a PIN, refused; not counted in a row"),
            Self::TooLong { max } => write!(f, "longer than {max} characters, so not the PIN; not counted in a row"),
            Self::Refused(refusal) => write!(f, "PIN refused, password required: {refusal}"),
            Self::WrongPin { failures, max } => {
                write!(f, "not the PIN, failure {failures} of {max}")?;
                if failures >= max {
                    write!(f, ", password required from now on")?;
                }
                Ok(())
            }
        }
    }
}

/// What the user typed, or `None` when it can't possibly be a PIN: empty, longer than
/// [`MAX_PIN_BYTES`], holding a NUL, or not UTF-8. Such input never counts in a row.
pub fn usable_input(raw: &[u8]) -> Option<&str> {
    if raw.is_empty() || raw.len() > MAX_PIN_BYTES || raw.contains(&0) {
        return None;
    }
    std::str::from_utf8(raw).ok()
}

/// One unlock attempt with `typed`, everything the lock screen passed on.
///
/// An `Err` means something is broken (a file, the clock, libxcrypt); the caller treats it like
/// any other refusal, so the password is checked next.
pub fn check(store: &impl Store, hasher: &impl Hasher, clock: &impl Clock, typed: &[u8]) -> Result<CheckOutcome, Error> {
    let plain = |verdict| Ok(CheckOutcome { verdict, judged: Judged::default() });
    if typed.is_empty() {
        return plain(Verdict::Empty);
    }
    let settings = store.settings()?;
    if settings.pin_hash.is_empty() {
        return plain(Verdict::NoPinSet);
    }
    let _lock = store.lock()?;
    let wall = clock.wall()?;
    let mut budget = store.load_budget()?;
    let judged = budget.judge(wall, &settings);
    // Every input is a failure until it unlocks, recorded before anything is decided, like the
    // failures in a row below. A correct password forgives it moments later, through `arm`.
    budget.record_failure(wall);
    store.save_budget(&budget)?;
    let verdict = match (judged.disabled, usable_input(typed)) {
        (Some(limit), _) => {
            forget_pepper(store, store.load_state())?;
            Verdict::Refused(Refusal::Disabled(limit))
        }
        (None, None) => Verdict::Unusable,
        (None, Some(pin)) if pin.chars().count() > settings.max_pin_length => Verdict::TooLong { max: settings.max_pin_length },
        (None, Some(pin)) => in_a_row(store, hasher, clock, &settings, pin)?,
    };
    if verdict.unlocks() {
        budget.forgive(wall, settings.forgive_before_correct_pin);
        store.save_budget(&budget)?;
    }
    Ok(CheckOutcome { verdict, judged })
}

/// The armed PIN against the failures in a row, then the peppered hash.
fn in_a_row(store: &impl Store, hasher: &impl Hasher, clock: &impl Clock, settings: &Settings, pin: &str) -> Result<Verdict, Error> {
    let state = store.load_state();
    if let Some(refusal) = settings.refusal(state.as_ref(), &clock.boot_id()?, clock.now()?) {
        forget_pepper(store, state)?;
        return Ok(Verdict::Refused(refusal));
    }
    // refusal() refuses a missing state or pepper, so neither is missing here.
    let Some(mut state) = state else { return Ok(Verdict::Refused(Refusal::NotArmed)) };
    let Some(pepper) = state.pepper.clone() else { return Ok(Verdict::Refused(Refusal::NoPepper)) };
    // Count the failure before checking, and take it back on a match. An attempt abandoned
    // halfway (Plasma 6.8 cancels authenticators it switches away from) then still counts.
    state.failures = state.failures.saturating_add(1);
    store.save_state(&state)?;
    if !hasher.verify(&pepper.peppered(pin), &settings.pin_hash)? {
        let failures = state.failures;
        if failures >= settings.max_failures {
            forget_pepper(store, Some(state))?;
        }
        return Ok(Verdict::WrongPin { failures, max: settings.max_failures });
    }
    state.failures = 0;
    store.save_state(&state)?;
    Ok(Verdict::Unlock)
}

/// Wipe the pepper from `state`, if it still holds one. The rest of the state stays, so the next
/// attempt is refused for the same reason, and the password must arm the PIN again.
fn forget_pepper(store: &impl Store, state: Option<PinState>) -> Result<(), Error> {
    match state {
        Some(state) if state.pepper.is_some() => store.save_state(&PinState { pepper: None, ..state }),
        _ => Ok(()),
    }
}

/// After a password unlock: forgive the recent failures as the user's own, and arm the PIN from
/// now, with nothing failed yet and the `pepper` the password decrypted, unless it is disabled.
/// `judged.disabled` says which; a disabled PIN's pepper is wiped.
pub fn arm(store: &impl Store, clock: &impl Clock, pepper: Pepper) -> Result<Judged, Error> {
    let settings = store.settings()?;
    let _lock = store.lock()?;
    let wall = clock.wall()?;
    let mut budget = store.load_budget()?;
    let judged = budget.judge(wall, &settings);
    budget.forgive(wall, settings.forgive_before_correct_password);
    store.save_budget(&budget)?;
    match judged.disabled {
        None => store.save_state(&PinState::armed(&clock.boot_id()?, clock.now()?, pepper))?,
        Some(_) => forget_pepper(store, store.load_state())?,
    }
    Ok(judged)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use proptest::prelude::*;

    use super::*;

    const PIN: &str = "4859";

    /// The pepper every test PIN is set with.
    fn pepper() -> Pepper {
        Pepper::new(zeroize::Zeroizing::new([0xab; crate::PEPPER_BYTES]))
    }

    struct MemoryStore {
        settings: Settings,
        state: RefCell<Option<PinState>>,
        budget: RefCell<Budget>,
        saves: Cell<usize>,
    }

    impl MemoryStore {
        fn with_pin() -> Self {
            let settings = Settings { pin_hash: format!("plain:{}", *pepper().peppered(PIN)), ..Settings::default() };
            Self { settings, state: RefCell::new(None), budget: RefCell::default(), saves: Cell::new(0) }
        }

        fn pending(&self) -> usize {
            self.budget.borrow().pending.len()
        }

        fn failures(&self) -> Option<u32> {
            self.state.borrow().as_ref().map(|state| state.failures)
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
        fn load_state(&self) -> Option<PinState> {
            self.state.borrow().clone()
        }
        fn save_state(&self, state: &PinState) -> Result<(), Error> {
            self.saves.set(self.saves.get() + 1);
            *self.state.borrow_mut() = Some(state.clone());
            Ok(())
        }
        fn load_budget(&self) -> Result<Budget, Error> {
            Ok(self.budget.borrow().clone())
        }
        fn save_budget(&self, budget: &Budget) -> Result<(), Error> {
            *self.budget.borrow_mut() = budget.clone();
            Ok(())
        }
    }

    /// Boot time and wall time move together, except across a reboot.
    struct FakeClock {
        boot_id: RefCell<String>,
        now: Cell<u64>,
        wall: Cell<u64>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self { boot_id: RefCell::new("boot-1".into()), now: Cell::new(1000), wall: Cell::new(1_800_000_000) }
        }
        fn advance(&self, seconds: u64) {
            self.now.set(self.now.get() + seconds);
            self.wall.set(self.wall.get() + seconds);
        }
    }

    impl Clock for FakeClock {
        fn boot_id(&self) -> Result<String, Error> {
            Ok(self.boot_id.borrow().clone())
        }
        fn now(&self) -> Result<u64, Error> {
            Ok(self.now.get())
        }
        fn wall(&self) -> Result<u64, Error> {
            Ok(self.wall.get())
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
        check(store, &PlainHasher, clock, typed.as_bytes()).unwrap().verdict
    }

    fn armed() -> (MemoryStore, FakeClock) {
        let (store, clock) = (MemoryStore::with_pin(), FakeClock::new());
        arm(&store, &clock, pepper()).unwrap();
        (store, clock)
    }

    #[test]
    fn unusable_input_never_counts_in_a_row_but_waits_in_the_budget() {
        let (store, clock) = armed();
        for raw in [&b"48\x0059"[..], b"\xff\xfe", &[b'1'; MAX_PIN_BYTES + 1]] {
            assert_eq!(check(&store, &PlainHasher, &clock, raw).unwrap().verdict, Verdict::Unusable);
        }
        assert_eq!((store.failures(), store.pending()), (Some(0), 3));
    }

    #[test]
    fn nothing_typed_and_no_pin_are_no_failures_at_all() {
        let (store, clock) = armed();
        assert_eq!(try_pin(&store, &clock, ""), Verdict::Empty);
        let without = MemoryStore { settings: Settings::default(), ..MemoryStore::with_pin() };
        assert_eq!(try_pin(&without, &clock, PIN), Verdict::NoPinSet);
        assert_eq!((store.pending(), without.pending()), (0, 0));
    }

    #[test]
    fn longer_input_is_not_a_pin_and_not_counted_in_a_row() {
        let (store, clock) = armed();
        assert_eq!(try_pin(&store, &clock, "correct horse battery"), Verdict::TooLong { max: 12 });
        assert_eq!((store.failures(), store.pending()), (Some(0), 1));
    }

    #[test]
    fn typos_before_a_correct_pin_or_password_are_forgiven() {
        let (store, clock) = armed();
        try_pin(&store, &clock, "1111");
        clock.advance(30);
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
        assert_eq!(store.pending(), 0);
        // A mistyped password, then the right one: check sees both, arm forgives both.
        try_pin(&store, &clock, "correct horse battery stapl");
        clock.advance(60);
        try_pin(&store, &clock, "correct horse battery staple");
        arm(&store, &clock, pepper()).unwrap();
        assert_eq!(store.pending(), 0);
        clock.advance(3600);
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
        assert_eq!(store.budget.borrow().total, 0);
    }

    /// The repeated-access attack: two guesses while the user is away, the user's own PIN much
    /// later, and again. The user's PIN never forgives the guesses, and the budget runs out.
    #[test]
    fn guesses_the_user_never_forgives_disable_the_pin() {
        let (store, clock) = armed();
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
        // The password no longer arms it either, and a reboot changes nothing.
        assert_eq!(arm(&store, &clock, pepper()).unwrap().disabled, Some(crate::Limit::Day(10)));
        *clock.boot_id.borrow_mut() = "boot-2".into();
        arm(&store, &clock, pepper()).unwrap();
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::Disabled(crate::Limit::Day(10))));
        // Root turning it back on: the same PIN works again after the next password unlock.
        let enabled = store.budget.borrow().enabled();
        *store.budget.borrow_mut() = enabled;
        arm(&store, &clock, pepper()).unwrap();
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
    }

    #[test]
    fn a_damaged_budget_refuses_and_the_password_still_arms_nothing() {
        struct Damaged(MemoryStore);
        impl Store for Damaged {
            type Lock = ();
            fn settings(&self) -> Result<Settings, Error> {
                self.0.settings()
            }
            fn lock(&self) -> Result<(), Error> {
                Ok(())
            }
            fn load_state(&self) -> Option<PinState> {
                self.0.load_state()
            }
            fn save_state(&self, state: &PinState) -> Result<(), Error> {
                self.0.save_state(state)
            }
            fn load_budget(&self) -> Result<Budget, Error> {
                Err(Error::System("damaged".into()))
            }
            fn save_budget(&self, _: &Budget) -> Result<(), Error> {
                Ok(())
            }
        }
        let store = Damaged(MemoryStore::with_pin());
        let clock = FakeClock::new();
        assert!(arm(&store, &clock, pepper()).is_err());
        assert!(check(&store, &PlainHasher, &clock, PIN.as_bytes()).is_err());
        assert_eq!(store.0.failures(), None);
    }

    #[test]
    fn after_boot_the_password_is_required_first() {
        let (store, clock) = (MemoryStore::with_pin(), FakeClock::new());
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::NotArmed));
        arm(&store, &clock, pepper()).unwrap();
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
    }

    #[test]
    fn wrong_pins_count_up_to_the_limit_and_a_right_pin_resets() {
        let (store, clock) = armed();
        assert_eq!(try_pin(&store, &clock, "1111"), Verdict::WrongPin { failures: 1, max: 3 });
        assert_eq!(try_pin(&store, &clock, "2222"), Verdict::WrongPin { failures: 2, max: 3 });
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
        assert_eq!(store.failures(), Some(0));
    }

    #[test]
    fn at_the_limit_even_the_right_pin_is_refused_until_the_password() {
        let (store, clock) = armed();
        for wrong in ["1111", "2222", "3333"] {
            try_pin(&store, &clock, wrong);
        }
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::TooManyFailures { failures: 3 }));
        arm(&store, &clock, pepper()).unwrap();
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
    }

    #[test]
    fn the_pin_expires_and_does_not_outlive_its_boot() {
        let (store, clock) = armed();
        clock.advance(8 * 3600);
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::Expired { age: 8 * 3600 }));

        let (store, clock) = armed();
        *clock.boot_id.borrow_mut() = "boot-2".into();
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::OtherBoot));
    }

    fn pepper_in_memory(store: &MemoryStore) -> bool {
        store.state.borrow().as_ref().is_some_and(|state| state.pepper.is_some())
    }

    #[test]
    fn every_refusal_wipes_the_pepper_until_the_password() {
        // Expired.
        let (store, clock) = armed();
        clock.advance(8 * 3600);
        assert!(matches!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::Expired { .. })));
        assert!(!pepper_in_memory(&store));
        // Three failures in a row: wiped with the third, and the reason stays the same.
        let (store, clock) = armed();
        for wrong in ["1111", "2222"] {
            try_pin(&store, &clock, wrong);
            assert!(pepper_in_memory(&store));
        }
        try_pin(&store, &clock, "3333");
        assert!(!pepper_in_memory(&store));
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::TooManyFailures { failures: 3 }));
        arm(&store, &clock, pepper()).unwrap();
        assert!(pepper_in_memory(&store));
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
    }

    #[test]
    fn a_disabled_pin_loses_its_pepper_and_the_password_does_not_bring_it_back() {
        let (store, clock) = armed();
        store.budget.borrow_mut().disabled = Some(crate::Disabled { limit: crate::Limit::Day(10), at: clock.wall.get() });
        assert!(matches!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::Disabled(_))));
        assert!(!pepper_in_memory(&store));
        assert!(arm(&store, &clock, pepper()).unwrap().disabled.is_some());
        assert!(!pepper_in_memory(&store));
        // Root's enable: the same PIN, once the password has armed it again.
        let enabled = store.budget.borrow().enabled();
        *store.budget.borrow_mut() = enabled;
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::NoPepper));
        arm(&store, &clock, pepper()).unwrap();
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Unlock);
    }

    /// After a password change the new password decrypts the pepper to garbage. Nothing notices:
    /// the right PIN is simply wrong.
    #[test]
    fn the_wrong_pepper_makes_the_right_pin_wrong() {
        let (store, clock) = (MemoryStore::with_pin(), FakeClock::new());
        arm(&store, &clock, pepper().xor(&[1; crate::PEPPER_BYTES])).unwrap();
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::WrongPin { failures: 1, max: 3 });
    }

    #[test]
    fn a_failure_is_saved_before_the_hash_is_checked() {
        let (store, clock) = armed();
        assert!(check(&store, &BrokenHasher, &clock, PIN.as_bytes()).is_err());
        assert_eq!((store.failures(), store.pending()), (Some(1), 1));
    }

    /// Checks like `PlainHasher`, and records the failure count the store holds at the moment it
    /// is asked: what would be on disk if the attempt were killed right there.
    struct WitnessHasher<'a> {
        store: &'a MemoryStore,
        seen: RefCell<Vec<Option<u32>>>,
    }

    impl Hasher for WitnessHasher<'_> {
        fn verify(&self, pin: &str, hash: &str) -> Result<bool, Error> {
            self.seen.borrow_mut().push(self.store.failures());
            PlainHasher.verify(pin, hash)
        }
    }

    /// No attempt is ever checked before it is counted, right or wrong: an attempt killed while
    /// the hash is checked (Plasma 6.8 kills its PAM worker on cancel) still counts.
    #[test]
    fn every_check_happens_with_its_attempt_already_counted() {
        let (store, clock) = armed();
        let hasher = WitnessHasher { store: &store, seen: RefCell::default() };
        for typed in ["1111", "2222", PIN, "3333"] {
            check(&store, &hasher, &clock, typed.as_bytes()).unwrap();
        }
        // Two wrong, then the right PIN seen as the third attempt and taken back, then one wrong.
        assert_eq!(*hasher.seen.borrow(), [Some(1), Some(2), Some(3), Some(1)]);
        assert_eq!(store.failures(), Some(1));
    }

    #[test]
    fn log_lines_say_what_happened() {
        assert_eq!(Verdict::WrongPin { failures: 3, max: 3 }.to_string(), "not the PIN, failure 3 of 3, password required from now on");
        assert_eq!(
            Verdict::Refused(Refusal::Expired { age: 28860 }).to_string(),
            "PIN refused, password required: the last password unlock was 8h01m ago"
        );
    }

    #[derive(Debug, Clone)]
    enum Event {
        PasswordUnlock,
        RightPin,
        WrongPin,
        Wait(u64),
        Reboot,
    }

    fn event() -> impl Strategy<Value = Event> {
        prop_oneof![
            Just(Event::PasswordUnlock),
            Just(Event::RightPin),
            Just(Event::WrongPin),
            (0..4 * 3600u64).prop_map(Event::Wait),
            Just(Event::Reboot),
        ]
    }

    proptest! {
        /// A tiny model of the rules, run against the real `check` and `arm`: the right PIN unlocks
        /// exactly when the model says it's armed, and a wrong PIN never does.
        #[test]
        fn the_pin_unlocks_exactly_when_armed(events in prop::collection::vec(event(), 0..60)) {
            // The budget is tested on its own; here its limits are out of reach.
            let mut store = MemoryStore::with_pin();
            store.settings = Settings { max_concerning_24h: 100, max_concerning_7d: 200, max_concerning_total: 100_000, ..store.settings };
            let clock = FakeClock::new();
            let limit = store.settings.max_failures;
            let mut armed_at: Option<u64> = None;
            let mut failures = 0;
            let mut boots = 1;
            for event in events {
                let now = clock.now.get();
                let allowed = armed_at.is_some_and(|at| now - at < 8 * 3600) && failures < limit;
                match event {
                    Event::PasswordUnlock => {
                        arm(&store, &clock, pepper()).unwrap();
                        (armed_at, failures) = (Some(now), 0);
                    }
                    Event::RightPin => {
                        prop_assert_eq!(try_pin(&store, &clock, PIN).unlocks(), allowed);
                        if allowed { failures = 0 }
                    }
                    Event::WrongPin => {
                        prop_assert!(!try_pin(&store, &clock, "0000").unlocks());
                        if allowed { failures += 1 }
                    }
                    Event::Wait(seconds) => clock.advance(seconds),
                    Event::Reboot => {
                        boots += 1;
                        *clock.boot_id.borrow_mut() = format!("boot-{boots}");
                        armed_at = None;
                    }
                }
            }
        }
    }
}
