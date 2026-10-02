//! One unlock attempt, and arming after a password unlock. Refusal is the default: the only
//! [`Verdict::Unlock`] comes from a matching PIN while the PIN is armed.

use std::fmt;

use crate::{Error, MAX_PIN_BYTES, PinState, Refusal, Settings};

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
}

/// This boot, and the time within it.
pub trait Clock {
    fn boot_id(&self) -> Result<String, Error>;
    /// Seconds since boot, suspend included. Changing the wall clock doesn't move it.
    fn now(&self) -> Result<u64, Error>;
}

/// Checks a typed PIN against the stored hash.
pub trait Hasher {
    fn verify(&self, pin: &str, hash: &str) -> Result<bool, Error>;
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
    /// Empty or unusable input: it can never be a PIN, so it isn't counted.
    Unusable,
    /// No PIN is set for this user.
    NoPinSet,
    /// Longer than any PIN may be: almost always the password. Not hashed, not counted.
    TooLong { max: usize },
    /// The PIN isn't armed; the input wasn't even checked.
    Refused(Refusal),
    /// Checked, and not the PIN. Counted.
    WrongPin { failures: u32, max: u32 },
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
            Self::Unusable => write!(f, "empty or unusable input, refused without counting as a failure"),
            Self::NoPinSet => write!(f, "no PIN is set, refused"),
            Self::TooLong { max } => write!(f, "longer than {max} characters, so not the PIN; not counted as a failure"),
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
/// [`MAX_PIN_BYTES`], holding a NUL, or not UTF-8. Such input never counts as a failure.
pub fn usable_input(raw: &[u8]) -> Option<&str> {
    if raw.is_empty() || raw.len() > MAX_PIN_BYTES || raw.contains(&0) {
        return None;
    }
    std::str::from_utf8(raw).ok()
}

/// One unlock attempt with `typed` (see [`usable_input`]).
///
/// An `Err` means something is broken (a file, the clock, libxcrypt); the caller treats it like
/// any other refusal, so the password is checked next.
pub fn check(store: &impl Store, hasher: &impl Hasher, clock: &impl Clock, typed: Option<&str>) -> Result<Verdict, Error> {
    let Some(pin) = typed.filter(|typed| !typed.is_empty()) else { return Ok(Verdict::Unusable) };
    let settings = store.settings()?;
    if settings.pin_hash.is_empty() {
        return Ok(Verdict::NoPinSet);
    }
    if pin.chars().count() > settings.max_pin_length {
        return Ok(Verdict::TooLong { max: settings.max_pin_length });
    }
    let _lock = store.lock()?;
    let state = store.load_state();
    let mut state = match (settings.refusal(state.as_ref(), &clock.boot_id()?, clock.now()?), state) {
        (None, Some(state)) => state,
        (Some(refusal), _) => return Ok(Verdict::Refused(refusal)),
        (None, None) => return Ok(Verdict::Refused(Refusal::NotArmed)), // refusal() never allows this
    };
    // Count the failure before checking, and take it back on a match. An attempt abandoned
    // halfway (Plasma 6.8 cancels authenticators it switches away from) then still counts.
    state.failures = state.failures.saturating_add(1);
    store.save_state(&state)?;
    if !hasher.verify(pin, &settings.pin_hash)? {
        return Ok(Verdict::WrongPin { failures: state.failures, max: settings.max_failures });
    }
    state.failures = 0;
    store.save_state(&state)?;
    Ok(Verdict::Unlock)
}

/// After a password unlock: arm the PIN from now, with nothing failed yet.
pub fn arm(store: &impl Store, clock: &impl Clock) -> Result<(), Error> {
    let _lock = store.lock()?;
    store.save_state(&PinState::armed(&clock.boot_id()?, clock.now()?))
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use proptest::prelude::*;

    use super::*;

    const PIN: &str = "4859";

    struct MemoryStore {
        settings: Settings,
        state: RefCell<Option<PinState>>,
        saves: Cell<usize>,
    }

    impl MemoryStore {
        fn with_pin() -> Self {
            let settings = Settings { pin_hash: format!("plain:{PIN}"), ..Settings::default() };
            Self { settings, state: RefCell::new(None), saves: Cell::new(0) }
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
    }

    struct FakeClock {
        boot_id: RefCell<String>,
        now: Cell<u64>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self { boot_id: RefCell::new("boot-1".into()), now: Cell::new(1000) }
        }
        fn advance(&self, seconds: u64) {
            self.now.set(self.now.get() + seconds);
        }
    }

    impl Clock for FakeClock {
        fn boot_id(&self) -> Result<String, Error> {
            Ok(self.boot_id.borrow().clone())
        }
        fn now(&self) -> Result<u64, Error> {
            Ok(self.now.get())
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
        check(store, &PlainHasher, clock, usable_input(typed.as_bytes())).unwrap()
    }

    fn armed() -> (MemoryStore, FakeClock) {
        let (store, clock) = (MemoryStore::with_pin(), FakeClock::new());
        arm(&store, &clock).unwrap();
        (store, clock)
    }

    #[test]
    fn unusable_input_is_never_counted() {
        let (store, clock) = armed();
        for raw in [&b""[..], b"48\x0059", b"\xff\xfe", &[b'1'; MAX_PIN_BYTES + 1]] {
            assert_eq!(check(&store, &PlainHasher, &clock, usable_input(raw)).unwrap(), Verdict::Unusable);
        }
        assert_eq!(store.failures(), Some(0));
    }

    #[test]
    fn without_a_hash_nothing_is_checked() {
        let store = MemoryStore { settings: Settings::default(), ..MemoryStore::with_pin() };
        assert_eq!(try_pin(&store, &FakeClock::new(), PIN), Verdict::NoPinSet);
    }

    #[test]
    fn longer_input_is_not_a_pin_and_not_counted() {
        let (store, clock) = armed();
        assert_eq!(try_pin(&store, &clock, "correct horse battery"), Verdict::TooLong { max: 12 });
        assert_eq!(store.failures(), Some(0));
    }

    #[test]
    fn after_boot_the_password_is_required_first() {
        let (store, clock) = (MemoryStore::with_pin(), FakeClock::new());
        assert_eq!(try_pin(&store, &clock, PIN), Verdict::Refused(Refusal::NotArmed));
        arm(&store, &clock).unwrap();
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
        arm(&store, &clock).unwrap();
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

    #[test]
    fn a_failure_is_saved_before_the_hash_is_checked() {
        let (store, clock) = armed();
        assert!(check(&store, &BrokenHasher, &clock, Some(PIN)).is_err());
        assert_eq!(store.failures(), Some(1));
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
            check(&store, &hasher, &clock, Some(typed)).unwrap();
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
            let (store, clock) = (MemoryStore::with_pin(), FakeClock::new());
            let limit = store.settings.max_failures;
            let mut armed_at: Option<u64> = None;
            let mut failures = 0;
            let mut boots = 1;
            for event in events {
                let now = clock.now.get();
                let allowed = armed_at.is_some_and(|at| now - at < 8 * 3600) && failures < limit;
                match event {
                    Event::PasswordUnlock => {
                        arm(&store, &clock).unwrap();
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
