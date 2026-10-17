use nix::time::{ClockId, clock_gettime};
use properpin_core::{Clock, Error};

use crate::system;

/// The wall clock, `CLOCK_REALTIME`: the only clock that survives a reboot, which the budget must.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64, Error> {
        let now = clock_gettime(ClockId::CLOCK_REALTIME).map_err(|error| system("CLOCK_REALTIME", error))?;
        u64::try_from(now.tv_sec()).map_err(|error| system("CLOCK_REALTIME", error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_time_of_day() {
        assert!(SystemClock.now().unwrap() > 1_700_000_000);
    }
}
