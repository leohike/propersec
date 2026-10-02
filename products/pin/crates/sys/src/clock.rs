use nix::time::{ClockId, clock_gettime};
use properpin_core::{Clock, Error};

use crate::system;

const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

/// This boot's id from the kernel, and `CLOCK_BOOTTIME`: seconds since boot, suspend included.
/// Changing the wall clock moves neither, so nobody at the keyboard can stretch the PIN's window.
#[derive(Debug, Clone, Copy, Default)]
pub struct BootClock;

impl Clock for BootClock {
    fn boot_id(&self) -> Result<String, Error> {
        let id = std::fs::read_to_string(BOOT_ID).map_err(|error| system(BOOT_ID, error))?;
        Ok(id.trim().into())
    }

    fn now(&self) -> Result<u64, Error> {
        let now = clock_gettime(ClockId::CLOCK_BOOTTIME).map_err(|error| system("CLOCK_BOOTTIME", error))?;
        u64::try_from(now.tv_sec()).map_err(|error| system("CLOCK_BOOTTIME", error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_this_boot() {
        assert_eq!(BootClock.boot_id().unwrap(), BootClock.boot_id().unwrap());
        assert_eq!(BootClock.boot_id().unwrap().len(), 36);
        assert!(BootClock.now().unwrap() > 0);
    }
}
