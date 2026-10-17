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

/// `at`, seconds since 1970, as this machine's local time with its zone and offset, such as
/// `2026-10-17 21:56:03 CEST (+0200)`. The zone is glibc's: `TZ` if set, else `/etc/localtime`.
/// The pinchecker clears its environment first, so there it is always `/etc/localtime`, which only
/// root can change. A time glibc can't convert comes back as the bare number.
#[allow(unsafe_code)]
pub fn local_time(at: u64) -> String {
    use nix::libc;
    let bare = || format!("{at} seconds since 1970");
    let Ok(seconds) = libc::time_t::try_from(at) else { return bare() };
    // SAFETY: `tm` is plain integers and a pointer, for which all zeroes is a valid value, and
    // localtime_r writes only into it, given a valid pointer to a time_t.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call, and localtime_r keeps neither.
    if unsafe { libc::localtime_r(&seconds, &mut tm) }.is_null() {
        return bare();
    }
    let mut out = [0u8; 64];
    // SAFETY: the format is NUL-terminated, `out` is writable for the length given, and `tm` was
    // filled in by localtime_r. strftime writes at most that many bytes, the NUL included, and
    // returns how many it wrote before the NUL, or 0 if they didn't fit.
    let written = unsafe { libc::strftime(out.as_mut_ptr().cast(), out.len(), c"%Y-%m-%d %H:%M:%S %Z (%z)".as_ptr(), &tm) };
    match out.get(..written) {
        Some(text) if written > 0 => String::from_utf8_lossy(text).into_owned(),
        _ => bare(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The zone depends on the machine running the tests, so only the shape is checked.
    #[test]
    fn local_time_has_the_date_the_time_and_the_zone() {
        let text = local_time(1_800_000_000);
        let (date, rest) = text.split_once(' ').unwrap();
        let (time, zone) = rest.split_once(' ').unwrap();
        assert!(date.len() == 10 && date.starts_with("2027-01-1"), "{text}");
        assert!(time.len() == 8 && time.bytes().filter(|&b| b == b':').count() == 2, "{text}");
        assert!(zone.ends_with(')') && (zone.contains(" (+") || zone.contains(" (-")), "{text}");
        assert_eq!(local_time(u64::MAX), format!("{} seconds since 1970", u64::MAX));
    }

    #[test]
    fn reads_the_time_of_day() {
        assert!(SystemClock.now().unwrap() > 1_700_000_000);
    }
}
