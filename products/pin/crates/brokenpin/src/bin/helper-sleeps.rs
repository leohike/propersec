//! Test-only: a `properpin-helper` that sleeps for ten hours, so every attempt waits for the
//! module's own timeout.

fn main() {
    std::thread::sleep(std::time::Duration::from_secs(10 * 3600));
}
