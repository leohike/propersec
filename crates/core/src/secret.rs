use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// What someone typed: a PIN, or a password the module only looks at. Wiped from memory when it
/// is dropped, and impossible to print or clone, so it can't end up in a log or linger in a copy.
///
/// Wiping is best effort. It covers this buffer; it can't reach copies made before the bytes got
/// here (libpam's, the lock screen's, the kernel's), and the buffer must not grow once it holds
/// secret bytes, because growing leaves the old allocation behind unwiped. Build it with
/// [`Secret::new`] from a `Vec` that already has its final length.
///
/// ```compile_fail,E0277
/// let secret = properpin_core::Secret::new(b"4859".to_vec());
/// println!("{secret}"); // no Display
/// ```
///
/// ```compile_fail,E0599
/// let secret = properpin_core::Secret::new(b"4859".to_vec());
/// let copy = secret.clone(); // no Clone
/// ```
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Takes ownership of `bytes`, so they are never copied on the way in.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Wipes now rather than at drop. Dropping does the same.
impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// `Secret(4 bytes)`: the length only, never the contents.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_bytes_until_wiped() {
        let mut secret = Secret::new(b"4859".to_vec());
        assert_eq!(secret.as_bytes(), b"4859");
        secret.zeroize();
        assert!(secret.as_bytes().is_empty());
    }

    #[test]
    fn debug_shows_the_length_only() {
        let secret = Secret::new(b"4859".to_vec());
        assert_eq!(format!("{secret:?}"), "Secret(4 bytes)");
        assert_eq!(format!("{:?}", Some(&secret)), "Some(Secret(4 bytes))");
    }
}
