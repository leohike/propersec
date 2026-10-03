use std::fmt;

use zeroize::Zeroizing;

/// Bytes in a pepper, and in `pepper_decryption_key`, which encrypts it.
pub const PEPPER_BYTES: usize = 32;

/// The `clear_text_pepper` of `docs/pepper-terminology.md`: 32 random bytes mixed into the PIN
/// hash, so the hash alone can't be brute-forced the way a hash of a few digits can. It lives in
/// clear text in memory only, in the per-boot state while the PIN is armed; on disk it is only ever
/// `encrypted_pepper`, under a key derived from the password.
///
/// Wiped when dropped, and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Pepper(Zeroizing<[u8; PEPPER_BYTES]>);

impl Pepper {
    pub fn new(bytes: Zeroizing<[u8; PEPPER_BYTES]>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PEPPER_BYTES] {
        &self.0
    }

    /// Exactly 64 lowercase hex digits, or `None`.
    pub fn from_hex(text: &str) -> Option<Self> {
        Some(Self(Zeroizing::new(from_hex(text)?)))
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::with_capacity(2 * PEPPER_BYTES));
        text.extend(self.0.iter().flat_map(|byte| hex_digits(*byte)));
        text
    }

    /// Each byte XORed with `pepper_decryption_key`'s. Encrypting and decrypting are this same step: a one-time pad,
    /// safe as long as no `pepper_decryption_key` is ever used twice, which a fresh salt at every `set` ensures. Nothing
    /// checks the result, on purpose: a wrong `pepper_decryption_key` gives random-looking bytes, never "wrong key",
    /// so the stored files give a password guesser nothing to test a guess against.
    pub fn xor(&self, pepper_decryption_key: &[u8; PEPPER_BYTES]) -> Self {
        let mut out = Zeroizing::new([0u8; PEPPER_BYTES]);
        for (out, (byte, key_byte)) in out.iter_mut().zip(self.0.iter().zip(pepper_decryption_key)) {
            *out = byte ^ key_byte;
        }
        Self(out)
    }

    /// What gets hashed: the pepper's 64 hex digits, then the PIN. The pepper's fixed length keeps
    /// the two apart, so no other pepper and PIN make the same text.
    pub fn peppered(&self, pin: &str) -> Zeroizing<String> {
        // Sized up front: a String that grows leaves its old allocation behind, unwiped.
        let mut text = Zeroizing::new(String::with_capacity(2 * PEPPER_BYTES + pin.len()));
        text.push_str(&self.to_hex());
        text.push_str(pin);
        text
    }
}

/// `Pepper(..)`: never the bytes.
impl fmt::Debug for Pepper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pepper(..)")
    }
}

/// 64 lowercase hex digits as 32 bytes, or `None`.
fn from_hex(text: &str) -> Option<[u8; PEPPER_BYTES]> {
    let digits = text.as_bytes();
    if digits.len() != 2 * PEPPER_BYTES {
        return None;
    }
    let value = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    let mut bytes = [0u8; PEPPER_BYTES];
    for (byte, [high, low]) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
        *byte = value(*high)? << 4 | value(*low)?;
    }
    Some(bytes)
}

pub fn to_hex(bytes: &[u8; PEPPER_BYTES]) -> String {
    bytes.iter().flat_map(|byte| hex_digits(*byte)).collect()
}

/// The two lowercase hex digits of `byte`, the inverse of `from_hex`'s `value`.
fn hex_digits(byte: u8) -> [char; 2] {
    let digit = |nibble: u8| char::from(if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 });
    [digit(byte >> 4), digit(byte & 15)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pepper(byte: u8) -> Pepper {
        Pepper::new(Zeroizing::new([byte; PEPPER_BYTES]))
    }

    #[test]
    fn hex_round_trips() {
        let pepper = Pepper::new(Zeroizing::new(std::array::from_fn(|index| u8::try_from(index * 8).unwrap())));
        assert_eq!(&pepper.to_hex()[..8], "00081018");
        assert_eq!(Pepper::from_hex(&pepper.to_hex()), Some(pepper));
    }

    #[test]
    fn anything_but_64_lowercase_hex_digits_is_refused() {
        let good = "ab".repeat(PEPPER_BYTES);
        assert!(Pepper::from_hex(&good).is_some());
        for bad in [
            String::new(),
            "ab".repeat(PEPPER_BYTES - 1),
            "ab".repeat(PEPPER_BYTES) + "a",
            "AB".repeat(PEPPER_BYTES),
            "zz".repeat(PEPPER_BYTES),
            "+1".repeat(PEPPER_BYTES),
        ] {
            assert_eq!(Pepper::from_hex(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn xor_twice_gives_the_pepper_back_and_another_key_gives_garbage() {
        let (clear, key, other) = (pepper(0x5a), [0x0f; PEPPER_BYTES], [0xf0; PEPPER_BYTES]);
        let encrypted = clear.xor(&key);
        assert_ne!(encrypted, clear);
        assert_eq!(encrypted.xor(&key), clear);
        assert_ne!(encrypted.xor(&other), clear);
    }

    #[test]
    fn the_pin_follows_the_pepper() {
        assert_eq!(*pepper(0xab).peppered("4859"), "ab".repeat(PEPPER_BYTES) + "4859");
    }

    #[test]
    fn debug_never_shows_the_bytes() {
        assert_eq!(format!("{:?}", pepper(0xab)), "Pepper(..)");
    }
}
