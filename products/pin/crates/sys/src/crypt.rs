use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};

use properpin_core::{Error, HASH_PREFIX, Hasher, MAX_PIN_BYTES};
use subtle::ConstantTimeEq;

/// `sizeof(struct crypt_data)` in libxcrypt.
const CRYPT_DATA_SIZE: usize = 32768;
/// `CRYPT_GENSALT_OUTPUT_SIZE` in libxcrypt.
const GENSALT_OUTPUT_SIZE: usize = 192;

/// yescrypt hashing through the system's libxcrypt. No crypto is implemented here: libxcrypt
/// hashes, this only compares.
///
/// A crypt(3) hash is one string, `$y$<cost>$<salt>$<hash>`, the format `/etc/shadow` uses.
/// Handed back to libxcrypt as the *setting*, it hashes new input with the same algorithm, cost and
/// salt, so the right PIN reproduces the stored string exactly.
#[derive(Debug, Clone, Copy, Default)]
pub struct Yescrypt;

impl Yescrypt {
    /// A fresh hash of `pin` at `cost`, salted from the kernel's random source.
    pub fn hash(&self, pin: &str, cost: u32) -> Result<String, Error> {
        let setting = make_setting(cost)?;
        compute_hash(pin, &setting)
    }
}

impl Hasher for Yescrypt {
    /// Whether `pin` hashes to `stored`, compared in constant time.
    fn verify(&self, pin: &str, stored: &str) -> Result<bool, Error> {
        if !stored.starts_with(HASH_PREFIX) {
            return Err(Error::NotYescrypt);
        }
        let setting = CString::new(stored).map_err(|_| Error::NotYescrypt)?;
        Ok(compute_hash(pin, &setting)?.as_bytes().ct_eq(stored.as_bytes()).into())
    }
}

#[allow(unsafe_code)]
mod ffi {
    use super::*;

    #[link(name = "crypt")]
    unsafe extern "C" {
        pub fn crypt_rn(phrase: *const c_char, setting: *const c_char, data: *mut c_void, size: c_int) -> *mut c_char;
        pub fn crypt_gensalt_rn(
            prefix: *const c_char,
            count: c_ulong,
            rbytes: *const c_char,
            nrbytes: c_int,
            output: *mut c_char,
            output_size: c_int,
        ) -> *mut c_char;
    }
}

/// `$y$<cost>$<salt>`, with a fresh random salt.
#[allow(unsafe_code)]
fn make_setting(cost: u32) -> Result<CString, Error> {
    let prefix = CString::new(HASH_PREFIX).expect("the prefix has no NUL");
    let mut output = vec![0u8; GENSALT_OUTPUT_SIZE];
    // SAFETY: every pointer is valid for the call: `prefix` is NUL-terminated, a null `rbytes` asks
    // libxcrypt for its own random bytes, and `output` is writable for the length given. The
    // result is null or points into `output`, which is still alive when it's read.
    let setting = unsafe {
        let result = ffi::crypt_gensalt_rn(
            prefix.as_ptr(),
            c_ulong::from(cost),
            std::ptr::null(),
            0,
            output.as_mut_ptr().cast(),
            GENSALT_OUTPUT_SIZE as c_int,
        );
        (!result.is_null()).then(|| CStr::from_ptr(result).to_owned())
    };
    setting.ok_or_else(|| Error::System(format!("libxcrypt could not make a yescrypt salt with cost {cost}")))
}

/// The full hash string of `pin` with `setting`. libxcrypt's failures are errors, so a failure can
/// never pass for a hash.
#[allow(unsafe_code)]
fn compute_hash(pin: &str, setting: &CStr) -> Result<String, Error> {
    // A C string ends at the first NUL, so "1234\0junk" would hash as "1234". Refuse it outright.
    let phrase = CString::new(pin).map_err(|_| Error::System("the PIN contains a NUL byte".into()))?;
    if pin.len() > MAX_PIN_BYTES {
        return Err(Error::System(format!("the PIN is longer than {MAX_PIN_BYTES} bytes")));
    }
    let mut data = vec![0u8; CRYPT_DATA_SIZE];
    // SAFETY: `phrase` and `setting` are NUL-terminated, and `data` is a zeroed, writable
    // `struct crypt_data` of the size given. The result is null or points into `data`, which is
    // still alive when it's copied out.
    let hash = unsafe {
        let result = ffi::crypt_rn(phrase.as_ptr(), setting.as_ptr(), data.as_mut_ptr().cast(), CRYPT_DATA_SIZE as c_int);
        (!result.is_null()).then(|| CStr::from_ptr(result).to_string_lossy().into_owned())
    };
    // libxcrypt signals failure with null, or with a string starting with "*" in some modes.
    hash.filter(|hash| !hash.starts_with('*')).ok_or_else(|| Error::System("libxcrypt could not hash the PIN".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_verifies() {
        let stored = Yescrypt.hash("4859", 5).unwrap();
        assert!(stored.starts_with("$y$j9T$"), "{stored}"); // j9T is cost 5
        assert!(Yescrypt.verify("4859", &stored).unwrap());
        assert!(!Yescrypt.verify("4860", &stored).unwrap());
        assert!(!Yescrypt.verify("48590", &stored).unwrap());
    }

    #[test]
    fn salts_are_fresh_and_cost_is_encoded() {
        assert_ne!(Yescrypt.hash("4859", 5).unwrap(), Yescrypt.hash("4859", 5).unwrap());
        assert!(Yescrypt.hash("4859", 4).unwrap().starts_with("$y$j8T$"));
    }

    #[test]
    fn a_nul_byte_never_truncates_the_input() {
        let stored = Yescrypt.hash("4859", 5).unwrap();
        assert!(Yescrypt.verify("4859\0junk", &stored).is_err());
    }

    #[test]
    fn refuses_hashes_that_are_not_yescrypt() {
        for stored in ["", "plain", "$6$salt$hash"] {
            assert!(matches!(Yescrypt.verify("4859", stored), Err(Error::NotYescrypt)), "{stored:?}");
        }
    }
}
