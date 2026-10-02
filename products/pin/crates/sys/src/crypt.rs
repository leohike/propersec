use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};

use properpin_core::{Error, HASH_PREFIX, Hasher, MAX_PIN_BYTES};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

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
///
/// Every copy of the PIN made here is wiped: the NUL-terminated copy libxcrypt needs, and its 32 KB
/// work area, which holds the computed hash and yescrypt's working state.
#[derive(Debug, Clone, Copy, Default)]
pub struct Yescrypt;

impl Yescrypt {
    /// A fresh hash of `pin` at `cost`, salted from the kernel's random source.
    pub fn hash(&self, pin: &str, cost: u32) -> Result<String, Error> {
        let setting = make_setting(cost)?;
        // A new hash is about to be written to a file, so it leaves the wiped work area as a copy.
        with_hash(pin, &setting, |hash| String::from_utf8_lossy(hash).into_owned())
    }
}

impl Hasher for Yescrypt {
    /// Whether `pin` hashes to `stored`, compared in constant time.
    fn verify(&self, pin: &str, stored: &str) -> Result<bool, Error> {
        if !stored.starts_with(HASH_PREFIX) {
            return Err(Error::NotYescrypt);
        }
        let setting = CString::new(stored).map_err(|_| Error::NotYescrypt)?;
        // Compared where libxcrypt wrote it, so the hash of what was typed is never copied out.
        with_hash(pin, &setting, |hash| hash.ct_eq(stored.as_bytes()).into())
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

/// Hash `pin` with `setting` and hand the full hash string to `inspect`, while it still sits in
/// libxcrypt's work area. Both the work area and the NUL-terminated copy of `pin` are wiped when
/// this returns, on every path. libxcrypt's failures are errors, so a failure can never pass for a
/// hash.
#[allow(unsafe_code)]
fn with_hash<T>(pin: &str, setting: &CStr, inspect: impl FnOnce(&[u8]) -> T) -> Result<T, Error> {
    // A C string ends at the first NUL, so "1234\0junk" would hash as "1234". Refuse it outright.
    if pin.as_bytes().contains(&0) {
        return Err(Error::System("the PIN contains a NUL byte".into()));
    }
    if pin.len() > MAX_PIN_BYTES {
        return Err(Error::System(format!("the PIN is longer than {MAX_PIN_BYTES} bytes")));
    }
    // Sized up front: a Vec that grows leaves its old allocation behind, unwiped.
    let mut phrase = Zeroizing::new(Vec::with_capacity(pin.len() + 1));
    phrase.extend_from_slice(pin.as_bytes());
    phrase.push(0);
    let mut data = Zeroizing::new(vec![0u8; CRYPT_DATA_SIZE]);
    // SAFETY: `phrase` and `setting` are NUL-terminated, and `data` is a zeroed, writable
    // `struct crypt_data` of the size given. Only the address of the result is kept.
    let result = unsafe { ffi::crypt_rn(phrase.as_ptr().cast(), setting.as_ptr(), data.as_mut_ptr().cast(), CRYPT_DATA_SIZE as c_int) };
    // libxcrypt writes the hash into `data` and returns where it starts. Turn that address into an
    // ordinary slice of `data`, so the compiler guarantees `data` outlives it, and so an address
    // outside `data`, or a hash without its terminating NUL, is an error rather than a wild read.
    let hash = (result as usize)
        .checked_sub(data.as_ptr() as usize)
        .and_then(|start| data.get(start..))
        .and_then(|rest| rest.iter().position(|&byte| byte == 0).map(|end| &rest[..end]));
    // libxcrypt signals failure with null, or with a string starting with "*" in some modes.
    match hash {
        Some(hash) if !hash.is_empty() && !hash.starts_with(b"*") => Ok(inspect(hash)),
        _ => Err(Error::System("libxcrypt could not hash the PIN".into())),
    }
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
