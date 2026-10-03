use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};
use std::io::Read;

use properpin_core::{
    CLEARTEXT_SALT_FOR_DERIVING_PEPPER_DECRYPTION_KEY_SETTING, ENCRYPTED_PEPPER_SETTING, Error, HASH_PREFIX, HASH_SETTING, Hasher,
    MAX_PHRASE_BYTES, PEPPER_BYTES, Pepper,
};
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
        with_hash(pin.as_bytes(), &setting, |hash| String::from_utf8_lossy(hash).into_owned())
    }

    /// Everything `set` writes for a new PIN: a fresh random pepper, the hash of the peppered PIN at
    /// `hash_cost`, and the pepper encrypted with a `pepper_decryption_key` derived from
    /// `password` at `seal_cost`, with a fresh salt, so no `pepper_decryption_key` is ever used
    /// twice. The caller must have checked the password:
    /// sealed with a mistyped one, the PIN could never be armed.
    pub fn new_pin(&self, pin: &str, password: &[u8], hash_cost: u32, seal_cost: u32) -> Result<NewPin, Error> {
        let pepper = random_pepper()?;
        let hash = self.hash(&pepper.peppered(pin), hash_cost)?;
        let cleartext_salt_for_deriving_pepper_decryption_key = make_setting(seal_cost)?;
        let pepper_decryption_key = derive_pepper_decryption_key(password, &cleartext_salt_for_deriving_pepper_decryption_key)?;
        let encrypted = pepper.xor(&pepper_decryption_key);
        let cleartext_salt_for_deriving_pepper_decryption_key = cleartext_salt_for_deriving_pepper_decryption_key
            .into_string()
            .map_err(|_| Error::System("libxcrypt made a salt that isn't text".into()))?;
        Ok(NewPin {
            hash,
            cleartext_salt_for_deriving_pepper_decryption_key,
            encrypted_pepper: properpin_core::pepper_hex(encrypted.as_bytes()),
            pepper,
        })
    }

    /// The pepper `encrypted_pepper` holds, decrypted with the `pepper_decryption_key` derived from
    /// `password` and
    /// `cleartext_salt_for_deriving_pepper_decryption_key`. A wrong password gives a wrong pepper, not an error: nothing here can tell.
    pub fn unseal(
        &self,
        cleartext_salt_for_deriving_pepper_decryption_key: &str,
        encrypted_pepper: &str,
        password: &[u8],
    ) -> Result<Pepper, Error> {
        let unusable = |what: &str| Error::System(format!("{what}; sudo properpin set makes a new PIN"));
        if cleartext_salt_for_deriving_pepper_decryption_key.is_empty() || encrypted_pepper.is_empty() {
            return Err(unusable("no encrypted pepper: the PIN was set before properpin had peppers"));
        }
        if !cleartext_salt_for_deriving_pepper_decryption_key.starts_with(HASH_PREFIX) {
            return Err(unusable("the cleartext salt for deriving the pepper decryption key is not a yescrypt setting"));
        }
        let encrypted = Pepper::from_hex(encrypted_pepper).ok_or_else(|| unusable("the encrypted pepper is not 64 hex digits"))?;
        let cleartext_salt_for_deriving_pepper_decryption_key = CString::new(cleartext_salt_for_deriving_pepper_decryption_key)
            .map_err(|_| unusable("the cleartext salt for deriving the pepper decryption key holds a NUL"))?;
        let pepper_decryption_key = derive_pepper_decryption_key(password, &cleartext_salt_for_deriving_pepper_decryption_key)?;
        Ok(encrypted.xor(&pepper_decryption_key))
    }
}

/// What `set` writes for a new PIN (see [`Yescrypt::new_pin`]), and the pepper it arms with.
#[derive(Debug)]
pub struct NewPin {
    /// `hash_of_peppered_pin`.
    pub hash: String,
    /// The yescrypt setting `pepper_decryption_key` is derived from the password with: a fresh salt,
    /// and `seal_cost`.
    pub cleartext_salt_for_deriving_pepper_decryption_key: String,
    /// The pepper XORed with `pepper_decryption_key`, as 64 hex digits.
    pub encrypted_pepper: String,
    /// The pepper in clear text, for memory only.
    pub pepper: Pepper,
}

impl NewPin {
    /// The settings to write to the user's file, in its order.
    pub fn pairs(&self) -> [(&'static str, &str); 3] {
        [
            (HASH_SETTING, &self.hash),
            (CLEARTEXT_SALT_FOR_DERIVING_PEPPER_DECRYPTION_KEY_SETTING, &self.cleartext_salt_for_deriving_pepper_decryption_key),
            (ENCRYPTED_PEPPER_SETTING, &self.encrypted_pepper),
        ]
    }

    /// The same as `key = value` lines, for tests that write a user's file by hand.
    pub fn lines(&self) -> String {
        self.pairs().iter().map(|(key, value)| format!("{key} = {value}\n")).collect()
    }
}

/// `pepper_decryption_key`: yescrypt of the password with `cleartext_salt_for_deriving_pepper_decryption_key`, its 43 characters of hash
/// decoded back into the 32 bytes they encode. Wiped when dropped.
fn derive_pepper_decryption_key(
    password: &[u8],
    cleartext_salt_for_deriving_pepper_decryption_key: &CStr,
) -> Result<Zeroizing<[u8; PEPPER_BYTES]>, Error> {
    let pepper_decryption_key = with_hash(password, cleartext_salt_for_deriving_pepper_decryption_key, |hash| {
        let encoded = hash.rsplit(|&byte| byte == b'$').next().unwrap_or_default();
        decode_hash(encoded)
    })?;
    pepper_decryption_key.ok_or_else(|| Error::System("libxcrypt's yescrypt hash is not 43 characters of crypt base64".into()))
}

/// The 32 bytes behind a yescrypt hash's 43 characters, in crypt's base64: `./0-9A-Za-z`, six bits
/// per character, least significant first. 43 characters carry 258 bits; the last two are zero.
fn decode_hash(encoded: &[u8]) -> Option<Zeroizing<[u8; PEPPER_BYTES]>> {
    const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if encoded.len() != 43 {
        return None;
    }
    let mut pepper_decryption_key = Zeroizing::new([0u8; PEPPER_BYTES]);
    let (mut bits, mut count, mut out) = (0u32, 0, 0);
    for character in encoded {
        bits |= (ALPHABET.iter().position(|letter| letter == character)? as u32) << count;
        count += 6;
        while count >= 8 && out < PEPPER_BYTES {
            pepper_decryption_key[out] = bits as u8;
            (bits, count, out) = (bits >> 8, count - 8, out + 1);
        }
    }
    (out == PEPPER_BYTES && bits == 0).then_some(pepper_decryption_key)
}

/// 32 bytes from the kernel's random source.
fn random_pepper() -> Result<Pepper, Error> {
    let mut bytes = Zeroizing::new([0u8; PEPPER_BYTES]);
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(bytes.as_mut()))
        .map_err(|error| Error::System(format!("/dev/urandom: {error}")))?;
    Ok(Pepper::new(bytes))
}

impl Hasher for Yescrypt {
    /// Whether `pin` hashes to `stored`, compared in constant time.
    fn verify(&self, pin: &str, stored: &str) -> Result<bool, Error> {
        if !stored.starts_with(HASH_PREFIX) {
            return Err(Error::NotYescrypt);
        }
        let setting = CString::new(stored).map_err(|_| Error::NotYescrypt)?;
        // Compared where libxcrypt wrote it, so the hash of what was typed is never copied out.
        with_hash(pin.as_bytes(), &setting, |hash| hash.ct_eq(stored.as_bytes()).into())
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

/// Hash `secret` (a peppered PIN, or a password) with `setting` and hand the full hash string to
/// `inspect`, while it still sits in libxcrypt's work area. Both the work area and the
/// NUL-terminated copy of `secret` are wiped when this returns, on every path. libxcrypt's
/// failures are errors, so a failure can never pass for a hash.
#[allow(unsafe_code)]
fn with_hash<T>(secret: &[u8], setting: &CStr, inspect: impl FnOnce(&[u8]) -> T) -> Result<T, Error> {
    // A C string ends at the first NUL, so "1234\0junk" would hash as "1234". Refuse it outright.
    if secret.contains(&0) {
        return Err(Error::System("the input contains a NUL byte".into()));
    }
    if secret.len() > MAX_PHRASE_BYTES {
        return Err(Error::System(format!("the input is longer than {MAX_PHRASE_BYTES} bytes")));
    }
    // Sized up front: a Vec that grows leaves its old allocation behind, unwiped.
    let mut phrase = Zeroizing::new(Vec::with_capacity(secret.len() + 1));
    phrase.extend_from_slice(secret);
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
        _ => Err(Error::System("libxcrypt could not hash the input".into())),
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

    const PASSWORD: &[u8] = b"correct horse battery staple";

    #[test]
    fn the_pepper_decryption_key_is_32_bytes_fixed_by_password_and_salt() {
        let salt = make_setting(4).unwrap();
        let pepper_decryption_key = derive_pepper_decryption_key(PASSWORD, &salt).unwrap();
        assert_eq!(*pepper_decryption_key, *derive_pepper_decryption_key(PASSWORD, &salt).unwrap());
        assert_ne!(*pepper_decryption_key, *derive_pepper_decryption_key(b"correct horse battery stapl", &salt).unwrap());
        assert_ne!(*pepper_decryption_key, *derive_pepper_decryption_key(PASSWORD, &make_setting(4).unwrap()).unwrap());
        // The decoding is exact: encoded again, the key gives back libxcrypt's own text.
        let hash = with_hash(PASSWORD, &salt, |hash| String::from_utf8_lossy(hash).into_owned()).unwrap();
        assert_eq!(encode_for_test(&pepper_decryption_key), hash.rsplit('$').next().unwrap());
    }

    /// crypt base64, the inverse of `decode_hash`, written out the obvious way.
    fn encode_for_test(pepper_decryption_key: &[u8; PEPPER_BYTES]) -> String {
        const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let bit = |index: usize| pepper_decryption_key.get(index / 8).map_or(0, |byte| byte >> (index % 8) & 1);
        (0..43).map(|char| char::from(ALPHABET[(0..6).map(|i| usize::from(bit(char * 6 + i)) << i).sum::<usize>()])).collect()
    }

    #[test]
    fn decoding_refuses_anything_but_43_characters_of_crypt_base64() {
        let good = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcd.";
        assert!(decode_hash(good.as_bytes()).is_some());
        for bad in ["", &good[1..], &format!("{good}a"), &good.replace('.', "+"), &good.replace("d.", "dz")] {
            assert!(decode_hash(bad.as_bytes()).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_new_pin_unseals_with_its_password_only() {
        let new = Yescrypt.new_pin("4859", PASSWORD, 4, 4).unwrap();
        assert!(
            new.cleartext_salt_for_deriving_pepper_decryption_key.starts_with("$y$j8T$"),
            "{}",
            new.cleartext_salt_for_deriving_pepper_decryption_key
        );
        assert_eq!(new.encrypted_pepper.len(), 64);
        let pepper = Yescrypt.unseal(&new.cleartext_salt_for_deriving_pepper_decryption_key, &new.encrypted_pepper, PASSWORD).unwrap();
        assert_eq!(pepper, new.pepper);
        assert!(Yescrypt.verify(&pepper.peppered("4859"), &new.hash).unwrap());
        // A wrong password is no error, just a pepper that makes the right PIN wrong.
        let wrong = Yescrypt
            .unseal(&new.cleartext_salt_for_deriving_pepper_decryption_key, &new.encrypted_pepper, b"Correct horse battery staple")
            .unwrap();
        assert_ne!(wrong, new.pepper);
        assert!(!Yescrypt.verify(&wrong.peppered("4859"), &new.hash).unwrap());
        // The PIN alone, without its pepper, is not the hash.
        assert!(!Yescrypt.verify("4859", &new.hash).unwrap());
    }

    #[test]
    fn every_pin_character_matters() {
        let pin = "a1b2c3d4e5f6";
        let new = Yescrypt.new_pin(pin, PASSWORD, 1, 1).unwrap();
        assert!(Yescrypt.verify(&new.pepper.peppered(pin), &new.hash).unwrap());
        for index in 0..pin.len() {
            let mut changed = pin.to_string().into_bytes();
            changed[index] = b'x';
            let changed = String::from_utf8(changed).unwrap();
            assert!(!Yescrypt.verify(&new.pepper.peppered(&changed), &new.hash).unwrap(), "{changed}");
        }
        for shorter in [&pin[1..], &pin[..pin.len() - 1]] {
            assert!(!Yescrypt.verify(&new.pepper.peppered(shorter), &new.hash).unwrap(), "{shorter}");
        }
    }

    #[test]
    fn every_seal_has_a_fresh_pepper_and_salt() {
        let (one, two) = (Yescrypt.new_pin("4859", PASSWORD, 1, 1).unwrap(), Yescrypt.new_pin("4859", PASSWORD, 1, 1).unwrap());
        assert_ne!(one.pepper, two.pepper);
        assert_ne!(one.cleartext_salt_for_deriving_pepper_decryption_key, two.cleartext_salt_for_deriving_pepper_decryption_key);
        assert_ne!(one.encrypted_pepper, two.encrypted_pepper);
    }

    #[test]
    fn an_unusable_seal_is_an_error_that_says_set_again() {
        let new = Yescrypt.new_pin("4859", PASSWORD, 1, 1).unwrap();
        for (salt, encrypted) in [
            ("", new.encrypted_pepper.as_str()),
            (new.cleartext_salt_for_deriving_pepper_decryption_key.as_str(), ""),
            ("$6$salt", new.encrypted_pepper.as_str()),
            (new.cleartext_salt_for_deriving_pepper_decryption_key.as_str(), &new.encrypted_pepper[1..]),
            (new.cleartext_salt_for_deriving_pepper_decryption_key.as_str(), &new.encrypted_pepper.to_uppercase()),
        ] {
            let error = Yescrypt.unseal(salt, encrypted, PASSWORD).unwrap_err().to_string();
            assert!(error.contains("sudo properpin set makes a new PIN"), "{error}");
        }
    }

    #[test]
    fn the_lines_are_what_settings_read() {
        let new = Yescrypt.new_pin("4859", PASSWORD, 1, 1).unwrap();
        assert_eq!(
            new.lines(),
            format!(
                "hash = {}\ncleartext_salt_for_deriving_pepper_decryption_key = {}\nencrypted_pepper = {}\n",
                new.hash, new.cleartext_salt_for_deriving_pepper_decryption_key, new.encrypted_pepper
            )
        );
    }

    #[test]
    fn refuses_hashes_that_are_not_yescrypt() {
        for stored in ["", "plain", "$6$salt$hash"] {
            assert!(matches!(Yescrypt.verify("4859", stored), Err(Error::NotYescrypt)), "{stored:?}");
        }
    }
}
